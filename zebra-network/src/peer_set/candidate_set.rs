use std::{cmp::min, mem, net::SocketAddr, sync::Arc, time::Duration};

use futures::stream::{FuturesUnordered, StreamExt};
use tokio::time::{sleep, sleep_until, timeout, Sleep};
use tower::{Service, ServiceExt};

use crate::{constants, types::MetaAddr, AddressBook, BoxError, Request, Response};

/// The [`CandidateSet`] manages outbound peer connection attempts.
/// Successful connections become peers in the [`PeerSet`].
///
/// The candidate set divides the set of all possible outbound peers into
/// disjoint subsets, using the [`PeerAddrState`:
///
/// 1. [`Responded`] peers, which we previously had outbound connections to.
/// 2. [`NeverAttemptedGossiped`] peers, which we learned about from other peers
///     but have never connected to;
/// 3. [`NeverAttemptedAlternate`] peers, which we learned from the [`Version`
///     messages of directly connected peers, but have never connected to;
/// 4. [`NeverAttemptedSeed`] peers, which we learned about from our seed config,
///     but have never connected to;
/// 5. [`Failed`] peers, to whom we attempted to connect but were unable to;
/// 6. [`AttemptPending`] peers, which we've recently queued for a connection.
///
/// Never attempted peers are always available for connection.
///
/// If a peer's attempted, success, or failed time is recent
/// (within the liveness limit), we avoid reconnecting to it.
/// Otherwise, we assume that it has disconnected or hung,
/// and attempt reconnection.
///
///
/// ```ascii,no_run
///                         ┌──────────────────┐
///                         │     PeerSet      │
///                         │     Gossiped     │
///                         │    Addresses     │
///                         └──────────────────┘
///                                  │      provides
///                                  │ untrusted_last_seen
///                                  │
///                                  │
///    ┌──────────────────┐          │          ┌──────────────────┐
///    │    Handshake     │          │          │       Seed       │
///    │    Canonical     │──────────┼──────────│    Addresses     │
///    │    Addresses     │          │          │                  │
///    └──────────────────┘          │          └──────────────────┘
///     untrusted_last_seen          │           untrusted_last_seen
///         set to now               │               is unknown
///                                  │
///                                  ▼
///             filter by            Λ
///          !contains_addr         ╱ ╲
///  ┌────────────────────────────▶▕   ▏
///  │                              ╲ ╱
///  │                               V
///  │                               │
///  ├───────────────────────────────┼───────────────────────────────┐
///  │ AddressBook                   ▼                               │
///  │ ┌─────────────┐  ┌─────────────────────────┐  ┌─────────────┐ │
///  │ │ `Responded` │  │`NeverAttemptedGossiped` │  │  `Failed`   │ │
///  │ │    Peers    │  │`NeverAttemptedAlternate`│  │   Peers     │◀┼┐
///  │ │             │  │  `NeverAttemptedSeed`   │  │             │ ││
///  │ │             │  │          Peers          │  │             │ ││
///  │ └─────────────┘  └─────────────────────────┘  └─────────────┘ ││
///  │        │                      │                      │        ││
///  │ #1 oldest_first        #2 newest_first        #3 oldest_first ││
///  │        │                      │                      │        ││
///  │        ├──────────────────────┴──────────────────────┘        ││
///  │        │         disjoint `PeerAddrState`s                    ││
///  ├────────┼──────────────────────────────────────────────────────┘│
///  │        ▼                                                       │
///  │        Λ                                                       │
///  │       ╱ ╲            filter by                                 │
///  └─────▶▕   ▏      !recently_used_addr                            │
///          ╲ ╱    to remove recent `Responded`,                     │
///           V  `AttemptPending`, and `Failed` peers                 │
///           │                                                       │
///           │    try outbound connection,                           │
///           ▼ update last_attempted to now()                        │
///    ┌────────────────┐                                             │
///    │`AttemptPending`│                                             │
///    │     Peers      │                                             │
///    │                │                                             │
///    └────────────────┘                                             │
///           │                                                       │
///           ▼                                                       │
///           Λ                                                       │
///          ╱ ╲                                                      │
///         ▕   ▏─────────────────────────────────────────────────────┘
///          ╲ ╱   connection failed, update last_failed to now()
///           V
///           │ connection succeeded
///           ▼
///    ┌────────────┐
///    │    send    │
///    │peer::Client│
///    │to Discover │
///    └────────────┘
///           │
///           ▼
///  ┌───────────────────────────────────────┐
///  │ every time we receive a peer message: │
///  │  * update state to `Responded`        │
///  │  * update last_success to now()       │
///  └───────────────────────────────────────┘
/// ```
// TODO:
//   * draw arrow from the "peer message" box into the `Responded` state box
//   * make the "disjoint states" box include `AttemptPending`
//   * show the Seed -> Gossip / Alternate transition
//   * show all possible transitions between Attempt/Responded/Failed,
//     except Failed -> Responded is invalid, must go through Attempt
pub(super) struct CandidateSet<S> {
    pub(super) address_book: Arc<std::sync::Mutex<AddressBook>>,
    pub(super) peer_service: S,
    next_peer_min_wait: Sleep,
}

impl<S> CandidateSet<S>
where
    S: Service<Request, Response = Response, Error = BoxError>,
    S::Future: Send + 'static,
{
    /// The minimum time between successive calls to [`CandidateSet::next`].
    ///
    /// ## Security
    ///
    /// Zebra resists distributed denial of service attacks by making sure that new peer connections
    /// are initiated at least [`MIN_PEER_CONNECTION_INTERVAL`] apart.
    const MIN_PEER_CONNECTION_INTERVAL: Duration = Duration::from_millis(100);

    /// Uses `address_book` and `peer_service` to manage a [`CandidateSet`] of peers.
    pub fn new(
        address_book: Arc<std::sync::Mutex<AddressBook>>,
        peer_service: S,
    ) -> CandidateSet<S> {
        CandidateSet {
            address_book,
            peer_service,
            next_peer_min_wait: sleep(Duration::from_secs(0)),
        }
    }

    /// Update the peer set from the network, using the default fanout limit.
    ///
    /// See [`update_initial`] for details.
    pub async fn update(&mut self) -> Result<(), BoxError> {
        self.update_timeout(None).await
    }

    /// Update the peer set from the network, limiting the fanout to
    /// `fanout_limit`.
    ///
    /// - Ask a few live [`Responded`] peers to send us more peers.
    /// - Process all completed peer responses, adding new peers in the
    ///   [`NeverAttemptedGossiped`] state.
    ///
    /// ## Correctness
    ///
    /// Pass the initial peer set size as `fanout_limit` during initialization,
    /// so that Zebra does not send duplicate requests to the same peer.
    ///
    /// The crawler exits when update returns an error, so it must only return
    /// errors on permanent failures.
    ///
    /// The handshaker sets up the peer message receiver so it also sends a
    /// [`Responded`] peer address update.
    ///
    /// [`report_failed`] puts peers into the [`Failed`] state.
    ///
    /// [`next`] puts peers into the [`AttemptPending`] state.
    pub async fn update_initial(&mut self, fanout_limit: usize) -> Result<(), BoxError> {
        self.update_timeout(Some(fanout_limit)).await
    }

    /// Update the peer set from the network, limiting the fanout to
    /// `fanout_limit`, and imposing a timeout on the entire fanout.
    ///
    /// See [`update_initial`] for details.
    async fn update_timeout(&mut self, fanout_limit: Option<usize>) -> Result<(), BoxError> {
        // CORRECTNESS
        //
        // Use a timeout to avoid deadlocks when there are no connected
        // peers, and:
        // - we're waiting on a handshake to complete so there are peers, or
        // - another task that handles or adds peers is waiting on this task
        //   to complete.
        if let Ok(fanout_result) =
            timeout(constants::REQUEST_TIMEOUT, self.update_fanout(fanout_limit)).await
        {
            fanout_result?;
        } else {
            // update must only return an error for permanent failures
            info!("timeout waiting for the peer service to become ready");
        }

        Ok(())
    }

    /// Update the peer set from the network, limiting the fanout to
    /// `fanout_limit`.
    ///
    /// See [`update_initial`] for details.
    ///
    /// # Correctness
    ///
    /// This function does not have a timeout. Use [`update_timeout`] instead.
    async fn update_fanout(&mut self, fanout_limit: Option<usize>) -> Result<(), BoxError> {
        // Opportunistically crawl the network on every update call to ensure
        // we're actively fetching peers. Continue independently of whether we
        // actually receive any peers, but always ask the network for more.
        //
        // Because requests are load-balanced across existing peers, we can make
        // multiple requests concurrently, which will be randomly assigned to
        // existing peers, but we don't make too many because update may be
        // called while the peer set is already loaded.
        let mut responses = FuturesUnordered::new();
        let fanout_limit = fanout_limit
            .map(|fanout_limit| min(fanout_limit, constants::GET_ADDR_FANOUT))
            .unwrap_or(constants::GET_ADDR_FANOUT);
        debug!(?fanout_limit, "sending GetPeers requests");
        // TODO: launch each fanout in its own task (might require tokio 1.6)
        for _ in 0..fanout_limit {
            let peer_service = self.peer_service.ready_and().await?;
            responses.push(peer_service.call(Request::Peers));
        }
        while let Some(rsp) = responses.next().await {
            match rsp {
                Ok(Response::Peers(addrs)) => {
                    trace!(
                        addr_count = ?addrs.len(),
                        ?addrs,
                        "got response to GetPeers"
                    );
                    let addrs = self.validate_addrs(addrs);
                    self.send_addrs(addrs);
                }
                Err(e) => {
                    // since we do a fanout, and new updates are triggered by
                    // each demand, we can ignore errors in individual responses
                    trace!(?e, "got error in GetPeers request");
                }
                Ok(_) => unreachable!("Peers requests always return Peers responses"),
            }
        }

        Ok(())
    }

    /// Check new `addrs` before adding them to the address book.
    ///
    /// If the data in an address is invalid, this function can:
    /// - modify the address data, or
    /// - delete the address.
    fn validate_addrs(
        &self,
        addrs: impl IntoIterator<Item = MetaAddr>,
    ) -> impl IntoIterator<Item = MetaAddr> {
        // Note: The address book handles duplicate addresses internally,
        // so we don't need to de-duplicate addresses here.

        // TODO:
        // We should eventually implement these checks in this function:
        // - Zebra should stop believing far-future last_seen times from peers (#1871)
        // - Zebra should ignore peers that are older than 3 weeks (part of #1865)
        //   - Zebra should count back 3 weeks from the newest peer timestamp sent
        //     by the other peer, to compensate for clock skew
        // - Zebra should limit the number of addresses it uses from a single Addrs
        //   response (#1869)

        addrs
    }

    /// Add new `addrs` to the address book.
    fn send_addrs(&self, addrs: impl IntoIterator<Item = MetaAddr>) {
        // Turn the addresses into "new gossiped" changes
        let addrs = addrs.into_iter().map(MetaAddr::new_gossiped_change);

        // # Correctness
        //
        // Briefly hold the address book threaded mutex, to extend
        // the address list.
        //
        // Extend handles duplicate addresses internally.
        self.address_book.lock().unwrap().extend(addrs);
    }

    /// Returns the next candidate for a connection attempt, if any are available.
    ///
    /// Returns peers in [`MetaAddr::cmp`] order, lowest first:
    /// - oldest [`Responded`] that are not live
    /// - [`NeverAttemptedSeed`], if any
    /// - newest [`NeverAttemptedGossiped`]
    /// - newest [`NeverAttemptedAlternate`]
    /// - oldest [`Failed`] that are not recent
    /// - oldest [`AttemptPending`] that are not recent
    ///
    /// Skips peers that have recently been attempted, connected, or failed.
    ///
    /// ## Correctness
    ///
    /// [`AttemptPending`] peers will become [`Responded`] if they respond, or
    /// become [`Failed`] if they time out or provide a bad response.
    ///
    /// Live [`Responded`] peers will stay live if they keep responding, or
    /// become a connection candidate if they stop responding.
    ///
    /// ## Security
    ///
    /// Zebra resists distributed denial of service attacks by making sure that
    /// new peer connections are initiated at least
    /// [`MIN_PEER_CONNECTION_INTERVAL`] apart.
    pub async fn next(&mut self) -> Option<MetaAddr> {
        let current_deadline = self.next_peer_min_wait.deadline();
        let mut sleep = sleep_until(current_deadline + Self::MIN_PEER_CONNECTION_INTERVAL);
        mem::swap(&mut self.next_peer_min_wait, &mut sleep);

        // # Correctness
        //
        // In this critical section, we hold the address mutex, blocking the
        // current thread, and all async tasks scheduled on that thread.
        //
        // To avoid deadlocks, the critical section:
        // - must not acquire any other locks
        // - must not await any futures
        //
        // To avoid hangs, any computation in the critical section should
        // be kept to a minimum.
        let connect = {
            let mut guard = self.address_book.lock().unwrap();
            // It's okay to return without sleeping here, because we're returning
            // `None`. We only need to sleep before yielding an address.
            let connect = guard.next_candidate_peer()?;

            let connect = MetaAddr::update_attempt(connect.addr);
            guard.update(connect)?
        };

        // SECURITY: rate-limit new candidate connections
        sleep.await;

        Some(connect)
    }

    /// Mark `addr` as a failed peer.
    pub fn report_failed(&mut self, addr: SocketAddr) {
        let addr = MetaAddr::update_failed(addr, None);
        // # Correctness
        //
        // Briefly hold the address book threaded mutex, to update the state for
        // a single address.
        self.address_book.lock().unwrap().update(addr);
    }

    /// Return the number of candidate peers.
    ///
    /// This number can change over time as recently used peers expire.
    pub fn candidate_peer_count(&self) -> usize {
        // # Correctness
        //
        // Briefly hold the address book threaded mutex.
        self.address_book.lock().unwrap().candidate_peer_count()
    }

    /// Return the number of recently used peers.
    ///
    /// This number can change over time as recently used peers expire.
    pub fn recent_peer_count(&self) -> usize {
        // # Correctness
        //
        // Briefly hold the address book threaded mutex.
        self.address_book
            .lock()
            .unwrap()
            .recently_used_peers()
            .count()
    }
}
