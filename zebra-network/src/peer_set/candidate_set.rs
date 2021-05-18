use std::{mem, net::SocketAddr, sync::Arc, time::Duration};

use futures::stream::{FuturesUnordered, StreamExt};
use tokio::time::{sleep, sleep_until, timeout, Sleep};
use tower::{Service, ServiceExt};

use crate::{constants, types::MetaAddr, AddressBook, BoxError, Request, Response};

/// The `CandidateSet` manages the `PeerSet`'s peer reconnection attempts.
///
/// It divides the set of all possible candidate peers into disjoint subsets,
/// using the `PeerAddrState`:
///
/// 1. `Responded` peers, which we previously had outbound connections to.
/// 2. `NeverAttemptedGossiped` peers, which we learned about from other peers
///    or a DNS seeder, but have never connected to;
/// 3. `NeverAttemptedAlternate` peers, which we learned from the `Version`
///     messages of directly connected peers, but have never connected to;
/// 4. `Failed` peers, to whom we attempted to connect but were unable to;
/// 5. `AttemptPending` peers, which we've recently queued for reconnection.
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
///                         │GetPeers Responses│
///                         └──────────────────┘
///                                  │
///                                  │
///                                  │
///                                  │
///                                  ▼
///             filter by            Λ
///          !contains_addr         ╱ ╲
///  ┌────────────────────────────▶▕   ▏
///  │                              ╲ ╱
///  │                               V
///  │                               │
///  │                               │
///  │                               │
///  │ ┌──────────────────┐          │
///  │ │     Inbound      │          │
///  │ │ Peer Connections │──────────┤
///  │ └──────────────────┘          │
///  │          │                    │
///  ├──────────┼────────────────────┼───────────────────────────────┐
///  │ PeerSet  ▼  AddressBook       ▼                               │
///  │ ┌─────────────┐  ┌─────────────────────────┐  ┌─────────────┐ │
///  │ │  Possibly   │  │`NeverAttemptedGossiped` │  │  `Failed`   │ │
///  │ │Disconnected │  │           and           │  │   Peers     │◀┼┐
///  │ │ `Responded` │  │`NeverAttemptedAlternate`│  │             │ ││
///  │ │    Peers    │  │          Peers          │  │             │ ││
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
///  └─────▶▕   ▏     !maybe_connected_addr                           │
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
///           │                                                       │
///           ▼                                                       │
///           Λ                                                       │
///          ╱ ╲                                                      │
///         ▕   ▏─────────────────────────────────────────────────────┘
///          ╲ ╱   connection failed, update last_failed to now()
///           V
///           │
///           │ connection succeeded
///           ▼
///    ┌────────────┐
///    │    send    │
///    │peer::Client│
///    │to Discover │
///    └────────────┘
///           │
///           │
///           ▼
///  ┌───────────────────────────────────────┐
///  │ every time we receive a peer message: │
///  │  * update state to `Responded`        │
///  │  * update last_success to now()       │
///  └───────────────────────────────────────┘
///
/// ```
// TODO:
//   * draw arrow from the "peer message" box into the `Responded` state box
//   * make the "disjoint states" box include `AttemptPending`
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
    /// The minimum time between successive calls to `CandidateSet::next()`.
    ///
    /// ## Security
    ///
    /// Zebra resists distributed denial of service attacks by making sure that new peer connections
    /// are initiated at least `MIN_PEER_CONNECTION_INTERVAL` apart.
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
    /// See `update_initial` for details.
    pub async fn update(&mut self) -> Result<(), BoxError> {
        self.update_inner(None).await
    }

    /// Update the peer set from the network, limiting the fanout to
    /// `fanout_limit`.
    ///
    /// - Ask a few live `Responded` peers to send us more peers.
    /// - Process all completed peer responses, adding new peers in the
    ///   `NeverAttemptedGossiped` state.
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
    /// `Responded` peer address update.
    ///
    /// `report_failed` puts peers into the `Failed` state.
    ///
    /// `next` puts peers into the `AttemptPending` state.
    pub async fn update_initial(&mut self, fanout_limit: usize) -> Result<(), BoxError> {
        self.update_inner(Some(fanout_limit)).await
    }

    /// Update the peer set from the network, limiting the fanout to
    /// `fanout_limit`.
    ///
    /// See `update_initial` for details.
    async fn update_inner(&mut self, fanout_limit: Option<usize>) -> Result<(), BoxError> {
        // Opportunistically crawl the network on every update call to ensure
        // we're actively fetching peers. Continue independently of whether we
        // actually receive any peers, but always ask the network for more.
        //
        // Because requests are load-balanced across existing peers, we can make
        // multiple requests concurrently, which will be randomly assigned to
        // existing peers, but we don't make too many because update may be
        // called while the peer set is already loaded.
        let mut responses = FuturesUnordered::new();
        trace!("sending GetPeers requests");
        for _ in 0..fanout_limit.unwrap_or(constants::GET_ADDR_FANOUT) {
            // CORRECTNESS
            //
            // Use a timeout to avoid deadlocks when there are no connected
            // peers, and:
            // - we're waiting on a handshake to complete so there are peers, or
            // - another task that handles or adds peers is waiting on this task
            //   to complete.
            let peer_service =
                match timeout(constants::REQUEST_TIMEOUT, self.peer_service.ready_and()).await {
                    // update must only return an error for permanent failures
                    Err(temporary_error) => {
                        info!(
                            ?temporary_error,
                            "timeout waiting for the peer service to become ready"
                        );
                        return Ok(());
                    }
                    Ok(Err(permanent_error)) => Err(permanent_error)?,
                    Ok(Ok(peer_service)) => peer_service,
                };
            responses.push(peer_service.call(Request::Peers));
        }
        while let Some(rsp) = responses.next().await {
            match rsp {
                Ok(Response::Peers(rsp_addrs)) => {
                    // Filter new addresses to ensure that gossiped addresses are actually new
                    let address_book = &self.address_book;
                    let new_addrs = rsp_addrs
                        .iter()
                        .map(MetaAddr::new_gossiped_change)
                        .collect::<Vec<_>>();
                    trace!(
                        ?rsp_addrs,
                        new_addr_count = ?new_addrs.len(),
                        "got response to GetPeers"
                    );

                    // `MetaAddr`s are deserialized in the `NeverAttemptedGossiped` state
                    //
                    // # Correctness
                    //
                    // Briefly hold the address book threaded mutex, to extend
                    // the address list.
                    //
                    // Extend handles duplicate addresses internally.
                    address_book.lock().unwrap().extend(new_addrs.into_iter());
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

    /// Returns the next candidate for a connection attempt, if any are available.
    ///
    /// Returns peers in this order:
    /// - oldest `Responded` that are not live
    /// - newest `NeverAttemptedGossiped`
    /// - newest `NeverAttemptedAlternate`
    /// - oldest `Failed` that are not recent
    /// - oldest `AttemptPending` that are not recent
    ///
    /// Skips peers that have recently been attempted, connected, or failed.
    ///
    /// ## Correctness
    ///
    /// `AttemptPending` peers will become `Responded` if they respond, or
    /// become `Failed` if they time out or provide a bad response.
    ///
    /// Live `Responded` peers will stay live if they keep responding, or
    /// become a connection candidate if they stop responding.
    ///
    /// ## Security
    ///
    /// Zebra resists distributed denial of service attacks by making sure that
    /// new peer connections are initiated at least
    /// `MIN_PEER_CONNECTION_INTERVAL` apart.
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

            let connect = MetaAddr::update_attempt(&connect.addr);
            guard.update(connect)?
        };

        // SECURITY: rate-limit new candidate connections
        sleep.await;

        Some(connect)
    }

    /// Mark `addr` as a failed peer.
    pub fn report_failed(&mut self, addr: &SocketAddr) {
        let addr = MetaAddr::update_failed(&addr, &None);
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
