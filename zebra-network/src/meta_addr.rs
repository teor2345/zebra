//! An address-with-metadata type used in Bitcoin networking.
//!
//! In Zebra, `MetaAddr`s also track Zebra-specific peer state.

use std::{
    cmp::{Ord, Ordering},
    convert::TryInto,
    io::{Read, Write},
    net::SocketAddr,
};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use chrono::{DateTime, TimeZone, Utc};

use zebra_chain::serialization::{
    ReadZcashExt, SerializationError, TrustedPreallocate, WriteZcashExt, ZcashDeserialize,
    ZcashSerialize,
};

use crate::protocol::{external::MAX_PROTOCOL_MESSAGE_LEN, types::PeerServices};

use PeerAddrState::*;

#[cfg(any(test, feature = "proptest-impl"))]
mod arbitrary;

#[cfg(test)]
mod tests;

/// Peer connection state, based on our interactions with the peer.
///
/// Zebra also tracks how recently a peer has sent us messages, and derives peer
/// liveness based on the current time. This derived state is tracked using
/// [`AddressBook::maybe_connected_peers`] and
/// [`AddressBook::reconnection_peers`].
#[derive(Copy, Clone, Debug)]
pub enum PeerAddrState {
    /// The peer's address has just been fetched from a DNS seeder, or via peer
    /// gossip, but we haven't attempted to connect to it yet.
    NeverAttemptedGossiped,

    /// The peer's address has just been received as part of a `Version` message,
    /// so we might already be connected to this peer.
    ///
    /// Alternate addresses are attempted after gossiped addresses.
    NeverAttemptedAlternate,

    /// We have started a connection attempt to this peer.
    AttemptPending {
        /// The last time we made an outbound attempt to this peer.
        /// See `get_last_attempt` for details.
        last_attempt: DateTime<Utc>,
        /// The last time we made a successful outbound connection to this peer.
        /// See `get_last_success` for details.
        last_success: Option<DateTime<Utc>>,
        /// The last time an outbound connection to this peer failed.
        /// See `get_last_failed` for details.
        last_failed: Option<DateTime<Utc>>,
    },

    /// The peer has sent us a valid message.
    ///
    /// Peers remain in this state, even if they stop responding to requests.
    /// (Peer liveness is derived from the `last_success` time, and the current
    /// time.)
    Responded {
        /// The last time we made an outbound attempt to this peer.
        /// See `get_last_attempt` for details.
        last_attempt: DateTime<Utc>,
        /// The last time we made a successful outbound connection to this peer.
        /// See `get_last_success` for details.
        last_success: DateTime<Utc>,
        /// The last time an outbound connection to this peer failed.
        /// See `get_last_failed` for details.
        last_failed: Option<DateTime<Utc>>,
    },

    /// The peer's TCP connection failed, or the peer sent us an unexpected
    /// Zcash protocol message, so we failed the connection.
    Failed {
        /// The last time we made an outbound attempt to this peer.
        /// See `get_last_attempt` for details.
        last_attempt: DateTime<Utc>,
        /// The last time we made a successful outbound connection to this peer.
        /// See `get_last_success` for details.
        last_success: Option<DateTime<Utc>>,
        /// The last time an outbound connection to this peer failed.
        /// See `get_last_failed` for details.
        last_failed: DateTime<Utc>,
    },
}

impl PeerAddrState {
    /// The last time we attempted to make a direct outbound connection to the
    /// address of this peer.
    ///
    /// Only updated by the `AttemptPending` state.
    /// Also present in `Responded` and `Failed`.
    pub fn get_last_attempt(&self) -> Option<DateTime<Utc>> {
        match self {
            NeverAttemptedGossiped => None,
            NeverAttemptedAlternate => None,
            AttemptPending { last_attempt, .. } => Some(*last_attempt),
            Responded { last_attempt, .. } => Some(*last_attempt),
            Failed { last_attempt, .. } => Some(*last_attempt),
        }
    }

    /// The last time we successfully made a direct outbound connection to the
    /// address of this peer.
    ///
    /// Only updated by the `Responded` state.
    /// Also optionally present in `Failed` and `AttemptPending`.
    pub fn get_last_success(&self) -> Option<DateTime<Utc>> {
        match self {
            NeverAttemptedGossiped => None,
            NeverAttemptedAlternate => None,
            AttemptPending { last_success, .. } => *last_success,
            Responded { last_success, .. } => Some(*last_success),
            Failed { last_success, .. } => *last_success,
        }
    }

    /// The last time a direct outbound connection to the address of this peer
    /// failed.
    ///
    /// Only updated by the `Failed` state.
    /// Also optionally present in `AttemptPending` and `Responded`.
    pub fn get_last_failed(&self) -> Option<DateTime<Utc>> {
        match self {
            NeverAttemptedGossiped => None,
            NeverAttemptedAlternate => None,
            AttemptPending { last_failed, .. } => *last_failed,
            Responded { last_failed, .. } => *last_failed,
            Failed { last_failed, .. } => Some(*last_failed),
        }
    }
}

// non-test code should explicitly specify the peer address state
#[cfg(test)]
impl Default for PeerAddrState {
    fn default() -> Self {
        NeverAttemptedGossiped
    }
}

impl Ord for PeerAddrState {
    /// `PeerAddrState`s are sorted in approximate reconnection attempt
    /// order, ignoring liveness.
    ///
    /// See [`CandidateSet`] and [`MetaAddr::cmp`] for more details.
    fn cmp(&self, other: &Self) -> Ordering {
        use Ordering::*;
        match (self, other) {
            (Responded { .. }, Responded { .. })
            | (Failed { .. }, Failed { .. })
            | (NeverAttemptedGossiped, NeverAttemptedGossiped)
            | (NeverAttemptedAlternate, NeverAttemptedAlternate)
            | (AttemptPending { .. }, AttemptPending { .. }) => {}
            // We reconnect to `Responded` peers that have stopped sending messages,
            // then `NeverAttempted` peers, then `Failed` peers
            (Responded { .. }, _) => return Less,
            (_, Responded { .. }) => return Greater,
            (NeverAttemptedGossiped, _) => return Less,
            (_, NeverAttemptedGossiped) => return Greater,
            (NeverAttemptedAlternate, _) => return Less,
            (_, NeverAttemptedAlternate) => return Greater,
            (Failed { .. }, _) => return Less,
            (_, Failed { .. }) => return Greater,
            // AttemptPending is covered by the other cases
        };

        // Prioritise successful peers:
        // - try the latest successful peers first
        // - try the oldest failed peers before re-trying the same peer
        // - use "oldest attempt" as a tie-breaker
        //
        // `None` is earlier than any `Some(time)`, which means:
        // - peers that have never succeeded sort last
        // - peers that have never failed sort first
        let success_order = self
            .get_last_success()
            .cmp(&other.get_last_success())
            .reverse();
        let failed_order = self.get_last_failed().cmp(&other.get_last_failed());
        let attempt_order = self.get_last_attempt().cmp(&other.get_last_attempt());

        success_order.then(failed_order).then(attempt_order)
    }
}

impl PartialOrd for PeerAddrState {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for PeerAddrState {
    fn eq(&self, other: &Self) -> bool {
        use Ordering::*;
        self.cmp(other) == Equal
    }
}

impl Eq for PeerAddrState {}

/// A change to a `MetaAddr` in an `AddressBook`.
///
/// Most `PeerAddrState`s have a corresponding `Change`.
#[derive(Copy, Clone, Debug)]
pub enum MetaAddrChange {
    /// A new gossiped peer `MetaAddr`.
    ///
    /// `Addr` messages provide an address, services, and a last seen time.
    /// The services can be updated by future handshakes with this peer.
    /// The untrusted last seen time is overridden by any `last_success` time.
    NewGossiped {
        addr: SocketAddr,
        services: PeerServices,
        untrusted_last_seen: DateTime<Utc>,
    },

    /// A new alternate peer `MetaAddr`.
    ///
    /// `Version` messages provide the canonical address and its services.
    /// The services can be updated by future handshakes with this peer.
    ///
    /// Sets the untrusted last seen time to the current time.
    NewAlternate {
        addr: SocketAddr,
        services: PeerServices,
    },

    /// We have started a connection attempt to this peer.
    ///
    /// Sets the last attempt time to the current time.
    UpdateAttempt { addr: SocketAddr },

    /// A peer has sent us a message, after a successful handshake on an outbound
    /// connection.
    ///
    /// The services are updated based on the handshake with this peer.
    ///
    /// Sets the last success time to the current time.
    UpdateResponded {
        addr: SocketAddr,
        services: PeerServices,
    },

    /// A connection to this peer has failed.
    ///
    /// If the handshake with this peer succeeded, update its services.
    ///
    /// Sets the last failed time to the current time.
    UpdateFailed {
        addr: SocketAddr,
        services: Option<PeerServices>,
    },

    /// A connection to this peer has shut down.
    ///
    /// If the handshake with this peer succeeded, update its services.
    ///
    /// If the peer is in the `Responded` state, do nothing.
    /// Otherwise, mark the peer as `Failed`, and set the last failed time to the
    /// current time.
    UpdateShutdown {
        addr: SocketAddr,
        services: Option<PeerServices>,
    },
}

impl MetaAddrChange {
    /// Return the address for the change.
    pub fn get_addr(&self) -> SocketAddr {
        use MetaAddrChange::*;
        match self {
            NewGossiped { addr, .. } => *addr,
            NewAlternate { addr, .. } => *addr,
            UpdateAttempt { addr } => *addr,
            UpdateResponded { addr, .. } => *addr,
            UpdateFailed { addr, .. } => *addr,
            UpdateShutdown { addr, .. } => *addr,
        }
    }

    /// Return the services for the change, if available.
    pub fn get_services(&self) -> Option<PeerServices> {
        use MetaAddrChange::*;
        match self {
            NewGossiped { services, .. } => Some(*services),
            NewAlternate { services, .. } => Some(*services),
            UpdateAttempt { .. } => None,
            UpdateResponded { services, .. } => Some(*services),
            UpdateFailed { services, .. } => *services,
            UpdateShutdown { services, .. } => *services,
        }
    }

    /// Return the untrusted last seen time for the change, if available.
    pub fn get_untrusted_last_seen(&self) -> Option<DateTime<Utc>> {
        use MetaAddrChange::*;
        match self {
            NewGossiped {
                untrusted_last_seen,
                ..
            } => Some(*untrusted_last_seen),
            NewAlternate { .. }
            | UpdateAttempt { .. }
            | UpdateResponded { .. }
            | UpdateFailed { .. }
            | UpdateShutdown { .. } => None,
        }
    }

    /// Is this address valid for outbound connections?
    ///
    /// `book_entry` is the entry for `self.get_addr()` in the address book.
    pub fn is_valid_for_outbound(&self, book_entry: &Option<&MetaAddr>) -> bool {
        if self.get_addr().ip().is_unspecified() || self.get_addr().port() == 0 {
            false
        } else {
            let book_services = book_entry.map(|book| book.services);
            // Use the latest services we have. Assume valid if we don't know.
            self.get_services()
                .or(book_services)
                .map(|services| services.contains(PeerServices::NODE_NETWORK))
                .unwrap_or(true)
        }
    }

    /// Is this address a directly connected client?
    ///
    /// `book_entry` is the entry for `self.get_addr()` in the address book.
    pub fn is_direct_client(&self, book_entry: &Option<&MetaAddr>) -> bool {
        let book_services = book_entry.map(|book| book.services);
        // Use the latest services we have. Assume server if we don't know.
        self.get_services()
            .or(book_services)
            .map(|services| !services.contains(PeerServices::NODE_NETWORK))
            .unwrap_or(false)
    }

    pub fn into_meta_addr(self, old_entry: &Option<&MetaAddr>) -> Option<MetaAddr> {
        use MetaAddrChange::*;

        let has_been_attempted = old_entry
            .map(|old| old.has_been_attempted())
            .unwrap_or(false);

        match self {
            // Skip the update if the peer has had a previous attempt
            // Update services, but ignore updates to untrusted last seen
            NewGossiped {
                addr,
                services,
                untrusted_last_seen,
            } if !has_been_attempted => Some(MetaAddr::new(
                &addr,
                &services,
                &old_entry
                    .map(|old| old.untrusted_last_seen)
                    .unwrap_or(untrusted_last_seen),
                &NeverAttemptedGossiped,
            )),
            NewAlternate { addr, services } if !has_been_attempted => Some(MetaAddr::new(
                &addr,
                &services,
                &old_entry
                    .map(|old| old.untrusted_last_seen)
                    .unwrap_or_else(Utc::now),
                &NeverAttemptedAlternate,
            )),
            NewGossiped { .. } | NewAlternate { .. } => None,
            // Update last_attempt
            // Panics if the peer does not have an existing entry
            UpdateAttempt { addr } => {
                if let Some(old_entry) = old_entry {
                    Some(MetaAddr::new(
                        &addr,
                        &old_entry.services,
                        &old_entry.untrusted_last_seen,
                        &AttemptPending {
                            last_attempt: Utc::now(),
                            last_success: old_entry.get_last_success(),
                            last_failed: old_entry.get_last_failed(),
                        },
                    ))
                } else {
                    panic!(
                        "unexpected attempt before gossip or alternate: change: {:?} old: {:?}",
                        self, old_entry
                    )
                }
            }
            // Update last_success and services
            // Panics if the peer has not had an attempt
            UpdateResponded { addr, services } => old_entry.map(|old_entry| {
                MetaAddr::new(
                    &addr,
                    &services,
                    &old_entry.untrusted_last_seen,
                    &Responded {
                        last_attempt: old_entry.get_last_attempt().unwrap_or_else(|| {
                            panic!(
                                "unexpected responded before attempt: change: {:?} old: {:?}",
                                self, old_entry
                            )
                        }),
                        last_success: Utc::now(),
                        last_failed: old_entry.get_last_failed(),
                    },
                )
            }),
            // Update last_failed and services if present
            // Panics if the peer has not had an attempt
            UpdateFailed { addr, services } => old_entry.map(|old_entry| {
                MetaAddr::new(
                    &addr,
                    &services.unwrap_or(old_entry.services),
                    &old_entry.untrusted_last_seen,
                    &Failed {
                        last_attempt: old_entry.get_last_attempt().unwrap_or_else(|| {
                            panic!(
                                "unexpected failure before attempt: change: {:?} old: {:?}",
                                self, old_entry
                            )
                        }),
                        last_success: old_entry.get_last_success(),
                        last_failed: Utc::now(),
                    },
                )
            }),
            UpdateShutdown { addr, services } => old_entry.map(|old_entry| {
                if matches!(old_entry.last_connection_state, Responded { .. }) {
                    // Update services if present
                    MetaAddr::new(
                        &addr,
                        &services.unwrap_or(old_entry.services),
                        &old_entry.untrusted_last_seen,
                        &old_entry.last_connection_state,
                    )
                } else {
                    // Update last_failed and services if present
                    MetaAddr::new(
                        &addr,
                        &services.unwrap_or(old_entry.services),
                        &old_entry.untrusted_last_seen,
                        &Failed {
                            last_attempt: old_entry.get_last_attempt().unwrap_or_else(|| {
                                panic!(
                                    "unexpected shutdown before attempt: change: {:?} old: {:?}",
                                    self, old_entry
                                )
                            }),
                            last_success: old_entry.get_last_success(),
                            last_failed: Utc::now(),
                        },
                    )
                }
            }),
        }
    }
}

/// An address with metadata on its advertised services and last-seen time.
///
/// [Bitcoin reference](https://en.bitcoin.it/wiki/Protocol_documentation#Network_address)
#[derive(Copy, Clone, Debug)]
pub struct MetaAddr {
    /// The peer's address.
    ///
    /// The exact meaning depends on `last_connection_state`:
    ///   - `Responded`: the address we used to make a direct outbound connection
    ///      to this peer
    ///   - `NeverAttemptedGossiped`: an unverified address provided by a remote
    ///      peer
    ///   - `NeverAttemptedAlternate`: a directly connected peer claimed that
    ///      this address was its canonical address in its `Version` message,
    ///      but either:
    ///      - the peer made an inbound connection to us, or
    ///      - the address we used to make a direct outbound connection was
    ///        different from the canonical address
    ///   - `Failed` or `AttemptPending`: an unverified gossiped or alternate
    ///      address, or an address from a previous direct outbound connection
    ///
    /// ## Security
    ///
    /// `addr`s from non-`Responded` peers may be invalid due to outdated
    /// records, or buggy or malicious peers.
    //
    // TODO: make the addr private to MetaAddr and AddressBook
    pub(super) addr: SocketAddr,

    /// The services advertised by the peer.
    ///
    /// The exact meaning depends on `last_connection_state`:
    ///   - `Responded`: the services advertised by this peer, the last time we
    ///      performed a handshake with it
    ///   - `NeverAttemptedGossiped`: the unverified services provided by the
    ///      remote peer that sent us this address
    ///   - `NeverAttemptedAlternate`: the services provided by the directly
    ///      connected peer that claimed that this address was its canonical
    ///      address
    ///   - `Failed` or `AttemptPending`: unverified services via another peer,
    ///      or services advertised in a previous handshake
    ///
    /// ## Security
    ///
    /// `services` from non-`Responded` peers may be invalid due to outdated
    /// records, older peer versions, or buggy or malicious peers.
    services: PeerServices,

    /// The last time another node claimed this peer was valid.
    ///
    /// See `get_untrusted_last_seen` for details.
    untrusted_last_seen: DateTime<Utc>,

    /// The outcome of our most recent direct outbound connection to this peer.
    //
    // TODO: make the state private to MetaAddr and AddressBook
    pub(super) last_connection_state: PeerAddrState,
}

impl MetaAddr {
    /// Create a new `MetaAddr` from its parts.
    ///
    /// This function should only be used by the `meta_addr` and `address_book`
    /// modules. Other callers should use a more specific `MetaAddr` or
    /// `MetaAddrChange` constructor.
    fn new(
        addr: &SocketAddr,
        services: &PeerServices,
        untrusted_last_seen: &DateTime<Utc>,
        last_connection_state: &PeerAddrState,
    ) -> MetaAddr {
        MetaAddr {
            addr: *addr,
            services: *services,
            untrusted_last_seen: *untrusted_last_seen,
            last_connection_state: *last_connection_state,
        }
    }

    /// Add or update an `AddressBook` entry, based on a gossiped peer `Addr`
    /// message.
    pub fn new_gossiped_change(meta_addr: &MetaAddr) -> MetaAddrChange {
        assert!(meta_addr.last_connection_state == NeverAttemptedGossiped);
        MetaAddrChange::NewGossiped {
            addr: meta_addr.addr,
            services: meta_addr.services,
            untrusted_last_seen: meta_addr.untrusted_last_seen,
        }
    }

    /// Create a new gossiped `MetaAddr`, based on the deserialized fields from
    /// a peer `Addr` message.
    pub fn new_gossiped_meta_addr(
        addr: &SocketAddr,
        services: &PeerServices,
        untrusted_last_seen: &DateTime<Utc>,
    ) -> MetaAddr {
        MetaAddr {
            addr: *addr,
            services: *services,
            untrusted_last_seen: *untrusted_last_seen,
            last_connection_state: NeverAttemptedGossiped,
        }
    }

    /// Add or update an `AddressBook` entry, based on the canonical address in a
    /// peer's `Version` message.
    pub fn new_alternate(addr: &SocketAddr, services: &PeerServices) -> MetaAddrChange {
        MetaAddrChange::NewAlternate {
            addr: *addr,
            services: *services,
        }
    }

    /// Update an `AddressBook` entry when we start connecting to a peer.
    pub fn update_attempt(addr: &SocketAddr) -> MetaAddrChange {
        MetaAddrChange::UpdateAttempt { addr: *addr }
    }

    /// Update an `AddressBook` entry when a peer sends a message after a
    /// successful handshake.
    ///
    /// # Security
    ///
    /// This address must be the remote address from an outbound connection,
    /// and the services must be the services from that peer's handshake.
    ///
    /// Otherwise:
    /// - malicious peers could interfere with other peers' `AddressBook` state,
    ///   or
    /// - Zebra could advertise unreachable addresses to its own peers.
    pub fn update_responded(addr: &SocketAddr, services: &PeerServices) -> MetaAddrChange {
        MetaAddrChange::UpdateResponded {
            addr: *addr,
            services: *services,
        }
    }

    /// Update an `AddressBook` entry when a peer connection fails.
    pub fn update_failed(addr: &SocketAddr, services: &Option<PeerServices>) -> MetaAddrChange {
        MetaAddrChange::UpdateFailed {
            addr: *addr,
            services: *services,
        }
    }

    /// Update an `AddressBook` entry when a peer connection shuts down.
    pub fn update_shutdown(addr: &SocketAddr, services: &Option<PeerServices>) -> MetaAddrChange {
        MetaAddrChange::UpdateShutdown {
            addr: *addr,
            services: *services,
        }
    }

    /// Add or update our local listener address in an `AddressBook`.
    ///
    /// See `AddressBook::get_local_listener` for details.
    pub fn new_local_listener(addr: &SocketAddr) -> MetaAddrChange {
        MetaAddrChange::NewAlternate {
            addr: *addr,
            // TODO: create a "local services" constant
            services: PeerServices::NODE_NETWORK,
        }
    }

    /// The last time another node claimed this peer was valid.
    ///
    /// The exact meaning depends on `last_connection_state`:
    ///   - `Responded`: the last time we processed a message from this peer
    ///   - `NeverAttemptedGossiped`: the unverified time provided by the remote
    ///      peer that sent us this address
    ///   - `NeverAttemptedAlternate`: the local time we received the `Version`
    ///      message containing this address from a peer
    ///   - `Failed` and `AttemptPending`: these states do not update this field
    ///
    /// ## Security
    ///
    /// last seen times from non-`Responded` peers may be invalid due to
    /// clock skew, or buggy or malicious peers.
    ///
    /// Typically, this field should be ignored, unless the peer is in a
    /// never attempted state.
    pub fn get_untrusted_last_seen(&self) -> DateTime<Utc> {
        self.untrusted_last_seen
    }

    /// The last time we attempted to make a direct outbound connection to the
    /// address of this peer.
    ///
    /// See `PeerAddrState::get_last_attempt` for details.
    pub fn get_last_attempt(&self) -> Option<DateTime<Utc>> {
        self.last_connection_state.get_last_attempt()
    }

    /// The last time we successfully made a direct outbound connection to the
    /// address of this peer.
    ///
    /// See `PeerAddrState::get_last_success` for details.
    pub fn get_last_success(&self) -> Option<DateTime<Utc>> {
        self.last_connection_state.get_last_success()
    }

    /// The last time a direct outbound connection to the address of this peer
    /// failed.
    ///
    /// See `PeerAddrState::get_last_failed` for details.
    pub fn get_last_failed(&self) -> Option<DateTime<Utc>> {
        self.last_connection_state.get_last_failed()
    }

    /// The last time we successfully made a direct outbound connection to this
    /// peer, or another node claimed this peer was valid.
    ///
    /// Clamped to a `u32` number of seconds.
    ///
    /// ## Security
    ///
    /// last seen times from non-`Responded` peers may be invalid due to
    /// clock skew, or buggy or malicious peers.
    ///
    /// Use `get_last_success` if you need a trusted, unclamped value.
    pub fn get_last_success_or_untrusted(&self) -> DateTime<Utc> {
        let seconds = self
            .get_last_success()
            .unwrap_or_else(|| self.get_untrusted_last_seen())
            .timestamp();
        let seconds = seconds.clamp(u32::MIN.into(), u32::MAX.into());

        Utc.timestamp_opt(seconds, 0)
            .single()
            .expect("unexpected invalid time: all u32 values should be valid")
    }

    /// Has this peer ever been attempted?
    pub fn has_been_attempted(&self) -> bool {
        self.get_last_attempt().is_some()
    }

    /// Is this address a directly connected client?
    pub fn is_direct_client(&self) -> bool {
        match self.last_connection_state {
            Responded { .. } => !self.services.contains(PeerServices::NODE_NETWORK),
            NeverAttemptedGossiped
            | NeverAttemptedAlternate
            | Failed { .. }
            | AttemptPending { .. } => false,
        }
    }

    /// Is this address valid for outbound connections?
    pub fn is_valid_for_outbound(&self) -> bool {
        self.services.contains(PeerServices::NODE_NETWORK)
            && !self.addr.ip().is_unspecified()
            && self.addr.port() != 0
    }

    /// Return a sanitized version of this `MetaAddr`, for sending to a remote peer.
    pub fn sanitize(&self) -> MetaAddr {
        let interval = crate::constants::TIMESTAMP_TRUNCATION_SECONDS;
        let ts = self.get_last_success_or_untrusted().timestamp();
        let last_seen_maybe_untrusted = Utc.timestamp(ts - ts.rem_euclid(interval), 0);
        MetaAddr {
            addr: self.addr,
            // services are sanitized during parsing, or set to a fixed valued by
            // new_local_listener, so we don't need to sanitize here
            services: self.services,
            untrusted_last_seen: last_seen_maybe_untrusted,
            // the state isn't sent to the remote peer, but sanitize it anyway
            last_connection_state: NeverAttemptedGossiped,
        }
    }
}

impl Ord for MetaAddr {
    /// `MetaAddr`s are sorted in approximate reconnection attempt order, but
    /// with `Responded` peers sorted first as a group.
    ///
    /// This order should not be used for reconnection attempts: use
    /// [`AddressBook::reconnection_peers`] instead.
    ///
    /// See [`CandidateSet`] for more details.
    fn cmp(&self, other: &Self) -> Ordering {
        use std::net::IpAddr::{V4, V6};
        use Ordering::*;

        let connection_state = self.last_connection_state.cmp(&other.last_connection_state);

        // Try (untrusted) recently seen peers before older peers.
        //
        // # Security
        // Ignore untrusted times if we have any local times.
        let untrusted_last_seen = if matches!(
            (self.last_connection_state, other.last_connection_state),
            (NeverAttemptedGossiped, NeverAttemptedGossiped)
                | (NeverAttemptedAlternate, NeverAttemptedAlternate)
        ) {
            self.get_untrusted_last_seen()
                .cmp(&other.get_untrusted_last_seen())
                .reverse()
        } else {
            Equal
        };

        let ip_numeric = match (self.addr.ip(), other.addr.ip()) {
            (V4(a), V4(b)) => a.octets().cmp(&b.octets()),
            (V6(a), V6(b)) => a.octets().cmp(&b.octets()),
            (V4(_), V6(_)) => Less,
            (V6(_), V4(_)) => Greater,
        };

        connection_state
            .then(untrusted_last_seen)
            // The remainder is meaningless as an ordering, but required so that we
            // have a total order on `MetaAddr` values: self and other must compare
            // as Equal iff they are equal.
            .then(ip_numeric)
            .then(self.addr.port().cmp(&other.addr.port()))
            .then(self.services.bits().cmp(&other.services.bits()))
    }
}

impl PartialOrd for MetaAddr {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for MetaAddr {
    fn eq(&self, other: &Self) -> bool {
        use Ordering::*;
        self.cmp(other) == Equal
    }
}

impl Eq for MetaAddr {}

impl ZcashSerialize for MetaAddr {
    fn zcash_serialize<W: Write>(&self, mut writer: W) -> Result<(), std::io::Error> {
        writer.write_u32::<LittleEndian>(
            self.get_last_success_or_untrusted()
                .timestamp()
                .try_into()
                .expect("time is in range"),
        )?;
        writer.write_u64::<LittleEndian>(self.services.bits())?;
        writer.write_socket_addr(self.addr)?;
        Ok(())
    }
}

impl ZcashDeserialize for MetaAddr {
    fn zcash_deserialize<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
        // This can't panic, because all u32 values are valid `Utc.timestamp`s
        let untrusted_last_seen = Utc.timestamp(reader.read_u32::<LittleEndian>()?.into(), 0);
        let services = PeerServices::from_bits_truncate(reader.read_u64::<LittleEndian>()?);
        let addr = reader.read_socket_addr()?;

        Ok(MetaAddr::new_gossiped_meta_addr(
            &addr,
            &services,
            &untrusted_last_seen,
        ))
    }
}

/// A serialized meta addr has a 4 byte time, 8 byte services, 16 byte IP addr, and 2 byte port
const META_ADDR_SIZE: usize = 4 + 8 + 16 + 2;

impl TrustedPreallocate for MetaAddr {
    fn max_allocation() -> u64 {
        // Since a maximal serialized Vec<MetAddr> uses at least three bytes for its length (2MB  messages / 30B MetaAddr implies the maximal length is much greater than 253)
        // the max allocation can never exceed (MAX_PROTOCOL_MESSAGE_LEN - 3) / META_ADDR_SIZE
        ((MAX_PROTOCOL_MESSAGE_LEN - 3) / META_ADDR_SIZE) as u64
    }
}
