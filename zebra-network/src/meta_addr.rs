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

    /// We just started a connection attempt to this peer.
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
    pub addr: SocketAddr,

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
    pub services: PeerServices,

    /// The last time another node claimed this peer was valid.
    ///
    /// See `get_untrusted_last_seen` for details.
    untrusted_last_seen: DateTime<Utc>,

    /// The outcome of our most recent direct outbound connection to this peer.
    pub last_connection_state: PeerAddrState,
}

impl MetaAddr {
    /// Create a new `MetaAddr` from the deserialized fields in a gossiped
    /// peer `Addr` message.
    pub fn new_gossiped(
        addr: &SocketAddr,
        services: &PeerServices,
        untrusted_last_seen: &DateTime<Utc>,
    ) -> MetaAddr {
        MetaAddr {
            addr: *addr,
            services: *services,
            untrusted_last_seen: *untrusted_last_seen,
            // the state is Zebra-specific, it isn't part of the Zcash network protocol
            last_connection_state: NeverAttemptedGossiped,
        }
    }

    /// Create a new `MetaAddr` for a peer that has just `Responded`.
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
    pub fn new_responded(addr: &SocketAddr, services: &PeerServices) -> MetaAddr {
        MetaAddr {
            addr: *addr,
            services: *services,
            untrusted_last_seen: (),
            last_connection_state: Responded {
                last_attempt: (),
                last_success: Utc::now(),
                last_failed: (),
            },
        }
    }

    /// Create a new `MetaAddr` for a peer that we want to reconnect to.
    pub fn new_reconnect(addr: &SocketAddr, services: &PeerServices) -> MetaAddr {
        MetaAddr {
            addr: *addr,
            services: (),
            untrusted_last_seen: (),
            last_connection_state: AttemptPending {
                last_attempt: Utc::now(),
                last_success: (),
                last_failed: (),
            },
        }
    }

    /// Create a new `MetaAddr` for a peer's alternate address, received via a
    /// `Version` message.
    pub fn new_alternate(addr: &SocketAddr, services: &PeerServices) -> MetaAddr {
        MetaAddr {
            addr: *addr,
            services: *services,
            untrusted_last_seen: Utc::now(),
            last_connection_state: NeverAttemptedAlternate,
        }
    }

    /// Create a new `MetaAddr` for a peer that has just had an error.
    pub fn new_errored(addr: &SocketAddr, services: &PeerServices) -> MetaAddr {
        MetaAddr {
            addr: *addr,
            services: (),
            untrusted_last_seen: (),
            last_connection_state: Failed {
                last_attempt: (),
                last_success: (),
                last_failed: Utc::now(),
            },
        }
    }

    /// Create a new `MetaAddr` for a peer that has just shut down.
    pub fn new_shutdown(addr: &SocketAddr, services: &PeerServices) -> MetaAddr {
        // TODO: should we preserve the state of `Responded` peers that shut down?
        MetaAddr::new_errored(addr, services)
    }

    /// Create a new `MetaAddr` for our own listener address.
    pub fn new_local_listener(addr: &SocketAddr) -> MetaAddr {
        MetaAddr {
            addr: *addr,
            // TODO: create a "local services" constant
            services: PeerServices::NODE_NETWORK,
            untrusted_last_seen: Utc::now(),
            last_connection_state: Responded {
                last_attempt: Utc::now(),
                last_success: Utc::now(),
                last_failed: None,
            },
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
            .expect("all u32 values are valid")
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

        Ok(MetaAddr::new_gossiped(
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
