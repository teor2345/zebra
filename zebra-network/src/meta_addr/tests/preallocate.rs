//! Tests for trusted preallocation during deserialization.

use super::super::{MetaAddr, PeerAddrState, PeerServices, META_ADDR_SIZE};

use zebra_chain::serialization::{TrustedPreallocate, ZcashSerialize, MAX_PROTOCOL_MESSAGE_LEN};

use chrono::{TimeZone, Utc};
use std::convert::TryInto;

#[test]
/// Confirm that each MetaAddr takes exactly META_ADDR_SIZE bytes when serialized.
/// This verifies that our calculated `TrustedPreallocate::max_allocation()` is indeed an upper bound.
fn meta_addr_size_is_correct() {
    let addr = MetaAddr {
        addr: ([192, 168, 0, 0], 8333).into(),
        services: PeerServices::default(),
        last_seen: Utc.timestamp(1_573_680_222, 0),
        last_connection_state: PeerAddrState::Responded,
    };
    let serialized = addr
        .zcash_serialize_to_vec()
        .expect("Serialization to vec must succeed");
    assert!(serialized.len() == META_ADDR_SIZE)
}
#[test]
/// Verifies that...
/// 1. The smallest disallowed vector of `MetaAddrs`s is too large to fit in a legal Zcash message
/// 2. The largest allowed vector is small enough to fit in a legal Zcash message
fn meta_addr_max_allocation_is_correct() {
    let addr = MetaAddr {
        addr: ([192, 168, 0, 0], 8333).into(),
        services: PeerServices::default(),
        last_seen: Utc.timestamp(1_573_680_222, 0),
        last_connection_state: PeerAddrState::Responded,
    };
    let max_allocation: usize = MetaAddr::max_allocation().try_into().unwrap();
    let mut smallest_disallowed_vec = Vec::with_capacity(max_allocation + 1);
    for _ in 0..(MetaAddr::max_allocation() + 1) {
        smallest_disallowed_vec.push(addr);
    }
    let smallest_disallowed_serialized = smallest_disallowed_vec
        .zcash_serialize_to_vec()
        .expect("Serialization to vec must succeed");
    // Check that our smallest_disallowed_vec is only one item larger than the limit
    assert!(((smallest_disallowed_vec.len() - 1) as u64) == MetaAddr::max_allocation());
    // Check that our smallest_disallowed_vec is too big to send in a valid Zcash message
    assert!(smallest_disallowed_serialized.len() > MAX_PROTOCOL_MESSAGE_LEN);

    // Create largest_allowed_vec by removing one element from smallest_disallowed_vec without copying (for efficiency)
    smallest_disallowed_vec.pop();
    let largest_allowed_vec = smallest_disallowed_vec;
    let largest_allowed_serialized = largest_allowed_vec
        .zcash_serialize_to_vec()
        .expect("Serialization to vec must succeed");

    // Check that our largest_allowed_vec contains the maximum number of MetaAddrs
    assert!((largest_allowed_vec.len() as u64) == MetaAddr::max_allocation());
    // Check that our largest_allowed_vec is small enough to fit in a Zcash message.
    assert!(largest_allowed_serialized.len() <= MAX_PROTOCOL_MESSAGE_LEN);
}
