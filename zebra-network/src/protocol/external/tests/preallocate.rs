//! Tests for trusted preallocation during deserialization.

use super::super::inv::{InventoryHash, INV_HASH_SIZE};

use zebra_chain::{
    block,
    serialization::{TrustedPreallocate, ZcashSerialize, MAX_PROTOCOL_MESSAGE_LEN},
    transaction,
};

use std::convert::TryInto;

#[test]
/// Confirm that each InventoryHash takes exactly INV_HASH_SIZE bytes when serialized.
/// This verifies that our calculated `TrustedPreallocate::max_allocation()` is indeed an upper bound.
fn inv_hash_size_is_correct() {
    let block_hash = block::Hash([1u8; 32]);
    let tx_hash = transaction::Hash([1u8; 32]);
    let inv_block = InventoryHash::Block(block_hash);
    let serialized_inv_block = inv_block
        .zcash_serialize_to_vec()
        .expect("Serialization to vec must succeed");
    assert!(serialized_inv_block.len() == INV_HASH_SIZE);

    let inv_filtered_block = InventoryHash::FilteredBlock(block_hash);
    let serialized_inv_filtered = inv_filtered_block
        .zcash_serialize_to_vec()
        .expect("Serialization to vec must succeed");
    assert!(serialized_inv_filtered.len() == INV_HASH_SIZE);

    let inv_tx = InventoryHash::Tx(tx_hash);
    let serialized_inv_tx = inv_tx
        .zcash_serialize_to_vec()
        .expect("Serialization to vec must succeed");
    assert!(serialized_inv_tx.len() == INV_HASH_SIZE);

    let inv_err = InventoryHash::Error;
    let serializd_inv_err = inv_err
        .zcash_serialize_to_vec()
        .expect("Serialization to vec must succeed");
    assert!(serializd_inv_err.len() == INV_HASH_SIZE)
}
#[test]
/// Verifies that...
/// 1. The smallest disallowed vector of `InventoryHash`s is too large to fit in a legal Zcash message
/// 2. The largest allowed vector is small enough to fit in a legal Zcash message
fn meta_addr_max_allocation_is_correct() {
    let inv = InventoryHash::Error;
    let max_allocation: usize = InventoryHash::max_allocation().try_into().unwrap();
    let mut smallest_disallowed_vec = Vec::with_capacity(max_allocation + 1);
    for _ in 0..(InventoryHash::max_allocation() + 1) {
        smallest_disallowed_vec.push(inv);
    }
    let smallest_disallowed_serialized = smallest_disallowed_vec
        .zcash_serialize_to_vec()
        .expect("Serialization to vec must succeed");
    // Check that our smallest_disallowed_vec is only one item larger than the limit
    assert!(((smallest_disallowed_vec.len() - 1) as u64) == InventoryHash::max_allocation());
    // Check that our smallest_disallowed_vec is too big to fit in a Zcash message.
    assert!(smallest_disallowed_serialized.len() > MAX_PROTOCOL_MESSAGE_LEN);

    // Create largest_allowed_vec by removing one element from smallest_disallowed_vec without copying (for efficiency)
    smallest_disallowed_vec.pop();
    let largest_allowed_vec = smallest_disallowed_vec;
    let largest_allowed_serialized = largest_allowed_vec
        .zcash_serialize_to_vec()
        .expect("Serialization to vec must succeed");

    // Check that our largest_allowed_vec contains the maximum number of InventoryHashes
    assert!((largest_allowed_vec.len() as u64) == InventoryHash::max_allocation());
    // Check that our largest_allowed_vec is small enough to fit in a Zcash message.
    assert!(largest_allowed_serialized.len() <= MAX_PROTOCOL_MESSAGE_LEN);
}
