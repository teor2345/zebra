use std::{convert::TryInto, io};

use super::{ReadZcashExt, SerializationError};

/// Consensus-critical serialization for Zcash.
///
/// This trait provides a generic deserialization for consensus-critical
/// formats, such as network messages, transactions, blocks, etc. It is intended
/// for use only in consensus-critical contexts; in other contexts, such as
/// internal storage, it would be preferable to use Serde.
pub trait ZcashDeserialize: Sized {
    /// Try to read `self` from the given `reader`.
    ///
    /// This function has a `zcash_` prefix to alert the reader that the
    /// serialization in use is consensus-critical serialization, rather than
    /// some other kind of serialization.
    fn zcash_deserialize<R: io::Read>(reader: R) -> Result<Self, SerializationError>;
}

impl<T: ZcashDeserialize + TrustedPreallocate> ZcashDeserialize for Vec<T> {
    fn zcash_deserialize<R: io::Read>(mut reader: R) -> Result<Self, SerializationError> {
        let len = reader.read_compactsize()?;
        if len > T::max_allocation() {
            return Err(SerializationError::Parse(
                "Vector longer than max_allocation",
            ));
        }
        let mut vec = Vec::with_capacity(len.try_into()?);
        for _ in 0..len {
            vec.push(T::zcash_deserialize(&mut reader)?);
        }
        Ok(vec)
    }
}

/// Helper for deserializing more succinctly via type inference
pub trait ZcashDeserializeInto {
    /// Deserialize based on type inference
    fn zcash_deserialize_into<T>(self) -> Result<T, SerializationError>
    where
        T: ZcashDeserialize;
}

impl<R: io::Read> ZcashDeserializeInto for R {
    fn zcash_deserialize_into<T>(self) -> Result<T, SerializationError>
    where
        T: ZcashDeserialize,
    {
        T::zcash_deserialize(self)
    }
}

/// Blind preallocation of a Vec<T: TrustedPreallocate> is based on a bounded length. This is in contrast
/// to blind preallocation of a generic Vec<T>, which is a DOS vector.
///
/// The max_allocation() function provides a loose upper bound on the size of the Vec<T: TrustedPreallocate>
/// which can possibly be received from an honest peer. If this limit is too low, Zebra may reject valid messages.
/// In the worst case, setting the lower bound too low could cause Zebra to fall out of consensus by rejecting all messages containing a valid block.
pub trait TrustedPreallocate {
    /// Provides a ***loose upper bound*** on the size of the Vec<T: TrustedPreallocate>
    /// which can possibly be received from an honest peer.
    fn max_allocation() -> u64;
}
