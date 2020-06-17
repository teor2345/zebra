//! Block verification and chain state updates for Zebra.
//!
//! Verification occurs in multiple stages:
//!   - getting blocks (disk- or network-bound)
//!   - context-free verification of signatures, proofs, and scripts (CPU-bound)
//!   - context-dependent verification of the chain state (awaits a verified parent block)
//!
//! Verification is provided via a `tower::Service`, to support backpressure and batch
//! verification.

use futures_util::FutureExt;
use std::{
    error,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tower::{buffer::Buffer, Service};

use zebra_chain::block::{Block, BlockHeaderHash};

mod script;
mod transaction;

struct BlockVerifier<S> {
    state_service: S,
}

/// The error type for the BlockVerifier Service.
// TODO(jlusby): Error = Report ?
type Error = Box<dyn error::Error + Send + Sync + 'static>;

/// Block validity checks
mod block {
    use super::Error;

    use chrono::{DateTime, Duration, Utc};
    use std::sync::Arc;

    use zebra_chain::block::Block;

    /// Helper function for `node_time_check()`, see that function for details.
    fn node_time_check_helper(
        block_header_time: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<(), Error> {
        let two_hours_in_the_future = now
            .checked_add_signed(Duration::hours(2))
            .ok_or("overflow when calculating 2 hours in the future")?;

        if block_header_time <= two_hours_in_the_future {
            Ok(())
        } else {
            Err("block header time is more than 2 hours in the future".into())
        }
    }

    /// Check if the block header time is less than or equal to
    /// 2 hours in the future, according to the node's local clock.
    ///
    /// This is a non-deterministic rule, as clocks vary over time, and
    /// between different nodes.
    ///
    /// "In addition, a full validator MUST NOT accept blocks with nTime
    /// more than two hours in the future according to its clock. This
    /// is not strictly a consensus rule because it is nondeterministic,
    /// and clock time varies between nodes. Also note that a block that
    /// is rejected by this rule at a given point in time may later be
    /// accepted."[S 7.5][7.5]
    ///
    /// [7.5]: https://zips.z.cash/protocol/protocol.pdf#blockheader
    pub(super) fn node_time_check(block: Arc<Block>) -> Result<(), Error> {
        node_time_check_helper(block.header.time, Utc::now())
    }
}

/// The BlockVerifier service implementation.
///
/// After verification, blocks are added to the underlying state service.
impl<S> Service<Arc<Block>> for BlockVerifier<S>
where
    S: Service<zebra_state::Request, Response = zebra_state::Response, Error = Error>,
    S::Future: Send + 'static,
{
    type Response = BlockHeaderHash;
    type Error = Error;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.state_service.poll_ready(context)
    }

    fn call(&mut self, block: Arc<Block>) -> Self::Future {
        // TODO(jlusby): Error = Report, handle errors from state_service.
        // TODO(teor):
        //   - handle chain reorgs
        //   - adjust state_service "unique block height" conditions
        //   - move expensive checks into the async block

        // Create an AddBlock Future, but don't run it yet.
        //
        // `state_service.call` is OK here because we already called
        // `state_service.poll_ready` in our `poll_ready`.
        //
        // `tower::Buffer` expects exactly one `call` for each
        // `poll_ready`. So we unconditionally create the AddBlock
        // Future using `state_service.call`. If verification fails,
        // we return an error, and implicitly cancel the future.
        let add_block = self.state_service.call(zebra_state::Request::AddBlock {
            block: block.clone(),
        });

        async move {
            // If verification fails, return an error result.
            // The AddBlock Future is implicitly cancelled by the
            // error return in `?`.

            // Since errors cause an early exit, try to do the
            // quick checks first.
            block::node_time_check(block)?;

            // Verification was successful.
            // Add the block to the state by awaiting the AddBlock
            // Future, and return its result.
            match add_block.await? {
                zebra_state::Response::Added { hash } => Ok(hash),
                _ => Err("adding block to zebra-state failed".into()),
            }
        }
        .boxed()
    }
}

/// Return a block verification service, using the provided state service.
///
/// The block verifier holds a state service of type `S`, used as context for
/// block validation and to which newly verified blocks will be committed. This
/// state is pluggable to allow for testing or instrumentation.
///
/// The returned type is opaque to allow instrumentation or other wrappers, but
/// can be boxed for storage. It is also `Clone` to allow sharing of a
/// verification service.
///
/// This function should be called only once for a particular state service (and
/// the result be shared) rather than constructing multiple verification services
/// backed by the same state layer.
pub fn init<S>(
    state_service: S,
) -> impl Service<
    Arc<Block>,
    Response = BlockHeaderHash,
    Error = Error,
    Future = impl Future<Output = Result<BlockHeaderHash, Error>>,
> + Send
       + Clone
       + 'static
where
    S: Service<zebra_state::Request, Response = zebra_state::Response, Error = Error>
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    Buffer::new(BlockVerifier { state_service }, 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use color_eyre::eyre::Report;
    use color_eyre::eyre::{bail, ensure, eyre};
    use tower::{util::ServiceExt, Service};
    use zebra_chain::serialization::ZcashDeserialize;

    fn install_tracing() {
        use tracing_error::ErrorLayer;
        use tracing_subscriber::prelude::*;
        use tracing_subscriber::{fmt, EnvFilter};

        let fmt_layer = fmt::layer().with_target(false);
        let filter_layer = EnvFilter::try_from_default_env()
            .or_else(|_| EnvFilter::try_new("info"))
            .unwrap();

        tracing_subscriber::registry()
            .with(filter_layer)
            .with(fmt_layer)
            .with(ErrorLayer::default())
            .init();
    }

    #[tokio::test]
    #[spandoc::spandoc]
    async fn verify() -> Result<(), Report> {
        let block =
            Arc::<Block>::zcash_deserialize(&zebra_test::vectors::BLOCK_MAINNET_415000_BYTES[..])?;
        let hash: BlockHeaderHash = block.as_ref().into();

        let state_service = Box::new(zebra_state::in_memory::init());
        let mut block_verifier = super::init(state_service);

        let verify_response = block_verifier
            .ready_and()
            .await
            .map_err(|e| eyre!(e))?
            .call(block.clone())
            .await
            .map_err(|e| eyre!(e))?;

        ensure!(
            verify_response == hash,
            "unexpected response kind: {:?}",
            verify_response
        );

        Ok(())
    }

    #[tokio::test]
    #[spandoc::spandoc]
    async fn round_trip() -> Result<(), Report> {
        let block =
            Arc::<Block>::zcash_deserialize(&zebra_test::vectors::BLOCK_MAINNET_415000_BYTES[..])?;
        let hash: BlockHeaderHash = block.as_ref().into();

        let mut state_service = zebra_state::in_memory::init();
        let mut block_verifier = super::init(state_service.clone());

        let verify_response = block_verifier
            .ready_and()
            .await
            .map_err(|e| eyre!(e))?
            .call(block.clone())
            .await
            .map_err(|e| eyre!(e))?;

        ensure!(
            verify_response == hash,
            "unexpected response kind: {:?}",
            verify_response
        );

        let state_response = state_service
            .ready_and()
            .await
            .map_err(|e| eyre!(e))?
            .call(zebra_state::Request::GetBlock { hash })
            .await
            .map_err(|e| eyre!(e))?;

        match state_response {
            zebra_state::Response::Block {
                block: returned_block,
            } => assert_eq!(block, returned_block),
            _ => bail!("unexpected response kind: {:?}", state_response),
        }

        Ok(())
    }

    #[tokio::test]
    #[spandoc::spandoc]
    async fn verify_fail_add_block() -> Result<(), Report> {
        install_tracing();

        let block =
            Arc::<Block>::zcash_deserialize(&zebra_test::vectors::BLOCK_MAINNET_415000_BYTES[..])?;
        let hash: BlockHeaderHash = block.as_ref().into();

        let mut state_service = zebra_state::in_memory::init();
        let mut block_verifier = super::init(state_service.clone());

        // Add the block for the first time
        let verify_response = block_verifier
            .ready_and()
            .await
            .map_err(|e| eyre!(e))?
            .call(block.clone())
            .await
            .map_err(|e| eyre!(e))?;

        ensure!(
            verify_response == hash,
            "unexpected response kind: {:?}",
            verify_response
        );

        let state_response = state_service
            .ready_and()
            .await
            .map_err(|e| eyre!(e))?
            .call(zebra_state::Request::GetBlock { hash })
            .await
            .map_err(|e| eyre!(e))?;

        match state_response {
            zebra_state::Response::Block {
                block: returned_block,
            } => assert_eq!(block, returned_block),
            _ => bail!("unexpected response kind: {:?}", state_response),
        }

        // Now try to add the block again, verify should fail
        // TODO(teor): ignore duplicate block verifies?
        let verify_result = block_verifier
            .ready_and()
            .await
            .map_err(|e| eyre!(e))?
            .call(block.clone())
            .await;

        ensure!(
            match verify_result {
                Ok(_) => false,
                // TODO(teor || jlusby): check error string
                _ => true,
            },
            "unexpected result kind: {:?}",
            verify_result
        );

        // But the state should still return the original block we added
        let state_response = state_service
            .ready_and()
            .await
            .map_err(|e| eyre!(e))?
            .call(zebra_state::Request::GetBlock { hash })
            .await
            .map_err(|e| eyre!(e))?;

        match state_response {
            zebra_state::Response::Block {
                block: returned_block,
            } => assert_eq!(block, returned_block),
            _ => bail!("unexpected response kind: {:?}", state_response),
        }

        Ok(())
    }
}
