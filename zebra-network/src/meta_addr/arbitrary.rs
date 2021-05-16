use chrono::{Duration, TimeZone, Utc, MAX_DATETIME, MIN_DATETIME};
use lazy_static::lazy_static;
use proptest::{arbitrary::any, arbitrary::Arbitrary, prelude::*};

use std::net::SocketAddr;

use super::{MetaAddr, PeerAddrState, PeerServices};

impl Arbitrary for MetaAddr {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (
            any::<SocketAddr>(),
            any::<PeerServices>(),
            any::<u32>(),
            any::<PeerAddrState>(),
        )
            .prop_map(
                |(addr, services, untrusted_last_seen, last_connection_state)| MetaAddr {
                    addr,
                    services,
                    // This can't panic, because all u32 values are valid `Utc.timestamp`s
                    untrusted_last_seen: Utc.timestamp(untrusted_last_seen.into(), 0),
                    last_connection_state,
                },
            )
            .boxed()
    }

    type Strategy = BoxedStrategy<Self>;
}

lazy_static! {
    pub static ref DATETIME_RANGE: i64 = (MAX_DATETIME - MIN_DATETIME).num_seconds();
}

impl Arbitrary for PeerAddrState {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use PeerAddrState::*;

        (
            (0..5),
            (0..=*DATETIME_RANGE),
            (0..=*DATETIME_RANGE),
            any::<bool>(),
            (0..=*DATETIME_RANGE),
            any::<bool>(),
        )
            .prop_map(
                |(variant, last_attempt, last_success, none_success, last_failed, none_failed)| {
                    let last_attempt = MIN_DATETIME + Duration::seconds(last_attempt);
                    let last_success = MIN_DATETIME + Duration::seconds(last_success);
                    let last_failed = MIN_DATETIME + Duration::seconds(last_failed);

                    match variant {
                        0 => NeverAttemptedGossiped,
                        1 => NeverAttemptedAlternate,
                        2 => AttemptPending {
                            last_attempt,
                            last_success: if none_success {
                                None
                            } else {
                                Some(last_success)
                            },
                            last_failed: if none_failed { None } else { Some(last_failed) },
                        },
                        3 => Responded {
                            last_attempt,
                            last_success,
                            last_failed: if none_failed { None } else { Some(last_failed) },
                        },
                        4 => Failed {
                            last_attempt,
                            last_success: if none_success {
                                None
                            } else {
                                Some(last_success)
                            },
                            last_failed,
                        },
                        _ => unreachable!("there is one index per variant"),
                    }
                },
            )
            .boxed()
    }

    type Strategy = BoxedStrategy<Self>;
}
