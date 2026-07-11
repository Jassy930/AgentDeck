//! Relay v2 单裁决 Core、连接状态与有界 writer。

mod connection;
mod lifecycle;
mod pair_route;
mod replay;
mod request_route;
mod router;
pub mod writer;

pub use pair_route::PairRouteLimits;
pub use router::{CoreConfig, RelayCore, ReplayTicket, RouteOutcome};
pub use writer::{
    WriterCloseReason, WriterConfig, WriterEnqueueError, WriterFrameClass, WriterHandle,
    WriterReceiver,
};
