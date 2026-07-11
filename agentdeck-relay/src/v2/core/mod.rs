//! Relay v2 单裁决 Core、连接状态与有界 writer。

mod connection;
mod lifecycle;
mod replay;
mod router;
pub mod writer;

pub use router::{CoreConfig, RelayCore, ReplayTicket, RouteOutcome};
pub use writer::{
    WriterCloseReason, WriterConfig, WriterEnqueueError, WriterFrameClass, WriterHandle,
    WriterReceiver,
};
