//! same-UID 本地 Runtime v1 传输的协议原语。
//!
//! 本模块只承载 transport-neutral framing 与 peer 身份门禁；production socket
//! pathname、bind/readiness 和连接生命周期由 `local::unix` 接线层负责。

pub(crate) mod framing;
pub(crate) mod peer;
pub mod unix;
