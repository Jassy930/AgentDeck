//! same-UID 本地 Runtime v3 传输的协议原语。
//!
//! framing/peer/unix 承载单连接协议原语；production pathname bind/readiness 与
//! supervisor 由 `listener` 负责，显式测试兼容入口由 `stdio_compat` 负责。

pub(crate) mod framing;
pub mod listener;
pub(crate) mod peer;
pub mod stdio_compat;
pub mod unix;
