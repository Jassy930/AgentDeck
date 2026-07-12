//! AgentDeck 自托管 Relay v2。
//!
//! Relay 只持有随机 route、授权元数据与 opaque sealed blob；不会接触 daemon、
//! vendor token、会话语义或任何 E2EE 明文。

pub mod config;
pub mod v2;
