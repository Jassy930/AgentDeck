//! Daemon runtime — stdin/stdout loop + per-session lock + worker pool +
//! AgentRouter (T2.4).

pub mod hub;
pub mod router;

pub use hub::RuntimeHub;
pub use router::AgentRouter;
