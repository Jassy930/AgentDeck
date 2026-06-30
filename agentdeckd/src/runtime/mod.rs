//! Daemon runtime — stdin/stdout loop + per-session lock + worker pool +
//! AgentRouter.

pub mod hub;
pub mod router;

pub use hub::RuntimeHub;
pub use router::AgentRouter;
