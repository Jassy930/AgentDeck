//! Daemon runtime — stdin/stdout loop + per-session lock + worker pool +
//! AgentRouter.

pub mod hub;
pub mod model;
pub mod namespace;
pub mod router;
pub mod singleton;
pub mod store;

pub use hub::RuntimeHub;
pub use router::AgentRouter;
