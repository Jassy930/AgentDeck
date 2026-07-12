//! Daemon runtime — stdin/stdout loop + per-session lock + worker pool +
//! AgentRouter.

pub(crate) mod adapter_state;
mod connection;
mod conversation;
mod core;
mod execution;
pub mod hub;
pub mod model;
pub mod namespace;
mod read_pool;
pub mod router;
pub mod singleton;
pub mod store;

pub use connection::{AuthenticatedPrincipal, ConnectionId, ConnectionSink, ConnectionWrite};
pub use core::{RecoveryReport, RuntimeCore};
pub use hub::RuntimeHub;
pub use router::AgentRouter;
