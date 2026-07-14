//! Daemon runtime — stdin/stdout loop + per-session lock + worker pool +
//! AgentRouter.

pub(crate) mod adapter_state;
pub(crate) mod approval;
pub mod backfill;
pub mod catalog_snapshot;
mod connection;
mod conversation;
mod core;
pub mod events;
mod execution;
pub mod hub;
pub mod model;
pub mod namespace;
pub(crate) mod publication;
mod read_pool;
pub mod router;
pub mod singleton;
pub mod snapshot;
pub mod store;
pub(crate) mod subscription;
pub mod transfer;

pub use connection::{
    AuthenticatedPrincipal, ConnectionId, ConnectionSink, ConnectionWrite, FlushReceipt,
};
pub use core::{RecoveryReport, RuntimeCore};
pub use hub::RuntimeHub;
pub use router::AgentRouter;
