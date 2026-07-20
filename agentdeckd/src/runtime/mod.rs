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
pub(crate) mod execution;
mod history_receipt;
pub mod hub;
pub mod model;
pub mod namespace;
pub(crate) mod native_metadata;
mod native_projector;
pub mod process_identity;
#[cfg(debug_assertions)]
#[doc(hidden)]
pub mod production_execution_probe;
pub(crate) mod publication;
mod read_pool;
pub mod recovery;
pub(crate) mod remote_administration;
pub mod router;
pub mod singleton;
pub mod snapshot;
pub mod store;
pub(crate) mod subscription;
pub mod transfer;
pub(crate) mod upgrade;

pub use connection::{
    AuthenticatedPrincipal, ConnectionId, ConnectionSink, ConnectionWrite, FlushReceipt,
};
#[cfg(test)]
pub(crate) use conversation::tests::FakeCoordinator;
pub use core::{RecoveryReport, RuntimeCore};
pub use hub::RuntimeHub;
pub use router::AgentRouter;
