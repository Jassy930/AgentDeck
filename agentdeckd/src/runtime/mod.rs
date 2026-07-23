//! Daemon runtime — stdin/stdout loop + per-session lock + worker pool +
//! AgentRouter.

pub(crate) mod adapter_state;
pub(crate) mod approval;
pub mod backfill;
pub mod catalog_snapshot;
mod connection;
mod conversation;
pub(crate) mod conversation_activation;
mod core;
pub mod events;
pub(crate) mod execution;
mod history_receipt;
pub mod hub;
pub mod model;
pub mod namespace;
pub(crate) mod native_metadata;
mod native_projector;
pub(crate) mod pairing_administration;
pub mod process_identity;
#[cfg(debug_assertions)]
#[doc(hidden)]
pub mod production_execution_probe;
pub(crate) mod publication;
mod read_pool;
pub mod recovery;
pub(crate) mod remote_administration;
pub(crate) mod revocation_administration;
pub mod router;
pub mod singleton;
pub mod snapshot;
pub mod store;
pub(crate) mod subscription;
pub mod transfer;
pub(crate) mod transfer_identity;
pub(crate) mod upgrade;

pub use connection::{
    AuthenticatedPrincipal, ConnectionId, ConnectionSink, ConnectionWrite, FlushReceipt,
};
pub(crate) use connection::{ConnectionFramingProfile, EncodedRuntimeFrameKind};
#[cfg(test)]
pub(crate) use conversation::tests::FakeCoordinator;
#[doc(hidden)]
pub use conversation_activation::{ConversationActivationCoordinator, ConversationActivationError};
pub use core::{RecoveryReport, RuntimeCore};
pub(crate) use core::{RemoteIngressReplayClass, RemotePrincipalActivation};
pub use hub::RuntimeHub;
#[doc(hidden)]
pub use pairing_administration::{
    PairingAdministration, PairingAdministrationError, PairingPendingSink,
};
#[doc(hidden)]
pub use revocation_administration::{RevocationAdministration, RevocationAdministrationError};
pub use router::AgentRouter;
