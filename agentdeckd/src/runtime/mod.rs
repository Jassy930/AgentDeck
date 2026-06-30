//! Daemon runtime — stdin/stdout loop + per-session lock + worker pool +
//! AgentRouter.

pub mod router;
pub use router::AgentRouter;

// hub.rs references v1 protocol types that Phase 3 will migrate. Gate it
// behind the same feature as the bin so cargo can build/test the lib
// (and the new AgentRouter tests) without forcing hub through compilation.
#[cfg(feature = "daemon-bin")]
pub mod hub;
#[cfg(feature = "daemon-bin")]
pub use hub::RuntimeHub;
