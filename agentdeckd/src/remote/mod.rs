//! 被控机器远程身份的本地安全基元。
//!
//! P4.1 建立 machine identity、Keychain guard 与 CounterGuard；P4.2 在 active
//! identity 上增加 root-signed certificate、durable enrollment workflow 与远程传输。

pub(crate) mod access;
pub mod bootstrap;
pub mod certificate;
pub mod cleanup;
pub mod config;
pub mod counter;
pub(crate) mod directed_reply;
pub(crate) mod dispatch;
pub mod enrollment;
pub(crate) mod grants;
pub mod identity;
pub(crate) mod key_control;
pub(crate) mod link;
pub(crate) mod maintenance;
pub mod manager;
pub(crate) mod pairing;
pub(crate) mod publication_transport;
pub mod publisher;
pub mod replay;
pub(crate) mod shared_publisher;
pub(crate) mod transition;
pub(crate) mod transition_backend;
pub(crate) mod transition_owner;
pub mod transport;
pub mod trust_reset;
pub mod workflow;

#[cfg(test)]
mod directed_reply_tests;
#[cfg(test)]
mod key_control_tests;
#[cfg(test)]
mod new_device_transition_tests;
#[cfg(test)]
mod p44_remote_link_tests;
#[cfg(test)]
mod p44_remote_transport_tests;
#[cfg(test)]
mod transition_tests;
