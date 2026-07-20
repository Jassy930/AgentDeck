//! 被控机器远程身份的本地安全基元。
//!
//! P4.1 建立 machine identity、Keychain guard 与 CounterGuard；P4.2 在 active
//! identity 上增加 root-signed certificate、durable enrollment workflow 与远程传输。

pub(crate) mod access;
pub mod bootstrap;
pub mod certificate;
pub mod cleanup;
pub mod config;
pub mod enrollment;
pub(crate) mod grants;
pub mod identity;
pub mod manager;
pub(crate) mod pairing;
pub mod transport;
pub mod trust_reset;
pub mod workflow;
