//! Relay v2 本机管理面。
//!
//! inventory、readback、purge 与 enrollment code 创建只允许通过 Relay host 本机
//! 0600 Unix domain socket；公网 listener 永远不暴露这些命令。

pub mod client;
pub mod command;
pub mod protocol;
pub mod server;

pub use client::{AdminClient, AdminClientError};
pub use command::{AdminCommandExecutor, AdminRuntimeConfig};
pub use protocol::{
    AdminFailure, AdminRequest, AdminResponse, AdminResult, Digest32, EnrollmentBundleV2,
};
pub use server::{AdminServer, AdminServerError};
