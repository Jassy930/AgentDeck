//! 被控机器远程身份的本地安全基元。
//!
//! P4.1 只建立 machine identity、Keychain guard 与 CounterGuard；网络、配对、
//! certificate 和 enrollment 由后续 Task 拥有。

pub mod identity;
