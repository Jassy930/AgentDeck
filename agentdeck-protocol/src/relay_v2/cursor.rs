//! Relay v2 复用 Runtime 的中立 [`StreamCursor`]（design §9.1）。
//!
//! wire/Swift/Rust 统一使用 `BeforeFirst | At(u64)`，绝不把 SQLite `-1` 编进
//! unsigned wire；`Subscribe(BeforeFirst)` 表示从 frame 0 开始。P1.1 已在
//! `runtime::sync` 定义该类型，这里 re-export 以保证外层/内层 cursor 语义单一来源。

pub use crate::runtime::sync::StreamCursor;
