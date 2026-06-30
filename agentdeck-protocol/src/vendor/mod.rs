//! Layer B — vendor namespace. Types here MAY contain vendor names
//! and vendor-specific fields (sandbox modes, permission modes, etc).
//! Strongly typed: no `serde_json::Value` passthrough allowed.

pub mod codex;
pub mod claude_code;
