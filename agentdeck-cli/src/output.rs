//! 稳定的输出与退出码契约。E2E 断言对象。
//!
//! Exit codes (per spec §README):
//!   0  success
//!   2  usage error
//!   3  protocol error
//!   4  transport error
//!   5  selfcheck / session failure
//!
//! C5 fix (v0.2 final review): the daemon attaches a structured
//! `error.code` to every `ServerEvent::Error` (e.g. `cc-not-installed`,
//! `agent-not-registered`, `session-not-found`). Previously the CLI
//! mapped every session-level failure to the literal string `"session"`,
//! losing the daemon's diagnostic code. `Session` and `Protocol` now
//! carry an optional `code: Option<String>` that, when present,
//! replaces the default discriminator in `error_envelope`. `exit_code`
//! is still derived from the variant kind so the contract `0/2/3/4/5`
//! is preserved.

#[derive(Debug)]
pub enum CliError {
    Usage(String),
    Protocol {
        code: Option<String>,
        message: String,
    },
    Transport {
        code: Option<String>,
        message: String,
    },
    Session {
        code: Option<String>,
        message: String,
    },
    Json(serde_json::Error),
}

impl CliError {
    pub fn exit_code(&self) -> i32 {
        match self {
            CliError::Usage(_) => 2,
            CliError::Protocol { .. } | CliError::Json(_) => 3,
            CliError::Transport { .. } => 4,
            CliError::Session { .. } => 5,
        }
    }
    /// Default discriminator when the daemon did not supply a more
    /// specific `error.code`. Preserved for tests that assert on the
    /// "outer" category string.
    pub fn code_str(&self) -> &'static str {
        match self {
            CliError::Usage(_) => "usage",
            CliError::Protocol { .. } | CliError::Json(_) => "protocol",
            CliError::Transport { .. } => "transport",
            CliError::Session { .. } => "session",
        }
    }
    pub fn message(&self) -> String {
        match self {
            CliError::Usage(m) => m.clone(),
            CliError::Protocol { message, .. }
            | CliError::Transport { message, .. }
            | CliError::Session { message, .. } => message.clone(),
            CliError::Json(e) => format!("JSON error: {e}"),
        }
    }
}

impl From<serde_json::Error> for CliError {
    fn from(e: serde_json::Error) -> Self {
        CliError::Json(e)
    }
}

impl From<std::io::Error> for CliError {
    fn from(e: std::io::Error) -> Self {
        CliError::Transport {
            code: None,
            message: e.to_string(),
        }
    }
}

pub fn render(value: &serde_json::Value, pretty: bool) -> String {
    if pretty {
        serde_json::to_string_pretty(value).expect("json")
    } else {
        serde_json::to_string(value).expect("json")
    }
}

pub fn error_envelope(err: &CliError) -> serde_json::Value {
    let code = match err {
        CliError::Protocol { code: Some(c), .. }
        | CliError::Transport { code: Some(c), .. }
        | CliError::Session { code: Some(c), .. } => c.clone(),
        _ => err.code_str().to_string(),
    };
    serde_json::json!({ "error": { "code": code, "message": err.message() } })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_match_contract() {
        assert_eq!(CliError::Usage("x".into()).exit_code(), 2);
        assert_eq!(
            CliError::Protocol {
                code: None,
                message: "x".into()
            }
            .exit_code(),
            3
        );
        assert_eq!(
            CliError::Transport {
                code: None,
                message: "x".into()
            }
            .exit_code(),
            4
        );
        assert_eq!(
            CliError::Session {
                code: None,
                message: "x".into()
            }
            .exit_code(),
            5
        );
    }

    #[test]
    fn error_envelope_has_code_and_message() {
        let v = error_envelope(&CliError::Protocol {
            code: None,
            message: "boom".into(),
        });
        assert_eq!(v["error"]["code"], "protocol");
        assert_eq!(v["error"]["message"], "boom");
    }

    /// C5 fix: when the daemon attaches a specific `error.code`
    /// (e.g. `cc-not-installed`), the CLI envelope surfaces it
    /// instead of the literal `"session"` discriminator.
    #[test]
    fn error_envelope_propagates_daemon_code() {
        let v = error_envelope(&CliError::Session {
            code: Some("cc-not-installed".into()),
            message: "no claude binary".into(),
        });
        assert_eq!(v["error"]["code"], "cc-not-installed");
        assert_eq!(v["error"]["message"], "no claude binary");
    }

    #[test]
    fn error_envelope_propagates_unix_client_code() {
        let v = error_envelope(&CliError::Transport {
            code: Some("daemon.client.socket_missing".into()),
            message: "canonical socket is absent".into(),
        });
        assert_eq!(v["error"]["code"], "daemon.client.socket_missing");
        assert_eq!(v["error"]["message"], "canonical socket is absent");
    }

    #[test]
    fn exit_for_json_error_is_protocol() {
        let je: serde_json::Error =
            serde_json::from_str::<serde_json::Value>("not json").unwrap_err();
        assert_eq!(CliError::Json(je).exit_code(), 3);
    }
}
