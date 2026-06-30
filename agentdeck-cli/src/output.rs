//! 稳定的输出与退出码契约。E2E 断言对象。
//!
//! Exit codes (per spec §README):
//!   0  success
//!   2  usage error
//!   3  protocol error
//!   4  transport error
//!   5  selfcheck / session failure

#[derive(Debug)]
pub enum CliError {
    Usage(String),
    Protocol(String),
    Transport(String),
    Session(String),
    Json(serde_json::Error),
    NoResponse,
}

impl CliError {
    pub fn exit_code(&self) -> i32 {
        match self {
            CliError::Usage(_) => 2,
            CliError::Protocol(_) | CliError::Json(_) | CliError::NoResponse => 3,
            CliError::Transport(_) => 4,
            CliError::Session(_) => 5,
        }
    }
    pub fn code_str(&self) -> &'static str {
        match self {
            CliError::Usage(_) => "usage",
            CliError::Protocol(_) | CliError::Json(_) | CliError::NoResponse => "protocol",
            CliError::Transport(_) => "transport",
            CliError::Session(_) => "session",
        }
    }
    pub fn message(&self) -> String {
        match self {
            CliError::Usage(m) | CliError::Protocol(m) | CliError::Transport(m) | CliError::Session(m) => m.clone(),
            CliError::Json(e) => format!("JSON error: {e}"),
            CliError::NoResponse => "daemon closed without response".to_string(),
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
        CliError::Transport(e.to_string())
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
    serde_json::json!({ "error": { "code": err.code_str(), "message": err.message() } })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_match_contract() {
        assert_eq!(CliError::Usage("x".into()).exit_code(), 2);
        assert_eq!(CliError::Protocol("x".into()).exit_code(), 3);
        assert_eq!(CliError::Transport("x".into()).exit_code(), 4);
        assert_eq!(CliError::Session("x".into()).exit_code(), 5);
        assert_eq!(CliError::NoResponse.exit_code(), 3);
    }

    #[test]
    fn error_envelope_has_code_and_message() {
        let v = error_envelope(&CliError::Protocol("boom".into()));
        assert_eq!(v["error"]["code"], "protocol");
        assert_eq!(v["error"]["message"], "boom");
    }

    #[test]
    fn exit_for_json_error_is_protocol() {
        let je: serde_json::Error = serde_json::from_str::<serde_json::Value>("not json").unwrap_err();
        assert_eq!(CliError::Json(je).exit_code(), 3);
    }
}
