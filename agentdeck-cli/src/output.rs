//! 稳定的输出与退出码契约。E2E 断言对象。
use agentdeck_protocol::IpcMessage;

#[derive(Debug)]
#[allow(dead_code)]
pub enum CliError {
    Usage(String),
    Protocol(String),
    Transport(String),
    Session(String),
}

impl CliError {
    pub fn exit_code(&self) -> i32 {
        match self {
            CliError::Usage(_) => 2,
            CliError::Protocol(_) => 3,
            CliError::Transport(_) => 4,
            CliError::Session(_) => 5,
        }
    }
    pub fn code_str(&self) -> &'static str {
        match self {
            CliError::Usage(_) => "usage",
            CliError::Protocol(_) => "protocol",
            CliError::Transport(_) => "transport",
            CliError::Session(_) => "session",
        }
    }
    pub fn message(&self) -> &str {
        match self {
            CliError::Usage(m) | CliError::Protocol(m) | CliError::Transport(m) | CliError::Session(m) => m,
        }
    }
}

#[allow(dead_code)]
pub fn req(kind: &str, payload: Option<serde_json::Value>) -> IpcMessage {
    IpcMessage { kind: kind.to_string(), id: None, session_id: None, thread_id: None, payload }
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
    }

    #[test]
    fn error_envelope_has_code_and_message() {
        let v = error_envelope(&CliError::Protocol("boom".into()));
        assert_eq!(v["error"]["code"], "protocol");
        assert_eq!(v["error"]["message"], "boom");
    }

    #[test]
    fn req_builds_neutral_message() {
        let m = req("ping", None);
        assert_eq!(m.kind, "ping");
        assert!(m.id.is_none() && m.payload.is_none());
    }
}
