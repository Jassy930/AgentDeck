use crate::output::CliError;
use crate::transport::Transport;
use agentdeck_protocol::IpcMessage;

pub struct Client<T: Transport> {
    transport: T,
    next_id: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalPolicy {
    Prompt,
    AutoApprove,
    AutoDeny,
}

impl<T: Transport> Client<T> {
    pub fn new(transport: T) -> Self {
        Self { transport, next_id: 1000 }
    }

    fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    pub fn round_trip(&mut self, mut req: IpcMessage) -> Result<IpcMessage, CliError> {
        let id = self.alloc_id();
        req.id = Some(id);
        self.transport.send(&req).map_err(|e| CliError::Transport(e.to_string()))?;
        loop {
            match self.transport.recv().map_err(|e| CliError::Transport(e.to_string()))? {
                None => return Err(CliError::Transport("agentdeckd disconnected".into())),
                Some(msg) if msg.id == Some(id) => return Ok(msg),
                Some(_) => continue, // 忽略无关帧
            }
        }
    }

    pub fn expect_kind(reply: IpcMessage, expected: &str) -> Result<serde_json::Value, CliError> {
        if reply.kind == expected {
            return Ok(reply.payload.unwrap_or(serde_json::Value::Null));
        }
        if reply.kind == "error" {
            let msg = reply.payload.as_ref()
                .and_then(|p| p.get("message"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error")
                .to_string();
            return Err(CliError::Protocol(msg));
        }
        Err(CliError::Protocol(format!("expected {expected}, got {}", reply.kind)))
    }

    pub fn run_stream(
        &mut self,
        mut req: IpcMessage,
        session_id: &str,
        policy: ApprovalPolicy,
        emit: &mut dyn FnMut(&serde_json::Value),
    ) -> Result<(), CliError> {
        let id = self.alloc_id();
        req.id = Some(id);
        req.session_id = Some(session_id.to_string());
        self.transport.send(&req).map_err(|e| CliError::Transport(e.to_string()))?;

        loop {
            let msg = match self.transport.recv().map_err(|e| CliError::Transport(e.to_string()))? {
                None => return Err(CliError::Transport("agentdeckd disconnected mid-session".into())),
                Some(m) => m,
            };
            if msg.id == Some(id) {
                if msg.kind == "turnAccepted" {
                    continue;
                }
                if msg.kind == "error" {
                    let m = msg.payload.as_ref()
                        .and_then(|p| p.get("message")).and_then(|v| v.as_str())
                        .unwrap_or("session rejected").to_string();
                    return Err(CliError::Protocol(m));
                }
            }
            if msg.kind != "session/event" {
                continue;
            }
            let Some(inner) = msg.payload.as_ref().and_then(|p| p.get("event")).cloned() else {
                continue;
            };
            emit(&inner);
            let inner_kind = inner.get("kind").and_then(|v| v.as_str()).unwrap_or("");
            match inner_kind {
                "actionRequest" => {
                    let request_id = inner.get("payload")
                        .and_then(|p| p.get("requestId"))
                        .and_then(|v| v.as_u64())
                        .ok_or_else(|| CliError::Protocol("actionRequest missing requestId".into()))?;
                    let decision = self.decide(policy, request_id)?;
                    let did = self.alloc_id();
                    let dec = IpcMessage {
                        kind: "actionDecision".into(),
                        id: Some(did),
                        session_id: Some(session_id.to_string()),
                        thread_id: None,
                        payload: Some(serde_json::json!({ "requestId": request_id, "decision": decision })),
                    };
                    self.transport.send(&dec).map_err(|e| CliError::Transport(e.to_string()))?;
                }
                "turnComplete" => return Ok(()),
                "error" => {
                    let m = inner.get("payload")
                        .and_then(|p| p.get("message")).and_then(|v| v.as_str())
                        .unwrap_or("session failed").to_string();
                    return Err(CliError::Session(m));
                }
                _ => continue,
            }
        }
    }

    fn decide(&self, policy: ApprovalPolicy, _request_id: u64) -> Result<String, CliError> {
        match policy {
            ApprovalPolicy::AutoApprove => Ok("approve".into()),
            ApprovalPolicy::AutoDeny => Ok("deny".into()),
            ApprovalPolicy::Prompt => {
                use std::io::BufRead;
                let stdin = std::io::stdin();
                let mut line = String::new();
                stdin.lock().read_line(&mut line).map_err(|e| CliError::Transport(e.to_string()))?;
                let v: serde_json::Value = serde_json::from_str(line.trim())
                    .map_err(|e| CliError::Usage(format!("invalid decision line: {e}")))?;
                let d = v.get("decision").and_then(|x| x.as_str()).unwrap_or("");
                match d {
                    "approve" | "deny" | "cancel" => Ok(d.to_string()),
                    _ => Err(CliError::Usage("decision must be approve|deny|cancel".into())),
                }
            }
        }
    }
}

#[cfg(test)]
pub trait IntoSent {
    fn into_sent(self) -> Vec<IpcMessage>;
}

#[cfg(test)]
impl IntoSent for crate::transport::FakeTransport {
    fn into_sent(self) -> Vec<IpcMessage> {
        self.sent
    }
}

#[cfg(test)]
impl<T: Transport + IntoSent> Client<T> {
    fn into_sent(self) -> Vec<IpcMessage> {
        self.transport.into_sent()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::FakeTransport;

    fn msg(kind: &str, id: Option<u64>, payload: Option<serde_json::Value>) -> IpcMessage {
        IpcMessage { kind: kind.into(), id, session_id: None, thread_id: None, payload }
    }

    fn session_event(inner: serde_json::Value) -> IpcMessage {
        IpcMessage {
            kind: "session/event".into(),
            id: None,
            session_id: Some("cli-1".into()),
            thread_id: None,
            payload: Some(serde_json::json!({ "event": inner })),
        }
    }

    #[test]
    fn round_trip_matches_reply_by_id_and_skips_strays() {
        // 第一帧 id 不匹配（stray），第二帧匹配分配的 id 1000。
        let t = FakeTransport::new(vec![
            msg("noise", Some(1), None),
            msg("pong", Some(1000), None),
        ]);
        let mut client = Client::new(t);
        let reply = client.round_trip(msg("ping", None, None)).unwrap();
        assert_eq!(reply.kind, "pong");
        assert_eq!(reply.id, Some(1000));
    }

    #[test]
    fn round_trip_disconnect_is_transport_error() {
        let t = FakeTransport::new(vec![]); // 立即 EOF
        let mut client = Client::new(t);
        let err = client.round_trip(msg("ping", None, None)).unwrap_err();
        assert_eq!(err.exit_code(), 4);
    }

    #[test]
    fn expect_kind_maps_error_frame_to_protocol_error() {
        let reply = msg("error", Some(1000), Some(serde_json::json!({"message": "boom"})));
        let err = Client::<FakeTransport>::expect_kind(reply, "pong").unwrap_err();
        assert_eq!(err.exit_code(), 3);
        assert_eq!(err.message(), "boom");
    }

    #[test]
    fn run_stream_auto_approve_sends_decision_and_completes() {
        let t = FakeTransport::new(vec![
            msg("turnAccepted", Some(1000), None),
            session_event(serde_json::json!({ "kind": "agentItem", "payload": { "id": "a1" } })),
            session_event(serde_json::json!({ "kind": "actionRequest", "payload": { "requestId": 5 } })),
            session_event(serde_json::json!({ "kind": "turnComplete" })),
        ]);
        let mut client = Client::new(t);
        let mut events = Vec::new();
        let mut emit = |e: &serde_json::Value| events.push(e.get("kind").and_then(|k| k.as_str()).unwrap_or("").to_string());
        let req = msg("startSession", None, Some(serde_json::json!({"cwd":"/tmp","prompt":"hi"})));
        client.run_stream(req, "cli-1", ApprovalPolicy::AutoApprove, &mut emit).unwrap();

        assert_eq!(events, vec!["agentItem", "actionRequest", "turnComplete"]);
        let sent = client.into_sent();
        let decision = sent.iter().find(|m| m.kind == "actionDecision").expect("decision sent");
        assert_eq!(decision.payload.as_ref().unwrap()["requestId"], 5);
        assert_eq!(decision.payload.as_ref().unwrap()["decision"], "approve");
        assert_eq!(decision.session_id.as_deref(), Some("cli-1"));
    }

    #[test]
    fn run_stream_inner_error_is_session_failure() {
        let t = FakeTransport::new(vec![
            msg("turnAccepted", Some(1000), None),
            session_event(serde_json::json!({ "kind": "error", "payload": { "message": "boom" } })),
        ]);
        let mut client = Client::new(t);
        let mut emit = |_: &serde_json::Value| {};
        let req = msg("startSession", None, Some(serde_json::json!({"cwd":"/tmp","prompt":"hi"})));
        let err = client.run_stream(req, "cli-1", ApprovalPolicy::AutoApprove, &mut emit).unwrap_err();
        assert_eq!(err.exit_code(), 5);
        assert_eq!(err.message(), "boom");
    }
}
