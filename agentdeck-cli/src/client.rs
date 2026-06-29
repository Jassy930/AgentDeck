use crate::output::CliError;
use crate::transport::Transport;
use agentdeck_protocol::IpcMessage;

pub struct Client<T: Transport> {
    transport: T,
    next_id: u64,
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::FakeTransport;

    fn msg(kind: &str, id: Option<u64>, payload: Option<serde_json::Value>) -> IpcMessage {
        IpcMessage { kind: kind.into(), id, session_id: None, thread_id: None, payload }
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
}
