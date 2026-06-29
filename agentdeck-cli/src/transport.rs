use agentdeck_protocol::IpcMessage;
use std::collections::VecDeque;

/// 阻塞式单连接传输缝。`recv` 返回 `Ok(None)` 表示 daemon EOF/断连。
pub trait Transport {
    fn send(&mut self, msg: &IpcMessage) -> std::io::Result<()>;
    fn recv(&mut self) -> std::io::Result<Option<IpcMessage>>;
}

/// 内存测试传输：记录发出的帧，按脚本顺序回放收到的帧。
pub struct FakeTransport {
    pub sent: Vec<IpcMessage>,
    incoming: VecDeque<IpcMessage>,
}

impl FakeTransport {
    pub fn new(incoming: Vec<IpcMessage>) -> Self {
        Self { sent: Vec::new(), incoming: incoming.into() }
    }
}

impl Transport for FakeTransport {
    fn send(&mut self, msg: &IpcMessage) -> std::io::Result<()> {
        self.sent.push(msg.clone());
        Ok(())
    }
    fn recv(&mut self) -> std::io::Result<Option<IpcMessage>> {
        Ok(self.incoming.pop_front())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_records_sent_and_replays_incoming() {
        let mut t = FakeTransport::new(vec![IpcMessage {
            kind: "pong".into(), id: Some(7), session_id: None, thread_id: None, payload: None,
        }]);
        t.send(&IpcMessage { kind: "ping".into(), id: Some(7), session_id: None, thread_id: None, payload: None }).unwrap();
        assert_eq!(t.sent.len(), 1);
        assert_eq!(t.sent[0].kind, "ping");
        assert_eq!(t.recv().unwrap().unwrap().kind, "pong");
        assert!(t.recv().unwrap().is_none());
    }
}
