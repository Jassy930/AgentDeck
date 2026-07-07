// agentdeck-relay/src/router.rs
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use agentdeck_protocol::remote::{
    ClientRole, MachineDescriptor, RelayControlMsg, RemoteFrame, SessionDescriptor, SubTarget,
};
use tokio::sync::mpsc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ClientId(u64);

/// 客户端（machine/device）与 relay 之间的内存双工连接。
pub struct RelayClient {
    tx: mpsc::Sender<RemoteFrame>,
    rx: mpsc::Receiver<RemoteFrame>,
}

impl RelayClient {
    pub async fn send(&self, frame: RemoteFrame) {
        let _ = self.tx.send(frame).await;
    }
    pub async fn recv(&mut self) -> Option<RemoteFrame> {
        self.rx.recv().await
    }
}

enum CoreMsg {
    Connect { id: ClientId, role: ClientRole, out: mpsc::Sender<RemoteFrame> },
    Frame { id: ClientId, frame: RemoteFrame },
    Disconnect { id: ClientId },
}

/// 内存内容不可见转发器（有状态）。
pub struct FakeRelay {
    core_tx: mpsc::Sender<CoreMsg>,
    next_id: Arc<AtomicU64>,
}

impl FakeRelay {
    pub fn start() -> Self {
        let (core_tx, core_rx) = mpsc::channel::<CoreMsg>(256);
        tokio::spawn(Core::default().run(core_rx));
        FakeRelay { core_tx, next_id: Arc::new(AtomicU64::new(1)) }
    }

    pub async fn connect(&self, role: ClientRole) -> RelayClient {
        let id = ClientId(self.next_id.fetch_add(1, Ordering::Relaxed));
        let (to_relay_tx, mut to_relay_rx) = mpsc::channel::<RemoteFrame>(64);
        let (from_relay_tx, from_relay_rx) = mpsc::channel::<RemoteFrame>(64);
        let _ = self
            .core_tx
            .send(CoreMsg::Connect { id, role, out: from_relay_tx })
            .await;
        let core_tx = self.core_tx.clone();
        tokio::spawn(async move {
            while let Some(f) = to_relay_rx.recv().await {
                if core_tx.send(CoreMsg::Frame { id, frame: f }).await.is_err() {
                    break;
                }
            }
            let _ = core_tx.send(CoreMsg::Disconnect { id }).await;
        });
        RelayClient { tx: to_relay_tx, rx: from_relay_rx }
    }
}

#[allow(dead_code)] // `role` 供 Task 4/5（按角色路由命令/事件）使用
struct Conn {
    role: ClientRole,
    out: mpsc::Sender<RemoteFrame>,
}

struct MachineEntry {
    conn: ClientId,
    descriptor: MachineDescriptor,
}

#[derive(Default)]
struct Core {
    conns: HashMap<ClientId, Conn>,
    machines: HashMap<String, MachineEntry>,
    conv_machine: HashMap<String, String>,
    turn_conv: HashMap<String, String>,
    sessions: HashMap<String, Vec<SessionDescriptor>>,
    conv_seq: HashMap<String, u64>,
    conv_buffer: HashMap<String, Vec<RelayControlMsg>>,
    #[allow(dead_code)] // req_origin 供 Task 5（命令面：请求/回执关联）使用，R0 先占位
    req_origin: HashMap<String, ClientId>,
    subs_machines: HashSet<ClientId>,
    subs_sessions: HashMap<String, HashSet<ClientId>>,
    subs_events: HashMap<String, HashSet<ClientId>>,
}

impl Core {
    async fn run(mut self, mut rx: mpsc::Receiver<CoreMsg>) {
        while let Some(msg) = rx.recv().await {
            match msg {
                CoreMsg::Connect { id, role, out } => {
                    self.conns.insert(id, Conn { role, out });
                }
                CoreMsg::Disconnect { id } => {
                    self.handle_disconnect(id).await;
                }
                CoreMsg::Frame { id, frame } => {
                    self.handle_frame(id, frame).await;
                }
            }
        }
    }

    /// relay → 指定连接 发一帧（from = Relay）。
    async fn send_to(&self, id: ClientId, trace_id: &str, msg: RelayControlMsg) {
        if let Some(conn) = self.conns.get(&id) {
            let frame = RemoteFrame::control(ClientRole::Relay, trace_id.to_string(), 0, msg);
            let _ = conn.out.send(frame).await;
        }
    }

    fn machine_list(&self) -> Vec<MachineDescriptor> {
        self.machines.values().map(|m| m.descriptor.clone()).collect()
    }

    async fn handle_frame(&mut self, id: ClientId, frame: RemoteFrame) {
        let trace = frame.trace_id.clone();
        match frame.msg {
            RelayControlMsg::RegisterMachine { machine } => {
                let mid = machine.machine_id.clone();
                self.machines.insert(mid, MachineEntry { conn: id, descriptor: machine });
                let list = self.machine_list();
                for dev in self.subs_machines.clone() {
                    self.send_to(dev, &trace, RelayControlMsg::MachineList { machines: list.clone() }).await;
                }
            }
            RelayControlMsg::ConnectDevice { .. } => {
                // R0：设备描述暂不持久化；连接已在 Connect 建立。
            }
            RelayControlMsg::Subscribe { target: SubTarget::Machines } => {
                self.subs_machines.insert(id);
                let list = self.machine_list();
                self.send_to(id, &trace, RelayControlMsg::MachineList { machines: list }).await;
            }
            RelayControlMsg::AnnounceSession { session } => {
                let mid = session.machine_id.clone();
                self.conv_machine.insert(session.conversation_id.clone(), mid.clone());
                self.sessions.entry(mid.clone()).or_default().push(session);
                let list = self.sessions.get(&mid).cloned().unwrap_or_default();
                if let Some(devs) = self.subs_sessions.get(&mid) {
                    for dev in devs.clone() {
                        self.send_to(dev, &trace, RelayControlMsg::SessionList { machine_id: mid.clone(), sessions: list.clone() }).await;
                    }
                }
            }
            RelayControlMsg::RetireSession { conversation_id } => {
                self.conv_machine.remove(&conversation_id);
            }
            RelayControlMsg::PublishEvent { conversation_id, turn_session_id, seq: _, data } => {
                let seq = {
                    let s = self.conv_seq.entry(conversation_id.clone()).or_insert(0);
                    let cur = *s;
                    *s += 1;
                    cur
                };
                self.turn_conv.insert(turn_session_id.clone(), conversation_id.clone());
                let ev = RelayControlMsg::Event {
                    conversation_id: conversation_id.clone(),
                    turn_session_id,
                    seq,
                    data,
                };
                self.conv_buffer.entry(conversation_id.clone()).or_default().push(ev.clone());
                if let Some(devs) = self.subs_events.get(&conversation_id) {
                    for dev in devs.clone() {
                        self.send_to(dev, &trace, ev.clone()).await;
                    }
                }
            }
            RelayControlMsg::Subscribe { target: SubTarget::Sessions { machine_id } } => {
                self.subs_sessions.entry(machine_id.clone()).or_default().insert(id);
                let list = self.sessions.get(&machine_id).cloned().unwrap_or_default();
                self.send_to(id, &trace, RelayControlMsg::SessionList { machine_id, sessions: list }).await;
            }
            RelayControlMsg::Subscribe { target: SubTarget::Events { conversation_id } } => {
                self.subs_events.entry(conversation_id.clone()).or_default().insert(id);
                if let Some(buf) = self.conv_buffer.get(&conversation_id).cloned() {
                    for ev in buf {
                        self.send_to(id, &trace, ev).await;
                    }
                }
            }
            RelayControlMsg::Ack { .. } | RelayControlMsg::Heartbeat { .. } => {}
            // 其余变体（命令面）在 Task 5 加入
            _ => {}
        }
    }

    async fn handle_disconnect(&mut self, id: ClientId) {
        self.conns.remove(&id);
        self.subs_machines.remove(&id);
        for set in self.subs_sessions.values_mut() {
            set.remove(&id);
        }
        for set in self.subs_events.values_mut() {
            set.remove(&id);
        }
        // 机器断开 → 标记离线并广播
        let offline: Vec<String> = self
            .machines
            .iter()
            .filter(|(_, m)| m.conn == id)
            .map(|(k, _)| k.clone())
            .collect();
        for mid in offline {
            if let Some(m) = self.machines.get_mut(&mid) {
                m.descriptor.is_online = false;
            }
        }
        if !self.machines.is_empty() || !self.subs_machines.is_empty() {
            let list = self.machine_list();
            for dev in self.subs_machines.clone() {
                self.send_to(dev, "disconnect", RelayControlMsg::MachineList { machines: list.clone() }).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentdeck_protocol::remote::{DataEnvelope, DeviceDescriptor, DeviceKind};

    fn machine(id: &str) -> MachineDescriptor {
        MachineDescriptor {
            machine_id: id.into(),
            name: format!("machine-{id}"),
            agentdeck_protocol_version: agentdeck_protocol::PROTOCOL_VERSION,
            is_online: true,
            last_heartbeat_ms: None,
        }
    }

    fn frame(from: ClientRole, msg: RelayControlMsg) -> RemoteFrame {
        RemoteFrame::control(from, "t".into(), 0, msg)
    }

    #[tokio::test]
    async fn device_subscribing_to_machines_gets_snapshot_after_register() {
        let relay = FakeRelay::start();

        // machine 接入并注册
        let m = relay.connect(ClientRole::Machine { machine_id: "M1".into() }).await;
        m.send(frame(
            ClientRole::Machine { machine_id: "M1".into() },
            RelayControlMsg::RegisterMachine { machine: machine("M1") },
        ))
        .await;

        // device 接入并订阅机器列表
        let mut d = relay.connect(ClientRole::Device { device_id: "D1".into() }).await;
        d.send(frame(
            ClientRole::Device { device_id: "D1".into() },
            RelayControlMsg::ConnectDevice { device: DeviceDescriptor { device_id: "D1".into(), kind: DeviceKind::Cli } },
        ))
        .await;
        d.send(frame(
            ClientRole::Device { device_id: "D1".into() },
            RelayControlMsg::Subscribe { target: SubTarget::Machines },
        ))
        .await;

        // 订阅后应立即收到含 M1 的 MachineList 快照
        let got = d.recv().await.expect("frame");
        match got.msg {
            RelayControlMsg::MachineList { machines } => {
                assert_eq!(machines.len(), 1);
                assert_eq!(machines[0].machine_id, "M1");
            }
            other => panic!("expected MachineList, got {other:?}"),
        }
    }

    fn session(conv: &str, machine: &str) -> SessionDescriptor {
        SessionDescriptor {
            conversation_id: conv.into(),
            machine_id: machine.into(),
            thread_id: Some(conv.into()),
            current_turn_session_id: None,
            agent_kind: agentdeck_protocol::AgentKind::Codex,
            cwd: "/tmp/proj".into(),
            title: None,
        }
    }

    // 从 machine 发一条 PublishEvent（payload 用一个字符串占位内层字节）
    async fn publish(m: &RelayClient, conv: &str, turn: &str) {
        m.send(frame(
            ClientRole::Machine { machine_id: "M1".into() },
            RelayControlMsg::PublishEvent {
                conversation_id: conv.into(),
                turn_session_id: turn.into(),
                seq: 0, // relay 自行 re-stamp
                data: DataEnvelope::plaintext(&format!("evt-{turn}")).unwrap(),
            },
        ))
        .await;
    }

    #[tokio::test]
    async fn events_keyed_on_conversation_survive_new_turn_and_replay_for_late_subscriber() {
        let relay = FakeRelay::start();
        let m = relay.connect(ClientRole::Machine { machine_id: "M1".into() }).await;
        m.send(frame(
            ClientRole::Machine { machine_id: "M1".into() },
            RelayControlMsg::RegisterMachine { machine: machine("M1") },
        ))
        .await;
        m.send(frame(
            ClientRole::Machine { machine_id: "M1".into() },
            RelayControlMsg::AnnounceSession { session: session("C1", "M1") },
        ))
        .await;

        // device 订阅 conversation C1
        let mut d1 = relay.connect(ClientRole::Device { device_id: "D1".into() }).await;
        d1.send(frame(
            ClientRole::Device { device_id: "D1".into() },
            RelayControlMsg::Subscribe { target: SubTarget::Events { conversation_id: "C1".into() } },
        ))
        .await;

        // turn A（session S1）发一条事件；随后 turn B（session S2，同 conversation）
        publish(&m, "C1", "S1").await;
        publish(&m, "C1", "S2").await;

        // D1 应按序收到两个 turn 的事件，seq 单调 0,1
        let e0 = recv_event(&mut d1).await;
        let e1 = recv_event(&mut d1).await;
        assert_eq!(e0, ("C1".to_string(), "S1".to_string(), 0));
        assert_eq!(e1, ("C1".to_string(), "S2".to_string(), 1));

        // 晚订阅的 D2 应补拉到已缓冲的两条
        let mut d2 = relay.connect(ClientRole::Device { device_id: "D2".into() }).await;
        d2.send(frame(
            ClientRole::Device { device_id: "D2".into() },
            RelayControlMsg::Subscribe { target: SubTarget::Events { conversation_id: "C1".into() } },
        ))
        .await;
        let r0 = recv_event(&mut d2).await;
        let r1 = recv_event(&mut d2).await;
        assert_eq!(r0, ("C1".to_string(), "S1".to_string(), 0));
        assert_eq!(r1, ("C1".to_string(), "S2".to_string(), 1));
    }

    async fn recv_event(c: &mut RelayClient) -> (String, String, u64) {
        loop {
            let frame = match tokio::time::timeout(std::time::Duration::from_secs(5), c.recv()).await {
                Ok(Some(frame)) => frame,
                Ok(None) => panic!("timed out waiting for Event frame: stream closed"),
                Err(_) => panic!("timed out waiting for Event frame"),
            };
            match frame.msg {
                RelayControlMsg::Event { conversation_id, turn_session_id, seq, .. } => {
                    return (conversation_id, turn_session_id, seq)
                }
                _ => continue,
            }
        }
    }
}
