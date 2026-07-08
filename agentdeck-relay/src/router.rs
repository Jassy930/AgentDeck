// agentdeck-relay/src/router.rs
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use agentdeck_protocol::remote::{
    ClientRole, CommandTarget, MachineDescriptor, RelayControlMsg, RemoteFrame, SessionDescriptor,
    SubTarget,
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

#[async_trait::async_trait]
impl crate::relay_link::RelayLink for RelayClient {
    async fn send(&self, frame: RemoteFrame) {
        RelayClient::send(self, frame).await
    }
    async fn recv(&mut self) -> Option<RemoteFrame> {
        RelayClient::recv(self).await
    }
}

/// 连接身份中的角色（供 Task 5 授权检查、Task 9 server 鉴权使用）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnRole {
    Machine { machine_id: String },
    Device,
}

/// 一个已建立连接的稳定身份：账号 + 设备/机器 + 角色。
/// R1a 本任务只负责携带/存储；Task 5 才会据此做授权检查。
#[derive(Debug, Clone)]
pub struct ConnIdentity {
    pub account_id: String,
    pub device_id: String,
    pub role: ConnRole,
}

enum CoreMsg {
    Connect { id: ClientId, identity: ConnIdentity, out: mpsc::Sender<RemoteFrame> },
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

    /// 便捷入口（内存测试/匿名 dev）：合成一个 dev-scope 身份。
    pub async fn connect(&self, role: ClientRole) -> RelayClient {
        let identity = ConnIdentity {
            account_id: "dev".into(),
            device_id: match &role {
                ClientRole::Device { device_id } => device_id.clone(),
                ClientRole::Machine { machine_id } => machine_id.clone(),
                ClientRole::Relay => "relay".into(),
            },
            role: match &role {
                ClientRole::Machine { machine_id } => ConnRole::Machine { machine_id: machine_id.clone() },
                _ => ConnRole::Device,
            },
        };
        self.connect_with_identity(identity).await
    }

    /// 携带稳定身份接入（Task 9 server 用：真实鉴权解析出的 account/device/role）。
    pub async fn connect_with_identity(&self, identity: ConnIdentity) -> RelayClient {
        let id = ClientId(self.next_id.fetch_add(1, Ordering::Relaxed));
        let (to_relay_tx, mut to_relay_rx) = mpsc::channel::<RemoteFrame>(64);
        let (from_relay_tx, from_relay_rx) = mpsc::channel::<RemoteFrame>(64);
        let _ = self
            .core_tx
            .send(CoreMsg::Connect { id, identity, out: from_relay_tx })
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

struct Conn {
    #[allow(dead_code)] // Task 5 授权检查读取；本任务只负责存储
    identity: ConnIdentity,
    out: mpsc::Sender<RemoteFrame>,
    #[allow(dead_code)] // R1b 补发对齐使用；本任务只在事件溢出时置位
    lagged: bool,
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
    req_origin: HashMap<String, ClientId>,
    subs_machines: HashSet<ClientId>,
    subs_sessions: HashMap<String, HashSet<ClientId>>,
    subs_events: HashMap<String, HashSet<ClientId>>,
    /// send_to 遇到满/已关闭的连接时延迟登记于此，避免在持有 conns 借用时直接
    /// handle_disconnect（借用冲突）；由 run 循环在每条消息处理完后统一 drain。
    disconnect_conns: Vec<ClientId>,
}

impl Core {
    async fn run(mut self, mut rx: mpsc::Receiver<CoreMsg>) {
        while let Some(msg) = rx.recv().await {
            match msg {
                CoreMsg::Connect { id, identity, out } => {
                    self.conns.insert(id, Conn { identity, out, lagged: false });
                }
                CoreMsg::Disconnect { id } => {
                    self.handle_disconnect(id).await;
                }
                CoreMsg::Frame { id, frame } => {
                    self.handle_frame(id, frame).await;
                }
            }
            self.drain_disconnects().await;
        }
    }

    /// 统一处理 send_to 延迟登记的断连（可能级联产生新的登记，故循环至空）。
    async fn drain_disconnects(&mut self) {
        while !self.disconnect_conns.is_empty() {
            let batch: Vec<ClientId> = self.disconnect_conns.drain(..).collect();
            for id in batch {
                self.handle_disconnect(id).await;
            }
        }
    }

    /// relay → 指定连接 发一帧（from = Relay）。用 try_send 防止单个慢/卡死
    /// 连接的出站队列写满时阻塞整个 Core 单任务循环（HOL）。
    /// 溢出策略：控制/回执类（会丢关键状态）→ 该连接不可用，登记延迟断连；
    /// 事件类（R1b 可补发）→ 丢帧并标记 lagged。
    async fn send_to(&mut self, id: ClientId, trace_id: &str, msg: RelayControlMsg) {
        let is_control = matches!(
            msg,
            RelayControlMsg::AdminReply { .. }
                | RelayControlMsg::CommandDelivered { .. }
                | RelayControlMsg::Error { .. }
                | RelayControlMsg::MachineList { .. }
                | RelayControlMsg::SessionList { .. }
        );
        if let Some(conn) = self.conns.get_mut(&id) {
            let frame = RemoteFrame::control(ClientRole::Relay, trace_id.to_string(), 0, msg);
            match conn.out.try_send(frame) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    if is_control {
                        self.disconnect_conns.push(id);
                    } else {
                        conn.lagged = true;
                    }
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    self.disconnect_conns.push(id);
                }
            }
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
            RelayControlMsg::SendCommand { request_id, target, data } => {
                let machine_id = match &target {
                    CommandTarget::Machine { machine_id } => Some(machine_id.clone()),
                    CommandTarget::Conversation { conversation_id } => {
                        self.conv_machine.get(conversation_id).cloned()
                    }
                    CommandTarget::Turn { turn_session_id } => self
                        .turn_conv
                        .get(turn_session_id)
                        .and_then(|c| self.conv_machine.get(c))
                        .cloned(),
                };
                let target_conn = machine_id
                    .and_then(|m| self.machines.get(&m))
                    .filter(|e| e.descriptor.is_online && self.conns.contains_key(&e.conn))
                    .map(|e| e.conn);
                match target_conn {
                    Some(machine_conn) => {
                        self.req_origin.insert(request_id.clone(), id);
                        self.send_to(
                            machine_conn,
                            &trace,
                            RelayControlMsg::SendCommand {
                                request_id: request_id.clone(),
                                target,
                                data,
                            },
                        )
                        .await;
                        self.send_to(id, &trace, RelayControlMsg::CommandDelivered { request_id }).await;
                    }
                    None => {
                        self.send_to(
                            id,
                            &trace,
                            RelayControlMsg::Error {
                                code: "remote.session.not_found".into(),
                                message: "no online machine for command target".into(),
                                in_reply_to: Some(request_id),
                            },
                        )
                        .await;
                    }
                }
            }
            RelayControlMsg::AdminReply { in_reply_to, data } => {
                if let Some(&dev) = self.req_origin.get(&in_reply_to) {
                    self.send_to(dev, &trace, RelayControlMsg::AdminReply { in_reply_to: in_reply_to.clone(), data }).await;
                    self.req_origin.remove(&in_reply_to);
                }
            }
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

    #[tokio::test]
    async fn slow_consumer_does_not_block_other_connections() {
        let relay = FakeRelay::start();
        // D_slow 订阅 machines 但从不 recv（模拟慢/卡死连接）
        let _d_slow = relay.connect(ClientRole::Device { device_id: "slow".into() }).await;
        _d_slow.send(frame(ClientRole::Device { device_id: "slow".into() },
            RelayControlMsg::Subscribe { target: SubTarget::Machines })).await;
        // 灌满 D_slow 的出站队列（>64）：注册很多机器触发广播
        for i in 0..200 {
            let m = relay.connect(ClientRole::Machine { machine_id: format!("M{i}") }).await;
            m.send(frame(ClientRole::Machine { machine_id: format!("M{i}") },
                RelayControlMsg::RegisterMachine { machine: machine(&format!("M{i}")) })).await;
        }
        // 新 device 订阅仍能及时拿到快照（Core 未被 D_slow 卡死）
        let mut d = relay.connect(ClientRole::Device { device_id: "fast".into() }).await;
        d.send(frame(ClientRole::Device { device_id: "fast".into() },
            RelayControlMsg::Subscribe { target: SubTarget::Machines })).await;
        let got = tokio::time::timeout(std::time::Duration::from_secs(5), d.recv()).await
            .expect("Core 被慢连接阻塞了（HOL）").expect("frame");
        assert!(matches!(got.msg, RelayControlMsg::MachineList { .. }));
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

    use agentdeck_protocol::remote::CommandTarget;

    #[tokio::test]
    async fn send_command_routes_to_machine_and_admin_reply_returns_to_origin_device() {
        let relay = FakeRelay::start();
        let mut m = relay.connect(ClientRole::Machine { machine_id: "M1".into() }).await;
        m.send(frame(
            ClientRole::Machine { machine_id: "M1".into() },
            RelayControlMsg::RegisterMachine { machine: machine("M1") },
        ))
        .await;

        let mut d = relay.connect(ClientRole::Device { device_id: "D1".into() }).await;
        // device → machine 的机器级命令（内层用占位字符串，relay 不解码）
        d.send(frame(
            ClientRole::Device { device_id: "D1".into() },
            RelayControlMsg::SendCommand {
                request_id: "r1".into(),
                target: CommandTarget::Machine { machine_id: "M1".into() },
                data: DataEnvelope::plaintext(&"ping-cmd").unwrap(),
            },
        ))
        .await;

        // machine 收到该 SendCommand（relay 未解码 data）
        let at_machine = recv_send_command(&mut m).await;
        assert_eq!(at_machine, "r1");

        // machine 回 AdminReply
        m.send(frame(
            ClientRole::Machine { machine_id: "M1".into() },
            RelayControlMsg::AdminReply { in_reply_to: "r1".into(), data: DataEnvelope::plaintext(&"pong").unwrap() },
        ))
        .await;

        // 发起 device 应收到该 AdminReply
        loop {
            let frame = match tokio::time::timeout(std::time::Duration::from_secs(5), d.recv()).await {
                Ok(Some(frame)) => frame,
                Ok(None) => panic!("timed out waiting for AdminReply frame: stream closed"),
                Err(_) => panic!("timed out waiting for AdminReply frame"),
            };
            match frame.msg {
                RelayControlMsg::AdminReply { in_reply_to, data } => {
                    assert_eq!(in_reply_to, "r1");
                    let s: String = data.decode_plaintext().unwrap();
                    assert_eq!(s, "pong");
                    break;
                }
                RelayControlMsg::CommandDelivered { .. } => continue,
                other => panic!("unexpected {other:?}"),
            }
        }
    }

    async fn recv_send_command(c: &mut RelayClient) -> String {
        loop {
            let frame = match tokio::time::timeout(std::time::Duration::from_secs(5), c.recv()).await {
                Ok(Some(frame)) => frame,
                Ok(None) => panic!("timed out waiting for SendCommand frame: stream closed"),
                Err(_) => panic!("timed out waiting for SendCommand frame"),
            };
            match frame.msg {
                RelayControlMsg::SendCommand { request_id, .. } => return request_id,
                _ => continue,
            }
        }
    }

    #[tokio::test]
    async fn unknown_conversation_command_returns_not_found_error() {
        let relay = FakeRelay::start();
        let mut d = relay.connect(ClientRole::Device { device_id: "D1".into() }).await;
        d.send(frame(
            ClientRole::Device { device_id: "D1".into() },
            RelayControlMsg::SendCommand {
                request_id: "r9".into(),
                target: CommandTarget::Conversation { conversation_id: "NOPE".into() },
                data: DataEnvelope::plaintext(&"x").unwrap(),
            },
        ))
        .await;
        match tokio::time::timeout(std::time::Duration::from_secs(5), d.recv())
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for Error frame"))
            .expect("frame")
            .msg
        {
            RelayControlMsg::Error { code, in_reply_to, .. } => {
                assert_eq!(code, "remote.session.not_found");
                assert_eq!(in_reply_to.as_deref(), Some("r9"));
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn relay_routes_opaque_data_without_decoding_it() {
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
        let mut d = relay.connect(ClientRole::Device { device_id: "D1".into() }).await;
        d.send(frame(
            ClientRole::Device { device_id: "D1".into() },
            RelayControlMsg::Subscribe { target: SubTarget::Events { conversation_id: "C1".into() } },
        ))
        .await;

        // 不可解码为任何协议类型的随机字节
        let garbage = DataEnvelope::Plaintext { agentdeck_protocol_version: 2, bytes: vec![0xFF, 0x00, 0x13, 0x37] };
        m.send(frame(
            ClientRole::Machine { machine_id: "M1".into() },
            RelayControlMsg::PublishEvent { conversation_id: "C1".into(), turn_session_id: "S1".into(), seq: 0, data: garbage.clone() },
        ))
        .await;

        // device 仍按控制面元数据收到，data 原样透传（relay 未解码）
        loop {
            let frame = match tokio::time::timeout(std::time::Duration::from_secs(5), d.recv()).await {
                Ok(Some(frame)) => frame,
                Ok(None) => panic!("timed out waiting for Event frame: stream closed"),
                Err(_) => panic!("timed out waiting for Event frame"),
            };
            match frame.msg {
                RelayControlMsg::Event { data, .. } => {
                    assert_eq!(data, garbage);
                    break;
                }
                _ => continue,
            }
        }
    }
}
