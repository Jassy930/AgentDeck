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
#[allow(dead_code)] // conv_machine/turn_conv/sessions/conv_seq/conv_buffer/req_origin 供 Task 4（事件面）/ Task 5（命令面）使用，R0 先占位
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
            // 其余变体在 Task 4 / Task 5 加入
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
    use agentdeck_protocol::remote::{DeviceDescriptor, DeviceKind};

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
}
