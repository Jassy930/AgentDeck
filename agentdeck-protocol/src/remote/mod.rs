// agentdeck-protocol/src/remote/mod.rs
//! Remote (relay) wire types — R0 契约 spike。
//!
//! 控制面（`RemoteFrame` + `RelayControlMsg`）relay 完整可读，用于路由；
//! 数据面（`DataEnvelope`）对 relay 不可见，R0 明文、R1/R2 换加密，控制面不动。

pub mod control;
pub mod data;
pub mod failure;
pub mod fleet;
pub mod frame;

/// relay 线协议版本，独立于内层 `PROTOCOL_VERSION`。R0 草案 = 0；
/// R1a：首个联网 wire-stable 版本 = 1。
pub const RELAY_PROTOCOL_VERSION: u16 = 1;

pub use control::{CommandTarget, RelayControlMsg, SubTarget};
pub use data::DataEnvelope;
pub use fleet::{DeviceDescriptor, DeviceKind, MachineDescriptor, SessionDescriptor};
pub use frame::{ClientRole, RemoteFrame};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ClientCommand;

    #[test]
    fn plaintext_data_envelope_round_trips_a_client_command() {
        let env = DataEnvelope::plaintext(&ClientCommand::Ping).unwrap();
        let back: ClientCommand = env.decode_plaintext().unwrap();
        assert!(matches!(back, ClientCommand::Ping));
    }

    #[test]
    fn remote_frame_serializes_control_plane_readably() {
        let frame = RemoteFrame::control(
            ClientRole::Device {
                device_id: "D1".into(),
            },
            "trace-1".into(),
            0,
            RelayControlMsg::Subscribe {
                target: SubTarget::Events {
                    conversation_id: "C1".into(),
                    since_seq: None,
                },
            },
        );
        let json = serde_json::to_value(&frame).unwrap();
        // 控制面字段对 relay 明文可读：
        assert_eq!(json["relayProtocolVersion"], 1);
        assert_eq!(json["from"]["role"], "device");
        assert_eq!(json["msg"]["msg"], "subscribe");
        assert_eq!(json["msg"]["target"]["kind"], "events");
        assert_eq!(json["msg"]["target"]["conversationId"], "C1");
        // 完整往返：
        let back: RemoteFrame = serde_json::from_value(json).unwrap();
        assert_eq!(back, frame);
    }
}
