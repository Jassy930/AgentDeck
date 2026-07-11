use agentdeck_protocol::remote::RemoteFrame;
use agentdeck_relay::{RelayClient, RelayLink};

pub struct InProcRelayClient(RelayClient);
impl InProcRelayClient {
    pub fn new(c: RelayClient) -> Self {
        Self(c)
    }
}

#[async_trait::async_trait]
impl RelayLink for InProcRelayClient {
    async fn send(&self, frame: RemoteFrame) {
        self.0.send(frame).await
    }
    async fn recv(&mut self) -> Option<RemoteFrame> {
        self.0.recv().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentdeck_protocol::remote::{ClientRole, RelayControlMsg, SubTarget};
    use agentdeck_relay::FakeRelay;

    #[tokio::test]
    async fn subscribe_machines_via_relay_link_returns_machine_list() {
        let relay = FakeRelay::start();
        let client = relay
            .connect(ClientRole::Device {
                device_id: "d".into(),
            })
            .await;
        let mut link = InProcRelayClient::new(client);

        RelayLink::send(
            &link,
            RemoteFrame::control(
                ClientRole::Device {
                    device_id: "d".into(),
                },
                "trace-1".into(),
                0,
                RelayControlMsg::Subscribe {
                    target: SubTarget::Machines,
                },
            ),
        )
        .await;

        let frame = link.recv().await.expect("expected a frame from relay");
        assert!(
            matches!(frame.msg, RelayControlMsg::MachineList { .. }),
            "expected MachineList, got {:?}",
            frame.msg
        );
    }
}
