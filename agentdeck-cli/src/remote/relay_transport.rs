//! Persistent paired Device 到 Relay v2 的 production transport composition。
//!
//! 本模块只组合 audited device capability、state-bound WSS/SPKI 与 `RelayClient`；
//! Runtime frozen frame 不在此重编码，Relay terminal error 也不降级为字符串。

#![cfg(unix)]

use agentdeck_protocol::relay_v2::OpaqueRouteFrame;
use agentdeck_relay_client::{RelayClient, RelayClientError};
use async_trait::async_trait;

use super::paired_machine::OpenedPairedMachine;
use super::runtime::{
    ExactRelayFrame, RemoteRuntime, RemoteRuntimeTransport, RemoteRuntimeTransportError,
};

#[async_trait]
pub(super) trait RelayRuntimeIo: Send {
    async fn send_encoded(&mut self, bytes: Vec<u8>) -> Result<(), RelayClientError>;

    async fn recv(&mut self) -> Result<Option<OpaqueRouteFrame>, RelayClientError>;

    async fn shutdown(&mut self);
}

#[async_trait]
impl RelayRuntimeIo for RelayClient {
    async fn send_encoded(&mut self, bytes: Vec<u8>) -> Result<(), RelayClientError> {
        RelayClient::send_encoded(self, bytes).await
    }

    async fn recv(&mut self) -> Result<Option<OpaqueRouteFrame>, RelayClientError> {
        RelayClient::recv(self).await
    }

    async fn shutdown(&mut self) {
        RelayClient::shutdown(self).await;
    }
}

/// `RemoteRuntimeTransport` 的 production RelayClient adapter。
pub struct RelayRuntimeTransport {
    relay: Box<dyn RelayRuntimeIo>,
}

impl std::fmt::Debug for RelayRuntimeTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RelayRuntimeTransport([REDACTED])")
    }
}

impl RelayRuntimeTransport {
    fn new(client: RelayClient) -> Self {
        Self {
            relay: Box::new(client),
        }
    }

    /// 仅供 library unit harness 注入无网络 connector；production binary 中不存在。
    #[cfg(test)]
    pub(super) fn from_test_connector(connector: impl RelayRuntimeIo + 'static) -> Self {
        Self {
            relay: Box::new(connector),
        }
    }
}

#[async_trait]
impl RemoteRuntimeTransport for RelayRuntimeTransport {
    async fn send(&mut self, frame: ExactRelayFrame) -> Result<(), RemoteRuntimeTransportError> {
        self.relay.send_encoded(frame.into_bytes()).await?;
        Ok(())
    }

    async fn recv(&mut self) -> Result<Option<OpaqueRouteFrame>, RemoteRuntimeTransportError> {
        self.relay.recv().await.map_err(Into::into)
    }

    async fn shutdown(&mut self) {
        self.relay.shutdown().await;
    }
}

/// 消费 audited paired handle 并建立唯一 production Relay Runtime composition。
///
/// `machine` 按值进入本函数：连接失败时立即释放其 device lease；连接成功后
/// `RemoteRuntime` 的字段顺序保证 Relay transport 先于 paired handle/lease 销毁。
pub async fn connect_paired_runtime<'a>(
    machine: OpenedPairedMachine<'a>,
) -> Result<RemoteRuntime<'a, RelayRuntimeTransport>, RelayClientError> {
    let material = machine.mint_relay_connection_material()?;
    let (config, authenticator) = material.into_parts();
    let client = RelayClient::connect(config, authenticator).await?;
    Ok(RemoteRuntime::new(
        machine,
        RelayRuntimeTransport::new(client),
    ))
}
