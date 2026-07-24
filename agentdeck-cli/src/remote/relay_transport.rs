//! Persistent paired Device 到 Relay v2 的 production transport composition。
//!
//! 本模块只组合 audited device capability、state-bound WSS/SPKI 与 `RelayClient`；
//! Runtime frozen frame 不在此重编码，Relay terminal error 也不降级为字符串。

#![cfg(unix)]

use std::future::Future;

use agentdeck_protocol::relay_v2::OpaqueRouteFrame;
use agentdeck_relay_client::{RelayClient, RelayClientError};
use async_trait::async_trait;
use thiserror::Error;

use super::paired_machine::{
    OpenedPairedMachine, PairedPromotionError, VerifiedRevocationTerminal,
};
use super::runtime::{
    ExactRelayFrame, ReceivedRuntimeFrame, RemoteRuntime, RemoteRuntimeError,
    RemoteRuntimeTransport, RemoteRuntimeTransportError,
};

#[async_trait]
pub(super) trait RelayRuntimeIo: Send {
    async fn send_encoded(&mut self, bytes: Vec<u8>) -> Result<(), RelayClientError>;

    async fn recv_exact(&mut self) -> Result<Option<ReceivedRuntimeFrame>, RelayClientError>;

    async fn shutdown(&mut self);
}

#[async_trait]
impl RelayRuntimeIo for RelayClient {
    async fn send_encoded(&mut self, bytes: Vec<u8>) -> Result<(), RelayClientError> {
        RelayClient::send_encoded(self, bytes).await
    }

    async fn recv_exact(&mut self) -> Result<Option<ReceivedRuntimeFrame>, RelayClientError> {
        RelayClient::recv_exact(self).await.map(|received| {
            received.map(|received| {
                let (frame, canonical_bytes) = received.into_parts();
                ReceivedRuntimeFrame::from_untrusted_parts(frame, canonical_bytes)
            })
        })
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

    async fn recv(&mut self) -> Result<Option<ReceivedRuntimeFrame>, RemoteRuntimeTransportError> {
        self.relay.recv_exact().await.map_err(Into::into)
    }

    async fn shutdown(&mut self) {
        self.relay.shutdown().await;
    }
}

/// 建立 paired Runtime 时可由调用方稳定区分的组合层错误。
#[derive(Debug, Error)]
pub enum PairedRuntimeConnectError {
    #[error("paired Runtime Relay connection failed")]
    Relay(#[source] RelayClientError),
    #[error("paired Runtime terminal validation or cleanup failed")]
    Paired(#[source] PairedPromotionError),
    #[error("paired Runtime durable recovery failed")]
    Runtime(#[source] RemoteRuntimeError),
}

impl PairedRuntimeConnectError {
    #[must_use]
    pub fn code(&self) -> &str {
        match self {
            Self::Relay(error) => error.code(),
            Self::Paired(error) => error.code(),
            Self::Runtime(error) => error.code(),
        }
    }
}

/// paired Runtime 握手完成后的 typed outcome。
///
/// `Revoked` 只会在 exact MachineRoot-signed `RevocationCommitted` 已完成 crash-safe
/// cleanup 后返回；握手层的 `RetirementCommitted` 或任一无效 terminal 都是 error。
pub enum PairedRuntimeConnectOutcome<'a> {
    Connected(Box<RemoteRuntime<'a, RelayRuntimeTransport>>),
    Revoked,
}

impl std::fmt::Debug for PairedRuntimeConnectOutcome<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connected(_) => formatter.write_str("PairedRuntimeConnectOutcome::Connected"),
            Self::Revoked => formatter.write_str("PairedRuntimeConnectOutcome::Revoked"),
        }
    }
}

/// 组合层的 module-private paired capability seam。
///
/// production 实现只委托给 `OpenedPairedMachine` 的 type-state API；unit harness 使用
/// fake 验证 connector 生命周期与 cleanup 调用顺序，不复制生产 cryptographic fixture。
pub(super) trait PairedRuntimeHandle: Sized {
    type Connected;
    type VerifiedRevocation;

    fn verify_revocation_terminal(
        &self,
        frame: &OpaqueRouteFrame,
        canonical_bytes: &[u8],
    ) -> Result<Self::VerifiedRevocation, PairedPromotionError>;

    fn into_connected(self, transport: RelayRuntimeTransport) -> Self::Connected;

    fn commit_revocation_cleanup(
        self,
        verified: Self::VerifiedRevocation,
    ) -> Result<(), PairedPromotionError>;
}

impl<'a> PairedRuntimeHandle for OpenedPairedMachine<'a> {
    type Connected = RemoteRuntime<'a, RelayRuntimeTransport>;
    type VerifiedRevocation = VerifiedRevocationTerminal;

    fn verify_revocation_terminal(
        &self,
        frame: &OpaqueRouteFrame,
        canonical_bytes: &[u8],
    ) -> Result<Self::VerifiedRevocation, PairedPromotionError> {
        OpenedPairedMachine::verify_revocation_terminal(self, frame, canonical_bytes)
    }

    fn into_connected(self, transport: RelayRuntimeTransport) -> Self::Connected {
        RemoteRuntime::new(self, transport)
    }

    fn commit_revocation_cleanup(
        self,
        verified: Self::VerifiedRevocation,
    ) -> Result<(), PairedPromotionError> {
        OpenedPairedMachine::commit_revocation_cleanup(self, verified)
    }
}

pub(super) enum RelayRuntimeConnectCompletion<C> {
    Connected(C),
    Revoked,
}

impl<C> std::fmt::Debug for RelayRuntimeConnectCompletion<C> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connected(_) => formatter.write_str("RelayRuntimeConnectCompletion::Connected"),
            Self::Revoked => formatter.write_str("RelayRuntimeConnectCompletion::Revoked"),
        }
    }
}

/// 等待 connector 完整结束后，再使用仍被本函数拥有的 paired capability 处理结果。
///
/// terminal error 内的 frame 与 WebSocket 原始 bytes 原样送入 paired verifier。connector
/// future 已在进入 match 前完成；因此失败连接持有的 socket/task 先销毁，cleanup journal
/// 才可能 durable。
pub(super) async fn complete_paired_runtime_connect<M, F>(
    machine: M,
    connector: F,
) -> Result<RelayRuntimeConnectCompletion<M::Connected>, PairedRuntimeConnectError>
where
    M: PairedRuntimeHandle,
    F: Future<Output = Result<RelayRuntimeTransport, RelayClientError>>,
{
    let connection = connector.await;
    match connection {
        Ok(transport) => Ok(RelayRuntimeConnectCompletion::Connected(
            machine.into_connected(transport),
        )),
        Err(RelayClientError::AuthenticationTerminal {
            frame,
            canonical_bytes,
        }) => {
            let verified = machine
                .verify_revocation_terminal(frame.as_ref(), canonical_bytes.as_ref())
                .map_err(PairedRuntimeConnectError::Paired)?;
            machine
                .commit_revocation_cleanup(verified)
                .map_err(PairedRuntimeConnectError::Paired)?;
            Ok(RelayRuntimeConnectCompletion::Revoked)
        }
        Err(error) => Err(PairedRuntimeConnectError::Relay(error)),
    }
}

/// 消费 audited paired handle 并建立唯一 production Relay Runtime composition。
///
/// `machine` 按值进入本函数：普通连接失败时立即释放其 device lease；精确 root-signed
/// revocation terminal 在 connector/socket 完整结束后执行 crash-safe cleanup；连接成功后
/// `RemoteRuntime` 的字段顺序保证 Relay transport 先于 paired handle/lease 销毁。
pub async fn connect_paired_runtime<'a>(
    machine: OpenedPairedMachine<'a>,
) -> Result<PairedRuntimeConnectOutcome<'a>, PairedRuntimeConnectError> {
    let material = machine
        .mint_relay_connection_material()
        .map_err(PairedRuntimeConnectError::Relay)?;
    let (config, authenticator) = material.into_parts();
    let connector = async move {
        RelayClient::connect(config, authenticator)
            .await
            .map(RelayRuntimeTransport::new)
    };
    match complete_paired_runtime_connect(machine, connector).await? {
        RelayRuntimeConnectCompletion::Connected(mut runtime) => {
            runtime
                .recover_durable_key_sync()
                .await
                .map_err(PairedRuntimeConnectError::Runtime)?;
            runtime
                .recover_durable_epoch_barrier_acks()
                .await
                .map_err(PairedRuntimeConnectError::Runtime)?;
            Ok(PairedRuntimeConnectOutcome::Connected(Box::new(runtime)))
        }
        RelayRuntimeConnectCompletion::Revoked => Ok(PairedRuntimeConnectOutcome::Revoked),
    }
}
