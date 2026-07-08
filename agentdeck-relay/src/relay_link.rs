// agentdeck-relay/src/relay_link.rs
use agentdeck_protocol::remote::RemoteFrame;

/// 客户端连接抽象（RemoteFrame 类型）。内存 `RelayClient` 与 R1a 的 `WsRelayClient`
/// 都实现它，bridge/CLI 依赖 trait 而非具体传输——切换零逻辑改。
#[async_trait::async_trait]
pub trait RelayLink: Send + 'static {
    async fn send(&self, frame: RemoteFrame);
    async fn recv(&mut self) -> Option<RemoteFrame>;
}
