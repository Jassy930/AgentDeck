//! 公开 listener 的 pre-upgrade 资源边界。
//!
//! permit 在 TCP accept 前取得，并随底层 IO 穿过 HTTP upgrade，直到 WebSocket 真正关闭；
//! TLS、HTTP header 与成功 101 upgrade 必须在固定 deadline 内完成，避免慢连接或普通
//! HTTP keep-alive 绕过 Core/ingress 上界。

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::extract::connect_info::Connected;
use axum::serve::{IncomingStream, Listener};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[cfg(feature = "tls")]
use tokio_rustls::server::TlsStream;

/// 包含 pre-upgrade 与已升级 WebSocket 在内的物理公开连接硬上界。
pub const MAX_PUBLIC_CONNECTIONS: usize = 1_024;
/// 从 TCP accept 到成功 101 upgrade 的总 deadline；TLS handshake 与 HTTP header 都计入。
pub const PUBLIC_UPGRADE_DEADLINE: Duration = Duration::from_secs(5);
/// request line + headers 的解密后硬上界。
pub const MAX_PUBLIC_HEADER_BYTES: usize = 64 * 1024;

#[derive(Clone)]
pub(crate) struct PublicConnectInfo {
    source: SocketAddr,
    upgraded: Arc<AtomicBool>,
}

impl PublicConnectInfo {
    fn new(source: SocketAddr) -> Self {
        Self {
            source,
            upgraded: Arc::new(AtomicBool::new(false)),
        }
    }

    pub(crate) fn source(&self) -> SocketAddr {
        self.source
    }

    pub(crate) fn mark_upgraded(&self) {
        self.upgraded.store(true, Ordering::Release);
    }
}

impl std::fmt::Debug for PublicConnectInfo {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PublicConnectInfo")
            .field("source", &"<redacted>")
            .field("upgraded", &self.upgraded.load(Ordering::Acquire))
            .finish()
    }
}

pub(crate) trait TransportFactory: Clone + Send + 'static {
    type Io: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    fn wrap(&self, stream: TcpStream) -> Self::Io;
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct PlainTransport;

impl TransportFactory for PlainTransport {
    type Io = TcpStream;

    fn wrap(&self, stream: TcpStream) -> Self::Io {
        stream
    }
}

#[cfg(feature = "tls")]
#[derive(Clone)]
pub(crate) struct TlsTransport {
    acceptor: tokio_rustls::TlsAcceptor,
}

#[cfg(feature = "tls")]
impl TlsTransport {
    pub(crate) fn new(config: Arc<rustls::ServerConfig>) -> Self {
        Self {
            acceptor: tokio_rustls::TlsAcceptor::from(config),
        }
    }
}

#[cfg(feature = "tls")]
impl TransportFactory for TlsTransport {
    type Io = LazyTlsIo;

    fn wrap(&self, stream: TcpStream) -> Self::Io {
        LazyTlsIo::new(self.acceptor.accept(stream))
    }
}

/// `axum::serve` listener：先取得全局 permit，再 accept 一个 TCP；permit 被放入 IO，
/// 因此不会在 HTTP upgrade 时提前释放。
pub(crate) struct BoundedTcpListener<F> {
    listener: TcpListener,
    permits: Arc<Semaphore>,
    factory: F,
    header_deadline: Duration,
    max_header_bytes: usize,
}

impl<F> BoundedTcpListener<F> {
    fn with_limits(
        listener: TcpListener,
        factory: F,
        max_connections: usize,
        header_deadline: Duration,
        max_header_bytes: usize,
    ) -> Self {
        Self {
            listener,
            permits: Arc::new(Semaphore::new(max_connections)),
            factory,
            header_deadline,
            max_header_bytes,
        }
    }
}

impl BoundedTcpListener<PlainTransport> {
    pub(crate) fn plaintext(listener: TcpListener) -> Self {
        Self::with_limits(
            listener,
            PlainTransport,
            MAX_PUBLIC_CONNECTIONS,
            PUBLIC_UPGRADE_DEADLINE,
            MAX_PUBLIC_HEADER_BYTES,
        )
    }
}

#[cfg(feature = "tls")]
impl BoundedTcpListener<TlsTransport> {
    pub(crate) fn tls(listener: TcpListener, config: Arc<rustls::ServerConfig>) -> Self {
        Self::with_limits(
            listener,
            TlsTransport::new(config),
            MAX_PUBLIC_CONNECTIONS,
            PUBLIC_UPGRADE_DEADLINE,
            MAX_PUBLIC_HEADER_BYTES,
        )
    }
}

impl<F> Listener for BoundedTcpListener<F>
where
    F: TransportFactory,
{
    type Io = UpgradeBoundedIo<F::Io>;
    type Addr = PublicConnectInfo;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            // Semaphore 由 listener 私有持有且从不 close；保留 Result 分支避免生产 unwrap。
            let permit = loop {
                if let Ok(permit) = Arc::clone(&self.permits).acquire_owned().await {
                    break permit;
                }
                tokio::task::yield_now().await;
            };
            match self.listener.accept().await {
                Ok((stream, source)) => {
                    let io = self.factory.wrap(stream);
                    let connect_info = PublicConnectInfo::new(source);
                    return (
                        UpgradeBoundedIo::new(
                            io,
                            permit,
                            self.header_deadline,
                            self.max_header_bytes,
                            Arc::clone(&connect_info.upgraded),
                        ),
                        connect_info,
                    );
                }
                Err(_) => {
                    drop(permit);
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.listener.local_addr().map(PublicConnectInfo::new)
    }
}

impl<F> Connected<IncomingStream<'_, BoundedTcpListener<F>>> for PublicConnectInfo
where
    F: TransportFactory,
{
    fn connect_info(stream: IncomingStream<'_, BoundedTcpListener<F>>) -> Self {
        stream.remote_addr().clone()
    }
}

/// permit + accept→101 deadline wrapper。header terminator 只停止 size 计数；handler 标记
/// 成功 upgrade 后才永久解除 deadline，使 WebSocket 可正常长连接。同一 read 中 terminator
/// 后的 bytes 不计入 header 上界。
pub(crate) struct UpgradeBoundedIo<T> {
    inner: T,
    _permit: OwnedSemaphorePermit,
    deadline: Pin<Box<tokio::time::Sleep>>,
    header_complete: bool,
    header_bytes: usize,
    header_match: usize,
    max_header_bytes: usize,
    upgraded: Arc<AtomicBool>,
}

impl<T> UpgradeBoundedIo<T> {
    fn new(
        inner: T,
        permit: OwnedSemaphorePermit,
        deadline: Duration,
        max_header_bytes: usize,
        upgraded: Arc<AtomicBool>,
    ) -> Self {
        Self {
            inner,
            _permit: permit,
            deadline: Box::pin(tokio::time::sleep(deadline)),
            header_complete: false,
            header_bytes: 0,
            header_match: 0,
            max_header_bytes,
            upgraded,
        }
    }

    fn check_deadline(&mut self, context: &mut Context<'_>) -> io::Result<()> {
        // 完整 HTTP header 只停止 header-size 计数；只有 handler 确认将返回 101 后才解除
        // accept→upgrade 总 deadline。400/404/405 keep-alive 因而不能绕过该期限。
        if !self.upgraded.load(Ordering::Acquire) && self.deadline.as_mut().poll(context).is_ready()
        {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Relay public HTTP upgrade deadline elapsed",
            ));
        }
        Ok(())
    }

    fn observe_header_bytes(&mut self, bytes: &[u8]) -> io::Result<()> {
        const TERMINATOR: &[u8; 4] = b"\r\n\r\n";
        for byte in bytes {
            if self.header_complete {
                break;
            }
            self.header_bytes = self.header_bytes.saturating_add(1);
            if self.header_bytes > self.max_header_bytes {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Relay public HTTP header exceeds limit",
                ));
            }
            if *byte == TERMINATOR[self.header_match] {
                self.header_match += 1;
                if self.header_match == TERMINATOR.len() {
                    self.header_complete = true;
                }
            } else {
                self.header_match = usize::from(*byte == TERMINATOR[0]);
            }
        }
        Ok(())
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for UpgradeBoundedIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Err(error) = this.check_deadline(context) {
            return Poll::Ready(Err(error));
        }
        let before = buffer.filled().len();
        match Pin::new(&mut this.inner).poll_read(context, buffer) {
            Poll::Ready(Ok(())) => {
                if let Err(error) = this.observe_header_bytes(&buffer.filled()[before..]) {
                    return Poll::Ready(Err(error));
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for UpgradeBoundedIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let this = self.get_mut();
        if let Err(error) = this.check_deadline(context) {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut this.inner).poll_write(context, bytes)
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let this = self.get_mut();
        if let Err(error) = this.check_deadline(context) {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut this.inner).poll_flush(context)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(context)
    }
}

#[cfg(feature = "tls")]
enum LazyTlsState {
    Handshake(Pin<Box<dyn Future<Output = io::Result<TlsStream<TcpStream>>> + Send>>),
    Streaming(TlsStream<TcpStream>),
    Failed,
}

#[cfg(feature = "tls")]
pub(crate) struct LazyTlsIo {
    state: LazyTlsState,
}

#[cfg(feature = "tls")]
impl LazyTlsIo {
    fn new(
        handshake: impl Future<Output = io::Result<TlsStream<TcpStream>>> + Send + 'static,
    ) -> Self {
        Self {
            state: LazyTlsState::Handshake(Box::pin(handshake)),
        }
    }

    fn failed() -> io::Error {
        io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "Relay TLS handshake failed",
        )
    }
}

#[cfg(feature = "tls")]
impl AsyncRead for LazyTlsIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            match &mut self.state {
                LazyTlsState::Handshake(handshake) => match handshake.as_mut().poll(context) {
                    Poll::Ready(Ok(stream)) => self.state = LazyTlsState::Streaming(stream),
                    Poll::Ready(Err(error)) => {
                        self.state = LazyTlsState::Failed;
                        return Poll::Ready(Err(error));
                    }
                    Poll::Pending => return Poll::Pending,
                },
                LazyTlsState::Streaming(stream) => {
                    return Pin::new(stream).poll_read(context, buffer);
                }
                LazyTlsState::Failed => return Poll::Ready(Err(Self::failed())),
            }
        }
    }
}

#[cfg(feature = "tls")]
impl AsyncWrite for LazyTlsIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        loop {
            match &mut self.state {
                LazyTlsState::Handshake(handshake) => match handshake.as_mut().poll(context) {
                    Poll::Ready(Ok(stream)) => self.state = LazyTlsState::Streaming(stream),
                    Poll::Ready(Err(error)) => {
                        self.state = LazyTlsState::Failed;
                        return Poll::Ready(Err(error));
                    }
                    Poll::Pending => return Poll::Pending,
                },
                LazyTlsState::Streaming(stream) => {
                    return Pin::new(stream).poll_write(context, bytes);
                }
                LazyTlsState::Failed => return Poll::Ready(Err(Self::failed())),
            }
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        loop {
            match &mut self.state {
                LazyTlsState::Handshake(handshake) => match handshake.as_mut().poll(context) {
                    Poll::Ready(Ok(stream)) => self.state = LazyTlsState::Streaming(stream),
                    Poll::Ready(Err(error)) => {
                        self.state = LazyTlsState::Failed;
                        return Poll::Ready(Err(error));
                    }
                    Poll::Pending => return Poll::Pending,
                },
                LazyTlsState::Streaming(stream) => return Pin::new(stream).poll_flush(context),
                LazyTlsState::Failed => return Poll::Ready(Err(Self::failed())),
            }
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        match &mut self.state {
            LazyTlsState::Streaming(stream) => Pin::new(stream).poll_shutdown(context),
            LazyTlsState::Handshake(_) | LazyTlsState::Failed => Poll::Ready(Ok(())),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::time::Duration;

    use axum::serve::Listener;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use super::{BoundedTcpListener, PlainTransport};

    #[tokio::test]
    async fn accept_permit_bounds_preupgrade_connections_and_recovers_on_drop() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut listener = BoundedTcpListener::with_limits(
            listener,
            PlainTransport,
            1,
            Duration::from_secs(1),
            1024,
        );
        let _first_client = TcpStream::connect(address).await.unwrap();
        let (first, _) = listener.accept().await;
        let _second_client = TcpStream::connect(address).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_err(),
            "second TCP must remain outside the process accept boundary while permit is held"
        );
        drop(first);
        tokio::time::timeout(Duration::from_secs(1), listener.accept())
            .await
            .expect("released permit allows next accept");
    }

    #[tokio::test]
    async fn partial_and_complete_non_upgrade_timeout_but_marked_upgrade_disarms_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut listener = BoundedTcpListener::with_limits(
            listener,
            PlainTransport,
            3,
            Duration::from_millis(50),
            1024,
        );

        let mut partial_client = TcpStream::connect(address).await.unwrap();
        partial_client
            .write_all(b"GET /v2/connect HTTP/1.1\r\n")
            .await
            .unwrap();
        let (mut partial, _) = listener.accept().await;
        let mut bytes = [0_u8; 128];
        let read = partial
            .read(&mut bytes)
            .await
            .expect("read available partial header");
        assert!(read > 0);
        let error = partial
            .read(&mut bytes)
            .await
            .expect_err("incomplete header must hit its deadline");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);

        let mut non_upgrade_client = TcpStream::connect(address).await.unwrap();
        non_upgrade_client
            .write_all(b"GET /v2/connect HTTP/1.1\r\nHost: relay\r\n\r\nfirst")
            .await
            .unwrap();
        let (mut non_upgrade, _) = listener.accept().await;
        let read = non_upgrade.read(&mut bytes).await.unwrap();
        assert!(read > 0);
        tokio::time::sleep(Duration::from_millis(75)).await;
        let error = non_upgrade
            .read(&mut bytes)
            .await
            .expect_err("complete non-upgrade request must retain the deadline");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);

        let mut upgraded_client = TcpStream::connect(address).await.unwrap();
        upgraded_client
            .write_all(b"GET /v2/connect HTTP/1.1\r\nHost: relay\r\n\r\nfirst")
            .await
            .unwrap();
        let (mut upgraded, connect_info) = listener.accept().await;
        let read = upgraded.read(&mut bytes).await.unwrap();
        assert!(read > 0);
        connect_info.mark_upgraded();
        tokio::time::sleep(Duration::from_millis(75)).await;
        upgraded_client.write_all(b"second").await.unwrap();
        let read = upgraded.read(&mut bytes).await.unwrap();
        assert!(
            read > 0,
            "explicitly marked upgrade must disarm pre-upgrade deadline"
        );
    }

    #[tokio::test]
    async fn oversized_header_fails_before_http_upgrade() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut listener = BoundedTcpListener::with_limits(
            listener,
            PlainTransport,
            1,
            Duration::from_secs(1),
            16,
        );

        let mut client = TcpStream::connect(address).await.unwrap();
        client
            .write_all(b"GET /v2/connect HTTP/1.1\r\n")
            .await
            .unwrap();
        let (mut bounded, _) = listener.accept().await;
        let mut bytes = [0_u8; 64];
        let error = bounded
            .read(&mut bytes)
            .await
            .expect_err("header larger than the configured limit must be rejected");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}
