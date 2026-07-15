//! same effective UID peer 身份门禁。
//!
//! 威胁场景：同机其他 UID 若能在 daemon 读取并处理客户端 preface 前冒充本地控制端，
//! 就可能获得 local-only 管理能力；因此 peer credential 必须先验证，验证成功后才能
//! 进入读取路径。

use std::future::Future;
use std::io;

/// 可注入的 peer UID 查询边界。
///
/// macOS/Linux 的 socket credential 查询由 `local::unix` 实现；单元测试使用 fake，
/// 不需要真实 socket。
pub(crate) trait PeerUidSource {
    fn peer_uid(&self) -> io::Result<u32>;
}

/// 已通过 same effective UID 检查的不可伪造 capability。
///
/// 字段私有且没有公开构造器；后续读取/签发 principal 的接线可以要求持有此 token。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedSameUidPeer {
    uid: u32,
}

impl VerifiedSameUidPeer {
    pub(crate) fn uid(self) -> u32 {
        self.uid
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum PeerUidError {
    #[error("failed to obtain peer uid: {0}")]
    Lookup(#[source] io::Error),
    #[error("peer uid {peer_uid} does not match daemon effective uid {effective_uid}")]
    Mismatch { effective_uid: u32, peer_uid: u32 },
}

/// 验证 socket peer UID 与 daemon effective UID 一致。
pub(crate) fn verify_same_effective_uid<S>(
    source: &S,
    effective_uid: u32,
) -> Result<VerifiedSameUidPeer, PeerUidError>
where
    S: PeerUidSource + ?Sized,
{
    let peer_uid = source.peer_uid().map_err(PeerUidError::Lookup)?;
    if peer_uid != effective_uid {
        return Err(PeerUidError::Mismatch {
            effective_uid,
            peer_uid,
        });
    }
    Ok(VerifiedSameUidPeer { uid: peer_uid })
}

/// 先完成 same-EUID 验证，再把 stream/source 交给可能读取 client bytes 的闭包。
///
/// 威胁场景：未来重构若把 preface read 移到 peer credential gate 前，其他 UID 即使最终
/// 被拒绝也能驱动 parser 与分配；把 source 的所有权只在验证后交给闭包，让这一顺序可由
/// 行为测试直接观察。
pub(crate) async fn after_same_effective_uid<S, F, Fut, T>(
    source: S,
    effective_uid: u32,
    after_verification: F,
) -> Result<T, PeerUidError>
where
    S: PeerUidSource,
    F: FnOnce(S, VerifiedSameUidPeer) -> Fut,
    Fut: Future<Output = T>,
{
    let verified = verify_same_effective_uid(&source, effective_uid)?;
    Ok(after_verification(source, verified).await)
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::{PeerUidError, PeerUidSource, after_same_effective_uid, verify_same_effective_uid};

    struct FakePeerUid {
        result: io::Result<u32>,
    }

    impl PeerUidSource for FakePeerUid {
        fn peer_uid(&self) -> io::Result<u32> {
            match &self.result {
                Ok(uid) => Ok(*uid),
                Err(error) => Err(io::Error::new(error.kind(), error.to_string())),
            }
        }
    }

    #[test]
    fn matching_effective_uid_issues_verified_capability() {
        let source = FakePeerUid { result: Ok(501) };

        let verified = verify_same_effective_uid(&source, 501).expect("same uid");

        assert_eq!(verified.uid(), 501);
    }

    #[test]
    fn mismatched_uid_is_rejected() {
        let source = FakePeerUid { result: Ok(502) };

        let error = verify_same_effective_uid(&source, 501).expect_err("different uid");

        assert!(matches!(
            error,
            PeerUidError::Mismatch {
                effective_uid: 501,
                peer_uid: 502
            }
        ));
    }

    #[test]
    fn peer_credential_lookup_failure_is_fail_closed() {
        let source = FakePeerUid {
            result: Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "credential unavailable",
            )),
        };

        let error = verify_same_effective_uid(&source, 501).expect_err("lookup must fail");

        assert!(matches!(error, PeerUidError::Lookup(_)));
    }

    #[tokio::test]
    async fn mismatched_uid_never_reaches_the_client_read_probe() {
        let read_observed = Arc::new(AtomicBool::new(false));
        let probe = read_observed.clone();

        let error = after_same_effective_uid(
            FakePeerUid { result: Ok(502) },
            501,
            move |_source, _verified| async move {
                probe.store(true, Ordering::SeqCst);
            },
        )
        .await
        .expect_err("mismatched UID must fail before read probe");

        assert!(matches!(error, PeerUidError::Mismatch { .. }));
        assert!(
            !read_observed.load(Ordering::SeqCst),
            "peer rejection must happen before any client read"
        );
    }
}
