//! Relay v2 stream replay 的分页拉取 helper。
//!
//! 这个模块不修改 Core 状态，也不直接向 writer 入队。Core actor 冻结 replay
//! identity 后，把 [`ReplayFetchTicket`] 交给短生命周期 task；task 只在 writer
//! 有一整页预算时读取 Store，重建并验证 canonical `Publish` outer frame，再把
//! typed completion 送回 Core。Core 仍须在真正入队前复核 authorization、
//! `replay_id` 与 cancellation，避免旧 task 越过新的订阅 generation。

use std::fmt;

use agentdeck_protocol::relay_v2::frame::{Gap, Publish, SealedBlob};
use agentdeck_protocol::relay_v2::{
    ConnectionInstanceId, MAX_FRAME_BYTES, MachineRouteId, OpaqueRouteFrame,
    RELAY_PROTOCOL_VERSION, RelayFrameBody, StreamCursor, encode,
};
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

use crate::v2::auth::AccessContext;
use crate::v2::store::{
    RelayStoreHandle, ReplayCursor, ReplayFrame, ReplayPage, ReplayPageRequest, ReplayPosition,
    StoreError, SubscriptionLease,
};

use super::connection::StreamKey;
use super::writer::WaitForBudgetError;

/// Store 与 writer 之间每个 replay task 允许物化的最大页。
pub(crate) const REPLAY_PAGE_MAX_FRAMES: usize = 64;
pub(crate) const REPLAY_PAGE_MAX_BYTES: usize = 8 * 1024 * 1024;

/// 当前分页属于冻结边界内的初始 replay，还是用于追赶初始边界后的 publish。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReplayMode {
    /// `terminal` 来自 `subscribe` 同一 SQLite transaction 冻结的 high-water。
    Initial { terminal: StreamCursor },
    /// 初始 `ReplayComplete` 之后，从 Store 当前 high-water 追赶 missed live frame。
    PostTerminal,
}

/// 一个短生命周期 replay page task 的全部不可变输入。
#[derive(Clone)]
pub(crate) struct ReplayFetchTicket {
    pub connection: ConnectionInstanceId,
    pub access: AccessContext,
    pub key: StreamKey,
    pub replay_id: u64,
    pub position: ReplayPosition,
    pub mode: ReplayMode,
    /// Store actor 瞬时入口背压的有界重试次数；成功取得一页后归零。
    pub busy_retries: u8,
    pub cancel: CancellationToken,
}

impl fmt::Debug for ReplayFetchTicket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("ReplayFetchTicket");
        debug
            .field("connection", &self.connection.redacted())
            .field("access", &self.access)
            .field("stream", &self.key.stream_route.redacted())
            .field("generation", &self.key.generation.redacted())
            .field("replay_id", &self.replay_id)
            .field("mode", &self.mode)
            .field("busy_retries", &self.busy_retries)
            .field("cancelled", &self.cancel.is_cancelled());
        match &self.position {
            ReplayPosition::Start(cursor) => {
                debug.field("position", &"start").field("cursor", cursor);
            }
            ReplayPosition::Continue(cursor) => {
                debug
                    .field("position", &"continue")
                    .field("next_seq", &cursor.next_seq)
                    .field("through_seq", &cursor.through_seq);
            }
        }
        debug.finish()
    }
}

/// 已通过 canonical size/hash/sequence/boundary 校验的一页 replay。
pub(crate) struct ReplayPageReady {
    pub frames: Vec<OpaqueRouteFrame>,
    pub next: Option<ReplayPosition>,
    pub replay_through: StreamCursor,
    pub mode: ReplayMode,
}

impl fmt::Debug for ReplayPageReady {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReplayPageReady")
            .field("frame_count", &self.frames.len())
            .field("has_next", &self.next.is_some())
            .field("replay_through", &self.replay_through)
            .field("mode", &self.mode)
            .finish()
    }
}

/// replay task 的 typed failure；Gap 与基础设施错误保持分离。
pub(crate) enum ReplayFetchError {
    Gap(Gap),
    Store(StoreError),
    Cancelled,
    /// 保留 [`WaitForBudgetError::Closed`] 中的精确 close reason，供 Core 清理。
    WriterUnavailable(WaitForBudgetError),
}

impl fmt::Debug for ReplayFetchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Gap(gap) => formatter
                .debug_struct("ReplayGap")
                .field("stream", &gap.stream_route.redacted())
                .field("generation", &gap.generation.redacted())
                .field("needed", &gap.need_stream_seq)
                .field("oldest", &gap.oldest_stream_seq)
                .finish(),
            Self::Store(error) => formatter
                .debug_struct("ReplayStoreError")
                .field("code", &error.diagnostic_code())
                .finish(),
            Self::Cancelled => formatter.write_str("ReplayCancelled"),
            Self::WriterUnavailable(error) => formatter
                .debug_tuple("ReplayWriterUnavailable")
                .field(error)
                .finish(),
        }
    }
}

impl fmt::Display for ReplayFetchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Gap(_) => formatter.write_str("replay retention gap"),
            Self::Store(error) => write!(formatter, "replay store failure: {error}"),
            Self::Cancelled => formatter.write_str("replay task cancelled"),
            Self::WriterUnavailable(error) => {
                write!(formatter, "replay writer unavailable: {error}")
            }
        }
    }
}

impl std::error::Error for ReplayFetchError {}

/// 由 `subscribe` 的 frozen lease 创建初始 replay ticket。
///
/// 初始页**必须**使用受限 [`ReplayPosition::Continue`]，不能退回
/// `ReplayPosition::Start` 重新读取更新后的 high-water。cursor 已位于 frozen terminal
/// 时返回 `None`，Core 可直接入队 `ReplayComplete`。
pub(crate) fn initial_replay_ticket(
    connection: ConnectionInstanceId,
    access: AccessContext,
    key: StreamKey,
    replay_id: u64,
    lease: &SubscriptionLease,
    cancel: CancellationToken,
) -> Result<Option<ReplayFetchTicket>, StoreError> {
    validate_ticket_access(connection, &access)?;
    validate_cursor_pair(lease.start, lease.replay_through)?;
    if lease.start == lease.replay_through {
        return Ok(None);
    }

    let next_seq = next_after_cursor(lease.start)?;
    let through_seq = cursor_value(lease.replay_through)?;
    if next_seq > through_seq {
        return Err(StoreError::InvalidReplayCursor);
    }
    Ok(Some(ReplayFetchTicket {
        connection,
        access,
        key,
        replay_id,
        position: ReplayPosition::Continue(ReplayCursor {
            stream_route: key.stream_route,
            generation: key.generation,
            next_seq,
            through_seq,
        }),
        mode: ReplayMode::Initial {
            terminal: lease.replay_through,
        },
        busy_retries: 0,
        cancel,
    }))
}

/// 创建初始 terminal 之后的追赶 ticket。Store 用 `Start(cursor)` 原子冻结此轮
/// catch-up 的新 high-water；后续分页再使用 Store 返回的 continuation。
pub(crate) fn post_terminal_replay_ticket(
    connection: ConnectionInstanceId,
    access: AccessContext,
    key: StreamKey,
    replay_id: u64,
    cursor: StreamCursor,
    cancel: CancellationToken,
) -> Result<ReplayFetchTicket, StoreError> {
    validate_ticket_access(connection, &access)?;
    reject_max_cursor(cursor)?;
    Ok(ReplayFetchTicket {
        connection,
        access,
        key,
        replay_id,
        position: ReplayPosition::Start(cursor),
        mode: ReplayMode::PostTerminal,
        busy_retries: 0,
        cancel,
    })
}

/// 拉取并验证一页 replay；不直接 enqueue。
pub(crate) async fn fetch_replay_page(
    store: &RelayStoreHandle,
    ticket: &ReplayFetchTicket,
    page_max_frames: usize,
    page_max_bytes: usize,
) -> Result<ReplayPageReady, ReplayFetchError> {
    if ticket.cancel.is_cancelled() {
        return Err(ReplayFetchError::Cancelled);
    }
    let machine_route = device_machine_route(&ticket.access).map_err(ReplayFetchError::Store)?;
    let request = ReplayPageRequest {
        machine_route,
        stream_route: ticket.key.stream_route,
        generation: ticket.key.generation,
        position: ticket.position.clone(),
        page_max_frames: u64::try_from(page_max_frames).map_err(|_| {
            ReplayFetchError::Store(StoreError::InvalidValue {
                field: "replay_page.limit",
                reason: "writer frame budget does not fit u64",
            })
        })?,
        page_max_bytes: u64::try_from(page_max_bytes).map_err(|_| {
            ReplayFetchError::Store(StoreError::InvalidValue {
                field: "replay_page.limit",
                reason: "writer byte budget does not fit u64",
            })
        })?,
    };
    // Store worker 一旦接纳命令仍会完成 SQLite 操作；task cancellation 只停止等待与
    // page 物化回传，避免 shutdown 被慢 Store reply 永久拖住。
    let page = tokio::select! {
        biased;
        _ = ticket.cancel.cancelled() => return Err(ReplayFetchError::Cancelled),
        result = store.replay_page(request) => result,
    }
    .map_err(|error| match error {
        StoreError::ReplayGap { needed, oldest } => ReplayFetchError::Gap(Gap {
            stream_route: ticket.key.stream_route,
            generation: ticket.key.generation,
            need_stream_seq: needed,
            oldest_stream_seq: oldest,
        }),
        other => ReplayFetchError::Store(other),
    })?;
    if ticket.cancel.is_cancelled() {
        return Err(ReplayFetchError::Cancelled);
    }
    validate_replay_page(ticket.key, &ticket.position, ticket.mode, page)
        .map_err(ReplayFetchError::Store)
}

fn validate_ticket_access(
    connection: ConnectionInstanceId,
    access: &AccessContext,
) -> Result<(), StoreError> {
    if access.connection_instance() != connection {
        return Err(StoreError::InvalidValue {
            field: "replay.connection",
            reason: "ticket connection does not match authenticated access",
        });
    }
    device_machine_route(access).map(|_| ())
}

fn device_machine_route(access: &AccessContext) -> Result<MachineRouteId, StoreError> {
    match access {
        AccessContext::Device(access) => Ok(access.machine_route),
        AccessContext::Machine(_) | AccessContext::Pairing(_) => Err(StoreError::InvalidValue {
            field: "replay.access",
            reason: "device access is required for stream replay",
        }),
    }
}

fn validate_replay_page(
    key: StreamKey,
    position: &ReplayPosition,
    mode: ReplayMode,
    page: ReplayPage,
) -> Result<ReplayPageReady, StoreError> {
    if page.frames.len() > REPLAY_PAGE_MAX_FRAMES {
        return Err(corrupt("replay page exceeds frame limit"));
    }
    validate_through(key, position, mode, page.replay_through)?;

    let expected_first = expected_first_seq(key, position)?;
    let through = match page.replay_through {
        StreamCursor::BeforeFirst => None,
        StreamCursor::At(value) => {
            reject_max_cursor(StreamCursor::At(value))?;
            Some(value)
        }
    };
    let raw_frames = page.frames;
    let mut frames = Vec::with_capacity(raw_frames.len());
    let mut expected = expected_first;
    let mut encoded_bytes = 0_usize;

    for replay in raw_frames {
        let expected_seq = expected.ok_or_else(|| corrupt("unexpected frame after terminal"))?;
        if replay.stream_seq != expected_seq
            || through.is_none_or(|value| replay.stream_seq > value)
        {
            return Err(corrupt("replay frame sequence is not contiguous"));
        }
        let frame = validate_replay_frame(key, replay)?;
        let size = encode(&frame).len();
        encoded_bytes = encoded_bytes
            .checked_add(size)
            .ok_or_else(|| corrupt("replay page byte count overflow"))?;
        if encoded_bytes > REPLAY_PAGE_MAX_BYTES {
            return Err(corrupt("replay page exceeds byte limit"));
        }
        frames.push(frame);
        expected = expected_seq.checked_add(1);
    }

    validate_next(
        key,
        position,
        through,
        expected,
        &frames,
        page.next.as_ref(),
    )?;
    Ok(ReplayPageReady {
        frames,
        next: page.next.map(ReplayPosition::Continue),
        replay_through: page.replay_through,
        mode,
    })
}

fn validate_replay_frame(
    key: StreamKey,
    replay: ReplayFrame,
) -> Result<OpaqueRouteFrame, StoreError> {
    if replay.stream_seq == u64::MAX {
        return Err(corrupt("u64::MAX stream sequence is not valid"));
    }
    let frame = OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::Publish(Publish {
            stream_route: key.stream_route,
            generation: key.generation,
            stream_seq: replay.stream_seq,
            sealed_blob: SealedBlob(replay.sealed_blob),
        }),
    };
    let canonical = encode(&frame);
    if canonical.len() > MAX_FRAME_BYTES
        || u64::try_from(canonical.len()).ok() != Some(replay.size)
        || <[u8; 32]>::from(Sha256::digest(&canonical)) != replay.frame_hash
    {
        return Err(corrupt("stored replay frame failed canonical validation"));
    }
    Ok(frame)
}

fn validate_through(
    key: StreamKey,
    position: &ReplayPosition,
    mode: ReplayMode,
    actual: StreamCursor,
) -> Result<(), StoreError> {
    reject_max_cursor(actual)?;
    match mode {
        ReplayMode::Initial { .. } if !matches!(position, ReplayPosition::Continue(_)) => {
            Err(StoreError::InvalidReplayCursor)
        }
        ReplayMode::Initial { terminal } if actual != terminal => {
            Err(corrupt("initial replay escaped frozen terminal"))
        }
        ReplayMode::Initial { terminal } => {
            reject_max_cursor(terminal)?;
            validate_position_through(key, position, terminal)
        }
        ReplayMode::PostTerminal => validate_position_through(key, position, actual),
    }
}

fn validate_position_through(
    key: StreamKey,
    position: &ReplayPosition,
    through: StreamCursor,
) -> Result<(), StoreError> {
    match position {
        ReplayPosition::Start(start) => validate_cursor_pair(*start, through),
        ReplayPosition::Continue(cursor) => {
            let through_seq = cursor_value(through)?;
            if cursor.stream_route != key.stream_route
                || cursor.generation != key.generation
                || cursor.through_seq != through_seq
                || cursor.next_seq > cursor.through_seq
            {
                return Err(StoreError::InvalidReplayCursor);
            }
            Ok(())
        }
    }
}

fn expected_first_seq(
    key: StreamKey,
    position: &ReplayPosition,
) -> Result<Option<u64>, StoreError> {
    match position {
        ReplayPosition::Start(cursor) => Ok(Some(next_after_cursor(*cursor)?)),
        ReplayPosition::Continue(cursor) => {
            if cursor.stream_route != key.stream_route
                || cursor.generation != key.generation
                || cursor.next_seq > cursor.through_seq
                || cursor.next_seq == u64::MAX
                || cursor.through_seq == u64::MAX
            {
                return Err(StoreError::InvalidReplayCursor);
            }
            Ok(Some(cursor.next_seq))
        }
    }
}

fn validate_next(
    key: StreamKey,
    position: &ReplayPosition,
    through: Option<u64>,
    expected_after_page: Option<u64>,
    frames: &[OpaqueRouteFrame],
    next: Option<&ReplayCursor>,
) -> Result<(), StoreError> {
    match next {
        Some(next) => {
            let through = through.ok_or_else(|| corrupt("empty stream returned continuation"))?;
            let expected = expected_after_page
                .ok_or_else(|| corrupt("replay continuation overflowed stream sequence"))?;
            if frames.is_empty()
                || next.stream_route != key.stream_route
                || next.generation != key.generation
                || next.next_seq != expected
                || next.through_seq != through
                || next.next_seq > next.through_seq
            {
                return Err(corrupt("invalid replay continuation returned by Store"));
            }
        }
        None if frames.is_empty() => {
            let start = cursor_before_position(position)?;
            if stream_cursor_value(start) != through {
                return Err(corrupt("empty replay page changed the cursor"));
            }
        }
        None => {
            let through = through.ok_or_else(|| corrupt("non-empty page has no terminal"))?;
            let last = frames
                .last()
                .ok_or_else(|| corrupt("terminal replay page lost its frames"))
                .and_then(publish_seq)?;
            if last != through {
                return Err(corrupt(
                    "terminal replay page stopped before frozen boundary",
                ));
            }
        }
    }
    Ok(())
}

fn cursor_before_position(position: &ReplayPosition) -> Result<StreamCursor, StoreError> {
    match position {
        ReplayPosition::Start(cursor) => Ok(*cursor),
        ReplayPosition::Continue(cursor) => {
            let previous = cursor
                .next_seq
                .checked_sub(1)
                .map(StreamCursor::At)
                .unwrap_or(StreamCursor::BeforeFirst);
            Ok(previous)
        }
    }
}

fn publish_seq(frame: &OpaqueRouteFrame) -> Result<u64, StoreError> {
    match &frame.body {
        RelayFrameBody::Publish(publish) => Ok(publish.stream_seq),
        _ => Err(corrupt("replay page rebuilt a non-Publish frame")),
    }
}

fn validate_cursor_pair(start: StreamCursor, terminal: StreamCursor) -> Result<(), StoreError> {
    reject_max_cursor(start)?;
    reject_max_cursor(terminal)?;
    match (start, terminal) {
        (StreamCursor::BeforeFirst, _) => Ok(()),
        (StreamCursor::At(_), StreamCursor::BeforeFirst) => Err(StoreError::InvalidReplayCursor),
        (StreamCursor::At(start), StreamCursor::At(terminal)) if start <= terminal => Ok(()),
        (StreamCursor::At(_), StreamCursor::At(_)) => Err(StoreError::InvalidReplayCursor),
    }
}

fn reject_max_cursor(cursor: StreamCursor) -> Result<(), StoreError> {
    if cursor == StreamCursor::At(u64::MAX) {
        Err(StoreError::InvalidReplayCursor)
    } else {
        Ok(())
    }
}

fn next_after_cursor(cursor: StreamCursor) -> Result<u64, StoreError> {
    match cursor {
        StreamCursor::BeforeFirst => Ok(0),
        StreamCursor::At(value) => value.checked_add(1).ok_or(StoreError::InvalidReplayCursor),
    }
}

fn cursor_value(cursor: StreamCursor) -> Result<u64, StoreError> {
    match cursor {
        StreamCursor::BeforeFirst => Err(StoreError::InvalidReplayCursor),
        StreamCursor::At(value) if value != u64::MAX => Ok(value),
        StreamCursor::At(_) => Err(StoreError::InvalidReplayCursor),
    }
}

fn stream_cursor_value(cursor: StreamCursor) -> Option<u64> {
    match cursor {
        StreamCursor::BeforeFirst => None,
        StreamCursor::At(value) => Some(value),
    }
}

fn corrupt(reason: &'static str) -> StoreError {
    StoreError::InvalidValue {
        field: "replay.page",
        reason,
    }
}

#[cfg(test)]
mod tests {
    use agentdeck_protocol::relay_v2::frame::SealedBlob;
    use agentdeck_protocol::relay_v2::{
        DeviceRouteId, GrantSerial, StreamGenerationId, StreamRouteId,
    };

    use super::*;
    use crate::v2::auth::{AccessContext, DeviceAccess};
    use crate::v2::store::ReplayFrame;

    fn key() -> StreamKey {
        StreamKey {
            stream_route: StreamRouteId::from_bytes([1; 16]),
            generation: StreamGenerationId::from_bytes([2; 16]),
        }
    }

    fn access() -> AccessContext {
        AccessContext::Device(DeviceAccess {
            machine_route: MachineRouteId::from_bytes([3; 16]),
            device_route: DeviceRouteId::from_bytes([4; 16]),
            connection_instance: ConnectionInstanceId::from_bytes([5; 16]),
            grant_serial: GrantSerial::new(6),
            grant_hash: [7; 32],
            device_sign_fingerprint: [8; 32],
        })
    }

    fn canonical_replay(seq: u64, byte: u8) -> ReplayFrame {
        let frame = OpaqueRouteFrame {
            version: RELAY_PROTOCOL_VERSION,
            body: RelayFrameBody::Publish(Publish {
                stream_route: key().stream_route,
                generation: key().generation,
                stream_seq: seq,
                sealed_blob: SealedBlob(vec![byte]),
            }),
        };
        let canonical = encode(&frame);
        ReplayFrame {
            stream_seq: seq,
            frame_hash: Sha256::digest(&canonical).into(),
            sealed_blob: vec![byte],
            size: canonical.len() as u64,
            received_at_ms: 1,
        }
    }

    #[test]
    fn initial_before_first_builds_frozen_continue_and_equal_empty_needs_no_fetch() {
        let ticket = initial_replay_ticket(
            ConnectionInstanceId::from_bytes([5; 16]),
            access(),
            key(),
            9,
            &SubscriptionLease {
                start: StreamCursor::BeforeFirst,
                replay_through: StreamCursor::At(4),
                ack: None,
                duplicate: false,
            },
            CancellationToken::new(),
        )
        .expect("valid frozen lease")
        .expect("non-empty replay");
        assert_eq!(
            ticket.mode,
            ReplayMode::Initial {
                terminal: StreamCursor::At(4)
            }
        );
        assert!(matches!(
            ticket.position,
            ReplayPosition::Continue(ReplayCursor {
                next_seq: 0,
                through_seq: 4,
                ..
            })
        ));

        let empty = initial_replay_ticket(
            ConnectionInstanceId::from_bytes([5; 16]),
            access(),
            key(),
            10,
            &SubscriptionLease {
                start: StreamCursor::BeforeFirst,
                replay_through: StreamCursor::BeforeFirst,
                ack: None,
                duplicate: false,
            },
            CancellationToken::new(),
        )
        .expect("empty stream is valid");
        assert!(empty.is_none());
    }

    #[test]
    fn initial_at_boundary_is_exclusive_and_equal_boundary_needs_no_fetch() {
        let ticket = initial_replay_ticket(
            ConnectionInstanceId::from_bytes([5; 16]),
            access(),
            key(),
            11,
            &SubscriptionLease {
                start: StreamCursor::At(2),
                replay_through: StreamCursor::At(4),
                ack: Some(2),
                duplicate: false,
            },
            CancellationToken::new(),
        )
        .expect("valid At boundary")
        .expect("suffix exists");
        assert!(matches!(
            ticket.position,
            ReplayPosition::Continue(ReplayCursor {
                next_seq: 3,
                through_seq: 4,
                ..
            })
        ));

        let current = initial_replay_ticket(
            ConnectionInstanceId::from_bytes([5; 16]),
            access(),
            key(),
            12,
            &SubscriptionLease {
                start: StreamCursor::At(4),
                replay_through: StreamCursor::At(4),
                ack: Some(4),
                duplicate: true,
            },
            CancellationToken::new(),
        )
        .expect("current cursor is valid");
        assert!(current.is_none());
    }

    #[test]
    fn max_or_reversed_cursor_fails_closed() {
        for lease in [
            SubscriptionLease {
                start: StreamCursor::At(u64::MAX),
                replay_through: StreamCursor::At(u64::MAX),
                ack: None,
                duplicate: false,
            },
            SubscriptionLease {
                start: StreamCursor::At(5),
                replay_through: StreamCursor::At(4),
                ack: None,
                duplicate: false,
            },
            SubscriptionLease {
                start: StreamCursor::At(0),
                replay_through: StreamCursor::BeforeFirst,
                ack: None,
                duplicate: false,
            },
        ] {
            assert!(matches!(
                initial_replay_ticket(
                    ConnectionInstanceId::from_bytes([5; 16]),
                    access(),
                    key(),
                    13,
                    &lease,
                    CancellationToken::new(),
                ),
                Err(StoreError::InvalidReplayCursor)
            ));
        }
        assert!(matches!(
            post_terminal_replay_ticket(
                ConnectionInstanceId::from_bytes([5; 16]),
                access(),
                key(),
                14,
                StreamCursor::At(u64::MAX),
                CancellationToken::new(),
            ),
            Err(StoreError::InvalidReplayCursor)
        ));
    }

    #[test]
    fn canonical_page_validation_accepts_ordered_frame_and_rejects_hash_or_size_corruption() {
        let position = ReplayPosition::Continue(ReplayCursor {
            stream_route: key().stream_route,
            generation: key().generation,
            next_seq: 0,
            through_seq: 0,
        });
        let valid = validate_replay_page(
            key(),
            &position,
            ReplayMode::Initial {
                terminal: StreamCursor::At(0),
            },
            ReplayPage {
                frames: vec![canonical_replay(0, 0xaa)],
                replay_through: StreamCursor::At(0),
                next: None,
            },
        )
        .expect("canonical page");
        assert_eq!(valid.frames.len(), 1);

        let mut bad_hash = canonical_replay(0, 0xaa);
        bad_hash.frame_hash[0] ^= 1;
        assert!(
            validate_replay_page(
                key(),
                &position,
                ReplayMode::Initial {
                    terminal: StreamCursor::At(0),
                },
                ReplayPage {
                    frames: vec![bad_hash],
                    replay_through: StreamCursor::At(0),
                    next: None,
                },
            )
            .is_err()
        );

        let mut bad_size = canonical_replay(0, 0xaa);
        bad_size.size += 1;
        assert!(
            validate_replay_page(
                key(),
                &position,
                ReplayMode::Initial {
                    terminal: StreamCursor::At(0),
                },
                ReplayPage {
                    frames: vec![bad_size],
                    replay_through: StreamCursor::At(0),
                    next: None,
                },
            )
            .is_err()
        );
    }

    #[test]
    fn empty_post_terminal_page_preserves_cursor() {
        let ready = validate_replay_page(
            key(),
            &ReplayPosition::Start(StreamCursor::At(7)),
            ReplayMode::PostTerminal,
            ReplayPage {
                frames: Vec::new(),
                replay_through: StreamCursor::At(7),
                next: None,
            },
        )
        .expect("no missed live frames");
        assert!(ready.frames.is_empty());
        assert!(ready.next.is_none());
        assert_eq!(ready.replay_through, StreamCursor::At(7));
    }
}
