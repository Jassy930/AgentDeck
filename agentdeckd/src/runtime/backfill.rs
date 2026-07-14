//! Catalog/Conversation 共用的 snapshot barrier 与 backfill 规划算法。

use agentdeck_protocol::runtime::StreamCursor;

use super::events::RuntimeStreamTarget;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BarrierRequest {
    Subscribe { cursor: StreamCursor },
    Backfill { after: StreamCursor },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BarrierInput {
    pub target: RuntimeStreamTarget,
    pub request: BarrierRequest,
    pub high_water: StreamCursor,
    /// 最老仍保留的 entry；空 retained window 为 None。
    pub retained_floor: Option<u64>,
    pub snapshot_base: StreamCursor,
    /// 只允许 Relay durable COMMIT 后的 outer cut。
    pub committed_outer: StreamCursor,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BarrierDecision {
    Snapshot {
        base: StreamCursor,
        through: StreamCursor,
        committed_outer: StreamCursor,
    },
    Backfill {
        after: StreamCursor,
        through: StreamCursor,
        committed_outer: StreamCursor,
    },
    SyncComplete {
        through: StreamCursor,
        committed_outer: StreamCursor,
    },
    NeedSnapshot {
        base: StreamCursor,
    },
    CursorAhead {
        high_water: StreamCursor,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BarrierError {
    #[error("stream generation must rotate before cursor wrap")]
    GenerationRotationRequired,
}

pub fn plan_barrier(input: BarrierInput) -> Result<BarrierDecision, BarrierError> {
    let BarrierInput {
        target: _,
        request,
        high_water,
        retained_floor,
        snapshot_base,
        committed_outer,
    } = input;
    let requested = match request {
        BarrierRequest::Subscribe { cursor } => cursor,
        BarrierRequest::Backfill { after } => after,
    };
    if requested == StreamCursor::At(u64::MAX) {
        return Err(BarrierError::GenerationRotationRequired);
    }
    if matches!(request, BarrierRequest::Subscribe { .. }) {
        return Ok(BarrierDecision::Snapshot {
            base: snapshot_base,
            through: high_water,
            committed_outer,
        });
    }
    let Some(through) = high_water.high_water() else {
        return Ok(match requested {
            StreamCursor::BeforeFirst => BarrierDecision::SyncComplete {
                through: StreamCursor::BeforeFirst,
                committed_outer,
            },
            StreamCursor::At(_) => BarrierDecision::CursorAhead { high_water },
        });
    };
    if requested == high_water {
        return Ok(BarrierDecision::SyncComplete {
            through: high_water,
            committed_outer,
        });
    }
    if requested.high_water().is_some_and(|after| after > through) {
        return Ok(BarrierDecision::CursorAhead { high_water });
    }
    let first = requested
        .checked_next()
        .map_err(|_| BarrierError::GenerationRotationRequired)?;
    if retained_floor.is_none_or(|floor| first < floor) {
        return Ok(BarrierDecision::NeedSnapshot {
            base: snapshot_base,
        });
    }
    Ok(BarrierDecision::Backfill {
        after: requested,
        through: high_water,
        committed_outer,
    })
}
