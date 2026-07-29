//! Catalog/Conversation 共用的 snapshot barrier 与 backfill 规划算法。

use agentdeck_protocol::runtime::StreamCursor;

use super::events::RuntimeStreamTarget;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BarrierRequest {
    Subscribe { cursor: StreamCursor },
    Backfill { after: StreamCursor },
}

/// Wire Subscribe(BeforeFirst) 没有 reducer baseline，必须强制 fresh snapshot；带已有
/// cursor 的 warm Subscribe 已有调用方 projection，只需要复用 retained backfill/empty
/// barrier 规划。内部 key-transition 仍可直接使用 `BarrierRequest::Subscribe` 强制冻结
/// snapshot，不能被客户端 warm-resume 语义改写。
pub(crate) const fn subscription_barrier_request(cursor: StreamCursor) -> BarrierRequest {
    match cursor {
        StreamCursor::BeforeFirst => BarrierRequest::Subscribe { cursor },
        StreamCursor::At(_) => BarrierRequest::Backfill { after: cursor },
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn conversation_input(cursor: StreamCursor, high_water: StreamCursor) -> BarrierInput {
        BarrierInput {
            target: RuntimeStreamTarget::Catalog,
            request: subscription_barrier_request(cursor),
            high_water,
            retained_floor: Some(0),
            snapshot_base: StreamCursor::At(0),
            committed_outer: StreamCursor::At(7),
        }
    }

    #[test]
    fn warm_subscribe_at_high_water_uses_empty_incremental_barrier() {
        let decision = plan_barrier(conversation_input(StreamCursor::At(8), StreamCursor::At(8)))
            .expect("plan warm exact-cursor subscribe");

        assert_eq!(
            decision,
            BarrierDecision::SyncComplete {
                through: StreamCursor::At(8),
                committed_outer: StreamCursor::At(7),
            }
        );
    }

    #[test]
    fn warm_subscribe_behind_high_water_uses_retained_backfill() {
        let decision = plan_barrier(conversation_input(StreamCursor::At(6), StreamCursor::At(8)))
            .expect("plan warm retained subscribe");

        assert_eq!(
            decision,
            BarrierDecision::Backfill {
                after: StreamCursor::At(6),
                through: StreamCursor::At(8),
                committed_outer: StreamCursor::At(7),
            }
        );
    }

    #[test]
    fn fresh_subscribe_keeps_snapshot_barrier_while_internal_subscribe_stays_explicit() {
        assert_eq!(
            subscription_barrier_request(StreamCursor::BeforeFirst),
            BarrierRequest::Subscribe {
                cursor: StreamCursor::BeforeFirst,
            }
        );
        assert_eq!(
            plan_barrier(BarrierInput {
                target: RuntimeStreamTarget::Catalog,
                request: BarrierRequest::Subscribe {
                    cursor: StreamCursor::At(8),
                },
                high_water: StreamCursor::At(8),
                retained_floor: Some(0),
                snapshot_base: StreamCursor::At(0),
                committed_outer: StreamCursor::At(7),
            })
            .expect("plan internal forced snapshot"),
            BarrierDecision::Snapshot {
                base: StreamCursor::At(0),
                through: StreamCursor::At(8),
                committed_outer: StreamCursor::At(7),
            }
        );
    }
}
