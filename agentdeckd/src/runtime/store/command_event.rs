//! Store-owned command critical records。
//!
//! 威胁场景：若 Start/terminal transaction 接受调用方提供的任意 event/result bytes，内部错误路径
//! 可以把 Item/Error 冒充 command 状态指针，造成 durable state 与 authenticated audit 语义分叉。

use agentdeck_protocol::runtime::identity::{CommandId, ConversationId, EventId, TurnId};
use agentdeck_protocol::runtime::{RuntimeEvent, RuntimeEventBody, RuntimeFailure};
use serde::Serialize;

use crate::runtime::model::{
    AcceptedTerminationReason, CommandRecord, CommandTerminal, MAX_CRITICAL_COMMAND_RECORD_BYTES,
    RuntimeStoreError, StartedBeforeReleaseTermination,
};

use super::RuntimeId;

#[derive(Clone)]
pub(super) enum StartEventSource {
    Canonical,
    /// 冻结 v1 migration 样本只能由 crate unit test 构造，release library 不含该入口。
    #[cfg(test)]
    LegacyV1Fixture {
        intent: Vec<u8>,
        event: Vec<u8>,
    },
}

impl StartEventSource {
    pub(super) fn retained_capacity(&self) -> usize {
        match self {
            Self::Canonical => MAX_CRITICAL_COMMAND_RECORD_BYTES,
            #[cfg(test)]
            Self::LegacyV1Fixture { intent, event } => {
                intent.capacity().saturating_add(event.capacity())
            }
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct CommandEventIdentity {
    pub(super) conversation_id: RuntimeId,
    pub(super) command_id: RuntimeId,
    pub(super) turn_id: RuntimeId,
    pub(super) event_id: RuntimeId,
    pub(super) event_seq: u64,
}

pub(super) struct StartCriticalRecords {
    pub(super) intent: Vec<u8>,
    pub(super) event: Vec<u8>,
}

pub(super) struct TerminalCriticalRecords {
    pub(super) result: Vec<u8>,
    pub(super) event: Vec<u8>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExecutionIntentV1<'a> {
    kind: &'static str,
    version: u8,
    conversation_id: &'a str,
    command_id: &'a str,
    command_seq: u64,
}

#[derive(Serialize)]
#[serde(tag = "state", rename_all = "camelCase")]
enum TerminalResultV1<'a> {
    Completed {
        origin: TerminalOperationOrigin,
    },
    Failed {
        origin: TerminalOperationOrigin,
        code: &'a str,
    },
    Interrupted {
        origin: TerminalOperationOrigin,
    },
    Canceled {
        origin: TerminalOperationOrigin,
    },
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
enum TerminalOperationOrigin {
    AfterReleaseAuthorization,
    BeforeRelease,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AcceptedTerminalEventV1<'a> {
    // 保持既有 serde_json Value 的稳定字节顺序：commandId 在 kind 前。
    command_id: &'a str,
    kind: &'static str,
}

pub(super) fn accepted_terminal_event(
    command_id: RuntimeId,
    reason: AcceptedTerminationReason,
) -> Result<Vec<u8>, RuntimeStoreError> {
    let kind = match reason {
        AcceptedTerminationReason::Canceled => "commandCanceledBeforeStart",
        AcceptedTerminationReason::RevokedBeforeStart => "commandRevokedBeforeStart",
    };
    let command_id = command_id.to_canonical_string();
    let event = serde_json::to_vec(&AcceptedTerminalEventV1 {
        command_id: &command_id,
        kind,
    })
    .map_err(|_| RuntimeStoreError::InvalidConfig("accepted terminal event encoding failed"))?;
    ensure_critical_size(&event, "accepted terminal event exceeds its fixed limit")?;
    Ok(event)
}

pub(super) fn start_records(
    command: &CommandRecord,
    identity: CommandEventIdentity,
    source: &StartEventSource,
) -> Result<StartCriticalRecords, RuntimeStoreError> {
    let conversation_id = identity.conversation_id.to_canonical_string();
    let command_id = identity.command_id.to_canonical_string();
    let canonical_intent = serde_json::to_vec(&ExecutionIntentV1 {
        kind: "runtimeExecutionIntent",
        version: 1,
        conversation_id: &conversation_id,
        command_id: &command_id,
        command_seq: command.command_seq,
    })
    .map_err(|_| RuntimeStoreError::InvalidConfig("critical intent encoding failed"))?;
    ensure_critical_size(&canonical_intent, "critical intent exceeds its fixed limit")?;
    let canonical_event = || {
        encode_event(
            identity,
            RuntimeEventBody::TurnStarted {
                turn_id: TurnId::new(identity.turn_id.to_canonical_string()),
            },
        )
    };
    let (intent, event) = match source {
        StartEventSource::Canonical => (canonical_intent, canonical_event()?),
        #[cfg(test)]
        StartEventSource::LegacyV1Fixture { intent, event } => {
            if intent.is_empty()
                || intent.len() > crate::runtime::model::MAX_EXECUTION_INTENT_BYTES
                || event.is_empty()
                || event.len() > crate::runtime::model::MAX_RUNTIME_EVENT_BYTES
            {
                return Err(RuntimeStoreError::PayloadTooLarge);
            }
            (intent.clone(), event.clone())
        }
    };
    Ok(StartCriticalRecords { intent, event })
}

pub(super) fn terminal_records(
    identity: CommandEventIdentity,
    terminal: &CommandTerminal,
) -> Result<TerminalCriticalRecords, RuntimeStoreError> {
    let (result, body) = match terminal.terminal_state() {
        crate::runtime::model::TerminalState::Completed => {
            let summary = terminal
                .completed_summary()
                .ok_or(RuntimeStoreError::InvalidStateTransition)?;
            (
                TerminalResultV1::Completed {
                    origin: TerminalOperationOrigin::AfterReleaseAuthorization,
                },
                RuntimeEventBody::TurnCompleted {
                    turn_id: TurnId::new(identity.turn_id.to_canonical_string()),
                    summary: summary.clone(),
                },
            )
        }
        crate::runtime::model::TerminalState::Failed => {
            let failure = terminal
                .failure()
                .ok_or(RuntimeStoreError::InvalidStateTransition)?;
            (
                TerminalResultV1::Failed {
                    origin: TerminalOperationOrigin::AfterReleaseAuthorization,
                    code: failure.code(),
                },
                RuntimeEventBody::Error {
                    failure: RuntimeFailure::new(failure.code(), failure.message()),
                },
            )
        }
        crate::runtime::model::TerminalState::Interrupted => (
            TerminalResultV1::Interrupted {
                origin: TerminalOperationOrigin::AfterReleaseAuthorization,
            },
            RuntimeEventBody::TurnInterrupted {
                turn_id: TurnId::new(identity.turn_id.to_canonical_string()),
            },
        ),
        crate::runtime::model::TerminalState::Canceled => (
            TerminalResultV1::Canceled {
                origin: TerminalOperationOrigin::AfterReleaseAuthorization,
            },
            RuntimeEventBody::TurnInterrupted {
                turn_id: TurnId::new(identity.turn_id.to_canonical_string()),
            },
        ),
    };
    encode_terminal(identity, result, body)
}

pub(super) fn before_release_terminal_records(
    identity: CommandEventIdentity,
    reason: StartedBeforeReleaseTermination,
) -> Result<TerminalCriticalRecords, RuntimeStoreError> {
    let result = match reason {
        StartedBeforeReleaseTermination::Canceled => TerminalResultV1::Canceled {
            origin: TerminalOperationOrigin::BeforeRelease,
        },
        StartedBeforeReleaseTermination::Interrupted => TerminalResultV1::Interrupted {
            origin: TerminalOperationOrigin::BeforeRelease,
        },
    };
    encode_terminal(
        identity,
        result,
        RuntimeEventBody::TurnInterrupted {
            turn_id: TurnId::new(identity.turn_id.to_canonical_string()),
        },
    )
}

fn encode_terminal(
    identity: CommandEventIdentity,
    result: TerminalResultV1<'_>,
    body: RuntimeEventBody,
) -> Result<TerminalCriticalRecords, RuntimeStoreError> {
    let result = serde_json::to_vec(&result)
        .map_err(|_| RuntimeStoreError::InvalidConfig("critical result encoding failed"))?;
    ensure_critical_size(&result, "critical result exceeds its fixed limit")?;
    let event = encode_event(identity, body)?;
    Ok(TerminalCriticalRecords { result, event })
}

fn encode_event(
    identity: CommandEventIdentity,
    body: RuntimeEventBody,
) -> Result<Vec<u8>, RuntimeStoreError> {
    let event = RuntimeEvent::new(
        ConversationId::new(identity.conversation_id.to_canonical_string()),
        EventId::new(identity.event_id.to_canonical_string()),
        identity.event_seq,
        Some(CommandId::new(identity.command_id.to_canonical_string())),
        None,
        None,
        body,
    )
    .map_err(|_| RuntimeStoreError::InvalidConfig("critical event identity is invalid"))?;
    let encoded = serde_json::to_vec(&event)
        .map_err(|_| RuntimeStoreError::InvalidConfig("critical event encoding failed"))?;
    ensure_critical_size(&encoded, "critical event exceeds its fixed limit")?;
    Ok(encoded)
}

fn ensure_critical_size(payload: &[u8], reason: &'static str) -> Result<(), RuntimeStoreError> {
    if payload.is_empty() || payload.len() > MAX_CRITICAL_COMMAND_RECORD_BYTES {
        Err(RuntimeStoreError::InvalidConfig(reason))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use agentdeck_protocol::TurnSummary;

    use super::*;
    use crate::runtime::model::{CommandState, IdempotencyOwner};
    use crate::runtime::store::{RuntimeIdKind, SanitizedTerminalFailure};

    fn id(kind: RuntimeIdKind, seed: u8) -> RuntimeId {
        RuntimeId::from_bytes(kind, [seed; 16]).expect("non-zero id")
    }

    fn command() -> CommandRecord {
        CommandRecord {
            conversation_id: id(RuntimeIdKind::Conversation, 1),
            command_id: id(RuntimeIdKind::Command, 2),
            command_seq: 7,
            configuration_revision: 0,
            owner: IdempotencyOwner::Local {
                machine_trust_domain: [3; 32],
                uid: 501,
                client_installation_id: [4; 16],
            },
            state: CommandState::Accepted,
            accepted_at_ms: 1,
            expires_at_ms: 2,
            retain_until_ms: 3,
            started_at_ms: None,
            terminal_at_ms: None,
            turn_id: None,
            started_event_id: None,
            terminal_event_id: None,
            payload: Vec::new(),
            result: None,
            remote_authorization: None,
        }
    }

    fn identity() -> CommandEventIdentity {
        CommandEventIdentity {
            conversation_id: id(RuntimeIdKind::Conversation, 1),
            command_id: id(RuntimeIdKind::Command, 2),
            turn_id: id(RuntimeIdKind::Turn, 5),
            event_id: id(RuntimeIdKind::Event, 6),
            event_seq: u64::MAX,
        }
    }

    #[test]
    fn store_owned_records_are_canonical_and_small() {
        let started = start_records(&command(), identity(), &StartEventSource::Canonical)
            .expect("build started records");
        assert!(started.intent.len() <= MAX_CRITICAL_COMMAND_RECORD_BYTES);
        let decoded: RuntimeEvent = serde_json::from_slice(&started.event).expect("started event");
        assert!(matches!(decoded.body, RuntimeEventBody::TurnStarted { .. }));
        assert!(decoded.command_id.is_some());
        assert!(decoded.item_id.is_none() && decoded.entity_id.is_none());

        let completed = terminal_records(
            identity(),
            &CommandTerminal::completed(TurnSummary {
                total_input_tokens: None,
                total_output_tokens: Some(u64::MAX),
                elapsed_ms: u64::MAX,
            }),
        )
        .expect("build completed records");
        assert!(completed.result.len() <= MAX_CRITICAL_COMMAND_RECORD_BYTES);
        assert!(completed.event.len() <= MAX_CRITICAL_COMMAND_RECORD_BYTES);
    }

    #[test]
    fn sanitized_failure_cannot_carry_adapter_text_or_diagnostic_reference() {
        let records = terminal_records(
            identity(),
            &CommandTerminal::failed(SanitizedTerminalFailure::execution_failed()),
        )
        .expect("build failed records");
        let decoded: RuntimeEvent = serde_json::from_slice(&records.event).expect("failed event");
        let RuntimeEventBody::Error { failure } = decoded.body else {
            panic!("failed terminal must be Error");
        };
        assert_eq!(
            failure.code,
            agentdeck_protocol::runtime::failure::DAEMON_RUNTIME_EXECUTION_FAILED
        );
        assert_eq!(failure.diagnostic_ref, None);
        assert_eq!(failure.message, "agent execution failed");
    }

    #[test]
    fn terminal_state_mapping_has_one_canonical_wire_shape_per_state() {
        let interrupted = terminal_records(identity(), &CommandTerminal::interrupted())
            .expect("build interrupted records");
        let canceled = terminal_records(identity(), &CommandTerminal::canceled())
            .expect("build canceled records");
        let interrupted_event: RuntimeEvent =
            serde_json::from_slice(&interrupted.event).expect("interrupted event");
        let canceled_event: RuntimeEvent =
            serde_json::from_slice(&canceled.event).expect("canceled event");
        assert!(matches!(
            interrupted_event.body,
            RuntimeEventBody::TurnInterrupted { .. }
        ));
        assert!(matches!(
            canceled_event.body,
            RuntimeEventBody::TurnInterrupted { .. }
        ));
        assert_eq!(interrupted.event, canceled.event);
        assert_ne!(interrupted.result, canceled.result);

        let before_release =
            before_release_terminal_records(identity(), StartedBeforeReleaseTermination::Canceled)
                .expect("build before-release cancel records");
        assert_eq!(before_release.event, canceled.event);
        assert_ne!(before_release.result, canceled.result);
        assert!(
            String::from_utf8(before_release.result)
                .expect("result utf8")
                .contains("beforeRelease")
        );
        // release authorization 的 COMMIT 不证明 capability 已送达或 vendor 已 exec；
        // durable result 只能陈述已越过的授权边界，不能升级成执行事实。
        let canceled_result = String::from_utf8(canceled.result).expect("result utf8");
        assert!(canceled_result.contains("afterReleaseAuthorization"));
        assert!(!canceled_result.contains("releasedExecution"));
    }

    #[test]
    fn accepted_terminal_events_are_store_owned_small_and_stable() {
        let command_id = id(RuntimeIdKind::Command, 2);
        let canceled = accepted_terminal_event(command_id, AcceptedTerminationReason::Canceled)
            .expect("canceled event");
        let revoked =
            accepted_terminal_event(command_id, AcceptedTerminationReason::RevokedBeforeStart)
                .expect("revoked event");
        assert_eq!(
            String::from_utf8(canceled).expect("canceled utf8"),
            format!(
                "{{\"commandId\":\"{}\",\"kind\":\"commandCanceledBeforeStart\"}}",
                command_id.to_canonical_string()
            )
        );
        assert_eq!(
            String::from_utf8(revoked).expect("revoked utf8"),
            format!(
                "{{\"commandId\":\"{}\",\"kind\":\"commandRevokedBeforeStart\"}}",
                command_id.to_canonical_string()
            )
        );
    }
}
