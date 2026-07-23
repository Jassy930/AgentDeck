use std::sync::{Arc, Mutex};

use agentdeck_crypto::rand_core::{Infallible, TryCryptoRng, TryRng};
use agentdeck_protocol::ActionDecision;
use agentdeck_protocol::runtime::identity::{
    ApprovalId, CommandId, GrantSerial as RuntimeGrantSerial, TurnId,
};
use agentdeck_protocol::runtime::{
    ApprovalReceipt, CommandReceipt, ConversationId, IdempotencyKey, PromptPayload,
    SendPromptRequest,
};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};

use super::mutations::{
    ConnectedMutationRuntime, PersistentRemoteMutation, PersistentRemoteMutationError,
    PersistentRemoteMutationOutcome, RuntimeConnectOutcome, execute_with,
};
use super::paired_machine::{PairedMachineIdentity, PairedPromotionError};
use super::runtime::RemoteRuntimeError;
use super::selector::PersistentMachineSelector;

#[derive(Default)]
struct DeterministicRng(u8);

impl TryRng for DeterministicRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0_u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0_u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        for byte in dest {
            self.0 = self.0.wrapping_add(1);
            *byte = self.0;
        }
        Ok(())
    }
}

impl TryCryptoRng for DeterministicRng {}

#[derive(Clone, Copy)]
enum RuntimeScript {
    Success,
    OutcomeUnknownAfterRouteAccepted,
}

struct FakeRuntime {
    events: Arc<Mutex<Vec<&'static str>>>,
    script: RuntimeScript,
}

impl FakeRuntime {
    fn record(&self, event: &'static str) {
        self.events.lock().expect("event recorder").push(event);
    }
}

impl Drop for FakeRuntime {
    fn drop(&mut self) {
        self.record("runtime_drop");
    }
}

#[async_trait(?Send)]
impl ConnectedMutationRuntime<DeterministicRng> for FakeRuntime {
    async fn execute_non_revoking(
        &mut self,
        mutation: PersistentRemoteMutation,
        _rng: &mut DeterministicRng,
    ) -> Result<PersistentRemoteMutationOutcome, RemoteRuntimeError> {
        let operation = match mutation {
            PersistentRemoteMutation::Prompt(_) => "prompt",
            PersistentRemoteMutation::ResolveApproval { .. } => "approve",
            PersistentRemoteMutation::RetryApproval { .. } => "retry_approval",
            PersistentRemoteMutation::RevokeSelf => panic!("revoke must consume the runtime"),
        };
        self.record(operation);
        match self.script {
            RuntimeScript::Success => Ok(success_outcome(operation)),
            RuntimeScript::OutcomeUnknownAfterRouteAccepted => {
                self.record("route_accepted");
                Err(RemoteRuntimeError::OutcomeUnknown)
            }
        }
    }

    async fn shutdown(self) {
        self.record("shutdown_start");
        tokio::task::yield_now().await;
        self.record("shutdown_complete");
    }

    async fn revoke_self(
        self,
        _rng: &mut DeterministicRng,
    ) -> Result<PersistentRemoteMutationOutcome, RemoteRuntimeError> {
        self.record("revoke_self_consuming");
        self.record("runtime_owned_shutdown_complete");
        Ok(PersistentRemoteMutationOutcome::Revocation {
            route_accepted: true,
            receipt: agentdeck_protocol::runtime::RevocationReceipt::Committed {
                grant_serial: RuntimeGrantSerial::new(7),
            },
        })
    }
}

fn selector() -> PersistentMachineSelector {
    PersistentMachineSelector::parse(&STANDARD.encode([0x11; 32]), &STANDARD.encode([0x22; 16]))
        .expect("canonical selector")
}

fn prompt_mutation() -> PersistentRemoteMutation {
    PersistentRemoteMutation::Prompt(SendPromptRequest {
        conversation_id: ConversationId::new("conversation-1"),
        idempotency_key: IdempotencyKey::new("prompt-1"),
        expected_configuration_revision: 7,
        prompt: PromptPayload::new("continue safely").expect("bounded prompt"),
    })
}

fn approval_mutation() -> PersistentRemoteMutation {
    PersistentRemoteMutation::ResolveApproval {
        conversation_id: ConversationId::new("conversation-1"),
        turn_id: TurnId::new("turn-1"),
        approval_id: ApprovalId::new("approval-1"),
        decision: ActionDecision {
            request_id: "request-1".to_owned(),
            decision: agentdeck_protocol::ActionDecisionKind::Deny,
            persist: true,
        },
    }
}

fn retry_mutation() -> PersistentRemoteMutation {
    PersistentRemoteMutation::RetryApproval {
        conversation_id: ConversationId::new("conversation-1"),
        approval_id: ApprovalId::new("approval-1"),
    }
}

fn success_outcome(operation: &str) -> PersistentRemoteMutationOutcome {
    match operation {
        "prompt" => PersistentRemoteMutationOutcome::Prompt {
            route_accepted: false,
            receipt: CommandReceipt::Accepted {
                command_id: CommandId::new("command-1"),
                queue_position: 1,
                configuration_revision: 7,
            },
        },
        "approve" | "retry_approval" => PersistentRemoteMutationOutcome::Approval {
            route_accepted: true,
            receipt: ApprovalReceipt::Applied {
                approval_id: ApprovalId::new("approval-1"),
            },
        },
        _ => panic!("unexpected fake operation"),
    }
}

async fn execute_fake(
    mutation: PersistentRemoteMutation,
    runtime_script: RuntimeScript,
    events: Arc<Mutex<Vec<&'static str>>>,
) -> Result<PersistentRemoteMutationOutcome, PersistentRemoteMutationError> {
    let recover_events = Arc::clone(&events);
    let open_events = Arc::clone(&events);
    let connect_events = Arc::clone(&events);
    let runtime_events = Arc::clone(&events);
    execute_with(
        selector(),
        mutation,
        &mut DeterministicRng::default(),
        move || {
            recover_events
                .lock()
                .expect("event recorder")
                .push("recover");
            Ok(())
        },
        move |(), identity| {
            open_events
                .lock()
                .expect("event recorder")
                .push("open_exact");
            assert_eq!(identity, selector().identity());
            Ok(identity)
        },
        move |machine: PairedMachineIdentity| async move {
            connect_events
                .lock()
                .expect("event recorder")
                .push("connect");
            assert_eq!(machine, selector().identity());
            Ok(RuntimeConnectOutcome::Connected(FakeRuntime {
                events: runtime_events,
                script: runtime_script,
            }))
        },
    )
    .await
}

#[tokio::test]
async fn recovery_open_connect_and_shutdown_are_strictly_ordered() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let outcome = execute_fake(
        prompt_mutation(),
        RuntimeScript::Success,
        Arc::clone(&events),
    )
    .await
    .expect("authenticated daemon receipt");

    assert!(matches!(
        outcome,
        PersistentRemoteMutationOutcome::Prompt {
            route_accepted: false,
            receipt: CommandReceipt::Accepted { .. },
        }
    ));
    assert_eq!(
        *events.lock().expect("event recorder"),
        [
            "recover",
            "open_exact",
            "connect",
            "prompt",
            "shutdown_start",
            "shutdown_complete",
            "runtime_drop",
        ]
    );
}

#[tokio::test]
async fn recovery_and_open_failures_never_call_the_connector() {
    let connector_calls = Arc::new(Mutex::new(0_usize));
    let calls = Arc::clone(&connector_calls);
    let recovery_error = execute_with(
        selector(),
        prompt_mutation(),
        &mut DeterministicRng::default(),
        || Err::<(), _>(PairedPromotionError::InvalidState.into()),
        |(), _| Ok::<_, PersistentRemoteMutationError>(()),
        move |()| async move {
            *calls.lock().expect("connector calls") += 1;
            Ok(RuntimeConnectOutcome::Connected(FakeRuntime {
                events: Arc::new(Mutex::new(Vec::new())),
                script: RuntimeScript::Success,
            }))
        },
    )
    .await
    .expect_err("recovery must fail closed");
    assert_eq!(recovery_error.code(), "remote.pairing.paired_invalid");
    assert_eq!(*connector_calls.lock().expect("connector calls"), 0);

    let calls = Arc::clone(&connector_calls);
    let open_error = execute_with(
        selector(),
        prompt_mutation(),
        &mut DeterministicRng::default(),
        || Ok(()),
        |(), _| Err::<(), _>(PairedPromotionError::Incomplete.into()),
        move |()| async move {
            *calls.lock().expect("connector calls") += 1;
            Ok(RuntimeConnectOutcome::Connected(FakeRuntime {
                events: Arc::new(Mutex::new(Vec::new())),
                script: RuntimeScript::Success,
            }))
        },
    )
    .await
    .expect_err("open must fail closed");
    assert_eq!(open_error.code(), "remote.pairing.paired_incomplete");
    assert_eq!(*connector_calls.lock().expect("connector calls"), 0);
}

#[tokio::test]
async fn prompt_approval_and_retry_always_shutdown_on_success_and_error() {
    for mutation in [prompt_mutation(), approval_mutation(), retry_mutation()] {
        let success_events = Arc::new(Mutex::new(Vec::new()));
        execute_fake(
            mutation,
            RuntimeScript::Success,
            Arc::clone(&success_events),
        )
        .await
        .expect("terminal receipt");
        let success = success_events.lock().expect("event recorder");
        assert!(success.ends_with(&["shutdown_start", "shutdown_complete", "runtime_drop"]));
    }

    for mutation in [prompt_mutation(), approval_mutation(), retry_mutation()] {
        let error_events = Arc::new(Mutex::new(Vec::new()));
        let error = execute_fake(
            mutation,
            RuntimeScript::OutcomeUnknownAfterRouteAccepted,
            Arc::clone(&error_events),
        )
        .await
        .expect_err("RouteAccepted without terminal receipt is not success");
        assert_eq!(error.code(), "remote.runtime.outcome_unknown");
        let error = error_events.lock().expect("event recorder");
        assert!(error.contains(&"route_accepted"));
        assert!(error.ends_with(&["shutdown_start", "shutdown_complete", "runtime_drop"]));
    }
}

#[tokio::test]
async fn revoked_handshake_is_a_typed_non_success_without_runtime_dispatch() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let connect_events = Arc::clone(&events);
    let result = execute_with(
        selector(),
        prompt_mutation(),
        &mut DeterministicRng::default(),
        || Ok(()),
        |(), identity| Ok(identity),
        move |_machine| async move {
            connect_events
                .lock()
                .expect("event recorder")
                .push("connect_revoked");
            Ok(RuntimeConnectOutcome::<FakeRuntime>::Revoked)
        },
    )
    .await;

    let error = result.expect_err("revoked handshake cannot complete the command");
    assert_eq!(error.code(), "remote.runtime.handshake_revoked");
    assert_eq!(*events.lock().expect("event recorder"), ["connect_revoked"]);
}

#[tokio::test]
async fn revoke_self_delegates_to_the_consuming_runtime_path_only_once() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let outcome = execute_fake(
        PersistentRemoteMutation::RevokeSelf,
        RuntimeScript::Success,
        Arc::clone(&events),
    )
    .await
    .expect("signed revocation terminal");
    assert!(matches!(
        outcome,
        PersistentRemoteMutationOutcome::Revocation {
            route_accepted: true,
            ..
        }
    ));
    assert_eq!(
        *events.lock().expect("event recorder"),
        [
            "recover",
            "open_exact",
            "connect",
            "revoke_self_consuming",
            "runtime_owned_shutdown_complete",
            "runtime_drop",
        ]
    );
}

#[test]
fn production_adapter_names_the_only_allowed_recovery_open_connect_chain() {
    let source = include_str!("mutations.rs");
    let body = source
        .split("pub async fn execute_persistent_remote_mutation")
        .nth(1)
        .expect("production mutation adapter");
    let recovery = body
        .find("recovered_paired_machine_store")
        .expect("startup recovery gateway");
    let open = body.find("open_exact").expect("exact machine open");
    let connect = body
        .find("connect_paired_runtime")
        .expect("paired Runtime connector");
    assert!(recovery < open && open < connect);
    for forbidden in [
        concat!("PairedMachineStore", "::new"),
        concat!(".key", "_store()"),
        concat!(".state", "_root()"),
    ] {
        assert!(
            !body.contains(forbidden),
            "production mutation adapter must not bypass branded recovery via {forbidden}"
        );
    }
}

#[test]
fn mutation_debug_never_exposes_prompt_or_approval_material() {
    let prompt = format!("{:?}", prompt_mutation());
    assert_eq!(prompt, "PersistentRemoteMutation::Prompt([REDACTED])");
    assert!(!prompt.contains("continue safely"));

    let approval = format!("{:?}", approval_mutation());
    assert_eq!(
        approval,
        "PersistentRemoteMutation::ResolveApproval([REDACTED])"
    );
    for secret in ["conversation-1", "turn-1", "approval-1", "request-1"] {
        assert!(!approval.contains(secret));
    }
}
