//! Durable machine enrollment orchestration。

use std::fmt;
use std::sync::Arc;

use agentdeck_crypto::sha256;
use agentdeck_protocol::relay_v2::{
    CertRole, MachineEnrollmentRequestV1, MachineEnrollmentResponseV1, RelayServerId,
    enrollment_receipt_hash,
};
use agentdeck_relay_client::{
    EnrollmentClientConfig, RelayClientConfig, RelayClientError, RelayEnrollmentClient,
};
use async_trait::async_trait;

use crate::runtime::store::{
    ActivateMachineEnrollmentOutcome, ActiveMachineEnrollmentState,
    MachineEnrollmentConnectionMaterial, MachineEnrollmentState, MachineIdentityBinding,
    MachineRemoteLifecycle, PrepareMachineEnrollmentOutcome,
    RecordValidatedEnrollmentResponseOutcome, RuntimeCommitOperation, RuntimeStoreError,
    RuntimeStoreHandle,
};

use super::config::{
    EnrollmentConfigError, ValidatedEnrollmentConfig, validate_sealed_relay_connection,
};
use super::enrollment::FrozenMachineEnrollmentParts;

#[async_trait]
pub(super) trait EnrollmentEndpoint: Send + Sync {
    async fn enroll(
        &self,
        config: RelayClientConfig,
        request: MachineEnrollmentRequestV1,
    ) -> Result<MachineEnrollmentResponseV1, RelayClientError>;
}

struct RelayEndpoint;

#[async_trait]
impl EnrollmentEndpoint for RelayEndpoint {
    async fn enroll(
        &self,
        config: RelayClientConfig,
        request: MachineEnrollmentRequestV1,
    ) -> Result<MachineEnrollmentResponseV1, RelayClientError> {
        RelayEnrollmentClient::enroll_machine(EnrollmentClientConfig::new(config), request).await
    }
}

#[async_trait]
trait EnrollmentStore: Send + Sync {
    async fn load(&self) -> Result<Option<MachineEnrollmentState>, RuntimeStoreError>;

    async fn prepare(
        &self,
        bundle: agentdeck_protocol::relay_v2::EnrollmentBundleV2,
        machine_route: agentdeck_protocol::relay_v2::MachineRouteId,
        binding: MachineIdentityBinding,
        link_cert: agentdeck_protocol::relay_v2::SignedCertificate,
        data_cert: agentdeck_protocol::relay_v2::SignedCertificate,
    ) -> Result<PrepareMachineEnrollmentOutcome, RuntimeStoreError>;

    async fn record_response(
        &self,
        expected_request_hash: [u8; 32],
        response: MachineEnrollmentResponseV1,
    ) -> Result<RecordValidatedEnrollmentResponseOutcome, RuntimeStoreError>;

    async fn activate(
        &self,
        expected_request_hash: [u8; 32],
        expected_response_hash: [u8; 32],
    ) -> Result<ActivateMachineEnrollmentOutcome, RuntimeStoreError>;
}

#[async_trait]
impl EnrollmentStore for RuntimeStoreHandle {
    async fn load(&self) -> Result<Option<MachineEnrollmentState>, RuntimeStoreError> {
        self.load_machine_enrollment_state().await
    }

    async fn prepare(
        &self,
        bundle: agentdeck_protocol::relay_v2::EnrollmentBundleV2,
        machine_route: agentdeck_protocol::relay_v2::MachineRouteId,
        binding: MachineIdentityBinding,
        link_cert: agentdeck_protocol::relay_v2::SignedCertificate,
        data_cert: agentdeck_protocol::relay_v2::SignedCertificate,
    ) -> Result<PrepareMachineEnrollmentOutcome, RuntimeStoreError> {
        self.prepare_machine_enrollment(bundle, machine_route, binding, link_cert, data_cert)
            .await
    }

    async fn record_response(
        &self,
        expected_request_hash: [u8; 32],
        response: MachineEnrollmentResponseV1,
    ) -> Result<RecordValidatedEnrollmentResponseOutcome, RuntimeStoreError> {
        self.record_validated_enrollment_response(expected_request_hash, response)
            .await
    }

    async fn activate(
        &self,
        expected_request_hash: [u8; 32],
        expected_response_hash: [u8; 32],
    ) -> Result<ActivateMachineEnrollmentOutcome, RuntimeStoreError> {
        self.activate_machine_enrollment(expected_request_hash, expected_response_hash)
            .await
    }
}

/// Prepared→ResponseValidated→Active 的唯一 durable enrollment orchestrator。
pub struct MachineEnrollmentWorkflow {
    endpoint: Arc<dyn EnrollmentEndpoint>,
}

impl MachineEnrollmentWorkflow {
    #[must_use]
    pub fn new() -> Self {
        Self {
            endpoint: Arc::new(RelayEndpoint),
        }
    }

    /// Fresh owner 的第一项副作用必须是 Store prepare；fresh config 永不直接拨号。
    pub async fn run_fresh(
        &self,
        store: &RuntimeStoreHandle,
        fresh: FrozenMachineEnrollmentParts,
        now_ms: u64,
    ) -> Result<Box<ActiveMachineEnrollmentState>, MachineEnrollmentWorkflowError> {
        self.run_fresh_with_store(store, fresh, now_ms).await
    }

    /// 从 Store sealed state 续做；不存在 durable state 时 fail-close。已 prepare 的请求
    /// 即使 bundle 到期也必须精确重放，因此恢复接口不接收当前时间。
    pub async fn resume(
        &self,
        store: &RuntimeStoreHandle,
    ) -> Result<Box<ActiveMachineEnrollmentState>, MachineEnrollmentWorkflowError> {
        self.resume_with_store(store).await
    }

    async fn run_fresh_with_store(
        &self,
        store: &dyn EnrollmentStore,
        fresh: FrozenMachineEnrollmentParts,
        now_ms: u64,
    ) -> Result<Box<ActiveMachineEnrollmentState>, MachineEnrollmentWorkflowError> {
        let FrozenMachineEnrollmentParts {
            bundle,
            machine_route,
            root_public_key,
            trust_epoch,
            binding,
            link_certificate,
            data_certificate,
            relay_client_config,
            receipt_verify_key,
            request_hash,
        } = fresh;
        let checked = ValidatedEnrollmentConfig::new(bundle, now_ms)
            .map_err(MachineEnrollmentWorkflowError::connection)?;
        let (bundle, checked_relay_config, checked_receipt_verify_key) = checked.into_parts();
        if root_public_key.0 != binding.root_public_key
            || trust_epoch != binding.trust_epoch
            || relay_client_config.origin() != checked_relay_config.origin()
            || receipt_verify_key.wire_anchor() != checked_receipt_verify_key.wire_anchor()
        {
            return Err(MachineEnrollmentWorkflowError::state_conflict());
        }
        drop(checked_relay_config);
        let transient = MachineEnrollmentRequestV1 {
            code: bundle.code.clone(),
            machine_route,
            root_pubkey: root_public_key,
            link_cert: link_certificate.clone(),
            data_cert: data_certificate.clone(),
        };
        if transient.canonical_sha256() != request_hash {
            return Err(MachineEnrollmentWorkflowError::state_conflict());
        }
        drop(transient);
        drop(relay_client_config);

        let prepared = store
            .prepare(
                bundle,
                machine_route,
                binding,
                link_certificate,
                data_certificate,
            )
            .await;
        let state = settle_prepare(store, prepared, request_hash).await?;
        self.drive(store, state).await
    }

    async fn resume_with_store(
        &self,
        store: &dyn EnrollmentStore,
    ) -> Result<Box<ActiveMachineEnrollmentState>, MachineEnrollmentWorkflowError> {
        let state = store
            .load()
            .await
            .map_err(MachineEnrollmentWorkflowError::store)?
            .ok_or_else(MachineEnrollmentWorkflowError::state_missing)?;
        self.drive(store, state).await
    }

    async fn drive(
        &self,
        store: &dyn EnrollmentStore,
        mut state: MachineEnrollmentState,
    ) -> Result<Box<ActiveMachineEnrollmentState>, MachineEnrollmentWorkflowError> {
        loop {
            state = match state {
                MachineEnrollmentState::EnrollmentPrepared(prepared) => {
                    let prepared = *prepared;
                    validate_request_state(
                        &prepared.record,
                        &prepared.connection,
                        &prepared.request,
                        MachineRemoteLifecycle::EnrollmentPrepared,
                    )?;
                    let request_hash = prepared.record.request_hash;
                    let relay_config = rebuild_client_config(&prepared.connection)?;
                    let response = self
                        .endpoint
                        .enroll(relay_config, prepared.request)
                        .await
                        .map_err(MachineEnrollmentWorkflowError::endpoint)?;
                    let response_hash =
                        validate_response(&prepared.record, &prepared.connection, &response)?;
                    let recorded = store.record_response(request_hash, response).await;
                    settle_response(store, recorded, request_hash, response_hash).await?
                }
                MachineEnrollmentState::EnrollmentResponseValidated(validated) => {
                    let validated = *validated;
                    validate_request_state(
                        &validated.record,
                        &validated.connection,
                        &validated.request,
                        MachineRemoteLifecycle::EnrollmentResponseValidated,
                    )?;
                    let request_hash = validated.record.request_hash;
                    let response_hash = validate_response(
                        &validated.record,
                        &validated.connection,
                        &validated.response,
                    )?;
                    let activated = store.activate(request_hash, response_hash).await;
                    settle_activation(store, activated, request_hash, response_hash).await?
                }
                MachineEnrollmentState::Active(active) => {
                    validate_active(&active)?;
                    return Ok(active);
                }
                MachineEnrollmentState::RetirePending(_)
                | MachineEnrollmentState::RelayCommitted(_)
                | MachineEnrollmentState::PurgeReadbackAbsent(_)
                | MachineEnrollmentState::LocalDeleted(_) => {
                    return Err(MachineEnrollmentWorkflowError::state_conflict());
                }
            };
        }
    }

    #[cfg(test)]
    pub(super) fn with_endpoint(endpoint: impl EnrollmentEndpoint + 'static) -> Self {
        Self {
            endpoint: Arc::new(endpoint),
        }
    }
}

impl Default for MachineEnrollmentWorkflow {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for MachineEnrollmentWorkflow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MachineEnrollmentWorkflow([REDACTED])")
    }
}

async fn settle_prepare(
    store: &dyn EnrollmentStore,
    result: Result<PrepareMachineEnrollmentOutcome, RuntimeStoreError>,
    request_hash: [u8; 32],
) -> Result<MachineEnrollmentState, MachineEnrollmentWorkflowError> {
    let state = match result {
        Ok(
            PrepareMachineEnrollmentOutcome::Prepared { state }
            | PrepareMachineEnrollmentOutcome::Replayed { state },
        ) => state,
        Err(RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::PrepareMachineEnrollment,
        }) => load_after_unknown(store).await?,
        Err(error) => return Err(MachineEnrollmentWorkflowError::store(error)),
    };
    require_stage(state, request_hash, None, DurableStage::Prepared)
}

async fn settle_response(
    store: &dyn EnrollmentStore,
    result: Result<RecordValidatedEnrollmentResponseOutcome, RuntimeStoreError>,
    request_hash: [u8; 32],
    response_hash: [u8; 32],
) -> Result<MachineEnrollmentState, MachineEnrollmentWorkflowError> {
    let state = match result {
        Ok(
            RecordValidatedEnrollmentResponseOutcome::Recorded { state }
            | RecordValidatedEnrollmentResponseOutcome::Replayed { state },
        ) => state,
        Err(RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::RecordValidatedEnrollmentResponse,
        }) => load_after_unknown(store).await?,
        Err(error) => return Err(MachineEnrollmentWorkflowError::store(error)),
    };
    require_stage(
        state,
        request_hash,
        Some(response_hash),
        DurableStage::ResponseValidated,
    )
}

async fn settle_activation(
    store: &dyn EnrollmentStore,
    result: Result<ActivateMachineEnrollmentOutcome, RuntimeStoreError>,
    request_hash: [u8; 32],
    response_hash: [u8; 32],
) -> Result<MachineEnrollmentState, MachineEnrollmentWorkflowError> {
    let state = match result {
        Ok(
            ActivateMachineEnrollmentOutcome::Activated { state }
            | ActivateMachineEnrollmentOutcome::Replayed { state },
        ) => state,
        Err(RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::ActivateMachineEnrollment,
        }) => load_after_unknown(store).await?,
        Err(error) => return Err(MachineEnrollmentWorkflowError::store(error)),
    };
    require_stage(
        state,
        request_hash,
        Some(response_hash),
        DurableStage::Active,
    )
}

async fn load_after_unknown(
    store: &dyn EnrollmentStore,
) -> Result<MachineEnrollmentState, MachineEnrollmentWorkflowError> {
    store
        .load()
        .await
        .map_err(MachineEnrollmentWorkflowError::store)?
        .ok_or_else(MachineEnrollmentWorkflowError::state_conflict)
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum DurableStage {
    Prepared,
    ResponseValidated,
    Active,
}

fn require_stage(
    state: MachineEnrollmentState,
    request_hash: [u8; 32],
    response_hash: Option<[u8; 32]>,
    minimum: DurableStage,
) -> Result<MachineEnrollmentState, MachineEnrollmentWorkflowError> {
    let (record, actual) = match &state {
        MachineEnrollmentState::EnrollmentPrepared(value) => {
            (&value.record, DurableStage::Prepared)
        }
        MachineEnrollmentState::EnrollmentResponseValidated(value) => {
            (&value.record, DurableStage::ResponseValidated)
        }
        MachineEnrollmentState::Active(value) => (&value.record, DurableStage::Active),
        MachineEnrollmentState::RetirePending(_)
        | MachineEnrollmentState::RelayCommitted(_)
        | MachineEnrollmentState::PurgeReadbackAbsent(_)
        | MachineEnrollmentState::LocalDeleted(_) => {
            return Err(MachineEnrollmentWorkflowError::state_conflict());
        }
    };
    if actual < minimum
        || request_hash == [0; 32]
        || record.request_hash != request_hash
        || response_hash.is_some_and(|hash| record.response_hash != Some(hash))
    {
        return Err(MachineEnrollmentWorkflowError::state_conflict());
    }
    Ok(state)
}

fn rebuild_client_config(
    connection: &MachineEnrollmentConnectionMaterial,
) -> Result<RelayClientConfig, MachineEnrollmentWorkflowError> {
    let (config, _) = validate_sealed_relay_connection(
        &connection.public_wss_url,
        connection.relay_server_id,
        &connection.receipt_verify_key,
        &connection.spki_pins,
        connection.expires_at_ms,
    )
    .map_err(MachineEnrollmentWorkflowError::connection)?;
    Ok(config)
}

fn validate_request_state(
    record: &crate::runtime::store::MachineRemoteStateRecord,
    connection: &MachineEnrollmentConnectionMaterial,
    request: &MachineEnrollmentRequestV1,
    lifecycle: MachineRemoteLifecycle,
) -> Result<(), MachineEnrollmentWorkflowError> {
    if record.lifecycle != lifecycle
        || record.relay_server_id != *connection.relay_server_id.as_bytes()
        || record.machine_route != *request.machine_route.as_bytes()
        || record.request_hash == [0; 32]
        || record.request_hash != request.canonical_sha256()
        || request.root_pubkey.0 == [0; 32]
        || record.root_fingerprint != sha256(&request.root_pubkey.0)
        || record.root_key_id != *request.link_cert.root_key_id.as_bytes()
        || request.link_cert.root_key_id != request.data_cert.root_key_id
        || request.link_cert.cert_role != CertRole::Link
        || request.data_cert.cert_role != CertRole::Data
        || request.link_cert.trust_epoch != request.data_cert.trust_epoch
        || record.trust_epoch != request.link_cert.trust_epoch.value()
    {
        return Err(MachineEnrollmentWorkflowError::state_conflict());
    }
    Ok(())
}

fn validate_response(
    record: &crate::runtime::store::MachineRemoteStateRecord,
    connection: &MachineEnrollmentConnectionMaterial,
    response: &MachineEnrollmentResponseV1,
) -> Result<[u8; 32], MachineEnrollmentWorkflowError> {
    response
        .validate()
        .map_err(|_| MachineEnrollmentWorkflowError::response_invalid())?;
    let relay_server_id = RelayServerId::from_bytes(record.relay_server_id);
    let machine_route =
        agentdeck_protocol::relay_v2::MachineRouteId::from_bytes(record.machine_route);
    if response.relay_server_id != connection.relay_server_id
        || response.relay_server_id != relay_server_id
        || response.machine_route != machine_route
        || response.trust_epoch != record.trust_epoch
        || response.receipt_hash
            != enrollment_receipt_hash(
                relay_server_id,
                machine_route,
                record.trust_epoch,
                record.request_hash,
            )
    {
        return Err(MachineEnrollmentWorkflowError::response_invalid());
    }
    response
        .canonical_sha256()
        .map_err(|_| MachineEnrollmentWorkflowError::response_invalid())
}

fn validate_active(
    active: &ActiveMachineEnrollmentState,
) -> Result<(), MachineEnrollmentWorkflowError> {
    let response_hash = validate_response(&active.record, &active.connection, &active.response)?;
    if active.record.lifecycle != MachineRemoteLifecycle::Active
        || active.record.response_hash != Some(response_hash)
        || active.record.enrollment_receipt_hash != Some(active.response.receipt_hash)
        || active.record.root_key_id != active.binding.root_key_id
        || active.record.root_fingerprint != active.binding.root_fingerprint
        || active.record.trust_epoch != active.binding.trust_epoch
        || active.link_cert.cert_role != CertRole::Link
        || active.data_cert.cert_role != CertRole::Data
    {
        return Err(MachineEnrollmentWorkflowError::state_conflict());
    }
    Ok(())
}

enum WorkflowErrorKind {
    Store(RuntimeStoreError),
    Endpoint(RelayClientError),
    Connection(EnrollmentConfigError),
    StateMissing,
    StateConflict,
    ResponseInvalid,
}

pub struct MachineEnrollmentWorkflowError {
    kind: WorkflowErrorKind,
}

impl MachineEnrollmentWorkflowError {
    fn store(error: RuntimeStoreError) -> Self {
        Self {
            kind: WorkflowErrorKind::Store(error),
        }
    }

    fn endpoint(error: RelayClientError) -> Self {
        Self {
            kind: WorkflowErrorKind::Endpoint(error),
        }
    }

    fn connection(error: EnrollmentConfigError) -> Self {
        Self {
            kind: WorkflowErrorKind::Connection(error),
        }
    }

    fn state_missing() -> Self {
        Self {
            kind: WorkflowErrorKind::StateMissing,
        }
    }

    fn state_conflict() -> Self {
        Self {
            kind: WorkflowErrorKind::StateConflict,
        }
    }

    fn response_invalid() -> Self {
        Self {
            kind: WorkflowErrorKind::ResponseInvalid,
        }
    }

    #[must_use]
    pub fn code(&self) -> &str {
        match &self.kind {
            WorkflowErrorKind::Store(error) => error.code(),
            WorkflowErrorKind::Endpoint(error) => error.code(),
            WorkflowErrorKind::Connection(error) => error.code(),
            WorkflowErrorKind::StateMissing => "daemon.remote.enrollment.state_missing",
            WorkflowErrorKind::StateConflict => "daemon.remote.enrollment.state_conflict",
            WorkflowErrorKind::ResponseInvalid => "daemon.remote.enrollment.response_invalid",
        }
    }
}

impl fmt::Debug for MachineEnrollmentWorkflowError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MachineEnrollmentWorkflowError")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for MachineEnrollmentWorkflowError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for MachineEnrollmentWorkflowError {}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

    use agentdeck_crypto::{SigningKey, ValidatedRelayReceiptSignerIdentityV1, sign_tbs};
    use agentdeck_protocol::relay_v2::{
        Digest32, ENROLLMENT_BUNDLE_VERSION, Ed25519Signature, EnrollmentBundleV2, EnrollmentCode,
        LinkGeneration, MachineRouteId, PublicKeyBytes, RelayServerId, RootKeyId,
        SignedCertificate, TrustEpoch,
    };

    use super::*;
    const NOW_MS: u64 = 1_700_000_000_000;
    const RELAY: RelayServerId = RelayServerId::from_bytes([0x31; 16]);
    const ROUTE: MachineRouteId = MachineRouteId::from_bytes([0x32; 16]);

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum FakeLifecycle {
        Prepared,
        Validated,
        Active,
    }

    #[derive(Clone)]
    struct FakeDurable {
        lifecycle: FakeLifecycle,
        connection: MachineEnrollmentConnectionMaterial,
        request: MachineEnrollmentRequestV1,
        binding: MachineIdentityBinding,
        link_cert: SignedCertificate,
        data_cert: SignedCertificate,
        response: Option<MachineEnrollmentResponseV1>,
    }

    #[derive(Default)]
    struct UnknownFlags {
        prepare: bool,
        response: bool,
        activate: bool,
    }

    #[derive(Default)]
    struct FakeStore {
        durable: Mutex<Option<FakeDurable>>,
        unknown: Mutex<UnknownFlags>,
        fail_activate_once: AtomicBool,
        prepares: AtomicUsize,
        records: AtomicUsize,
        activates: AtomicUsize,
        loads: AtomicUsize,
        events: Arc<Mutex<Vec<&'static str>>>,
    }

    impl FakeStore {
        fn with_unknowns() -> Self {
            Self {
                unknown: Mutex::new(UnknownFlags {
                    prepare: true,
                    response: true,
                    activate: true,
                }),
                ..Self::default()
            }
        }

        fn lifecycle(&self) -> Option<FakeLifecycle> {
            self.durable
                .lock()
                .expect("lock fake durable state")
                .as_ref()
                .map(|state| state.lifecycle)
        }

        fn mutate_connection(&self, mutate: impl FnOnce(&mut MachineEnrollmentConnectionMaterial)) {
            let mut durable = self.durable.lock().expect("lock fake durable state");
            mutate(&mut durable.as_mut().expect("prepared durable state").connection);
        }

        fn state(&self) -> Option<MachineEnrollmentState> {
            self.durable
                .lock()
                .expect("lock fake durable state")
                .as_ref()
                .map(fake_public_state)
        }
    }

    #[async_trait]
    impl EnrollmentStore for FakeStore {
        async fn load(&self) -> Result<Option<MachineEnrollmentState>, RuntimeStoreError> {
            self.loads.fetch_add(1, Ordering::SeqCst);
            self.events.lock().expect("lock events").push("load");
            Ok(self.state())
        }

        async fn prepare(
            &self,
            bundle: EnrollmentBundleV2,
            machine_route: MachineRouteId,
            binding: MachineIdentityBinding,
            link_cert: SignedCertificate,
            data_cert: SignedCertificate,
        ) -> Result<PrepareMachineEnrollmentOutcome, RuntimeStoreError> {
            self.prepares.fetch_add(1, Ordering::SeqCst);
            self.events.lock().expect("lock events").push("prepare");
            let request = MachineEnrollmentRequestV1 {
                code: bundle.code,
                machine_route,
                root_pubkey: PublicKeyBytes(binding.root_public_key),
                link_cert: link_cert.clone(),
                data_cert: data_cert.clone(),
            };
            let connection = MachineEnrollmentConnectionMaterial {
                public_wss_url: bundle.public_wss_url,
                relay_server_id: bundle.relay_server_id,
                receipt_verify_key: bundle.receipt_verify_key,
                spki_pins: bundle.spki_pins,
                expires_at_ms: bundle.expires_at_ms,
            };
            let durable = FakeDurable {
                lifecycle: FakeLifecycle::Prepared,
                connection,
                request,
                binding,
                link_cert,
                data_cert,
                response: None,
            };
            let mut current = self.durable.lock().expect("lock fake durable state");
            let replayed = current.is_some();
            if let Some(existing) = current.as_ref() {
                if existing.request.canonical_sha256() != durable.request.canonical_sha256() {
                    return Err(RuntimeStoreError::MachineRemoteConflict);
                }
            } else {
                *current = Some(durable);
            }
            drop(current);
            if take_flag(&self.unknown, |flags| &mut flags.prepare) {
                return Err(RuntimeStoreError::CommitOutcomeUnknown {
                    operation: RuntimeCommitOperation::PrepareMachineEnrollment,
                });
            }
            let state = self.state().expect("prepared fake state");
            if replayed {
                Ok(PrepareMachineEnrollmentOutcome::Replayed { state })
            } else {
                Ok(PrepareMachineEnrollmentOutcome::Prepared { state })
            }
        }

        async fn record_response(
            &self,
            expected_request_hash: [u8; 32],
            response: MachineEnrollmentResponseV1,
        ) -> Result<RecordValidatedEnrollmentResponseOutcome, RuntimeStoreError> {
            self.records.fetch_add(1, Ordering::SeqCst);
            self.events.lock().expect("lock events").push("record");
            let mut durable = self.durable.lock().expect("lock fake durable state");
            let state = durable
                .as_mut()
                .ok_or(RuntimeStoreError::MachineRemoteConflict)?;
            if state.request.canonical_sha256() != expected_request_hash {
                return Err(RuntimeStoreError::MachineRemoteConflict);
            }
            state.response = Some(response);
            state.lifecycle = FakeLifecycle::Validated;
            drop(durable);
            if take_flag(&self.unknown, |flags| &mut flags.response) {
                return Err(RuntimeStoreError::CommitOutcomeUnknown {
                    operation: RuntimeCommitOperation::RecordValidatedEnrollmentResponse,
                });
            }
            Ok(RecordValidatedEnrollmentResponseOutcome::Recorded {
                state: self.state().expect("validated fake state"),
            })
        }

        async fn activate(
            &self,
            expected_request_hash: [u8; 32],
            expected_response_hash: [u8; 32],
        ) -> Result<ActivateMachineEnrollmentOutcome, RuntimeStoreError> {
            self.activates.fetch_add(1, Ordering::SeqCst);
            self.events.lock().expect("lock events").push("activate");
            if self.fail_activate_once.swap(false, Ordering::SeqCst) {
                return Err(RuntimeStoreError::WorkerStopped);
            }
            let mut durable = self.durable.lock().expect("lock fake durable state");
            let state = durable
                .as_mut()
                .ok_or(RuntimeStoreError::MachineRemoteConflict)?;
            let response = state
                .response
                .as_ref()
                .ok_or(RuntimeStoreError::MachineRemoteConflict)?;
            if state.request.canonical_sha256() != expected_request_hash
                || response.canonical_sha256().ok() != Some(expected_response_hash)
            {
                return Err(RuntimeStoreError::MachineRemoteConflict);
            }
            state.lifecycle = FakeLifecycle::Active;
            drop(durable);
            if take_flag(&self.unknown, |flags| &mut flags.activate) {
                return Err(RuntimeStoreError::CommitOutcomeUnknown {
                    operation: RuntimeCommitOperation::ActivateMachineEnrollment,
                });
            }
            Ok(ActivateMachineEnrollmentOutcome::Activated {
                state: self.state().expect("active fake state"),
            })
        }
    }

    fn take_flag(
        flags: &Mutex<UnknownFlags>,
        select: impl FnOnce(&mut UnknownFlags) -> &mut bool,
    ) -> bool {
        let mut flags = flags.lock().expect("lock unknown flags");
        std::mem::take(select(&mut flags))
    }

    fn fake_public_state(durable: &FakeDurable) -> MachineEnrollmentState {
        let record = fake_record(durable);
        match durable.lifecycle {
            FakeLifecycle::Prepared => MachineEnrollmentState::EnrollmentPrepared(Box::new(
                crate::runtime::store::PreparedMachineEnrollmentState {
                    record,
                    connection: durable.connection.clone(),
                    request: durable.request.clone(),
                },
            )),
            FakeLifecycle::Validated => MachineEnrollmentState::EnrollmentResponseValidated(
                Box::new(crate::runtime::store::ValidatedMachineEnrollmentState {
                    record,
                    connection: durable.connection.clone(),
                    request: durable.request.clone(),
                    response: durable.response.clone().expect("validated response"),
                }),
            ),
            FakeLifecycle::Active => {
                MachineEnrollmentState::Active(Box::new(ActiveMachineEnrollmentState {
                    record,
                    connection: durable.connection.clone(),
                    binding: durable.binding.clone(),
                    link_cert: durable.link_cert.clone(),
                    data_cert: durable.data_cert.clone(),
                    prepare_input_hash: [0x91; 32],
                    response: durable.response.clone().expect("active response"),
                }))
            }
        }
    }

    fn fake_record(durable: &FakeDurable) -> crate::runtime::store::MachineRemoteStateRecord {
        let request_hash = durable.request.canonical_sha256();
        let response_hash = durable
            .response
            .as_ref()
            .map(|response| response.canonical_sha256().expect("valid fake response"));
        crate::runtime::store::MachineRemoteStateRecord {
            lifecycle: match durable.lifecycle {
                FakeLifecycle::Prepared => MachineRemoteLifecycle::EnrollmentPrepared,
                FakeLifecycle::Validated => MachineRemoteLifecycle::EnrollmentResponseValidated,
                FakeLifecycle::Active => MachineRemoteLifecycle::Active,
            },
            relay_server_id: durable.connection.relay_server_id.0,
            machine_route: durable.request.machine_route.0,
            root_key_id: durable.binding.root_key_id,
            root_fingerprint: durable.binding.root_fingerprint,
            trust_epoch: durable.binding.trust_epoch,
            request_hash,
            response_hash,
            enrollment_receipt_hash: (durable.lifecycle == FakeLifecycle::Active).then(|| {
                durable
                    .response
                    .as_ref()
                    .expect("active response")
                    .receipt_hash
            }),
            receipt_verify_key_hash: durable
                .connection
                .receipt_verify_key
                .canonical_sha256()
                .expect("valid receipt anchor"),
            sealed_state_bytes: 1,
        }
    }

    const ENDPOINT_SUCCESS: u8 = 0;
    const ENDPOINT_FAILURE: u8 = 1;
    const ENDPOINT_INVALID_RESPONSE: u8 = 2;

    #[derive(Clone)]
    struct FakeEndpoint {
        state: Arc<FakeEndpointState>,
    }

    struct FakeEndpointState {
        mode: AtomicU8,
        calls: AtomicUsize,
        requests: Mutex<Vec<Vec<u8>>>,
        origins: Mutex<Vec<String>>,
        events: Arc<Mutex<Vec<&'static str>>>,
    }

    impl FakeEndpoint {
        fn new(mode: u8, events: Arc<Mutex<Vec<&'static str>>>) -> Self {
            Self {
                state: Arc::new(FakeEndpointState {
                    mode: AtomicU8::new(mode),
                    calls: AtomicUsize::new(0),
                    requests: Mutex::new(Vec::new()),
                    origins: Mutex::new(Vec::new()),
                    events,
                }),
            }
        }

        fn set_mode(&self, mode: u8) {
            self.state.mode.store(mode, Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl EnrollmentEndpoint for FakeEndpoint {
        async fn enroll(
            &self,
            config: RelayClientConfig,
            request: MachineEnrollmentRequestV1,
        ) -> Result<MachineEnrollmentResponseV1, RelayClientError> {
            self.state.calls.fetch_add(1, Ordering::SeqCst);
            self.state
                .events
                .lock()
                .expect("lock events")
                .push("network");
            self.state
                .origins
                .lock()
                .expect("lock origins")
                .push(config.origin().to_owned());
            self.state
                .requests
                .lock()
                .expect("lock requests")
                .push(request.canonical_bytes().to_vec());
            match self.state.mode.load(Ordering::SeqCst) {
                ENDPOINT_FAILURE => Err(RelayClientError::Failure {
                    code: "relay.store.unavailable".to_owned(),
                }),
                ENDPOINT_INVALID_RESPONSE => MachineEnrollmentResponseV1::new(
                    RELAY,
                    request.machine_route,
                    request.link_cert.trust_epoch.value(),
                    [0xee; 32],
                )
                .map_err(|_| RelayClientError::Failure {
                    code: "relay.client.enrollment_response_invalid".to_owned(),
                }),
                _ => {
                    let request_hash = request.canonical_sha256();
                    MachineEnrollmentResponseV1::new(
                        RELAY,
                        request.machine_route,
                        request.link_cert.trust_epoch.value(),
                        enrollment_receipt_hash(
                            RELAY,
                            request.machine_route,
                            request.link_cert.trust_epoch.value(),
                            request_hash,
                        ),
                    )
                    .map_err(|_| RelayClientError::Failure {
                        code: "relay.client.enrollment_response_invalid".to_owned(),
                    })
                }
            }
        }
    }

    fn fresh_parts() -> FrozenMachineEnrollmentParts {
        let binding = binding();
        let link_certificate = certificate(&binding, CertRole::Link);
        let data_certificate = certificate(&binding, CertRole::Data);
        let receipt_signer = SigningKey::from_seed(&[0x51; 32]);
        let receipt_verify_key =
            ValidatedRelayReceiptSignerIdentityV1::from_signing_key(&receipt_signer)
                .expect("valid receipt signer")
                .bind_to_relay(RELAY)
                .expect("bind receipt signer")
                .wire_anchor()
                .clone();
        let validated = ValidatedEnrollmentConfig::new(
            EnrollmentBundleV2 {
                version: ENROLLMENT_BUNDLE_VERSION,
                public_wss_url: "wss://relay.example.test:8443/".to_owned(),
                relay_server_id: RELAY,
                receipt_verify_key,
                code: EnrollmentCode([0x61; 32]),
                spki_pins: vec![Digest32([0x62; 32]), Digest32([0x63; 32])],
                expires_at_ms: NOW_MS + 10,
            },
            NOW_MS,
        )
        .expect("valid enrollment config");
        let (bundle, relay_client_config, receipt_verify_key) = validated.into_parts();
        let request_hash = MachineEnrollmentRequestV1 {
            code: bundle.code.clone(),
            machine_route: ROUTE,
            root_pubkey: PublicKeyBytes(binding.root_public_key),
            link_cert: link_certificate.clone(),
            data_cert: data_certificate.clone(),
        }
        .canonical_sha256();
        FrozenMachineEnrollmentParts {
            bundle,
            machine_route: ROUTE,
            root_public_key: PublicKeyBytes(binding.root_public_key),
            trust_epoch: binding.trust_epoch,
            binding,
            link_certificate,
            data_certificate,
            relay_client_config,
            receipt_verify_key,
            request_hash,
        }
    }

    fn binding() -> MachineIdentityBinding {
        let root_public_key = SigningKey::from_seed(&[0x41; 32])
            .verifying_key()
            .to_bytes();
        let link_sign_public_key = SigningKey::from_seed(&[0x42; 32])
            .verifying_key()
            .to_bytes();
        let data_sign_public_key = SigningKey::from_seed(&[0x43; 32])
            .verifying_key()
            .to_bytes();
        let machine_hpke_public_key = [0x44; 32];
        MachineIdentityBinding {
            root_key_id: [0x45; 16],
            trust_epoch: 1,
            link_generation: 1,
            data_generation: 1,
            key_directory_revision: 0,
            root_public_key,
            root_fingerprint: sha256(&root_public_key),
            machine_hpke_public_key,
            machine_hpke_fingerprint: sha256(&machine_hpke_public_key),
            link_sign_public_key,
            link_sign_fingerprint: sha256(&link_sign_public_key),
            data_sign_public_key,
            data_sign_fingerprint: sha256(&data_sign_public_key),
        }
    }

    fn certificate(binding: &MachineIdentityBinding, role: CertRole) -> SignedCertificate {
        let (subject, generation) = match role {
            CertRole::Link => (binding.link_sign_public_key, binding.link_generation),
            CertRole::Data => (binding.data_sign_public_key, binding.data_generation),
        };
        let mut certificate = SignedCertificate {
            subject_pubkey: PublicKeyBytes(subject),
            cert_role: role,
            generation: LinkGeneration::new(generation),
            root_key_id: RootKeyId::from_bytes(binding.root_key_id),
            trust_epoch: TrustEpoch::new(binding.trust_epoch),
            not_after_ms: None,
            signature: Ed25519Signature([0; 64]),
        };
        certificate.signature = sign_tbs(
            &SigningKey::from_seed(&[0x41; 32]),
            &certificate.to_be_signed_v1(RELAY, ROUTE, binding.root_fingerprint),
        )
        .into();
        certificate
    }

    fn local_deleted_state() -> MachineEnrollmentState {
        let parts = fresh_parts();
        MachineEnrollmentState::LocalDeleted(Box::new(
            crate::runtime::store::LocalDeletedMachineEnrollmentState {
                record: crate::runtime::store::MachineRemoteStateRecord {
                    lifecycle: MachineRemoteLifecycle::LocalDeleted,
                    relay_server_id: *parts.bundle.relay_server_id.as_bytes(),
                    machine_route: *parts.machine_route.as_bytes(),
                    root_key_id: parts.binding.root_key_id,
                    root_fingerprint: parts.binding.root_fingerprint,
                    trust_epoch: parts.binding.trust_epoch,
                    request_hash: parts.request_hash,
                    response_hash: Some([0x91; 32]),
                    enrollment_receipt_hash: Some([0x92; 32]),
                    receipt_verify_key_hash: parts
                        .bundle
                        .receipt_verify_key
                        .canonical_sha256()
                        .expect("valid receipt anchor"),
                    sealed_state_bytes: 1,
                },
                reset_kind: crate::runtime::store::MachineTrustResetKind::RootPresent,
                previous_prepare_input_hash: [0x93; 32],
                purge_proof_hash: [0x94; 32],
                cleanup_witness_hash: [0x95; 32],
            },
        ))
    }

    fn expect_workflow_error(
        result: Result<Box<ActiveMachineEnrollmentState>, MachineEnrollmentWorkflowError>,
        context: &str,
    ) -> MachineEnrollmentWorkflowError {
        match result {
            Ok(_) => panic!("{context}"),
            Err(error) => error,
        }
    }

    #[tokio::test]
    async fn fresh_is_prepared_before_network_then_recorded_before_active() {
        let store = FakeStore::default();
        let endpoint = FakeEndpoint::new(ENDPOINT_SUCCESS, Arc::clone(&store.events));
        let workflow = MachineEnrollmentWorkflow::with_endpoint(endpoint.clone());
        let active = workflow
            .run_fresh_with_store(&store, fresh_parts(), NOW_MS)
            .await
            .expect("complete durable enrollment");
        assert_eq!(active.record.lifecycle, MachineRemoteLifecycle::Active);
        assert_eq!(endpoint.state.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            *store.events.lock().expect("lock events"),
            ["prepare", "network", "record", "activate"]
        );
        assert_eq!(store.prepares.load(Ordering::SeqCst), 1);
        assert_eq!(store.records.load(Ordering::SeqCst), 1);
        assert_eq!(store.activates.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn fresh_expired_preflight_has_zero_store_and_zero_network_side_effects() {
        let store = FakeStore::default();
        let endpoint = FakeEndpoint::new(ENDPOINT_SUCCESS, Arc::clone(&store.events));
        let workflow = MachineEnrollmentWorkflow::with_endpoint(endpoint.clone());
        let error = expect_workflow_error(
            workflow
                .run_fresh_with_store(&store, fresh_parts(), NOW_MS + 10)
                .await,
            "expired fresh owner must fail before prepare",
        );

        assert_eq!(error.code(), "daemon.remote.enrollment.expired");
        assert_eq!(store.prepares.load(Ordering::SeqCst), 0);
        assert_eq!(store.records.load(Ordering::SeqCst), 0);
        assert_eq!(store.activates.load(Ordering::SeqCst), 0);
        assert_eq!(store.loads.load(Ordering::SeqCst), 0);
        assert_eq!(endpoint.state.calls.load(Ordering::SeqCst), 0);
        assert!(store.events.lock().expect("lock events").is_empty());
    }

    #[tokio::test]
    async fn prepared_network_and_validation_failures_preserve_exact_retry() {
        let store = FakeStore::default();
        let endpoint = FakeEndpoint::new(ENDPOINT_FAILURE, Arc::clone(&store.events));
        let workflow = MachineEnrollmentWorkflow::with_endpoint(endpoint.clone());
        let error = expect_workflow_error(
            workflow
                .run_fresh_with_store(&store, fresh_parts(), NOW_MS)
                .await,
            "network failure must keep Prepared",
        );
        assert_eq!(error.code(), "relay.store.unavailable");
        assert_eq!(store.lifecycle(), Some(FakeLifecycle::Prepared));

        endpoint.set_mode(ENDPOINT_INVALID_RESPONSE);
        let error = expect_workflow_error(
            workflow.resume_with_store(&store).await,
            "invalid response must keep Prepared",
        );
        assert_eq!(error.code(), "daemon.remote.enrollment.response_invalid");
        assert_eq!(store.lifecycle(), Some(FakeLifecycle::Prepared));

        endpoint.set_mode(ENDPOINT_SUCCESS);
        workflow
            .resume_with_store(&store)
            .await
            .expect("retry exact prepared request");
        assert_eq!(store.prepares.load(Ordering::SeqCst), 1);
        let requests = endpoint.state.requests.lock().expect("lock requests");
        assert_eq!(requests.len(), 3);
        assert!(requests.windows(2).all(|pair| pair[0] == pair[1]));
        drop(requests);
        let debug = format!("{error:?}");
        assert!(!debug.contains("relay.example.test"));
        assert!(!debug.contains("YWFh"));
    }

    #[tokio::test]
    async fn expired_prepared_request_is_replayed_once_and_converges_active() {
        let store = FakeStore::default();
        let endpoint = FakeEndpoint::new(ENDPOINT_SUCCESS, Arc::clone(&store.events));
        let workflow = MachineEnrollmentWorkflow::with_endpoint(endpoint.clone());
        let mut parts = fresh_parts();
        parts.bundle.expires_at_ms = 1;
        let expected_request = {
            let transient = MachineEnrollmentRequestV1 {
                code: parts.bundle.code.clone(),
                machine_route: parts.machine_route,
                root_pubkey: parts.root_public_key,
                link_cert: parts.link_certificate.clone(),
                data_cert: parts.data_certificate.clone(),
            };
            let bytes = transient.canonical_bytes().to_vec();
            drop(transient);
            bytes
        };
        store
            .prepare(
                parts.bundle,
                parts.machine_route,
                parts.binding,
                parts.link_certificate,
                parts.data_certificate,
            )
            .await
            .expect("seed durable Prepared state");

        let active = workflow
            .resume_with_store(&store)
            .await
            .expect("expired Prepared must replay after Relay-side commit ambiguity");
        assert_eq!(active.record.lifecycle, MachineRemoteLifecycle::Active);
        assert_eq!(endpoint.state.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            *endpoint.state.requests.lock().expect("lock requests"),
            [expected_request]
        );
    }

    #[tokio::test]
    async fn validated_restart_activates_without_a_second_network_call() {
        let store = FakeStore {
            fail_activate_once: AtomicBool::new(true),
            ..FakeStore::default()
        };
        let endpoint = FakeEndpoint::new(ENDPOINT_SUCCESS, Arc::clone(&store.events));
        let workflow = MachineEnrollmentWorkflow::with_endpoint(endpoint.clone());
        let error = expect_workflow_error(
            workflow
                .run_fresh_with_store(&store, fresh_parts(), NOW_MS)
                .await,
            "first activate fails before commit",
        );
        assert_eq!(error.code(), "daemon.runtime.store_unavailable");
        assert_eq!(store.lifecycle(), Some(FakeLifecycle::Validated));
        assert_eq!(endpoint.state.calls.load(Ordering::SeqCst), 1);

        workflow
            .resume_with_store(&store)
            .await
            .expect("resume validated state locally");
        assert_eq!(endpoint.state.calls.load(Ordering::SeqCst), 1);
        assert_eq!(store.lifecycle(), Some(FakeLifecycle::Active));
    }

    #[tokio::test]
    async fn all_three_after_commit_unknowns_converge_by_exact_readback() {
        let store = FakeStore::with_unknowns();
        let endpoint = FakeEndpoint::new(ENDPOINT_SUCCESS, Arc::clone(&store.events));
        let workflow = MachineEnrollmentWorkflow::with_endpoint(endpoint.clone());
        let active = workflow
            .run_fresh_with_store(&store, fresh_parts(), NOW_MS)
            .await
            .expect("all unknown commits converge");
        assert_eq!(active.record.lifecycle, MachineRemoteLifecycle::Active);
        assert_eq!(store.loads.load(Ordering::SeqCst), 3);
        assert_eq!(store.prepares.load(Ordering::SeqCst), 1);
        assert_eq!(store.records.load(Ordering::SeqCst), 1);
        assert_eq!(store.activates.load(Ordering::SeqCst), 1);
        assert_eq!(endpoint.state.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn active_resume_is_zero_dial_and_has_no_code_owner() {
        let store = FakeStore::default();
        let endpoint = FakeEndpoint::new(ENDPOINT_SUCCESS, Arc::clone(&store.events));
        let workflow = MachineEnrollmentWorkflow::with_endpoint(endpoint.clone());
        workflow
            .run_fresh_with_store(&store, fresh_parts(), NOW_MS)
            .await
            .expect("activate enrollment");
        let calls = endpoint.state.calls.load(Ordering::SeqCst);
        let active = workflow
            .resume_with_store(&store)
            .await
            .expect("Active resumes without bootstrap material");
        assert_eq!(endpoint.state.calls.load(Ordering::SeqCst), calls);
        assert_eq!(active.record.lifecycle, MachineRemoteLifecycle::Active);
        assert_eq!(
            format!("{workflow:?}"),
            "MachineEnrollmentWorkflow([REDACTED])"
        );
    }

    #[tokio::test]
    async fn local_deleted_is_state_conflict_with_zero_store_mutation_and_zero_network() {
        let store = FakeStore::default();
        let endpoint = FakeEndpoint::new(ENDPOINT_SUCCESS, Arc::clone(&store.events));
        let workflow = MachineEnrollmentWorkflow::with_endpoint(endpoint.clone());
        let error = expect_workflow_error(
            workflow.drive(&store, local_deleted_state()).await,
            "LocalDeleted must not enter enrollment resume",
        );

        assert_eq!(error.code(), "daemon.remote.enrollment.state_conflict");
        assert_eq!(endpoint.state.calls.load(Ordering::SeqCst), 0);
        assert_eq!(store.prepares.load(Ordering::SeqCst), 0);
        assert_eq!(store.records.load(Ordering::SeqCst), 0);
        assert_eq!(store.activates.load(Ordering::SeqCst), 0);
        assert!(store.events.lock().expect("lock events").is_empty());
    }

    #[tokio::test]
    async fn prepared_rebuilds_strict_config_only_from_sealed_connection_material() {
        let store = FakeStore::default();
        let endpoint = FakeEndpoint::new(ENDPOINT_FAILURE, Arc::clone(&store.events));
        let workflow = MachineEnrollmentWorkflow::with_endpoint(endpoint.clone());
        let _ = expect_workflow_error(
            workflow
                .run_fresh_with_store(&store, fresh_parts(), NOW_MS)
                .await,
            "seed Prepared via endpoint failure",
        );
        assert_eq!(
            endpoint.state.origins.lock().expect("lock origins")[0],
            "wss://relay.example.test:8443/"
        );
        store.mutate_connection(|connection| {
            connection.public_wss_url = "wss://relay.example.test/not-an-origin".to_owned();
        });
        let calls = endpoint.state.calls.load(Ordering::SeqCst);
        let error = expect_workflow_error(
            workflow.resume_with_store(&store).await,
            "invalid sealed origin must fail before endpoint",
        );
        assert_eq!(error.code(), "daemon.remote.enrollment.origin_invalid");
        assert_eq!(endpoint.state.calls.load(Ordering::SeqCst), calls);
    }
}
