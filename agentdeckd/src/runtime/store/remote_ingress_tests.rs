//! P4.4 Store-issued Remote ingress capability RED tests。
//!
//! RemoteLink 只能从 authenticated Active authorization projection 取得 opaque proof；
//! DeviceSign/AEAD 验证结束后必须用同一 proof 做 exact Active recheck，不能把第一次
//! 读取结果当成可长期缓存的 canonical authorization state。

use agentdeck_crypto::{SigningKey, sha256, sign_tbs};
use agentdeck_protocol::e2ee::{AuthorizationCapabilityV1, AuthorizationPermissionV1, KeyPurpose};
use agentdeck_protocol::relay_v2::{
    DeviceRevocation, DeviceRouteId, Ed25519Signature, GrantSerial, MachineRouteId,
};
use agentdeck_protocol::runtime::identity::{DeviceHandle, GrantSerial as RuntimeGrantSerial};
use agentdeck_protocol::runtime::{
    CodexConversationConfiguration, ConfigurationReceipt, ConfigureConversationRequest,
    ConversationConfiguration, ConversationId, IdempotencyKey, RuntimeReply,
    VendorConfigurationSnapshot,
};
use agentdeck_protocol::{AgentKind, CodexApprovalPolicy, CodexReasoningEffort, CodexSandboxMode};
use rusqlite::{Connection, OpenFlags};
use tokio::sync::mpsc;

use crate::runtime::model::{
    AcceptCommand, AcceptOutcome, ConversationDescriptor, IdempotencyOwner, MachineEnrollmentState,
    NewConversation, RemoteCommandAuthorizationBinding,
};
use crate::runtime::{AgentRouter, ConnectionSink, RuntimeCore};
use crate::security::{MemoryKeyStore, load_or_create_storage_kek};

use super::identity::{RuntimeId, RuntimeIdKind};
use super::pairing_revocation::{
    BeginDeviceRevocation, BeginDeviceRevocationOutcome, RevocationTargetStatus,
};
use super::pairing_tests::TestRoot;
use super::{
    ConfigureConversation, ConfigureConversationOutcome, RuntimeStoreHandle,
    active_authorization_store_with_permissions_for_test,
};

const MACHINE_ROUTE: MachineRouteId = MachineRouteId::from_bytes([0x32; 16]);
const DEVICE_ROUTE: DeviceRouteId = DeviceRouteId::from_bytes([0xd1; 16]);
const DEVICE_SIGN_SEED: [u8; 32] = [0xa4; 32];
const ROOT_SIGN_SEED: [u8; 32] = [0x41; 32];

fn all_capabilities() -> Vec<AuthorizationCapabilityV1> {
    vec![
        AuthorizationCapabilityV1::Catalog,
        AuthorizationCapabilityV1::Conversation,
        AuthorizationCapabilityV1::Prompt,
        AuthorizationCapabilityV1::Command,
        AuthorizationCapabilityV1::Approval,
        AuthorizationCapabilityV1::Metadata,
        AuthorizationCapabilityV1::SelfRevocation,
    ]
}

fn all_permissions() -> Vec<AuthorizationPermissionV1> {
    vec![
        AuthorizationPermissionV1::CatalogRead,
        AuthorizationPermissionV1::ConversationRead,
        AuthorizationPermissionV1::ConversationStart,
        AuthorizationPermissionV1::PromptSend,
        AuthorizationPermissionV1::CommandCancel,
        AuthorizationPermissionV1::ApprovalResolve,
        AuthorizationPermissionV1::ApprovalRetry,
        AuthorizationPermissionV1::MetadataWrite,
        AuthorizationPermissionV1::RevokeSelf,
    ]
}

async fn full_authorization_store(root: &TestRoot) -> RuntimeStoreHandle {
    let keys = MemoryKeyStore::new();
    let database = root.database();
    active_authorization_store_with_permissions_for_test(
        &database,
        load_or_create_storage_kek(&keys, &database).expect("create ingress proof StorageKEK"),
        all_capabilities(),
        all_permissions(),
    )
    .await
}

fn device_handle(route: DeviceRouteId) -> DeviceHandle {
    let encoded = route
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    DeviceHandle::new(format!("device-{encoded}"))
}

async fn begin_local_revocation(store: &RuntimeStoreHandle) {
    let target = match store
        .load_revocation_target(&device_handle(DEVICE_ROUTE), RuntimeGrantSerial::new(1))
        .await
        .expect("load active revocation target")
        .expect("active authorization must be revocable")
    {
        RevocationTargetStatus::Ready { target } => target,
        other => panic!("fresh authorization must be ready, got {other:?}"),
    };
    let Some(MachineEnrollmentState::Active(active)) = store
        .load_machine_enrollment_state()
        .await
        .expect("load active machine enrollment")
    else {
        panic!("authorization fixture must keep machine enrollment Active")
    };
    let grant = target.grant();
    let mut revocation = DeviceRevocation {
        machine_route: grant.machine_route,
        device_route: grant.device_route,
        grant_serial: grant.grant_serial,
        root_key_id: grant.root_key_id,
        trust_epoch: grant.trust_epoch,
        signature: Ed25519Signature([0; 64]),
    };
    revocation.signature = sign_tbs(
        &SigningKey::from_seed(&ROOT_SIGN_SEED),
        &revocation.to_be_signed_v1(
            active.connection.relay_server_id,
            active.binding.root_fingerprint,
        ),
    )
    .into();
    assert!(matches!(
        store
            .begin_device_revocation(BeginDeviceRevocation::local(revocation))
            .await
            .expect("begin local revocation"),
        BeginDeviceRevocationOutcome::Prepared { .. }
    ));
}

#[tokio::test]
async fn active_ingress_proof_binds_exact_identity_command_epoch_and_nine_permissions() {
    let root = TestRoot::new("p44-active-ingress-proof");
    let store = full_authorization_store(&root).await;
    let trust_domain = store
        .machine_trust_domain()
        .expect("derive Store trust domain");

    let proof = store
        .load_active_remote_ingress(MACHINE_ROUTE, DEVICE_ROUTE)
        .await
        .expect("load Store-issued Active ingress proof");

    assert_eq!(proof.machine_trust_domain(), trust_domain);
    assert_eq!(proof.machine_route(), MACHINE_ROUTE);
    assert_eq!(proof.device_route(), DEVICE_ROUTE);
    assert_eq!(proof.grant_serial(), GrantSerial::new(1));
    assert_eq!(
        proof.device_sign_fingerprint(),
        sha256(
            &SigningKey::from_seed(&DEVICE_SIGN_SEED)
                .verifying_key()
                .to_bytes()
        )
    );
    assert_eq!(proof.key_directory_revision().value(), 1);
    assert_eq!(proof.command_key_epoch(), 1);
    assert_eq!(proof.permissions(), all_permissions().as_slice());
    assert_eq!(
        proof.device_verifying_key().to_bytes(),
        SigningKey::from_seed(&DEVICE_SIGN_SEED)
            .verifying_key()
            .to_bytes()
    );
    assert_eq!(proof.command_receiving_key().epoch, 1);
    assert_eq!(
        proof.command_receiving_key().key_id.purpose,
        KeyPurpose::DeviceCommandTx
    );

    assert!(
        store
            .load_active_remote_ingress(MachineRouteId::from_bytes([0x33; 16]), DEVICE_ROUTE,)
            .await
            .is_err(),
        "wrong machine route must not yield a proof"
    );
    assert!(
        store
            .load_active_remote_ingress(MACHINE_ROUTE, DeviceRouteId::from_bytes([0xd2; 16]),)
            .await
            .is_err(),
        "wrong device route must not yield a proof"
    );
    store
        .shutdown()
        .await
        .expect("shutdown ingress proof store");
}

#[tokio::test]
async fn local_revoke_bootstrap_proof_requires_exact_active_device_and_serial() {
    let root = TestRoot::new("p44-local-revoke-bootstrap-proof");
    let store = full_authorization_store(&root).await;
    let handle = device_handle(DEVICE_ROUTE);

    let proof = store
        .load_active_remote_ingress_for_revoke(&handle, RuntimeGrantSerial::new(1))
        .await
        .expect("load exact local revoke bootstrap proof")
        .expect("Active authorization has a bootstrap proof");
    assert_eq!(proof.device_route(), DEVICE_ROUTE);
    assert_eq!(proof.grant_serial(), GrantSerial::new(1));
    assert!(
        store
            .load_active_remote_ingress_for_revoke(&handle, RuntimeGrantSerial::new(2))
            .await
            .expect("query wrong serial without approximation")
            .is_none(),
        "wrong serial must not mint a nearby authorization lease"
    );

    begin_local_revocation(&store).await;
    assert!(
        store
            .load_active_remote_ingress_for_revoke(&handle, RuntimeGrantSerial::new(1))
            .await
            .expect("query Revoking target")
            .is_none(),
        "Revoking authorization must not bootstrap a new Active lease"
    );
    store.shutdown().await.expect("shutdown bootstrap Store");
}

#[tokio::test]
async fn post_crypto_exact_recheck_rejects_a_grant_that_became_revoking() {
    let root = TestRoot::new("p44-active-recheck-revoke");
    let store = full_authorization_store(&root).await;
    let ingress = store
        .load_active_remote_ingress(MACHINE_ROUTE, DEVICE_ROUTE)
        .await
        .expect("load pre-crypto Active proof");

    let current = store
        .recheck_active_remote_ingress(&ingress)
        .await
        .expect("unchanged authorization stays current");
    assert_eq!(current.grant_serial(), ingress.grant_serial());
    assert_eq!(current.authorization_hash(), ingress.authorization_hash());
    let reply = current.remote_reply_authorization();
    assert_eq!(reply.machine_trust_domain(), ingress.machine_trust_domain());
    assert_eq!(reply.machine_route(), ingress.machine_route());
    assert_eq!(reply.device_route(), ingress.device_route());
    assert_eq!(reply.grant_serial(), ingress.grant_serial());
    assert_eq!(reply.authorization_hash(), ingress.authorization_hash());
    assert_eq!(
        reply.key_directory_revision(),
        ingress.key_directory_revision()
    );
    assert_eq!(reply.reply_key_epoch(), 1);

    // 模拟 proof 读取后完成 DeviceSign/AAD/replay/AEAD 前，本机管理员提交 revoke。
    begin_local_revocation(&store).await;
    assert!(
        store.recheck_active_remote_ingress(&ingress).await.is_err(),
        "final Active recheck must reject a frame buffered before local revoke"
    );
    assert!(
        store
            .load_active_remote_ingress(MACHINE_ROUTE, DEVICE_ROUTE)
            .await
            .is_err(),
        "Revoking authorization must not mint another ingress proof"
    );
    store.shutdown().await.expect("shutdown recheck store");
}

#[tokio::test]
async fn exact_recheck_rejects_a_proof_issued_by_another_store() {
    let first_root = TestRoot::new("p44-active-proof-first-store");
    let second_root = TestRoot::new("p44-active-proof-second-store");
    let first = full_authorization_store(&first_root).await;
    let second = full_authorization_store(&second_root).await;
    let foreign = second
        .load_active_remote_ingress(MACHINE_ROUTE, DEVICE_ROUTE)
        .await
        .expect("load foreign Store-issued proof");

    assert!(
        first.recheck_active_remote_ingress(&foreign).await.is_err(),
        "opaque proof must bind the issuing Store trust domain/database identity"
    );
    first.shutdown().await.expect("shutdown first proof store");
    second
        .shutdown()
        .await
        .expect("shutdown second proof store");
}

fn runtime_id(kind: RuntimeIdKind, seed: u8) -> RuntimeId {
    RuntimeId::from_bytes(kind, [seed; 16]).expect("nonzero P4.4 runtime id")
}

fn remote_owner(trust_domain: [u8; 32]) -> IdempotencyOwner {
    IdempotencyOwner::Remote {
        machine_trust_domain: trust_domain,
        device_route: *DEVICE_ROUTE.as_bytes(),
        device_sign_fingerprint: sha256(
            &SigningKey::from_seed(&DEVICE_SIGN_SEED)
                .verifying_key()
                .to_bytes(),
        ),
    }
}

fn codex_configuration() -> ConversationConfiguration {
    ConversationConfiguration::new(VendorConfigurationSnapshot::Codex(
        CodexConversationConfiguration::new(
            CodexApprovalPolicy::OnRequest,
            CodexSandboxMode::WorkspaceWrite,
            CodexReasoningEffort::Medium,
        ),
    ))
}

async fn create_conversation(
    store: &RuntimeStoreHandle,
    conversation_id: RuntimeId,
    adapter_seed: u8,
    title: &str,
) {
    store
        .create_conversation(NewConversation {
            conversation_id,
            adapter_state_key: runtime_id(RuntimeIdKind::AdapterState, adapter_seed),
            descriptor: ConversationDescriptor {
                agent_kind: AgentKind::Codex,
                title: Some(title.to_owned()),
                cwd: std::path::PathBuf::from("/tmp/agentdeck-p44-adc2"),
            },
        })
        .await
        .expect("create ADC2 recovery conversation");
    super::complete_active_zero_cut_transition(store).await;
}

async fn configure_remote_conversation(
    store: &RuntimeStoreHandle,
    conversation_id: RuntimeId,
    owner: IdempotencyOwner,
    key: &str,
) {
    assert!(matches!(
        store
            .configure_conversation(ConfigureConversation {
                conversation_id,
                owner,
                idempotency_key: key.to_owned(),
                expected_configuration_revision: 0,
                configuration: codex_configuration(),
            })
            .await
            .expect("configure ADC2 recovery conversation"),
        ConfigureConversationOutcome::Applied { .. }
    ));
}

async fn recover_and_prove_healthy_write(
    store: RuntimeStoreHandle,
    healthy_id: RuntimeId,
    expected_ready_accepted: u64,
) {
    let trust_domain = store
        .machine_trust_domain()
        .expect("derive ADC2 recovery trust domain");
    let router = std::sync::Arc::new(AgentRouter::with_runtime_store(store.clone()));
    let core = std::sync::Arc::new(
        RuntimeCore::new(store, router, trust_domain).expect("construct ADC2 recovery Core"),
    );
    let report = core
        .recover()
        .await
        .expect("recover ADC2 case without global abort");
    assert_eq!(report.accepted_commands, expected_ready_accepted);
    let principal = core
        .issue_verified_local_principal(501, [0xe1; 16])
        .expect("issue healthy local principal");
    let (sink, mut receiver) = mpsc::channel::<crate::runtime::ConnectionWrite>(8);
    tokio::spawn(async move {
        while let Some(write) = receiver.recv().await {
            let _ = write.acknowledge();
        }
    });
    let connection = core
        .connect(principal, ConnectionSink::new(sink))
        .expect("connect healthy local principal");
    let healthy = ConversationId::new(healthy_id.to_canonical_string());
    let reply = core
        .handle(
            connection,
            agentdeck_protocol::runtime::RuntimeRequest::ConfigureConversation(
                ConfigureConversationRequest::new(
                    healthy.clone(),
                    IdempotencyKey::new("healthy-after-remote-recovery"),
                    0,
                    codex_configuration(),
                ),
            ),
        )
        .await;
    assert!(matches!(
        reply,
        RuntimeReply::Configuration(ConfigurationReceipt::Applied {
            conversation_id,
            configuration_revision: 1,
        }) if conversation_id == healthy
    ));
    core.shutdown().await.expect("shutdown ADC2 recovery Core");
}

async fn prepare_remote_and_healthy(
    store: &RuntimeStoreHandle,
    remote_seed: u8,
    healthy_seed: u8,
) -> (RuntimeId, RuntimeId, IdempotencyOwner) {
    let remote_id = runtime_id(RuntimeIdKind::Conversation, remote_seed);
    let healthy_id = runtime_id(RuntimeIdKind::Conversation, healthy_seed);
    create_conversation(store, remote_id, remote_seed.wrapping_add(0x20), "remote").await;
    create_conversation(
        store,
        healthy_id,
        healthy_seed.wrapping_add(0x20),
        "healthy",
    )
    .await;
    let owner = remote_owner(
        store
            .machine_trust_domain()
            .expect("derive remote owner trust domain"),
    );
    configure_remote_conversation(store, remote_id, owner.clone(), "remote-configuration").await;
    (remote_id, healthy_id, owner)
}

#[tokio::test]
async fn adc2_freezes_exact_authorization_and_active_recovery_is_conversation_scoped() {
    let root = TestRoot::new("p44-adc2-active-recovery");
    let store = full_authorization_store(&root).await;
    let (remote_id, healthy_id, owner) = prepare_remote_and_healthy(&store, 0x41, 0x42).await;
    let ingress = store
        .load_active_remote_ingress(MACHINE_ROUTE, DEVICE_ROUTE)
        .await
        .expect("load ADC2 ingress proof");
    let current = store
        .recheck_active_remote_ingress(&ingress)
        .await
        .expect("recheck ADC2 Active proof");
    let command = match store
        .accept_remote_command_authorized(
            AcceptCommand {
                conversation_id: remote_id,
                owner,
                idempotency_key: "adc2-active-command".to_owned(),
                expected_configuration_revision: 1,
                payload: b"ADC2 active recovery".to_vec(),
            },
            &current,
        )
        .await
        .expect("accept Store-authorized ADC2 command")
    {
        AcceptOutcome::Accepted { command, .. } => command,
        AcceptOutcome::Replayed { .. } => panic!("fresh ADC2 command replayed"),
    };
    let binding: &RemoteCommandAuthorizationBinding = command
        .remote_authorization_binding()
        .expect("remote command must freeze ADC2 authorization");
    assert_eq!(
        binding.machine_trust_domain(),
        ingress.machine_trust_domain()
    );
    assert_eq!(binding.machine_route(), ingress.machine_route());
    assert_eq!(binding.device_route(), ingress.device_route());
    assert_eq!(binding.grant_serial(), ingress.grant_serial());
    assert_eq!(
        binding.device_sign_fingerprint(),
        ingress.device_sign_fingerprint()
    );
    assert_eq!(
        binding.key_directory_revision(),
        ingress.key_directory_revision()
    );
    assert_eq!(binding.command_key_epoch(), ingress.command_key_epoch());
    assert_eq!(binding.permissions(), ingress.permissions());
    assert_eq!(binding.authorization_hash(), ingress.authorization_hash());

    recover_and_prove_healthy_write(store, healthy_id, 1).await;
}

#[tokio::test]
async fn inactive_adc2_is_revoked_before_start_without_blocking_healthy_recovery() {
    let root = TestRoot::new("p44-adc2-inactive-recovery");
    let store = full_authorization_store(&root).await;
    let (remote_id, healthy_id, owner) = prepare_remote_and_healthy(&store, 0x51, 0x52).await;
    let ingress = store
        .load_active_remote_ingress(MACHINE_ROUTE, DEVICE_ROUTE)
        .await
        .expect("load inactive-case ingress proof");
    let current = store
        .recheck_active_remote_ingress(&ingress)
        .await
        .expect("recheck inactive-case authorization before accept");
    let command = match store
        .accept_remote_command_authorized(
            AcceptCommand {
                conversation_id: remote_id,
                owner: owner.clone(),
                idempotency_key: "adc2-inactive-command".to_owned(),
                expected_configuration_revision: 1,
                payload: b"ADC2 inactive recovery".to_vec(),
            },
            &current,
        )
        .await
        .expect("accept ADC2 command before revoke")
    {
        AcceptOutcome::Accepted { command, .. } => command,
        AcceptOutcome::Replayed { .. } => panic!("fresh inactive ADC2 command replayed"),
    };
    begin_local_revocation(&store).await;
    recover_and_prove_healthy_write(store.clone(), healthy_id, 0).await;
    let connection = Connection::open_with_flags(root.database(), OpenFlags::SQLITE_OPEN_READ_ONLY)
        .expect("open inactive ADC2 recovery evidence DB");
    let state: String = connection
        .query_row(
            "SELECT state FROM commands WHERE command_id = ?1",
            [&command.command_id.as_bytes()[..]],
            |row| row.get(0),
        )
        .expect("query inactive ADC2 recovery outcome");
    assert_eq!(state, "revokedBeforeStart");
}

#[tokio::test]
async fn legacy_adc1_remote_command_blocks_only_its_conversation() {
    let root = TestRoot::new("p44-adc1-local-block");
    let store = full_authorization_store(&root).await;
    let (remote_id, healthy_id, owner) = prepare_remote_and_healthy(&store, 0x61, 0x62).await;
    store
        .accept_command(AcceptCommand {
            conversation_id: remote_id,
            owner,
            idempotency_key: "legacy-adc1-command".to_owned(),
            expected_configuration_revision: 1,
            payload: b"legacy ADC1 cannot prove exact grant".to_vec(),
        })
        .await
        .expect("create legacy ADC1 remote command");

    recover_and_prove_healthy_write(store, healthy_id, 0).await;
    let connection = Connection::open_with_flags(root.database(), OpenFlags::SQLITE_OPEN_READ_ONLY)
        .expect("open ADC1 recovery evidence DB");
    let lifecycle: String = connection
        .query_row(
            "SELECT lifecycle FROM conversations WHERE conversation_id = ?1",
            [&remote_id.as_bytes()[..]],
            |row| row.get(0),
        )
        .expect("read ADC1 conversation lifecycle");
    assert_eq!(lifecycle, "recoveryBlocked");
}
