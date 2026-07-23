//! `agentdeck remote` 的 Relay v2 命令面。
//!
//! P2 仅开放不落盘的 synthetic 端到端自检。持久 Companion 配对由 P4
//! 接管；被删除的 v1 命令只在拨号前返回稳定迁移错误，绝不读取旧 secret
//! 内容、写文件或回退到旧网络路径。

use std::fs::File;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use agentdeck_cli::unix_transport::RuntimeUnixClient;
use agentdeck_protocol::relay_v2::{EnrollmentBundleV2, RelayAdminPurgeReceiptV1};
use agentdeck_protocol::runtime::command::{RevokeRequest, RevokeTarget};
use agentdeck_protocol::runtime::identity::{DeviceHandle, GrantSerial, PairingId};
use agentdeck_protocol::runtime::{
    CreatePairInviteRequest, IdempotencyKey, LocalOnlyAdministration, MachineEnrollRequest,
    MachineRemoteLifecycle, MachineRemoteStatus, RuntimeReply, RuntimeRequest, TrustResetRequest,
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use zeroize::Zeroizing;

use crate::output::{CliError, render};
use crate::runtime_cli;

#[path = "remote/v2_synthetic.rs"]
mod v2_synthetic;

const MAX_REMOTE_INPUT_BYTES: usize = 64 * 1024;
const INPUT_UNSAFE: &str = "remote.local_input.unsafe";
const INPUT_TOO_LARGE: &str = "remote.local_input.too_large";
const INPUT_INVALID: &str = "remote.local_input.invalid_json";

pub enum RuntimeRemotePlan {
    MachineEnroll(EnrollmentBundleV2),
    MachineStatus,
    TrustReset(Option<Box<RelayAdminPurgeReceiptV1>>),
    CreatePairInvite {
        display_name: String,
        idempotency_key: String,
    },
    PairingPending,
    PairingApprove(PairingId),
    PairingCancel(PairingId),
    RevokeDevice(DeviceHandle, GrantSerial),
}

#[derive(Clone, Copy)]
enum PairingReplyKind {
    Invite,
    Pending,
    Decision,
}

impl std::fmt::Debug for RuntimeRemotePlan {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::MachineEnroll(_) => "RuntimeRemotePlan::MachineEnroll(<redacted>)",
            Self::MachineStatus => "RuntimeRemotePlan::MachineStatus",
            Self::TrustReset(_) => "RuntimeRemotePlan::TrustReset(<redacted>)",
            Self::CreatePairInvite { .. } => "RuntimeRemotePlan::CreatePairInvite(<redacted>)",
            Self::PairingPending => "RuntimeRemotePlan::PairingPending",
            Self::PairingApprove(_) => "RuntimeRemotePlan::PairingApprove(<redacted>)",
            Self::PairingCancel(_) => "RuntimeRemotePlan::PairingCancel(<redacted>)",
            Self::RevokeDevice(_, _) => "RuntimeRemotePlan::RevokeDevice(<redacted>)",
        })
    }
}

impl RuntimeRemotePlan {
    pub fn machine_enroll(bundle_file: &Path) -> Result<Self, CliError> {
        Ok(Self::MachineEnroll(read_strict_json_file(
            bundle_file,
            "enrollment bundle",
        )?))
    }

    pub const fn machine_status() -> Self {
        Self::MachineStatus
    }

    pub fn trust_reset(receipt_file: Option<&Path>) -> Result<Self, CliError> {
        let receipt = receipt_file
            .map(|path| {
                read_strict_json_file::<RelayAdminPurgeReceiptV1>(path, "admin purge receipt")
            })
            .transpose()?
            .map(Box::new);
        if let Some(receipt) = &receipt {
            receipt
                .validate()
                .map_err(|_| input_invalid("admin purge receipt"))?;
        }
        Ok(Self::TrustReset(receipt))
    }

    pub fn create_pair_invite(
        display_name: String,
        idempotency_key: String,
    ) -> Result<Self, CliError> {
        agentdeck_protocol::e2ee::pairing::validate_pairing_display_name(&display_name)
            .map_err(|error| CliError::Usage(error.to_string()))?;
        validate_pairing_idempotency_key(&idempotency_key)?;
        Ok(Self::CreatePairInvite {
            display_name,
            idempotency_key,
        })
    }

    pub const fn pairing_pending() -> Self {
        Self::PairingPending
    }

    pub fn pairing_approve(pairing_id: String) -> Result<Self, CliError> {
        canonical_pairing_id(pairing_id).map(Self::PairingApprove)
    }

    pub fn pairing_cancel(pairing_id: String) -> Result<Self, CliError> {
        canonical_pairing_id(pairing_id).map(Self::PairingCancel)
    }

    pub fn revoke_device(device: String, grant_serial: u64) -> Result<Self, CliError> {
        if grant_serial == 0 {
            return Err(CliError::Usage(
                "remote revoke --grant-serial must be greater than zero".to_owned(),
            ));
        }
        Ok(Self::RevokeDevice(
            canonical_device_handle(device)?,
            GrantSerial::new(grant_serial),
        ))
    }

    const fn operation(&self) -> &'static str {
        match self {
            Self::MachineEnroll(_) => "remote.machine.enroll",
            Self::MachineStatus => "remote.machine.status",
            Self::TrustReset(_) => "remote.trustReset",
            Self::CreatePairInvite { .. } => "remote.pairing.invite",
            Self::PairingPending => "remote.pairing.pending",
            Self::PairingApprove(_) => "remote.pairing.approve",
            Self::PairingCancel(_) => "remote.pairing.cancel",
            Self::RevokeDevice(_, _) => "remote.device.revoke",
        }
    }

    const fn exposes_admin_purge_template(&self) -> bool {
        matches!(self, Self::MachineStatus | Self::TrustReset(_))
    }

    const fn pairing_reply_kind(&self) -> Option<PairingReplyKind> {
        match self {
            Self::CreatePairInvite { .. } => Some(PairingReplyKind::Invite),
            Self::PairingPending => Some(PairingReplyKind::Pending),
            Self::PairingApprove(_) | Self::PairingCancel(_) => Some(PairingReplyKind::Decision),
            Self::MachineEnroll(_) | Self::MachineStatus | Self::TrustReset(_) => None,
            Self::RevokeDevice(_, _) => None,
        }
    }

    const fn is_revocation(&self) -> bool {
        matches!(self, Self::RevokeDevice(_, _))
    }

    fn into_request(self) -> Result<RuntimeRequest, CliError> {
        match self {
            Self::MachineEnroll(bundle) => {
                Ok(RuntimeRequest::MachineEnroll(MachineEnrollRequest {
                    bundle,
                    scope: LocalOnlyAdministration::LocalOnly,
                }))
            }
            Self::MachineStatus => Ok(RuntimeRequest::MachineRemoteStatus {
                scope: LocalOnlyAdministration::LocalOnly,
            }),
            Self::TrustReset(receipt) => {
                TrustResetRequest::new(LocalOnlyAdministration::LocalOnly, receipt)
                    .map(RuntimeRequest::TrustReset)
                    .map_err(|_| input_invalid("admin purge receipt"))
            }
            Self::CreatePairInvite {
                display_name,
                idempotency_key,
            } => Ok(RuntimeRequest::CreatePairInvite(CreatePairInviteRequest {
                display_name,
                idempotency_key: IdempotencyKey::new(idempotency_key),
                scope: LocalOnlyAdministration::LocalOnly,
            })),
            Self::PairingPending => Ok(RuntimeRequest::ListPendingPairings {
                scope: LocalOnlyAdministration::LocalOnly,
            }),
            Self::PairingApprove(pairing_id) => Ok(RuntimeRequest::ConfirmPairing {
                pairing_id,
                scope: LocalOnlyAdministration::LocalOnly,
            }),
            Self::PairingCancel(pairing_id) => Ok(RuntimeRequest::CancelPairing {
                pairing_id,
                scope: LocalOnlyAdministration::LocalOnly,
            }),
            Self::RevokeDevice(device, grant_serial) => Ok(RuntimeRequest::Revoke(RevokeRequest {
                target: RevokeTarget::Device {
                    device,
                    grant_serial,
                    scope: LocalOnlyAdministration::LocalOnly,
                },
            })),
        }
    }
}

pub async fn run_runtime(
    client: &RuntimeUnixClient,
    plan: RuntimeRemotePlan,
    pretty: bool,
) -> Result<(), CliError> {
    let operation = plan.operation();
    if plan.is_revocation() {
        let receipt =
            runtime_cli::request_revocation_administration(client, plan.into_request()?).await?;
        println!(
            "{}",
            render(
                &serde_json::json!({"operation": operation, "result": receipt}),
                pretty,
            )
        );
        return Ok(());
    }
    if let Some(expected) = plan.pairing_reply_kind() {
        let reply =
            runtime_cli::request_pairing_administration(client, plan.into_request()?).await?;
        let result = match (expected, reply) {
            (PairingReplyKind::Invite, RuntimeReply::PairInvite(value)) => {
                canonical_pair_invite_output(value, crate::unix_now_ms())?
            }
            (PairingReplyKind::Pending, RuntimeReply::PendingPairings { pairings }) => {
                serde_json::to_value(pairings)?
            }
            (PairingReplyKind::Decision, RuntimeReply::Pairing(receipt)) => {
                serde_json::to_value(receipt)?
            }
            _ => {
                return Err(CliError::Protocol {
                    code: Some("daemon.client.pairing_reply_mismatch".to_owned()),
                    message: "pairing administration reply does not match the requested operation"
                        .to_owned(),
                });
            }
        };
        println!(
            "{}",
            render(
                &serde_json::json!({"operation": operation, "result": result}),
                pretty,
            )
        );
        return Ok(());
    }
    let expose_template = plan.exposes_admin_purge_template();
    let trust_reset = matches!(&plan, RuntimeRemotePlan::TrustReset(_));
    let request = plan.into_request()?;
    let (status, request_failure_code) =
        match runtime_cli::request_machine_remote_status(client, request).await {
            Ok(status) => (status, None),
            Err(error @ CliError::Session { .. })
                if trust_reset
                    && cli_error_code(&error)
                        == Some("daemon.remote.trust_reset.admin_receipt_required") =>
            {
                let failure_code = cli_error_code(&error).map(str::to_owned);
                let status = runtime_cli::request_machine_remote_status(
                    client,
                    RuntimeRequest::MachineRemoteStatus {
                        scope: LocalOnlyAdministration::LocalOnly,
                    },
                )
                .await
                .map_err(|_| error)?;
                (status, failure_code)
            }
            Err(error) => return Err(error),
        };
    let output = machine_status_output(
        operation,
        expose_template,
        request_failure_code.as_deref(),
        &status,
    )?;
    println!("{}", render(&output, pretty));
    Ok(())
}

fn canonical_pair_invite_output(
    value: agentdeck_protocol::runtime::PairInvite,
    now_ms: u64,
) -> Result<serde_json::Value, CliError> {
    let invite_uri = value
        .invite
        .encode_uri(now_ms)
        .map_err(|_| CliError::Protocol {
            code: Some("daemon.client.pairing_invite_invalid".to_owned()),
            message: "daemon returned an invalid or expired pairing invite".to_owned(),
        })?;
    Ok(serde_json::json!({
        "pairingId": value.pairing_id,
        "inviteUri": invite_uri,
    }))
}

fn validate_pairing_idempotency_key(value: &str) -> Result<(), CliError> {
    if value.is_empty() || value.len() > 1_024 || value.as_bytes().contains(&0) {
        return Err(CliError::Usage(
            "pairing invite --idempotency-key must contain 1 to 1024 UTF-8 bytes and no NUL"
                .to_owned(),
        ));
    }
    Ok(())
}

fn canonical_pairing_id(value: String) -> Result<PairingId, CliError> {
    let parsed = uuid::Uuid::parse_str(&value)
        .map_err(|_| CliError::Usage("PAIRING_ID must be a canonical UUID".to_owned()))?;
    if parsed.is_nil() || parsed.hyphenated().to_string() != value {
        return Err(CliError::Usage(
            "PAIRING_ID must be a canonical non-zero lowercase UUID".to_owned(),
        ));
    }
    Ok(PairingId::new(value))
}

fn canonical_device_handle(value: String) -> Result<DeviceHandle, CliError> {
    let Some(encoded) = value.strip_prefix("device-") else {
        return Err(CliError::Usage(
            "remote revoke --device must be device- followed by 32 lowercase hex digits".to_owned(),
        ));
    };
    if encoded.len() != 32
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || encoded.bytes().all(|byte| byte == b'0')
    {
        return Err(CliError::Usage(
            "remote revoke --device must be device- followed by 32 lowercase nonzero hex digits"
                .to_owned(),
        ));
    }
    Ok(DeviceHandle::new(value))
}

fn read_strict_json_file<T: serde::de::DeserializeOwned>(
    path: &Path,
    label: &'static str,
) -> Result<T, CliError> {
    let mut options = File::options();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    let file = options.open(path).map_err(|_| input_unsafe(label))?;
    let metadata = file.metadata().map_err(|_| input_unsafe(label))?;
    // `File::metadata` is descriptor-based. Retaining the same descriptor through the bounded
    // read avoids a path re-open race and O_NOFOLLOW rejects a symlink final component.
    // SAFETY: geteuid has no preconditions.
    let current_uid = unsafe { libc::geteuid() };
    if !safe_input_metadata(&metadata, current_uid) {
        return Err(input_unsafe(label));
    }
    if metadata.len() > MAX_REMOTE_INPUT_BYTES as u64 {
        return Err(input_too_large(label));
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
    file.take((MAX_REMOTE_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| input_unsafe(label))?;
    if bytes.len() > MAX_REMOTE_INPUT_BYTES {
        return Err(input_too_large(label));
    }
    serde_json::from_slice(&bytes).map_err(|_| input_invalid(label))
}

fn safe_input_metadata(metadata: &std::fs::Metadata, current_uid: u32) -> bool {
    metadata.file_type().is_file()
        && !metadata.file_type().is_symlink()
        && metadata.uid() == current_uid
        && metadata.nlink() == 1
        && metadata.mode() & 0o077 == 0
}

fn machine_status_output(
    operation: &'static str,
    expose_template: bool,
    request_failure_code: Option<&str>,
    status: &MachineRemoteStatus,
) -> Result<serde_json::Value, CliError> {
    status.validate().map_err(|_| CliError::Protocol {
        code: Some("daemon.client.machine_status_invalid".to_owned()),
        message: "daemon returned an invalid machine remote status".to_owned(),
    })?;
    let relay_admin_purge = if expose_template
        && status.lifecycle == MachineRemoteLifecycle::Blocked
        && status.relay_server_id.is_some()
        && status.machine_route.is_some()
        && status.root_fingerprint.is_some()
        && status.trust_epoch.is_some()
        && status
            .failure_code
            .as_ref()
            .is_some_and(|code| code.as_str() == "daemon.remote.trust_reset.admin_receipt_required")
    {
        Some(relay_admin_purge_template(status)?)
    } else {
        None
    };
    Ok(serde_json::json!({
        "operation": operation,
        "requestFailureCode": request_failure_code,
        "status": serde_json::to_value(status)?,
        "relayAdminPurge": relay_admin_purge,
    }))
}

fn relay_admin_purge_template(status: &MachineRemoteStatus) -> Result<serde_json::Value, CliError> {
    let route = STANDARD.encode(
        status
            .machine_route
            .as_ref()
            .ok_or_else(|| invalid_status_template("machineRoute"))?
            .as_bytes(),
    );
    let fingerprint = URL_SAFE_NO_PAD.encode(
        status
            .root_fingerprint
            .as_ref()
            .ok_or_else(|| invalid_status_template("rootFingerprint"))?
            .as_bytes(),
    );
    let ndjson = serde_json::to_string(&serde_json::json!({
        "command": "machine_purge",
        "confirm_root_fingerprint": fingerprint,
        "machine_route": route,
    }))?;
    let quoted_ndjson = shell_single_quote(&ndjson);
    Ok(serde_json::json!({
        "commandTemplate": format!(
            "printf '%s\\n' {quoted_ndjson} | nc -U '<RELAY_ADMIN_SOCKET>'"
        ),
        "ndjson": ndjson,
    }))
}

fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn cli_error_code(error: &CliError) -> Option<&str> {
    match error {
        CliError::Protocol {
            code: Some(code), ..
        }
        | CliError::Transport {
            code: Some(code), ..
        }
        | CliError::Session {
            code: Some(code), ..
        } => Some(code),
        _ => None,
    }
}

fn input_unsafe(label: &'static str) -> CliError {
    local_input_error(
        INPUT_UNSAFE,
        format!("{label} must be a current-UID no-follow regular file"),
    )
}

fn input_too_large(label: &'static str) -> CliError {
    local_input_error(
        INPUT_TOO_LARGE,
        format!("{label} exceeds the {MAX_REMOTE_INPUT_BYTES}-byte limit"),
    )
}

fn input_invalid(label: &'static str) -> CliError {
    local_input_error(
        INPUT_INVALID,
        format!("{label} is not the strict canonical JSON DTO"),
    )
}

fn invalid_status_template(field: &'static str) -> CliError {
    CliError::Protocol {
        code: Some("daemon.client.machine_status_invalid".to_owned()),
        message: format!("blocked machine status is missing {field}"),
    }
}

fn local_input_error(code: &'static str, message: String) -> CliError {
    CliError::Protocol {
        code: Some(code.to_owned()),
        message,
    }
}

pub enum RemoteOpArg {
    Synthetic { bundle: PathBuf },
    LegacyV1,
    PersistentUnsupported,
}

pub async fn run(arg: RemoteOpArg, profile: &str, data_dir: Option<&str>) -> ExitCode {
    match arg {
        RemoteOpArg::Synthetic { bundle } => match v2_synthetic::run(&bundle).await {
            Ok(report) => match serde_json::to_string(&report) {
                Ok(json) => {
                    println!("{json}");
                    ExitCode::SUCCESS
                }
                Err(_) => fail("remote.synthetic.report_failed"),
            },
            Err(error) => fail(error.code()),
        },
        RemoteOpArg::LegacyV1 => fail("remote.v1.reset_required"),
        RemoteOpArg::PersistentUnsupported => match legacy_marker_state(data_dir, profile) {
            LegacyMarkerState::Present | LegacyMarkerState::Unknown => {
                fail("remote.v1.reset_required")
            }
            LegacyMarkerState::Absent => fail("remote.persistent.unsupported"),
        },
    }
}

fn fail(code: &str) -> ExitCode {
    eprintln!("{code}");
    ExitCode::FAILURE
}

/// 只探测旧凭据文件是否存在；不打开、不解析、不删除，也不读取其中任何 bearer。
fn legacy_marker_path(data_dir: Option<&str>, profile: &str) -> PathBuf {
    let base = data_dir.map_or_else(default_data_dir, PathBuf::from);
    base.join("relay")
        .join(format!("{profile}.credentials.json"))
}

enum LegacyMarkerState {
    Present,
    Absent,
    Unknown,
}

fn legacy_marker_state(data_dir: Option<&str>, profile: &str) -> LegacyMarkerState {
    match std::fs::symlink_metadata(legacy_marker_path(data_dir, profile)) {
        Ok(_) => LegacyMarkerState::Present,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => LegacyMarkerState::Absent,
        Err(_) => LegacyMarkerState::Unknown,
    }
}

#[cfg(target_os = "macos")]
fn default_data_dir() -> PathBuf {
    Path::new(&std::env::var_os("HOME").unwrap_or_default())
        .join("Library/Application Support/AgentDeck")
}

#[cfg(not(target_os = "macos"))]
fn default_data_dir() -> PathBuf {
    Path::new(&std::env::var_os("HOME").unwrap_or_default()).join(".local/share/agentdeck")
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::os::unix::fs::{PermissionsExt, symlink};

    use agentdeck_protocol::relay_v2::{MachineRouteId, RelayServerId};
    use agentdeck_protocol::runtime::{
        MachineRemoteFailureCode, MachineRootFingerprint, RuntimeRequest,
    };
    use tempfile::{NamedTempFile, tempdir};

    use super::*;

    fn fixture_payload(case_name: &str) -> serde_json::Value {
        include_str!("../../protocol/agentdeck/fixtures/runtime-v4-wire.jsonl")
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("fixture JSON"))
            .find(|case| case["case"] == case_name)
            .unwrap_or_else(|| panic!("missing fixture {case_name}"))["value"]["body"]["payload"]
            .clone()
    }

    fn private_json_file(value: &serde_json::Value) -> NamedTempFile {
        let mut file = NamedTempFile::new().expect("temporary input");
        serde_json::to_writer(file.as_file_mut(), value).expect("write fixture JSON");
        file.as_file_mut().flush().expect("flush fixture JSON");
        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o600))
            .expect("private fixture mode");
        file
    }

    fn blocked_status(code: &str) -> MachineRemoteStatus {
        MachineRemoteStatus::new(
            MachineRemoteLifecycle::Blocked,
            Some(RelayServerId::from_bytes([0x22; 16])),
            Some(MachineRouteId::from_bytes([0x33; 16])),
            Some(MachineRootFingerprint::from_bytes([0x44; 32])),
            Some(7),
            Some(MachineRemoteFailureCode::new(code).expect("stable failure code")),
        )
        .expect("valid blocked status")
    }

    #[test]
    fn legacy_marker_is_profile_scoped_without_reading_contents() {
        assert_eq!(
            legacy_marker_path(Some("/tmp/agentdeck-test"), "dev"),
            PathBuf::from("/tmp/agentdeck-test/relay/dev.credentials.json")
        );
    }

    #[test]
    fn legacy_marker_metadata_error_fails_closed() {
        assert!(matches!(
            legacy_marker_state(Some("/tmp/agentdeck-test"), "invalid\0profile"),
            LegacyMarkerState::Unknown
        ));
    }

    #[test]
    fn strict_files_build_only_typed_runtime_requests() {
        let enrollment = private_json_file(&fixture_payload("requestMachineEnroll")["bundle"]);
        let plan = RuntimeRemotePlan::machine_enroll(enrollment.path()).expect("safe bundle");
        let RuntimeRequest::MachineEnroll(request) = plan.into_request().expect("enroll request")
        else {
            panic!("expected MachineEnroll request")
        };
        assert_eq!(request.bundle.version, 2);

        let receipt = private_json_file(
            &fixture_payload("requestTrustResetWithAdminPurgeReceipt")["adminPurgeReceipt"],
        );
        let plan = RuntimeRemotePlan::trust_reset(Some(receipt.path())).expect("safe receipt");
        let RuntimeRequest::TrustReset(request) = plan.into_request().expect("trust reset request")
        else {
            panic!("expected TrustReset request")
        };
        assert!(!request.uninstall_purge());
        assert!(request.uninstall_purge_plan().is_none());
        assert!(request.admin_purge_receipt().is_some());
    }

    #[test]
    fn strict_files_reject_unknown_tampered_oversize_symlink_hardlink_and_public_mode() {
        let mut unknown = fixture_payload("requestMachineEnroll")["bundle"].clone();
        unknown["future"] = serde_json::json!(true);
        let unknown = private_json_file(&unknown);
        assert_eq!(
            cli_error_code(&RuntimeRemotePlan::machine_enroll(unknown.path()).unwrap_err()),
            Some(INPUT_INVALID)
        );

        let mut tampered =
            fixture_payload("requestTrustResetWithAdminPurgeReceipt")["adminPurgeReceipt"].clone();
        tampered["readback"]["retiredTombstones"] = serde_json::json!(2);
        let tampered = private_json_file(&tampered);
        assert_eq!(
            cli_error_code(&RuntimeRemotePlan::trust_reset(Some(tampered.path())).unwrap_err()),
            Some(INPUT_INVALID)
        );

        let directory = tempdir().expect("temporary directory");
        let oversize = directory.path().join("oversize.json");
        let mut oversize_file = File::create(&oversize).expect("create oversize file");
        oversize_file
            .write_all(&vec![b'x'; MAX_REMOTE_INPUT_BYTES + 1])
            .expect("write oversize file");
        drop(oversize_file);
        std::fs::set_permissions(&oversize, std::fs::Permissions::from_mode(0o600))
            .expect("private oversize mode");
        assert_eq!(
            cli_error_code(&RuntimeRemotePlan::machine_enroll(&oversize).unwrap_err()),
            Some(INPUT_TOO_LARGE)
        );

        let target = private_json_file(&fixture_payload("requestMachineEnroll")["bundle"]);
        let symlink_path = directory.path().join("bundle-link.json");
        symlink(target.path(), &symlink_path).expect("create symlink");
        assert_eq!(
            cli_error_code(&RuntimeRemotePlan::machine_enroll(&symlink_path).unwrap_err()),
            Some(INPUT_UNSAFE)
        );

        let hardlink_path = directory.path().join("bundle-hardlink.json");
        std::fs::hard_link(target.path(), &hardlink_path).expect("create hardlink");
        assert_eq!(
            cli_error_code(&RuntimeRemotePlan::machine_enroll(target.path()).unwrap_err()),
            Some(INPUT_UNSAFE)
        );

        let public = private_json_file(&fixture_payload("requestMachineEnroll")["bundle"]);
        std::fs::set_permissions(public.path(), std::fs::Permissions::from_mode(0o644))
            .expect("public fixture mode");
        assert_eq!(
            cli_error_code(&RuntimeRemotePlan::machine_enroll(public.path()).unwrap_err()),
            Some(INPUT_UNSAFE)
        );

        let private = private_json_file(&fixture_payload("requestMachineEnroll")["bundle"]);
        let metadata = private.as_file().metadata().expect("fixture metadata");
        // SAFETY: geteuid has no preconditions.
        let uid = unsafe { libc::geteuid() };
        assert!(safe_input_metadata(&metadata, uid));
        assert!(!safe_input_metadata(&metadata, uid.saturating_add(1)));
    }

    #[test]
    fn pairing_plans_validate_local_inputs_and_build_only_v4_admin_requests() {
        let invite = RuntimeRemotePlan::create_pair_invite(
            "workstation".to_owned(),
            "pairing-invite-1".to_owned(),
        )
        .expect("valid pairing invite plan");
        assert!(matches!(
            invite.into_request().expect("create invite request"),
            RuntimeRequest::CreatePairInvite(CreatePairInviteRequest {
                display_name,
                idempotency_key,
                scope: LocalOnlyAdministration::LocalOnly,
            }) if display_name == "workstation" && idempotency_key.as_str() == "pairing-invite-1"
        ));
        assert!(matches!(
            RuntimeRemotePlan::pairing_pending()
                .into_request()
                .expect("pending request"),
            RuntimeRequest::ListPendingPairings {
                scope: LocalOnlyAdministration::LocalOnly
            }
        ));

        let pairing_id = "11111111-1111-1111-1111-111111111111";
        assert!(matches!(
            RuntimeRemotePlan::pairing_approve(pairing_id.to_owned())
                .expect("approve plan")
                .into_request()
                .expect("approve request"),
            RuntimeRequest::ConfirmPairing { pairing_id: value, .. }
                if value.as_str() == pairing_id
        ));
        assert!(matches!(
            RuntimeRemotePlan::pairing_cancel(pairing_id.to_owned())
                .expect("cancel plan")
                .into_request()
                .expect("cancel request"),
            RuntimeRequest::CancelPairing { pairing_id: value, .. }
                if value.as_str() == pairing_id
        ));

        assert!(RuntimeRemotePlan::create_pair_invite("\n".to_owned(), "key".to_owned()).is_err());
        assert!(
            RuntimeRemotePlan::create_pair_invite("machine".to_owned(), String::new()).is_err()
        );
        assert!(
            RuntimeRemotePlan::pairing_approve("AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA".to_owned())
                .is_err()
        );
        assert!(RuntimeRemotePlan::pairing_cancel(uuid::Uuid::nil().to_string()).is_err());
    }

    #[test]
    fn pairing_invite_output_is_one_canonical_uri_without_structured_secret_fields() {
        let reply: RuntimeReply =
            serde_json::from_value(fixture_payload("replyPairInvite")).expect("fixture reply");
        let RuntimeReply::PairInvite(value) = reply else {
            panic!("expected PairInvite reply")
        };
        let expected = (*value.invite).clone();
        let output = canonical_pair_invite_output(value, 1_700_000_000_000)
            .expect("fresh canonical invite URI");

        assert_eq!(output.as_object().map(serde_json::Map::len), Some(2));
        assert_eq!(output["pairingId"], "pairing-invite-1");
        let invite_uri = output["inviteUri"].as_str().expect("inviteUri string");
        assert_eq!(
            agentdeck_protocol::e2ee::PairInviteV1::decode_uri(invite_uri, 1_700_000_000_000,)
                .expect("decode emitted URI"),
            expected,
        );
        let rendered = output.to_string();
        for forbidden in ["inviteSecret", "wssUrl", "currentSpkiPin", "dataSignCert"] {
            assert!(!rendered.contains(forbidden));
        }
    }

    #[test]
    fn revoke_plan_requires_exact_device_handle_and_nonzero_serial() {
        let handle = "device-11111111111111111111111111111111";
        assert!(matches!(
            RuntimeRemotePlan::revoke_device(handle.to_owned(), 7)
                .expect("valid revoke plan")
                .into_request()
                .expect("revoke request"),
            RuntimeRequest::Revoke(RevokeRequest {
                target: RevokeTarget::Device {
                    device,
                    grant_serial,
                    scope: LocalOnlyAdministration::LocalOnly,
                }
            }) if device.as_str() == handle && grant_serial == GrantSerial::new(7)
        ));
        assert!(RuntimeRemotePlan::revoke_device(handle.to_owned(), 0).is_err());
        assert!(
            RuntimeRemotePlan::revoke_device(
                "device-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
                1,
            )
            .is_err()
        );
        assert!(
            RuntimeRemotePlan::revoke_device(
                "device-00000000000000000000000000000000".to_owned(),
                1
            )
            .is_err()
        );
    }

    #[test]
    fn blocked_output_allows_only_root_lost_admin_purge_and_redacts_input_material() {
        let status = blocked_status("daemon.remote.trust_reset.admin_receipt_required");
        let output = machine_status_output("remote.trustReset", true, None, &status)
            .expect("render root-lost status");
        let action = output["relayAdminPurge"].clone();
        let ndjson = action["ndjson"].as_str().expect("NDJSON template");
        let parsed: agentdeck_relay::v2::admin::AdminRequest =
            serde_json::from_str(ndjson).expect("template matches Relay admin protocol");
        assert!(matches!(
            parsed,
            agentdeck_relay::v2::admin::AdminRequest::MachinePurge { .. }
        ));
        assert!(
            action["commandTemplate"]
                .as_str()
                .expect("command template")
                .starts_with("printf '%s\\n' ")
        );
        let encoded = serde_json::to_string(&output).expect("status JSON");
        for forbidden in [
            "spkiPins",
            "linkCert",
            "dataCert",
            "adminPurgeReceipt",
            "signature",
            "tombstoneHash",
        ] {
            assert!(
                !encoded.contains(forbidden),
                "leaked {forbidden}: {encoded}"
            );
        }

        for code in [
            "daemon.remote.identity.key_missing",
            "daemon.remote.enrollment.pinset_invalid",
            "daemon.remote.trust_reset.state_conflict",
            "daemon.remote.trust_reset.relay_restarting",
        ] {
            let output =
                machine_status_output("remote.machine.status", true, None, &blocked_status(code))
                    .expect("render non-root-lost blocked status");
            assert!(
                output["relayAdminPurge"].is_null(),
                "unsafe action for {code}"
            );
        }
    }

    #[test]
    fn shell_quote_is_total_for_operator_template_values() {
        assert_eq!(shell_single_quote("plain"), "'plain'");
        assert_eq!(shell_single_quote("a'b"), "'a'\"'\"'b'");
    }
}
