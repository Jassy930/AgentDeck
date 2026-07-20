//! Runtime v4 device/local → daemon 请求（design §8 / §13.2）。
//!
//! `RuntimeRequest` 是解密后设备/本地统一规范化的业务请求（RC-2 传输平权）。
//! pending pairing 的 list/confirm/cancel 以及 create/trust-reset/device-revoke 是
//! **local-only administration**：daemon 只允许 same-UID UDS `LocalPrincipal` 调用，
//! 任何 `RemotePrincipal`、PairingAccess 或 Relay 管理员都无权调用（design §6.2/§6.3/§6.5）。
//! 本 task 只定义契约与标注，不实现执行语义。

use crate::e2ee::pairing::{PAIRING_MAX_DISPLAY_NAME_BYTES, validate_pairing_display_name};
use crate::relay_v2::enrollment::EnrollmentBundleV2;
use crate::relay_v2::{RelayAdminPurgeReceiptError, RelayAdminPurgeReceiptV1};
use crate::runtime::configuration::ConfigureConversationRequest;
use crate::runtime::identity::{
    ApprovalId, CatalogPageCursor, CommandId, ConversationId, DeviceHandle, GrantSerial,
    IdempotencyKey, PairingId, TurnId,
};
use crate::runtime::metadata::ConversationMetadataMutationRequest;
use crate::runtime::sync::{BackfillRequest, RuntimeInnerCursor, RuntimeSubscriptionTarget};
use crate::runtime::upgrade::{ArtifactSha256, StageUpgradeRequest};
use crate::trunk::{ActionDecision, AgentKind};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use schemars::{
    JsonSchema,
    schema::{InstanceType, Schema, SchemaObject},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Component, Path, PathBuf};

/// prompt 明文 UTF-8 最大字节数（design §8.8：256 KiB）。
pub const MAX_PROMPT_BYTES: usize = 256 * 1024;
/// PairInvite 的固定 5 分钟 TTL；不接受 wire caller 覆盖。
pub const PAIR_INVITE_TTL_SECS: u32 = 300;
pub const UNINSTALL_PURGE_PLAN_VERSION: u16 = 1;
pub const MAX_UNINSTALL_HELPER_PATH_BYTES: usize = 1024;
pub const MAX_UNINSTALL_HELPER_VERSION_BYTES: usize = 128;
pub const MAX_TEAM_IDENTIFIER_BYTES: usize = 64;
pub const MAX_KEYCHAIN_ACCESS_GROUP_BYTES: usize = 255;
const DAEMON_KEYCHAIN_ACCESS_GROUP_SUFFIX: &str = ".com.agentdeck.agentdeckd.stable";

/// prompt 校验失败。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PromptError {
    #[error("prompt exceeds {MAX_PROMPT_BYTES} bytes (256 KiB)")]
    TooLarge,
}

/// 已校验的 prompt 明文（≤ 256 KiB UTF-8）。构造与 wire 反序列化都强制上限。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(try_from = "String", into = "String")]
#[schemars(with = "String")]
pub struct PromptPayload(String);

impl PromptPayload {
    pub fn new(text: impl Into<String>) -> Result<Self, PromptError> {
        let text = text.into();
        if text.len() > MAX_PROMPT_BYTES {
            return Err(PromptError::TooLarge);
        }
        Ok(Self(text))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl TryFrom<String> for PromptPayload {
    type Error = PromptError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        PromptPayload::new(value)
    }
}

impl From<PromptPayload> for String {
    fn from(value: PromptPayload) -> Self {
        value.0
    }
}

/// local-only administration 信任边界标记。
///
/// 携带此标记的请求是 **local-only administration**：daemon 必须拒绝任何不是来自
/// same-UID UDS `LocalPrincipal` 的调用。它显式记录在类型、文档与 schema 中，
/// 让客户端与审阅者都能确认该请求永不允许远端或 Relay 管理员发起。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum LocalOnlyAdministration {
    LocalOnly,
}

/// `Hello` 握手参数。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HelloParams {
    pub runtime_protocol_version: u16,
}

/// catalog 请求。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CatalogRequest {
    #[serde(deserialize_with = "deserialize_required_optional_page_cursor")]
    #[schemars(with = "crate::runtime::schema::RequiredNullable<CatalogPageCursor>")]
    pub page_cursor: Option<CatalogPageCursor>,
}

/// 新建 conversation（daemon 在 adapter 启动前生成 conversationId）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConversationStart {
    pub agent_kind: AgentKind,
    pub idempotency_key: IdempotencyKey,
    pub cwd: PathBuf,
    #[serde(default)]
    pub title: Option<String>,
}

/// 发送 prompt。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SendPromptRequest {
    pub conversation_id: ConversationId,
    pub idempotency_key: IdempotencyKey,
    pub expected_configuration_revision: u64,
    pub prompt: PromptPayload,
}

/// 按 command 或 conversation-scoped idempotency key 精确查询原始回执。
///
/// internally-tagged 形态排除“全空、两种 selector 同时出现、字段互相矛盾”的
/// 歧义；两种 selector 都必须绑定 conversation。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "selector", rename_all = "camelCase", deny_unknown_fields)]
pub enum QueryReceiptSelector {
    Command {
        #[serde(rename = "conversationId")]
        conversation_id: ConversationId,
        #[serde(rename = "commandId")]
        command_id: CommandId,
    },
    Idempotency {
        #[serde(rename = "conversationId")]
        conversation_id: ConversationId,
        #[serde(rename = "idempotencyKey")]
        idempotency_key: IdempotencyKey,
    },
}

/// 创建 PairInvite —— local-only administration（design §6.2）。
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema)]
#[schemars(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreatePairInviteRequest {
    /// 仅供人识别的机器显示名；存在于带外邀请中，不进入 Relay 明文。
    #[schemars(length(min = 1, max = 128))]
    pub display_name: String,
    /// caller-scoped retry key；丢失 reply 后重试必须读回同一份 durable invite。
    pub idempotency_key: IdempotencyKey,
    /// local-only administration 标记。
    pub scope: LocalOnlyAdministration,
}

impl Serialize for CreatePairInviteRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        validate_pairing_display_name(&self.display_name).map_err(serde::ser::Error::custom)?;
        debug_assert_eq!(PAIRING_MAX_DISPLAY_NAME_BYTES, 128);
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire<'a> {
            display_name: &'a str,
            idempotency_key: &'a IdempotencyKey,
            scope: LocalOnlyAdministration,
        }
        Wire {
            display_name: &self.display_name,
            idempotency_key: &self.idempotency_key,
            scope: self.scope,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for CreatePairInviteRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            display_name: String,
            idempotency_key: IdempotencyKey,
            scope: LocalOnlyAdministration,
        }
        let wire = Wire::deserialize(deserializer)?;
        validate_pairing_display_name(&wire.display_name).map_err(serde::de::Error::custom)?;
        Ok(Self {
            display_name: wire.display_name,
            idempotency_key: wire.idempotency_key,
            scope: wire.scope,
        })
    }
}

/// 由 same-UID 本机管理员提交的 machine enrollment 请求。
///
/// bundle 是 Relay admin 与 daemon/CLI 共用的严格共享 DTO；Runtime 只承载它，
/// 不复制 enrollment JSON 形状，也不在公开 status 中回显 code、origin 或 pinset。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MachineEnrollRequest {
    pub bundle: EnrollmentBundleV2,
    pub scope: LocalOnlyAdministration,
}

/// 卸载 purge helper attestation plan 校验失败。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum UninstallPurgePlanError {
    #[error("unsupported uninstall purge plan version")]
    UnsupportedVersion,
    #[error("uninstall purge helper path is not bounded canonical absolute UTF-8")]
    InvalidHelperPath,
    #[error("uninstall purge helper version is empty, unsafe or oversized")]
    InvalidHelperVersion,
    #[error("uninstall purge TeamIdentifier is invalid")]
    InvalidTeamIdentifier,
    #[error("uninstall purge Keychain access group is invalid")]
    InvalidKeychainAccessGroup,
    #[error("uninstall purge planId does not match the canonical helper attestation")]
    PlanIdMismatch,
    #[error("uninstall purge planId derivation produced an all-zero value")]
    ZeroPlanId,
}

/// CLI 预检 helper 后交给 daemon finalizer 的确定性 attestation plan。
///
/// `planId = SHA256(domain || canonical attestation fields)[0..16]`。相同 helper
/// attestation 在 CLI crash/retry 后得到同一 marker identity；任一字段变化都会得到
/// 不同 ID，并由 daemon existing-only marker fail-close。
#[derive(Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UninstallPurgePlanV1 {
    #[schemars(range(min = 1, max = 1))]
    version: u16,
    #[serde(with = "plan_id_b64")]
    #[schemars(with = "String")]
    plan_id: [u8; 16],
    #[schemars(length(min = 1, max = 1024))]
    helper_path: PathBuf,
    #[schemars(length(min = 1, max = 128), regex(pattern = "^[A-Za-z0-9._+-]+$"))]
    helper_version: String,
    helper_sha256: ArtifactSha256,
    #[schemars(length(min = 1, max = 64), regex(pattern = "^[A-Za-z0-9]+$"))]
    team_identifier: String,
    #[schemars(length(min = 1, max = 255), regex(pattern = "^[A-Za-z0-9.]+$"))]
    keychain_access_group: String,
}

impl UninstallPurgePlanV1 {
    pub fn new(
        helper_path: PathBuf,
        helper_version: String,
        helper_sha256: ArtifactSha256,
        team_identifier: String,
        keychain_access_group: String,
    ) -> Result<Self, UninstallPurgePlanError> {
        validate_uninstall_helper_path(&helper_path)?;
        validate_uninstall_helper_version(&helper_version)?;
        validate_team_identifier(&team_identifier)?;
        validate_keychain_access_group(&team_identifier, &keychain_access_group)?;
        let plan_id = Self::derive_plan_id(
            &helper_path,
            &helper_version,
            &helper_sha256,
            &team_identifier,
            &keychain_access_group,
        )?;
        Ok(Self {
            version: UNINSTALL_PURGE_PLAN_VERSION,
            plan_id,
            helper_path,
            helper_version,
            helper_sha256,
            team_identifier,
            keychain_access_group,
        })
    }

    pub fn derive_plan_id(
        helper_path: &Path,
        helper_version: &str,
        helper_sha256: &ArtifactSha256,
        team_identifier: &str,
        keychain_access_group: &str,
    ) -> Result<[u8; 16], UninstallPurgePlanError> {
        validate_uninstall_helper_path(helper_path)?;
        validate_uninstall_helper_version(helper_version)?;
        validate_team_identifier(team_identifier)?;
        validate_keychain_access_group(team_identifier, keychain_access_group)?;
        let path = helper_path
            .to_str()
            .ok_or(UninstallPurgePlanError::InvalidHelperPath)?;
        let mut hasher = Sha256::new();
        hasher.update(b"AgentDeck/UninstallPurgePlanV1\0");
        hasher.update(UNINSTALL_PURGE_PLAN_VERSION.to_be_bytes());
        update_plan_hash(&mut hasher, path.as_bytes());
        update_plan_hash(&mut hasher, helper_version.as_bytes());
        update_plan_hash(&mut hasher, helper_sha256.as_str().as_bytes());
        update_plan_hash(&mut hasher, team_identifier.as_bytes());
        update_plan_hash(&mut hasher, keychain_access_group.as_bytes());
        let digest = hasher.finalize();
        let mut plan_id = [0_u8; 16];
        plan_id.copy_from_slice(&digest[..16]);
        if plan_id == [0; 16] {
            return Err(UninstallPurgePlanError::ZeroPlanId);
        }
        Ok(plan_id)
    }

    pub const fn version(&self) -> u16 {
        self.version
    }

    pub const fn plan_id(&self) -> &[u8; 16] {
        &self.plan_id
    }

    pub fn helper_path(&self) -> &Path {
        &self.helper_path
    }

    pub fn helper_version(&self) -> &str {
        &self.helper_version
    }

    pub const fn helper_sha256(&self) -> &ArtifactSha256 {
        &self.helper_sha256
    }

    pub fn team_identifier(&self) -> &str {
        &self.team_identifier
    }

    pub fn keychain_access_group(&self) -> &str {
        &self.keychain_access_group
    }
}

impl std::fmt::Debug for UninstallPurgePlanV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UninstallPurgePlanV1")
            .field("version", &self.version)
            .field("attestation", &"<redacted>")
            .finish()
    }
}

impl<'de> Deserialize<'de> for UninstallPurgePlanV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            version: u16,
            #[serde(with = "plan_id_b64")]
            plan_id: [u8; 16],
            helper_path: PathBuf,
            helper_version: String,
            helper_sha256: ArtifactSha256,
            team_identifier: String,
            keychain_access_group: String,
        }

        let wire = Wire::deserialize(deserializer)?;
        if wire.version != UNINSTALL_PURGE_PLAN_VERSION {
            return Err(serde::de::Error::custom(
                UninstallPurgePlanError::UnsupportedVersion,
            ));
        }
        let plan = Self::new(
            wire.helper_path,
            wire.helper_version,
            wire.helper_sha256,
            wire.team_identifier,
            wire.keychain_access_group,
        )
        .map_err(serde::de::Error::custom)?;
        if wire.plan_id != plan.plan_id {
            return Err(serde::de::Error::custom(
                UninstallPurgePlanError::PlanIdMismatch,
            ));
        }
        Ok(plan)
    }
}

fn update_plan_hash(hasher: &mut Sha256, value: &[u8]) {
    let length = u32::try_from(value.len()).expect("validated plan field fits in u32");
    hasher.update(length.to_be_bytes());
    hasher.update(value);
}

fn validate_uninstall_helper_path(path: &Path) -> Result<(), UninstallPurgePlanError> {
    let value = path
        .to_str()
        .ok_or(UninstallPurgePlanError::InvalidHelperPath)?;
    if value.is_empty()
        || value.len() > MAX_UNINSTALL_HELPER_PATH_BYTES
        || value.as_bytes().contains(&0)
        || !path.is_absolute()
    {
        return Err(UninstallPurgePlanError::InvalidHelperPath);
    }
    let mut canonical = PathBuf::from("/");
    let mut normal_components = 0_usize;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(component) => {
                canonical.push(component);
                normal_components += 1;
            }
            _ => return Err(UninstallPurgePlanError::InvalidHelperPath),
        }
    }
    if normal_components == 0 || canonical.as_os_str() != path.as_os_str() {
        return Err(UninstallPurgePlanError::InvalidHelperPath);
    }
    Ok(())
}

fn validate_uninstall_helper_version(value: &str) -> Result<(), UninstallPurgePlanError> {
    if value.is_empty()
        || matches!(value, "." | "..")
        || value.len() > MAX_UNINSTALL_HELPER_VERSION_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-'))
    {
        return Err(UninstallPurgePlanError::InvalidHelperVersion);
    }
    Ok(())
}

fn validate_team_identifier(value: &str) -> Result<(), UninstallPurgePlanError> {
    if value.is_empty()
        || value == "TEAMID"
        || value.len() > MAX_TEAM_IDENTIFIER_BYTES
        || !value.bytes().all(|byte| byte.is_ascii_alphanumeric())
    {
        return Err(UninstallPurgePlanError::InvalidTeamIdentifier);
    }
    Ok(())
}

fn validate_keychain_access_group(
    team_identifier: &str,
    value: &str,
) -> Result<(), UninstallPurgePlanError> {
    let expected = format!("{team_identifier}{DAEMON_KEYCHAIN_ACCESS_GROUP_SUFFIX}");
    if value.len() > MAX_KEYCHAIN_ACCESS_GROUP_BYTES || value != expected {
        return Err(UninstallPurgePlanError::InvalidKeychainAccessGroup);
    }
    Ok(())
}

mod plan_id_b64 {
    use super::*;

    pub fn serialize<S: serde::Serializer>(
        value: &[u8; 16],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(value))
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<[u8; 16], D::Error> {
        let encoded = String::deserialize(deserializer)?;
        let bytes = STANDARD
            .decode(encoded.as_bytes())
            .map_err(serde::de::Error::custom)?;
        let bytes: [u8; 16] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("planId must decode to exactly 16 bytes"))?;
        if STANDARD.encode(bytes) != encoded || bytes == [0; 16] {
            return Err(serde::de::Error::custom(
                "planId must be canonical nonzero 16-byte base64",
            ));
        }
        Ok(bytes)
    }
}

/// local-only machine trust-reset request。
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustResetRequest {
    scope: LocalOnlyAdministration,
    #[serde(default, skip_serializing_if = "is_false")]
    uninstall_purge: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    uninstall_purge_plan: Option<UninstallPurgePlanV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    admin_purge_receipt: Option<Box<RelayAdminPurgeReceiptV1>>,
}

#[allow(dead_code)]
#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OrdinaryTrustResetRequestSchema {
    scope: LocalOnlyAdministration,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    uninstall_purge: Option<UninstallPurgeFalseSchema>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    admin_purge_receipt: Option<Box<RelayAdminPurgeReceiptV1>>,
}

#[allow(dead_code)]
#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FinalizerTrustResetRequestSchema {
    scope: LocalOnlyAdministration,
    uninstall_purge: UninstallPurgeTrueSchema,
    uninstall_purge_plan: UninstallPurgePlanV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    admin_purge_receipt: Option<Box<RelayAdminPurgeReceiptV1>>,
}

#[allow(dead_code)]
#[derive(Serialize, JsonSchema)]
#[serde(untagged)]
enum TrustResetRequestSchema {
    Ordinary(OrdinaryTrustResetRequestSchema),
    Finalizer(FinalizerTrustResetRequestSchema),
}

struct UninstallPurgeFalseSchema;
struct UninstallPurgeTrueSchema;

impl JsonSchema for UninstallPurgeFalseSchema {
    fn schema_name() -> String {
        "UninstallPurgeFalse".to_owned()
    }

    fn json_schema(_generator: &mut schemars::r#gen::SchemaGenerator) -> Schema {
        boolean_literal_schema(false)
    }
}

impl JsonSchema for UninstallPurgeTrueSchema {
    fn schema_name() -> String {
        "UninstallPurgeTrue".to_owned()
    }

    fn json_schema(_generator: &mut schemars::r#gen::SchemaGenerator) -> Schema {
        boolean_literal_schema(true)
    }
}

impl Serialize for UninstallPurgeFalseSchema {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bool(false)
    }
}

impl Serialize for UninstallPurgeTrueSchema {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bool(true)
    }
}

fn boolean_literal_schema(value: bool) -> Schema {
    SchemaObject {
        instance_type: Some(InstanceType::Boolean.into()),
        enum_values: Some(vec![serde_json::Value::Bool(value)]),
        ..Default::default()
    }
    .into()
}

impl JsonSchema for TrustResetRequest {
    fn schema_name() -> String {
        "TrustResetRequest".to_owned()
    }

    fn json_schema(generator: &mut schemars::r#gen::SchemaGenerator) -> Schema {
        TrustResetRequestSchema::json_schema(generator)
    }
}

impl TrustResetRequest {
    pub fn new(
        scope: LocalOnlyAdministration,
        admin_purge_receipt: Option<Box<RelayAdminPurgeReceiptV1>>,
    ) -> Result<Self, RelayAdminPurgeReceiptError> {
        if let Some(receipt) = &admin_purge_receipt {
            receipt.validate()?;
        }
        Ok(Self {
            scope,
            uninstall_purge: false,
            uninstall_purge_plan: None,
            admin_purge_receipt,
        })
    }

    pub fn for_uninstall_purge(
        scope: LocalOnlyAdministration,
        plan: UninstallPurgePlanV1,
        admin_purge_receipt: Option<Box<RelayAdminPurgeReceiptV1>>,
    ) -> Result<Self, RelayAdminPurgeReceiptError> {
        if let Some(receipt) = &admin_purge_receipt {
            receipt.validate()?;
        }
        Ok(Self {
            scope,
            uninstall_purge: true,
            uninstall_purge_plan: Some(plan),
            admin_purge_receipt,
        })
    }

    pub const fn scope(&self) -> LocalOnlyAdministration {
        self.scope
    }

    pub const fn uninstall_purge(&self) -> bool {
        self.uninstall_purge
    }

    pub const fn uninstall_purge_plan(&self) -> Option<&UninstallPurgePlanV1> {
        self.uninstall_purge_plan.as_ref()
    }

    pub fn admin_purge_receipt(&self) -> Option<&RelayAdminPurgeReceiptV1> {
        self.admin_purge_receipt.as_deref()
    }

    pub fn into_admin_purge_receipt(self) -> Option<Box<RelayAdminPurgeReceiptV1>> {
        self.admin_purge_receipt
    }
}

impl std::fmt::Debug for TrustResetRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TrustResetRequest")
            .field("scope", &self.scope)
            .field("uninstall_purge", &self.uninstall_purge)
            .field("uninstall_purge_plan", &self.uninstall_purge_plan.is_some())
            .field("admin_purge_receipt", &self.admin_purge_receipt.is_some())
            .finish()
    }
}

impl<'de> Deserialize<'de> for TrustResetRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            scope: LocalOnlyAdministration,
            #[serde(default)]
            uninstall_purge: bool,
            #[serde(default)]
            uninstall_purge_plan: Option<UninstallPurgePlanV1>,
            #[serde(default)]
            admin_purge_receipt: Option<Box<RelayAdminPurgeReceiptV1>>,
        }

        let wire = Wire::deserialize(deserializer)?;
        if wire.uninstall_purge != wire.uninstall_purge_plan.is_some() {
            return Err(serde::de::Error::custom(
                "uninstallPurge must be true iff uninstallPurgePlan is present",
            ));
        }
        let request = if let Some(plan) = wire.uninstall_purge_plan {
            Self::for_uninstall_purge(wire.scope, plan, wire.admin_purge_receipt)
        } else {
            Self::new(wire.scope, wire.admin_purge_receipt)
        };
        request.map_err(serde::de::Error::custom)
    }
}

/// 撤销请求。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevokeRequest {
    pub target: RevokeTarget,
}

/// 撤销目标：设备只能 revoke self；撤销其他设备是 local-only administration。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum RevokeTarget {
    /// 撤销自身（iOS 只允许这一种）。
    SelfDevice,
    /// 撤销指定设备 —— local-only administration。
    Device {
        device: DeviceHandle,
        grant_serial: GrantSerial,
        scope: LocalOnlyAdministration,
    },
}

/// device/local → daemon 请求集合（design §13.2 命令面 + §6 pairing/revoke 管理面）。
///
/// 未派生 `PartialEq`：`ResolveApproval` 内嵌未派生 `PartialEq` 的中立 `ActionDecision`；
/// 本 task 不改动 trunk，契约测试以 wire round-trip 覆盖。
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "request", rename_all = "camelCase", deny_unknown_fields)]
pub enum RuntimeRequest {
    /// 版本/能力握手。
    Hello(HelloParams),
    /// 枚举可用 agent、capabilities 与默认 conversation configuration。
    DescribeAgents,
    /// 请求 catalog snapshot / 订阅。
    Catalog(CatalogRequest),
    /// 订阅某 conversation 的事件流，从 cursor 之后开始。
    Subscribe {
        #[serde(rename = "innerCursor")]
        inner_cursor: RuntimeInnerCursor,
    },
    /// 释放 catalog/conversation watcher；对相同 target 幂等。
    Unsubscribe { target: RuntimeSubscriptionTarget },
    /// Relay gap 后按 inner HWM 请求定向 backfill/snapshot。
    Backfill(BackfillRequest),
    /// 新建 conversation。
    Start(ConversationStart),
    /// 以 CAS + idempotency 追加 conversation configuration revision。
    ConfigureConversation(ConfigureConversationRequest),
    /// 以独立 entry revision CAS 更新 canonical metadata。
    UpdateConversationMetadata(ConversationMetadataMutationRequest),
    /// 发送 prompt（有副作用；receipt Accepted/Replayed/Failed）。
    SendPrompt(SendPromptRequest),
    /// 提交 approval 决定（first-wins）。
    ResolveApproval {
        conversation_id: ConversationId,
        turn_id: TurnId,
        approval_id: ApprovalId,
        decision: ActionDecision,
    },
    /// 对已 claim 的同一决定重启投递（不提交新决定）。
    RetryApproval {
        conversation_id: ConversationId,
        approval_id: ApprovalId,
    },
    /// 精确取消尚未 Started 的 queued command。
    CancelQueued {
        #[serde(rename = "conversationId")]
        conversation_id: ConversationId,
        #[serde(rename = "commandId")]
        command_id: CommandId,
    },
    /// 明确请求取消当前 active turn；缺失/stale turnId 必须 fail-close。
    CancelActive {
        #[serde(rename = "conversationId")]
        conversation_id: ConversationId,
        #[serde(rename = "turnId")]
        turn_id: TurnId,
    },
    /// 查询原始回执（断线重取；不依赖 Relay 请求来源缓存）。
    QueryReceipt(QueryReceiptSelector),
    /// 创建 PairInvite —— local-only administration。
    CreatePairInvite(CreatePairInviteRequest),
    /// 列出待本地确认的 pending pairing —— local-only administration。
    ///
    /// daemon 只允许 same-UID UDS `LocalPrincipal` 调用；远端/Relay 管理员无权调用。
    ListPendingPairings { scope: LocalOnlyAdministration },
    /// 确认一个 pending pairing —— local-only administration。
    ///
    /// daemon 只允许 same-UID UDS `LocalPrincipal` 调用；远端/Relay 管理员无权调用。
    ConfirmPairing {
        pairing_id: PairingId,
        scope: LocalOnlyAdministration,
    },
    /// 取消一个 pending pairing —— local-only administration。
    ///
    /// daemon 只允许 same-UID UDS `LocalPrincipal` 调用；远端/Relay 管理员无权调用。
    CancelPairing {
        pairing_id: PairingId,
        scope: LocalOnlyAdministration,
    },
    /// 撤销设备（self 或指定设备）。
    Revoke(RevokeRequest),
    /// 使用共享 enrollment bundle 登记本机 —— local-only administration。
    MachineEnroll(MachineEnrollRequest),
    /// 读取最小 machine remote lifecycle —— local-only administration。
    MachineRemoteStatus { scope: LocalOnlyAdministration },
    /// machine trust reset —— local-only administration。
    ///
    /// `admin_purge_receipt` 仅用于 MachineRoot 已丢失的路径；有 root 时必须为
    /// `None`，并保持既有 `{request, scope}` wire 逐字节不变。portable proof 使用
    /// Relay/daemon 共用的严格 DTO，不接受 raw JSON 或 opaque bytes。
    TrustReset(TrustResetRequest),
    /// 本机管理员 staged upgrade；P3.9 只冻结 wire，执行语义属于 P3.10。
    StageUpgrade(StageUpgradeRequest),
}

const fn is_false(value: &bool) -> bool {
    !*value
}

fn deserialize_required_optional_page_cursor<'de, D>(
    deserializer: D,
) -> Result<Option<CatalogPageCursor>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<CatalogPageCursor>::deserialize(deserializer)
}
