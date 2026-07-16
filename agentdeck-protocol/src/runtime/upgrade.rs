//! Runtime v2 dormant local-only StageUpgrade contract（执行语义属于 P3.10）。

use crate::runtime::command::LocalOnlyAdministration;
use crate::runtime::failure::RuntimeFailure;
use crate::runtime::identity::IdempotencyKey;
use schemars::schema::{InstanceType, Schema, SchemaObject, StringValidation, SubschemaValidation};
use schemars::{JsonSchema, r#gen::SchemaGenerator};
use serde::{Deserialize, Serialize};

pub const ARTIFACT_SHA256_HEX_BYTES: usize = 64;
pub const MAX_TARGET_VERSION_BYTES: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UpgradeContractError {
    #[error("artifact SHA-256 must be canonical lowercase 64-hex")]
    InvalidHash,
    #[error("target version is empty, unsafe or too large")]
    InvalidVersion,
}

struct UpgradeTargetVersionSchema;

impl JsonSchema for UpgradeTargetVersionSchema {
    fn is_referenceable() -> bool {
        false
    }

    fn schema_name() -> String {
        "UpgradeTargetVersion".into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        let forbidden_dot_segments = SchemaObject {
            enum_values: Some(vec![
                serde_json::Value::String(".".into()),
                serde_json::Value::String("..".into()),
            ]),
            ..Default::default()
        };
        SchemaObject {
            instance_type: Some(InstanceType::String.into()),
            string: Some(Box::new(StringValidation {
                min_length: Some(1),
                max_length: Some(MAX_TARGET_VERSION_BYTES as u32),
                pattern: Some("^[A-Za-z0-9._+-]+$".into()),
            })),
            subschemas: Some(Box::new(SubschemaValidation {
                not: Some(Box::new(forbidden_dot_segments.into())),
                ..Default::default()
            })),
            ..Default::default()
        }
        .into()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ArtifactSha256(String);

impl ArtifactSha256 {
    pub fn new(value: impl Into<String>) -> Result<Self, UpgradeContractError> {
        let value = value.into();
        if value.len() != ARTIFACT_SHA256_HEX_BYTES
            || !value
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        {
            return Err(UpgradeContractError::InvalidHash);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Serialize for ArtifactSha256 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ArtifactSha256 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for ArtifactSha256 {
    fn is_referenceable() -> bool {
        false
    }

    fn schema_name() -> String {
        "ArtifactSha256".into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        SchemaObject {
            instance_type: Some(InstanceType::String.into()),
            string: Some(Box::new(StringValidation {
                min_length: Some(ARTIFACT_SHA256_HEX_BYTES as u32),
                max_length: Some(ARTIFACT_SHA256_HEX_BYTES as u32),
                pattern: Some("^[0-9a-f]{64}$".into()),
            })),
            ..Default::default()
        }
        .into()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StageUpgradeRequest {
    #[schemars(with = "UpgradeTargetVersionSchema")]
    target_version: String,
    candidate_sha256: ArtifactSha256,
    idempotency_key: IdempotencyKey,
    scope: LocalOnlyAdministration,
}

impl StageUpgradeRequest {
    pub fn new(
        target_version: String,
        candidate_sha256: ArtifactSha256,
        idempotency_key: IdempotencyKey,
        scope: LocalOnlyAdministration,
    ) -> Result<Self, UpgradeContractError> {
        validate_target_version(&target_version)?;
        Ok(Self {
            target_version,
            candidate_sha256,
            idempotency_key,
            scope,
        })
    }

    #[must_use]
    pub const fn is_local_only(&self) -> bool {
        matches!(self.scope, LocalOnlyAdministration::LocalOnly)
    }

    #[must_use]
    pub fn target_version(&self) -> &str {
        &self.target_version
    }

    #[must_use]
    pub const fn candidate_sha256(&self) -> &ArtifactSha256 {
        &self.candidate_sha256
    }

    #[must_use]
    pub const fn idempotency_key(&self) -> &IdempotencyKey {
        &self.idempotency_key
    }
}

impl<'de> Deserialize<'de> for StageUpgradeRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            target_version: String,
            candidate_sha256: ArtifactSha256,
            idempotency_key: IdempotencyKey,
            scope: LocalOnlyAdministration,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(
            wire.target_version,
            wire.candidate_sha256,
            wire.idempotency_key,
            wire.scope,
        )
        .map_err(serde::de::Error::custom)
    }
}

fn validate_target_version(value: &str) -> Result<(), UpgradeContractError> {
    if value.is_empty()
        || matches!(value, "." | "..")
        || value.len() > MAX_TARGET_VERSION_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-'))
    {
        return Err(UpgradeContractError::InvalidVersion);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
#[serde(tag = "status", rename_all = "camelCase", deny_unknown_fields)]
pub enum StageUpgradeReceipt {
    Staged {
        #[serde(rename = "targetVersion", serialize_with = "serialize_target_version")]
        #[schemars(rename = "targetVersion", with = "UpgradeTargetVersionSchema")]
        target_version: String,
    },
    AwaitingIdle {
        #[serde(rename = "targetVersion", serialize_with = "serialize_target_version")]
        #[schemars(rename = "targetVersion", with = "UpgradeTargetVersionSchema")]
        target_version: String,
        #[serde(
            rename = "activeTurns",
            serialize_with = "serialize_nonzero_active_turns"
        )]
        #[schemars(rename = "activeTurns", range(min = 1))]
        active_turns: u32,
    },
    Replayed {
        #[serde(rename = "targetVersion", serialize_with = "serialize_target_version")]
        #[schemars(rename = "targetVersion", with = "UpgradeTargetVersionSchema")]
        target_version: String,
    },
    Failed {
        failure: RuntimeFailure,
    },
}

impl<'de> Deserialize<'de> for StageUpgradeReceipt {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(
            tag = "status",
            rename_all = "camelCase",
            rename_all_fields = "camelCase",
            deny_unknown_fields
        )]
        enum Wire {
            Staged {
                target_version: String,
            },
            AwaitingIdle {
                target_version: String,
                active_turns: u32,
            },
            Replayed {
                target_version: String,
            },
            Failed {
                failure: RuntimeFailure,
            },
        }

        Ok(match Wire::deserialize(deserializer)? {
            Wire::Staged { target_version } => {
                validate_target_version(&target_version).map_err(serde::de::Error::custom)?;
                Self::Staged { target_version }
            }
            Wire::AwaitingIdle {
                target_version,
                active_turns,
            } => {
                validate_target_version(&target_version).map_err(serde::de::Error::custom)?;
                if active_turns == 0 {
                    return Err(serde::de::Error::custom(
                        "awaiting-idle receipt requires at least one active turn",
                    ));
                }
                Self::AwaitingIdle {
                    target_version,
                    active_turns,
                }
            }
            Wire::Replayed { target_version } => {
                validate_target_version(&target_version).map_err(serde::de::Error::custom)?;
                Self::Replayed { target_version }
            }
            Wire::Failed { failure } => Self::Failed { failure },
        })
    }
}

fn serialize_target_version<S>(value: &String, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    validate_target_version(value).map_err(serde::ser::Error::custom)?;
    value.serialize(serializer)
}

fn serialize_nonzero_active_turns<S>(value: &u32, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    if *value == 0 {
        return Err(serde::ser::Error::custom(
            "awaiting-idle receipt requires at least one active turn",
        ));
    }
    value.serialize(serializer)
}
