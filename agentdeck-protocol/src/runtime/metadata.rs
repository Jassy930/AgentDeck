//! Runtime v2 canonical conversation metadata CAS contract。

use crate::runtime::failure::RuntimeFailure;
use crate::runtime::identity::{ConversationId, IdempotencyKey};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub const MAX_CONVERSATION_TITLE_BYTES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MetadataError {
    #[error("conversation title exceeds its UTF-8 bound or contains NUL")]
    InvalidTitle,
    #[error("applied metadata revision must be non-zero")]
    InvalidRevision,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum ConversationMetadataMutation {
    Rename {
        #[serde(serialize_with = "serialize_validated_optional_title")]
        #[schemars(with = "crate::runtime::schema::RequiredNullable<String>")]
        title: Option<String>,
    },
    SetArchived {
        archived: bool,
    },
}

impl ConversationMetadataMutation {
    pub fn rename(title: Option<String>) -> Result<Self, MetadataError> {
        validate_optional_title(&title)?;
        Ok(Self::Rename { title })
    }
}

fn validate_optional_title(title: &Option<String>) -> Result<(), MetadataError> {
    if let Some(title) = title
        && (title.len() > MAX_CONVERSATION_TITLE_BYTES || title.as_bytes().contains(&0))
    {
        return Err(MetadataError::InvalidTitle);
    }
    Ok(())
}

fn serialize_validated_optional_title<S>(
    title: &Option<String>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    validate_optional_title(title).map_err(serde::ser::Error::custom)?;
    title.serialize(serializer)
}

impl<'de> Deserialize<'de> for ConversationMetadataMutation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
        enum Wire {
            Rename {
                #[serde(deserialize_with = "deserialize_required_optional_title")]
                title: Option<String>,
            },
            SetArchived {
                archived: bool,
            },
        }
        match Wire::deserialize(deserializer)? {
            Wire::Rename { title } => Self::rename(title).map_err(serde::de::Error::custom),
            Wire::SetArchived { archived } => Ok(Self::SetArchived { archived }),
        }
    }
}

fn deserialize_required_optional_title<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConversationMetadataMutationRequest {
    pub conversation_id: ConversationId,
    pub idempotency_key: IdempotencyKey,
    pub expected_entry_revision: u64,
    pub mutation: ConversationMetadataMutation,
}

impl ConversationMetadataMutationRequest {
    pub fn new(
        conversation_id: ConversationId,
        idempotency_key: IdempotencyKey,
        expected_entry_revision: u64,
        mutation: ConversationMetadataMutation,
    ) -> Result<Self, MetadataError> {
        if let ConversationMetadataMutation::Rename { title } = &mutation {
            let _ = ConversationMetadataMutation::rename(title.clone())?;
        }
        Ok(Self {
            conversation_id,
            idempotency_key,
            expected_entry_revision,
            mutation,
        })
    }
}

impl<'de> Deserialize<'de> for ConversationMetadataMutationRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            conversation_id: ConversationId,
            idempotency_key: IdempotencyKey,
            expected_entry_revision: u64,
            mutation: ConversationMetadataMutation,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(
            wire.conversation_id,
            wire.idempotency_key,
            wire.expected_entry_revision,
            wire.mutation,
        )
        .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
#[serde(tag = "status", rename_all = "camelCase", deny_unknown_fields)]
pub enum ConversationMetadataReceipt {
    Applied {
        #[serde(rename = "conversationId")]
        #[schemars(rename = "conversationId")]
        conversation_id: ConversationId,
        #[serde(
            rename = "entryRevision",
            serialize_with = "serialize_nonzero_revision"
        )]
        #[schemars(rename = "entryRevision", range(min = 1))]
        entry_revision: u64,
    },
    Replayed {
        #[serde(rename = "conversationId")]
        #[schemars(rename = "conversationId")]
        conversation_id: ConversationId,
        #[serde(
            rename = "entryRevision",
            serialize_with = "serialize_nonzero_revision"
        )]
        #[schemars(rename = "entryRevision", range(min = 1))]
        entry_revision: u64,
    },
    Conflict {
        #[serde(rename = "conversationId")]
        #[schemars(rename = "conversationId")]
        conversation_id: ConversationId,
        #[serde(rename = "currentEntryRevision")]
        #[schemars(rename = "currentEntryRevision")]
        current_entry_revision: u64,
    },
    Failed {
        failure: RuntimeFailure,
    },
}

impl<'de> Deserialize<'de> for ConversationMetadataReceipt {
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
            Applied {
                conversation_id: ConversationId,
                entry_revision: u64,
            },
            Replayed {
                conversation_id: ConversationId,
                entry_revision: u64,
            },
            Conflict {
                conversation_id: ConversationId,
                current_entry_revision: u64,
            },
            Failed {
                failure: RuntimeFailure,
            },
        }
        Ok(match Wire::deserialize(deserializer)? {
            Wire::Applied {
                conversation_id,
                entry_revision,
            } if entry_revision > 0 => Self::Applied {
                conversation_id,
                entry_revision,
            },
            Wire::Replayed {
                conversation_id,
                entry_revision,
            } if entry_revision > 0 => Self::Replayed {
                conversation_id,
                entry_revision,
            },
            Wire::Conflict {
                conversation_id,
                current_entry_revision,
            } => Self::Conflict {
                conversation_id,
                current_entry_revision,
            },
            Wire::Failed { failure } => Self::Failed { failure },
            _ => return Err(serde::de::Error::custom(MetadataError::InvalidRevision)),
        })
    }
}

fn serialize_nonzero_revision<S>(revision: &u64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    if *revision == 0 {
        return Err(serde::ser::Error::custom(MetadataError::InvalidRevision));
    }
    revision.serialize(serializer)
}
