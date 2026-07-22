//! managed conversation 与远程 ConversationDEK 的同事务 activation。
//!
//! conversation catalog row、publication mapping、ADGK2 revision、authorization
//! revision 与 `ActivateConversation` transition 必须由同一个 `BEGIN IMMEDIATE`
//! 提交。publisher 只消费这里建立的 authenticated mapping，不能临时补 route/key。

use agentdeck_crypto::sha256;
use agentdeck_protocol::relay_v2::StreamRouteId;
use rusqlite::{Connection, Transaction, params};
use zeroize::Zeroizing;

use crate::runtime::model::RuntimeStoreError;
use crate::security::SecretBytes;

use super::cipher::{CipherError, RuntimeKeyBundle};
use super::identity::RuntimeId;
use super::key_transition::{
    BeginKeyTransition, KeyTransitionOperation, KeyTransitionRecipient, KeyTransitionTarget,
};
use super::pairing_authorization::{
    AuthenticatedAuthorization, AuthorizationLifecycle, authorization_token, load_authorizations,
};
use super::pairing_grant::{
    AuthenticatedGlobalKeyState, GLOBAL_KEY_COLUMN, GLOBAL_KEY_TABLE, MAX_GLOBAL_KEY_STATE_BYTES,
    global_key_token, load_global_key_state, seal_row,
};
use super::publication::{PublicationScope, PublicationStreamRecord, PublicationStreamState};
use super::sqlite::RuntimeLedger;

const CONVERSATION_KEY_ENTROPY_ATTEMPTS: usize = 16;

/// 第一笔 DML 前认证并占住唯一 transition slot；若尚未建立全局 key state，
/// conversation 仍只建立 dormant publication mapping，首次 grant 会原子 bootstrap。
pub(super) struct ConversationActivationPreflight {
    global: Option<AuthenticatedGlobalKeyState>,
    authorizations: Vec<AuthenticatedAuthorization>,
}

pub(super) struct ConversationActivationStage<'a> {
    conversation_id: RuntimeId,
    publication: &'a PublicationStreamRecord,
    now_ms: u64,
}

impl<'a> ConversationActivationStage<'a> {
    pub(super) fn new(
        conversation_id: RuntimeId,
        publication: &'a PublicationStreamRecord,
        now_ms: u64,
    ) -> Self {
        Self {
            conversation_id,
            publication,
            now_ms,
        }
    }
}

impl ConversationActivationPreflight {
    pub(super) fn load(
        transaction: &Transaction<'_>,
        key_bundle: &RuntimeKeyBundle,
        database_id: [u8; 16],
        ledger: &RuntimeLedger,
    ) -> Result<Self, RuntimeStoreError> {
        let global = load_global_key_state(transaction, key_bundle, database_id)?;
        let authorizations = if let Some(global) = &global {
            if ledger.remote_key_directory_count != 1
                || ledger.remote_key_directory_sealed_bytes != global.sealed_bytes
            {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            super::key_transition::ensure_key_transition_slot_available(
                transaction,
                key_bundle,
                database_id,
                ledger,
            )?;
            load_authorizations(transaction, key_bundle, database_id)?
        } else {
            if ledger.remote_key_directory_count != 0
                || ledger.remote_key_directory_sealed_bytes != 0
            {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            Vec::new()
        };
        Ok(Self {
            global,
            authorizations,
        })
    }

    /// 返回 `true` 表示事务同时建立了必须由唯一 transition owner 推进的 durable
    /// activation。所有写入仍由外层 CreateConversation 一次更新 ledger/COMMIT。
    pub(super) fn stage(
        self,
        transaction: &Transaction<'_>,
        key_bundle: &RuntimeKeyBundle,
        database_id: [u8; 16],
        next_ledger: &mut RuntimeLedger,
        stage: ConversationActivationStage<'_>,
    ) -> Result<bool, RuntimeStoreError> {
        let ConversationActivationStage {
            conversation_id,
            publication,
            now_ms,
        } = stage;
        let Some(previous) = self.global else {
            return Ok(false);
        };
        if publication.scope != PublicationScope::Conversation(conversation_id)
            || publication.state != PublicationStreamState::Active
            || publication.stream_route == [0; 16]
            || publication.counter_scope_token.is_some()
            || publication.sender_counter_high_water.is_some()
        {
            return Err(RuntimeStoreError::PublicationMismatch);
        }

        let from_revision = previous.revision;
        let to_revision = from_revision
            .checked_add(1)
            .ok_or(RuntimeStoreError::PublicationCounterExhausted)?;
        let recipients = current_recipients(&self.authorizations, from_revision)?;
        let stream_route = StreamRouteId::from_bytes(publication.stream_route);
        let next_global = previous
            .state
            .activate_conversation(stream_route, fresh_conversation_key()?)?;
        if next_global.revision().value() != to_revision
            || !next_global
                .active_conversation_routes()
                .contains(&stream_route)
        {
            return Err(RuntimeStoreError::PublicationMismatch);
        }
        let canonical = next_global.canonical_bytes()?;
        let directory_hash = sha256(canonical.as_slice());
        let sealed = seal_row(
            key_bundle,
            database_id,
            GLOBAL_KEY_TABLE,
            b"1",
            GLOBAL_KEY_COLUMN,
            canonical.as_slice(),
            MAX_GLOBAL_KEY_STATE_BYTES,
        )?;
        let metadata_token = global_key_token(
            key_bundle,
            database_id,
            to_revision,
            directory_hash,
            &sealed,
        )?;
        replace_global_key_bytes(next_ledger, previous.sealed_bytes, sealed.len())?;

        // transition 必须在任何 global revision DML 之前完成验证并进入同一 ledger。
        super::key_transition::stage_key_transition_in_transaction(
            transaction,
            key_bundle,
            database_id,
            next_ledger,
            BeginKeyTransition {
                operation_id: publication.publication_stream_id,
                operation: KeyTransitionOperation::ActivateConversation,
                target: KeyTransitionTarget::Conversation {
                    conversation_id: *conversation_id.as_bytes(),
                    stream_route: publication.stream_route,
                },
                from_revision,
                to_revision,
                recipients,
                replay_retirement: None,
                created_at_ms: now_ms,
            },
        )?;
        align_current_authorizations(
            transaction,
            key_bundle,
            database_id,
            &self.authorizations,
            from_revision,
            to_revision,
        )?;
        if transaction.execute(
            "UPDATE remote_key_directory
             SET revision = ?1, directory_hash = ?2, sealed_directory = ?3,
                 sealed_directory_bytes = ?4, metadata_token = ?5
             WHERE singleton = 1 AND revision = ?6 AND directory_hash = ?7
               AND metadata_token = ?8",
            params![
                super::sequence::encode_sequence(to_revision),
                &directory_hash[..],
                &sealed,
                i64::try_from(sealed.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
                &metadata_token[..],
                super::sequence::encode_sequence(from_revision),
                &previous.directory_hash[..],
                &previous.metadata_token[..],
            ],
        )? != 1
        {
            return Err(RuntimeStoreError::PairingConflict);
        }
        Ok(true)
    }
}

/// idempotent Start 在 COMMIT-unknown/restart 后只读认证 exact route/key/transition。
pub(super) fn replay_activation_pending(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    conversation_id: RuntimeId,
    publication: &PublicationStreamRecord,
) -> Result<bool, RuntimeStoreError> {
    if publication.scope != PublicationScope::Conversation(conversation_id)
        || publication.state != PublicationStreamState::Active
        || publication.stream_route == [0; 16]
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let Some(global) = load_global_key_state(connection, key_bundle, database_id)? else {
        return Ok(false);
    };
    let route = StreamRouteId::from_bytes(publication.stream_route);
    if !global.state.active_conversation_routes().contains(&route) {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    match super::key_transition::ensure_no_active_transition_for_business(
        connection,
        key_bundle,
        database_id,
    ) {
        Ok(()) => Ok(false),
        Err(RuntimeStoreError::InvalidStateTransition) => Ok(true),
        Err(error) => Err(error),
    }
}

fn fresh_conversation_key() -> Result<SecretBytes, RuntimeStoreError> {
    for _ in 0..CONVERSATION_KEY_ENTROPY_ATTEMPTS {
        let mut key = Zeroizing::new([0_u8; 32]);
        getrandom::fill(key.as_mut()).map_err(|_| CipherError::EntropyUnavailable)?;
        if key.iter().any(|byte| *byte != 0) {
            return Ok(SecretBytes::new(key.as_slice().to_vec()));
        }
    }
    Err(CipherError::EntropyUnavailable.into())
}

pub(super) fn current_recipients(
    authorizations: &[AuthenticatedAuthorization],
    expected_revision: u64,
) -> Result<Vec<KeyTransitionRecipient>, RuntimeStoreError> {
    let mut recipients = authorizations
        .iter()
        .filter(|authorization| {
            matches!(
                authorization.lifecycle,
                AuthorizationLifecycle::GrantPreparing | AuthorizationLifecycle::Active
            )
        })
        .map(|authorization| {
            if authorization.key_directory_revision != expected_revision
                || authorization.revocation_hash.is_some()
                || authorization.sealed_revocation_bytes.is_some()
            {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            Ok(KeyTransitionRecipient {
                device_route: *authorization.device_route.as_bytes(),
                grant_serial: authorization.grant_serial.value(),
            })
        })
        .collect::<Result<Vec<_>, RuntimeStoreError>>()?;
    recipients.sort_unstable();
    if recipients.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(recipients)
}

pub(super) fn align_current_authorizations(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    authorizations: &[AuthenticatedAuthorization],
    from_revision: u64,
    to_revision: u64,
) -> Result<(), RuntimeStoreError> {
    for authorization in authorizations.iter().filter(|authorization| {
        matches!(
            authorization.lifecycle,
            AuthorizationLifecycle::GrantPreparing | AuthorizationLifecycle::Active
        )
    }) {
        if authorization.key_directory_revision != from_revision
            || authorization.revocation_hash.is_some()
            || authorization.sealed_revocation_bytes.is_some()
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let lifecycle = authorization.lifecycle.as_str();
        let sealed: Vec<u8> = transaction.query_row(
            "SELECT sealed_authorization FROM remote_authorization_ledger
             WHERE device_route = ?1 AND grant_serial = ?2 AND lifecycle = ?3",
            params![
                authorization.device_route.as_bytes().as_slice(),
                super::sequence::encode_sequence(authorization.grant_serial.value()),
                lifecycle,
            ],
            |row| row.get(0),
        )?;
        if u64::try_from(sealed.len()).unwrap_or(u64::MAX) != authorization.sealed_bytes {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let token = authorization_token(
            key_bundle,
            database_id,
            authorization.device_route,
            authorization.grant_serial,
            authorization.lifecycle,
            authorization.device_sign_fingerprint,
            authorization.grant_hash,
            authorization.authorization_hash,
            to_revision,
            &sealed,
            authorization.created_at_ms,
            authorization.state_changed_at_ms,
        )?;
        if transaction.execute(
            "UPDATE remote_authorization_ledger
             SET key_directory_revision = ?1, metadata_token = ?2
             WHERE device_route = ?3 AND grant_serial = ?4 AND lifecycle = ?5
               AND key_directory_revision = ?6 AND metadata_token = ?7",
            params![
                super::sequence::encode_sequence(to_revision),
                &token[..],
                authorization.device_route.as_bytes().as_slice(),
                super::sequence::encode_sequence(authorization.grant_serial.value()),
                lifecycle,
                super::sequence::encode_sequence(from_revision),
                &authorization.metadata_token[..],
            ],
        )? != 1
        {
            return Err(RuntimeStoreError::PairingConflict);
        }
    }
    Ok(())
}

pub(super) fn replace_global_key_bytes(
    ledger: &mut RuntimeLedger,
    previous: u64,
    next: usize,
) -> Result<(), RuntimeStoreError> {
    let next = u64::try_from(next).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    ledger.remote_key_directory_sealed_bytes = ledger
        .remote_key_directory_sealed_bytes
        .checked_sub(previous)
        .and_then(|bytes| bytes.checked_add(next))
        .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
            field: "remote_key_directory_sealed_bytes",
        })?;
    if ledger.remote_key_directory_count != 1
        || ledger.remote_key_directory_sealed_bytes > MAX_GLOBAL_KEY_STATE_BYTES as u64
    {
        return Err(RuntimeStoreError::PairingLimit);
    }
    Ok(())
}
