//! Claude Code cross-agent history layer (N8 守护：CC 原生接口为唯一权威事实源).
//!
//! Phase 4 Task 4B. **No AgentDeck-side history metadata layer** — list /
//! read / archive / rename all go through CC's native artefacts
//! (`~/.claude/projects/<encoded_cwd>/*.jsonl`, `claude rm`,
//! `claude --resume --name`). P3.3 的 `claude_code_adapter_state` 只是一份
//! StorageKEK 保护的 resume 派生索引，不保存本文件负责的任何历史元数据；没有
//! `cc-meta/` 目录，本文件也不会创建它。
//!
//! ## Wire-shape findings vs spec § 5.6
//!
//! The spec assumed `claude agents --json` was the catalogue of "all
//! CC sessions for a cwd"; reality is that it's the **background /
//! interactive agent view** (only sessions tracked by `agents start`
//! or currently-running interactive REPLs). The full session
//! catalogue (which the user actually needs in a cross-agent history
//! sidebar) lives in:
//!
//!   `~/.claude/projects/<encoded_cwd>/<session_uuid>.jsonl`
//!
//! where `<encoded_cwd>` is `/`→`-` (and `.`→`-`) with leading
//! separators preserved by the same substitution (so
//! `/Users/jassy/foo` → `-Users-jassy-foo`).
//!
//! `claude rm <id>` is **background-agent-only**. For regular `--print`
//! sessions there is no native "archive" command — we fall back to
//! a structured error so the UI tells the user to delete the jsonl
//! file manually (and so we don't silently lose state).
//!
//! Rename: `claude --print --resume <id> -n <name>
//! --output-format stream-json --input-format stream-json < /dev/null`
//! writes a `{"type":"custom-title", "customTitle":"<name>", ...}`
//! line into the jsonl tail; subsequent list scans pick it up as
//! `HistoryListItem::title`. Verified live against `claude 2.1.191`.

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use agentdeck_protocol::runtime::ConversationConfiguration;
use agentdeck_protocol::{
    AgentItem, AgentItemMeta, AgentKind, DiffFile, DiffStatus, HistoryListItem,
    HistoryReadResponse, HistoryTurn, ProtocolError, ShellStatus, ThreadId,
    effective_history_list_limit,
};
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

use crate::agent::{
    CanonicalNativeHistoryItem, CanonicalNativeHistoryRead, CompletedNativeProjectionScan,
    DynNativeProjectionScan, NATIVE_PROJECTION_ROUND_BYTE_LIMIT,
    NATIVE_PROJECTION_ROUND_CANDIDATE_LIMIT, NATIVE_PROJECTION_ROUND_IMPORT_LIMIT,
    NATIVE_PROJECTION_ROUND_TIME_LIMIT, NativeItemKey, NativeProjectionAcknowledgement,
    NativeProjectionCandidate, NativeProjectionScan, NativeProjectionScanIssuer,
    NativeProjectionSourceError, NativeProjectionStep, NativeProjectionYieldReason, NativeTurnKey,
};
use crate::claude_code::state::{ClaudeCodeStateRepository, ResolvedClaudeCodeReference};
use crate::runtime::store::{ConversationDescriptor, RuntimeId, RuntimeStoreError};
use crate::security::SecretBytes;

mod native;
#[cfg(test)]
mod native_tests;

pub(in crate::claude_code) use native::{NativeTranscriptRefV1, safe_legacy_session_id};

use native::{
    NativeHistoryCandidate, NativeHistoryError, NativeHistoryScanner, NativeHistorySource,
    NativeIoBudget, NativeParseLimits, NativeReadOutcome, NativeScanStep, NativeScanStop,
};

/// 只由本模块在本机 CC projects root 中读回实体 JSONL 后签发的 opaque entry。
/// Debug 不输出 native session id/path，客户端 wire 也无法构造。
pub(super) struct VerifiedNativeHistoryEntry {
    reference: NativeTranscriptRefV1,
}

/// Bounded/no-follow read 证明的 private metadata target。
#[allow(dead_code, reason = "后续 coordinator 接线")]
pub(super) struct VerifiedNativeMetadata {
    resume_thread_id: ThreadId,
    cwd: PathBuf,
    custom_title: Option<String>,
}

#[allow(dead_code, reason = "后续 coordinator 接线")]
impl VerifiedNativeMetadata {
    pub(super) fn into_parts(self) -> (ThreadId, PathBuf, Option<String>) {
        (self.resume_thread_id, self.cwd, self.custom_title)
    }
}

impl std::fmt::Debug for VerifiedNativeMetadata {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("VerifiedNativeMetadata([REDACTED])")
    }
}

#[derive(Clone, Copy)]
struct NativeProjectionRoundLimits {
    candidate_limit: u32,
    import_limit: u32,
    byte_limit: u64,
    time_limit: Duration,
}

impl NativeProjectionRoundLimits {
    const PRODUCTION: Self = Self {
        candidate_limit: NATIVE_PROJECTION_ROUND_CANDIDATE_LIMIT,
        import_limit: NATIVE_PROJECTION_ROUND_IMPORT_LIMIT,
        byte_limit: NATIVE_PROJECTION_ROUND_BYTE_LIMIT,
        time_limit: NATIVE_PROJECTION_ROUND_TIME_LIMIT,
    };

    fn budget(self) -> NativeIoBudget {
        NativeIoBudget::new(
            self.candidate_limit,
            self.byte_limit,
            Instant::now() + self.time_limit,
        )
    }
}

#[allow(
    dead_code,
    reason = "C-f Core projector lifecycle drives the registered source"
)]
struct PendingNativeProjectionCandidate {
    native: NativeHistoryCandidate,
    descriptor: ConversationDescriptor,
    acknowledgement_token: [u8; 16],
}

#[allow(
    dead_code,
    reason = "C-f Core projector lifecycle drives the registered source"
)]
impl PendingNativeProjectionCandidate {
    fn delivery(
        &self,
        issuer: &NativeProjectionScanIssuer,
        default_configuration: &ConversationConfiguration,
    ) -> Result<NativeProjectionCandidate, NativeProjectionSourceError> {
        issuer.issue_candidate(
            self.descriptor.clone(),
            default_configuration.clone(),
            SecretBytes::new(self.native.reference().encode()),
            self.acknowledgement_token,
        )
    }
}

/// Claude Code 私域 scanner 到 vendor-neutral projector seam 的有界 bridge。
///
/// 每个 filesystem candidate 先在同一 round budget 内重新 open/read/parse 并完成
/// canonical cwd/title 校验；只有随后构造的 neutral candidate 能跨入 Runtime。
/// pending candidate 会 exact replay，直到 Runtime 按值归还 ACK。
#[allow(
    dead_code,
    reason = "C-f Core projector lifecycle drives the registered source"
)]
struct ClaudeCodeNativeProjectionScan {
    source: NativeHistorySource,
    scanner: NativeHistoryScanner,
    issuer: NativeProjectionScanIssuer,
    default_configuration: ConversationConfiguration,
    limits: NativeProjectionRoundLimits,
    budget: NativeIoBudget,
    pending: Option<PendingNativeProjectionCandidate>,
    imports_in_round: u32,
    inspected_candidates: u64,
    imported_candidates: u64,
    incomplete_generation: bool,
    paused: Option<NativeProjectionYieldReason>,
    exhausted: bool,
    failed: bool,
}

#[allow(
    dead_code,
    reason = "C-f Core projector lifecycle drives the registered source"
)]
impl ClaudeCodeNativeProjectionScan {
    fn new(
        source: NativeHistorySource,
        issuer: NativeProjectionScanIssuer,
        default_configuration: ConversationConfiguration,
        limits: NativeProjectionRoundLimits,
    ) -> Result<Self, NativeProjectionSourceError> {
        if limits.candidate_limit == 0
            || limits.import_limit == 0
            || limits.byte_limit == 0
            || limits.time_limit.is_zero()
        {
            return Err(NativeProjectionSourceError::InvalidSource);
        }
        let scanner = source
            .scanner(issuer.generation())
            .map_err(classify_native_projection_source_error)?;
        Ok(Self {
            source,
            scanner,
            issuer,
            default_configuration,
            limits,
            budget: limits.budget(),
            pending: None,
            imports_in_round: 0,
            inspected_candidates: 0,
            imported_candidates: 0,
            incomplete_generation: false,
            paused: None,
            exhausted: false,
            failed: false,
        })
    }

    fn pause(&mut self, reason: NativeProjectionYieldReason) -> NativeProjectionStep {
        self.paused = Some(reason);
        NativeProjectionStep::Yielded(reason)
    }

    fn fail(
        &mut self,
        error: NativeProjectionSourceError,
    ) -> Result<NativeProjectionStep, NativeProjectionSourceError> {
        self.failed = true;
        Err(error)
    }

    fn acknowledge_filtered(
        &mut self,
        native: NativeHistoryCandidate,
    ) -> Result<(), NativeProjectionSourceError> {
        if let Err(error) = self.scanner.acknowledge(native) {
            self.failed = true;
            return Err(classify_native_projection_source_error(error));
        }
        let Some(inspected_candidates) = self.inspected_candidates.checked_add(1) else {
            self.failed = true;
            return Err(NativeProjectionSourceError::PayloadTooLarge);
        };
        self.inspected_candidates = inspected_candidates;
        Ok(())
    }

    /// 单个 transcript 内容无效时仍推进 opaque scanner continuation，让同一轮后续
    /// valid candidate 可以 import；但整代永久标成 incomplete，EOF 不能签发
    /// completed witness，因此 invalid 绝不会被静默解释成 absent/Removed。
    fn reject_invalid_candidate(
        &mut self,
        native: NativeHistoryCandidate,
    ) -> Result<(), NativeProjectionSourceError> {
        self.acknowledge_filtered(native)?;
        self.incomplete_generation = true;
        Ok(())
    }

    fn next_unfailed(&mut self) -> Result<NativeProjectionStep, NativeProjectionSourceError> {
        if let Some(reason) = self.paused {
            return Ok(NativeProjectionStep::Yielded(reason));
        }
        if self.exhausted {
            return Ok(NativeProjectionStep::Complete);
        }
        if let Some(pending) = self.pending.as_ref() {
            return pending
                .delivery(&self.issuer, &self.default_configuration)
                .map(Box::new)
                .map(NativeProjectionStep::Candidate);
        }
        if self.imports_in_round >= self.limits.import_limit {
            return Ok(self.pause(NativeProjectionYieldReason::ImportLimit));
        }

        loop {
            let native = match self.scanner.next(&mut self.budget) {
                Ok(NativeScanStep::Candidate(candidate)) => candidate,
                Ok(NativeScanStep::Yielded(NativeScanStop::CandidateLimit)) => {
                    return Ok(self.pause(NativeProjectionYieldReason::CandidateLimit));
                }
                Ok(NativeScanStep::Yielded(NativeScanStop::Deadline)) => {
                    return Ok(self.pause(NativeProjectionYieldReason::Deadline));
                }
                Ok(NativeScanStep::Complete) => {
                    self.exhausted = true;
                    return Ok(NativeProjectionStep::Complete);
                }
                Err(error) => {
                    let error = classify_native_projection_source_error(error);
                    return self.fail(error);
                }
            };

            if native.size_bytes > self.limits.byte_limit {
                self.reject_invalid_candidate(native)?;
                continue;
            }
            let document = match self.source.read(
                native.reference(),
                &mut self.budget,
                NativeParseLimits::default(),
            ) {
                Ok(NativeReadOutcome::FilteredObserver) => {
                    self.acknowledge_filtered(native)?;
                    continue;
                }
                Ok(NativeReadOutcome::Document(document)) => document,
                Err(NativeHistoryError::ByteBudget) => {
                    return Ok(self.pause(NativeProjectionYieldReason::ByteLimit));
                }
                Err(NativeHistoryError::TimeBudget) => {
                    return Ok(self.pause(NativeProjectionYieldReason::Deadline));
                }
                Err(error) if invalid_native_candidate(&error) => {
                    self.reject_invalid_candidate(native)?;
                    continue;
                }
                Err(error) => {
                    let error = classify_native_projection_source_error(error);
                    return self.fail(error);
                }
            };
            if document.modeled_item_count() == 0 {
                self.acknowledge_filtered(native)?;
                continue;
            }
            let (cwd, title) = match document.into_metadata() {
                Ok(metadata) => metadata,
                Err(error) if invalid_native_candidate(&error) => {
                    self.reject_invalid_candidate(native)?;
                    continue;
                }
                Err(error) => {
                    let error = classify_native_projection_source_error(error);
                    return self.fail(error);
                }
            };
            let mut acknowledgement_token = *Uuid::new_v4().as_bytes();
            if acknowledgement_token == [0; 16] {
                acknowledgement_token[0] = 1;
            }
            self.pending = Some(PendingNativeProjectionCandidate {
                native,
                descriptor: ConversationDescriptor {
                    agent_kind: AgentKind::ClaudeCode,
                    title,
                    cwd,
                },
                acknowledgement_token,
            });
            return self
                .pending
                .as_ref()
                .expect("verified native candidate remains pending")
                .delivery(&self.issuer, &self.default_configuration)
                .map(Box::new)
                .map(NativeProjectionStep::Candidate);
        }
    }

    fn acknowledge_pending(
        &mut self,
        acknowledgement: NativeProjectionAcknowledgement,
    ) -> Result<(), NativeProjectionSourceError> {
        if self.failed || self.paused.is_some() || self.exhausted {
            return Err(NativeProjectionSourceError::InvalidState);
        }
        let Some(pending) = self.pending.take() else {
            return Err(NativeProjectionSourceError::InvalidAcknowledgement);
        };
        if !self
            .issuer
            .matches_acknowledgement(&acknowledgement, &pending.acknowledgement_token)
        {
            self.pending = Some(pending);
            return Err(NativeProjectionSourceError::InvalidAcknowledgement);
        }
        if let Err(error) = self.scanner.acknowledge(pending.native) {
            self.failed = true;
            return Err(classify_native_projection_source_error(error));
        }
        let next_counts = self
            .imports_in_round
            .checked_add(1)
            .zip(self.inspected_candidates.checked_add(1))
            .zip(self.imported_candidates.checked_add(1));
        let Some(((imports_in_round, inspected_candidates), imported_candidates)) = next_counts
        else {
            self.failed = true;
            return Err(NativeProjectionSourceError::PayloadTooLarge);
        };
        self.imports_in_round = imports_in_round;
        self.inspected_candidates = inspected_candidates;
        self.imported_candidates = imported_candidates;
        Ok(())
    }
}

impl NativeProjectionScan for ClaudeCodeNativeProjectionScan {
    fn next(&mut self) -> Result<NativeProjectionStep, NativeProjectionSourceError> {
        if self.failed {
            return Err(NativeProjectionSourceError::InvalidState);
        }
        self.next_unfailed()
    }

    fn acknowledge(
        &mut self,
        acknowledgement: NativeProjectionAcknowledgement,
    ) -> Result<(), NativeProjectionSourceError> {
        self.acknowledge_pending(acknowledgement)
    }

    fn resume_after_yield(&mut self) -> Result<(), NativeProjectionSourceError> {
        if self.failed || self.exhausted || self.pending.is_some() || self.paused.take().is_none() {
            return Err(NativeProjectionSourceError::InvalidState);
        }
        self.budget = self.limits.budget();
        self.imports_in_round = 0;
        Ok(())
    }

    fn into_completed(
        self: Box<Self>,
    ) -> Result<CompletedNativeProjectionScan, NativeProjectionSourceError> {
        if self.failed
            || !self.exhausted
            || self.incomplete_generation
            || self.paused.is_some()
            || self.pending.is_some()
        {
            return Err(NativeProjectionSourceError::ScanIncomplete);
        }
        let native = self
            .scanner
            .into_completed_scan()
            .map_err(|_| NativeProjectionSourceError::ScanIncomplete)?;
        let generation = self.issuer.generation();
        let (native_generation, native_acknowledged_candidates) = native.into_parts();
        if native_generation != generation
            || native_acknowledged_candidates != self.inspected_candidates
        {
            return Err(NativeProjectionSourceError::ScanIncomplete);
        }
        self.issuer.complete(
            generation,
            self.inspected_candidates,
            self.imported_candidates,
        )
    }
}

fn invalid_native_candidate(error: &NativeHistoryError) -> bool {
    matches!(
        error,
        NativeHistoryError::LineTooLarge { .. }
            | NativeHistoryError::RecordLimit
            | NativeHistoryError::RetainedBudget
            | NativeHistoryError::Malformed { .. }
            | NativeHistoryError::InvalidKey { .. }
            | NativeHistoryError::DuplicateKey { .. }
            | NativeHistoryError::MetadataInvalid { .. }
            | NativeHistoryError::MetadataAmbiguous { .. }
            | NativeHistoryError::MissingParent { .. }
    )
}

impl std::fmt::Debug for ClaudeCodeNativeProjectionScan {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ClaudeCodeNativeProjectionScan([REDACTED])")
    }
}

pub(super) fn begin_native_projection_scan(
    default_configuration: ConversationConfiguration,
    issuer: NativeProjectionScanIssuer,
) -> Result<DynNativeProjectionScan, NativeProjectionSourceError> {
    let source = NativeHistorySource::for_current_account()
        .map_err(classify_native_projection_source_error)?;
    ClaudeCodeNativeProjectionScan::new(
        source,
        issuer,
        default_configuration,
        NativeProjectionRoundLimits::PRODUCTION,
    )
    .map(|scan| Box::new(scan) as DynNativeProjectionScan)
}

#[cfg(test)]
fn begin_native_projection_scan_for_test(
    source: NativeHistorySource,
    default_configuration: ConversationConfiguration,
    generation: [u8; 16],
    candidate_limit: u32,
    import_limit: u32,
    byte_limit: u64,
    time_limit: Duration,
) -> Result<DynNativeProjectionScan, NativeProjectionSourceError> {
    let issuer = crate::agent::native_projection_scan_issuer_for_test(generation)?;
    ClaudeCodeNativeProjectionScan::new(
        source,
        issuer,
        default_configuration,
        NativeProjectionRoundLimits {
            candidate_limit,
            import_limit,
            byte_limit,
            time_limit,
        },
    )
    .map(|scan| Box::new(scan) as DynNativeProjectionScan)
}

fn classify_native_projection_source_error(
    error: NativeHistoryError,
) -> NativeProjectionSourceError {
    match error {
        NativeHistoryError::InvalidScanGeneration => NativeProjectionSourceError::InvalidGeneration,
        NativeHistoryError::LineTooLarge { .. }
        | NativeHistoryError::RecordLimit
        | NativeHistoryError::RetainedBudget
        | NativeHistoryError::ByteBudget => NativeProjectionSourceError::PayloadTooLarge,
        NativeHistoryError::SourceUnavailable { .. } => NativeProjectionSourceError::Unavailable,
        NativeHistoryError::HomeUnavailable
        | NativeHistoryError::Io { .. }
        | NativeHistoryError::TimeBudget => NativeProjectionSourceError::ReadUnavailable,
        NativeHistoryError::InvalidCandidateAcknowledgement => {
            NativeProjectionSourceError::InvalidAcknowledgement
        }
        NativeHistoryError::ScanIncomplete => NativeProjectionSourceError::ScanIncomplete,
        NativeHistoryError::ScanFailed => NativeProjectionSourceError::InvalidState,
        NativeHistoryError::SourceUnsafe { .. }
        | NativeHistoryError::InvalidReference
        | NativeHistoryError::UnsupportedReferenceVersion
        | NativeHistoryError::Malformed { .. }
        | NativeHistoryError::InvalidKey { .. }
        | NativeHistoryError::DuplicateKey { .. }
        | NativeHistoryError::MetadataInvalid { .. }
        | NativeHistoryError::MetadataAmbiguous { .. }
        | NativeHistoryError::MissingParent { .. } => NativeProjectionSourceError::InvalidSource,
    }
}

impl VerifiedNativeHistoryEntry {
    #[cfg(test)]
    pub(super) fn into_thread_id(self) -> ThreadId {
        ThreadId(
            self.reference
                .resume_thread_id()
                .expect("verified native transcript filename has a safe session id"),
        )
    }

    pub(super) fn into_private_reference(self) -> NativeTranscriptRefV1 {
        self.reference
    }
}

impl std::fmt::Debug for VerifiedNativeHistoryEntry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("VerifiedNativeHistoryEntry([REDACTED])")
    }
}

/// Canonical Runtime history lookup：common 只给 neutral adapterStateKey，raw
/// CC session id 在本模块内解析后立即交给 native JSONL backend。
pub(super) async fn read_managed_history(
    repository: &ClaudeCodeStateRepository,
    adapter_state_key: RuntimeId,
) -> Result<HistoryReadResponse, ProtocolError> {
    let reference = resolve_managed_native_reference(repository, adapter_state_key).await?;
    read_native_history(reference).await
}

/// Native-projected Runtime conversation 的 key-bearing read。返回值只包含
/// vendor-neutral opaque key 与已建模 item，不携带 native reference/session/path。
pub(super) async fn read_native_projection_history(
    repository: &ClaudeCodeStateRepository,
    adapter_state_key: RuntimeId,
) -> Result<CanonicalNativeHistoryRead, ProtocolError> {
    let reference = resolve_native_projection_reference(repository, adapter_state_key).await?;
    read_keyed_native_history(reference).await
}

/// 每次从 vault exact v1 ref 重新认证并有界读取，不 decode/猜测 cwd/path。
#[allow(dead_code, reason = "后续 coordinator 接线")]
pub(super) async fn read_native_projection_metadata(
    repository: &ClaudeCodeStateRepository,
    adapter_state_key: RuntimeId,
) -> Result<VerifiedNativeMetadata, ProtocolError> {
    let reference = resolve_native_projection_reference(repository, adapter_state_key).await?;
    read_native_metadata(reference).await
}

async fn resolve_native_projection_reference(
    repository: &ClaudeCodeStateRepository,
    adapter_state_key: RuntimeId,
) -> Result<NativeTranscriptRefV1, ProtocolError> {
    let reference = repository
        .resolve_private(adapter_state_key)
        .await
        .map_err(adapter_state_protocol_error)?
        .ok_or_else(|| ProtocolError {
            code: "adapter-state-not-found".into(),
            message: "Claude Code history mapping was not found".into(),
            diagnostic_ref: None,
        })?;
    require_native_projection_reference(reference)
}

fn require_native_projection_reference(
    reference: ResolvedClaudeCodeReference,
) -> Result<NativeTranscriptRefV1, ProtocolError> {
    match reference {
        ResolvedClaudeCodeReference::NativeV1(reference) => Ok(reference),
        ResolvedClaudeCodeReference::LegacySessionId(_) => Err(ProtocolError {
            code: "adapter-native-history-reference-invalid".into(),
            message: "native-projected history requires a verified opaque reference".into(),
            diagnostic_ref: None,
        }),
    }
}

async fn resolve_managed_native_reference(
    repository: &ClaudeCodeStateRepository,
    adapter_state_key: RuntimeId,
) -> Result<NativeTranscriptRefV1, ProtocolError> {
    let reference = repository
        .resolve_private(adapter_state_key)
        .await
        .map_err(adapter_state_protocol_error)?
        .ok_or_else(|| ProtocolError {
            code: "adapter-state-not-found".into(),
            message: "Claude Code history mapping was not found".into(),
            diagnostic_ref: None,
        })?;
    match reference {
        ResolvedClaudeCodeReference::LegacySessionId(thread_id) => {
            verify_legacy_native_reference(thread_id).await
        }
        ResolvedClaudeCodeReference::NativeV1(reference) => Ok(reference),
    }
}

async fn verify_legacy_native_reference(
    thread_id: ThreadId,
) -> Result<NativeTranscriptRefV1, ProtocolError> {
    let root = claude_projects_root().ok_or_else(|| ProtocolError {
        code: "cc-history-root-unavailable".into(),
        message: "cannot resolve the current user's Claude Code history root".into(),
        diagnostic_ref: None,
    })?;
    let lookup_id = thread_id.clone();
    let verified = tokio::task::spawn_blocking(move || {
        verify_native_history_entry_at(
            &root,
            &HistoryListItem {
                thread_id: lookup_id,
                agent_kind: AgentKind::ClaudeCode,
                title: None,
                cwd: PathBuf::new(),
                last_active_ms: 0,
                archived: false,
            },
        )
    })
    .await
    .map_err(|error| ProtocolError {
        code: "cc-history-task-join".into(),
        message: format!("legacy native history lookup failed: {error}"),
        diagnostic_ref: None,
    })??;
    Ok(verified.into_private_reference())
}

async fn read_native_history(
    reference: NativeTranscriptRefV1,
) -> Result<HistoryReadResponse, ProtocolError> {
    let thread_id = ThreadId(
        reference
            .resume_thread_id()
            .map_err(native_history_protocol_error)?,
    );
    tokio::task::spawn_blocking(move || {
        let source =
            NativeHistorySource::for_current_account().map_err(native_history_protocol_error)?;
        let projection = source
            .read_projection(&reference)
            .map_err(native_history_protocol_error)?;
        let document = match projection.into_outcome() {
            NativeReadOutcome::Document(document) => document,
            NativeReadOutcome::FilteredObserver => return Err(native_history_not_found()),
        };
        if document.turns().is_empty() {
            return Err(invalid_native_history());
        }
        let turns = document
            .into_turns()
            .into_iter()
            .map(|turn| {
                let turn_key = turn.key();
                let _stable_turn_key = turn_key.as_bytes();
                HistoryTurn {
                    items: turn
                        .into_items()
                        .into_iter()
                        .map(|item| {
                            debug_assert_eq!(item.turn_key(), turn_key);
                            let _stable_item_key = item.key();
                            let _stable_item_key_bytes = _stable_item_key.as_bytes();
                            item.into_item()
                        })
                        .collect(),
                }
            })
            .collect();
        Ok(HistoryReadResponse {
            thread_id,
            agent_kind: AgentKind::ClaudeCode,
            turns,
        })
    })
    .await
    .map_err(|error| ProtocolError {
        code: "cc-history-task-join".into(),
        message: format!("native history task failed: {error}"),
        diagnostic_ref: None,
    })?
}

async fn read_keyed_native_history(
    reference: NativeTranscriptRefV1,
) -> Result<CanonicalNativeHistoryRead, ProtocolError> {
    tokio::task::spawn_blocking(move || {
        let source =
            NativeHistorySource::for_current_account().map_err(native_history_protocol_error)?;
        let projection = source
            .read_projection(&reference)
            .map_err(native_history_protocol_error)?;
        let source_bytes = projection.bytes_read();
        let document = match projection.into_outcome() {
            NativeReadOutcome::Document(document) => document,
            NativeReadOutcome::FilteredObserver => return Err(native_history_not_found()),
        };
        if document.turns().is_empty() {
            return Err(invalid_native_history());
        }
        canonicalize_native_projection(document, source_bytes)
    })
    .await
    .map_err(|error| ProtocolError {
        code: "cc-history-task-join".into(),
        message: format!("key-bearing native history task failed: {error}"),
        diagnostic_ref: None,
    })?
}

#[allow(dead_code, reason = "后续 coordinator 接线")]
async fn read_native_metadata(
    reference: NativeTranscriptRefV1,
) -> Result<VerifiedNativeMetadata, ProtocolError> {
    let resume_thread_id = ThreadId(
        reference
            .resume_thread_id()
            .map_err(native_history_protocol_error)?,
    );
    tokio::task::spawn_blocking(move || {
        let source =
            NativeHistorySource::for_current_account().map_err(native_history_protocol_error)?;
        let projection = source
            .read_projection(&reference)
            .map_err(native_history_protocol_error)?;
        let document = match projection.into_outcome() {
            NativeReadOutcome::Document(document) => document,
            NativeReadOutcome::FilteredObserver => return Err(native_history_not_found()),
        };
        if document.turns().is_empty() {
            return Err(invalid_native_history());
        }
        let (cwd, custom_title) = document
            .into_metadata()
            .map_err(native_history_protocol_error)?;
        Ok(VerifiedNativeMetadata {
            resume_thread_id,
            cwd,
            custom_title,
        })
    })
    .await
    .map_err(|error| ProtocolError {
        code: "cc-history-task-join".into(),
        message: format!("native metadata task failed: {error}"),
        diagnostic_ref: None,
    })?
}

fn canonicalize_native_projection(
    document: native::NativeHistoryDocument,
    source_bytes: u64,
) -> Result<CanonicalNativeHistoryRead, ProtocolError> {
    let mut items = Vec::new();
    for turn in document.into_turns() {
        let native_turn_key = turn.key();
        let turn_key = NativeTurnKey::from_verified_bytes(*native_turn_key.as_bytes())?;
        for item in turn.into_items() {
            debug_assert_eq!(item.turn_key(), native_turn_key);
            let native_item_key = item.key();
            items.push(CanonicalNativeHistoryItem::new(
                turn_key,
                NativeItemKey::from_verified_bytes(*native_item_key.as_bytes())?,
                item.into_item(),
            )?);
        }
    }
    CanonicalNativeHistoryRead::new(AgentKind::ClaudeCode, items, source_bytes)
}

/// 只从调用方明确选定的 native history entry 重建派生索引；不按
/// title/cwd/mtime 猜测随机 adapterStateKey 的旧归属。
pub(super) async fn rebuild_managed_index(
    repository: &ClaudeCodeStateRepository,
    adapter_state_key: RuntimeId,
    native: &HistoryListItem,
) -> Result<(), ProtocolError> {
    let root = claude_projects_root().ok_or_else(|| ProtocolError {
        code: "cc-history-root-unavailable".into(),
        message: "cannot resolve the current user's Claude Code history root".into(),
        diagnostic_ref: None,
    })?;
    rebuild_managed_index_at(repository, adapter_state_key, native, root).await
}

async fn rebuild_managed_index_at(
    repository: &ClaudeCodeStateRepository,
    adapter_state_key: RuntimeId,
    native: &HistoryListItem,
    root: PathBuf,
) -> Result<(), ProtocolError> {
    let native = native.clone();
    let verified =
        tokio::task::spawn_blocking(move || verify_native_history_entry_at(&root, &native))
            .await
            .map_err(|error| ProtocolError {
                code: "cc-history-task-join".into(),
                message: format!("native history verification task failed: {error}"),
                diagnostic_ref: None,
            })??;
    repository
        .bind_verified_native_history(adapter_state_key, verified)
        .await
        .map_err(adapter_state_protocol_error)
}

/// Adapter canonical retry 只据已持久化 private ref 判断 native session 是否已经
/// 真正落成。恰好一个 regular/non-memory JSONL 才返回 true；不存在返回 false，
/// 歧义与其他 IO/安全错误 fail-close。
pub(super) async fn native_session_is_materialized(
    thread_id: &ThreadId,
) -> Result<bool, ProtocolError> {
    let root = claude_projects_root().ok_or_else(|| ProtocolError {
        code: "cc-history-root-unavailable".into(),
        message: "cannot resolve the current user's Claude Code history root".into(),
        diagnostic_ref: None,
    })?;
    native_session_is_materialized_at(root, thread_id).await
}

async fn native_session_is_materialized_at(
    root: PathBuf,
    thread_id: &ThreadId,
) -> Result<bool, ProtocolError> {
    let native = HistoryListItem {
        thread_id: thread_id.clone(),
        agent_kind: AgentKind::ClaudeCode,
        title: None,
        cwd: PathBuf::new(),
        last_active_ms: 0,
        archived: false,
    };
    match tokio::task::spawn_blocking(move || verify_native_history_entry_at(&root, &native))
        .await
        .map_err(|error| ProtocolError {
            code: "cc-history-task-join".into(),
            message: format!("native history verification task failed: {error}"),
            diagnostic_ref: None,
        })? {
        Ok(_) => Ok(true),
        Err(error) if error.code == "cc-history-native-entry-not-found" => Ok(false),
        Err(error) => Err(error),
    }
}

fn adapter_state_protocol_error(error: RuntimeStoreError) -> ProtocolError {
    ProtocolError {
        code: error.code().into(),
        message: format!("Claude Code private history mapping failed: {error}"),
        diagnostic_ref: None,
    }
}

// ── Path encoding (CC convention) ───────────────────────────────────────────

/// Encode a cwd into CC's project-directory name (replace `/` with
/// `-`, also `.`). Round-trip-tested below.
pub fn encode_cwd(cwd: &Path) -> String {
    let s = cwd.to_string_lossy();
    s.replace(['/', '.'], "-")
}

/// Decode a CC project-directory name back into an absolute path.
/// Best-effort — CC drops the `/` vs `-` distinction, so any `-` in
/// the original cwd becomes ambiguous. We re-build the most plausible
/// absolute path by replacing every `-` with `/`.
pub fn decode_cwd(dirname: &str) -> PathBuf {
    let s = dirname.replace('-', "/");
    PathBuf::from(s)
}

/// `~/.claude/projects/` 只从 `getpwuid_r(geteuid())` 的 OS account home 派生。
fn claude_projects_root() -> Option<PathBuf> {
    crate::config::current_user_home()
        .ok()
        .map(|home| home.join(".claude").join("projects"))
}

fn verify_native_history_entry_at(
    root: &Path,
    native: &HistoryListItem,
) -> Result<VerifiedNativeHistoryEntry, ProtocolError> {
    if native.agent_kind != AgentKind::ClaudeCode {
        return Err(ProtocolError {
            code: "cc-history-wrong-agent".into(),
            message: "native history entry is not owned by Claude Code".into(),
            diagnostic_ref: None,
        });
    }
    let id = native.thread_id.0.as_str();
    if !native::safe_legacy_session_id(id) {
        return Err(ProtocolError {
            code: "cc-history-invalid-session-id".into(),
            message: "Claude Code native session id has an unsafe shape".into(),
            diagnostic_ref: None,
        });
    }
    let home = root
        .parent()
        .and_then(Path::parent)
        .ok_or_else(invalid_native_history)?;
    if home.join(".claude").join("projects") != root {
        return Err(invalid_native_history());
    }
    // SAFETY: geteuid has no preconditions and reads only process credentials.
    let uid = unsafe { libc::geteuid() };
    let source = match NativeHistorySource::from_home(home, uid) {
        Ok(source) => source,
        Err(NativeHistoryError::SourceUnavailable { .. }) => {
            return Err(native_history_not_found());
        }
        Err(error) => return Err(native_history_protocol_error(error)),
    };
    let scan_generation = *Uuid::new_v4().as_bytes();
    let mut scanner = source
        .scanner(scan_generation)
        .map_err(native_history_protocol_error)?;
    let mut budget = NativeIoBudget::new(
        2_000,
        64 * 1024 * 1024,
        Instant::now() + Duration::from_secs(2),
    );
    let mut matched = None;
    loop {
        match scanner
            .next(&mut budget)
            .map_err(native_history_protocol_error)?
        {
            NativeScanStep::Candidate(candidate) => {
                if !matches!(
                    candidate.reference().resume_thread_id().as_deref(),
                    Ok(found) if found == id
                ) {
                    scanner
                        .acknowledge(candidate)
                        .map_err(native_history_protocol_error)?;
                    continue;
                }
                match source
                    .read(
                        candidate.reference(),
                        &mut budget,
                        NativeParseLimits::default(),
                    )
                    .map_err(native_verification_read_error)?
                {
                    NativeReadOutcome::FilteredObserver => {
                        scanner
                            .acknowledge(candidate)
                            .map_err(native_history_protocol_error)?;
                        continue;
                    }
                    NativeReadOutcome::Document(document) if document.turns().is_empty() => {
                        return Err(invalid_native_history());
                    }
                    NativeReadOutcome::Document(_) => {}
                }
                if matched.replace(candidate.reference().clone()).is_some() {
                    return Err(ProtocolError {
                        code: "cc-history-native-entry-ambiguous".into(),
                        message: "Claude Code native history entry did not resolve to exactly one JSONL file".into(),
                        diagnostic_ref: None,
                    });
                }
                scanner
                    .acknowledge(candidate)
                    .map_err(native_history_protocol_error)?;
            }
            NativeScanStep::Yielded(NativeScanStop::CandidateLimit | NativeScanStop::Deadline) => {
                return Err(ProtocolError {
                    code: "cc-history-native-scan-truncated".into(),
                    message: "Claude Code native history verification exceeded its bounded scan"
                        .into(),
                    diagnostic_ref: None,
                });
            }
            NativeScanStep::Complete => {
                let completed = scanner
                    .into_completed_scan()
                    .map_err(native_history_protocol_error)?;
                let (completed_generation, _acknowledged_candidates) = completed.into_parts();
                debug_assert_eq!(completed_generation, scan_generation);
                break;
            }
        }
    }
    matched
        .map(|reference| VerifiedNativeHistoryEntry { reference })
        .ok_or_else(native_history_not_found)
}

fn native_history_not_found() -> ProtocolError {
    ProtocolError {
        code: "cc-history-native-entry-not-found".into(),
        message: "Claude Code native history entry did not resolve to exactly one JSONL file"
            .into(),
        diagnostic_ref: None,
    }
}

fn json_value_is_memory_agent(value: &Value) -> bool {
    if value
        .get("content")
        .and_then(Value::as_str)
        .map(is_memory_agent_prompt)
        .unwrap_or(false)
    {
        return true;
    }
    value.get("type").and_then(Value::as_str) == Some("user")
        && value
            .get("message")
            .and_then(|message| message.get("content"))
            .and_then(Value::as_str)
            .map(is_memory_agent_prompt)
            .unwrap_or(false)
}

fn invalid_native_history() -> ProtocolError {
    ProtocolError {
        code: "cc-history-native-entry-invalid".into(),
        message: "Claude Code native history entry was not readable, bounded valid JSONL".into(),
        diagnostic_ref: None,
    }
}

fn native_history_protocol_error(error: NativeHistoryError) -> ProtocolError {
    ProtocolError {
        code: error.code().into(),
        message: "Claude Code native history verification failed".into(),
        diagnostic_ref: None,
    }
}

fn native_verification_read_error(error: NativeHistoryError) -> ProtocolError {
    match error {
        NativeHistoryError::SourceUnavailable { .. }
        | NativeHistoryError::SourceUnsafe { .. }
        | NativeHistoryError::Io { .. }
        | NativeHistoryError::HomeUnavailable => native_history_protocol_error(error),
        _ => invalid_native_history(),
    }
}

// ── claude agents --json parser (best-effort live-agent enrichment) ─────────

/// Subset of fields `claude agents --json` returns. Real shape includes
/// many more (sessionId, kind, status, state, pid, …). We keep only
/// the fields the v0.2 sidebar needs, all optional, so a future CC
/// shape change lands soft.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
struct AgentsJsonRow {
    session_id: Option<String>,
    cwd: Option<String>,
    name: Option<String>,
    /// epoch millis
    started_at: Option<u64>,
    kind: Option<String>,
    state: Option<String>,
    status: Option<String>,
}

/// Parse a `claude agents --json` payload. Tolerant: each row's
/// fields are all optional, and rows without a `session_id` are
/// dropped (they can't be addressed in the History namespace anyway).
pub fn parse_agents_json_array(raw: &str) -> Result<Vec<HistoryListItem>, ProtocolError> {
    // CC's serializer uses camelCase, but we accept either by setting
    // serde's default. (#[serde(default)] keeps unknown fields out of
    // the way.)
    let rows: Vec<serde_json::Value> =
        serde_json::from_str(raw.trim()).map_err(|e| ProtocolError {
            code: "cc-history-parse".into(),
            message: format!("claude agents --json parse failed: {e}"),
            diagnostic_ref: None,
        })?;
    let mut out = Vec::with_capacity(rows.len());
    for v in rows {
        // Manual extraction: CC uses both camelCase and snake_case in
        // different versions; pulling fields by name in either casing
        // is more robust than two struct variants.
        let row = AgentsJsonRow {
            session_id: v
                .get("sessionId")
                .or_else(|| v.get("session_id"))
                .and_then(Value::as_str)
                .map(String::from),
            cwd: v.get("cwd").and_then(Value::as_str).map(String::from),
            name: v.get("name").and_then(Value::as_str).map(String::from),
            started_at: v
                .get("startedAt")
                .or_else(|| v.get("started_at"))
                .and_then(Value::as_u64),
            kind: v.get("kind").and_then(Value::as_str).map(String::from),
            state: v.get("state").and_then(Value::as_str).map(String::from),
            status: v.get("status").and_then(Value::as_str).map(String::from),
        };
        let Some(session_id) = row.session_id else {
            continue;
        };
        let cwd = row.cwd.map(PathBuf::from).unwrap_or_default();
        // CC `agents` `state ∈ {stopped, failed, done, blocked}` are
        // "no longer live"; we surface those as `archived=false` (the
        // catalogue still owns them) so the UI sidebar shows them
        // until the user explicitly removes via `claude rm`.
        let _ = (row.kind, row.state, row.status); // intentionally unused fields kept for future filters
        out.push(HistoryListItem {
            thread_id: ThreadId(session_id),
            agent_kind: AgentKind::ClaudeCode,
            title: row.name,
            cwd,
            last_active_ms: row.started_at.unwrap_or(0),
            archived: false,
        });
    }
    Ok(out)
}

// ── .jsonl-based catalogue (the actual source of all sessions) ──────────────

/// Enumerate every `*.jsonl` under `~/.claude/projects/<encoded_cwd>/`
/// (or every project dir when `cwd_filter` is `None`) and return one
/// `HistoryListItem` per file.
///
/// Title resolution: scan the jsonl for the latest
/// `{"type":"custom-title", "customTitle":"<x>"}` line (set by
/// `rename`); fall back to first 80 chars of the first `user`
/// message content; fall back to `None`.
pub fn list_history_from_jsonl(
    cwd_filter: Option<&Path>,
    limit: Option<usize>,
) -> Result<Vec<HistoryListItem>, ProtocolError> {
    let root = match claude_projects_root() {
        Some(r) => r,
        None => return Ok(vec![]),
    };
    list_history_from_jsonl_root(&root, cwd_filter, effective_history_list_limit(limit))
}

fn list_history_from_jsonl_root(
    root: &Path,
    cwd_filter: Option<&Path>,
    limit: usize,
) -> Result<Vec<HistoryListItem>, ProtocolError> {
    struct HistoryListCandidate {
        path: PathBuf,
        thread_id: ThreadId,
        cwd: PathBuf,
        last_active_ms: u64,
    }

    let mut candidates = Vec::new();
    let dirs: Vec<PathBuf> = if let Some(cwd) = cwd_filter {
        let p = root.join(encode_cwd(cwd));
        if p.is_dir() { vec![p] } else { vec![] }
    } else {
        match std::fs::read_dir(root) {
            Ok(rd) => rd
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| p.is_dir())
                .collect(),
            // Missing projects dir = no history. Not an error.
            Err(_) => vec![],
        }
    };
    for dir in dirs {
        let Some(dirname) = dir.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        let cwd = decode_cwd(dirname);
        let rd = match std::fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(_) => continue,
        };
        for entry in rd.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("jsonl") {
                continue;
            }
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            // session id is the bare uuid; sanity-check shape (length
            // & dashes) so transient files don't pollute the list.
            if stem.len() < 8 || !stem.contains('-') {
                continue;
            }
            let thread_id = ThreadId(stem.to_string());
            let last_active_ms = file_mtime_ms(&path);
            candidates.push(HistoryListCandidate {
                path,
                thread_id,
                cwd: cwd.clone(),
                last_active_ms,
            });
        }
    }
    // Newest first — what the sidebar wants by default.
    candidates.sort_by_key(|i| std::cmp::Reverse(i.last_active_ms));

    let mut items = Vec::new();
    for candidate in candidates {
        if items.len() >= limit {
            break;
        }
        if is_memory_agent_session(&candidate.path) {
            continue;
        }
        let title = scan_title(&candidate.path);
        items.push(HistoryListItem {
            thread_id: candidate.thread_id,
            agent_kind: AgentKind::ClaudeCode,
            title,
            cwd: candidate.cwd,
            last_active_ms: candidate.last_active_ms,
            archived: false,
        });
    }

    Ok(items)
}

fn file_mtime_ms(p: &Path) -> u64 {
    std::fs::metadata(p)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Scan a jsonl for the last `custom-title` line (CC's rename
/// artefact) and, failing that, the first user message excerpt.
fn scan_title(path: &Path) -> Option<String> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return None;
    };
    let mut custom: Option<String> = None;
    let mut first_user: Option<String> = None;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let v: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let kind = v.get("type").and_then(Value::as_str).unwrap_or("");
        match kind {
            "custom-title" => {
                if let Some(t) = v
                    .get("customTitle")
                    .or_else(|| v.get("custom_title"))
                    .and_then(Value::as_str)
                {
                    // Last one wins.
                    custom = Some(t.to_string());
                }
            }
            "agent-name" if custom.is_none() => {
                if let Some(t) = v
                    .get("agentName")
                    .or_else(|| v.get("agent_name"))
                    .and_then(Value::as_str)
                {
                    custom = Some(t.to_string());
                }
            }
            "user" if first_user.is_none() => {
                if let Some(s) = v
                    .get("message")
                    .and_then(|m| m.get("content"))
                    .and_then(Value::as_str)
                {
                    let snippet: String = s.chars().take(80).collect();
                    first_user = Some(snippet);
                }
            }
            _ => {}
        }
    }
    custom.or(first_user)
}

fn is_memory_agent_session(path: &Path) -> bool {
    if is_memory_agent_project_path(path) {
        return true;
    }
    let Ok(file) = std::fs::File::open(path) else {
        return false;
    };
    let reader = BufReader::new(file);
    let mut bytes_seen = 0usize;
    for line in reader.lines() {
        let Ok(line) = line else {
            break;
        };
        bytes_seen = bytes_seen.saturating_add(line.len());
        if bytes_seen > 64 * 1024 {
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_str::<Value>(trimmed) else {
            continue;
        };
        if v.get("content")
            .and_then(Value::as_str)
            .map(is_memory_agent_prompt)
            .unwrap_or(false)
        {
            return true;
        }
        if v.get("type").and_then(Value::as_str) != Some("user") {
            continue;
        }
        return v
            .get("message")
            .and_then(|m| m.get("content"))
            .and_then(Value::as_str)
            .map(is_memory_agent_prompt)
            .unwrap_or(false);
    }
    false
}

fn is_memory_agent_project_path(path: &Path) -> bool {
    path.parent()
        .and_then(|p| p.file_name())
        .and_then(|s| s.to_str())
        .map(|name| name.contains("claude-mem-observer-sessions"))
        .unwrap_or(false)
}

fn is_memory_agent_prompt(prompt: &str) -> bool {
    let normalized = prompt.trim_start().to_ascii_lowercase();
    normalized.starts_with("hello memory agent") || normalized.starts_with("you are a claude-mem")
}

/// List history (async wrapper). Spawning is sync-blocking on the
/// filesystem so we run inside `spawn_blocking` to keep tokio runtime
/// responsive even on slow disks.
pub async fn list_history(
    cwd_filter: Option<&Path>,
    limit: Option<usize>,
) -> Result<Vec<HistoryListItem>, ProtocolError> {
    let cwd_owned = cwd_filter.map(PathBuf::from);
    tokio::task::spawn_blocking(move || list_history_from_jsonl(cwd_owned.as_deref(), limit))
        .await
        .map_err(|e| ProtocolError {
            code: "cc-history-task-join".into(),
            message: format!("history task panicked: {e}"),
            diagnostic_ref: None,
        })?
}

// ── jsonl → HistoryReadResponse ─────────────────────────────────────────────

/// Parse one session's jsonl content into a `HistoryReadResponse`.
///
/// Grouping rule: every `type=user` line opens a new `HistoryTurn`;
/// assistant content blocks and tool_result blocks (echoed on `user`
/// lines that carry a `tool_result`) accumulate into the open turn.
pub fn parse_session_jsonl(
    content: &str,
    thread_id: ThreadId,
) -> Result<HistoryReadResponse, ProtocolError> {
    let mut turns: Vec<HistoryTurn> = Vec::new();
    let mut current: Vec<AgentItem> = Vec::new();
    let mut in_flight: HashMap<String, (String, Value)> = HashMap::new();

    let flush = |current: &mut Vec<AgentItem>, turns: &mut Vec<HistoryTurn>| {
        if !current.is_empty() {
            turns.push(HistoryTurn {
                items: std::mem::take(current),
            });
        }
    };

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let v: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let line_kind = v.get("type").and_then(Value::as_str).unwrap_or("");
        match line_kind {
            "user" => {
                // Two sub-shapes:
                //   1) plain user prompt: message.content is a string
                //      → open a new turn with UserMessage
                //   2) tool_result echo: message.content is an array
                //      with `type:"tool_result"` blocks → fold into
                //      the current turn (don't open a new one)
                let content_val = v.get("message").and_then(|m| m.get("content"));
                if let Some(text) = content_val.and_then(Value::as_str) {
                    // New turn boundary.
                    flush(&mut current, &mut turns);
                    current.push(AgentItem::UserMessage {
                        text: text.to_string(),
                        meta: AgentItemMeta::default(),
                    });
                } else if let Some(arr) = content_val.and_then(Value::as_array) {
                    for block in arr {
                        if block.get("type").and_then(Value::as_str) == Some("tool_result") {
                            let id = block
                                .get("tool_use_id")
                                .and_then(Value::as_str)
                                .unwrap_or("");
                            let is_error = block
                                .get("is_error")
                                .and_then(Value::as_bool)
                                .unwrap_or(false);
                            let text = extract_tool_result_text(block);
                            if let Some((name, input)) = in_flight.remove(id) {
                                current.push(tool_result_to_agent_item(
                                    &name, &input, is_error, &text,
                                ));
                            } else {
                                current.push(AgentItem::Raw {
                                    raw_kind: "user.tool_result_orphan".into(),
                                    raw_payload: serde_json::to_string(block).unwrap_or_default(),
                                    meta: AgentItemMeta::default(),
                                });
                            }
                        } else if block.get("type").and_then(Value::as_str) == Some("text") {
                            // Plain user prompt that arrived as a block array.
                            if let Some(t) = block.get("text").and_then(Value::as_str)
                                && !t.is_empty()
                            {
                                flush(&mut current, &mut turns);
                                current.push(AgentItem::UserMessage {
                                    text: t.to_string(),
                                    meta: AgentItemMeta::default(),
                                });
                            }
                        }
                    }
                }
            }
            "assistant" => {
                let blocks = v
                    .get("message")
                    .and_then(|m| m.get("content"))
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                for block in &blocks {
                    let bk = block.get("type").and_then(Value::as_str).unwrap_or("");
                    match bk {
                        "text" => {
                            if let Some(t) = block.get("text").and_then(Value::as_str)
                                && !t.is_empty()
                            {
                                current.push(AgentItem::AssistantMessage {
                                    text: t.to_string(),
                                    meta: AgentItemMeta::default(),
                                });
                            }
                        }
                        "thinking" => {
                            if let Some(t) = block
                                .get("thinking")
                                .or_else(|| block.get("text"))
                                .and_then(Value::as_str)
                                && !t.is_empty()
                            {
                                current.push(AgentItem::Reasoning {
                                    text: t.to_string(),
                                    meta: AgentItemMeta::default(),
                                });
                            }
                        }
                        "tool_use" => {
                            if let (Some(id), Some(name)) = (
                                block.get("id").and_then(Value::as_str),
                                block.get("name").and_then(Value::as_str),
                            ) {
                                let input = block.get("input").cloned().unwrap_or(Value::Null);
                                in_flight.insert(id.to_string(), (name.to_string(), input.clone()));
                                current.push(tool_use_to_agent_item(name, &input));
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {
                // attachments, hook events, mode-changes, etc. — not
                // surfaced in the v0.2 history reader.
            }
        }
    }
    flush(&mut current, &mut turns);

    Ok(HistoryReadResponse {
        thread_id,
        agent_kind: AgentKind::ClaudeCode,
        turns,
    })
}

/// Map a `tool_use` block onto an `AgentItem` (Shell / Diff /
/// ToolCall depending on the tool name). Mirrors translator logic but
/// without mutable state.
fn tool_use_to_agent_item(name: &str, input: &Value) -> AgentItem {
    match name {
        "Bash" => {
            let command = input
                .get("command")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            AgentItem::Shell {
                command,
                status: ShellStatus::Running,
                exit_code: None,
                duration_ms: None,
                meta: AgentItemMeta::default(),
            }
        }
        "Edit" | "Write" | "MultiEdit" => AgentItem::Diff {
            files: diff_files_from_tool_use(name, input),
            meta: AgentItemMeta::default(),
        },
        _ => AgentItem::ToolCall {
            name: name.to_string(),
            args: input.clone(),
            result: None,
            meta: AgentItemMeta::default(),
        },
    }
}

/// Build a finalized AgentItem from a tool_result given the matching
/// original tool_use's name + input.
fn tool_result_to_agent_item(
    name: &str,
    input: &Value,
    is_error: bool,
    result_text: &str,
) -> AgentItem {
    match name {
        "Bash" => {
            let command = input
                .get("command")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            AgentItem::Shell {
                command,
                status: if is_error {
                    ShellStatus::Failed
                } else {
                    ShellStatus::Completed
                },
                // Native JSONL 的 tool_result 只携带 is_error；没有权威进程退出码。
                exit_code: None,
                duration_ms: None,
                meta: AgentItemMeta::default(),
            }
        }
        "Edit" | "Write" | "MultiEdit" => AgentItem::Diff {
            files: diff_files_from_tool_use(name, input),
            meta: AgentItemMeta::default(),
        },
        _ => AgentItem::ToolCall {
            name: name.to_string(),
            args: input.clone(),
            result: Some(serde_json::json!(result_text)),
            meta: AgentItemMeta::default(),
        },
    }
}

fn diff_files_from_tool_use(tool_name: &str, input: &Value) -> Vec<DiffFile> {
    match tool_name {
        "Write" => {
            let path = input.get("file_path").and_then(Value::as_str).unwrap_or("");
            let content = input.get("content").and_then(Value::as_str).unwrap_or("");
            vec![DiffFile {
                path: PathBuf::from(path),
                status: DiffStatus::Added,
                patch: Some(content.to_string()),
            }]
        }
        "Edit" => {
            let path = input.get("file_path").and_then(Value::as_str).unwrap_or("");
            let old = input
                .get("old_string")
                .and_then(Value::as_str)
                .unwrap_or("");
            let new = input
                .get("new_string")
                .and_then(Value::as_str)
                .unwrap_or("");
            vec![DiffFile {
                path: PathBuf::from(path),
                status: DiffStatus::Modified,
                patch: Some(synth_patch(old, new)),
            }]
        }
        "MultiEdit" => {
            let path = input.get("file_path").and_then(Value::as_str).unwrap_or("");
            let edits = input
                .get("edits")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let mut patch = String::new();
            for e in &edits {
                let old = e.get("old_string").and_then(Value::as_str).unwrap_or("");
                let new = e.get("new_string").and_then(Value::as_str).unwrap_or("");
                patch.push_str(&synth_patch(old, new));
                patch.push('\n');
            }
            vec![DiffFile {
                path: PathBuf::from(path),
                status: DiffStatus::Modified,
                patch: Some(patch),
            }]
        }
        _ => Vec::new(),
    }
}

fn synth_patch(old: &str, new: &str) -> String {
    let mut out = String::new();
    for line in old.lines() {
        out.push('-');
        out.push_str(line);
        out.push('\n');
    }
    for line in new.lines() {
        out.push('+');
        out.push_str(line);
        out.push('\n');
    }
    out
}

fn extract_tool_result_text(block: &Value) -> String {
    let c = block.get("content");
    if let Some(s) = c.and_then(Value::as_str) {
        return s.to_string();
    }
    if let Some(arr) = c.and_then(Value::as_array) {
        return arr
            .iter()
            .filter_map(|el| {
                if el.get("type").and_then(Value::as_str) == Some("text") {
                    el.get("text").and_then(Value::as_str)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
    }
    String::new()
}

// ── Public async API ────────────────────────────────────────────────────────

/// Read a session's transcript. Looks up the jsonl file by scanning
/// all project dirs for `<thread_id>.jsonl` (the cwd is encoded into
/// the dir name and is not knowable up front for read requests).
pub async fn read_history(thread_id: &ThreadId) -> Result<HistoryReadResponse, ProtocolError> {
    let tid = thread_id.clone();
    tokio::task::spawn_blocking(move || -> Result<HistoryReadResponse, ProtocolError> {
        let root = claude_projects_root().ok_or_else(|| ProtocolError {
            code: "cc-history-no-home".into(),
            message: "$HOME unset; cannot resolve ~/.claude/projects".into(),
            diagnostic_ref: None,
        })?;
        let rd = std::fs::read_dir(&root).map_err(|e| ProtocolError {
            code: "cc-history-projects-read".into(),
            message: format!("read {}: {e}", root.display()),
            diagnostic_ref: None,
        })?;
        for entry in rd.flatten() {
            let dir = entry.path();
            if !dir.is_dir() {
                continue;
            }
            let candidate = dir.join(format!("{}.jsonl", tid.0));
            if candidate.is_file() {
                let content = std::fs::read_to_string(&candidate).map_err(|e| ProtocolError {
                    code: "cc-history-read".into(),
                    message: format!("read {}: {e}", candidate.display()),
                    diagnostic_ref: None,
                })?;
                return parse_session_jsonl(&content, tid.clone());
            }
        }
        Err(ProtocolError {
            code: "cc-history-not-found".into(),
            message: format!("session {} not found in ~/.claude/projects", tid.0),
            diagnostic_ref: None,
        })
    })
    .await
    .map_err(|e| ProtocolError {
        code: "cc-history-task-join".into(),
        message: format!("read task panicked: {e}"),
        diagnostic_ref: None,
    })?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verified_native_metadata_debug_hides_session_cwd_and_title() {
        let metadata = VerifiedNativeMetadata {
            resume_thread_id: ThreadId("private-session-sentinel".into()),
            cwd: PathBuf::from("/private/cwd/sentinel"),
            custom_title: Some("private title sentinel".into()),
        };
        let debug = format!("{metadata:?}");
        for sentinel in [
            "private-session-sentinel",
            "/private/cwd/sentinel",
            "private title sentinel",
        ] {
            assert!(!debug.contains(sentinel));
        }
    }

    #[test]
    fn encode_cwd_round_trip_unix_path() {
        let p = Path::new("/Users/jassy/Documents/glm/AgentDeck");
        assert_eq!(encode_cwd(p), "-Users-jassy-Documents-glm-AgentDeck");
    }

    #[test]
    fn decode_cwd_recovers_a_plausible_path() {
        let d = decode_cwd("-Users-jassy-Documents-glm-AgentDeck");
        assert_eq!(d, PathBuf::from("/Users/jassy/Documents/glm/AgentDeck"));
    }

    #[test]
    fn parse_agents_json_real_shape_extracts_sessionid_and_name() {
        // Truncated real `claude agents --json` payload (CC 2.1.191).
        let raw = r#"[
          {"id":"31472303","cwd":"/private/tmp/claude-bg","kind":"background",
           "startedAt":1782398046433,
           "sessionId":"31472303-b986-42f3-9e63-71a1fa9605c6",
           "name":"write hello to /tmp/claude-bg/note.txt then wait 30 seconds",
           "state":"stopped"},
          {"pid":7088,"cwd":"/Users/jassy/Documents/glm/AgentDeck","kind":"interactive",
           "startedAt":1782791596105,
           "sessionId":"590b6337-73da-4285-836e-87071ac305db","status":"busy"}
        ]"#;
        let items = parse_agents_json_array(raw).expect("parse ok");
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].thread_id.0, "31472303-b986-42f3-9e63-71a1fa9605c6");
        assert_eq!(items[0].cwd, PathBuf::from("/private/tmp/claude-bg"));
        assert!(
            items[0]
                .title
                .as_deref()
                .unwrap_or("")
                .starts_with("write hello")
        );
        assert_eq!(items[0].agent_kind, AgentKind::ClaudeCode);
        assert_eq!(items[0].last_active_ms, 1782398046433);
        assert!(items[1].title.is_none());
    }

    #[test]
    fn parse_agents_json_rows_without_sessionid_dropped() {
        let raw = r#"[{"cwd":"/x","kind":"background"}]"#;
        let items = parse_agents_json_array(raw).expect("parse ok");
        assert!(items.is_empty(), "row without sessionId must be dropped");
    }

    #[test]
    fn parse_agents_json_malformed_returns_structured_error() {
        let err = parse_agents_json_array("not json").unwrap_err();
        assert_eq!(err.code, "cc-history-parse");
    }

    #[test]
    fn parse_session_jsonl_user_then_assistant_groups_into_one_turn() {
        let content = r#"
{"type":"user","message":{"role":"user","content":"hello"},"sessionId":"abc"}
{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"world"}]},"sessionId":"abc"}
"#;
        let resp = parse_session_jsonl(content, ThreadId("abc".into())).unwrap();
        assert_eq!(resp.turns.len(), 1);
        assert_eq!(resp.turns[0].items.len(), 2);
        assert!(matches!(
            resp.turns[0].items[0],
            AgentItem::UserMessage { .. }
        ));
        assert!(matches!(
            resp.turns[0].items[1],
            AgentItem::AssistantMessage { .. }
        ));
    }

    #[test]
    fn parse_session_jsonl_bash_tool_use_and_result_emit_shell_pair() {
        let content = r#"
{"type":"user","message":{"role":"user","content":"run ls"}}
{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"Bash","input":{"command":"ls"}}]}}
{"type":"user","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":"a\nb","is_error":false}]}}
"#;
        let resp = parse_session_jsonl(content, ThreadId("x".into())).unwrap();
        assert_eq!(resp.turns.len(), 1);
        let items = &resp.turns[0].items;
        assert!(matches!(items[0], AgentItem::UserMessage { .. }));
        match &items[1] {
            AgentItem::Shell {
                command, status, ..
            } => {
                assert_eq!(command, "ls");
                assert!(matches!(status, ShellStatus::Running));
            }
            other => panic!("expected Shell tool_use, got {other:?}"),
        }
        match &items[2] {
            AgentItem::Shell {
                command,
                status,
                exit_code,
                ..
            } => {
                assert_eq!(command, "ls");
                assert!(matches!(status, ShellStatus::Completed));
                assert_eq!(*exit_code, None);
            }
            other => panic!("expected Shell tool_result, got {other:?}"),
        }
    }

    #[test]
    fn parse_session_jsonl_two_user_messages_yield_two_turns() {
        let content = r#"
{"type":"user","message":{"role":"user","content":"q1"}}
{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"a1"}]}}
{"type":"user","message":{"role":"user","content":"q2"}}
{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"a2"}]}}
"#;
        let resp = parse_session_jsonl(content, ThreadId("x".into())).unwrap();
        assert_eq!(resp.turns.len(), 2);
        assert_eq!(resp.turns[0].items.len(), 2);
        assert_eq!(resp.turns[1].items.len(), 2);
    }

    #[test]
    fn parse_session_jsonl_skips_attachments_and_modes() {
        let content = r#"
{"type":"queue-operation","operation":"enqueue"}
{"type":"mode","mode":"normal"}
{"type":"permission-mode","permissionMode":"default"}
{"type":"user","message":{"role":"user","content":"hi"}}
"#;
        let resp = parse_session_jsonl(content, ThreadId("x".into())).unwrap();
        // Only the user line opens a turn.
        assert_eq!(resp.turns.len(), 1);
        assert_eq!(resp.turns[0].items.len(), 1);
    }

    #[test]
    fn scan_title_prefers_custom_title_line() {
        let dir = tempdir_unique();
        let path = dir.join("sess.jsonl");
        std::fs::write(
            &path,
            r#"{"type":"user","message":{"role":"user","content":"first prompt here"}}
{"type":"custom-title","customTitle":"My Renamed Session"}
"#,
        )
        .unwrap();
        let title = scan_title(&path);
        assert_eq!(title.as_deref(), Some("My Renamed Session"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn scan_title_falls_back_to_first_user_snippet() {
        let dir = tempdir_unique();
        let path = dir.join("sess.jsonl");
        std::fs::write(
            &path,
            r#"{"type":"user","message":{"role":"user","content":"first prompt content here"}}
{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"reply"}]}}
"#,
        )
        .unwrap();
        let title = scan_title(&path);
        assert_eq!(title.as_deref(), Some("first prompt content here"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn list_history_from_jsonl_root_sorts_newest_first_and_applies_limit() {
        let home = tempdir_unique();
        let root = home.join(".claude").join("projects");
        let project = root.join(encode_cwd(Path::new("/tmp/agentdeck")));
        std::fs::create_dir_all(&project).unwrap();

        for idx in 0..3 {
            let path = project.join(format!("00000000-0000-0000-0000-00000000000{idx}.jsonl"));
            std::fs::write(
                &path,
                format!(
                    r#"{{"type":"user","message":{{"role":"user","content":"prompt {idx}"}}}}"#
                ),
            )
            .unwrap();
            let now = std::time::SystemTime::now() + std::time::Duration::from_secs(idx as u64);
            let _ = std::fs::File::open(&path).unwrap().set_modified(now);
        }

        let items = list_history_from_jsonl_root(&root, None, 2).unwrap();
        assert_eq!(items.len(), 2);
        assert!(
            items[0].last_active_ms >= items[1].last_active_ms,
            "items should stay newest-first"
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn list_history_filters_memory_agent_sessions_and_backfills_limit() {
        let home = tempdir_unique();
        let root = home.join(".claude").join("projects");
        let project = root.join(encode_cwd(Path::new("/tmp/agentdeck")));
        std::fs::create_dir_all(&project).unwrap();

        let claude_mem = project.join("00000000-0000-0000-0000-000000000300.jsonl");
        std::fs::write(
            &claude_mem,
            r#"{"type":"user","message":{"role":"user","content":"You are a Claude-Mem, a specialized observer tool for creating searchable memory FOR FUTURE SESSIONS."}}"#,
        )
        .unwrap();
        let newest = std::time::SystemTime::now() + std::time::Duration::from_secs(180);
        std::fs::File::open(&claude_mem)
            .unwrap()
            .set_modified(newest)
            .unwrap();

        let memory = project.join("00000000-0000-0000-0000-000000000200.jsonl");
        std::fs::write(
            &memory,
            r#"{"type":"user","message":{"role":"user","content":"Hello memory agent, you are continuing to observe the primary Claude session."}}"#,
        )
        .unwrap();
        let second_newest = std::time::SystemTime::now() + std::time::Duration::from_secs(120);
        std::fs::File::open(&memory)
            .unwrap()
            .set_modified(second_newest)
            .unwrap();

        let normal = project.join("00000000-0000-0000-0000-000000000100.jsonl");
        std::fs::write(
            &normal,
            r#"{"type":"user","message":{"role":"user","content":"real user prompt"}}"#,
        )
        .unwrap();
        let older = std::time::SystemTime::now() + std::time::Duration::from_secs(60);
        std::fs::File::open(&normal)
            .unwrap()
            .set_modified(older)
            .unwrap();

        let items = list_history_from_jsonl_root(&root, None, 1).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].thread_id.0, "00000000-0000-0000-0000-000000000100");
        assert_eq!(items[0].title.as_deref(), Some("real user prompt"));

        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn list_history_filters_claude_mem_observer_project_dir() {
        let home = tempdir_unique();
        let root = home.join(".claude").join("projects");
        let observer = root.join("-Users-jassy--claude-mem-observer-sessions");
        let project = root.join(encode_cwd(Path::new("/tmp/agentdeck")));
        std::fs::create_dir_all(&observer).unwrap();
        std::fs::create_dir_all(&project).unwrap();

        let observer_session = observer.join("00000000-0000-0000-0000-000000000200.jsonl");
        std::fs::write(
            &observer_session,
            r#"{"type":"user","message":{"role":"user","content":"internal observer prompt"}}"#,
        )
        .unwrap();
        let newest = std::time::SystemTime::now() + std::time::Duration::from_secs(120);
        std::fs::File::open(&observer_session)
            .unwrap()
            .set_modified(newest)
            .unwrap();

        let normal = project.join("00000000-0000-0000-0000-000000000100.jsonl");
        std::fs::write(
            &normal,
            r#"{"type":"user","message":{"role":"user","content":"real user prompt"}}"#,
        )
        .unwrap();
        let older = std::time::SystemTime::now() + std::time::Duration::from_secs(60);
        std::fs::File::open(&normal)
            .unwrap()
            .set_modified(older)
            .unwrap();

        let items = list_history_from_jsonl_root(&root, None, 1).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].thread_id.0, "00000000-0000-0000-0000-000000000100");

        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn native_history_verification_requires_one_regular_non_memory_jsonl() {
        let home = tempdir_unique();
        let root = home.join(".claude").join("projects");
        let project = root.join(encode_cwd(Path::new("/tmp/verified-native")));
        std::fs::create_dir_all(&project).unwrap();
        let session_id = "10000000-0000-0000-0000-000000000001";
        std::fs::write(
            project.join(format!("{session_id}.jsonl")),
            r#"{"type":"user","uuid":"11000000-0000-4000-8000-000000000011","parentUuid":null,"message":{"role":"user","content":"real prompt"}}"#,
        )
        .unwrap();
        let native = HistoryListItem {
            thread_id: ThreadId(session_id.to_owned()),
            agent_kind: AgentKind::ClaudeCode,
            title: Some("wire title is not trusted for identity".to_owned()),
            cwd: PathBuf::from("/intentionally/not/used/as/identity"),
            last_active_ms: 0,
            archived: false,
        };

        let verified =
            verify_native_history_entry_at(&root, &native).expect("one native JSONL verifies");
        assert_eq!(
            format!("{verified:?}"),
            "VerifiedNativeHistoryEntry([REDACTED])"
        );
        assert_eq!(verified.into_thread_id(), native.thread_id);
        assert!(!home.join("cc-meta").exists());

        let duplicate_project = root.join("-tmp-duplicate");
        std::fs::create_dir_all(&duplicate_project).unwrap();
        std::fs::write(
            duplicate_project.join(format!("{session_id}.jsonl")),
            r#"{"type":"user","uuid":"12000000-0000-4000-8000-000000000012","parentUuid":null,"message":{"role":"user","content":"duplicate"}}"#,
        )
        .unwrap();
        let error = verify_native_history_entry_at(&root, &native)
            .expect_err("duplicate native ids are ambiguous");
        assert_eq!(error.code, "cc-history-native-entry-ambiguous");
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn native_history_verification_rejects_wire_only_and_memory_entries() {
        let home = tempdir_unique();
        let root = home.join(".claude").join("projects");
        let observer = root.join("-Users-user--claude-mem-observer-sessions");
        std::fs::create_dir_all(&observer).unwrap();
        let session_id = "20000000-0000-0000-0000-000000000002";
        std::fs::write(
            observer.join(format!("{session_id}.jsonl")),
            r#"{"type":"user","message":{"role":"user","content":"internal observer"}}"#,
        )
        .unwrap();
        let mut native = HistoryListItem {
            thread_id: ThreadId(session_id.to_owned()),
            agent_kind: AgentKind::ClaudeCode,
            title: None,
            cwd: PathBuf::new(),
            last_active_ms: 0,
            archived: false,
        };
        let error = verify_native_history_entry_at(&root, &native)
            .expect_err("observer sessions are not importable");
        assert_eq!(error.code, "cc-history-native-entry-not-found");

        native.agent_kind = AgentKind::Codex;
        let error = verify_native_history_entry_at(&root, &native)
            .expect_err("client cannot relabel another agent as native CC history");
        assert_eq!(error.code, "cc-history-wrong-agent");
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn native_history_missing_projects_root_is_not_materialized() {
        let home = tempdir_unique();
        let root = home.join(".claude").join("projects");
        let native = HistoryListItem {
            thread_id: ThreadId("21000000-0000-0000-0000-000000000002".to_owned()),
            agent_kind: AgentKind::ClaudeCode,
            title: None,
            cwd: PathBuf::new(),
            last_active_ms: 0,
            archived: false,
        };

        let error = verify_native_history_entry_at(&root, &native)
            .expect_err("a fresh home has no materialized native session");
        assert_eq!(error.code, "cc-history-native-entry-not-found");
        let _ = std::fs::remove_dir_all(&home);
    }

    #[tokio::test]
    async fn canonical_retry_treats_missing_projects_root_as_not_materialized() {
        let home = tempdir_unique();
        let root = home.join(".claude").join("projects");
        let thread_id = ThreadId("21500000-0000-0000-0000-000000000002".to_owned());

        assert!(
            !native_session_is_materialized_at(root, &thread_id)
                .await
                .expect("fresh home should allow retry with the persisted --session-id")
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn native_history_verification_rejects_empty_and_malformed_jsonl() {
        let home = tempdir_unique();
        let root = home.join(".claude").join("projects");
        let project = root.join(encode_cwd(Path::new("/tmp/invalid-native")));
        std::fs::create_dir_all(&project).unwrap();
        let session_id = "22000000-0000-0000-0000-000000000002";
        let candidate = project.join(format!("{session_id}.jsonl"));
        let native = HistoryListItem {
            thread_id: ThreadId(session_id.to_owned()),
            agent_kind: AgentKind::ClaudeCode,
            title: None,
            cwd: PathBuf::new(),
            last_active_ms: 0,
            archived: false,
        };

        for content in ["", "not-json\n"] {
            std::fs::write(&candidate, content).unwrap();
            let error = verify_native_history_entry_at(&root, &native)
                .expect_err("candidate must contain readable JSONL");
            assert_eq!(error.code, "cc-history-native-entry-invalid");
        }
        let _ = std::fs::remove_dir_all(&home);
    }

    #[tokio::test]
    async fn managed_index_rebuild_verifies_native_jsonl_persists_and_never_creates_cc_meta() {
        use crate::claude_code::state::ClaudeCodeStateRepository;
        use crate::runtime::store::{
            NewConversation, RuntimeId, RuntimeIdKind, RuntimeStoreConfig, RuntimeStoreHandle,
        };
        use crate::security::{MemoryKeyStore, load_or_create_storage_kek};

        let home = tempdir_unique();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let projects = home.join(".claude").join("projects");
        let project = projects.join(encode_cwd(Path::new("/tmp/rebuild-managed")));
        std::fs::create_dir_all(&project).unwrap();
        let native_id = "30000000-0000-0000-0000-000000000003";
        std::fs::write(
            project.join(format!("{native_id}.jsonl")),
            r#"{"type":"user","uuid":"31000000-0000-4000-8000-000000000031","parentUuid":null,"message":{"role":"user","content":"native"}}"#,
        )
        .unwrap();
        let native = HistoryListItem {
            thread_id: ThreadId(native_id.into()),
            agent_kind: AgentKind::ClaudeCode,
            title: Some("untrusted wire title".into()),
            cwd: PathBuf::from("/untrusted/wire/cwd"),
            last_active_ms: 0,
            archived: false,
        };

        let database = home.join("runtime.db");
        let keys = MemoryKeyStore::new();
        let storage_kek =
            load_or_create_storage_kek(&keys, &database).expect("create rebuild StorageKEK");
        let store =
            RuntimeStoreHandle::open(RuntimeStoreConfig::new(database.clone()), storage_kek)
                .await
                .expect("open rebuild store");
        let adapter_state_key =
            RuntimeId::from_bytes(RuntimeIdKind::AdapterState, [0x93; 16]).unwrap();
        store
            .create_conversation(NewConversation {
                conversation_id: RuntimeId::from_bytes(RuntimeIdKind::Conversation, [0x92; 16])
                    .unwrap(),
                adapter_state_key,
                descriptor: ConversationDescriptor {
                    agent_kind: AgentKind::ClaudeCode,
                    title: Some("rebuild".to_owned()),
                    cwd: PathBuf::from("/tmp/agentdeck-cc-history"),
                },
            })
            .await
            .expect("create managed conversation");
        let repository = ClaudeCodeStateRepository::new_for_test(store.clone());
        rebuild_managed_index_at(&repository, adapter_state_key, &native, projects.clone())
            .await
            .expect("verified native rebuild");
        assert_eq!(
            repository
                .resolve(adapter_state_key)
                .await
                .expect("resolve rebuilt mapping"),
            Some(native.thread_id.clone())
        );
        let exact = resolve_native_projection_reference(&repository, adapter_state_key)
            .await
            .expect("metadata/history seam resolves exact NativeTranscriptRefV1 from vault");
        assert_eq!(exact.resume_thread_id().unwrap(), native_id);
        assert!(!format!("{exact:?}").contains(native_id));
        store.shutdown().await.expect("shutdown rebuild store");

        let storage_kek =
            load_or_create_storage_kek(&keys, &database).expect("reload rebuild StorageKEK");
        let reopened =
            RuntimeStoreHandle::open(RuntimeStoreConfig::new(database.clone()), storage_kek)
                .await
                .expect("reopen rebuild store");
        assert_eq!(
            ClaudeCodeStateRepository::new_for_test(reopened.clone())
                .resolve(adapter_state_key)
                .await
                .expect("resolve rebuilt mapping after restart"),
            Some(native.thread_id.clone())
        );

        let duplicate = projects.join("-tmp-rebuild-duplicate");
        std::fs::create_dir_all(&duplicate).unwrap();
        std::fs::write(
            duplicate.join(format!("{native_id}.jsonl")),
            r#"{"type":"user","uuid":"32000000-0000-4000-8000-000000000032","parentUuid":null,"message":{"role":"user","content":"duplicate"}}"#,
        )
        .unwrap();
        assert_eq!(
            rebuild_managed_index_at(
                &ClaudeCodeStateRepository::new_for_test(reopened.clone()),
                adapter_state_key,
                &native,
                projects.clone(),
            )
            .await
            .expect_err("ambiguous native history must fail before bind")
            .code,
            "cc-history-native-entry-ambiguous"
        );
        reopened.shutdown().await.expect("shutdown reopened store");

        assert!(!home.join("cc-meta").exists());
        assert!(
            !home
                .join("Library")
                .join("Application Support")
                .join("AgentDeck")
                .join("cc-meta")
                .exists()
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    #[cfg(unix)]
    #[test]
    fn list_history_applies_limit_before_scanning_titles() {
        use std::io::Write;
        use std::sync::mpsc;
        use std::time::Duration;

        let home = tempdir_unique();
        let root = home.join(".claude").join("projects");
        let project = root.join(encode_cwd(Path::new("/tmp/agentdeck")));
        std::fs::create_dir_all(&project).unwrap();

        let newest = project.join("00000000-0000-0000-0000-000000000100.jsonl");
        std::fs::write(
            &newest,
            r#"{"type":"user","message":{"role":"user","content":"newest prompt"}}"#,
        )
        .unwrap();
        let future = std::time::SystemTime::now() + std::time::Duration::from_secs(60);
        std::fs::File::open(&newest)
            .unwrap()
            .set_modified(future)
            .unwrap();

        let stale_fifo = project.join("00000000-0000-0000-0000-000000000001.jsonl");
        let status = std::process::Command::new("mkfifo")
            .arg(&stale_fifo)
            .status()
            .unwrap();
        assert!(
            status.success(),
            "mkfifo should create a blocking stale candidate"
        );

        let root_for_thread = root.clone();
        let (tx, rx) = mpsc::channel();
        let handle = std::thread::spawn(move || {
            let result = list_history_from_jsonl_root(&root_for_thread, None, 1);
            let _ = tx.send(result);
        });

        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(result) => {
                let items = result.unwrap();
                assert_eq!(items.len(), 1);
                assert_eq!(items[0].thread_id.0, "00000000-0000-0000-0000-000000000100");
            }
            Err(_) => {
                let mut writer = std::fs::OpenOptions::new()
                    .write(true)
                    .open(&stale_fifo)
                    .unwrap();
                writeln!(
                    writer,
                    r#"{{"type":"user","message":{{"role":"user","content":"stale prompt"}}}}"#
                )
                .unwrap();
                drop(writer);
                let _ = handle.join();
                let _ = std::fs::remove_dir_all(&home);
                panic!("history list blocked while scanning a truncated-out stale title");
            }
        }

        let _ = handle.join();
        let _ = std::fs::remove_dir_all(&home);
    }

    fn tempdir_unique() -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!(
            "agentdeck-cc-history-test-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
            seq
        ));
        std::fs::create_dir_all(&base).unwrap();
        base
    }
}
