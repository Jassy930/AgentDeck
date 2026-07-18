//! Claude Code 原生历史的 daemon-private 安全读取边界。
//!
//! 本模块只信任 OS account home 与已打开的 directory/file descriptor。目录名只用于
//! `openat`，不把 transcript path、session id 或 private reference 暴露到 wire/log。
//! 同 UID 在线攻击者属于明确 residual risk；这里不实现 pathname/inode race 取证。

use std::collections::{HashMap, HashSet};
use std::ffi::{CString, OsStr, OsString};
use std::fs::{File, ReadDir};
use std::io::{self, BufRead, BufReader};
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::{Path, PathBuf};
use std::time::Instant;

use agentdeck_protocol::{AgentItem, AgentItemMeta};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use super::{json_value_is_memory_agent, tool_result_to_agent_item, tool_use_to_agent_item};

const PRIVATE_REF_MAGIC: &[u8; 8] = b"ADCCNREF";
const PRIVATE_REF_VERSION: u8 = 1;
const PRIVATE_REF_HEADER_LEN: usize = PRIVATE_REF_MAGIC.len() + 1 + 2 + 2;
const MAX_COMPONENT_BYTES: usize = 255;
const KEY_DOMAIN_TURN: &[u8] = b"agentdeck.cc.native-turn.v1\0";
const KEY_DOMAIN_ITEM: &[u8] = b"agentdeck.cc.native-item.v1\0";

#[derive(Debug, Error)]
pub(in crate::claude_code) enum NativeHistoryError {
    #[error("OS account home is unavailable for Claude Code history")]
    HomeUnavailable,
    #[error("Claude Code native history source is unavailable during {operation}")]
    SourceUnavailable { operation: &'static str },
    #[error("Claude Code native history source is unsafe at {level}: {reason}")]
    SourceUnsafe {
        level: &'static str,
        reason: &'static str,
    },
    #[error("Claude Code native history IO failed during {operation} (errno={errno:?})")]
    Io {
        operation: &'static str,
        errno: Option<i32>,
    },
    #[error("Claude Code native private reference is malformed")]
    InvalidReference,
    #[error("Claude Code native private reference version is unsupported")]
    UnsupportedReferenceVersion,
    #[error("Claude Code native history byte budget is exhausted")]
    ByteBudget,
    #[error("Claude Code native history time budget is exhausted")]
    TimeBudget,
    #[error("Claude Code native history line {line} exceeds its bound")]
    LineTooLarge { line: u64 },
    #[error("Claude Code native history record/item limit is exceeded")]
    RecordLimit,
    #[error("Claude Code native history line {line} is malformed")]
    Malformed { line: u64 },
    #[error("Claude Code native history line {line} has no canonical stable key")]
    InvalidKey { line: u64 },
    #[error("Claude Code native history line {line} duplicates a stable key")]
    DuplicateKey { line: u64 },
    #[error("Claude Code native history line {line} has no verified parent turn")]
    MissingParent { line: u64 },
    #[error("Claude Code native history scan generation must be non-zero")]
    InvalidScanGeneration,
    #[error("Claude Code native history candidate acknowledgement is invalid")]
    InvalidCandidateAcknowledgement,
    #[error("Claude Code native history scan failed before completion")]
    ScanFailed,
    #[error("Claude Code native history scan is incomplete")]
    ScanIncomplete,
}

impl NativeHistoryError {
    pub(super) const fn code(&self) -> &'static str {
        match self {
            Self::HomeUnavailable => "cc-history-native-home-unavailable",
            Self::SourceUnavailable { .. } => "cc-history-native-source-unavailable",
            Self::SourceUnsafe { .. } => "cc-history-native-source-unsafe",
            Self::Io { .. } => "cc-history-native-source-read",
            Self::InvalidReference => "cc-history-native-ref-invalid",
            Self::UnsupportedReferenceVersion => "cc-history-native-ref-version",
            Self::ByteBudget => "cc-history-native-budget-bytes",
            Self::TimeBudget => "cc-history-native-budget-time",
            Self::LineTooLarge { .. } | Self::RecordLimit => "cc-history-native-too-large",
            Self::Malformed { .. } => "cc-history-native-malformed",
            Self::InvalidKey { .. } | Self::MissingParent { .. } => "cc-history-native-key-invalid",
            Self::DuplicateKey { .. } => "cc-history-native-duplicate-key",
            Self::InvalidScanGeneration => "cc-history-native-scan-generation-invalid",
            Self::InvalidCandidateAcknowledgement => "cc-history-native-scan-ack-invalid",
            Self::ScanFailed => "cc-history-native-scan-failed",
            Self::ScanIncomplete => "cc-history-native-scan-incomplete",
        }
    }
}

/// 经验证的 project component + transcript filename。二者都保留 Unix 原始字节，
/// Debug 永远不输出内容。
#[derive(Clone, Eq, PartialEq, Hash)]
pub(in crate::claude_code) struct NativeTranscriptRefV1 {
    project_component: OsString,
    transcript_filename: OsString,
}

impl NativeTranscriptRefV1 {
    fn from_verified_components(
        project_component: OsString,
        transcript_filename: OsString,
    ) -> Result<Self, NativeHistoryError> {
        validate_component(&project_component, false)?;
        validate_component(&transcript_filename, true)?;
        Ok(Self {
            project_component,
            transcript_filename,
        })
    }

    #[cfg(test)]
    pub(in crate::claude_code) fn from_components_for_test(
        project_component: OsString,
        transcript_filename: OsString,
    ) -> Result<Self, NativeHistoryError> {
        Self::from_verified_components(project_component, transcript_filename)
    }

    pub(in crate::claude_code) fn encode(&self) -> Vec<u8> {
        let project = os_bytes(&self.project_component);
        let transcript = os_bytes(&self.transcript_filename);
        let mut encoded =
            Vec::with_capacity(PRIVATE_REF_HEADER_LEN + project.len() + transcript.len());
        encoded.extend_from_slice(PRIVATE_REF_MAGIC);
        encoded.push(PRIVATE_REF_VERSION);
        encoded.extend_from_slice(&(project.len() as u16).to_be_bytes());
        encoded.extend_from_slice(&(transcript.len() as u16).to_be_bytes());
        encoded.extend_from_slice(project);
        encoded.extend_from_slice(transcript);
        encoded
    }

    #[cfg(test)]
    pub(super) fn encoded_bytes_for_test(&self) -> Vec<u8> {
        self.encode()
    }

    pub(in crate::claude_code) fn decode(encoded: &[u8]) -> Result<Self, NativeHistoryError> {
        if encoded.len() < PRIVATE_REF_HEADER_LEN
            || &encoded[..PRIVATE_REF_MAGIC.len()] != PRIVATE_REF_MAGIC
        {
            return Err(NativeHistoryError::InvalidReference);
        }
        if encoded[PRIVATE_REF_MAGIC.len()] != PRIVATE_REF_VERSION {
            return Err(NativeHistoryError::UnsupportedReferenceVersion);
        }
        let lengths = &encoded[PRIVATE_REF_MAGIC.len() + 1..PRIVATE_REF_HEADER_LEN];
        let project_len = usize::from(u16::from_be_bytes([lengths[0], lengths[1]]));
        let transcript_len = usize::from(u16::from_be_bytes([lengths[2], lengths[3]]));
        let expected = PRIVATE_REF_HEADER_LEN
            .checked_add(project_len)
            .and_then(|value| value.checked_add(transcript_len))
            .ok_or(NativeHistoryError::InvalidReference)?;
        if expected != encoded.len() {
            return Err(NativeHistoryError::InvalidReference);
        }
        let project_start = PRIVATE_REF_HEADER_LEN;
        let transcript_start = project_start + project_len;
        Self::from_verified_components(
            os_string_from_bytes(&encoded[project_start..transcript_start]),
            os_string_from_bytes(&encoded[transcript_start..]),
        )
    }

    pub(in crate::claude_code) fn is_encoded(encoded: &[u8]) -> bool {
        encoded.starts_with(PRIVATE_REF_MAGIC)
    }

    pub(in crate::claude_code) fn resume_thread_id(&self) -> Result<String, NativeHistoryError> {
        let filename = os_bytes(&self.transcript_filename);
        let stem = filename
            .strip_suffix(b".jsonl")
            .ok_or(NativeHistoryError::InvalidReference)?;
        let value = std::str::from_utf8(stem).map_err(|_| NativeHistoryError::InvalidReference)?;
        if !safe_legacy_session_id(value) {
            return Err(NativeHistoryError::InvalidReference);
        }
        Ok(value.to_owned())
    }

    pub(super) fn project_component(&self) -> &OsStr {
        &self.project_component
    }

    pub(super) fn transcript_filename(&self) -> &OsStr {
        &self.transcript_filename
    }
}

impl std::fmt::Debug for NativeTranscriptRefV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("NativeTranscriptRefV1([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub(super) struct NativeTurnKey([u8; 32]);

impl NativeTurnKey {
    pub(super) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for NativeTurnKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("NativeTurnKey([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub(super) struct NativeItemKey([u8; 32]);

impl NativeItemKey {
    pub(super) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[cfg(test)]
    pub(super) fn as_bytes_for_test(self) -> [u8; 32] {
        self.0
    }
}

impl std::fmt::Debug for NativeItemKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("NativeItemKey([REDACTED])")
    }
}

pub(super) struct NativeHistoryItem {
    key: NativeItemKey,
    turn_key: NativeTurnKey,
    pub(super) item: AgentItem,
}

impl NativeHistoryItem {
    pub(super) fn key(&self) -> NativeItemKey {
        self.key
    }

    pub(super) fn turn_key(&self) -> NativeTurnKey {
        self.turn_key
    }

    pub(super) fn into_item(self) -> AgentItem {
        self.item
    }
}

impl std::fmt::Debug for NativeHistoryItem {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("NativeHistoryItem([REDACTED])")
    }
}

pub(super) struct NativeHistoryTurn {
    key: NativeTurnKey,
    items: Vec<NativeHistoryItem>,
}

impl NativeHistoryTurn {
    pub(super) fn key(&self) -> NativeTurnKey {
        self.key
    }

    #[cfg(test)]
    pub(super) fn items(&self) -> &[NativeHistoryItem] {
        &self.items
    }

    pub(super) fn into_items(self) -> Vec<NativeHistoryItem> {
        self.items
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum NativeTailState {
    Complete,
    IncompleteIgnored,
}

pub(super) struct NativeHistoryDocument {
    turns: Vec<NativeHistoryTurn>,
    tail: NativeTailState,
}

impl NativeHistoryDocument {
    pub(super) fn turns(&self) -> &[NativeHistoryTurn] {
        &self.turns
    }

    #[cfg(test)]
    pub(super) fn tail(&self) -> NativeTailState {
        self.tail
    }

    pub(super) fn into_turns(self) -> Vec<NativeHistoryTurn> {
        self.turns
    }
}

impl std::fmt::Debug for NativeHistoryDocument {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeHistoryDocument")
            .field("turn_count", &self.turns.len())
            .field("tail", &self.tail)
            .finish()
    }
}

#[derive(Debug)]
pub(super) enum NativeReadOutcome {
    Document(NativeHistoryDocument),
    FilteredObserver,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum NativeScanStop {
    CandidateLimit,
    Deadline,
}

#[derive(Debug)]
pub(super) enum NativeScanStep {
    Candidate(NativeHistoryCandidate),
    Yielded(NativeScanStop),
    Complete,
}

pub(super) struct NativeHistoryCandidate {
    reference: NativeTranscriptRefV1,
    pub(super) size_bytes: u64,
    acknowledgement: NativeCandidateAcknowledgement,
}

impl NativeHistoryCandidate {
    pub(super) fn reference(&self) -> &NativeTranscriptRefV1 {
        &self.reference
    }
}

impl std::fmt::Debug for NativeHistoryCandidate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeHistoryCandidate")
            .field("reference", &"[REDACTED]")
            .field("size_bytes", &self.size_bytes)
            .finish()
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct NativeCandidateAcknowledgement {
    generation: [u8; 16],
    token: [u8; 16],
}

struct PendingNativeCandidate {
    reference: NativeTranscriptRefV1,
    size_bytes: u64,
    acknowledgement: NativeCandidateAcknowledgement,
    charged: bool,
}

impl PendingNativeCandidate {
    fn delivery(&self) -> NativeHistoryCandidate {
        NativeHistoryCandidate {
            reference: self.reference.clone(),
            size_bytes: self.size_bytes,
            acknowledgement: self.acknowledgement,
        }
    }
}

/// 只有完整遍历真实目录、逐个确认全部 candidate 后才能取得的 generation witness。
///
/// 字段与 production constructor 都留在本 scanner 模块；Runtime Store 只消费本
/// opaque type，不能用裸 generation 伪造完成状态。
pub(crate) struct CompletedNativeScan {
    generation: [u8; 16],
    acknowledged_candidates: u64,
}

impl CompletedNativeScan {
    pub(crate) const fn into_generation(self) -> [u8; 16] {
        self.generation
    }

    #[cfg(test)]
    pub(crate) const fn generation(&self) -> [u8; 16] {
        self.generation
    }

    #[cfg(test)]
    pub(crate) const fn acknowledged_candidates(&self) -> u64 {
        self.acknowledged_candidates
    }
}

impl std::fmt::Debug for CompletedNativeScan {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CompletedNativeScan")
            .field("generation", &"[REDACTED]")
            .field("acknowledged_candidates", &self.acknowledged_candidates)
            .finish()
    }
}

pub(super) struct NativeIoBudget {
    candidates_remaining: u32,
    bytes_remaining: u64,
    bytes_read: u64,
    deadline: Instant,
}

impl NativeIoBudget {
    pub(super) fn new(candidate_limit: u32, byte_limit: u64, deadline: Instant) -> Self {
        Self {
            candidates_remaining: candidate_limit,
            bytes_remaining: byte_limit,
            bytes_read: 0,
            deadline,
        }
    }

    #[cfg(test)]
    pub(super) fn bytes_read(&self) -> u64 {
        self.bytes_read
    }

    fn deadline_reached(&self) -> bool {
        Instant::now() >= self.deadline
    }

    fn charge_candidate(&mut self) -> Result<(), NativeScanStop> {
        if self.deadline_reached() {
            return Err(NativeScanStop::Deadline);
        }
        if self.candidates_remaining == 0 {
            return Err(NativeScanStop::CandidateLimit);
        }
        self.candidates_remaining -= 1;
        Ok(())
    }

    fn read_cap(&self, line_limit: u64) -> Result<u64, NativeHistoryError> {
        if self.deadline_reached() {
            return Err(NativeHistoryError::TimeBudget);
        }
        Ok(self.bytes_remaining.min(line_limit).saturating_add(1))
    }

    fn charge_bytes(&mut self, amount: u64) -> Result<(), NativeHistoryError> {
        self.bytes_read = self
            .bytes_read
            .checked_add(amount)
            .ok_or(NativeHistoryError::ByteBudget)?;
        if amount > self.bytes_remaining {
            self.bytes_remaining = 0;
            return Err(NativeHistoryError::ByteBudget);
        }
        self.bytes_remaining -= amount;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct NativeParseLimits {
    pub max_line_bytes: u64,
    pub max_records: u64,
    pub max_items: usize,
}

impl Default for NativeParseLimits {
    fn default() -> Self {
        Self {
            max_line_bytes: 64 * 1024 * 1024,
            max_records: 100_000,
            max_items: 10_000,
        }
    }
}

/// OS account home 是唯一生产路径来源；`HOME` 不参与解析。
#[cfg(test)]
pub(super) fn current_projects_path() -> Result<PathBuf, NativeHistoryError> {
    crate::config::current_user_home()
        .map(|home| home.join(".claude").join("projects"))
        .map_err(|_| NativeHistoryError::HomeUnavailable)
}

pub(super) struct NativeHistorySource {
    projects: File,
    projects_path: PathBuf,
    expected_uid: libc::uid_t,
}

impl NativeHistorySource {
    pub(super) fn for_current_account() -> Result<Self, NativeHistoryError> {
        let home =
            crate::config::current_user_home().map_err(|_| NativeHistoryError::HomeUnavailable)?;
        // SAFETY: geteuid has no preconditions and reads only process credentials.
        let expected_uid = unsafe { libc::geteuid() };
        Self::from_home(&home, expected_uid)
    }

    #[cfg(test)]
    pub(super) fn from_home_for_test(
        home: &Path,
        expected_uid: libc::uid_t,
    ) -> Result<Self, NativeHistoryError> {
        Self::from_home(home, expected_uid)
    }

    pub(super) fn from_home(
        home: &Path,
        expected_uid: libc::uid_t,
    ) -> Result<Self, NativeHistoryError> {
        let home_directory = open_directory_path(home, "home", expected_uid)?;
        let claude = open_directory_at(
            &home_directory,
            OsStr::new(".claude"),
            "claude",
            expected_uid,
        )?;
        let projects =
            open_directory_at(&claude, OsStr::new("projects"), "projects", expected_uid)?;
        Ok(Self {
            projects,
            projects_path: home.join(".claude").join("projects"),
            expected_uid,
        })
    }

    pub(super) fn scanner(
        &self,
        generation: [u8; 16],
    ) -> Result<NativeHistoryScanner, NativeHistoryError> {
        if generation == [0; 16] {
            return Err(NativeHistoryError::InvalidScanGeneration);
        }
        let projects = self
            .projects
            .try_clone()
            .map_err(|error| io_error("clone projects fd", error))?;
        let entries = std::fs::read_dir(&self.projects_path)
            .map_err(|error| io_error("enumerate projects", error))?;
        Ok(NativeHistoryScanner {
            projects,
            projects_path: self.projects_path.clone(),
            expected_uid: self.expected_uid,
            projects_entries: entries,
            current_project: None,
            generation,
            pending: None,
            acknowledged_candidates: 0,
            exhausted: false,
            failed: false,
        })
    }

    pub(super) fn read(
        &self,
        reference: &NativeTranscriptRefV1,
        budget: &mut NativeIoBudget,
        limits: NativeParseLimits,
    ) -> Result<NativeReadOutcome, NativeHistoryError> {
        if is_observer_component(reference.project_component()) {
            return Ok(NativeReadOutcome::FilteredObserver);
        }
        let project = open_directory_at(
            &self.projects,
            reference.project_component(),
            "project",
            self.expected_uid,
        )?;
        let transcript = open_regular_at(
            &project,
            reference.transcript_filename(),
            "transcript",
            self.expected_uid,
        )?;
        parse_native_jsonl(BufReader::new(transcript), budget, limits, false)
    }
}

impl std::fmt::Debug for NativeHistorySource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("NativeHistorySource([REDACTED])")
    }
}

struct CurrentProject {
    component: OsString,
    directory: File,
    entries: ReadDir,
}

pub(super) struct NativeHistoryScanner {
    projects: File,
    projects_path: PathBuf,
    expected_uid: libc::uid_t,
    projects_entries: ReadDir,
    current_project: Option<CurrentProject>,
    generation: [u8; 16],
    pending: Option<PendingNativeCandidate>,
    acknowledged_candidates: u64,
    exhausted: bool,
    failed: bool,
}

impl NativeHistoryScanner {
    pub(super) fn next(
        &mut self,
        budget: &mut NativeIoBudget,
    ) -> Result<NativeScanStep, NativeHistoryError> {
        if self.failed {
            return Err(NativeHistoryError::ScanFailed);
        }
        if self.exhausted {
            return Ok(NativeScanStep::Complete);
        }
        if self
            .pending
            .as_ref()
            .is_some_and(|pending| !pending.charged)
        {
            if let Err(stop) = budget.charge_candidate() {
                return Ok(NativeScanStep::Yielded(stop));
            }
            self.pending
                .as_mut()
                .expect("pending candidate remains present")
                .charged = true;
        }
        if let Some(pending) = self.pending.as_ref() {
            return Ok(NativeScanStep::Candidate(pending.delivery()));
        }

        let result = self.next_unpoisoned(budget);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn next_unpoisoned(
        &mut self,
        budget: &mut NativeIoBudget,
    ) -> Result<NativeScanStep, NativeHistoryError> {
        if budget.deadline_reached() {
            return Ok(NativeScanStep::Yielded(NativeScanStop::Deadline));
        }
        if budget.candidates_remaining == 0 {
            return Ok(NativeScanStep::Yielded(NativeScanStop::CandidateLimit));
        }
        loop {
            if budget.deadline_reached() {
                return Ok(NativeScanStep::Yielded(NativeScanStop::Deadline));
            }
            if let Some(project) = self.current_project.as_mut() {
                match project.entries.next() {
                    Some(Ok(entry)) => {
                        let filename = entry.file_name();
                        if !os_bytes(&filename).ends_with(b".jsonl") {
                            continue;
                        }
                        let file_type = entry
                            .file_type()
                            .map_err(|error| io_error("inspect transcript entry", error))?;
                        if file_type.is_symlink() || !file_type.is_file() {
                            return Err(unsafe_source(
                                "transcript",
                                "entry is not a real regular file",
                            ));
                        }
                        let file = open_regular_at(
                            &project.directory,
                            &filename,
                            "transcript",
                            self.expected_uid,
                        )?;
                        let size_bytes = file
                            .metadata()
                            .map_err(|error| io_error("inspect transcript fd", error))?
                            .len();
                        let reference = NativeTranscriptRefV1::from_verified_components(
                            project.component.clone(),
                            filename,
                        )?;
                        let pending = PendingNativeCandidate {
                            reference,
                            size_bytes,
                            acknowledgement: NativeCandidateAcknowledgement {
                                generation: self.generation,
                                token: *Uuid::new_v4().as_bytes(),
                            },
                            charged: false,
                        };
                        self.pending = Some(pending);
                        if let Err(stop) = budget.charge_candidate() {
                            return Ok(NativeScanStep::Yielded(stop));
                        }
                        let pending = self
                            .pending
                            .as_mut()
                            .expect("new pending candidate remains present");
                        pending.charged = true;
                        return Ok(NativeScanStep::Candidate(pending.delivery()));
                    }
                    Some(Err(error)) => return Err(io_error("enumerate transcript entry", error)),
                    None => {
                        self.current_project = None;
                        continue;
                    }
                }
            }

            let Some(entry) = self.projects_entries.next() else {
                self.exhausted = true;
                return Ok(NativeScanStep::Complete);
            };
            let entry = entry.map_err(|error| io_error("enumerate project entry", error))?;
            let component = entry.file_name();
            if is_observer_component(&component) {
                continue;
            }
            let file_type = entry
                .file_type()
                .map_err(|error| io_error("inspect project entry", error))?;
            if file_type.is_symlink() {
                return Err(unsafe_source(
                    "project",
                    "symlink project component is forbidden",
                ));
            }
            if !file_type.is_dir() {
                continue;
            }
            let directory =
                open_directory_at(&self.projects, &component, "project", self.expected_uid)?;
            let entries = std::fs::read_dir(self.projects_path.join(&component))
                .map_err(|error| io_error("enumerate project transcript entries", error))?;
            self.current_project = Some(CurrentProject {
                component,
                directory,
                entries,
            });
        }
    }

    /// 只有当前 pending candidate 自身携带的 opaque token 才能推进扫描。
    pub(super) fn acknowledge(
        &mut self,
        candidate: NativeHistoryCandidate,
    ) -> Result<(), NativeHistoryError> {
        let Some(pending) = self.pending.as_ref() else {
            return Err(NativeHistoryError::InvalidCandidateAcknowledgement);
        };
        if candidate.acknowledgement != pending.acknowledgement {
            return Err(NativeHistoryError::InvalidCandidateAcknowledgement);
        }
        self.pending = None;
        self.acknowledged_candidates = self
            .acknowledged_candidates
            .checked_add(1)
            .ok_or(NativeHistoryError::ScanFailed)?;
        Ok(())
    }

    /// 消费 scanner，阻止 partial/yield/error/drop 路径伪造完整 generation witness。
    pub(super) fn into_completed_scan(self) -> Result<CompletedNativeScan, NativeHistoryError> {
        if self.failed || !self.exhausted || self.pending.is_some() {
            return Err(NativeHistoryError::ScanIncomplete);
        }
        Ok(CompletedNativeScan {
            generation: self.generation,
            acknowledged_candidates: self.acknowledged_candidates,
        })
    }
}

impl std::fmt::Debug for NativeHistoryScanner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("NativeHistoryScanner([REDACTED])")
    }
}

pub(super) fn parse_native_jsonl<R: BufRead>(
    mut reader: R,
    budget: &mut NativeIoBudget,
    limits: NativeParseLimits,
    observer_project: bool,
) -> Result<NativeReadOutcome, NativeHistoryError> {
    if observer_project {
        return Ok(NativeReadOutcome::FilteredObserver);
    }

    let mut state = NativeParserState::new(limits.max_items);
    let mut line = Vec::new();
    let mut line_number = 0_u64;
    let mut tail = NativeTailState::Complete;
    loop {
        line.clear();
        let cap = budget.read_cap(limits.max_line_bytes)?;
        let read = std::io::Read::take(&mut reader, cap)
            .read_until(b'\n', &mut line)
            .map_err(|error| io_error("read transcript line", error))?;
        if read == 0 {
            break;
        }
        let read_u64 = u64::try_from(read).map_err(|_| NativeHistoryError::ByteBudget)?;
        budget.charge_bytes(read_u64)?;
        line_number = line_number
            .checked_add(1)
            .ok_or(NativeHistoryError::RecordLimit)?;
        if read_u64 > limits.max_line_bytes {
            return Err(NativeHistoryError::LineTooLarge { line: line_number });
        }
        let had_newline = line.last() == Some(&b'\n');
        if had_newline {
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
        }
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        if state.record_count >= limits.max_records {
            return Err(NativeHistoryError::RecordLimit);
        }
        let value: Value = match serde_json::from_slice(&line) {
            Ok(value) => value,
            Err(error) if !had_newline && error.classify() == serde_json::error::Category::Eof => {
                tail = NativeTailState::IncompleteIgnored;
                break;
            }
            Err(_) => return Err(NativeHistoryError::Malformed { line: line_number }),
        };
        if !value.is_object() {
            return Err(NativeHistoryError::Malformed { line: line_number });
        }
        state.record_count += 1;
        if json_value_is_memory_agent(&value) {
            return Ok(NativeReadOutcome::FilteredObserver);
        }
        state.consume(&value, line_number)?;
    }

    Ok(NativeReadOutcome::Document(NativeHistoryDocument {
        turns: state.turns,
        tail,
    }))
}

struct NativeParserState {
    turns: Vec<NativeHistoryTurn>,
    turn_indexes: HashMap<NativeTurnKey, usize>,
    record_turns: HashMap<Uuid, Option<NativeTurnKey>>,
    seen_records: HashSet<Uuid>,
    seen_items: HashSet<NativeItemKey>,
    seen_tool_ids: HashSet<String>,
    in_flight: HashMap<String, (String, Value)>,
    record_count: u64,
    item_limit: usize,
}

impl NativeParserState {
    fn new(item_limit: usize) -> Self {
        Self {
            turns: Vec::new(),
            turn_indexes: HashMap::new(),
            record_turns: HashMap::new(),
            seen_records: HashSet::new(),
            seen_items: HashSet::new(),
            seen_tool_ids: HashSet::new(),
            in_flight: HashMap::new(),
            record_count: 0,
            item_limit,
        }
    }

    fn consume(&mut self, value: &Value, line: u64) -> Result<(), NativeHistoryError> {
        let kind = value.get("type").and_then(Value::as_str).unwrap_or("");
        let content = value
            .get("message")
            .and_then(|message| message.get("content"));
        let is_root_user = kind == "user"
            && (content.and_then(Value::as_str).is_some()
                || content
                    .and_then(Value::as_array)
                    .is_some_and(|blocks| blocks.iter().any(is_user_text_block)));
        let item_bearing = is_root_user
            || (kind == "assistant"
                && content
                    .and_then(Value::as_array)
                    .is_some_and(|blocks| blocks.iter().any(is_supported_assistant_block)))
            || (kind == "user"
                && content
                    .and_then(Value::as_array)
                    .is_some_and(|blocks| blocks.iter().any(is_tool_result_block)));

        let record_uuid = match value.get("uuid") {
            Some(Value::String(raw)) => Some(canonical_uuid(raw, line)?),
            Some(_) => return Err(NativeHistoryError::InvalidKey { line }),
            None if item_bearing => return Err(NativeHistoryError::InvalidKey { line }),
            None => None,
        };
        if let Some(record_uuid) = record_uuid
            && !self.seen_records.insert(record_uuid)
        {
            return Err(NativeHistoryError::DuplicateKey { line });
        }

        let parent_uuid = match value.get("parentUuid") {
            Some(Value::String(raw)) => Some(canonical_uuid(raw, line)?),
            Some(Value::Null) | None => None,
            Some(_) => return Err(NativeHistoryError::InvalidKey { line }),
        };
        let inherited_turn = parent_uuid
            .and_then(|parent| self.record_turns.get(&parent))
            .copied()
            .flatten();
        let turn_key = if is_root_user {
            Some(derive_turn_key(
                record_uuid.expect("item-bearing UUID checked"),
            ))
        } else {
            inherited_turn
        };
        if item_bearing && turn_key.is_none() {
            return Err(NativeHistoryError::MissingParent { line });
        }
        if let Some(turn_key) = turn_key {
            self.ensure_turn(turn_key);
        }

        match kind {
            "user" => self.consume_user(content, record_uuid, turn_key, line)?,
            "assistant" => self.consume_assistant(content, record_uuid, turn_key, line)?,
            _ => {}
        }
        if let Some(record_uuid) = record_uuid {
            self.record_turns.insert(record_uuid, turn_key);
        }
        Ok(())
    }

    fn consume_user(
        &mut self,
        content: Option<&Value>,
        record_uuid: Option<Uuid>,
        turn_key: Option<NativeTurnKey>,
        line: u64,
    ) -> Result<(), NativeHistoryError> {
        let Some(record_uuid) = record_uuid else {
            return Ok(());
        };
        let Some(turn_key) = turn_key else {
            return Ok(());
        };
        if let Some(text) = content.and_then(Value::as_str) {
            self.push_item(
                turn_key,
                derive_item_key(record_uuid, b"user-text", None),
                AgentItem::UserMessage {
                    text: text.to_owned(),
                    meta: AgentItemMeta::default(),
                },
                line,
            )?;
            return Ok(());
        }
        let Some(blocks) = content.and_then(Value::as_array) else {
            return Ok(());
        };
        for block in blocks {
            match block.get("type").and_then(Value::as_str) {
                Some("text") => {
                    if let Some(text) = block.get("text").and_then(Value::as_str) {
                        self.push_item(
                            turn_key,
                            derive_item_key(record_uuid, b"user-text", None),
                            AgentItem::UserMessage {
                                text: text.to_owned(),
                                meta: AgentItemMeta::default(),
                            },
                            line,
                        )?;
                    }
                }
                Some("tool_result") => {
                    let tool_id = block
                        .get("tool_use_id")
                        .and_then(Value::as_str)
                        .filter(|value| !value.is_empty())
                        .ok_or(NativeHistoryError::InvalidKey { line })?;
                    let is_error = block
                        .get("is_error")
                        .and_then(Value::as_bool)
                        .unwrap_or(false);
                    let text = super::extract_tool_result_text(block);
                    let (name, input) = self
                        .in_flight
                        .remove(tool_id)
                        .ok_or(NativeHistoryError::InvalidKey { line })?;
                    let item = tool_result_to_agent_item(&name, &input, is_error, &text);
                    self.push_item(
                        turn_key,
                        derive_item_key(record_uuid, b"tool-result", Some(tool_id.as_bytes())),
                        item,
                        line,
                    )?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn consume_assistant(
        &mut self,
        content: Option<&Value>,
        record_uuid: Option<Uuid>,
        turn_key: Option<NativeTurnKey>,
        line: u64,
    ) -> Result<(), NativeHistoryError> {
        let Some(record_uuid) = record_uuid else {
            return Ok(());
        };
        let Some(turn_key) = turn_key else {
            return Ok(());
        };
        let Some(blocks) = content.and_then(Value::as_array) else {
            return Ok(());
        };
        for block in blocks {
            match block.get("type").and_then(Value::as_str) {
                Some("text") => {
                    if let Some(text) = block.get("text").and_then(Value::as_str) {
                        self.push_item(
                            turn_key,
                            derive_item_key(record_uuid, b"assistant-text", None),
                            AgentItem::AssistantMessage {
                                text: text.to_owned(),
                                meta: AgentItemMeta::default(),
                            },
                            line,
                        )?;
                    }
                }
                Some("thinking") => {
                    if let Some(text) = block
                        .get("thinking")
                        .or_else(|| block.get("text"))
                        .and_then(Value::as_str)
                    {
                        self.push_item(
                            turn_key,
                            derive_item_key(record_uuid, b"assistant-thinking", None),
                            AgentItem::Reasoning {
                                text: text.to_owned(),
                                meta: AgentItemMeta::default(),
                            },
                            line,
                        )?;
                    }
                }
                Some("tool_use") => {
                    let tool_id = block
                        .get("id")
                        .and_then(Value::as_str)
                        .filter(|value| !value.is_empty())
                        .ok_or(NativeHistoryError::InvalidKey { line })?;
                    let name = block
                        .get("name")
                        .and_then(Value::as_str)
                        .filter(|value| !value.is_empty())
                        .ok_or(NativeHistoryError::InvalidKey { line })?;
                    if !self.seen_tool_ids.insert(tool_id.to_owned()) {
                        return Err(NativeHistoryError::DuplicateKey { line });
                    }
                    let input = block.get("input").cloned().unwrap_or(Value::Null);
                    self.in_flight
                        .insert(tool_id.to_owned(), (name.to_owned(), input.clone()));
                    self.push_item(
                        turn_key,
                        derive_item_key(record_uuid, b"tool-use", Some(tool_id.as_bytes())),
                        tool_use_to_agent_item(name, &input),
                        line,
                    )?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn ensure_turn(&mut self, turn_key: NativeTurnKey) {
        if self.turn_indexes.contains_key(&turn_key) {
            return;
        }
        let index = self.turns.len();
        self.turn_indexes.insert(turn_key, index);
        self.turns.push(NativeHistoryTurn {
            key: turn_key,
            items: Vec::new(),
        });
    }

    fn push_item(
        &mut self,
        turn_key: NativeTurnKey,
        item_key: NativeItemKey,
        item: AgentItem,
        line: u64,
    ) -> Result<(), NativeHistoryError> {
        if !self.seen_items.insert(item_key) {
            return Err(NativeHistoryError::DuplicateKey { line });
        }
        if self.seen_items.len() > self.item_limit {
            return Err(NativeHistoryError::RecordLimit);
        }
        let index = *self
            .turn_indexes
            .get(&turn_key)
            .ok_or(NativeHistoryError::MissingParent { line })?;
        self.turns[index].items.push(NativeHistoryItem {
            key: item_key,
            turn_key,
            item,
        });
        Ok(())
    }
}

fn derive_turn_key(uuid: Uuid) -> NativeTurnKey {
    NativeTurnKey(hash_key(KEY_DOMAIN_TURN, uuid, b"turn", None))
}

fn derive_item_key(uuid: Uuid, semantic_tag: &[u8], vendor_key: Option<&[u8]>) -> NativeItemKey {
    NativeItemKey(hash_key(KEY_DOMAIN_ITEM, uuid, semantic_tag, vendor_key))
}

fn hash_key(domain: &[u8], uuid: Uuid, semantic_tag: &[u8], vendor_key: Option<&[u8]>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(uuid.as_bytes());
    hasher.update((semantic_tag.len() as u32).to_be_bytes());
    hasher.update(semantic_tag);
    if let Some(vendor_key) = vendor_key {
        hasher.update((vendor_key.len() as u32).to_be_bytes());
        hasher.update(vendor_key);
    } else {
        hasher.update(0_u32.to_be_bytes());
    }
    hasher.finalize().into()
}

fn canonical_uuid(raw: &str, line: u64) -> Result<Uuid, NativeHistoryError> {
    let parsed = Uuid::parse_str(raw).map_err(|_| NativeHistoryError::InvalidKey { line })?;
    if parsed.hyphenated().to_string() != raw {
        return Err(NativeHistoryError::InvalidKey { line });
    }
    Ok(parsed)
}

fn is_user_text_block(value: &Value) -> bool {
    value.get("type").and_then(Value::as_str) == Some("text")
        && value.get("text").and_then(Value::as_str).is_some()
}

fn is_tool_result_block(value: &Value) -> bool {
    value.get("type").and_then(Value::as_str) == Some("tool_result")
}

fn is_supported_assistant_block(value: &Value) -> bool {
    matches!(
        value.get("type").and_then(Value::as_str),
        Some("text" | "thinking" | "tool_use")
    )
}

fn is_observer_component(component: &OsStr) -> bool {
    os_bytes(component)
        .windows(b"claude-mem-observer-sessions".len())
        .any(|window| window == b"claude-mem-observer-sessions")
}

fn validate_component(component: &OsStr, transcript: bool) -> Result<(), NativeHistoryError> {
    let bytes = os_bytes(component);
    if bytes.is_empty()
        || bytes.len() > MAX_COMPONENT_BYTES
        || bytes == b"."
        || bytes == b".."
        || bytes.contains(&b'/')
        || bytes.contains(&0)
        || (transcript && !bytes.ends_with(b".jsonl"))
    {
        return Err(NativeHistoryError::InvalidReference);
    }
    Ok(())
}

pub(in crate::claude_code) fn safe_legacy_session_id(value: &str) -> bool {
    (8..=128).contains(&value.len())
        && value.contains('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn open_directory_path(
    path: &Path,
    level: &'static str,
    expected_uid: libc::uid_t,
) -> Result<File, NativeHistoryError> {
    let name = cstring_path(path)?;
    // SAFETY: name is NUL-terminated; a successful fd is uniquely transferred to File.
    let fd = unsafe {
        libc::open(
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    owned_validated_fd(fd, level, expected_uid, libc::S_IFDIR)
}

fn open_directory_at(
    parent: &File,
    name: &OsStr,
    level: &'static str,
    expected_uid: libc::uid_t,
) -> Result<File, NativeHistoryError> {
    validate_component(name, false)?;
    let name = cstring_component(name)?;
    // SAFETY: parent/name are live; successful fd is uniquely transferred below.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    owned_validated_fd(fd, level, expected_uid, libc::S_IFDIR)
}

fn open_regular_at(
    parent: &File,
    name: &OsStr,
    level: &'static str,
    expected_uid: libc::uid_t,
) -> Result<File, NativeHistoryError> {
    validate_component(name, true)?;
    let name = cstring_component(name)?;
    // O_NONBLOCK prevents a static FIFO/device fixture from blocking before fstat rejects it.
    // SAFETY: parent/name are live; successful fd is uniquely transferred below.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    owned_validated_fd(fd, level, expected_uid, libc::S_IFREG)
}

fn owned_validated_fd(
    fd: libc::c_int,
    level: &'static str,
    expected_uid: libc::uid_t,
    expected_kind: libc::mode_t,
) -> Result<File, NativeHistoryError> {
    if fd < 0 {
        return Err(open_error(level, io::Error::last_os_error()));
    }
    // SAFETY: fd was returned uniquely by open/openat and is transferred exactly once.
    let file = unsafe { File::from_raw_fd(fd) };
    let mut status = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: file fd is live and status points to writable stat storage.
    if unsafe { libc::fstat(file.as_raw_fd(), status.as_mut_ptr()) } != 0 {
        return Err(io_error(
            "inspect opened native history fd",
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: successful fstat initialized status.
    let status = unsafe { status.assume_init() };
    if status.st_mode & libc::S_IFMT != expected_kind || status.st_uid != expected_uid {
        return Err(unsafe_source(
            level,
            "opened fd has the wrong type or owner",
        ));
    }
    Ok(file)
}

fn open_error(level: &'static str, error: io::Error) -> NativeHistoryError {
    match error.raw_os_error() {
        Some(libc::ELOOP | libc::ENOTDIR) => unsafe_source(level, "symlink or wrong entry type"),
        Some(libc::ENOENT) => NativeHistoryError::SourceUnavailable {
            operation: "open native history component",
        },
        _ => io_error("open native history component", error),
    }
}

fn unsafe_source(level: &'static str, reason: &'static str) -> NativeHistoryError {
    NativeHistoryError::SourceUnsafe { level, reason }
}

fn io_error(operation: &'static str, error: io::Error) -> NativeHistoryError {
    NativeHistoryError::Io {
        operation,
        errno: error.raw_os_error(),
    }
}

fn cstring_path(path: &Path) -> Result<CString, NativeHistoryError> {
    CString::new(os_bytes(path.as_os_str())).map_err(|_| unsafe_source("path", "path contains NUL"))
}

fn cstring_component(component: &OsStr) -> Result<CString, NativeHistoryError> {
    CString::new(os_bytes(component))
        .map_err(|_| unsafe_source("component", "component contains NUL"))
}

#[cfg(unix)]
fn os_bytes(value: &OsStr) -> &[u8] {
    use std::os::unix::ffi::OsStrExt;
    value.as_bytes()
}

#[cfg(unix)]
fn os_string_from_bytes(value: &[u8]) -> OsString {
    use std::os::unix::ffi::OsStringExt;
    OsString::from_vec(value.to_vec())
}
