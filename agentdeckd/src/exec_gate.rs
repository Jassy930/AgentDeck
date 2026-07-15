//! 当前 `agentdeckd --exec-gate` binary 的 pre-exec 私有 FD 子模式。
//!
//! gate 只接受继承的固定 FD 3；program/cwd/argv、execution nonce 与 release token
//! 都不进入 argv/env。gate 先建立独立 process group 并回报精确 PID/start-time，只有
//! exact release frame 与随机 token commitment 同时匹配后才 spawn vendor。gate 本身
//! 作为常驻 group-leader sentinel，直到 daemon 对整个 execution group 完成 fencing，
//! 禁止 vendor leader 先退出后只剩一个可复用的整数 PGID。

use std::env;
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

use crate::agent::{
    MAX_EXEC_ARGUMENT_BYTES, MAX_EXEC_ARGUMENTS, MAX_EXEC_CONTROL_FRAME_BYTES, MAX_EXEC_PATH_BYTES,
    MAX_EXEC_SINGLE_ARGUMENT_BYTES, exec_spec_control_frame_bytes,
};
use crate::runtime::model::MAX_EXECUTION_NONCE_BYTES;
use crate::runtime::process_identity::{ProcessIdentity, current_process_start_time};
use crate::runtime::store::{RuntimeId, RuntimeIdKind};

mod parent;

pub use parent::GatedChildIo;
pub(crate) use parent::{GatedChild, GatedChildOwner, GatedChildRelease};

pub(super) const CONTROL_FD: RawFd = 3;
pub(super) const GATE_PROTOCOL_VERSION: u16 = 1;
pub(super) const MAX_WIRE_FRAME_BYTES: usize = 512 * 1024;
pub(super) const RELEASE_TOKEN_BYTES: usize = 32;
pub(super) const TOKEN_COMMITMENT_BYTES: usize = 32;
pub(super) const SAFE_ENV_KEYS: &[&str] = &["HOME", "TMPDIR", "LANG", "LC_ALL", "TERM"];
pub(super) const SAFE_SYSTEM_PATH: &str =
    "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin";
const WIRE_MAGIC: [u8; 4] = *b"ADGX";
const WIRE_CODEC_VERSION: u16 = 1;
const PREPARE_TAG: u8 = 1;
const RELEASE_TAG: u8 = 2;
const READY_TAG: u8 = 3;
const ABORTED_TAG: u8 = 4;
const RUNTIME_ID_TEXT_BYTES: usize = 36;
const MAX_ERROR_CODE_BYTES: usize = 128;

/// 构造 exec gate parent、vendor resolver 与最终 vendor 共同使用的固定目录集合。
///
/// 系统目录固定在前；macOS 再追加由 `getpwuid_r(geteuid())` 得到的 account
/// `~/.local/bin`。这里不读取继承的 HOME/PATH，项目目录或 shell 注入不能改变集合。
pub(crate) fn trusted_vendor_path() -> OsString {
    let mut paths = env::split_paths(&OsString::from(SAFE_SYSTEM_PATH)).collect::<Vec<_>>();
    #[cfg(target_os = "macos")]
    if let Ok(home) = crate::config::current_user_home() {
        paths.push(home.join(".local/bin"));
    }
    env::join_paths(paths).expect("trusted vendor path contains only absolute OS paths")
}

/// 只从 exec gate 最终进程也会收到的固定目录集合解析 vendor binary。
///
/// 威胁场景：stable daemon 若继承含项目目录或其他用户可写目录的 `PATH`，typed
/// prepare 直接使用该 PATH 会在 gate 之前把伪造 vendor 固化成绝对路径，随后即使 gate
/// 清空环境也仍会执行它。这里拒绝带路径的名称，并让解析与最终 vendor PATH 使用同一信任根。
pub(crate) fn resolve_trusted_program(binary: &str) -> Option<PathBuf> {
    if binary.is_empty() || binary.as_bytes().contains(&b'/') {
        return None;
    }
    which::which_in(binary, Some(trusted_vendor_path()), Path::new("/")).ok()
}

#[derive(Debug, thiserror::Error)]
pub enum ExecGateError {
    #[error("exec gate private control FD is unavailable: {0}")]
    Control(#[source] io::Error),
    #[error("exec gate control frame is invalid")]
    InvalidFrame,
    #[error("exec gate protocol version is unsupported")]
    Version,
    #[error("exec gate binding is invalid")]
    InvalidBinding,
    #[error("exec gate process group could not be established: {0}")]
    ProcessGroup(#[source] io::Error),
    #[error("exec gate entropy is unavailable")]
    Entropy,
    #[error("exec gate release capability does not match")]
    ReleaseMismatch,
    #[error("exec gate vendor exec failed: {0}")]
    Exec(#[source] io::Error),
    #[error("exec gate process could not be spawned: {0}")]
    Spawn(#[source] io::Error),
    #[error("exec gate handshake timed out")]
    HandshakeTimeout,
    #[error("exec gate rejected the parent handshake")]
    Rejected,
    #[error("exec gate process wait failed: {0}")]
    Wait(#[source] io::Error),
    #[error("exec gate process group is not confirmed exited")]
    ProcessGroupNotExited,
}

impl ExecGateError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Control(_) => "daemon.exec_gate.control_unavailable",
            Self::InvalidFrame => "daemon.exec_gate.invalid_frame",
            Self::Version => "daemon.exec_gate.version_mismatch",
            Self::InvalidBinding => "daemon.exec_gate.invalid_binding",
            Self::ProcessGroup(_) => "daemon.exec_gate.process_group_failed",
            Self::Entropy => "daemon.exec_gate.entropy_unavailable",
            Self::ReleaseMismatch => "daemon.exec_gate.release_mismatch",
            Self::Exec(_) => "daemon.exec_gate.exec_failed",
            Self::Spawn(_) => "daemon.exec_gate.spawn_failed",
            Self::HandshakeTimeout => "daemon.exec_gate.handshake_timeout",
            Self::Rejected => "daemon.exec_gate.rejected",
            Self::Wait(_) => "daemon.exec_gate.wait_failed",
            Self::ProcessGroupNotExited => "daemon.exec_gate.process_group_not_exited",
        }
    }
}

/// parent 侧 spawn 的 child-ownership disposition。
///
/// 威胁场景：本机 current-exe/FD 配置在调用 Tokio spawn 前失败时没有 gate child；若把
/// 这类普通失败与 spawn/Ready handshake 之后的不确定清理混为一谈，actor 会把本可安全
/// 终止的 conversation 永久标成 RecoveryBlocked。Tokio `Command::spawn` 本身先创建 OS
/// child、再做可失败的异步封装，因此一旦调用 spawn，连 Err 也必须保持 fail-close。
#[derive(Debug, thiserror::Error)]
pub(crate) enum GatedChildSpawnError {
    #[error("exec gate spawn failed with no surviving child: {0}")]
    NoSurvivingChild(#[source] ExecGateError),
    #[error("exec gate spawn failed after child creation with uncertain group cleanup: {0}")]
    ChildOutcomeUnknown(#[source] ExecGateError),
}

impl GatedChildSpawnError {
    #[must_use]
    pub(crate) const fn permits_clean_prepare_failure(&self) -> bool {
        matches!(self, Self::NoSurvivingChild(_))
    }
}

pub(super) enum ParentFrame {
    Prepare {
        protocol_version: u16,
        command_id: String,
        daemon_boot_id: String,
        execution_nonce: Vec<u8>,
        program: Vec<u8>,
        arguments: Vec<Vec<u8>>,
        cwd: Vec<u8>,
    },
    Release {
        command_id: String,
        daemon_boot_id: String,
        execution_nonce: Vec<u8>,
        process_group_id: i64,
        leader_pid: i64,
        leader_start_time: u64,
        release_token: Vec<u8>,
        token_commitment: Vec<u8>,
        release_authorized_at_ms: u64,
    },
}

enum ChildFrame<'a> {
    Ready {
        protocol_version: u16,
        process_group_id: i64,
        leader_pid: i64,
        leader_start_time: u64,
        execution_nonce: &'a [u8],
        release_token: &'a [u8],
        token_commitment: &'a [u8],
    },
    Aborted {
        code: &'a str,
    },
}

#[allow(dead_code, reason = "P3.7 production coordinator decodes gate replies")]
pub(super) enum ChildReply {
    Ready {
        protocol_version: u16,
        process_group_id: i64,
        leader_pid: i64,
        leader_start_time: u64,
        execution_nonce: Vec<u8>,
        release_token: Vec<u8>,
        token_commitment: Vec<u8>,
    },
    Aborted {
        code: String,
    },
}

struct PreparedSpec {
    command_id: RuntimeId,
    daemon_boot_id: RuntimeId,
    execution_nonce: Vec<u8>,
    program: PathBuf,
    arguments: Vec<OsString>,
    cwd: PathBuf,
}

struct GateBinding {
    command_id: RuntimeId,
    daemon_boot_id: RuntimeId,
    execution_nonce: Vec<u8>,
    process: ProcessIdentity,
    release_token: [u8; RELEASE_TOKEN_BYTES],
    token_commitment: [u8; TOKEN_COMMITMENT_BYTES],
}

pub fn run_from_private_fd() -> Result<(), ExecGateError> {
    // SAFETY: this submode is entered only by the daemon spawner, which installs one owned
    // socket endpoint at fixed FD 3. FromRawFd transfers that ownership exactly once.
    let mut control = unsafe { UnixStream::from_raw_fd(CONTROL_FD) };
    let prepare = match read_frame(&mut control)? {
        ParentFrame::Prepare {
            protocol_version,
            command_id,
            daemon_boot_id,
            execution_nonce,
            program,
            arguments,
            cwd,
        } => validate_prepare(
            protocol_version,
            command_id,
            daemon_boot_id,
            execution_nonce,
            program,
            arguments,
            cwd,
        )?,
        ParentFrame::Release { .. } => return abort(&mut control, ExecGateError::InvalidFrame),
    };
    let binding = establish_binding(&prepare)?;
    write_frame(
        &mut control,
        &ChildFrame::Ready {
            protocol_version: GATE_PROTOCOL_VERSION,
            process_group_id: binding.process.process_group_id(),
            leader_pid: binding.process.leader_pid(),
            leader_start_time: binding.process.leader_start_time(),
            execution_nonce: &binding.execution_nonce,
            release_token: &binding.release_token,
            token_commitment: &binding.token_commitment,
        },
    )?;
    let release = read_frame(&mut control)?;
    if !release_matches(&binding, release) {
        return abort(&mut control, ExecGateError::ReleaseMismatch);
    }

    let inherited = SAFE_ENV_KEYS
        .iter()
        .filter_map(|key| std::env::var_os(key).map(|value| ((*key).to_owned(), value)))
        .collect::<Vec<_>>();
    let mut command = Command::new(&prepare.program);
    command
        .args(&prepare.arguments)
        .current_dir(&prepare.cwd)
        .env_clear()
        .envs(inherited)
        .env("PATH", trusted_vendor_path());

    // 威胁场景：vendor leader 先退出但同 PGID tool child 仍在执行副作用；若 gate 也退出，
    // daemon 只剩可能复用的整数 PGID，既不能安全 KILL，也不能证明旧 execution 已清空。
    // 此子模式在 Tokio runtime 创建前同步运行，所以只在这里显式 fork：gate 永久保留原
    // PID/PGID/start-time 作为 sentinel，vendor 是同一 group 内的普通 child。
    ignore_signals_in_sentinel()?;
    // SAFETY: --exec-gate is an exclusive, synchronous mode entered before the daemon creates
    // any runtime threads. All Command allocation/configuration happened above; after fork the
    // child only changes signal dispositions, closes one owned FD, and calls exec/_exit.
    let vendor_pid = unsafe { libc::fork() };
    if vendor_pid < 0 {
        return Err(ExecGateError::Spawn(io::Error::last_os_error()));
    }
    if vendor_pid == 0 {
        if !restore_vendor_signal_defaults() {
            // SAFETY: the post-fork child must not unwind through copied process state.
            unsafe { libc::_exit(126) };
        }
        drop(control);
        let _error = command.exec();
        // SAFETY: exec failure is observable by adapter EOF; the sentinel remains the exact
        // group capability until the daemon fences it. Do not unwind or run copied destructors.
        unsafe { libc::_exit(127) };
    }

    // 两个 fork 分支都显式关闭 capability FD；sentinel 再关闭自己的 stdio 副本，使
    // vendor/descendants 退出后 adapter 立即看到 EOF。SIGCHLD=IGN 让短命 vendor 由
    // kernel 自动回收，sentinel 不等待 vendor，始终只等待 daemon 的 group SIGKILL。
    drop(control);
    close_sentinel_stdio();
    loop {
        // SAFETY: pause only suspends this single-purpose sentinel until a caught signal arrives.
        unsafe { libc::pause() };
    }
}

fn ignore_signals_in_sentinel() -> Result<(), ExecGateError> {
    // SAFETY: signal changes only this single-threaded exec-gate subprocess. Ignoring SIGCHLD
    // before fork prevents an exited vendor child from becoming a zombie owned by the sentinel.
    for signal in [libc::SIGTERM, libc::SIGCHLD] {
        if unsafe { libc::signal(signal, libc::SIG_IGN) } == libc::SIG_ERR {
            return Err(ExecGateError::ProcessGroup(io::Error::last_os_error()));
        }
    }
    Ok(())
}

fn restore_vendor_signal_defaults() -> bool {
    // SAFETY: called only in the single-threaded post-fork child before exec; signal(3) changes
    // the two dispositions inherited from the sentinel and performs no Rust allocation.
    [libc::SIGTERM, libc::SIGCHLD]
        .into_iter()
        .all(|signal| unsafe { libc::signal(signal, libc::SIG_DFL) } != libc::SIG_ERR)
}

fn close_sentinel_stdio() {
    for fd in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
        // SAFETY: vendor already inherited its own descriptor table. The sentinel no longer reads
        // or writes stdio, and close errors do not weaken process-group ownership.
        unsafe {
            libc::close(fd);
        }
    }
}

fn validate_prepare(
    protocol_version: u16,
    command_id: String,
    daemon_boot_id: String,
    execution_nonce: Vec<u8>,
    program: Vec<u8>,
    arguments: Vec<Vec<u8>>,
    cwd: Vec<u8>,
) -> Result<PreparedSpec, ExecGateError> {
    if protocol_version != GATE_PROTOCOL_VERSION {
        return Err(ExecGateError::Version);
    }
    let command_id = RuntimeId::parse_canonical(RuntimeIdKind::Command, &command_id)
        .map_err(|_| ExecGateError::InvalidBinding)?;
    let daemon_boot_id = RuntimeId::parse_canonical(RuntimeIdKind::DaemonBoot, &daemon_boot_id)
        .map_err(|_| ExecGateError::InvalidBinding)?;
    if execution_nonce.is_empty() || execution_nonce.len() > MAX_EXECUTION_NONCE_BYTES {
        return Err(ExecGateError::InvalidBinding);
    }
    let program_bytes = program.len();
    let cwd_bytes = cwd.len();
    let program = decode_path(program)?;
    let cwd = decode_path(cwd)?;
    if !program.is_absolute() || !cwd.is_absolute() {
        return Err(ExecGateError::InvalidBinding);
    }
    if arguments.len() > MAX_EXEC_ARGUMENTS {
        return Err(ExecGateError::InvalidBinding);
    }
    let argument_count = arguments.len();
    let mut total = 0_usize;
    let arguments = arguments
        .into_iter()
        .map(|value| {
            if value.contains(&0) || value.len() > MAX_EXEC_SINGLE_ARGUMENT_BYTES {
                return Err(ExecGateError::InvalidBinding);
            }
            total = total
                .checked_add(value.len())
                .ok_or(ExecGateError::InvalidBinding)?;
            if total > MAX_EXEC_ARGUMENT_BYTES {
                return Err(ExecGateError::InvalidBinding);
            }
            Ok(OsString::from_vec(value))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let control_frame_bytes =
        exec_spec_control_frame_bytes(program_bytes, cwd_bytes, argument_count, total)
            .ok_or(ExecGateError::InvalidBinding)?;
    if control_frame_bytes > MAX_EXEC_CONTROL_FRAME_BYTES {
        return Err(ExecGateError::InvalidBinding);
    }
    Ok(PreparedSpec {
        command_id,
        daemon_boot_id,
        execution_nonce,
        program,
        arguments,
        cwd,
    })
}

fn decode_path(value: Vec<u8>) -> Result<PathBuf, ExecGateError> {
    if value.is_empty() || value.len() > MAX_EXEC_PATH_BYTES || value.contains(&0) {
        return Err(ExecGateError::InvalidBinding);
    }
    Ok(PathBuf::from(OsString::from_vec(value)))
}

fn establish_binding(spec: &PreparedSpec) -> Result<GateBinding, ExecGateError> {
    // SAFETY: pid=0/pgid=0 requests a new group led by this exact gate process.
    if unsafe { libc::setpgid(0, 0) } != 0 {
        return Err(ExecGateError::ProcessGroup(io::Error::last_os_error()));
    }
    // SAFETY: getpid/getpgrp have no preconditions.
    let pid = unsafe { libc::getpid() };
    let pgid = unsafe { libc::getpgrp() };
    let start_time = current_process_start_time()
        .map_err(|error| ExecGateError::ProcessGroup(io::Error::other(error)))?;
    let process = ProcessIdentity::new(i64::from(pgid), i64::from(pid), start_time)
        .map_err(|error| ExecGateError::ProcessGroup(io::Error::other(error)))?;
    let mut release_token = [0_u8; RELEASE_TOKEN_BYTES];
    getrandom::fill(&mut release_token).map_err(|_| ExecGateError::Entropy)?;
    if release_token == [0; RELEASE_TOKEN_BYTES] {
        return Err(ExecGateError::Entropy);
    }
    let token_commitment = token_commitment(spec, process, &release_token);
    Ok(GateBinding {
        command_id: spec.command_id,
        daemon_boot_id: spec.daemon_boot_id,
        execution_nonce: spec.execution_nonce.clone(),
        process,
        release_token,
        token_commitment,
    })
}

fn token_commitment(
    spec: &PreparedSpec,
    process: ProcessIdentity,
    token: &[u8; RELEASE_TOKEN_BYTES],
) -> [u8; TOKEN_COMMITMENT_BYTES] {
    let mut hash = Sha256::new();
    hash.update(b"agentdeck.exec-gate.release.v1\0");
    hash.update(spec.command_id.to_canonical_string().as_bytes());
    hash.update(spec.daemon_boot_id.to_canonical_string().as_bytes());
    hash.update((spec.execution_nonce.len() as u64).to_be_bytes());
    hash.update(&spec.execution_nonce);
    hash.update(process.process_group_id().to_be_bytes());
    hash.update(process.leader_pid().to_be_bytes());
    hash.update(process.leader_start_time().to_be_bytes());
    hash.update(token);
    hash.finalize().into()
}

fn release_matches(binding: &GateBinding, frame: ParentFrame) -> bool {
    let ParentFrame::Release {
        command_id,
        daemon_boot_id,
        execution_nonce,
        process_group_id,
        leader_pid,
        leader_start_time,
        release_token,
        token_commitment,
        release_authorized_at_ms,
    } = frame
    else {
        return false;
    };
    command_id == binding.command_id.to_canonical_string()
        && daemon_boot_id == binding.daemon_boot_id.to_canonical_string()
        && constant_time_eq(&execution_nonce, &binding.execution_nonce)
        && process_group_id == binding.process.process_group_id()
        && leader_pid == binding.process.leader_pid()
        && leader_start_time == binding.process.leader_start_time()
        && constant_time_eq(&release_token, &binding.release_token)
        && constant_time_eq(&token_commitment, &binding.token_commitment)
        && release_authorized_at_ms > 0
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn abort(control: &mut UnixStream, error: ExecGateError) -> Result<(), ExecGateError> {
    let _ = write_frame(control, &ChildFrame::Aborted { code: error.code() });
    Err(error)
}

fn read_frame(stream: &mut UnixStream) -> Result<ParentFrame, ExecGateError> {
    read_parent_frame(stream)
}

fn write_frame(stream: &mut UnixStream, frame: &ChildFrame<'_>) -> Result<(), ExecGateError> {
    write_child_frame(stream, frame)
}

/// 威胁场景：JSON `Vec<u8>` 会把一个合法 288 KiB `ExecSpec` 膨胀到超过 1 MiB，
/// 让受 constructor 接受的 command 在 gate 边界不可表示；反向的畸形长度又可能在完整
/// schema 校验前触发无界分配。wire codec 因此使用固定 header 与逐字段大端长度前缀，
/// decoder 在复制字段前核对单字段、argv 总量和完整 `ExecSpec` 三层上界。
pub(super) fn write_parent_frame(
    stream: &mut UnixStream,
    frame: &ParentFrame,
) -> Result<(), ExecGateError> {
    write_wire_payload(stream, &encode_parent_frame(frame)?)
}

fn read_parent_frame(stream: &mut UnixStream) -> Result<ParentFrame, ExecGateError> {
    let payload = read_wire_payload(stream)?;
    decode_parent_payload(&payload)
}

#[cfg(test)]
pub(crate) fn read_parent_frame_for_test(
    stream: &mut UnixStream,
) -> Result<ParentFrame, ExecGateError> {
    read_parent_frame(stream)
}

fn write_child_frame(stream: &mut UnixStream, frame: &ChildFrame<'_>) -> Result<(), ExecGateError> {
    write_wire_payload(stream, &encode_child_frame(frame)?)
}

pub(super) fn read_child_reply(stream: &mut UnixStream) -> Result<ChildReply, ExecGateError> {
    let payload = read_wire_payload(stream)?;
    decode_child_payload(&payload)
}

fn encode_parent_frame(frame: &ParentFrame) -> Result<Vec<u8>, ExecGateError> {
    let mut encoder = match frame {
        ParentFrame::Prepare { .. } => FrameEncoder::new(PREPARE_TAG),
        ParentFrame::Release { .. } => FrameEncoder::new(RELEASE_TAG),
    };
    match frame {
        ParentFrame::Prepare {
            protocol_version,
            command_id,
            daemon_boot_id,
            execution_nonce,
            program,
            arguments,
            cwd,
        } => {
            let argument_bytes = arguments.iter().try_fold(0_usize, |total, argument| {
                if argument.len() > MAX_EXEC_SINGLE_ARGUMENT_BYTES {
                    return Err(ExecGateError::InvalidFrame);
                }
                total
                    .checked_add(argument.len())
                    .ok_or(ExecGateError::InvalidFrame)
            })?;
            if arguments.len() > MAX_EXEC_ARGUMENTS
                || argument_bytes > MAX_EXEC_ARGUMENT_BYTES
                || program.len() > MAX_EXEC_PATH_BYTES
                || cwd.len() > MAX_EXEC_PATH_BYTES
                || exec_spec_control_frame_bytes(
                    program.len(),
                    cwd.len(),
                    arguments.len(),
                    argument_bytes,
                )
                .is_none_or(|bytes| bytes > MAX_EXEC_CONTROL_FRAME_BYTES)
            {
                return Err(ExecGateError::InvalidFrame);
            }
            encoder.push_u16(*protocol_version);
            encoder.push_text(command_id, RUNTIME_ID_TEXT_BYTES)?;
            encoder.push_text(daemon_boot_id, RUNTIME_ID_TEXT_BYTES)?;
            encoder.push_bytes(execution_nonce, MAX_EXECUTION_NONCE_BYTES)?;
            encoder.push_bytes(program, MAX_EXEC_PATH_BYTES)?;
            encoder
                .push_u16(u16::try_from(arguments.len()).map_err(|_| ExecGateError::InvalidFrame)?);
            for argument in arguments {
                encoder.push_bytes(argument, MAX_EXEC_SINGLE_ARGUMENT_BYTES)?;
            }
            encoder.push_bytes(cwd, MAX_EXEC_PATH_BYTES)?;
        }
        ParentFrame::Release {
            command_id,
            daemon_boot_id,
            execution_nonce,
            process_group_id,
            leader_pid,
            leader_start_time,
            release_token,
            token_commitment,
            release_authorized_at_ms,
        } => {
            encoder.push_text(command_id, RUNTIME_ID_TEXT_BYTES)?;
            encoder.push_text(daemon_boot_id, RUNTIME_ID_TEXT_BYTES)?;
            encoder.push_bytes(execution_nonce, MAX_EXECUTION_NONCE_BYTES)?;
            encoder.push_i64(*process_group_id);
            encoder.push_i64(*leader_pid);
            encoder.push_u64(*leader_start_time);
            encoder.push_exact_bytes(release_token, RELEASE_TOKEN_BYTES)?;
            encoder.push_exact_bytes(token_commitment, TOKEN_COMMITMENT_BYTES)?;
            encoder.push_u64(*release_authorized_at_ms);
        }
    }
    encoder.finish()
}

fn decode_parent_payload(payload: &[u8]) -> Result<ParentFrame, ExecGateError> {
    let (tag, mut decoder) = FrameDecoder::new(payload)?;
    let frame = match tag {
        PREPARE_TAG => {
            let protocol_version = decoder.read_u16()?;
            let command_id = decoder.read_text(RUNTIME_ID_TEXT_BYTES)?;
            let daemon_boot_id = decoder.read_text(RUNTIME_ID_TEXT_BYTES)?;
            let execution_nonce = decoder.read_bytes(MAX_EXECUTION_NONCE_BYTES)?;
            let program = decoder.read_bytes(MAX_EXEC_PATH_BYTES)?;
            let argument_count = usize::from(decoder.read_u16()?);
            if argument_count > MAX_EXEC_ARGUMENTS {
                return Err(ExecGateError::InvalidFrame);
            }
            let mut argument_bytes = 0_usize;
            let mut arguments = Vec::with_capacity(argument_count);
            for _ in 0..argument_count {
                let argument = decoder.read_bytes(MAX_EXEC_SINGLE_ARGUMENT_BYTES)?;
                argument_bytes = argument_bytes
                    .checked_add(argument.len())
                    .ok_or(ExecGateError::InvalidFrame)?;
                if argument_bytes > MAX_EXEC_ARGUMENT_BYTES {
                    return Err(ExecGateError::InvalidFrame);
                }
                arguments.push(argument);
            }
            let cwd = decoder.read_bytes(MAX_EXEC_PATH_BYTES)?;
            if exec_spec_control_frame_bytes(
                program.len(),
                cwd.len(),
                argument_count,
                argument_bytes,
            )
            .is_none_or(|bytes| bytes > MAX_EXEC_CONTROL_FRAME_BYTES)
            {
                return Err(ExecGateError::InvalidFrame);
            }
            ParentFrame::Prepare {
                protocol_version,
                command_id,
                daemon_boot_id,
                execution_nonce,
                program,
                arguments,
                cwd,
            }
        }
        RELEASE_TAG => ParentFrame::Release {
            command_id: decoder.read_text(RUNTIME_ID_TEXT_BYTES)?,
            daemon_boot_id: decoder.read_text(RUNTIME_ID_TEXT_BYTES)?,
            execution_nonce: decoder.read_bytes(MAX_EXECUTION_NONCE_BYTES)?,
            process_group_id: decoder.read_i64()?,
            leader_pid: decoder.read_i64()?,
            leader_start_time: decoder.read_u64()?,
            release_token: decoder.read_exact_bytes(RELEASE_TOKEN_BYTES)?,
            token_commitment: decoder.read_exact_bytes(TOKEN_COMMITMENT_BYTES)?,
            release_authorized_at_ms: decoder.read_u64()?,
        },
        _ => return Err(ExecGateError::InvalidFrame),
    };
    decoder.finish()?;
    Ok(frame)
}

fn encode_child_frame(frame: &ChildFrame<'_>) -> Result<Vec<u8>, ExecGateError> {
    let mut encoder = match frame {
        ChildFrame::Ready { .. } => FrameEncoder::new(READY_TAG),
        ChildFrame::Aborted { .. } => FrameEncoder::new(ABORTED_TAG),
    };
    match frame {
        ChildFrame::Ready {
            protocol_version,
            process_group_id,
            leader_pid,
            leader_start_time,
            execution_nonce,
            release_token,
            token_commitment,
        } => {
            encoder.push_u16(*protocol_version);
            encoder.push_i64(*process_group_id);
            encoder.push_i64(*leader_pid);
            encoder.push_u64(*leader_start_time);
            encoder.push_bytes(execution_nonce, MAX_EXECUTION_NONCE_BYTES)?;
            encoder.push_exact_bytes(release_token, RELEASE_TOKEN_BYTES)?;
            encoder.push_exact_bytes(token_commitment, TOKEN_COMMITMENT_BYTES)?;
        }
        ChildFrame::Aborted { code } => encoder.push_text(code, MAX_ERROR_CODE_BYTES)?,
    }
    encoder.finish()
}

fn decode_child_payload(payload: &[u8]) -> Result<ChildReply, ExecGateError> {
    let (tag, mut decoder) = FrameDecoder::new(payload)?;
    let frame = match tag {
        READY_TAG => ChildReply::Ready {
            protocol_version: decoder.read_u16()?,
            process_group_id: decoder.read_i64()?,
            leader_pid: decoder.read_i64()?,
            leader_start_time: decoder.read_u64()?,
            execution_nonce: decoder.read_bytes(MAX_EXECUTION_NONCE_BYTES)?,
            release_token: decoder.read_exact_bytes(RELEASE_TOKEN_BYTES)?,
            token_commitment: decoder.read_exact_bytes(TOKEN_COMMITMENT_BYTES)?,
        },
        ABORTED_TAG => ChildReply::Aborted {
            code: decoder.read_text(MAX_ERROR_CODE_BYTES)?,
        },
        _ => return Err(ExecGateError::InvalidFrame),
    };
    decoder.finish()?;
    Ok(frame)
}

fn read_wire_payload(stream: &mut UnixStream) -> Result<Vec<u8>, ExecGateError> {
    let mut length = [0_u8; 4];
    stream
        .read_exact(&mut length)
        .map_err(ExecGateError::Control)?;
    let length =
        usize::try_from(u32::from_be_bytes(length)).map_err(|_| ExecGateError::InvalidFrame)?;
    if length == 0 || length > MAX_WIRE_FRAME_BYTES {
        return Err(ExecGateError::InvalidFrame);
    }
    let mut payload = vec![0_u8; length];
    stream
        .read_exact(&mut payload)
        .map_err(ExecGateError::Control)?;
    Ok(payload)
}

fn write_wire_payload(stream: &mut UnixStream, payload: &[u8]) -> Result<(), ExecGateError> {
    if payload.is_empty() || payload.len() > MAX_WIRE_FRAME_BYTES {
        return Err(ExecGateError::InvalidFrame);
    }
    let length = u32::try_from(payload.len()).map_err(|_| ExecGateError::InvalidFrame)?;
    stream
        .write_all(&length.to_be_bytes())
        .and_then(|_| stream.write_all(payload))
        .and_then(|_| stream.flush())
        .map_err(ExecGateError::Control)
}

struct FrameEncoder {
    payload: Vec<u8>,
}

impl FrameEncoder {
    fn new(tag: u8) -> Self {
        let mut payload = Vec::with_capacity(256);
        payload.extend_from_slice(&WIRE_MAGIC);
        payload.extend_from_slice(&WIRE_CODEC_VERSION.to_be_bytes());
        payload.push(tag);
        Self { payload }
    }

    fn push_u16(&mut self, value: u16) {
        self.payload.extend_from_slice(&value.to_be_bytes());
    }

    fn push_u32(&mut self, value: u32) {
        self.payload.extend_from_slice(&value.to_be_bytes());
    }

    fn push_u64(&mut self, value: u64) {
        self.payload.extend_from_slice(&value.to_be_bytes());
    }

    fn push_i64(&mut self, value: i64) {
        self.payload.extend_from_slice(&value.to_be_bytes());
    }

    fn push_text(&mut self, value: &str, max: usize) -> Result<(), ExecGateError> {
        self.push_bytes(value.as_bytes(), max)
    }

    fn push_exact_bytes(&mut self, value: &[u8], expected: usize) -> Result<(), ExecGateError> {
        if value.len() != expected {
            return Err(ExecGateError::InvalidFrame);
        }
        self.push_bytes(value, expected)
    }

    fn push_bytes(&mut self, value: &[u8], max: usize) -> Result<(), ExecGateError> {
        if value.len() > max {
            return Err(ExecGateError::InvalidFrame);
        }
        self.push_u32(u32::try_from(value.len()).map_err(|_| ExecGateError::InvalidFrame)?);
        self.payload.extend_from_slice(value);
        if self.payload.len() > MAX_WIRE_FRAME_BYTES {
            return Err(ExecGateError::InvalidFrame);
        }
        Ok(())
    }

    fn finish(self) -> Result<Vec<u8>, ExecGateError> {
        if self.payload.is_empty() || self.payload.len() > MAX_WIRE_FRAME_BYTES {
            return Err(ExecGateError::InvalidFrame);
        }
        Ok(self.payload)
    }
}

struct FrameDecoder<'a> {
    payload: &'a [u8],
    cursor: usize,
}

impl<'a> FrameDecoder<'a> {
    fn new(payload: &'a [u8]) -> Result<(u8, Self), ExecGateError> {
        if payload.is_empty() || payload.len() > MAX_WIRE_FRAME_BYTES {
            return Err(ExecGateError::InvalidFrame);
        }
        let mut decoder = Self { payload, cursor: 0 };
        if decoder.take(WIRE_MAGIC.len())? != WIRE_MAGIC {
            return Err(ExecGateError::InvalidFrame);
        }
        if decoder.read_u16()? != WIRE_CODEC_VERSION {
            return Err(ExecGateError::InvalidFrame);
        }
        let tag = decoder.read_u8()?;
        Ok((tag, decoder))
    }

    fn read_u8(&mut self) -> Result<u8, ExecGateError> {
        Ok(self.take(1)?[0])
    }

    fn read_u16(&mut self) -> Result<u16, ExecGateError> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| ExecGateError::InvalidFrame)?,
        ))
    }

    fn read_u32(&mut self) -> Result<u32, ExecGateError> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| ExecGateError::InvalidFrame)?,
        ))
    }

    fn read_u64(&mut self) -> Result<u64, ExecGateError> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| ExecGateError::InvalidFrame)?,
        ))
    }

    fn read_i64(&mut self) -> Result<i64, ExecGateError> {
        Ok(i64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| ExecGateError::InvalidFrame)?,
        ))
    }

    fn read_text(&mut self, max: usize) -> Result<String, ExecGateError> {
        String::from_utf8(self.read_bytes(max)?).map_err(|_| ExecGateError::InvalidFrame)
    }

    fn read_exact_bytes(&mut self, expected: usize) -> Result<Vec<u8>, ExecGateError> {
        let value = self.read_bytes(expected)?;
        if value.len() != expected {
            return Err(ExecGateError::InvalidFrame);
        }
        Ok(value)
    }

    fn read_bytes(&mut self, max: usize) -> Result<Vec<u8>, ExecGateError> {
        let length = usize::try_from(self.read_u32()?).map_err(|_| ExecGateError::InvalidFrame)?;
        if length > max {
            return Err(ExecGateError::InvalidFrame);
        }
        Ok(self.take(length)?.to_vec())
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ExecGateError> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or(ExecGateError::InvalidFrame)?;
        let value = self
            .payload
            .get(self.cursor..end)
            .ok_or(ExecGateError::InvalidFrame)?;
        self.cursor = end;
        Ok(value)
    }

    fn finish(self) -> Result<(), ExecGateError> {
        if self.cursor == self.payload.len() {
            Ok(())
        } else {
            Err(ExecGateError::InvalidFrame)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trusted_program_resolution_ignores_arbitrary_paths_and_stays_in_safe_path() {
        assert!(resolve_trusted_program("").is_none());
        assert!(resolve_trusted_program("./sh").is_none());
        assert!(resolve_trusted_program("/bin/sh").is_none());

        let resolved = resolve_trusted_program("sh").expect("system sh is in the fixed safe path");
        assert!(
            env::split_paths(&trusted_vendor_path()).any(|root| resolved.starts_with(root)),
            "resolved program escaped the fixed safe path: {}",
            resolved.display()
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn trusted_program_resolution_accepts_the_real_account_claude_sample_when_present() {
        // 真实样本门禁：本机安装器把 Claude 放在 OS account 的 ~/.local/bin；resolver
        // 与 exec gate 必须对同一真实文件达成一致，不能只靠合成 PATH 测试宣称可用。
        let expected = crate::config::current_user_home()
            .expect("read OS account home")
            .join(".local/bin/claude");
        if !expected.is_file() {
            return;
        }
        let resolved = resolve_trusted_program("claude").expect("resolve real Claude sample");
        assert_eq!(
            std::fs::canonicalize(resolved).expect("canonicalize resolved Claude"),
            std::fs::canonicalize(expected).expect("canonicalize installed Claude")
        );
    }
}
