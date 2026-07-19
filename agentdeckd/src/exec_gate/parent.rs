//! daemon 侧 current-binary exec-gate owner。
//!
//! 威胁场景：adapter 若能直接 spawn vendor，或 parent 只按 PID/nonce 发送 release，
//! 未提交 Fence 的错误进程就可能越过副作用边界。本模块独占 current-binary spawn、
//! 私有 FD、随机 gate token 与 exact committed release 的逐字段核验。

use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::{Child as StdChild, Command as StdCommand, Stdio};
use std::time::Duration;

use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command};
use tokio::sync::oneshot;

use super::{
    CONTROL_FD, ChildReply, ExecGateError, GATE_PROTOCOL_VERSION, GateBinding,
    GatedChildSpawnError, ParentFrame, RELEASE_TOKEN_BYTES, SAFE_ENV_KEYS, TOKEN_COMMITMENT_BYTES,
    constant_time_eq, parent_prepare_token_commitment, read_child_reply, trusted_vendor_path,
    write_parent_frame,
};
use crate::agent::{CheckedExecSpec, ExecutionId, NativeMetadataEffectSpec};
use crate::runtime::execution::{ExecutionReleasePermit, RuntimeProcessIdentity};
use crate::runtime::process_identity::{
    ProcessGroupController, ProcessIdentity, ProcessObservation,
};
use crate::runtime::store::{NativeMetadataEffectReleasePermit, RuntimeId};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
pub(crate) struct GatedChild {
    execution_id: ExecutionId,
    inner: BoundGatedChild,
}

#[allow(dead_code, reason = "C-e4 coordinator owns the native gated child")]
pub(crate) struct NativeMetadataGatedChild {
    inner: NativeBoundGatedChild,
}

struct BoundGatedChild {
    release: GatedChildRelease,
    owner: GatedChildOwner,
}

struct NativeBoundGatedChild {
    release: GatedChildRelease,
    owner: NativeGatedChildOwner,
    io: Option<GatedChildIo>,
}

/// blocked gate 的一次性 release capability。它只拥有私有 control FD 与 committed
/// binding，不拥有 `Child`，因此 daemon 可以从 prepare 起让唯一 owner 并行等待/reap。
pub(crate) struct GatedChildRelease {
    binding: GateBinding,
    daemon_boot_id: RuntimeId,
    execution_nonce: Vec<u8>,
    process: ProcessIdentity,
    release_token: [u8; RELEASE_TOKEN_BYTES],
    token_commitment: [u8; TOKEN_COMMITMENT_BYTES],
    control: Option<UnixStream>,
}

/// direct child 的唯一 owner。release capability 与 owner 拆分后，此 owner 从 gate
/// Ready 起即可等待 sentinel；无论 release 前取消还是 release 后 completion，都只有
/// 这一处调用 `Child::wait`。
pub(crate) struct GatedChildOwner {
    process: ProcessIdentity,
    child: Child,
    group_exit_verified: bool,
}

pub(crate) struct NativeGatedChildOwner {
    process: ProcessIdentity,
    wait: Option<tokio::task::JoinHandle<io::Result<std::process::ExitStatus>>>,
    group_exit_verified: bool,
}

/// adapter 只能取得 gate/vendor 的私有 stdio；release token、process identity 与
/// child owner 继续由 daemon coordinator 保留。
pub struct GatedChildIo {
    pub stdin: ChildStdin,
    pub stdout: ChildStdout,
    pub stderr: ChildStderr,
}

fn prepare_frame(
    daemon_boot_id: RuntimeId,
    execution_nonce: &[u8],
    spec: CheckedExecSpec<'_>,
) -> ParentFrame {
    ParentFrame::Prepare {
        protocol_version: GATE_PROTOCOL_VERSION,
        command_id: spec.execution_id().command_id().to_canonical_string(),
        daemon_boot_id: daemon_boot_id.to_canonical_string(),
        execution_nonce: execution_nonce.to_vec(),
        program: spec.program().as_os_str().as_bytes().to_vec(),
        arguments: spec
            .non_sensitive_args()
            .iter()
            .map(|argument| argument.as_os_str().as_bytes().to_vec())
            .collect(),
        cwd: spec.cwd().as_os_str().as_bytes().to_vec(),
    }
}

#[allow(dead_code, reason = "C-e4 coordinator consumes the native gate frame")]
fn native_metadata_prepare_frame(
    binding: GateBinding,
    daemon_boot_id: RuntimeId,
    effect_nonce: &[u8],
    spec: &NativeMetadataEffectSpec,
) -> Result<ParentFrame, ExecGateError> {
    let GateBinding::NativeMetadata {
        conversation_id,
        idempotency_token,
    } = binding
    else {
        return Err(ExecGateError::InvalidBinding);
    };
    if conversation_id.kind() != crate::runtime::store::RuntimeIdKind::Conversation {
        return Err(ExecGateError::InvalidBinding);
    }
    let (program, arguments, cwd) = spec.parts();
    Ok(ParentFrame::PrepareNativeMetadata {
        protocol_version: GATE_PROTOCOL_VERSION,
        conversation_id: conversation_id.to_canonical_string(),
        idempotency_token: idempotency_token.to_vec(),
        daemon_boot_id: daemon_boot_id.to_canonical_string(),
        effect_nonce: effect_nonce.to_vec(),
        program: program.as_os_str().as_bytes().to_vec(),
        arguments: arguments
            .iter()
            .map(|argument| argument.as_os_str().as_bytes().to_vec())
            .collect(),
        cwd: cwd.as_os_str().as_bytes().to_vec(),
    })
}

impl GatedChild {
    #[cfg(test)]
    pub(crate) fn new_for_test(
        binding: (ExecutionId, RuntimeId, Vec<u8>, ProcessIdentity),
        release: ([u8; RELEASE_TOKEN_BYTES], [u8; TOKEN_COMMITMENT_BYTES]),
        control: UnixStream,
        child: Child,
    ) -> Self {
        let (execution_id, daemon_boot_id, execution_nonce, process) = binding;
        let (release_token, token_commitment) = release;
        Self {
            execution_id,
            inner: BoundGatedChild {
                release: GatedChildRelease {
                    binding: GateBinding::Command {
                        command_id: execution_id.command_id(),
                    },
                    daemon_boot_id,
                    execution_nonce,
                    process,
                    release_token,
                    token_commitment,
                    control: Some(control),
                },
                owner: GatedChildOwner {
                    process,
                    child,
                    group_exit_verified: false,
                },
            },
        }
    }

    pub(crate) async fn spawn_current(
        daemon_boot_id: RuntimeId,
        execution_nonce: Vec<u8>,
        spec: CheckedExecSpec<'_>,
    ) -> Result<Self, GatedChildSpawnError> {
        let binary = std::env::current_exe()
            .map_err(|error| GatedChildSpawnError::NoSurvivingChild(ExecGateError::Spawn(error)))?;
        Self::spawn_with_binary(&binary, daemon_boot_id, execution_nonce, spec).await
    }

    pub(crate) async fn spawn_with_binary(
        binary: &Path,
        daemon_boot_id: RuntimeId,
        execution_nonce: Vec<u8>,
        spec: CheckedExecSpec<'_>,
    ) -> Result<Self, GatedChildSpawnError> {
        let execution_id = spec.execution_id();
        let binding = GateBinding::Command {
            command_id: execution_id.command_id(),
        };
        let prepare = prepare_frame(daemon_boot_id, &execution_nonce, spec);
        let inner = Self::spawn_prepared_with_binary(
            binary,
            binding,
            daemon_boot_id,
            execution_nonce,
            prepare,
        )
        .await?;
        Ok(Self {
            execution_id,
            inner,
        })
    }

    async fn spawn_prepared_with_binary(
        binary: &Path,
        binding: GateBinding,
        daemon_boot_id: RuntimeId,
        execution_nonce: Vec<u8>,
        prepare: ParentFrame,
    ) -> Result<BoundGatedChild, GatedChildSpawnError> {
        let (parent_control, child_control) = UnixStream::pair().map_err(|error| {
            GatedChildSpawnError::NoSurvivingChild(ExecGateError::Control(error))
        })?;
        parent_control
            .set_read_timeout(Some(HANDSHAKE_TIMEOUT))
            .and_then(|()| parent_control.set_write_timeout(Some(HANDSHAKE_TIMEOUT)))
            .map_err(|error| {
                GatedChildSpawnError::NoSurvivingChild(ExecGateError::Control(error))
            })?;
        let child_fd = child_control.as_raw_fd();
        let inherited = SAFE_ENV_KEYS
            .iter()
            .filter_map(|key| std::env::var_os(key).map(|value| ((*key).to_owned(), value)))
            .collect::<Vec<_>>();
        let mut command = Command::new(binary);
        command
            .arg("--exec-gate")
            .env_clear()
            .envs(inherited)
            .env("PATH", trusted_vendor_path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        // SAFETY: pre_exec 只调用 async-signal-safe dup2/fcntl/close，把唯一 socketpair
        // endpoint 安装到固定私有 FD；不会分配内存或触碰共享锁。
        unsafe {
            command.pre_exec(move || {
                if libc::dup2(child_fd, CONTROL_FD) < 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::fcntl(CONTROL_FD, libc::F_SETFD, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
                if child_fd != CONTROL_FD {
                    libc::close(child_fd);
                }
                Ok(())
            });
        }
        // 威胁场景：Tokio 先成功创建 std Child，再做可失败的非阻塞 stdio/SIGCHLD
        // reaper 封装；`spawn()` 返回 Err 仍可能已有 OS child，且此处拿不到 owner 做
        // exact cleanup。因此从调用 spawn 起一律 outcome unknown，不能放行 successor。
        let mut child = command.spawn().map_err(|error| {
            GatedChildSpawnError::ChildOutcomeUnknown(ExecGateError::Spawn(error))
        })?;
        drop(child_control);
        // 威胁场景：OS spawn 成功但 Tokio 未暴露 PID；若直接 `?` 返回，调用方会把
        // PrepareFailedClean 当成无 child，而实际 gate 可能仍在运行。
        let child_pid = match child.id() {
            Some(child_pid) => i64::from(child_pid),
            None => {
                reap_failed_spawn(&mut child).await;
                return Err(GatedChildSpawnError::ChildOutcomeUnknown(
                    ExecGateError::Spawn(io::Error::other("exec gate child has no process id")),
                ));
            }
        };
        let handshake = tokio::task::spawn_blocking(move || {
            let mut control = parent_control;
            write_parent_frame(&mut control, &prepare)?;
            let reply = read_child_reply(&mut control)?;
            Ok::<_, ExecGateError>((control, reply, prepare))
        });
        let (control, reply, prepare) = match tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake)
            .await
        {
            Ok(Ok(Ok(value))) => value,
            Ok(Ok(Err(error))) => {
                reap_failed_spawn(&mut child).await;
                return Err(GatedChildSpawnError::ChildOutcomeUnknown(error));
            }
            Ok(Err(_)) => {
                reap_failed_spawn(&mut child).await;
                return Err(GatedChildSpawnError::ChildOutcomeUnknown(
                    ExecGateError::Control(io::Error::other("exec gate handshake worker failed")),
                ));
            }
            Err(_) => {
                reap_failed_spawn(&mut child).await;
                return Err(GatedChildSpawnError::ChildOutcomeUnknown(
                    ExecGateError::HandshakeTimeout,
                ));
            }
        };
        let ChildReply::Ready {
            protocol_version,
            process_group_id,
            leader_pid,
            leader_start_time,
            execution_nonce: observed_nonce,
            release_token,
            token_commitment,
        } = reply
        else {
            reap_failed_spawn(&mut child).await;
            return Err(GatedChildSpawnError::ChildOutcomeUnknown(
                ExecGateError::Rejected,
            ));
        };
        if protocol_version != GATE_PROTOCOL_VERSION
            || leader_pid != child_pid
            || process_group_id != child_pid
            || !constant_time_eq(&observed_nonce, &execution_nonce)
            || release_token.len() != RELEASE_TOKEN_BYTES
            || token_commitment.len() != TOKEN_COMMITMENT_BYTES
            || release_token.iter().all(|byte| *byte == 0)
            || token_commitment.iter().all(|byte| *byte == 0)
        {
            reap_failed_spawn(&mut child).await;
            return Err(GatedChildSpawnError::ChildOutcomeUnknown(
                ExecGateError::InvalidBinding,
            ));
        }
        let process = match ProcessIdentity::new(process_group_id, leader_pid, leader_start_time) {
            Ok(process) => process,
            Err(_) => {
                reap_failed_spawn(&mut child).await;
                return Err(GatedChildSpawnError::ChildOutcomeUnknown(
                    ExecGateError::InvalidBinding,
                ));
            }
        };
        if ProcessIdentity::for_process_group_leader(leader_pid).ok() != Some(process) {
            reap_failed_spawn(&mut child).await;
            return Err(GatedChildSpawnError::ChildOutcomeUnknown(
                ExecGateError::InvalidBinding,
            ));
        }
        // 威胁场景：wire 长度校验与数组转换未来发生漂移；child 已 spawn 后的转换错误
        // 仍必须同步 cleanup，不能把当前“不可达”分支留成 clean 分类漏洞。
        let release_token: [u8; RELEASE_TOKEN_BYTES] = match release_token.try_into() {
            Ok(release_token) => release_token,
            Err(_) => {
                reap_failed_spawn(&mut child).await;
                return Err(GatedChildSpawnError::ChildOutcomeUnknown(
                    ExecGateError::InvalidBinding,
                ));
            }
        };
        let token_commitment: [u8; TOKEN_COMMITMENT_BYTES] = match token_commitment.try_into() {
            Ok(token_commitment) => token_commitment,
            Err(_) => {
                reap_failed_spawn(&mut child).await;
                return Err(GatedChildSpawnError::ChildOutcomeUnknown(
                    ExecGateError::InvalidBinding,
                ));
            }
        };
        let expected_commitment =
            match parent_prepare_token_commitment(&prepare, process, &release_token) {
                Ok(commitment) => commitment,
                Err(error) => {
                    reap_failed_spawn(&mut child).await;
                    return Err(GatedChildSpawnError::ChildOutcomeUnknown(error));
                }
            };
        if !constant_time_eq(&token_commitment, &expected_commitment) {
            reap_failed_spawn(&mut child).await;
            return Err(GatedChildSpawnError::ChildOutcomeUnknown(
                ExecGateError::InvalidBinding,
            ));
        }
        Ok(BoundGatedChild {
            release: GatedChildRelease {
                binding,
                daemon_boot_id,
                execution_nonce,
                process,
                release_token,
                token_commitment,
                control: Some(control),
            },
            owner: GatedChildOwner {
                process,
                child,
                group_exit_verified: false,
            },
        })
    }

    pub(crate) const fn execution_id(&self) -> ExecutionId {
        self.execution_id
    }

    pub(crate) fn runtime_process_identity(&self) -> RuntimeProcessIdentity {
        self.inner.runtime_process_identity()
    }

    pub(crate) fn take_io(&mut self) -> Result<GatedChildIo, ExecGateError> {
        self.inner.take_io()
    }

    /// 威胁场景：release capability 若同时拥有 `Child`，release 前取消便没有并行
    /// waiter 收割 sentinel zombie。这里把 blocked gate 拆为一次性 release capability
    /// 与唯一 direct-child owner。
    /// owner 必须立即进入 wait；release 仅写私有 control FD，不再转移或等待 Child。
    pub(crate) fn into_owner_parts(self) -> (GatedChildRelease, GatedChildOwner) {
        self.inner.into_owner_parts()
    }

    pub(crate) fn process_identity(&self) -> ProcessIdentity {
        self.inner.process_identity()
    }
}

impl BoundGatedChild {
    fn runtime_process_identity(&self) -> RuntimeProcessIdentity {
        RuntimeProcessIdentity {
            process_group_id: self.release.process.process_group_id(),
            leader_pid: self.release.process.leader_pid(),
            leader_start_time: self.release.process.leader_start_time(),
            fence_payload: self.release.token_commitment.to_vec(),
        }
    }

    fn take_stdin(&mut self) -> Option<ChildStdin> {
        self.owner.child.stdin.take()
    }

    fn take_stdout(&mut self) -> Option<ChildStdout> {
        self.owner.child.stdout.take()
    }

    fn take_stderr(&mut self) -> Option<ChildStderr> {
        self.owner.child.stderr.take()
    }

    fn take_io(&mut self) -> Result<GatedChildIo, ExecGateError> {
        let stdin = self.take_stdin().ok_or(ExecGateError::InvalidBinding)?;
        let stdout = self.take_stdout().ok_or(ExecGateError::InvalidBinding)?;
        let stderr = self.take_stderr().ok_or(ExecGateError::InvalidBinding)?;
        Ok(GatedChildIo {
            stdin,
            stdout,
            stderr,
        })
    }

    fn into_owner_parts(self) -> (GatedChildRelease, GatedChildOwner) {
        (self.release, self.owner)
    }

    fn process_identity(&self) -> ProcessIdentity {
        self.release.process
    }
}

#[allow(dead_code, reason = "C-e4 coordinator consumes the native gate owner")]
impl NativeMetadataGatedChild {
    pub(crate) fn canonical_effect_spec(
        spec: &NativeMetadataEffectSpec,
    ) -> Result<Vec<u8>, ExecGateError> {
        let (program, arguments, cwd) = spec.parts();
        let mut encoded = Vec::new();
        encoded.extend_from_slice(b"agentdeck.native-metadata.exec-spec.v1\0");
        append_spec_field(&mut encoded, program.as_os_str().as_bytes())?;
        encoded.extend_from_slice(
            &u64::try_from(arguments.len())
                .map_err(|_| ExecGateError::InvalidBinding)?
                .to_be_bytes(),
        );
        for argument in arguments {
            append_spec_field(&mut encoded, argument.as_os_str().as_bytes())?;
        }
        append_spec_field(&mut encoded, cwd.as_os_str().as_bytes())?;
        Ok(encoded)
    }

    pub(crate) async fn spawn_current(
        binding: GateBinding,
        daemon_boot_id: RuntimeId,
        effect_nonce: Vec<u8>,
        spec: &NativeMetadataEffectSpec,
    ) -> Result<Self, GatedChildSpawnError> {
        let binary = std::env::current_exe()
            .map_err(|error| GatedChildSpawnError::NoSurvivingChild(ExecGateError::Spawn(error)))?;
        Self::spawn_with_binary(&binary, binding, daemon_boot_id, effect_nonce, spec).await
    }

    pub(crate) async fn spawn_with_binary(
        binary: &Path,
        binding: GateBinding,
        daemon_boot_id: RuntimeId,
        effect_nonce: Vec<u8>,
        spec: &NativeMetadataEffectSpec,
    ) -> Result<Self, GatedChildSpawnError> {
        let prepare = native_metadata_prepare_frame(binding, daemon_boot_id, &effect_nonce, spec)
            .map_err(GatedChildSpawnError::NoSurvivingChild)?;
        let inner = spawn_native_prepared_with_binary(
            binary,
            binding,
            daemon_boot_id,
            effect_nonce,
            prepare,
        )
        .await?;
        Ok(Self { inner })
    }

    pub(crate) const fn binding(&self) -> GateBinding {
        self.inner.release.binding
    }

    pub(crate) const fn release_token_commitment(&self) -> &[u8; TOKEN_COMMITMENT_BYTES] {
        &self.inner.release.token_commitment
    }

    pub(crate) fn process_identity(&self) -> ProcessIdentity {
        self.inner.release.process
    }

    pub(crate) fn take_io(&mut self) -> Result<GatedChildIo, ExecGateError> {
        self.inner.io.take().ok_or(ExecGateError::InvalidBinding)
    }

    pub(crate) fn into_owner_parts(self) -> (GatedChildRelease, NativeGatedChildOwner) {
        (self.inner.release, self.inner.owner)
    }
}

fn append_spec_field(encoded: &mut Vec<u8>, value: &[u8]) -> Result<(), ExecGateError> {
    let length = u64::try_from(value.len()).map_err(|_| ExecGateError::InvalidBinding)?;
    encoded
        .try_reserve(std::mem::size_of::<u64>() + value.len())
        .map_err(|_| ExecGateError::InvalidBinding)?;
    encoded.extend_from_slice(&length.to_be_bytes());
    encoded.extend_from_slice(value);
    Ok(())
}

async fn spawn_native_prepared_with_binary(
    binary: &Path,
    binding: GateBinding,
    daemon_boot_id: RuntimeId,
    execution_nonce: Vec<u8>,
    prepare: ParentFrame,
) -> Result<NativeBoundGatedChild, GatedChildSpawnError> {
    let (parent_control, child_control) = UnixStream::pair()
        .map_err(|error| GatedChildSpawnError::NoSurvivingChild(ExecGateError::Control(error)))?;
    parent_control
        .set_read_timeout(Some(HANDSHAKE_TIMEOUT))
        .and_then(|()| parent_control.set_write_timeout(Some(HANDSHAKE_TIMEOUT)))
        .map_err(|error| GatedChildSpawnError::NoSurvivingChild(ExecGateError::Control(error)))?;
    let child_fd = child_control.as_raw_fd();
    let inherited = SAFE_ENV_KEYS
        .iter()
        .filter_map(|key| std::env::var_os(key).map(|value| ((*key).to_owned(), value)))
        .collect::<Vec<_>>();
    let mut command = StdCommand::new(binary);
    command
        .arg("--exec-gate")
        .env_clear()
        .envs(inherited)
        .env("PATH", trusted_vendor_path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: 与 command gate 相同，只把唯一 socket endpoint 安装到固定 FD 3。
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(child_fd, CONTROL_FD) < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::fcntl(CONTROL_FD, libc::F_SETFD, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            if child_fd != CONTROL_FD {
                libc::close(child_fd);
            }
            Ok(())
        });
    }
    // std::process::Command::spawn 的 Err 契约不返回 Child；成功后本函数始终保留
    // 唯一 Child，任一后续失败都先 SIGKILL+wait，再返回 clean disposition。
    let child = command
        .spawn()
        .map_err(|error| GatedChildSpawnError::NoSurvivingChild(ExecGateError::Spawn(error)))?;
    // 从 spawn 返回的下一条语句起安装 cancel-safe owner。后续 handshake await、
    // frame 校验或 stdio 转换期间 future 被 abort，Drop 都会把唯一 Child 移交
    // 独立 OS reaper；正常成功路径则显式把 Child 交给唯一 waiter。
    let mut child = PendingNativeChildOwner::new(child);
    drop(child_control);
    let child_pid = i64::from(child.id());
    let handshake = tokio::task::spawn_blocking(move || {
        let mut control = parent_control;
        write_parent_frame(&mut control, &prepare)?;
        let reply = read_child_reply(&mut control)?;
        Ok::<_, ExecGateError>((control, reply, prepare))
    });
    let (control, reply, prepare) = match tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake).await {
        Ok(Ok(Ok(value))) => value,
        Ok(Ok(Err(error))) => return native_spawn_cleanup(child, error).await,
        Ok(Err(_)) => {
            return native_spawn_cleanup(
                child,
                ExecGateError::Control(io::Error::other(
                    "native exec gate handshake worker failed",
                )),
            )
            .await;
        }
        Err(_) => return native_spawn_cleanup(child, ExecGateError::HandshakeTimeout).await,
    };
    let ChildReply::Ready {
        protocol_version,
        process_group_id,
        leader_pid,
        leader_start_time,
        execution_nonce: observed_nonce,
        release_token,
        token_commitment,
    } = reply
    else {
        return native_spawn_cleanup(child, ExecGateError::Rejected).await;
    };
    if protocol_version != GATE_PROTOCOL_VERSION
        || leader_pid != child_pid
        || process_group_id != child_pid
        || !constant_time_eq(&observed_nonce, &execution_nonce)
        || release_token.len() != RELEASE_TOKEN_BYTES
        || token_commitment.len() != TOKEN_COMMITMENT_BYTES
        || release_token.iter().all(|byte| *byte == 0)
        || token_commitment.iter().all(|byte| *byte == 0)
    {
        return native_spawn_cleanup(child, ExecGateError::InvalidBinding).await;
    }
    let process = match ProcessIdentity::new(process_group_id, leader_pid, leader_start_time) {
        Ok(process) => process,
        Err(_) => return native_spawn_cleanup(child, ExecGateError::InvalidBinding).await,
    };
    if ProcessIdentity::for_process_group_leader(leader_pid).ok() != Some(process) {
        return native_spawn_cleanup(child, ExecGateError::InvalidBinding).await;
    }
    let release_token: [u8; RELEASE_TOKEN_BYTES] = match release_token.try_into() {
        Ok(token) => token,
        Err(_) => return native_spawn_cleanup(child, ExecGateError::InvalidBinding).await,
    };
    let token_commitment: [u8; TOKEN_COMMITMENT_BYTES] = match token_commitment.try_into() {
        Ok(commitment) => commitment,
        Err(_) => return native_spawn_cleanup(child, ExecGateError::InvalidBinding).await,
    };
    let expected_commitment =
        match parent_prepare_token_commitment(&prepare, process, &release_token) {
            Ok(commitment) => commitment,
            Err(error) => return native_spawn_cleanup(child, error).await,
        };
    if !constant_time_eq(&token_commitment, &expected_commitment) {
        return native_spawn_cleanup(child, ExecGateError::InvalidBinding).await;
    }

    let stdin = match child.stdin.take().map(ChildStdin::from_std) {
        Some(Ok(stdin)) => stdin,
        _ => return native_spawn_cleanup(child, ExecGateError::InvalidBinding).await,
    };
    let stdout = match child.stdout.take().map(ChildStdout::from_std) {
        Some(Ok(stdout)) => stdout,
        _ => {
            drop(stdin);
            return native_spawn_cleanup(child, ExecGateError::InvalidBinding).await;
        }
    };
    let stderr = match child.stderr.take().map(ChildStderr::from_std) {
        Some(Ok(stderr)) => stderr,
        _ => {
            drop(stdin);
            drop(stdout);
            return native_spawn_cleanup(child, ExecGateError::InvalidBinding).await;
        }
    };
    let mut child = child.into_child();
    let wait = tokio::task::spawn_blocking(move || child.wait());
    Ok(NativeBoundGatedChild {
        release: GatedChildRelease {
            binding,
            daemon_boot_id,
            execution_nonce,
            process,
            release_token,
            token_commitment,
            control: Some(control),
        },
        owner: NativeGatedChildOwner {
            process,
            wait: Some(wait),
            group_exit_verified: false,
        },
        io: Some(GatedChildIo {
            stdin,
            stdout,
            stderr,
        }),
    })
}

async fn native_spawn_cleanup(
    child: PendingNativeChildOwner,
    error: ExecGateError,
) -> Result<NativeBoundGatedChild, GatedChildSpawnError> {
    // spawn 成功后立即把唯一 StdChild 交给独立 OS owner thread。该线程
    // 在 completion 之前始终持有 Child；调用 future 被 abort 只会 detach join
    // handle，不会取消 reaper 或 Drop Child。因此持续 wait 错误/不可杀
    // child 仍保持 fail-close，但不再占住 Tokio worker 或拖死 daemon 其他通道。
    let reaper = match NativeChildReaperTask::spawn(child.into_child()) {
        Ok(reaper) => reaper,
        Err((child, _thread_error)) => {
            // OS 已无法创建 owner thread 时不能 Drop 唯一 Child。这是唯一
            // 保留的同步降级：必须先 exact kill+wait，才能返回 clean。
            reap_native_child_fail_closed(child);
            return Err(GatedChildSpawnError::NoSurvivingChild(error));
        }
    };
    match reaper.join().await {
        Ok(()) => Err(GatedChildSpawnError::NoSurvivingChild(error)),
        Err(cleanup_error) => Err(GatedChildSpawnError::ChildOutcomeUnknown(cleanup_error)),
    }
}

/// `StdCommand::spawn` 成功后的第一任 cancel-safe owner。它只在正常成功路径按值
/// 交给 waiter；任何显式错误或 future Drop 都必须先把唯一 Child 移交 OS reaper。
struct PendingNativeChildOwner {
    child: Option<StdChild>,
}

impl PendingNativeChildOwner {
    fn new(child: StdChild) -> Self {
        Self { child: Some(child) }
    }

    fn child(&self) -> &StdChild {
        self.child
            .as_ref()
            .expect("pending native child owner is populated")
    }

    fn child_mut(&mut self) -> &mut StdChild {
        self.child
            .as_mut()
            .expect("pending native child owner is populated")
    }

    fn id(&self) -> u32 {
        self.child().id()
    }

    fn into_child(mut self) -> StdChild {
        self.child
            .take()
            .expect("pending native child transfers exactly once")
    }
}

impl std::ops::Deref for PendingNativeChildOwner {
    type Target = StdChild;

    fn deref(&self) -> &Self::Target {
        self.child()
    }
}

impl std::ops::DerefMut for PendingNativeChildOwner {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.child_mut()
    }
}

impl Drop for PendingNativeChildOwner {
    fn drop(&mut self) {
        let Some(child) = self.child.take() else {
            return;
        };
        match NativeChildReaperTask::spawn(child) {
            Ok(reaper) => {
                // Drop JoinHandle 只 detach；OS thread 与其 channel 已持有 Child。
                drop(reaper);
            }
            Err((child, _thread_error)) => {
                // thread 资源耗尽时仍不能只 Drop。同步 fail-close 是最后兜底，且
                // 只有 wait 成功或明确 ECHILD 才会返回当前 Drop。
                reap_native_child_fail_closed(child);
            }
        }
    }
}

struct NativeChildReaperTask {
    completion: oneshot::Receiver<()>,
    owner: Option<std::thread::JoinHandle<()>>,
}

impl NativeChildReaperTask {
    fn spawn(child: StdChild) -> Result<Self, (StdChild, io::Error)> {
        Self::spawn_with_before_reap(child, || {})
    }

    fn spawn_with_before_reap<F>(
        child: StdChild,
        before_reap: F,
    ) -> Result<Self, (StdChild, io::Error)>
    where
        F: FnOnce() + Send + 'static,
    {
        // 先创建 OS thread，再通过 channel 按值移交 Child。若 thread 创建
        // 或移交失败，SendError 会把原 Child 还给调用方，绝不会因
        // closure 创建失败而只执行 Drop。
        let (child_sender, child_receiver) = std::sync::mpsc::channel::<StdChild>();
        let (completion_sender, completion) = oneshot::channel();
        let owner = match std::thread::Builder::new()
            .name("agentdeck-native-child-reaper".to_owned())
            .spawn(move || {
                let Ok(child) = child_receiver.recv() else {
                    return;
                };
                let owner = FailClosedNativeChildOwner::new(child);
                before_reap();
                owner.reap();
                let _ = completion_sender.send(());
            }) {
            Ok(owner) => owner,
            Err(error) => return Err((child, error)),
        };
        if let Err(error) = child_sender.send(child) {
            let child = error.0;
            let _ = owner.join();
            return Err((
                child,
                io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "native child reaper exited before ownership transfer",
                ),
            ));
        }
        Ok(Self {
            completion,
            owner: Some(owner),
        })
    }

    async fn join(mut self) -> Result<(), ExecGateError> {
        let completed = (&mut self.completion).await;
        let owner = self.owner.take().ok_or_else(|| {
            ExecGateError::Wait(io::Error::other("native child reaper owner is missing"))
        })?;
        let joined = owner.join();
        if completed.is_ok() && joined.is_ok() {
            Ok(())
        } else {
            Err(ExecGateError::Wait(io::Error::other(
                "native child reaper terminated before exact wait completion",
            )))
        }
    }
}

/// OS reaper thread 内的最后一道 fail-close owner。即使线程在测试 hook
/// 或后续维护代码中 panic，unwind 也会在该 OS thread 内完成 kill+wait，
/// 不会把唯一 Child 变成无主进程。
struct FailClosedNativeChildOwner {
    child: Option<StdChild>,
}

impl FailClosedNativeChildOwner {
    fn new(child: StdChild) -> Self {
        Self { child: Some(child) }
    }

    fn reap(mut self) {
        if let Some(child) = self.child.take() {
            reap_native_child_fail_closed(child);
        }
    }
}

impl Drop for FailClosedNativeChildOwner {
    fn drop(&mut self) {
        if let Some(child) = self.child.take() {
            reap_native_child_fail_closed(child);
        }
    }
}

fn reap_native_child_fail_closed(mut child: StdChild) {
    loop {
        let _ = child.kill();
        match child.wait() {
            Ok(_) => return,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if error.raw_os_error() == Some(libc::ECHILD) => return,
            Err(_) => std::thread::sleep(Duration::from_millis(10)),
        }
    }
}

impl GatedChildRelease {
    pub(crate) async fn release(self, permit: ExecutionReleasePermit) -> Result<(), ExecGateError> {
        let observed_binding = GateBinding::Command {
            command_id: permit.command_id(),
        };
        self.release_exact(
            observed_binding,
            permit.daemon_boot_id(),
            permit.execution_nonce(),
            (
                permit.process_group_id(),
                permit.leader_pid(),
                permit.leader_start_time(),
            ),
            permit.fence_payload(),
            permit.release_authorized_at_ms(),
        )
        .await
    }

    #[allow(
        dead_code,
        reason = "C-e4 coordinator consumes the durable native release permit"
    )]
    pub(crate) async fn release_native_metadata(
        self,
        permit: NativeMetadataEffectReleasePermit,
    ) -> Result<(), ExecGateError> {
        let observed_binding = GateBinding::NativeMetadata {
            conversation_id: permit.conversation_id(),
            idempotency_token: *permit.idempotency_token(),
        };
        let process = permit.process();
        self.release_exact(
            observed_binding,
            permit.daemon_boot_id(),
            permit.effect_nonce(),
            (
                process.process_group_id(),
                process.leader_pid(),
                process.leader_start_time(),
            ),
            permit.release_token_commitment(),
            permit.release_authorized_at_ms(),
        )
        .await
    }

    async fn release_exact(
        mut self,
        observed_binding: GateBinding,
        daemon_boot_id: RuntimeId,
        execution_nonce: &[u8],
        process: (i64, i64, u64),
        token_commitment: &[u8],
        release_authorized_at_ms: u64,
    ) -> Result<(), ExecGateError> {
        if !self.binding.exact_eq(&observed_binding)
            || daemon_boot_id != self.daemon_boot_id
            || !constant_time_eq(execution_nonce, &self.execution_nonce)
            || process.0 != self.process.process_group_id()
            || process.1 != self.process.leader_pid()
            || process.2 != self.process.leader_start_time()
            || !constant_time_eq(token_commitment, &self.token_commitment)
            || release_authorized_at_ms == 0
        {
            return Err(ExecGateError::ReleaseMismatch);
        }
        let mut control = self.control.take().ok_or(ExecGateError::ReleaseMismatch)?;
        let release = match observed_binding {
            GateBinding::Command { command_id } => ParentFrame::Release {
                command_id: command_id.to_canonical_string(),
                daemon_boot_id: daemon_boot_id.to_canonical_string(),
                execution_nonce: execution_nonce.to_vec(),
                process_group_id: process.0,
                leader_pid: process.1,
                leader_start_time: process.2,
                release_token: self.release_token.to_vec(),
                token_commitment: self.token_commitment.to_vec(),
                release_authorized_at_ms,
            },
            GateBinding::NativeMetadata {
                conversation_id,
                idempotency_token,
            } => ParentFrame::ReleaseNativeMetadata {
                conversation_id: conversation_id.to_canonical_string(),
                idempotency_token: idempotency_token.to_vec(),
                daemon_boot_id: daemon_boot_id.to_canonical_string(),
                effect_nonce: execution_nonce.to_vec(),
                process_group_id: process.0,
                leader_pid: process.1,
                leader_start_time: process.2,
                release_token: self.release_token.to_vec(),
                token_commitment: self.token_commitment.to_vec(),
                release_authorized_at_ms,
            },
        };
        tokio::task::spawn_blocking(move || write_parent_frame(&mut control, &release))
            .await
            .map_err(|_| {
                ExecGateError::Control(io::Error::other("exec gate release worker failed"))
            })??;
        Ok(())
    }
}

impl GatedChildOwner {
    /// fencing 已经以 exact live sentinel identity 向整个 group 发信号；随后等待 sentinel
    /// 并让 OS controller 证明整个 PGID 已退出。单独的 child status 不是 terminal
    /// capability，后台 vendor/tool child 仍可能继续产生副作用。
    pub(crate) async fn wait_and_verify_group_exit(
        &mut self,
        processes: &dyn ProcessGroupController,
        timeout: Duration,
    ) -> Result<std::process::ExitStatus, ExecGateError> {
        let status = self.child.wait().await.map_err(ExecGateError::Wait)?;
        let observation = processes
            .wait_for_exit(self.process, timeout)
            .await
            .map_err(|error| ExecGateError::ProcessGroup(io::Error::other(error)))?;
        require_group_exited(observation)?;
        self.group_exit_verified = true;
        Ok(status)
    }
}

impl NativeGatedChildOwner {
    pub(crate) async fn wait_and_verify_group_exit(
        &mut self,
        processes: &dyn ProcessGroupController,
        timeout: Duration,
    ) -> Result<std::process::ExitStatus, ExecGateError> {
        let wait = self.wait.take().ok_or(ExecGateError::InvalidBinding)?;
        let status = wait
            .await
            .map_err(|_| ExecGateError::Wait(io::Error::other("native gate waiter failed")))?
            .map_err(ExecGateError::Wait)?;
        let observation = processes
            .wait_for_exit(self.process, timeout)
            .await
            .map_err(|error| ExecGateError::ProcessGroup(io::Error::other(error)))?;
        require_group_exited(observation)?;
        self.group_exit_verified = true;
        Ok(status)
    }
}

impl std::fmt::Debug for GatedChild {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GatedChild")
            .field("execution_id", &"[REDACTED]")
            .field("process_identity", &"[REDACTED]")
            .field("release_capability", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for NativeMetadataGatedChild {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeMetadataGatedChild")
            .field("binding", &"[REDACTED]")
            .field("process_identity", &"[REDACTED]")
            .field("release_capability", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl Drop for GatedChildOwner {
    fn drop(&mut self) {
        if self.group_exit_verified {
            return;
        }

        // 威胁场景：`Child::wait` 已收割 sentinel、但后续 group absence 验证失败；若仍
        // 用持久化 identity PID 启动 raw waitpid，该 PID 可已复用为 daemon 的其他 child。
        // `Child::id == None` 表示本 owner 已无可收割的 direct child，必须立即停止。
        let Some(owned_child_pid) = self.child.id() else {
            return;
        };
        // `kill_on_drop` only targets the direct child. The gate is a persistent sentinel leader of
        // an isolated process group, so this owner may kill the whole group only while the exact
        // PID/start-time/PGID identity is still observable. Once the sentinel has been reaped, the
        // integer PGID is no longer a capability and must never authorize another group signal.
        let process = self.process;
        let exact_leader_is_alive =
            ProcessIdentity::for_process_group_leader(process.leader_pid()).ok() == Some(process);
        if exact_leader_is_alive {
            signal_group_best_effort(process.process_group_id(), libc::SIGKILL);
        }
        let _ = self.child.start_kill();
        spawn_drop_reaper(i64::from(owned_child_pid));
    }
}

impl Drop for NativeGatedChildOwner {
    fn drop(&mut self) {
        if self.group_exit_verified {
            return;
        }
        // wait task 从 spawn 成功起唯一持有 std Child 并最终 wait/reap；Drop 只在
        // exact leader identity 仍匹配时 KILL 整组，绝不按已失效的整数 PGID 发信号。
        let exact_leader_is_alive =
            ProcessIdentity::for_process_group_leader(self.process.leader_pid()).ok()
                == Some(self.process);
        if exact_leader_is_alive {
            signal_group_best_effort(self.process.process_group_id(), libc::SIGKILL);
        }
        // JoinHandle drop 只 detach；spawn_blocking waiter 继续持有并收割 exact Child。
        self.wait.take();
    }
}

async fn reap_failed_spawn(child: &mut Child) {
    if let Some(pid) = child.id() {
        let pid = i64::from(pid);
        if let Ok(process) = ProcessIdentity::for_process_group_leader(pid) {
            signal_group_best_effort(process.process_group_id(), libc::SIGKILL);
        }
    }
    let _ = child.start_kill();
    let _ = child.wait().await;
}

fn signal_group_best_effort(process_group_id: i64, signal: libc::c_int) {
    let Ok(process_group_id) = i32::try_from(process_group_id) else {
        return;
    };
    if process_group_id <= 1 {
        return;
    }
    // SAFETY: callers pass an isolated gate-owned PGID; a negative PID targets only that group.
    unsafe {
        libc::kill(-process_group_id, signal);
    }
}

fn spawn_drop_reaper(owned_child_pid: i64) {
    let Ok(owned_child_pid) = i32::try_from(owned_child_pid) else {
        return;
    };
    let _ = std::thread::Builder::new()
        .name("agentdeck-exec-reaper".to_owned())
        .spawn(move || {
            let mut status = 0;
            loop {
                // SAFETY: owned_child_pid came from the still-live Child owned by this owner.
                let result = unsafe { libc::waitpid(owned_child_pid, &raw mut status, 0) };
                if result == owned_child_pid {
                    break;
                }
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                // Tokio's orphan reaper may win the waitpid race; ECHILD is therefore complete
                // from this thread's perspective.
                break;
            }
        });
}

fn require_group_exited(observation: ProcessObservation) -> Result<(), ExecGateError> {
    if observation == ProcessObservation::Exited {
        Ok(())
    } else {
        Err(ExecGateError::ProcessGroupNotExited)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    use agentdeck_protocol::runtime::{
        CodexConversationConfiguration, ConversationConfiguration, PromptPayload,
        VendorConfigurationSnapshot,
    };
    use agentdeck_protocol::{CodexApprovalPolicy, CodexReasoningEffort, CodexSandboxMode};

    use crate::agent::{
        AdapterStateHandle, AgentTurnContractError, AgentTurnRequest, ExecSpec,
        MAX_EXEC_ARGUMENT_BYTES, MAX_EXEC_ARGUMENTS, MAX_EXEC_CONTROL_FRAME_BYTES,
        MAX_EXEC_PATH_BYTES, MAX_EXEC_SINGLE_ARGUMENT_BYTES,
    };
    use crate::runtime::process_identity::SystemProcessGroupController;
    use crate::runtime::store::RuntimeIdKind;

    fn path_with_encoded_len(length: usize, fill: u8) -> std::path::PathBuf {
        assert!(length >= 1);
        let mut bytes = vec![fill; length];
        bytes[0] = b'/';
        std::path::PathBuf::from(OsString::from_vec(bytes))
    }

    fn execution_configuration() -> ConversationConfiguration {
        ConversationConfiguration::new(VendorConfigurationSnapshot::Codex(
            CodexConversationConfiguration::new(
                CodexApprovalPolicy::Never,
                CodexSandboxMode::ReadOnly,
                CodexReasoningEffort::High,
            ),
        ))
    }

    #[tokio::test]
    async fn tokio_spawn_and_later_failures_never_claim_no_surviving_child() {
        // 威胁场景：缺失 gate binary 通常在 std spawn 阶段失败，但 Tokio 的公开 Err
        // 不能区分它与 OS child 已创建后的异步封装失败；若凭具体 errno 猜 clean，资源
        // 异常时仍会泄漏 child 并启动 successor。真实样本必须共同保持 fail-close。
        let request = AgentTurnRequest::new(
            ExecutionId::from_command_id(
                RuntimeId::from_bytes(RuntimeIdKind::Command, [0x51; 16]).unwrap(),
            )
            .unwrap(),
            "/tmp",
            PromptPayload::new("spawn disposition").unwrap(),
            3,
            execution_configuration(),
        )
        .unwrap();
        let spec = ExecSpec::new(
            &request,
            AdapterStateHandle::new(
                RuntimeId::from_bytes(RuntimeIdKind::AdapterState, [0x52; 16]).unwrap(),
            )
            .unwrap(),
            "/usr/bin/true",
            std::iter::empty::<OsString>(),
            "/tmp",
        )
        .unwrap();
        let daemon_boot_id = RuntimeId::from_bytes(RuntimeIdKind::DaemonBoot, [0x53; 16]).unwrap();

        let spawn_error = match GatedChild::spawn_with_binary(
            Path::new("/definitely/missing/agentdeckd"),
            daemon_boot_id,
            b"missing-gate-binary".to_vec(),
            spec.checked_for_test(),
        )
        .await
        {
            Ok(_) => panic!("missing binary unexpectedly spawned"),
            Err(error) => error,
        };
        assert!(!spawn_error.permits_clean_prepare_failure());

        let child_created = match GatedChild::spawn_with_binary(
            Path::new("/usr/bin/false"),
            daemon_boot_id,
            b"child-before-handshake-failure".to_vec(),
            spec.checked_for_test(),
        )
        .await
        {
            Ok(_) => panic!("non-gate binary unexpectedly completed the handshake"),
            Err(error) => error,
        };
        assert!(!child_created.permits_clean_prepare_failure());
    }

    #[tokio::test]
    async fn native_std_spawn_returns_clean_only_after_zero_child_or_exact_wait() {
        let binding = GateBinding::NativeMetadata {
            conversation_id: RuntimeId::from_bytes(RuntimeIdKind::Conversation, [0x54; 16])
                .expect("native spawn conversation id"),
            idempotency_token: [0x55; 32],
        };
        let daemon_boot_id = RuntimeId::from_bytes(RuntimeIdKind::DaemonBoot, [0x56; 16]).unwrap();
        let spec =
            NativeMetadataEffectSpec::new("/usr/bin/true", std::iter::empty::<OsString>(), "/tmp")
                .expect("valid native spawn spec");

        let missing = NativeMetadataGatedChild::spawn_with_binary(
            Path::new("/definitely/missing/agentdeckd"),
            binding,
            daemon_boot_id,
            b"native-missing-binary".to_vec(),
            &spec,
        )
        .await
        .expect_err("missing native gate binary must fail");
        assert!(missing.permits_clean_prepare_failure());

        let non_gate = NativeMetadataGatedChild::spawn_with_binary(
            Path::new("/usr/bin/false"),
            binding,
            daemon_boot_id,
            b"native-child-before-handshake-failure".to_vec(),
            &spec,
        )
        .await
        .expect_err("non-gate native binary must fail handshake");
        assert!(
            non_gate.permits_clean_prepare_failure(),
            "std Child must be SIGKILL+wait complete before clean disposition"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn native_os_reaper_keeps_child_ownership_after_join_future_is_aborted() {
        // 威胁场景：post-spawn handshake 失败后，request/runtime task 在 cleanup
        // await 期间被 abort。若 Child 只在 async future 里，Drop 会留下
        // 未收割的 gate；若在 Tokio worker 里直接 wait，又会阻塞整个
        // current-thread runtime。OS owner 必须在 future 取消后继续 kill+wait。
        let child = StdCommand::new("/bin/sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn native reaper fixture");
        let child_pid = i32::try_from(child.id()).expect("fixture pid fits i32");
        let (entered_sender, entered_receiver) = std::sync::mpsc::sync_channel(1);
        let (release_sender, release_receiver) = std::sync::mpsc::sync_channel(0);
        let reaper = NativeChildReaperTask::spawn_with_before_reap(child, move || {
            let _ = entered_sender.send(());
            let _ = release_receiver.recv();
        })
        .map_err(|(_, error)| error)
        .expect("start native OS reaper");
        entered_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("OS reaper owns child before cancellation");

        let cleanup = tokio::spawn(reaper.join());
        tokio::task::yield_now().await;
        cleanup.abort();
        assert!(
            cleanup
                .await
                .expect_err("cleanup future must be canceled")
                .is_cancelled(),
            "test canceled the join future rather than the OS reaper"
        );
        tokio::time::timeout(Duration::from_millis(100), tokio::task::yield_now())
            .await
            .expect("blocked OS reaper must not occupy the current Tokio worker");

        release_sender
            .send(())
            .expect("allow detached OS reaper to finish");
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                // SAFETY: signal 0 only probes the exact fixture PID. The reaper must both
                // SIGKILL and wait it before this PID disappears.
                if unsafe { libc::kill(child_pid, 0) } != 0
                    && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("detached OS reaper kills and reaps the exact child");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn aborting_production_native_spawn_during_handshake_reaps_exact_child() {
        // 威胁场景：production spawn 已成功，但子进程故意不回 Ready；调用 task 在
        // handshake await 中被 abort。Pending owner 必须从 spawn 后第一时间持有 Child，
        // Drop 后转交 OS reaper，且不能阻塞这个 current-thread Tokio runtime。
        let root = Path::new("/tmp").join(format!(
            "agentdeck-native-handshake-abort-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).expect("create native handshake abort root");
        let script = root.join("blocked-gate.sh");
        let pid_file = root.join("child.pid");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\necho $$ > '{}'\nread ignored\n",
                pid_file.display()
            ),
        )
        .expect("write blocked native gate fixture");
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700))
            .expect("make blocked native gate fixture executable");

        let binding = GateBinding::NativeMetadata {
            conversation_id: RuntimeId::from_bytes(RuntimeIdKind::Conversation, [0x71; 16])
                .expect("handshake abort conversation id"),
            idempotency_token: [0x72; 32],
        };
        let daemon_boot_id = RuntimeId::from_bytes(RuntimeIdKind::DaemonBoot, [0x73; 16])
            .expect("handshake abort daemon boot id");
        let spec =
            NativeMetadataEffectSpec::new("/usr/bin/true", std::iter::empty::<OsString>(), "/tmp")
                .expect("handshake abort native spec");
        let attempt = tokio::spawn(async move {
            NativeMetadataGatedChild::spawn_with_binary(
                &script,
                binding,
                daemon_boot_id,
                b"native-handshake-abort".to_vec(),
                &spec,
            )
            .await
        });

        let child_pid = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Ok(raw) = std::fs::read_to_string(&pid_file)
                    && let Ok(pid) = raw.trim().parse::<i32>()
                {
                    break pid;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("production child enters blocked handshake");
        attempt.abort();
        assert!(
            attempt
                .await
                .expect_err("production spawn task must be canceled")
                .is_cancelled(),
            "test canceled the production spawn future during handshake"
        );
        tokio::time::timeout(Duration::from_millis(100), tokio::task::yield_now())
            .await
            .expect("handshake cleanup must not occupy the current Tokio worker");

        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                // SAFETY: signal 0 only probes the exact fixture PID. A zombie still exists
                // here, so ESRCH proves another owner already completed wait/reap; this test
                // must not race the production reaper by calling waitpid in the polling loop.
                if unsafe { libc::kill(child_pid, 0) } == -1
                    && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("aborted production handshake child is killed and reaped");
        // SAFETY: this is a single postcondition probe after ESRCH. ECHILD proves the test
        // process no longer owns an unreaped direct child and did not perform the reap itself.
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(child_pid, &raw mut status, libc::WNOHANG) },
            -1
        );
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
        std::fs::remove_dir_all(&root).expect("remove native handshake abort fixture");
    }

    #[test]
    fn production_prepare_encoder_accepts_the_exact_checked_exec_spec_maximum() {
        // 威胁场景：raw integration harness 自己编码成功，但 production parent 从
        // CheckedExecSpec 生成 frame 时截断或拒绝同一合法上界，真实 adapter 才暴露故障。
        let execution_id = ExecutionId::from_command_id(
            RuntimeId::from_bytes(RuntimeIdKind::Command, [0x61; 16]).unwrap(),
        )
        .unwrap();
        let request = AgentTurnRequest::new(
            execution_id,
            "/tmp",
            PromptPayload::new("exact parent encoder").unwrap(),
            3,
            execution_configuration(),
        )
        .unwrap();
        let adapter_state = AdapterStateHandle::new(
            RuntimeId::from_bytes(RuntimeIdKind::AdapterState, [0x62; 16]).unwrap(),
        )
        .unwrap();
        let arguments = std::iter::repeat_n(
            OsString::from_vec(vec![b'a'; MAX_EXEC_SINGLE_ARGUMENT_BYTES]),
            MAX_EXEC_ARGUMENT_BYTES / MAX_EXEC_SINGLE_ARGUMENT_BYTES,
        )
        .collect::<Vec<_>>();
        assert!(arguments.len() <= MAX_EXEC_ARGUMENTS);
        let program = path_with_encoded_len(MAX_EXEC_PATH_BYTES, b'p');
        let exact_cwd_bytes = MAX_EXEC_CONTROL_FRAME_BYTES
            - MAX_EXEC_ARGUMENT_BYTES
            - MAX_EXEC_PATH_BYTES
            - (3 + arguments.len()) * std::mem::size_of::<u64>();
        let cwd = path_with_encoded_len(exact_cwd_bytes, b'c');
        let spec = ExecSpec::new(
            &request,
            adapter_state,
            program,
            arguments.clone(),
            cwd.clone(),
        )
        .expect("constructor accepts the exact structural maximum");
        let daemon_boot_id = RuntimeId::from_bytes(RuntimeIdKind::DaemonBoot, [0x63; 16]).unwrap();
        let nonce = b"production-parent-exact-max";
        let frame = prepare_frame(daemon_boot_id, nonce, spec.checked_for_test());
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        let writer = std::thread::spawn(move || {
            write_parent_frame(&mut writer, &frame).expect("production encoder writes exact max");
        });
        let decoded = super::super::read_parent_frame(&mut reader)
            .expect("production decoder reads exact max");
        writer.join().expect("join production encoder");
        let ParentFrame::Prepare {
            execution_nonce,
            program,
            arguments: decoded_arguments,
            cwd: decoded_cwd,
            ..
        } = decoded
        else {
            panic!("exact max encoded as a non-prepare frame");
        };
        assert_eq!(execution_nonce, nonce);
        assert_eq!(program.len(), MAX_EXEC_PATH_BYTES);
        assert_eq!(decoded_arguments.len(), arguments.len());
        assert_eq!(decoded_cwd.len(), exact_cwd_bytes);

        let oversized = ExecSpec::new(
            &request,
            adapter_state,
            path_with_encoded_len(MAX_EXEC_PATH_BYTES, b'p'),
            arguments,
            path_with_encoded_len(exact_cwd_bytes + 1, b'c'),
        );
        assert!(matches!(
            oversized,
            Err(AgentTurnContractError::ControlFrameTooLarge)
        ));
    }

    #[test]
    fn native_parent_prepare_uses_explicit_binding_and_parent_recomputes_exact_commitment() {
        let conversation_id = RuntimeId::from_bytes(RuntimeIdKind::Conversation, [0x64; 16])
            .expect("native conversation id");
        let binding = GateBinding::NativeMetadata {
            conversation_id,
            idempotency_token: [0x65; 32],
        };
        let daemon_boot_id = RuntimeId::from_bytes(RuntimeIdKind::DaemonBoot, [0x66; 16])
            .expect("native daemon boot id");
        let nonce = b"parent-native-nonce";
        let spec = NativeMetadataEffectSpec::new(
            "/usr/bin/true",
            [OsString::from("--name"), OsString::from("exact title")],
            "/tmp",
        )
        .expect("valid native metadata effect spec");
        let frame = native_metadata_prepare_frame(binding, daemon_boot_id, nonce, &spec)
            .expect("encode native parent prepare");
        let process = ProcessIdentity::new(771, 771, 772).expect("valid native process");
        let release_token = [0x67; RELEASE_TOKEN_BYTES];
        let commitment = parent_prepare_token_commitment(&frame, process, &release_token)
            .expect("parent recomputes native commitment");

        let ParentFrame::PrepareNativeMetadata {
            conversation_id: observed_conversation,
            idempotency_token,
            effect_nonce,
            ..
        } = frame
        else {
            panic!("native parent encoded a command binding");
        };
        assert_eq!(observed_conversation, conversation_id.to_canonical_string());
        assert_eq!(idempotency_token, vec![0x65; 32]);
        assert_eq!(effect_nonce, nonce);
        assert_ne!(commitment, [0; TOKEN_COMMITMENT_BYTES]);

        let changed_spec = NativeMetadataEffectSpec::new(
            "/usr/bin/true",
            [OsString::from("--name"), OsString::from("different title")],
            "/tmp",
        )
        .expect("valid changed native metadata effect spec");
        let changed = native_metadata_prepare_frame(binding, daemon_boot_id, nonce, &changed_spec)
            .expect("encode changed native parent prepare");
        assert_ne!(
            commitment,
            parent_prepare_token_commitment(&changed, process, &release_token)
                .expect("recompute changed native commitment")
        );
    }

    #[tokio::test]
    async fn native_parent_release_emits_only_exact_authorized_binding() {
        let conversation_id = RuntimeId::from_bytes(RuntimeIdKind::Conversation, [0x68; 16])
            .expect("native release conversation id");
        let binding = GateBinding::NativeMetadata {
            conversation_id,
            idempotency_token: [0x69; 32],
        };
        let daemon_boot_id = RuntimeId::from_bytes(RuntimeIdKind::DaemonBoot, [0x6a; 16])
            .expect("native release daemon boot id");
        let nonce = b"native-release-nonce".to_vec();
        let process = ProcessIdentity::new(881, 881, 882).expect("valid release process");
        let release_token = [0x6b; RELEASE_TOKEN_BYTES];
        let token_commitment = [0x6c; TOKEN_COMMITMENT_BYTES];
        let (parent_control, mut child_control) = UnixStream::pair().expect("native release pair");
        let release = GatedChildRelease {
            binding,
            daemon_boot_id,
            execution_nonce: nonce.clone(),
            process,
            release_token,
            token_commitment,
            control: Some(parent_control),
        };
        release
            .release_exact(
                binding,
                daemon_boot_id,
                &nonce,
                (
                    process.process_group_id(),
                    process.leader_pid(),
                    process.leader_start_time(),
                ),
                &token_commitment,
                99,
            )
            .await
            .expect("write exact native release");
        let frame = super::super::read_parent_frame(&mut child_control)
            .expect("read exact native release frame");
        let ParentFrame::ReleaseNativeMetadata {
            conversation_id: observed_conversation,
            idempotency_token,
            daemon_boot_id: observed_boot,
            effect_nonce,
            process_group_id,
            leader_pid,
            leader_start_time,
            release_token: observed_token,
            token_commitment: observed_commitment,
            release_authorized_at_ms,
        } = frame
        else {
            panic!("native release was encoded as command release");
        };
        assert_eq!(observed_conversation, conversation_id.to_canonical_string());
        assert_eq!(idempotency_token, vec![0x69; 32]);
        assert_eq!(observed_boot, daemon_boot_id.to_canonical_string());
        assert_eq!(effect_nonce, nonce);
        assert_eq!(process_group_id, process.process_group_id());
        assert_eq!(leader_pid, process.leader_pid());
        assert_eq!(leader_start_time, process.leader_start_time());
        assert_eq!(observed_token, release_token);
        assert_eq!(observed_commitment, token_commitment);
        assert_eq!(release_authorized_at_ms, 99);

        let (control, _reader) = UnixStream::pair().expect("mismatch release pair");
        let mismatched = GatedChildRelease {
            binding,
            daemon_boot_id,
            execution_nonce: b"different-nonce".to_vec(),
            process,
            release_token,
            token_commitment,
            control: Some(control),
        };
        assert!(matches!(
            mismatched
                .release_exact(
                    binding,
                    daemon_boot_id,
                    &nonce,
                    (
                        process.process_group_id(),
                        process.leader_pid(),
                        process.leader_start_time(),
                    ),
                    &token_commitment,
                    99,
                )
                .await,
            Err(ExecGateError::ReleaseMismatch)
        ));

        let mismatch_capability = || {
            let (control, reader) = UnixStream::pair().expect("mismatch capability pair");
            (
                GatedChildRelease {
                    binding,
                    daemon_boot_id,
                    execution_nonce: nonce.clone(),
                    process,
                    release_token,
                    token_commitment,
                    control: Some(control),
                },
                reader,
            )
        };
        let (wrong_binding, _reader) = mismatch_capability();
        assert!(matches!(
            wrong_binding
                .release_exact(
                    GateBinding::Command {
                        command_id: RuntimeId::from_bytes(RuntimeIdKind::Command, [0x6d; 16])
                            .expect("mismatch command id"),
                    },
                    daemon_boot_id,
                    &nonce,
                    (
                        process.process_group_id(),
                        process.leader_pid(),
                        process.leader_start_time(),
                    ),
                    &token_commitment,
                    99,
                )
                .await,
            Err(ExecGateError::ReleaseMismatch)
        ));
        let (zero_time, _reader) = mismatch_capability();
        assert!(matches!(
            zero_time
                .release_exact(
                    binding,
                    daemon_boot_id,
                    &nonce,
                    (
                        process.process_group_id(),
                        process.leader_pid(),
                        process.leader_start_time(),
                    ),
                    &token_commitment,
                    0,
                )
                .await,
            Err(ExecGateError::ReleaseMismatch)
        ));
    }

    #[test]
    fn leader_exit_is_never_accepted_as_process_group_exit() {
        assert!(require_group_exited(ProcessObservation::Exited).is_ok());
        for observation in [
            ProcessObservation::ExactAlive,
            ProcessObservation::IdentityMismatch,
            ProcessObservation::Unknown,
        ] {
            assert!(matches!(
                require_group_exited(observation),
                Err(ExecGateError::ProcessGroupNotExited)
            ));
        }
    }

    #[tokio::test]
    async fn dropping_gate_owner_kills_and_reaps_complete_process_group() {
        // 威胁场景：actor/future 在 release 后被 abort；若 Drop 只依赖 tokio
        // `kill_on_drop`，leader 会死但 vendor tool child 仍可继续产生副作用。
        let root = std::path::Path::new("/tmp").join(format!(
            "agentdeckd-gated-child-drop-{}",
            std::process::id()
        ));
        let marker = root.join("ready");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).expect("create drop test root");

        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg(concat!(
                "trap '' TERM; /bin/sleep 60 & child=$!; ",
                "printf ready > \"$1\"; wait $child"
            ))
            .arg("drop-test")
            .arg(&marker)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        // SAFETY: the child has not started; setpgid(0, 0) creates its isolated owned group.
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) == 0 {
                    Ok(())
                } else {
                    Err(io::Error::last_os_error())
                }
            });
        }
        let child = command.spawn().expect("spawn drop-owned process group");
        let pid = i64::from(child.id().expect("drop child pid"));
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while !marker.exists() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "drop fixture did not become ready"
            );
            tokio::task::yield_now().await;
        }
        let process = ProcessIdentity::for_process_group_leader(pid)
            .expect("read exact drop fixture identity");
        let execution_id = ExecutionId::from_command_id(
            RuntimeId::from_bytes(RuntimeIdKind::Command, [0x71; 16]).unwrap(),
        )
        .unwrap();
        let gate = GatedChild {
            execution_id,
            inner: BoundGatedChild {
                release: GatedChildRelease {
                    binding: GateBinding::Command {
                        command_id: execution_id.command_id(),
                    },
                    daemon_boot_id: RuntimeId::from_bytes(RuntimeIdKind::DaemonBoot, [0x72; 16])
                        .unwrap(),
                    execution_nonce: b"drop-owner-nonce".to_vec(),
                    process,
                    release_token: [0x73; RELEASE_TOKEN_BYTES],
                    token_commitment: [0x74; TOKEN_COMMITMENT_BYTES],
                    control: None,
                },
                owner: GatedChildOwner {
                    process,
                    child,
                    group_exit_verified: false,
                },
            },
        };
        drop(gate);

        let observation = SystemProcessGroupController
            .wait_for_exit(process, Duration::from_secs(2))
            .await
            .expect("observe drop cleanup");
        if observation != ProcessObservation::Exited {
            // Keep the red test hygienic: clean the deliberately leaked child before asserting.
            unsafe {
                libc::kill(
                    -i32::try_from(process.process_group_id()).unwrap(),
                    libc::SIGKILL,
                );
            }
            let _ = SystemProcessGroupController
                .wait_for_exit(process, Duration::from_secs(2))
                .await;
        }
        assert_eq!(observation, ProcessObservation::Exited);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn drop_after_leader_reap_never_signals_an_unverifiable_pgid() {
        // 威胁场景：旧式非 sentinel leader 已回收且 tool child 仍占 PGID；若 Drop 把
        // “曾拥有 Child”继续当成 group capability，PID/PGID 在回收后复用的竞态会误杀
        // 或 raw-wait unrelated process。没有 live owned Child 时必须 fail-close，不再按
        // 持久化 leader PID 发 group signal 或启动 reaper。
        let root = std::path::Path::new("/tmp").join(format!(
            "agentdeckd-gated-child-reaped-drop-{}",
            std::process::id()
        ));
        let ready = root.join("ready");
        let release_leader = root.join("release-leader");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).expect("create reaped-drop test root");

        let mut unrelated = Command::new("/bin/sleep");
        unrelated
            .arg("60")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        // SAFETY: the child has not started; setpgid(0, 0) creates a separate control group.
        unsafe {
            unrelated.pre_exec(|| {
                if libc::setpgid(0, 0) == 0 {
                    Ok(())
                } else {
                    Err(io::Error::last_os_error())
                }
            });
        }
        let mut unrelated = unrelated.spawn().expect("spawn unrelated process group");
        let unrelated_pid = i32::try_from(unrelated.id().expect("unrelated pid")).unwrap();

        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg(concat!(
                "trap '' HUP TERM; ",
                "/bin/sh -c 'trap \"\" HUP TERM; while :; do /bin/sleep 1; done' & child=$!; ",
                "printf '%s' \"$child\" > \"$1\"; ",
                "while [ ! -e \"$2\" ]; do /bin/sleep 0.01; done; ",
                "exit 0"
            ))
            .arg("reaped-drop-test")
            .arg(&ready)
            .arg(&release_leader)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        // SAFETY: the child has not started; setpgid(0, 0) creates its isolated owned group.
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) == 0 {
                    Ok(())
                } else {
                    Err(io::Error::last_os_error())
                }
            });
        }
        let child = command.spawn().expect("spawn leader-exit process group");
        let leader_pid = i64::from(child.id().expect("owned leader pid"));

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while !ready.exists() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "leader-exit fixture did not become ready"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let tool_pid = std::fs::read_to_string(&ready)
            .expect("read tool pid")
            .parse::<i32>()
            .expect("parse tool pid");
        let process = ProcessIdentity::for_process_group_leader(leader_pid)
            .expect("read exact leader-exit identity");
        assert_ne!(process.process_group_id(), i64::from(unrelated_pid));

        let execution_id = ExecutionId::from_command_id(
            RuntimeId::from_bytes(RuntimeIdKind::Command, [0x81; 16]).unwrap(),
        )
        .unwrap();
        let mut gate = GatedChild {
            execution_id,
            inner: BoundGatedChild {
                release: GatedChildRelease {
                    binding: GateBinding::Command {
                        command_id: execution_id.command_id(),
                    },
                    daemon_boot_id: RuntimeId::from_bytes(RuntimeIdKind::DaemonBoot, [0x82; 16])
                        .unwrap(),
                    execution_nonce: b"reaped-drop-owner-nonce".to_vec(),
                    process,
                    release_token: [0x83; RELEASE_TOKEN_BYTES],
                    token_commitment: [0x84; TOKEN_COMMITMENT_BYTES],
                    control: None,
                },
                owner: GatedChildOwner {
                    process,
                    child,
                    group_exit_verified: false,
                },
            },
        };
        std::fs::write(&release_leader, b"release\n").expect("release owned leader");
        assert!(
            gate.inner
                .owner
                .child
                .wait()
                .await
                .expect("owner-local wait exact leader")
                .success(),
            "owned leader did not exit cleanly"
        );
        assert!(
            gate.inner.owner.child.id().is_none(),
            "reaped Child must no longer expose a reusable raw PID"
        );
        assert_eq!(
            SystemProcessGroupController
                .probe(process)
                .await
                .expect("probe leader-gone group"),
            ProcessObservation::Unknown,
            "fixture did not reach the cancel-first Unknown window"
        );

        let pgid = i32::try_from(process.process_group_id()).unwrap();
        // SAFETY: this signal targets only the owned fixture PGID; its child explicitly ignores TERM.
        assert_eq!(unsafe { libc::kill(-pgid, libc::SIGTERM) }, 0);
        tokio::time::sleep(Duration::from_millis(50)).await;
        // SAFETY: signal 0 only probes the exact fixture child/unrelated PIDs.
        assert_eq!(
            unsafe { libc::kill(tool_pid, 0) },
            0,
            "tool did not ignore TERM"
        );
        assert_eq!(
            unsafe { libc::kill(unrelated_pid, 0) },
            0,
            "unrelated group died before owner drop"
        );

        drop(gate);
        tokio::time::sleep(Duration::from_millis(50)).await;
        // SAFETY: signal 0 only probes the deliberately surviving fixture tool.
        let tool_alive_after_drop = unsafe { libc::kill(tool_pid, 0) } == 0;
        // SAFETY: signal 0 only probes the unrelated control process.
        let unrelated_alive = unsafe { libc::kill(unrelated_pid, 0) } == 0;
        // Keep the fail-closed fixture hygienic after observing that Drop did not use an unsafe
        // post-reap PGID capability.
        // SAFETY: pgid is the exact isolated test group captured before its leader exited.
        unsafe {
            libc::kill(-pgid, libc::SIGKILL);
        }
        let _ = SystemProcessGroupController
            .wait_for_exit(process, Duration::from_secs(2))
            .await;
        let _ = unrelated.start_kill();
        let _ = unrelated.wait().await;
        let _ = std::fs::remove_dir_all(root);

        assert!(
            tool_alive_after_drop,
            "Drop used a post-reap integer PGID as a signal capability"
        );
        assert!(unrelated_alive, "cleanup killed an unrelated process group");
    }
}
