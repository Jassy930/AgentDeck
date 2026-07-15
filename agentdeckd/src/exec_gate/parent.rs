//! daemon 侧 current-binary exec-gate owner。
//!
//! 威胁场景：adapter 若能直接 spawn vendor，或 parent 只按 PID/nonce 发送 release，
//! 未提交 Fence 的错误进程就可能越过副作用边界。本模块独占 current-binary spawn、
//! 私有 FD、随机 gate token 与 exact committed release 的逐字段核验。

use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command};

use super::{
    CONTROL_FD, ChildReply, ExecGateError, GATE_PROTOCOL_VERSION, GatedChildSpawnError,
    ParentFrame, RELEASE_TOKEN_BYTES, SAFE_ENV_KEYS, TOKEN_COMMITMENT_BYTES, constant_time_eq,
    read_child_reply, trusted_vendor_path, write_parent_frame,
};
use crate::agent::{CheckedExecSpec, ExecutionId};
use crate::runtime::execution::{ExecutionReleasePermit, RuntimeProcessIdentity};
use crate::runtime::process_identity::{
    ProcessGroupController, ProcessIdentity, ProcessObservation,
};
use crate::runtime::store::RuntimeId;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
pub(crate) struct GatedChild {
    release: GatedChildRelease,
    owner: GatedChildOwner,
}

/// blocked gate 的一次性 release capability。它只拥有私有 control FD 与 committed
/// binding，不拥有 `Child`，因此 daemon 可以从 prepare 起让唯一 owner 并行等待/reap。
pub(crate) struct GatedChildRelease {
    execution_id: ExecutionId,
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
            release: GatedChildRelease {
                execution_id,
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
        let prepare = prepare_frame(daemon_boot_id, &execution_nonce, spec);
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
            Ok::<_, ExecGateError>((control, reply))
        });
        let (control, reply) = match tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake).await {
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
        let release_token = match release_token.try_into() {
            Ok(release_token) => release_token,
            Err(_) => {
                reap_failed_spawn(&mut child).await;
                return Err(GatedChildSpawnError::ChildOutcomeUnknown(
                    ExecGateError::InvalidBinding,
                ));
            }
        };
        let token_commitment = match token_commitment.try_into() {
            Ok(token_commitment) => token_commitment,
            Err(_) => {
                reap_failed_spawn(&mut child).await;
                return Err(GatedChildSpawnError::ChildOutcomeUnknown(
                    ExecGateError::InvalidBinding,
                ));
            }
        };
        Ok(Self {
            release: GatedChildRelease {
                execution_id,
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
        self.release.execution_id
    }

    pub(crate) fn runtime_process_identity(&self) -> RuntimeProcessIdentity {
        RuntimeProcessIdentity {
            process_group_id: self.release.process.process_group_id(),
            leader_pid: self.release.process.leader_pid(),
            leader_start_time: self.release.process.leader_start_time(),
            fence_payload: self.release.token_commitment.to_vec(),
        }
    }

    pub(crate) fn take_stdin(&mut self) -> Option<ChildStdin> {
        self.owner.child.stdin.take()
    }

    pub(crate) fn take_stdout(&mut self) -> Option<ChildStdout> {
        self.owner.child.stdout.take()
    }

    pub(crate) fn take_stderr(&mut self) -> Option<ChildStderr> {
        self.owner.child.stderr.take()
    }

    pub(crate) fn take_io(&mut self) -> Result<GatedChildIo, ExecGateError> {
        let stdin = self.take_stdin().ok_or(ExecGateError::InvalidBinding)?;
        let stdout = self.take_stdout().ok_or(ExecGateError::InvalidBinding)?;
        let stderr = self.take_stderr().ok_or(ExecGateError::InvalidBinding)?;
        Ok(GatedChildIo {
            stdin,
            stdout,
            stderr,
        })
    }

    /// 威胁场景：release capability 若同时拥有 `Child`，release 前取消便没有并行
    /// waiter 收割 sentinel zombie。这里把 blocked gate 拆为一次性 release capability
    /// 与唯一 direct-child owner。
    /// owner 必须立即进入 wait；release 仅写私有 control FD，不再转移或等待 Child。
    pub(crate) fn into_owner_parts(self) -> (GatedChildRelease, GatedChildOwner) {
        (self.release, self.owner)
    }

    pub(crate) fn process_identity(&self) -> ProcessIdentity {
        self.release.process
    }
}

impl GatedChildRelease {
    pub(crate) async fn release(
        mut self,
        permit: ExecutionReleasePermit,
    ) -> Result<(), ExecGateError> {
        if permit.command_id() != self.execution_id.command_id()
            || permit.daemon_boot_id() != self.daemon_boot_id
            || !constant_time_eq(permit.execution_nonce(), &self.execution_nonce)
            || permit.process_group_id() != self.process.process_group_id()
            || permit.leader_pid() != self.process.leader_pid()
            || permit.leader_start_time() != self.process.leader_start_time()
            || !constant_time_eq(permit.fence_payload(), &self.token_commitment)
            || permit.release_authorized_at_ms() == 0
        {
            return Err(ExecGateError::ReleaseMismatch);
        }
        let mut control = self.control.take().ok_or(ExecGateError::ReleaseMismatch)?;
        let release = ParentFrame::Release {
            command_id: permit.command_id().to_canonical_string(),
            daemon_boot_id: permit.daemon_boot_id().to_canonical_string(),
            execution_nonce: permit.execution_nonce().to_vec(),
            process_group_id: permit.process_group_id(),
            leader_pid: permit.leader_pid(),
            leader_start_time: permit.leader_start_time(),
            release_token: self.release_token.to_vec(),
            token_commitment: self.token_commitment.to_vec(),
            release_authorized_at_ms: permit.release_authorized_at_ms(),
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

    use agentdeck_protocol::runtime::PromptPayload;

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
            release: GatedChildRelease {
                execution_id,
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
            release: GatedChildRelease {
                execution_id,
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
        };
        std::fs::write(&release_leader, b"release\n").expect("release owned leader");
        assert!(
            gate.owner
                .child
                .wait()
                .await
                .expect("owner-local wait exact leader")
                .success(),
            "owned leader did not exit cleanly"
        );
        assert!(
            gate.owner.child.id().is_none(),
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
