//! OS process identity 与 process-group fencing。
//!
//! 威胁场景：daemon 重启后若只按持久化的 PID/PGID 清理 orphan，PID/PGID 已复用时
//! 会误杀无关进程；因此只有 leader 的启动时间与独立 process group 同时匹配时才允许
//! 发信号，并且只有内核确认整个 PGID 已无成员时才把 execution 判为已退出。

use std::io;
use std::time::Duration;

const PROCESS_EXIT_POLL_INTERVAL: Duration = Duration::from_millis(20);

/// 可持久化的独立 process-group 身份。
///
/// exec gate 必须是它所在 process group 的 leader，因此 `process_group_id == leader_pid`。
/// `leader_start_time` 是平台内核提供的 opaque 值，只能与同平台的后续 probe 比较。
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProcessIdentity {
    process_group_id: i64,
    leader_pid: i64,
    leader_start_time: u64,
}

impl ProcessIdentity {
    pub fn new(
        process_group_id: i64,
        leader_pid: i64,
        leader_start_time: u64,
    ) -> Result<Self, ProcessControlError> {
        // PGID 1 传给 kill(-pgid, ...) 会变成 kill(-1, ...)，其语义是向调用者
        // 有权发送信号的所有进程广播，绝不能把它当普通 process group。
        if process_group_id <= 1
            || leader_pid <= 1
            || process_group_id != leader_pid
            || leader_start_time == 0
            || i32::try_from(process_group_id).is_err()
            || i32::try_from(leader_pid).is_err()
        {
            return Err(ProcessControlError::InvalidIdentity);
        }
        Ok(Self {
            process_group_id,
            leader_pid,
            leader_start_time,
        })
    }

    /// 在 exec gate 已执行 `setpgid(0, 0)` 后读取当前 gate 的真实身份。
    ///
    /// leader start-time 与 recovery probe 共用同一平台实现，避免两边单位或来源漂移。
    #[cfg(unix)]
    pub fn for_current_process_group_leader() -> Result<Self, ProcessControlError> {
        let pid = i64::from(
            i32::try_from(std::process::id()).map_err(|_| ProcessControlError::InvalidIdentity)?,
        );
        Self::for_process_group_leader(pid)
    }

    /// 从内核独立读取指定 process-group leader 的 PGID 与启动时间。
    /// exec-gate parent 用它复核 child 自报的 Ready identity，禁止把 wire 值直接当事实。
    #[cfg(unix)]
    pub(crate) fn for_process_group_leader(leader_pid: i64) -> Result<Self, ProcessControlError> {
        let pid = i32::try_from(leader_pid).map_err(|_| ProcessControlError::InvalidIdentity)?;
        // SAFETY: getpgid 只读取当前进程的内核元数据。
        let process_group_id = unsafe { libc::getpgid(pid) };
        if process_group_id < 0 {
            return Err(ProcessControlError::Probe(io::Error::last_os_error()));
        }
        if process_group_id != pid {
            return Err(ProcessControlError::InvalidIdentity);
        }
        let leader_start_time = process_start_time(pid).map_err(ProcessControlError::Probe)?;
        Self::new(i64::from(process_group_id), leader_pid, leader_start_time)
    }

    #[cfg(not(unix))]
    pub fn for_current_process_group_leader() -> Result<Self, ProcessControlError> {
        Err(ProcessControlError::Probe(io::Error::new(
            io::ErrorKind::Unsupported,
            "process-group identity is unsupported on this platform",
        )))
    }

    pub const fn process_group_id(self) -> i64 {
        self.process_group_id
    }

    pub const fn leader_pid(self) -> i64 {
        self.leader_pid
    }

    pub const fn leader_start_time(self) -> u64 {
        self.leader_start_time
    }
}

/// exec gate 兼容入口；与 [`ProcessIdentity::for_current_process_group_leader`] 使用同一
/// 内核 start-time 来源。新调用方应优先一次性构造完整 identity，避免自行拼接 PID/PGID。
#[cfg(unix)]
pub(crate) fn current_process_start_time() -> Result<u64, ProcessControlError> {
    let pid =
        i32::try_from(std::process::id()).map_err(|_| ProcessControlError::InvalidIdentity)?;
    process_start_time(pid).map_err(ProcessControlError::Probe)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessObservation {
    /// 内核确认该 PGID 当前没有任何成员。
    Exited,
    /// PGID 存在，且 leader PID、启动时间、PGID 三者精确匹配。
    ExactAlive,
    /// PGID 仍存在，但 leader PID 已被复用或已不属于该 group。
    IdentityMismatch,
    /// PGID 仍存在，但权限或 leader 消失使其身份无法被安全证明。
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessSignal {
    Terminate,
    Kill,
}

#[cfg(unix)]
impl ProcessSignal {
    const fn as_raw(self) -> libc::c_int {
        match self {
            Self::Terminate => libc::SIGTERM,
            Self::Kill => libc::SIGKILL,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProcessControlError {
    #[error("process identity is invalid or no longer safe to target")]
    InvalidIdentity,
    #[error("process identity probe failed: {0}")]
    Probe(#[source] io::Error),
    #[error("process group signal failed: {0}")]
    Signal(#[source] io::Error),
}

#[async_trait::async_trait]
pub trait ProcessGroupController: Send + Sync + 'static {
    async fn probe(
        &self,
        identity: ProcessIdentity,
    ) -> Result<ProcessObservation, ProcessControlError>;

    async fn signal(
        &self,
        identity: ProcessIdentity,
        signal: ProcessSignal,
    ) -> Result<(), ProcessControlError>;

    async fn wait_for_exit(
        &self,
        identity: ProcessIdentity,
        timeout: Duration,
    ) -> Result<ProcessObservation, ProcessControlError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemProcessGroupController;

#[cfg(unix)]
#[async_trait::async_trait]
impl ProcessGroupController for SystemProcessGroupController {
    async fn probe(
        &self,
        identity: ProcessIdentity,
    ) -> Result<ProcessObservation, ProcessControlError> {
        probe_exact(identity)
    }

    async fn signal(
        &self,
        identity: ProcessIdentity,
        signal: ProcessSignal,
    ) -> Result<(), ProcessControlError> {
        match probe_exact(identity)? {
            ProcessObservation::ExactAlive => {}
            // 目标在 probe 与 signal 间自然退出，已经满足 fencing 目标。
            ProcessObservation::Exited => return Ok(()),
            ProcessObservation::IdentityMismatch | ProcessObservation::Unknown => {
                return Err(ProcessControlError::InvalidIdentity);
            }
        }
        let pgid = i32::try_from(identity.process_group_id)
            .map_err(|_| ProcessControlError::InvalidIdentity)?;
        // SAFETY: 上方刚核对 leader start-time 与独立 PGID；负 pid 只向该 group 发信号。
        // ProcessIdentity::new 排除了 kill(-1, ...) 的广播特例。
        if unsafe { libc::kill(-pgid, signal.as_raw()) } == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            // group 在精确 probe 后、signal 前已退出，同样是安全完成。
            Ok(())
        } else {
            Err(ProcessControlError::Signal(error))
        }
    }

    async fn wait_for_exit(
        &self,
        identity: ProcessIdentity,
        timeout: Duration,
    ) -> Result<ProcessObservation, ProcessControlError> {
        let deadline = tokio::time::Instant::now()
            .checked_add(timeout)
            .ok_or(ProcessControlError::InvalidIdentity)?;
        loop {
            let observation = probe_exact(identity)?;
            if observation == ProcessObservation::Exited {
                return Ok(ProcessObservation::Exited);
            }
            // `Unknown` after the leader has exited does not mean the process group is gone:
            // background vendor/tool children may still hold the PGID. This method is read-only,
            // so it can safely keep polling for group absence without ever signalling an identity
            // that is no longer exact. Recovery/cancel callers still receive the conservative last
            // observation when the timeout expires.
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Ok(observation);
            }
            tokio::time::sleep(PROCESS_EXIT_POLL_INTERVAL.min(deadline - now)).await;
        }
    }
}

#[cfg(not(unix))]
#[async_trait::async_trait]
impl ProcessGroupController for SystemProcessGroupController {
    async fn probe(
        &self,
        _identity: ProcessIdentity,
    ) -> Result<ProcessObservation, ProcessControlError> {
        Err(unsupported_process_control())
    }

    async fn signal(
        &self,
        _identity: ProcessIdentity,
        _signal: ProcessSignal,
    ) -> Result<(), ProcessControlError> {
        Err(unsupported_process_control())
    }

    async fn wait_for_exit(
        &self,
        _identity: ProcessIdentity,
        _timeout: Duration,
    ) -> Result<ProcessObservation, ProcessControlError> {
        Err(unsupported_process_control())
    }
}

#[cfg(not(unix))]
fn unsupported_process_control() -> ProcessControlError {
    ProcessControlError::Probe(io::Error::new(
        io::ErrorKind::Unsupported,
        "process-group control is unsupported on this platform",
    ))
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProcessGroupPresence {
    Present,
    Absent,
    Inaccessible,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LeaderObservation {
    Exact,
    Absent,
    Mismatch,
    Inaccessible,
}

#[cfg(unix)]
fn probe_exact(identity: ProcessIdentity) -> Result<ProcessObservation, ProcessControlError> {
    let pgid = i32::try_from(identity.process_group_id)
        .map_err(|_| ProcessControlError::InvalidIdentity)?;

    // `Exited` 必须证明整个 group 不存在；leader 单独退出不足以释放同 conversation。
    match process_group_presence(pgid).map_err(ProcessControlError::Probe)? {
        ProcessGroupPresence::Absent => return Ok(ProcessObservation::Exited),
        ProcessGroupPresence::Inaccessible => return Ok(ProcessObservation::Unknown),
        ProcessGroupPresence::Present => {}
    }

    let leader = probe_leader(identity)?;

    // leader probe 期间 group 可能自然退出。最后再读一次 PGID，避免把该正常竞态
    // 错报成 PID reuse；反之 group 仍存在而 leader 不可证明时必须保守阻断。
    match process_group_presence(pgid).map_err(ProcessControlError::Probe)? {
        ProcessGroupPresence::Absent => Ok(ProcessObservation::Exited),
        ProcessGroupPresence::Inaccessible => Ok(ProcessObservation::Unknown),
        ProcessGroupPresence::Present => match leader {
            LeaderObservation::Exact => Ok(ProcessObservation::ExactAlive),
            LeaderObservation::Mismatch => Ok(ProcessObservation::IdentityMismatch),
            LeaderObservation::Absent | LeaderObservation::Inaccessible => {
                Ok(ProcessObservation::Unknown)
            }
        },
    }
}

#[cfg(unix)]
fn process_group_presence(pgid: i32) -> io::Result<ProcessGroupPresence> {
    // SAFETY: signal 0 不发送信号；负 pid 查询该 PGID 是否至少还有一个成员。
    if unsafe { libc::kill(-pgid, 0) } == 0 {
        return Ok(ProcessGroupPresence::Present);
    }
    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ESRCH) => Ok(ProcessGroupPresence::Absent),
        Some(libc::EPERM) => Ok(ProcessGroupPresence::Inaccessible),
        _ => Err(error),
    }
}

#[cfg(unix)]
fn probe_leader(identity: ProcessIdentity) -> Result<LeaderObservation, ProcessControlError> {
    let pid =
        i32::try_from(identity.leader_pid).map_err(|_| ProcessControlError::InvalidIdentity)?;

    // SAFETY: signal 0 是只读的存在性/权限 probe。
    if unsafe { libc::kill(pid, 0) } != 0 {
        let error = io::Error::last_os_error();
        return match error.raw_os_error() {
            Some(libc::ESRCH) => Ok(LeaderObservation::Absent),
            Some(libc::EPERM) => Ok(LeaderObservation::Inaccessible),
            _ => Err(ProcessControlError::Probe(error)),
        };
    }

    let observed_start = match process_start_time(pid) {
        Ok(value) => value,
        Err(error) if process_disappeared(&error) => return Ok(LeaderObservation::Absent),
        Err(error) if process_inaccessible(&error) => {
            return Ok(LeaderObservation::Inaccessible);
        }
        Err(error) => return Err(ProcessControlError::Probe(error)),
    };
    if observed_start != identity.leader_start_time {
        return Ok(LeaderObservation::Mismatch);
    }

    // SAFETY: getpgid 只读取指定 PID 的内核元数据。
    let observed_group = unsafe { libc::getpgid(pid) };
    if observed_group < 0 {
        let error = io::Error::last_os_error();
        return match error.raw_os_error() {
            Some(libc::ESRCH) => Ok(LeaderObservation::Absent),
            Some(libc::EPERM) => Ok(LeaderObservation::Inaccessible),
            _ => Err(ProcessControlError::Probe(error)),
        };
    }
    if i64::from(observed_group) == identity.process_group_id {
        Ok(LeaderObservation::Exact)
    } else {
        Ok(LeaderObservation::Mismatch)
    }
}

#[cfg(unix)]
fn process_disappeared(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::NotFound || error.raw_os_error() == Some(libc::ESRCH)
}

#[cfg(unix)]
fn process_inaccessible(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::PermissionDenied || error.raw_os_error() == Some(libc::EPERM)
}

#[cfg(target_os = "macos")]
fn process_start_time(pid: i32) -> io::Result<u64> {
    // SAFETY: zeroed 是合法输出缓冲区，且 proc_pidinfo 收到精确的 buffer size；
    // 只有完整写入 struct 后才读取字段。
    let mut info = unsafe { std::mem::zeroed::<libc::proc_bsdinfo>() };
    let size = i32::try_from(std::mem::size_of::<libc::proc_bsdinfo>())
        .map_err(|_| io::Error::other("proc_bsdinfo size overflow"))?;
    // SAFETY: pid 为正，info 指向可写的 proc_bsdinfo buffer。
    let read =
        unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, (&raw mut info).cast(), size) };
    if read == 0 {
        return Err(io::Error::last_os_error());
    }
    if read != size {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "proc_pidinfo returned a partial proc_bsdinfo",
        ));
    }
    info.pbi_start_tvsec
        .checked_mul(1_000_000)
        .and_then(|value| value.checked_add(info.pbi_start_tvusec))
        .filter(|value| *value != 0)
        .ok_or_else(|| io::Error::other("process start time is zero or overflowed"))
}

#[cfg(target_os = "linux")]
fn process_start_time(pid: i32) -> io::Result<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let end = stat
        .rfind(')')
        .ok_or_else(|| io::Error::other("malformed process stat"))?;
    let fields = stat[end + 1..].split_whitespace().collect::<Vec<_>>();
    // /proc/<pid>/stat 的 starttime 是 field 22；去掉 pid/comm 后 fields[0] 是 field 3。
    fields
        .get(19)
        .ok_or_else(|| io::Error::other("process stat has no start time"))?
        .parse::<u64>()
        .map_err(io::Error::other)
        .and_then(|value| {
            if value == 0 {
                Err(io::Error::other("process start time is zero"))
            } else {
                Ok(value)
            }
        })
}

#[cfg(all(unix, not(any(target_os = "macos", target_os = "linux"))))]
fn process_start_time(_pid: i32) -> io::Result<u64> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "process start-time probing is unsupported on this Unix platform",
    ))
}
