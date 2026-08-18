#![allow(dead_code)] // Each integration test crate uses only part of this shared helper.

use std::ffi::OsStr;
use std::fmt;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

pub const ADMIN_TIMEOUT: Duration = Duration::from_secs(10);
pub const HISTORY_TIMEOUT: Duration = Duration::from_secs(40);
pub const SESSION_TIMEOUT: Duration = Duration::from_secs(60);

const DAEMON_BIN_ENV: &str = "AGENTDECK_DAEMON_BIN";

pub fn e2e_gate_value(value: Option<&OsStr>) -> bool {
    value == Some(OsStr::new("1"))
}

pub fn real_e2e_enabled() -> bool {
    e2e_gate_value(std::env::var_os("AGENTDECK_E2E").as_deref())
}

fn is_executable_file(path: &Path) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return false;
        }
    }
    true
}

pub fn vendor_available(name: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| is_executable_file(&dir.join(name)))
}

fn required_daemon_bin() -> PathBuf {
    let value = std::env::var_os(DAEMON_BIN_ENV).unwrap_or_else(|| {
        panic!(
            "{DAEMON_BIN_ENV} must name the current checkout's built agentdeckd for CLI integration tests"
        )
    });
    assert!(!value.is_empty(), "{DAEMON_BIN_ENV} must not be empty");
    let path = PathBuf::from(value);
    assert!(
        path.is_absolute(),
        "{DAEMON_BIN_ENV} must be absolute: {}",
        path.display()
    );
    assert!(
        is_executable_file(&path),
        "{DAEMON_BIN_ENV} must point to an executable file: {}",
        path.display()
    );
    path
}

pub fn cli_command(args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_agentdeck"));
    command
        .args(args)
        .env(DAEMON_BIN_ENV, required_daemon_bin());
    command
}

#[derive(Debug)]
pub enum RunError {
    Io {
        stage: &'static str,
        source: io::Error,
    },
    DrainPanicked(&'static str),
    TimedOut {
        timeout: Duration,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    },
}

impl fmt::Display for RunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { stage, source } => write!(formatter, "{stage}: {source}"),
            Self::DrainPanicked(stream) => write!(formatter, "{stream} drain thread panicked"),
            Self::TimedOut {
                timeout,
                stdout,
                stderr,
            } => write!(
                formatter,
                "process exceeded {timeout:?}\nstdout: {}\nstderr: {}",
                String::from_utf8_lossy(stdout),
                String::from_utf8_lossy(stderr)
            ),
        }
    }
}

fn io_error(stage: &'static str, source: io::Error) -> RunError {
    RunError::Io { stage, source }
}

fn drain_thread<R>(mut reader: R) -> thread::JoinHandle<io::Result<Vec<u8>>>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes)?;
        Ok(bytes)
    })
}

fn finish_drain(
    stream: &'static str,
    handle: thread::JoinHandle<io::Result<Vec<u8>>>,
) -> Result<Vec<u8>, RunError> {
    handle
        .join()
        .map_err(|_| RunError::DrainPanicked(stream))?
        .map_err(|error| io_error(stream, error))
}

#[cfg(unix)]
fn snapshot_descendants(root_pid: i32) -> Vec<i32> {
    let Ok(output) = Command::new("ps").args(["-axo", "pid=,ppid="]).output() else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }

    let pairs: Vec<(i32, i32)> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let mut columns = line.split_whitespace();
            let pid = columns.next()?.parse().ok()?;
            let parent = columns.next()?.parse().ok()?;
            Some((pid, parent))
        })
        .collect();

    let mut descendants = Vec::new();
    let mut frontier = vec![root_pid];
    while let Some(parent) = frontier.pop() {
        for (pid, ppid) in &pairs {
            if *ppid == parent && !descendants.contains(pid) {
                descendants.push(*pid);
                frontier.push(*pid);
            }
        }
    }
    descendants
}

#[cfg(unix)]
fn kill_owned_process_tree(root_pid: i32, child: &mut std::process::Child) {
    let descendants = snapshot_descendants(root_pid);
    let current_group = unsafe { libc::getpgrp() };
    let mut descendant_groups: Vec<i32> = descendants
        .iter()
        .filter_map(|pid| {
            let group = unsafe { libc::getpgid(*pid) };
            (group > 0 && group != current_group).then_some(group)
        })
        .collect();
    descendant_groups.sort_unstable();
    descendant_groups.dedup();

    for group in descendant_groups.into_iter().rev() {
        unsafe {
            libc::kill(-group, libc::SIGKILL);
        }
    }
    for pid in descendants.into_iter().rev() {
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
    }
    // `run_command` makes the root PID its process-group ID. Use that known
    // value directly: the root may already have exited while a descendant is
    // still holding one of the captured pipes open.
    if root_pid > 0 && root_pid != current_group {
        unsafe {
            libc::kill(-root_pid, libc::SIGKILL);
        }
    }
    let _ = child.kill();
}

#[cfg(not(unix))]
fn kill_owned_process_tree(_root_pid: i32, child: &mut std::process::Child) {
    let _ = child.kill();
}

pub fn run_command(mut command: Command, timeout: Duration) -> Result<Output, RunError> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }

    let mut child = command
        .spawn()
        .map_err(|error| io_error("spawn process", error))?;
    let root_pid = child.id() as i32;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io_error("capture stdout", io::Error::other("stdout was not piped")))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io_error("capture stderr", io::Error::other("stderr was not piped")))?;
    let stdout_thread = drain_thread(stdout);
    let stderr_thread = drain_thread(stderr);

    let deadline = Instant::now() + timeout;
    let mut status: Option<ExitStatus> = None;
    loop {
        if status.is_none() {
            status = child
                .try_wait()
                .map_err(|error| io_error("poll process", error))?;
        }
        if status.is_some() && stdout_thread.is_finished() && stderr_thread.is_finished() {
            break;
        }
        if Instant::now() >= deadline {
            kill_owned_process_tree(root_pid, &mut child);
            let _ = child.wait();
            let stdout = finish_drain("stdout", stdout_thread)?;
            let stderr = finish_drain("stderr", stderr_thread)?;
            return Err(RunError::TimedOut {
                timeout,
                stdout,
                stderr,
            });
        }
        thread::sleep(Duration::from_millis(10));
    }

    let stdout = finish_drain("stdout", stdout_thread)?;
    let stderr = finish_drain("stderr", stderr_thread)?;
    Ok(Output {
        status: status.expect("completed process must have an exit status"),
        stdout,
        stderr,
    })
}

pub fn run_cli(args: &[&str], timeout: Duration) -> Output {
    run_command(cli_command(args), timeout)
        .unwrap_or_else(|error| panic!("failed to run agentdeck {args:?}: {error}"))
}
