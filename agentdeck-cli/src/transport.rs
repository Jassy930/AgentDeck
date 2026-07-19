//! 显式 diagnostics one-shot transport。
//!
//! 普通 CLI 命令只连接 canonical shared-daemon UDS；本模块唯一允许的 child
//! process 是用户明确请求 `diagnostics report` 时运行的一次性 daemon。它不作为
//! UDS connect/selfcheck 的 fallback。

use std::path::{Path, PathBuf};
use std::process::Command;

fn is_file(path: &Path) -> bool {
    std::fs::metadata(path)
        .map(|metadata| metadata.is_file())
        .unwrap_or(false)
}

/// 只供显式 diagnostics one-shot 定位与启动 agentdeckd。
fn locate_daemon() -> Option<PathBuf> {
    if let Ok(executable) = std::env::current_exe()
        && let Some(directory) = executable.parent()
    {
        let sibling = directory.join("agentdeckd");
        if is_file(&sibling) {
            return Some(sibling);
        }
    }
    [
        "target/debug/agentdeckd",
        "target/release/agentdeckd",
        "/usr/local/bin/agentdeckd",
        "/opt/homebrew/bin/agentdeckd",
    ]
    .into_iter()
    .map(PathBuf::from)
    .find(|candidate| is_file(candidate))
}

pub fn run_daemon_diagnostics_report(
    profile: &str,
    data_dir: Option<&str>,
) -> std::io::Result<String> {
    let path = locate_daemon().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "agentdeckd not found (build it: cargo build -p agentdeckd)",
        )
    })?;
    let mut command = Command::new(path);
    command
        .arg("--diagnostics-report")
        .arg("--profile")
        .arg(profile);
    if let Some(data_dir) = data_dir {
        command.arg("--data-dir").arg(data_dir);
    }
    let output = command.output()?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned());
    }
    Err(std::io::Error::other(format!(
        "agentdeckd --diagnostics-report failed: {}{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_lookup_is_side_effect_free() {
        let _ = locate_daemon();
    }
}
