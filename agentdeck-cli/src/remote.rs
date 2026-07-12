//! `agentdeck remote` 的 Relay v2 命令面。
//!
//! P2 仅开放不落盘的 synthetic 端到端自检。持久 Companion 配对由 P4
//! 接管；被删除的 v1 命令只在拨号前返回稳定迁移错误，绝不读取旧 secret
//! 内容、写文件或回退到旧网络路径。

use std::path::{Path, PathBuf};
use std::process::ExitCode;

mod v2_synthetic;

pub enum RemoteOpArg {
    Synthetic { bundle: PathBuf },
    LegacyV1,
    PersistentUnsupported,
}

pub async fn run(arg: RemoteOpArg, profile: &str, data_dir: Option<&str>) -> ExitCode {
    match arg {
        RemoteOpArg::Synthetic { bundle } => match v2_synthetic::run(&bundle).await {
            Ok(report) => match serde_json::to_string(&report) {
                Ok(json) => {
                    println!("{json}");
                    ExitCode::SUCCESS
                }
                Err(_) => fail("remote.synthetic.report_failed"),
            },
            Err(error) => fail(error.code()),
        },
        RemoteOpArg::LegacyV1 => fail("remote.v1.reset_required"),
        RemoteOpArg::PersistentUnsupported => match legacy_marker_state(data_dir, profile) {
            LegacyMarkerState::Present | LegacyMarkerState::Unknown => {
                fail("remote.v1.reset_required")
            }
            LegacyMarkerState::Absent => fail("remote.persistent.unsupported"),
        },
    }
}

fn fail(code: &str) -> ExitCode {
    eprintln!("{code}");
    ExitCode::FAILURE
}

/// 只探测旧凭据文件是否存在；不打开、不解析、不删除，也不读取其中任何 bearer。
fn legacy_marker_path(data_dir: Option<&str>, profile: &str) -> PathBuf {
    let base = data_dir.map_or_else(default_data_dir, PathBuf::from);
    base.join("relay")
        .join(format!("{profile}.credentials.json"))
}

enum LegacyMarkerState {
    Present,
    Absent,
    Unknown,
}

fn legacy_marker_state(data_dir: Option<&str>, profile: &str) -> LegacyMarkerState {
    match std::fs::symlink_metadata(legacy_marker_path(data_dir, profile)) {
        Ok(_) => LegacyMarkerState::Present,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => LegacyMarkerState::Absent,
        Err(_) => LegacyMarkerState::Unknown,
    }
}

#[cfg(target_os = "macos")]
fn default_data_dir() -> PathBuf {
    Path::new(&std::env::var_os("HOME").unwrap_or_default())
        .join("Library/Application Support/AgentDeck")
}

#[cfg(not(target_os = "macos"))]
fn default_data_dir() -> PathBuf {
    Path::new(&std::env::var_os("HOME").unwrap_or_default()).join(".local/share/agentdeck")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_marker_is_profile_scoped_without_reading_contents() {
        assert_eq!(
            legacy_marker_path(Some("/tmp/agentdeck-test"), "dev"),
            PathBuf::from("/tmp/agentdeck-test/relay/dev.credentials.json")
        );
    }

    #[test]
    fn legacy_marker_metadata_error_fails_closed() {
        assert!(matches!(
            legacy_marker_state(Some("/tmp/agentdeck-test"), "invalid\0profile"),
            LegacyMarkerState::Unknown
        ));
    }
}
