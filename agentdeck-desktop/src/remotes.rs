//! 已连接的远端主机列表：一行一个 ssh 目标，与 daemon 共用数据目录规则
//! （`AGENTDECK_DATA_DIR` 覆盖，否则按 stable/dev profile 选择 Application Support 目录）。

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use crate::daemon;

const FILE_NAME: &str = "desktop-remotes";

fn path() -> Option<PathBuf> {
    path_from(
        std::env::var_os("AGENTDECK_DATA_DIR").as_deref(),
        std::env::var_os("AGENTDECK_PROFILE").as_deref(),
        std::env::var_os("HOME").as_deref(),
    )
}

fn path_from(
    data_dir: Option<&OsStr>,
    profile: Option<&OsStr>,
    home: Option<&OsStr>,
) -> Option<PathBuf> {
    let dir = match data_dir.filter(|dir| !dir.is_empty()) {
        Some(dir) => PathBuf::from(dir),
        None => {
            let profile = profile
                .and_then(|profile| profile.to_str())
                .filter(|profile| !profile.is_empty())
                .unwrap_or("stable");
            let app_dir = match profile {
                "stable" => "AgentDeck",
                "dev" => "AgentDeck-Dev",
                _ => return None,
            };
            PathBuf::from(home?)
                .join("Library/Application Support")
                .join(app_dir)
        }
    };
    Some(dir.join(FILE_NAME))
}

/// 文件不存在即空列表；无效或重复的行直接跳过，不阻止其他主机加载。
pub fn load() -> Vec<String> {
    path().map_or_else(Vec::new, |path| load_from(&path))
}

pub fn save(hosts: &[&str]) -> Result<(), String> {
    let path = path().ok_or("无法确定数据目录（HOME 未设置或 AGENTDECK_PROFILE 无效）")?;
    save_to(&path, hosts)
}

fn load_from(path: &Path) -> Vec<String> {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let mut hosts: Vec<String> = Vec::new();
    for host in text.lines().map(str::trim) {
        if daemon::validate_host(host).is_ok() && !hosts.iter().any(|known| known == host) {
            hosts.push(host.to_string());
        }
    }
    hosts
}

fn save_to(path: &Path, hosts: &[&str]) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .map_err(|source| format!("创建 {} 失败：{source}", dir.display()))?;
    }
    let mut text = hosts.join("\n");
    text.push('\n');
    std::fs::write(path, text).map_err(|source| format!("保存 {} 失败：{source}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_respects_profile_and_data_dir_precedence() {
        let home = Some(OsStr::new("/Users/example"));
        for (profile, app_dir) in [
            (None, "AgentDeck"),
            (Some(""), "AgentDeck"),
            (Some("stable"), "AgentDeck"),
            (Some("dev"), "AgentDeck-Dev"),
        ] {
            assert_eq!(
                path_from(Some(OsStr::new("")), profile.map(OsStr::new), home),
                Some(
                    Path::new("/Users/example/Library/Application Support")
                        .join(app_dir)
                        .join(FILE_NAME)
                )
            );
        }
        assert_eq!(path_from(None, Some(OsStr::new("invalid")), home), None);
        assert_eq!(path_from(None, None, None), None);
        assert_eq!(
            path_from(
                Some(OsStr::new("/tmp/agentdeck-custom")),
                Some(OsStr::new("invalid")),
                None,
            ),
            Some(PathBuf::from("/tmp/agentdeck-custom/desktop-remotes"))
        );
    }

    #[test]
    fn round_trip_skips_invalid_and_duplicate_hosts() {
        let dir = std::env::temp_dir().join(format!("agentdeck-remotes-{}", std::process::id()));
        let path = dir.join("nested").join(super::FILE_NAME);
        assert!(super::load_from(&path).is_empty());

        super::save_to(&path, &["dt", "jassy@10.0.0.2"]).unwrap();
        assert_eq!(super::load_from(&path), ["dt", "jassy@10.0.0.2"]);

        std::fs::write(&path, "dt\n\n-oProxyCommand=x\ndt\n  lab  \n").unwrap();
        assert_eq!(super::load_from(&path), ["dt", "lab"]);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
