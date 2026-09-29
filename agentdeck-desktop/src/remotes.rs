//! 已连接的远端主机列表：一行一个 ssh 目标，与 daemon 共用数据目录规则
//! （`AGENTDECK_DATA_DIR` 覆盖，否则按 stable/dev profile 选择 Application Support 目录）。

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

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

/// `~/.ssh/config`（含 `Include`）里的具体 Host 别名，供机器页快速添加；带通配符的模式跳过。
pub fn ssh_config_hosts() -> Vec<String> {
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        return Vec::new();
    };
    let mut hosts = Vec::new();
    collect_ssh_hosts(&home.join(".ssh/config"), &home, &mut hosts, 0);
    hosts
}

// ponytail: Include 只认具体路径，不展开 glob；有需要再接 glob 匹配。
fn collect_ssh_hosts(path: &Path, home: &Path, hosts: &mut Vec<String>, depth: usize) {
    let Ok(text) = std::fs::read_to_string(path) else {
        return;
    };
    for line in text.lines() {
        let mut words = line.split_whitespace();
        let (Some(key), rest) = (words.next(), words) else {
            continue;
        };
        if key.eq_ignore_ascii_case("host") {
            for host in rest {
                if !host.contains(['*', '?', '!'])
                    && daemon::validate_host(host).is_ok()
                    && !hosts.iter().any(|known| known == host)
                {
                    hosts.push(host.to_string());
                }
            }
        } else if key.eq_ignore_ascii_case("include") && depth < 8 {
            for include in rest {
                let include = match include.strip_prefix("~/") {
                    Some(rel) => home.join(rel),
                    None if include.starts_with('/') => PathBuf::from(include),
                    None => home.join(".ssh").join(include),
                };
                collect_ssh_hosts(&include, home, hosts, depth + 1);
            }
        }
    }
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

/// 预编译 agentdeckd 的下载地址前缀；默认是与桌面端同版本的 GitHub Release，
/// 保证装上去的 daemon 与桌面端协议一致。测试可指向 `file://` 目录。
const RELEASE_URL_ENV: &str = "AGENTDECK_RELEASE_URL";

/// 桌面端配套的 agentdeckd 版本。
pub const DAEMON_VERSION: &str = env!("CARGO_PKG_VERSION");

/// `uname -sm` → Release 资产的目标三元组。
fn release_target(uname: &str) -> Result<&'static str, String> {
    match uname.split_whitespace().collect::<Vec<_>>()[..] {
        ["Linux", "x86_64"] => Ok("x86_64-unknown-linux-musl"),
        ["Linux", "aarch64" | "arm64"] => Ok("aarch64-unknown-linux-musl"),
        _ => Err(format!("没有适用于 {uname} 的预编译 agentdeckd")),
    }
}

fn ssh(host: &str) -> Command {
    let mut command = Command::new("ssh");
    command.args(daemon::SSH_OPTIONS).args(["--", host]);
    command
}

/// 把与桌面端同版本的预编译 agentdeckd 装到远端 `~/.local/bin`：本机 curl 下载，
/// 经 ssh stdin 传过去。先写临时文件并试运行，确认能执行（架构对）才替换，
/// 也避开覆盖正在运行的可执行文件（ETXTBSY）。阻塞调用，返回新 daemon 的 `--version`。
pub fn install_daemon(host: &str) -> Result<String, String> {
    daemon::validate_host(host)?;
    let uname = ssh(host)
        .arg("uname -sm")
        .output()
        .map_err(|error| format!("运行 ssh 失败：{error}"))?;
    if !uname.status.success() {
        return Err(String::from_utf8_lossy(&uname.stderr).trim().to_string());
    }
    let target = release_target(String::from_utf8_lossy(&uname.stdout).trim())?;
    let base = std::env::var(RELEASE_URL_ENV).unwrap_or_else(|_| {
        format!("https://github.com/Jassy930/AgentDeck/releases/download/v{DAEMON_VERSION}")
    });
    let url = format!("{base}/agentdeckd-{target}.tar.gz");

    // -L 必需：GitHub 的资产下载会 302 到对象存储。
    let mut curl = Command::new("curl")
        .args(["-fsSL", "--max-time", "300", &url])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("运行 curl 失败：{error}"))?;
    let body = curl.stdout.take().expect("curl stdout piped");
    let script = r#"sh -c 'set -e; d="$HOME/.local/bin"; t="$d/.agentdeckd.tmp"; trap "rm -f \"$t\"" EXIT; mkdir -p "$d"; tar -xzO agentdeckd > "$t"; chmod 755 "$t"; "$t" --version >/dev/null; mv -f "$t" "$d/agentdeckd"; "$d/agentdeckd" --version'"#;
    let installed = ssh(host)
        .arg(script)
        .stdin(body)
        .output()
        .map_err(|error| format!("运行 ssh 失败：{error}"))?;
    let fetched = curl
        .wait_with_output()
        .map_err(|error| format!("等待 curl 失败：{error}"))?;
    // 远端先失败时 curl 会写管道失败（23）或被 SIGPIPE 杀掉，那不是下载问题。
    if !fetched.status.success() && !matches!(fetched.status.code(), Some(23) | None) {
        return Err(format!(
            "下载 agentdeckd v{DAEMON_VERSION} 失败，GitHub 上可能还没有发布 {target} 二进制（{url}：{}）",
            String::from_utf8_lossy(&fetched.stderr).trim()
        ));
    }
    if !installed.status.success() {
        return Err(format!(
            "远端安装失败：{}",
            String::from_utf8_lossy(&installed.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&installed.stdout)
        .trim()
        .to_string())
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
    fn ssh_config_hosts_follow_includes_and_skip_patterns() {
        let home = std::env::temp_dir().join(format!("agentdeck-ssh-{}", std::process::id()));
        std::fs::create_dir_all(home.join(".ssh/conf.d")).unwrap();
        std::fs::write(
            home.join(".ssh/config"),
            "Host dt\n  HostName 10.0.0.2\nHost * !bad\nhost a b.example.com a\nInclude conf.d/more\n",
        )
        .unwrap();
        std::fs::write(home.join(".ssh/conf.d/more"), "Host thor-1 thor-*\n").unwrap();
        let mut hosts = Vec::new();
        collect_ssh_hosts(&home.join(".ssh/config"), &home, &mut hosts, 0);
        assert_eq!(hosts, ["dt", "a", "b.example.com", "thor-1"]);
        std::fs::remove_dir_all(home).unwrap();
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

    #[test]
    fn release_target_maps_uname() {
        assert_eq!(
            release_target("Linux x86_64"),
            Ok("x86_64-unknown-linux-musl")
        );
        assert_eq!(
            release_target("Linux aarch64"),
            Ok("aarch64-unknown-linux-musl")
        );
        assert!(release_target("Darwin arm64").is_err());
    }
}
