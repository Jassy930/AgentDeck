//! 桌面端自更新：查 GitHub 最新 Release，下载本平台归档并按 SHA256SUMS 校验，
//! 在安装位置旁解压后替换，由 Shell 等会话空闲再重启。
//!
//! 只有正式 Release 安装（安装根带 RELEASE-VERSION）才启用；本地构建不检查。
//! ponytail: SHA256SUMS 与归档同出一个 Release，只防下载损坏，防不了 Release 被篡改；
//! 需要时加 `gh attestation verify` 或给发布产物签名。

use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use agentdeck_protocol::{AgentKind, ThreadId};
use sha2::{Digest, Sha256};

use crate::shell::SessionKey;

pub const CURRENT: &str = env!("CARGO_PKG_VERSION");
/// 覆盖 Release 根地址（默认 GitHub），本地用 302 服务端到端测试时用。
const URL_ENV: &str = "AGENTDECK_UPDATE_URL";
const DEFAULT_URL: &str = "https://github.com/Jassy930/AgentDeck/releases";
/// 每次更新的暂存目录前缀；放在安装根旁边，保证 rename 不跨卷。
const STAGING_PREFIX: &str = ".agentdeck-update-";
/// 重启后自动打开的会话：`--reopen <host>\t<kind>\t<thread>`，本机 host 为空。
const REOPEN_ARG: &str = "--reopen";

const TARGET: &str = if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
    "aarch64-apple-darwin"
} else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
    "x86_64-apple-darwin"
} else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
    "aarch64-unknown-linux-gnu"
} else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
    "x86_64-unknown-linux-gnu"
} else if cfg!(all(windows, target_arch = "x86_64")) {
    "x86_64-pc-windows-msvc"
} else {
    ""
};

/// 归档里的顶层目录、安装根下的可执行文件与版本标记，与 scripts/release 打包布局一致。
const PACKAGE_DIR: &str = if cfg!(target_os = "macos") {
    "AgentDeck.app"
} else {
    "AgentDeck"
};
const EXE: &str = if cfg!(target_os = "macos") {
    "Contents/MacOS/AgentDeck"
} else if cfg!(windows) {
    "AgentDeck.exe"
} else {
    "agentdeck-desktop"
};
const MARKER: &str = if cfg!(target_os = "macos") {
    "Contents/Resources/RELEASE-VERSION"
} else {
    "RELEASE-VERSION"
};
const NULL_DEVICE: &str = if cfg!(windows) { "NUL" } else { "/dev/null" };

#[derive(Clone, Debug, PartialEq)]
pub enum Status {
    Idle,
    Available(String),
    Installing(String),
    /// 已替换安装目录，等用户点重启。
    Ready(String),
    /// 用户点了重启，等所有会话空闲；再点一次立即重启。
    Waiting(String),
    Failed(String, String),
}

impl Status {
    pub fn version(&self) -> Option<String> {
        match self {
            Status::Idle => None,
            Status::Available(version)
            | Status::Installing(version)
            | Status::Ready(version)
            | Status::Waiting(version)
            | Status::Failed(version, _) => Some(version.clone()),
        }
    }
}

fn archive_name() -> String {
    let ext = if cfg!(windows) { "zip" } else { "tar.gz" };
    format!("AgentDeck-{TARGET}.{ext}")
}

fn base_url() -> String {
    std::env::var(URL_ENV).unwrap_or_else(|_| DEFAULT_URL.to_string())
}

/// 正式 Release 安装的根目录（macOS 为 .app）；本地构建或未知平台返回 None。
/// 必须在替换前算好：替换后 current_exe 可能指向已改名的旧文件。
pub fn install_root() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    // Windows 上 canonicalize 会带 \\?\ 前缀，tar 和 CreateProcess 都不认。
    let exe = if cfg!(windows) {
        exe
    } else {
        exe.canonicalize().ok()?
    };
    let depth = EXE.split('/').count();
    let root = exe.ancestors().nth(depth)?.to_path_buf();
    (!TARGET.is_empty() && root.join(EXE) == exe && root.join(MARKER).is_file()).then_some(root)
}

/// 删掉上次更新留下的暂存目录（旧版本文件）；老进程可能还没退，失败就留到下次。
pub fn cleanup(root: &Path) {
    let Some(entries) = root.parent().and_then(|parent| fs::read_dir(parent).ok()) else {
        return;
    };
    for entry in entries.flatten() {
        if entry
            .file_name()
            .to_string_lossy()
            .starts_with(STAGING_PREFIX)
        {
            let _ = fs::remove_dir_all(entry.path());
        }
    }
}

fn valid_version(version: &str) -> bool {
    version.starts_with(|c: char| c.is_ascii_digit())
        && version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+'))
}

/// `…/releases/tag/v0.1.6` → `0.1.6`；版本串会拼进 URL 和路径，先校验字符集。
fn version_from_redirect(url: &str) -> Option<&str> {
    let version = url.trim().rsplit_once("/tag/v")?.1;
    valid_version(version).then_some(version)
}

/// 查最新 Release 的版本号；只取 `releases/latest` 的 302 目标，不走有限流的 API。
/// 阻塞调用，放到后台线程执行。
pub fn fetch_latest() -> Result<String, String> {
    let url = format!("{}/latest", base_url());
    let output = crate::platform::command("curl")
        .args(["-sS", "-I", "--max-time", "10", "-o", NULL_DEVICE])
        .args(["-w", "%{redirect_url}", &url])
        .output()
        .map_err(|error| format!("运行 curl 失败：{error}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    version_from_redirect(&String::from_utf8_lossy(&output.stdout))
        .map(str::to_owned)
        .ok_or_else(|| format!("{url} 没有跳转到 Release tag"))
}

pub fn is_newer(latest: &str) -> bool {
    crate::versions::compare(latest, CURRENT).is_gt()
}

fn expected_sha256<'a>(sums: &'a str, name: &str) -> Option<&'a str> {
    sums.lines().find_map(|line| {
        let (hash, file) = line.split_once("  ")?;
        (file == name).then_some(hash)
    })
}

fn sha256_file(path: &Path) -> io::Result<String> {
    let mut hasher = Sha256::new();
    io::copy(&mut fs::File::open(path)?, &mut hasher)?;
    Ok(format!("{:x}", hasher.finalize()))
}

fn run(command: &mut Command, what: &str) -> Result<(), String> {
    let output = command
        .output()
        .map_err(|error| format!("{what}失败：{error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{what}失败：{}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn io_error(path: &Path, error: io::Error) -> String {
    if error.kind() == io::ErrorKind::PermissionDenied {
        format!("没有写入 {} 的权限，请手动下载新版本", path.display())
    } else {
        format!("{}：{error}", path.display())
    }
}

/// 下载、校验、解压并替换安装根。旧文件留在暂存目录，下次启动由 [`cleanup`] 删除，
/// 在那之前可手动挪回来回滚。阻塞调用，放到后台线程执行。
pub fn install(root: &Path, version: &str) -> Result<(), String> {
    if !valid_version(version) {
        return Err(format!("版本号不合法：{version}"));
    }
    let parent = root.parent().ok_or("安装位置没有上级目录")?;
    let staging = parent.join(format!("{STAGING_PREFIX}{}", std::process::id()));
    let _ = fs::remove_dir_all(&staging);
    fs::create_dir(&staging).map_err(|error| io_error(parent, error))?;
    let result = install_into(root, version, &staging);
    if result.is_err() {
        let _ = fs::remove_dir_all(&staging);
    }
    result
}

fn install_into(root: &Path, version: &str, staging: &Path) -> Result<(), String> {
    let archive = archive_name();
    let base = format!("{}/download/v{version}", base_url());
    for name in [archive.as_str(), "SHA256SUMS"] {
        // -L 必需：GitHub 的资产下载会 302 到对象存储。
        run(
            crate::platform::command("curl")
                .args(["-fsSL", "--max-time", "600", "-o"])
                .arg(staging.join(name))
                .arg(format!("{base}/{name}")),
            &format!("下载 {name} "),
        )?;
    }
    let sums = fs::read_to_string(staging.join("SHA256SUMS")).map_err(|e| e.to_string())?;
    let expected = expected_sha256(&sums, &archive).ok_or("SHA256SUMS 里没有本平台归档")?;
    let actual = sha256_file(&staging.join(&archive)).map_err(|e| e.to_string())?;
    if actual != expected {
        return Err(format!("{archive} 校验失败，下载可能损坏"));
    }

    let unpacked = staging.join("new");
    fs::create_dir(&unpacked).map_err(|e| e.to_string())?;
    // Windows 10+ 自带的 tar 是 bsdtar，能解 zip。
    run(
        crate::platform::command("tar")
            .arg("-xf")
            .arg(staging.join(&archive))
            .arg("-C")
            .arg(&unpacked),
        "解压 ",
    )?;
    let new_root = unpacked.join(PACKAGE_DIR);
    let packaged = fs::read_to_string(new_root.join(MARKER)).unwrap_or_default();
    if packaged.trim() != version || !new_root.join(EXE).is_file() {
        return Err(format!("{archive} 内容与 v{version} 不符"));
    }

    let old = staging.join("old");
    if cfg!(windows) {
        swap_entries(root, &new_root, &old)
    } else {
        swap_dir(root, &new_root, &old)
    }
    .map_err(|error| io_error(root, error))
}

/// 整目录交换：macOS 的 .app 带签名目录结构，只能整体换；Unix 允许改名运行中程序所在的目录。
fn swap_dir(root: &Path, new: &Path, old: &Path) -> io::Result<()> {
    fs::rename(root, old)?;
    fs::rename(new, root).inspect_err(|_| {
        let _ = fs::rename(old, root);
    })
}

/// 逐项交换：Windows 不能改名含运行中 exe 的目录，但能改名 exe 本身。
fn swap_entries(root: &Path, new: &Path, old: &Path) -> io::Result<()> {
    fs::create_dir(old)?;
    let mut moved: Vec<OsString> = Vec::new();
    let result = (|| {
        for entry in fs::read_dir(new)? {
            let name = entry?.file_name();
            let dest = root.join(&name);
            moved.push(name.clone());
            if dest.exists() {
                fs::rename(&dest, old.join(&name))?;
            }
            fs::rename(new.join(&name), &dest)?;
        }
        Ok(())
    })();
    if result.is_err() {
        for name in moved.iter().rev() {
            let _ = fs::rename(root.join(name), new.join(name));
            let _ = fs::rename(old.join(name), root.join(name));
        }
    }
    result
}

/// 启动替换后的新版本；调用方随后退出。stdio 置空，免得父进程退出后子进程写管道被杀。
pub fn relaunch(root: &Path, reopen: Option<&SessionKey>) -> io::Result<()> {
    let args: Vec<String> = reopen
        .map(|key| vec![REOPEN_ARG.to_string(), encode_key(key)])
        .unwrap_or_default();
    let mut command = if cfg!(target_os = "macos") {
        let mut open = Command::new("open");
        open.arg("-n").arg(root).arg("--args");
        open
    } else {
        crate::platform::command(root.join(EXE))
    };
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(drop)
}

fn encode_key((host, kind, thread): &SessionKey) -> String {
    format!(
        "{}\t{}\t{}",
        host.as_ref().map_or("", |host| host.as_ref()),
        kind.as_str(),
        thread.0
    )
}

fn decode_key(raw: &str) -> Option<SessionKey> {
    let mut parts = raw.splitn(3, '\t');
    let host = parts.next()?;
    let kind = match parts.next()? {
        "codex" => AgentKind::Codex,
        "claude_code" => AgentKind::ClaudeCode,
        _ => return None,
    };
    let thread = parts.next().filter(|thread| !thread.is_empty())?;
    let host = (!host.is_empty()).then(|| host.to_string().into());
    Some((host, kind, ThreadId(thread.to_string())))
}

/// 上次自更新重启时停留的会话。
pub fn reopen_arg() -> Option<SessionKey> {
    let mut args = std::env::args().skip_while(|arg| arg != REOPEN_ARG);
    args.next()?;
    decode_key(&args.next()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_redirect_and_rejects_unsafe_versions() {
        let url = "https://github.com/Jassy930/AgentDeck/releases/tag/v0.1.6\n";
        assert_eq!(version_from_redirect(url), Some("0.1.6"));
        assert_eq!(
            version_from_redirect(".../tag/v0.2.0-rc.1"),
            Some("0.2.0-rc.1")
        );
        assert_eq!(version_from_redirect(""), None);
        assert_eq!(version_from_redirect(".../tag/v0.1.6/../../x"), None);
        assert_eq!(version_from_redirect(".../tag/vnext"), None);
    }

    #[test]
    fn picks_checksum_by_exact_name() {
        let sums = "aaa  AgentDeck-x.tar.gz.bak\nbbb  AgentDeck-x.tar.gz\n";
        assert_eq!(expected_sha256(sums, "AgentDeck-x.tar.gz"), Some("bbb"));
        assert_eq!(expected_sha256(sums, "missing"), None);
        assert!(!is_newer(CURRENT));
    }

    #[test]
    fn reopen_key_round_trips() {
        for host in [None, Some("user@dt".into())] {
            let key = (host, AgentKind::ClaudeCode, ThreadId("a\tb".into()));
            assert_eq!(decode_key(&encode_key(&key)), Some(key));
        }
        assert_eq!(decode_key("\tunknown\tx"), None);
    }

    fn tree(dir: &Path, files: &[(&str, &str)]) {
        fs::create_dir_all(dir).unwrap();
        for (name, body) in files {
            fs::write(dir.join(name), body).unwrap();
        }
    }

    #[test]
    fn swaps_install_root_and_keeps_old_files() {
        type Swap = fn(&Path, &Path, &Path) -> io::Result<()>;
        for (name, swap) in [("dir", swap_dir as Swap), ("entries", swap_entries)] {
            let base = std::env::temp_dir().join(format!(
                "agentdeck-update-test-{}-{name}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&base);
            let (root, new, old) = (base.join("root"), base.join("new"), base.join("old"));
            tree(&root, &[("app", "1"), ("RELEASE-VERSION", "0.1.0")]);
            tree(&new, &[("app", "2"), ("RELEASE-VERSION", "0.2.0")]);
            swap(&root, &new, &old).unwrap();
            assert_eq!(fs::read_to_string(root.join("app")).unwrap(), "2");
            assert_eq!(fs::read_to_string(old.join("app")).unwrap(), "1");

            // 新目录缺失时必须原样回滚。
            let _ = fs::remove_dir_all(&old);
            assert!(swap(&root, &base.join("missing"), &old).is_err());
            assert_eq!(fs::read_to_string(root.join("app")).unwrap(), "2");
            fs::remove_dir_all(&base).unwrap();
        }
    }
}
