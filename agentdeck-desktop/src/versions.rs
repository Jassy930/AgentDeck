//! 版本号提取与比较，以及从 npm registry 查询 agent CLI 的最新发布版本。

use std::cmp::Ordering;
use std::process::Command;

use agentdeck_protocol::AgentKind;

/// 从 "2.1.191 (Claude Code)" / "codex-cli 0.156.1" / "v0.1.0" 里取出版本号本体；
/// 探测失败（"… unknown"）返回 None。
pub fn extract(raw: &str) -> Option<&str> {
    if raw.ends_with("unknown") {
        return None;
    }
    raw.split_whitespace()
        .map(|part| part.strip_prefix('v').unwrap_or(part))
        .find(|part| part.starts_with(|c: char| c.is_ascii_digit()))
}

/// 语义化版本比较：先比数字核心，核心相同时带预发布后缀的更旧。
/// ponytail: 预发布之间只按字符串比，alpha.9 与 alpha.10 会排错；需要时换 semver crate。
pub fn compare(a: &str, b: &str) -> Ordering {
    fn split(v: &str) -> (Vec<u64>, Option<&str>) {
        let (core, pre) = match v.split_once('-') {
            Some((core, pre)) => (core, Some(pre)),
            None => (v, None),
        };
        let core = core.split('.').map(|n| n.parse().unwrap_or(0)).collect();
        (core, pre)
    }
    let ((core_a, pre_a), (core_b, pre_b)) = (split(a), split(b));
    core_a.cmp(&core_b).then_with(|| match (pre_a, pre_b) {
        (None, None) => Ordering::Equal,
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (Some(a), Some(b)) => a.cmp(b),
    })
}

fn npm_package(kind: AgentKind) -> &'static str {
    match kind {
        AgentKind::Codex => "@openai/codex",
        AgentKind::ClaudeCode => "@anthropic-ai/claude-code",
    }
}

/// 在本机查 npm registry 上的最新版本；阻塞调用，放到后台线程执行。
pub fn fetch_latest(kind: AgentKind) -> Result<String, String> {
    let url = format!("https://registry.npmjs.org/{}/latest", npm_package(kind));
    let output = Command::new("curl")
        .args(["-fsSL", "--max-time", "10", &url])
        .output()
        .map_err(|error| format!("运行 curl 失败：{error}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    let body: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("解析 npm 回复失败：{error}"))?;
    body["version"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| "npm 回复缺少 version".to_string())
}

#[cfg(test)]
mod tests {
    use std::cmp::Ordering::*;

    #[test]
    fn extract_and_compare_versions() {
        assert_eq!(super::extract("2.1.191 (Claude Code)"), Some("2.1.191"));
        assert_eq!(super::extract("codex-cli 0.156.1"), Some("0.156.1"));
        assert_eq!(super::extract("agentdeckd v0.1.0"), Some("0.1.0"));
        assert_eq!(super::extract("codex unknown"), None);
        assert_eq!(super::compare("0.155.0-alpha.16", "0.158.0"), Less);
        assert_eq!(super::compare("0.158.0-alpha.1", "0.158.0"), Less);
        assert_eq!(super::compare("2.1.283", "2.1.283"), Equal);
        assert_eq!(super::compare("2.1.300", "2.1.283"), Greater);
        assert_eq!(super::compare("0.10.0", "0.9.9"), Greater);
    }
}
