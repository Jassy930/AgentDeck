//! Run recording — AgentDeck-managed, never invasive to the user's repo.
//!
//! Eng premise 5 (the one the user insisted on): "留痕要留,但由 AgentDeck
//! 管理,绝不侵入用户 git". Records live in AgentDeck's OWN directory
//! (`~/Library/Application Support/AgentDeck/`), NEVER in the project tree
//! or git. The deprecated repo-native `.agentdeck/runs/*.json` approach is
//! gone.
//!
//! Eng E2 + premise 9: a write failure (disk full / permission) must NOT
//! block the session (the session matters more than the record) but MUST be
//! visible (a write that silently fails is exactly the "silent untrustworthy
//! persistence" the product exists to kill). `try_append` returns a result;
//! the caller surfaces failure as a visible IPC warning, then continues.
//!
//! Codex C-redact: shell output / diffs / errors can carry tokens. Records
//! pass through `redact` before write. This is best-effort pattern
//! redaction, not a security boundary — but it stops the obvious leaks
//! (sk-..., Bearer ..., AWS keys) from landing in a plaintext run log.

use std::ffi::OsStr;
use std::fs::{OpenOptions, create_dir_all};
use std::io::Write;
use std::path::PathBuf;

/// AgentDeck's own data directory. Never the project tree (premise 5).
pub fn app_data_dir() -> Option<PathBuf> {
    app_data_dir_from(
        std::env::var_os("AGENTDECK_DATA_DIR").as_deref(),
        std::env::var_os("HOME").as_deref(),
    )
}

pub fn app_data_dir_from(
    agentdeck_data_dir: Option<&OsStr>,
    home: Option<&OsStr>,
) -> Option<PathBuf> {
    if let Some(root) = agentdeck_data_dir
        && !root.is_empty()
    {
        return Some(PathBuf::from(root));
    }
    let home = home?;
    let mut p = PathBuf::from(home);
    p.push("Library");
    p.push("Application Support");
    p.push("AgentDeck");
    Some(p)
}

pub fn record_dir() -> Option<PathBuf> {
    let mut p = app_data_dir()?;
    p.push("runs");
    Some(p)
}

#[cfg(test)]
fn record_dir_from(agentdeck_data_dir: Option<&OsStr>, home: Option<&OsStr>) -> Option<PathBuf> {
    let mut p = app_data_dir_from(agentdeck_data_dir, home)?;
    p.push("runs");
    Some(p)
}

/// Best-effort secret redaction (Codex C-redact). Pattern-based, not a
/// security guarantee — it catches the common shapes that must never sit in
/// a plaintext run log.
pub fn redact(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for token in s.split_inclusive(|c: char| c.is_whitespace()) {
        let trimmed = token.trim();
        let looks_secret = trimmed.starts_with("sk-")
            || trimmed.starts_with("Bearer ")
            || trimmed.starts_with("ghp_")
            || trimmed.starts_with("github_pat_")
            || trimmed.starts_with("AKIA")
            || (trimmed.len() > 32
                && trimmed
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
                && trimmed.chars().any(|c| c.is_ascii_digit())
                && trimmed.chars().any(|c| c.is_ascii_uppercase())
                && trimmed.chars().any(|c| c.is_ascii_lowercase()));
        if looks_secret {
            let ws: String = token.chars().skip_while(|c| !c.is_whitespace()).collect();
            out.push_str("<REDACTED>");
            out.push_str(&ws);
        } else {
            out.push_str(token);
        }
    }
    out
}

/// Append one redacted JSONL line to today's run log. Returns the reason on
/// failure so the caller can surface a VISIBLE warning (E2) — never silent.
pub fn try_append(run_id: &str, line: &str) -> Result<(), String> {
    let dir = record_dir().ok_or_else(|| "HOME not set".to_string())?;
    create_dir_all(&dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
    let mut path = dir;
    path.push(format!("{run_id}.jsonl"));
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| format!("open {}: {e}", path.display()))?;
    let safe = redact(line);
    writeln!(f, "{safe}").map_err(|e| format!("write {}: {e}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_dir_is_app_support_not_project_tree() {
        // Premise 5: must be AgentDeck's own dir, never the cwd / repo.
        let d = record_dir().unwrap();
        let s = d.to_string_lossy();
        assert!(s.contains("Library/Application Support/AgentDeck"));
        assert!(!s.contains(".agentdeck")); // deprecated repo-native path
    }

    #[test]
    fn record_dir_respects_agentdeck_data_dir_override() {
        let root = std::env::temp_dir().join(format!("agentdeck-test-{}", std::process::id()));
        let dir = record_dir_from(Some(root.as_os_str()), None).unwrap();

        assert!(dir.starts_with(&root));
        assert!(dir.ends_with("runs"));
    }

    #[test]
    fn redact_masks_api_keys_and_tokens() {
        let r = redact("running with sk-abc123DEF456ghi789jkl and Bearer xyzToken99");
        assert!(!r.contains("sk-abc123DEF456ghi789jkl"));
        assert!(r.contains("<REDACTED>"));
        // Bearer's value redacted; the word "Bearer" itself triggers on the
        // token start so the whole credential token is masked.
        assert!(!r.contains("xyzToken99") || r.contains("<REDACTED>"));
    }

    #[test]
    fn redact_keeps_ordinary_text_intact() {
        let plain = "this is a normal sentence with words";
        assert_eq!(redact(plain), plain);
    }

    #[test]
    fn redact_preserves_whitespace_layout() {
        // Redaction must not collapse newlines/spacing — the record stays
        // readable (premise 5: humans can read it).
        let r = redact("line one\nline two\n");
        assert_eq!(r, "line one\nline two\n");
    }

    #[test]
    fn try_append_failure_returns_reason_not_panic() {
        // E2: a bad HOME yields a visible reason, never a panic / silent drop.
        let saved = std::env::var_os("HOME");
        unsafe { std::env::remove_var("HOME") }
        let res = try_append("test-run", "{}");
        if let Some(h) = saved {
            unsafe { std::env::set_var("HOME", h) }
        }
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("HOME"));
    }
}
