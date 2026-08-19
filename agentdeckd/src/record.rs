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
        std::env::var_os("AGENTDECK_PROFILE").as_deref(),
        std::env::var_os("HOME").as_deref(),
    )
}

pub fn app_data_dir_from(
    agentdeck_data_dir: Option<&OsStr>,
    agentdeck_profile: Option<&OsStr>,
    home: Option<&OsStr>,
) -> Option<PathBuf> {
    if let Some(root) = agentdeck_data_dir
        && !root.is_empty()
    {
        return Some(PathBuf::from(root));
    }
    let profile = agentdeck_profile
        .and_then(|p| p.to_str())
        .filter(|p| !p.is_empty())
        .unwrap_or("stable");
    let app_dir_name = match profile {
        "stable" => "AgentDeck",
        "dev" => "AgentDeck-Dev",
        _ => return None,
    };
    let home = home?;
    let mut p = PathBuf::from(home);
    p.push("Library");
    p.push("Application Support");
    p.push(app_dir_name);
    Some(p)
}

pub fn record_dir() -> Option<PathBuf> {
    let mut p = app_data_dir()?;
    p.push("runs");
    Some(p)
}

#[cfg(test)]
fn record_dir_from(
    agentdeck_data_dir: Option<&OsStr>,
    agentdeck_profile: Option<&OsStr>,
    home: Option<&OsStr>,
) -> Option<PathBuf> {
    let mut p = app_data_dir_from(agentdeck_data_dir, agentdeck_profile, home)?;
    p.push("runs");
    Some(p)
}

/// Best-effort secret redaction (Codex C-redact). Pattern-based, not a
/// security guarantee — it catches the common shapes that must never sit in
/// a plaintext run log.
pub fn redact(s: &str) -> String {
    let s = redact_prefixed_secret_values(s);
    let s = redact_bearer_values(&s);
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

fn redact_prefixed_secret_values(s: &str) -> String {
    let prefixes = ["sk-", "ghp_", "github_pat_", "AKIA"];
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    loop {
        let next = prefixes
            .iter()
            .filter_map(|prefix| rest.find(prefix).map(|idx| (idx, *prefix)))
            .min_by_key(|(idx, _)| *idx);
        let Some((idx, prefix)) = next else {
            out.push_str(rest);
            break;
        };
        let (before, after_start) = rest.split_at(idx);
        out.push_str(before);
        let token_end = after_start
            .char_indices()
            .find(|(_, c)| is_secret_delimiter(*c))
            .map(|(i, _)| i)
            .unwrap_or(after_start.len());
        if token_end >= prefix.len() {
            out.push_str("<REDACTED>");
            rest = &after_start[token_end..];
        } else {
            out.push_str(prefix);
            rest = &after_start[prefix.len()..];
        }
    }
    out
}

fn redact_bearer_values(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(idx) = rest.find("Bearer ") {
        let (before, after_marker) = rest.split_at(idx + "Bearer ".len());
        out.push_str(before);
        let token_end = after_marker
            .char_indices()
            .find(|(_, c)| is_secret_delimiter(*c))
            .map(|(i, _)| i)
            .unwrap_or(after_marker.len());
        if token_end > 0 {
            out.push_str("<REDACTED>");
            rest = &after_marker[token_end..];
        } else {
            rest = after_marker;
        }
    }
    out.push_str(rest);
    out
}

fn is_secret_delimiter(c: char) -> bool {
    c.is_whitespace() || matches!(c, '"' | '\'' | ',' | '}' | ']' | ')')
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

// ── v2 RunRecord ────────────────────────────────────────────────────────────
//
// Phase 3 / Task 3C: thin record helper for v2 `ServerEvent` streams.
// Stamps the producing adapter (Codex / ClaudeCode / …) at session
// start so a single run log can be replayed without ambiguity. Wraps
// the always-on `try_append` so the redactor still runs on every line.

use agentdeck_protocol::{AgentKind, ServerEvent};

/// One run = one session = one `runs/<runId>.jsonl` file. The header
/// line records `agentKind` + `agentVersion` + `cwd` + `startedAt` so
/// the file is self-describing.
pub struct RunRecord {
    run_id: String,
    agent_kind: AgentKind,
}

impl RunRecord {
    /// Open a new run record. Writes a header line immediately so the
    /// file always carries adapter identity (even if no AgentItem ever
    /// arrives). Errors mirror `try_append` — visible to the caller, not
    /// silent.
    pub fn open(
        run_id: impl Into<String>,
        agent_kind: AgentKind,
        agent_version: impl Into<String>,
        cwd: &std::path::Path,
    ) -> Result<Self, String> {
        let run_id = run_id.into();
        let agent_version = agent_version.into();
        let header = serde_json::json!({
            "kind": "runHeader",
            "schemaVersion": 2,
            "runId": run_id,
            "agentKind": agent_kind.as_str(),
            "agentVersion": agent_version,
            "cwd": cwd,
            "startedAtMs": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
        });
        try_append(&run_id, &header.to_string())?;
        Ok(Self { run_id, agent_kind })
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    pub fn agent_kind(&self) -> AgentKind {
        self.agent_kind
    }

    /// Append one ServerEvent to the run log. Serialization failure
    /// (impossible for ServerEvent in practice) is mapped to a string
    /// error, consistent with `try_append`.
    pub fn append_event(&self, event: &ServerEvent) -> Result<(), String> {
        let line = serde_json::to_string(event)
            .map_err(|e| format!("ServerEvent serialize failed: {e}"))?;
        try_append(&self.run_id, &line)
    }

    /// Close the record by writing a footer line. Best-effort: a write
    /// failure here is logged via the returned error but doesn't poison
    /// the file (header + events are already on disk).
    pub fn close(self) -> Result<(), String> {
        let footer = serde_json::json!({
            "kind": "runFooter",
            "schemaVersion": 2,
            "runId": self.run_id,
            "agentKind": self.agent_kind.as_str(),
            "endedAtMs": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
        });
        try_append(&self.run_id, &footer.to_string())
    }
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
        let dir = record_dir_from(Some(root.as_os_str()), None, None).unwrap();

        assert!(dir.starts_with(&root));
        assert!(dir.ends_with("runs"));
    }

    #[test]
    fn app_data_dir_uses_dev_profile() {
        let home = std::ffi::OsStr::new("/Users/example");
        let dir = app_data_dir_from(None, Some(std::ffi::OsStr::new("dev")), Some(home)).unwrap();

        assert_eq!(
            dir.to_string_lossy(),
            "/Users/example/Library/Application Support/AgentDeck-Dev"
        );
    }

    #[test]
    fn app_data_dir_uses_stable_by_default() {
        let home = std::ffi::OsStr::new("/Users/example");
        let dir = app_data_dir_from(None, None, Some(home)).unwrap();

        assert_eq!(
            dir.to_string_lossy(),
            "/Users/example/Library/Application Support/AgentDeck"
        );
    }

    #[test]
    fn app_data_dir_override_wins_over_profile() {
        let override_dir = std::ffi::OsStr::new("/tmp/agentdeck-custom");
        let home = std::ffi::OsStr::new("/Users/example");
        let dir = app_data_dir_from(
            Some(override_dir),
            Some(std::ffi::OsStr::new("dev")),
            Some(home),
        )
        .unwrap();

        assert_eq!(dir.to_string_lossy(), "/tmp/agentdeck-custom");
    }

    #[test]
    fn redact_masks_api_keys_and_tokens() {
        let r = redact("running with sk-abc123DEF456ghi789jkl and Bearer xyzToken99");
        assert!(!r.contains("sk-abc123DEF456ghi789jkl"));
        assert!(r.contains("<REDACTED>"));
        // Bearer's value redacted; the word "Bearer" itself triggers on the
        // token start so the whole credential token is masked.
        assert!(!r.contains("xyzToken99"));
    }

    #[test]
    fn redact_masks_bearer_value_after_space() {
        let r = redact("Authorization: Bearer xyzToken99");
        assert!(!r.contains("xyzToken99"));
        assert!(r.contains("Bearer <REDACTED>") || r.contains("<REDACTED>"));
    }

    #[test]
    fn redact_masks_json_authorization_header() {
        let r = redact(r#"{"authorization":"Bearer xyzToken99"}"#);
        assert!(!r.contains("xyzToken99"));
    }

    #[test]
    fn redact_masks_json_api_key_value() {
        let r = redact(r#"{"token":"sk-agentdeck-selfcheck"}"#);
        assert!(!r.contains("sk-agentdeck-selfcheck"));
        assert!(r.contains("<REDACTED>"));
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

    /// Mutex used by env-mutating tests so they don't race with each
    /// other (HOME / AGENTDECK_DATA_DIR are process-global).
    static ENV_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn run_record_writes_header_and_appends_events_with_agent_kind() {
        use agentdeck_protocol::{
            AgentItem, AgentItemMeta, AgentItemState, AgentKind, ServerEvent, SessionId, ThreadId,
            TurnId,
        };
        let _guard = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());

        let dir = std::env::temp_dir().join(format!(
            "agentdeck-runrec-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        // Drive RunRecord via the AGENTDECK_DATA_DIR override.
        let prev = std::env::var_os("AGENTDECK_DATA_DIR");
        unsafe {
            std::env::set_var("AGENTDECK_DATA_DIR", &dir);
        }

        let cwd = std::path::PathBuf::from("/tmp/example");
        let rec = RunRecord::open(
            "run_test_123",
            AgentKind::Codex,
            "codex-cli 0.x".to_string(),
            &cwd,
        )
        .expect("open run record");

        let event = ServerEvent::AgentItem {
            session_id: SessionId("sid".into()),
            thread_id: ThreadId("tid".into()),
            agent_kind: AgentKind::Codex,
            turn_id: TurnId("turn-1".into()),
            item_id: "message-1".into(),
            state: AgentItemState::Completed,
            item: AgentItem::AssistantMessage {
                text: "hello".into(),
                meta: AgentItemMeta::default(),
            },
        };
        rec.append_event(&event).expect("append event");
        rec.close().expect("close run record");

        let log = dir.join("runs/run_test_123.jsonl");
        let body = std::fs::read_to_string(&log).expect("read run log");
        let lines: Vec<&str> = body.lines().collect();
        assert!(
            lines.len() >= 3,
            "expected header + event + footer, got {lines:?}"
        );
        let header: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(header["kind"], "runHeader");
        assert_eq!(header["agentKind"], "codex");
        assert_eq!(header["agentVersion"], "codex-cli 0.x");
        let event_line: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(event_line["type"], "agentItem");
        assert_eq!(event_line["agentKind"], "codex");
        assert_eq!(event_line["turnId"], "turn-1");
        assert_eq!(event_line["itemId"], "message-1");
        assert_eq!(event_line["state"], "completed");
        let footer: serde_json::Value = serde_json::from_str(lines[2]).unwrap();
        assert_eq!(footer["kind"], "runFooter");

        // Restore env.
        if let Some(p) = prev {
            unsafe {
                std::env::set_var("AGENTDECK_DATA_DIR", p);
            }
        } else {
            unsafe {
                std::env::remove_var("AGENTDECK_DATA_DIR");
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn try_append_failure_returns_reason_not_panic() {
        let _guard = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
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
