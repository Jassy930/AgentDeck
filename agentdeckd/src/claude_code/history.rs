//! Claude Code history layer — `claude agents --json` + direct read of
//! `~/.claude/projects/<encoded_cwd>/<id>.jsonl`.
//!
//! Populated in Task 4B. Per N8, this module is the only allowed read path
//! for CC history; it must NEVER create or maintain an AgentDeck-side
//! metadata layer (no `cc-meta/` directory, no rename/archive sidecar).
//! Rename / archive operations shell out to CC's native commands
//! (`claude --name`, `claude rm`).
