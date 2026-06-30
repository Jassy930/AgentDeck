//! Shared clap ValueEnum types and session run argument struct.
//! Extracted here so both `main.rs` and `commands.rs` can use them
//! without a circular dependency.

use std::path::PathBuf;

// ── AgentKind clap arg ────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum AgentKindArg {
    #[value(name = "codex")]
    Codex,
    #[value(name = "claude-code")]
    ClaudeCode,
}

// ── Codex-specific args ───────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum SandboxArg {
    #[value(name = "read-only")]
    ReadOnly,
    #[value(name = "workspace-write")]
    WorkspaceWrite,
    #[value(name = "full-access")]
    FullAccess,
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum ApprovalArg {
    #[value(name = "on-request")]
    OnRequest,
    #[value(name = "never")]
    Never,
    #[value(name = "always")]
    Always,
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum EffortArg {
    #[value(name = "minimal")]
    Minimal,
    #[value(name = "low")]
    Low,
    #[value(name = "medium")]
    Medium,
    #[value(name = "high")]
    High,
}

// ── CC-specific args ──────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum PermissionArg {
    #[value(name = "default")]
    Default,
    #[value(name = "accept-edits")]
    AcceptEdits,
    #[value(name = "plan")]
    Plan,
    #[value(name = "auto")]
    Auto,
    #[value(name = "dont-ask")]
    DontAsk,
    #[value(name = "bypass-permissions")]
    BypassPermissions,
}

// ── Combined session run args (passed from main.rs to commands.rs) ────────────

/// Flat struct collecting all `session run` flags; commands.rs routes per agent.
#[derive(Debug)]
pub struct SessionRunArgs {
    pub agent: AgentKindArg,
    pub cwd: PathBuf,
    pub prompt: String,
    // Codex-only
    pub sandbox: Option<SandboxArg>,
    pub approval: Option<ApprovalArg>,
    pub persist_approval: bool,
    pub reasoning_effort: Option<EffortArg>,
    // CC-only
    pub permission: Option<PermissionArg>,
    pub output_style: Option<String>,
    pub model: Option<String>,
    pub effort: Option<String>,
    pub worktree: Option<String>,
    pub session_name: Option<String>,
}
