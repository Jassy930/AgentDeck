//! 会话交互的 live 状态：在已读历史之后发出的轮次、运行中的 turn 和待决审批。
//!
//! 纯数据结构，不依赖 GPUI；Shell 负责把 daemon 事件按 sessionId 交给对应会话，
//! 再把 `turns()` 渲染在历史记录之后。

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use agentdeck_protocol::{
    ActionDecision, ActionDecisionKind, ActionRequest, AgentItem, AgentItemMeta, AgentKind,
    ClaudeCodePermissionMode, ClaudeCodeSessionOptions, ClientCommand, CodexApprovalPolicy,
    CodexReasoningEffort, CodexSandboxMode, CodexSessionOptions, HistoryTurn, InitialTurn,
    ServerEvent, SessionId, SessionStart, TurnId, TurnOutcome, VendorSessionOptions,
};

use crate::shell::SessionKey;

/// caller-owned 的 sessionId / turnId：进程内递增，再带 pid 和启动毫秒避免跨进程撞号。
fn next_id(prefix: &str) -> String {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let started = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    format!(
        "desktop-{prefix}-{}-{started}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
}

/// 桌面发起会话的默认启动选项。Claude Code 用 default 权限模式，工具调用走界面审批；
/// Codex 只接受 daemon 固定的 M0 选项。
fn vendor_options(kind: AgentKind) -> VendorSessionOptions {
    match kind {
        AgentKind::Codex => VendorSessionOptions::Codex(CodexSessionOptions {
            approval_policy: CodexApprovalPolicy::Never,
            sandbox: CodexSandboxMode::ReadOnly,
            persist_approval: false,
            reasoning_effort: CodexReasoningEffort::Medium,
            mcp_overrides: vec![],
        }),
        AgentKind::ClaudeCode => VendorSessionOptions::ClaudeCode(ClaudeCodeSessionOptions {
            permission_mode: ClaudeCodePermissionMode::Default,
            model: None,
            effort: None,
            hooks: vec![],
            output_style: None,
            allowed_tools: None,
            disallowed_tools: None,
            mcp_config_path: None,
            plugin_dirs: vec![],
            worktree: None,
            session_name: None,
            session_id: None,
        }),
    }
}

/// 事件所属的 sessionId；连接级错误没有。
pub fn event_session(event: &ServerEvent) -> Option<&SessionId> {
    match event {
        ServerEvent::SessionStarted { session_id, .. }
        | ServerEvent::SessionCapabilities { session_id, .. }
        | ServerEvent::AgentItem { session_id, .. }
        | ServerEvent::ActionRequest { session_id, .. }
        | ServerEvent::TurnStarted { session_id, .. }
        | ServerEvent::TurnFinished { session_id, .. }
        | ServerEvent::SessionClosed { session_id, .. }
        | ServerEvent::TurnComplete { session_id, .. }
        | ServerEvent::VendorControl { session_id, .. }
        | ServerEvent::VendorPanelEvent { session_id, .. } => Some(session_id),
        ServerEvent::Error { session_id, .. } => session_id.as_ref(),
    }
}

/// 不终止当前轮次的会话级错误：daemon 的 record 告警、审批决定没送达。
const NON_TERMINAL_ERRORS: &[&str] = &[
    "record_write_failed",
    "cc-decision-no-route",
    "action-decision-not-supported",
];

pub struct LiveTurn {
    prompt: String,
    /// 按 itemId upsert：流式快照和工具开始/完成共用同一个 id。
    items: Vec<(String, AgentItem)>,
    finished: bool,
}

pub struct LiveSession {
    pub key: SessionKey,
    /// `Some` 表示 daemon 上开着这个会话，后续轮次直接 TurnStart。
    pub session_id: Option<SessionId>,
    /// 见过 SessionStarted；之前的错误说明会话没起来。
    started: bool,
    pub running: Option<TurnId>,
    turns: Vec<LiveTurn>,
    pub action: Option<ActionRequest>,
    pub error: Option<String>,
}

impl LiveSession {
    pub fn new(key: SessionKey) -> Self {
        Self {
            key,
            session_id: None,
            started: false,
            running: None,
            turns: Vec::new(),
            action: None,
            error: None,
        }
    }

    /// 登记一轮并返回要发给 daemon 的命令：会话没开就带 initial turn 续上原 thread。
    pub fn send(&mut self, prompt: String, cwd: std::path::PathBuf) -> ClientCommand {
        let turn_id = TurnId(next_id("turn"));
        self.running = Some(turn_id.clone());
        self.error = None;
        self.turns.push(LiveTurn {
            prompt: prompt.clone(),
            items: Vec::new(),
            finished: false,
        });
        if let Some(session_id) = &self.session_id {
            return ClientCommand::TurnStart {
                session_id: session_id.clone(),
                turn_id,
                prompt,
            };
        }
        let session_id = SessionId(next_id("session"));
        self.session_id = Some(session_id.clone());
        self.started = false;
        let (_, kind, thread_id) = &self.key;
        ClientCommand::SessionStart(SessionStart {
            session_id,
            agent_kind: *kind,
            cwd,
            resume_thread_id: Some(thread_id.clone()),
            initial_turn: Some(InitialTurn { turn_id, prompt }),
            vendor_options: vendor_options(*kind),
            runtime_options: Default::default(),
        })
    }

    pub fn cancel(&self) -> Option<ClientCommand> {
        Some(ClientCommand::TurnCancel {
            session_id: self.session_id.clone()?,
            turn_id: self.running.clone()?,
        })
    }

    pub fn decide(&mut self, approve: bool) -> Option<ClientCommand> {
        let request = self.action.take()?;
        Some(ClientCommand::ActionDecision {
            session_id: self.session_id.clone()?,
            decision: ActionDecision {
                request_id: request.request_id,
                decision: if approve {
                    ActionDecisionKind::Approve
                } else {
                    ActionDecisionKind::Deny
                },
                persist: false,
                message: None,
            },
        })
    }

    /// 发送失败（写不进 daemon）：这一轮不会有任何事件回来。
    pub fn send_failed(&mut self, message: String) {
        self.session_id = None;
        self.running = None;
        self.error = Some(message);
    }

    pub fn disconnected(&mut self, message: &str) {
        self.session_id = None;
        if self.running.take().is_some() || self.action.take().is_some() {
            self.error = Some(message.to_string());
        }
    }

    /// 重新读历史时调用：已完成的轮次已经写进 vendor 历史，只留还在跑的那轮。
    /// ponytail: 进行中的轮次可能和历史里已落盘的半截重复，轮次结束后重开会话即可。
    pub fn forget_finished(&mut self) {
        self.turns.retain(|turn| !turn.finished);
    }

    /// 应用一条属于本会话的事件；返回是否需要重绘。
    pub fn apply(&mut self, event: ServerEvent) -> bool {
        match event {
            ServerEvent::SessionStarted { .. } => self.started = true,
            ServerEvent::AgentItem { item_id, item, .. } => {
                let Some(turn) = self.turns.last_mut() else {
                    return false;
                };
                match turn.items.iter_mut().find(|(id, _)| *id == item_id) {
                    Some((_, existing)) => *existing = item,
                    None => turn.items.push((item_id, item)),
                }
            }
            ServerEvent::ActionRequest { request, .. } => self.action = Some(request),
            ServerEvent::TurnFinished { outcome, error, .. } => {
                self.finish_turn();
                if outcome == TurnOutcome::Failed {
                    self.error = Some(error.map_or_else(|| "本轮失败".into(), |e| e.message));
                }
            }
            // 旧版 daemon 的 Claude Code 终态。
            ServerEvent::TurnComplete { .. } => self.finish_turn(),
            ServerEvent::SessionClosed { error, .. } => {
                self.finish_turn();
                self.session_id = None;
                if let Some(error) = error {
                    self.error = Some(error.message);
                }
            }
            ServerEvent::Error { error, .. } => {
                // 记录写失败和审批路由错误不影响正在跑的轮次。
                if !NON_TERMINAL_ERRORS.contains(&error.code.as_str()) {
                    self.finish_turn();
                }
                // 没起来的会话和 daemon 已不认识的会话，下次发送重新 SessionStart。
                if !self.started || error.code == "session-not-found" {
                    self.session_id = None;
                }
                self.error = Some(format!("{}（{}）", error.message, error.code));
            }
            _ => return false,
        }
        true
    }

    fn finish_turn(&mut self) {
        self.running = None;
        self.action = None;
        if let Some(turn) = self.turns.last_mut() {
            turn.finished = true;
        }
    }

    pub fn turns(&self) -> Vec<HistoryTurn> {
        self.turns
            .iter()
            .map(|turn| HistoryTurn {
                items: std::iter::once(AgentItem::UserMessage {
                    text: turn.prompt.clone(),
                    meta: AgentItemMeta::default(),
                })
                .chain(turn.items.iter().map(|(_, item)| item.clone()))
                .collect(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentdeck_protocol::{
        ActionKind, ActionRequestVendor, AgentItemState, ProtocolError, ThreadId, TurnNextState,
    };

    fn session() -> LiveSession {
        LiveSession::new((None, AgentKind::ClaudeCode, ThreadId("thread".into())))
    }

    fn message(id: &str, text: &str) -> ServerEvent {
        ServerEvent::AgentItem {
            session_id: SessionId("s".into()),
            thread_id: ThreadId("thread".into()),
            agent_kind: AgentKind::ClaudeCode,
            turn_id: TurnId("t".into()),
            item_id: id.into(),
            state: AgentItemState::Streaming,
            item: AgentItem::AssistantMessage {
                text: text.into(),
                meta: AgentItemMeta::default(),
            },
        }
    }

    fn finished(outcome: TurnOutcome) -> ServerEvent {
        ServerEvent::TurnFinished {
            session_id: SessionId("s".into()),
            thread_id: ThreadId("thread".into()),
            agent_kind: AgentKind::ClaudeCode,
            turn_id: TurnId("t".into()),
            outcome,
            next_state: TurnNextState::Ready,
            summary: None,
            error: None,
        }
    }

    fn error(code: &str) -> ServerEvent {
        ServerEvent::Error {
            session_id: Some(SessionId("s".into())),
            error: ProtocolError {
                code: code.into(),
                message: "boom".into(),
                diagnostic_ref: None,
            },
        }
    }

    #[test]
    fn first_send_resumes_the_thread_and_later_sends_reuse_the_session() {
        let mut live = session();
        let ClientCommand::SessionStart(start) = live.send("hi".into(), "/repo".into()) else {
            panic!("first send must start a session");
        };
        assert_eq!(start.resume_thread_id, Some(ThreadId("thread".into())));
        assert_eq!(start.initial_turn.map(|t| t.prompt).as_deref(), Some("hi"));
        assert!(live.running.is_some());

        live.apply(ServerEvent::SessionStarted {
            session_id: start.session_id.clone(),
            thread_id: None,
            agent_kind: AgentKind::ClaudeCode,
        });
        live.apply(finished(TurnOutcome::Succeeded));
        assert!(live.running.is_none());
        assert!(matches!(
            live.send("again".into(), "/repo".into()),
            ClientCommand::TurnStart { session_id, .. } if session_id == start.session_id
        ));
    }

    #[test]
    fn streaming_snapshots_upsert_by_item_id() {
        let mut live = session();
        live.send("hi".into(), "/repo".into());
        live.apply(message("m:0", "Hel"));
        live.apply(message("m:0", "Hello"));
        live.apply(message("m:1", "next"));
        let turns = live.turns();
        assert_eq!(turns[0].items.len(), 3, "prompt + two distinct items");
        assert!(
            matches!(&turns[0].items[1], AgentItem::AssistantMessage { text, .. } if text == "Hello")
        );
    }

    #[test]
    fn startup_errors_stop_the_spinner_and_force_a_fresh_start() {
        let mut live = session();
        live.send("hi".into(), "/repo".into());
        assert!(live.apply(error("cc-not-authenticated")));
        assert!(live.running.is_none());
        assert!(live.session_id.is_none());
        assert!(
            live.error
                .as_deref()
                .unwrap()
                .contains("cc-not-authenticated")
        );
        assert!(matches!(
            live.send("retry".into(), "/repo".into()),
            ClientCommand::SessionStart(_)
        ));
    }

    #[test]
    fn record_warnings_keep_the_turn_running() {
        let mut live = session();
        live.send("hi".into(), "/repo".into());
        live.apply(ServerEvent::SessionStarted {
            session_id: SessionId("s".into()),
            thread_id: None,
            agent_kind: AgentKind::ClaudeCode,
        });
        live.apply(error("record_write_failed"));
        assert!(live.running.is_some(), "the vendor turn is still running");
        assert!(live.session_id.is_some());
        assert!(live.error.is_some());
    }

    #[test]
    fn approvals_and_disconnects_clear_pending_state() {
        let mut live = session();
        live.send("hi".into(), "/repo".into());
        live.apply(ServerEvent::ActionRequest {
            session_id: SessionId("s".into()),
            thread_id: ThreadId("thread".into()),
            agent_kind: AgentKind::ClaudeCode,
            request: ActionRequest {
                request_id: "perm-1".into(),
                kind: ActionKind::ExecuteCommand,
                summary: "Bash: ls".into(),
                detail: Some("ls".into()),
                vendor: ActionRequestVendor::ClaudeCode {
                    permission_mode_at_decision: ClaudeCodePermissionMode::Default,
                    tool_name: "Bash".into(),
                    can_persist: true,
                },
            },
        });
        assert!(matches!(
            live.decide(true),
            Some(ClientCommand::ActionDecision { decision, .. })
                if decision.request_id == "perm-1" && decision.decision == ActionDecisionKind::Approve
        ));
        assert!(live.action.is_none());

        live.disconnected("连接已断开");
        assert!(live.running.is_none() && live.session_id.is_none());
        assert_eq!(live.error.as_deref(), Some("连接已断开"));
    }

    #[test]
    fn reopening_keeps_only_the_running_turn() {
        let mut live = session();
        live.send("one".into(), "/repo".into());
        live.apply(finished(TurnOutcome::Canceled));
        live.send("two".into(), "/repo".into());
        live.forget_finished();
        let turns = live.turns();
        assert_eq!(turns.len(), 1);
        assert!(matches!(&turns[0].items[0], AgentItem::UserMessage { text, .. } if text == "two"));
    }
}
