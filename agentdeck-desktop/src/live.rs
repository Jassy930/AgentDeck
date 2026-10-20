//! 会话交互的 live 状态：在已读历史之后发出的轮次、运行中的 turn 和待决审批。
//!
//! 纯数据结构，不依赖 GPUI；Shell 负责把 daemon 事件按 sessionId 交给对应会话，
//! 再把 `turns()` 渲染在历史记录之后。

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use agentdeck_protocol::{
    ActionDecision, ActionDecisionKind, ActionRequest, AgentItem, AgentItemMeta, AgentKind,
    ClaudeCodePermissionMode, ClaudeCodeSessionOptions, ClaudeCodeVendorControl,
    ClaudeCodeVendorPanelEvent, ClientCommand, CodexApprovalPolicy, CodexReasoningEffort,
    CodexSandboxMode, CodexSessionOptions, HistoryTurn, InitialTurn, ServerEvent, SessionId,
    SessionStart, TurnId, TurnOutcome, VendorControlPayload, VendorPanelPayload,
    VendorSessionOptions,
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

/// 桌面发起会话的启动选项。Claude Code 按界面选择的权限模式启动；
/// Codex 只接受 daemon 固定的 M0 选项。
fn vendor_options(kind: AgentKind, mode: ClaudeCodePermissionMode) -> VendorSessionOptions {
    match kind {
        AgentKind::Codex => VendorSessionOptions::Codex(CodexSessionOptions {
            approval_policy: CodexApprovalPolicy::Never,
            sandbox: CodexSandboxMode::ReadOnly,
            persist_approval: false,
            reasoning_effort: CodexReasoningEffort::Medium,
            mcp_overrides: vec![],
        }),
        AgentKind::ClaudeCode => VendorSessionOptions::ClaudeCode(ClaudeCodeSessionOptions {
            permission_mode: mode,
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
    "cc-permission-mode-rejected",
    "cc-vendor-control-not-supported",
    "cc-vendor-control-requires-new-turn",
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
    /// 会话里实际生效的权限模式：开始前是本地选择，开始后只跟 daemon 的模式事件。
    pub mode: ClaudeCodePermissionMode,
    /// 待决提问每题已选的选项标签。
    pub picks: Vec<Vec<String>>,
    /// 待决提问每题是否选了“其他”（自由输入）。
    pub others: Vec<bool>,
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
            mode: ClaudeCodePermissionMode::Default,
            picks: Vec::new(),
            others: Vec::new(),
        }
    }

    fn question_is_multi(&self, question: usize) -> Option<bool> {
        self.action
            .as_ref()?
            .questions
            .as_ref()?
            .get(question)
            .map(|asked| asked.multi_select)
    }

    /// 单选题选“其他”会清掉已选选项；多选题与选项并存。
    pub fn toggle_other(&mut self, question: usize) {
        let Some(multi) = self.question_is_multi(question) else {
            return;
        };
        let (Some(other), Some(picks)) =
            (self.others.get_mut(question), self.picks.get_mut(question))
        else {
            return;
        };
        if multi {
            *other = !*other;
        } else {
            *other = true;
            picks.clear();
        }
    }

    /// 每题都有选择（选项或“其他”）才算答完。
    pub fn answered(&self) -> bool {
        self.picks
            .iter()
            .zip(&self.others)
            .all(|(picks, other)| !picks.is_empty() || *other)
    }

    /// 单选题点选即替换，多选题点选即切换。
    pub fn toggle_pick(&mut self, question: usize, label: &str) {
        let Some(asked) = self
            .action
            .as_ref()
            .and_then(|action| action.questions.as_ref())
            .and_then(|questions| questions.get(question))
        else {
            return;
        };
        let multi = asked.multi_select;
        let (Some(picks), Some(other)) =
            (self.picks.get_mut(question), self.others.get_mut(question))
        else {
            return;
        };
        if !multi {
            *other = false;
        }
        match picks.iter().position(|pick| pick == label) {
            Some(index) if multi => {
                picks.remove(index);
            }
            Some(_) => {}
            None if multi => picks.push(label.to_string()),
            None => *picks = vec![label.to_string()],
        }
    }

    /// 作答：每题的选项按原顺序，加上“其他”里填的文字，用 ", " 连接。
    /// `others` 是各题“其他”输入框的内容；有题没答或“其他”没填时返回给用户看的提示。
    pub fn answer(&mut self, others: &[String]) -> Result<ClientCommand, String> {
        let session_id = self.session_id.clone().ok_or("会话已结束")?;
        let action = self.action.as_ref().ok_or("没有待回答的问题")?;
        let questions = action.questions.as_ref().ok_or("没有待回答的问题")?;
        let mut answers = std::collections::BTreeMap::new();
        for (ix, question) in questions.iter().enumerate() {
            let picks = self.picks.get(ix).map(Vec::as_slice).unwrap_or_default();
            let mut chosen: Vec<String> = question
                .options
                .iter()
                .filter(|option| picks.contains(&option.label))
                .map(|option| option.label.clone())
                .collect();
            if self.others.get(ix).copied().unwrap_or(false) {
                let text = others.get(ix).map(|text| text.trim()).unwrap_or_default();
                if text.is_empty() {
                    return Err(format!("“{}”选了其他，请填写内容", question.question));
                }
                chosen.push(text.to_string());
            }
            if chosen.is_empty() {
                return Err(format!("还没回答“{}”", question.question));
            }
            answers.insert(question.question.clone(), chosen.join(", "));
        }
        let request = self.action.take().expect("checked above");
        Ok(ClientCommand::ActionDecision {
            session_id,
            decision: ActionDecision {
                request_id: request.request_id,
                decision: ActionDecisionKind::Approve,
                persist: false,
                message: None,
                answers: Some(answers),
            },
        })
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
            vendor_options: vendor_options(*kind, self.mode),
            runtime_options: Default::default(),
        })
    }

    pub fn cancel(&self) -> Option<ClientCommand> {
        Some(ClientCommand::TurnCancel {
            session_id: self.session_id.clone()?,
            turn_id: self.running.clone()?,
        })
    }

    /// 会话没开始时只改本地选择，下次 SessionStart 带上；开始后交给 daemon，
    /// 显示等 `PermissionModeChanged`（CC 可能拒绝）。
    pub fn set_mode(&mut self, mode: ClaudeCodePermissionMode) -> Option<ClientCommand> {
        let Some(session_id) = self.session_id.clone() else {
            self.mode = mode;
            return None;
        };
        Some(ClientCommand::VendorControl {
            session_id,
            payload: VendorControlPayload::ClaudeCode(
                ClaudeCodeVendorControl::UpdatePermissionMode(mode),
            ),
        })
    }

    pub fn decide(
        &mut self,
        approve: bool,
        persist: bool,
        message: Option<String>,
    ) -> Option<ClientCommand> {
        // 提问的“提交”走 `answer`，这里只处理批准/拒绝和跳过提问。
        if approve && self.action.as_ref()?.questions.is_some() {
            return None;
        }
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
                persist,
                message,
                answers: None,
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
            ServerEvent::ActionRequest { request, .. } => {
                let count = request.questions.as_ref().map_or(0, Vec::len);
                self.picks = vec![Vec::new(); count];
                self.others = vec![false; count];
                self.action = Some(request);
            }
            ServerEvent::VendorPanelEvent {
                payload:
                    VendorPanelPayload::ClaudeCode(ClaudeCodeVendorPanelEvent::PermissionModeChanged {
                        mode,
                    }),
                ..
            } => self.mode = mode,
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

    /// 本轮已发出但 agent 还没有任何输出，也没有待决审批。
    pub fn waiting(&self) -> bool {
        self.running.is_some()
            && self.action.is_none()
            && self.turns.last().is_some_and(|turn| turn.items.is_empty())
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
        assert!(live.waiting());

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
    fn permission_mode_is_local_before_start_and_event_driven_after() {
        let mut live = session();
        assert!(live.set_mode(ClaudeCodePermissionMode::Plan).is_none());
        let ClientCommand::SessionStart(start) = live.send("hi".into(), "/repo".into()) else {
            panic!("first send must start a session");
        };
        assert!(matches!(
            start.vendor_options,
            VendorSessionOptions::ClaudeCode(ClaudeCodeSessionOptions {
                permission_mode: ClaudeCodePermissionMode::Plan,
                ..
            })
        ));

        assert!(matches!(
            live.set_mode(ClaudeCodePermissionMode::BypassPermissions),
            Some(ClientCommand::VendorControl { .. })
        ));
        assert_eq!(
            live.mode,
            ClaudeCodePermissionMode::Plan,
            "waits for the event"
        );
        live.apply(error("cc-permission-mode-rejected"));
        assert!(
            live.running.is_some(),
            "a rejected switch keeps the turn running"
        );
        live.apply(ServerEvent::VendorPanelEvent {
            session_id: SessionId("s".into()),
            agent_kind: AgentKind::ClaudeCode,
            payload: VendorPanelPayload::ClaudeCode(
                ClaudeCodeVendorPanelEvent::PermissionModeChanged {
                    mode: ClaudeCodePermissionMode::AcceptEdits,
                },
            ),
        });
        assert_eq!(live.mode, ClaudeCodePermissionMode::AcceptEdits);
    }

    #[test]
    fn questions_need_an_answer_each_and_join_multi_select_in_option_order() {
        use agentdeck_protocol::{UserQuestion, UserQuestionOption};
        let option = |label: &str| UserQuestionOption {
            label: label.into(),
            description: None,
        };
        let mut live = session();
        live.send("hi".into(), "/repo".into());
        live.apply(ServerEvent::ActionRequest {
            session_id: SessionId("s".into()),
            thread_id: ThreadId("thread".into()),
            agent_kind: AgentKind::ClaudeCode,
            request: ActionRequest {
                request_id: "ask-1".into(),
                kind: ActionKind::AnswerQuestions,
                summary: "AskUserQuestion".into(),
                detail: None,
                questions: Some(vec![
                    UserQuestion {
                        question: "颜色".into(),
                        header: None,
                        options: vec![option("红"), option("蓝")],
                        multi_select: false,
                    },
                    UserQuestion {
                        question: "水果".into(),
                        header: None,
                        options: vec![option("苹果"), option("香蕉"), option("橙子")],
                        multi_select: true,
                    },
                ]),
                vendor: ActionRequestVendor::ClaudeCode {
                    permission_mode_at_decision: ClaudeCodePermissionMode::Default,
                    tool_name: "AskUserQuestion".into(),
                    can_persist: false,
                },
            },
        });
        live.toggle_pick(0, "红");
        live.toggle_other(0);
        assert!(
            live.picks[0].is_empty(),
            "single select: other replaces the option"
        );
        live.toggle_pick(0, "蓝");
        assert!(!live.others[0], "single select: an option replaces other");
        assert!(!live.answered());
        assert!(live.answer(&[]).unwrap_err().contains("水果"));

        live.toggle_pick(1, "橙子");
        live.toggle_pick(1, "香蕉");
        live.toggle_pick(1, "苹果");
        live.toggle_pick(1, "香蕉");
        live.toggle_other(1);
        assert!(live.answered());
        assert!(
            live.answer(&["".into(), "  ".into()])
                .unwrap_err()
                .contains("其他"),
            "an empty other is rejected"
        );
        let Ok(ClientCommand::ActionDecision { decision, .. }) =
            live.answer(&["".into(), " 芒果 ".into()])
        else {
            panic!("every question is answered");
        };
        let answers = decision.answers.unwrap();
        assert_eq!(answers["颜色"], "蓝");
        assert_eq!(answers["水果"], "苹果, 橙子, 芒果");
        assert!(live.action.is_none());
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
                questions: None,
                vendor: ActionRequestVendor::ClaudeCode {
                    permission_mode_at_decision: ClaudeCodePermissionMode::Default,
                    tool_name: "Bash".into(),
                    can_persist: true,
                },
            },
        });
        assert!(matches!(
            live.decide(false, false, Some("换个做法".into())),
            Some(ClientCommand::ActionDecision { decision, .. })
                if decision.request_id == "perm-1"
                    && decision.decision == ActionDecisionKind::Deny
                    && decision.message.as_deref() == Some("换个做法")
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
