//! 会话交互的 live 状态：在已读历史之后发出的轮次、运行中的 turn 和待决审批。
//!
//! 纯数据结构，不依赖 GPUI；Shell 负责把 daemon 事件按 sessionId 交给对应会话，
//! 再把 `turns()` 渲染在历史记录之后。

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use agentdeck_protocol::{
    ActionDecision, ActionDecisionKind, ActionRequest, AgentItem, AgentItemMeta,
    ClaudeCodePermissionMode, ClaudeCodeVendorPanelEvent, ClientCommand, HistoryTurn, InitialTurn,
    ServerEvent, SessionCapabilities, SessionId, SessionStart, TurnId, TurnOutcome,
    VendorPanelPayload,
};

use crate::session_router::SessionRouter;
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
    actions: VecDeque<ActionRequest>,
    capabilities: Option<SessionCapabilities>,
    pub error: Option<String>,
    pub mode: ClaudeCodePermissionMode,
}

impl LiveSession {
    pub fn new(key: SessionKey) -> Self {
        Self {
            key,
            session_id: None,
            started: false,
            running: None,
            turns: Vec::new(),
            actions: VecDeque::new(),
            capabilities: None,
            error: None,
            mode: ClaudeCodePermissionMode::Default,
        }
    }

    pub fn router<'a>(
        &'a self,
        initial: Option<&'a SessionCapabilities>,
    ) -> Option<SessionRouter<'a>> {
        if self.session_id.is_some() {
            self.capabilities.as_ref().map(SessionRouter)
        } else {
            initial.map(SessionRouter)
        }
    }

    pub fn can_send(&self, initial: Option<&SessionCapabilities>) -> bool {
        self.running.is_none()
            && self.router(initial).is_some_and(|router| {
                router.supports_messages()
                    && (self.session_id.is_some() || router.start_options(self.mode).is_ok())
            })
    }

    /// 登记一轮并返回要发给 daemon 的命令：会话没开就带 initial turn 续上原 thread。
    pub fn send(
        &mut self,
        prompt: String,
        cwd: std::path::PathBuf,
        initial: Option<&SessionCapabilities>,
    ) -> Option<ClientCommand> {
        if !self.can_send(initial) {
            return None;
        }
        let options = if self.session_id.is_none() {
            Some(self.router(initial)?.start_options(self.mode).ok()?)
        } else {
            None
        };
        let turn_id = TurnId(next_id("turn"));
        self.running = Some(turn_id.clone());
        self.error = None;
        self.turns.push(LiveTurn {
            prompt: prompt.clone(),
            items: Vec::new(),
            finished: false,
        });
        if let Some(session_id) = &self.session_id {
            return Some(ClientCommand::TurnStart {
                session_id: session_id.clone(),
                turn_id,
                prompt,
            });
        }
        let session_id = SessionId(next_id("session"));
        self.session_id = Some(session_id.clone());
        self.started = false;
        let (_, kind, thread_id) = &self.key;
        self.capabilities = None;
        Some(ClientCommand::SessionStart(SessionStart {
            session_id,
            agent_kind: *kind,
            cwd,
            resume_thread_id: Some(thread_id.clone()),
            initial_turn: Some(InitialTurn { turn_id, prompt }),
            vendor_options: options?,
            runtime_options: Default::default(),
        }))
    }

    pub fn cancel(&self) -> Option<ClientCommand> {
        self.capabilities.as_ref()?;
        Some(ClientCommand::TurnCancel {
            session_id: self.session_id.clone()?,
            turn_id: self.running.clone()?,
        })
    }

    pub fn set_mode(
        &mut self,
        mode: ClaudeCodePermissionMode,
        initial: Option<&SessionCapabilities>,
    ) -> Option<ClientCommand> {
        let router = self.router(initial)?;
        if !router.permission_modes().contains(&mode) {
            return None;
        }
        if let Some(session_id) = self.session_id.clone() {
            router.permission_mode_command(session_id, mode)
        } else {
            self.mode = mode;
            None
        }
    }

    pub fn decide(
        &mut self,
        approve: bool,
        persist: bool,
        message: Option<String>,
    ) -> Option<ClientCommand> {
        self.action()?;
        let session_id = self.session_id.clone()?;
        let request = self.actions.pop_front()?;
        Some(ClientCommand::ActionDecision {
            session_id,
            decision: ActionDecision {
                request_id: request.request_id,
                decision: if approve {
                    ActionDecisionKind::Approve
                } else {
                    ActionDecisionKind::Deny
                },
                persist,
                message,
            },
        })
    }

    pub fn action(&self) -> Option<&ActionRequest> {
        self.router(None)
            .filter(|router| router.supports_approval())?;
        self.actions.front()
    }

    /// 发送失败（写不进 daemon）：这一轮不会有任何事件回来。
    pub fn send_failed(&mut self, message: String) {
        self.disconnected(&message);
        self.error = Some(message);
    }

    pub fn disconnected(&mut self, message: &str) {
        let interrupted = self.running.is_some() || !self.actions.is_empty();
        self.finish_turn();
        self.session_id = None;
        self.started = false;
        self.capabilities = None;
        if interrupted {
            self.error = Some(message.to_string());
        }
    }

    /// 重新读历史时调用：已完成的轮次已经写进 vendor 历史，只留还在跑的那轮。
    /// shortcut: 进行中的轮次可能与已落盘历史重复，接入历史/live item 去重时移除此限制。
    pub fn forget_finished(&mut self) {
        self.turns.retain(|turn| !turn.finished);
    }

    /// 应用一条属于本会话的事件；返回是否需要重绘。
    pub fn apply(&mut self, event: ServerEvent) -> bool {
        match event {
            ServerEvent::SessionStarted { .. } => self.started = true,
            ServerEvent::SessionCapabilities { capabilities, .. } => {
                self.capabilities = Some(capabilities);
            }
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
                if let Some(existing) = self
                    .actions
                    .iter_mut()
                    .find(|action| action.request_id == request.request_id)
                {
                    *existing = request;
                } else {
                    self.actions.push_back(request);
                }
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
                self.capabilities = None;
                if let Some(error) = error {
                    self.error = Some(error.message);
                }
            }
            ServerEvent::Error { error, .. } => {
                if error.code == crate::daemon::DISCONNECTED {
                    self.disconnected(&error.message);
                    return true;
                }
                // 记录写失败和审批路由错误不影响正在跑的轮次。
                if !NON_TERMINAL_ERRORS.contains(&error.code.as_str()) {
                    self.finish_turn();
                }
                // 没起来的会话和 daemon 已不认识的会话，下次发送重新 SessionStart。
                if !self.started || error.code == "session-not-found" {
                    self.session_id = None;
                    self.capabilities = None;
                }
                self.error = Some(format!("{}（{}）", error.message, error.code));
            }
            _ => return false,
        }
        true
    }

    fn finish_turn(&mut self) {
        self.running = None;
        self.actions.clear();
        if let Some(turn) = self.turns.last_mut() {
            turn.finished = true;
        }
    }

    pub fn waiting(&self) -> bool {
        self.running.is_some()
            && self.actions.is_empty()
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
        ActionKind, ActionRequestVendor, AgentItemState, AgentKind, CapabilityId,
        ClaudeCodePermissionMode, ProtocolError, ThreadId, TurnNextState,
    };

    fn session() -> LiveSession {
        LiveSession::new((None, AgentKind::ClaudeCode, ThreadId("thread".into())))
    }

    fn capabilities_event(capabilities: SessionCapabilities) -> ServerEvent {
        ServerEvent::SessionCapabilities {
            session_id: SessionId("s".into()),
            agent_kind: capabilities.agent_kind,
            capabilities,
        }
    }

    fn send(live: &mut LiveSession, prompt: &str) -> ClientCommand {
        let caps = crate::session_router::test_capabilities(AgentKind::ClaudeCode);
        let command = live
            .send(prompt.into(), "/repo".into(), Some(&caps))
            .unwrap();
        live.apply(capabilities_event(caps));
        command
    }

    fn approval(id: &str) -> ServerEvent {
        ServerEvent::ActionRequest {
            session_id: SessionId("s".into()),
            thread_id: ThreadId("thread".into()),
            agent_kind: AgentKind::ClaudeCode,
            request: ActionRequest {
                request_id: id.into(),
                kind: ActionKind::ExecuteCommand,
                summary: "Bash: ls".into(),
                detail: Some("ls".into()),
                vendor: ActionRequestVendor::ClaudeCode {
                    permission_mode_at_decision: ClaudeCodePermissionMode::Default,
                    tool_name: "Bash".into(),
                    can_persist: true,
                },
            },
        }
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
        let ClientCommand::SessionStart(start) = send(&mut live, "hi") else {
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
            send(&mut live, "again"),
            ClientCommand::TurnStart { session_id, .. } if session_id == start.session_id
        ));
    }

    #[test]
    fn streaming_snapshots_upsert_by_item_id() {
        let mut live = session();
        send(&mut live, "hi");
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
        send(&mut live, "hi");
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
            send(&mut live, "retry"),
            ClientCommand::SessionStart(_)
        ));
    }

    #[test]
    fn permission_modes_follow_session_handshake_and_confirmed_events() {
        use agentdeck_protocol::{VendorCapabilities, VendorSessionOptions};
        let mut live = session();
        let caps = crate::session_router::test_capabilities(AgentKind::ClaudeCode);
        assert!(
            live.set_mode(ClaudeCodePermissionMode::Plan, Some(&caps))
                .is_none()
        );
        let ClientCommand::SessionStart(start) = live
            .send("plan".into(), "/repo".into(), Some(&caps))
            .unwrap()
        else {
            panic!("expected session start");
        };
        assert!(
            matches!(start.vendor_options, VendorSessionOptions::ClaudeCode(options) if options.permission_mode == ClaudeCodePermissionMode::Plan)
        );
        assert!(live.waiting());
        assert!(
            live.set_mode(ClaudeCodePermissionMode::BypassPermissions, Some(&caps))
                .is_none(),
            "wait for the session handshake"
        );
        let mut session_caps = caps.clone();
        let VendorCapabilities::ClaudeCode(vendor) = &mut session_caps.vendor else {
            unreachable!()
        };
        vendor.permission_modes = vec![
            ClaudeCodePermissionMode::Plan,
            ClaudeCodePermissionMode::AcceptEdits,
        ];
        live.apply(capabilities_event(session_caps));
        assert!(
            live.set_mode(ClaudeCodePermissionMode::BypassPermissions, Some(&caps))
                .is_none(),
            "machine capability cannot override session capability"
        );
        assert!(matches!(
            live.set_mode(ClaudeCodePermissionMode::AcceptEdits, None),
            Some(ClientCommand::VendorControl { .. })
        ));
        assert_eq!(live.mode, ClaudeCodePermissionMode::Plan);
        live.apply(ServerEvent::SessionStarted {
            session_id: start.session_id,
            thread_id: None,
            agent_kind: AgentKind::ClaudeCode,
        });
        live.apply(error("cc-permission-mode-rejected"));
        assert!(live.running.is_some());
        assert_eq!(live.mode, ClaudeCodePermissionMode::Plan);
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
    fn record_warnings_keep_the_turn_running() {
        let mut live = session();
        send(&mut live, "hi");
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
        send(&mut live, "hi");
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
            live.decide(true, false, None),
            Some(ClientCommand::ActionDecision { decision, .. })
                if decision.request_id == "perm-1" && decision.decision == ActionDecisionKind::Approve
        ));
        assert!(live.action().is_none());

        live.disconnected("连接已断开");
        assert!(live.running.is_none() && live.session_id.is_none());
        assert_eq!(live.error.as_deref(), Some("连接已断开"));
    }

    #[test]
    fn pending_approvals_are_answered_in_order_without_losing_requests() {
        let mut live = session();
        send(&mut live, "hi");
        live.apply(approval("first"));
        live.apply(approval("second"));
        live.apply(approval("first"));
        assert_eq!(live.actions.len(), 2);
        for (id, approve) in [("first", true), ("second", false)] {
            assert_eq!(live.action().unwrap().request_id, id);
            let Some(ClientCommand::ActionDecision { decision, .. }) =
                live.decide(approve, approve, (!approve).then(|| "修改计划".into()))
            else {
                panic!("pending request must remain answerable");
            };
            assert_eq!(decision.request_id, id);
            assert_eq!(decision.persist, approve);
            assert_eq!(
                decision.message.as_deref(),
                (!approve).then_some("修改计划")
            );
            assert_eq!(
                decision.decision,
                if approve {
                    ActionDecisionKind::Approve
                } else {
                    ActionDecisionKind::Deny
                }
            );
        }
        assert!(live.decide(true, false, None).is_none());
        assert!(live.running.is_some());
    }

    #[test]
    fn disconnect_and_write_failure_clear_running_and_all_approvals() {
        for write_failure in [false, true] {
            let mut live = session();
            send(&mut live, "hi");
            live.apply(approval("first"));
            live.apply(approval("second"));
            if write_failure {
                live.send_failed("断线".into());
            } else {
                live.apply(error(crate::daemon::DISCONNECTED));
            }
            assert!(live.running.is_none() && live.session_id.is_none());
            assert!(live.actions.is_empty());
            assert!(live.capabilities.is_none());
            assert!(live.error.is_some());
            send(&mut live, "retry");
            assert!(
                live.decide(true, false, None).is_none(),
                "old requests must not reach the new session"
            );
        }
    }

    #[test]
    fn session_handshake_controls_sending_cancellation_and_approval() {
        let mut live = session();
        let mut caps = crate::session_router::test_capabilities(AgentKind::ClaudeCode);
        assert!(live.send("hi".into(), "/repo".into(), None).is_none());
        assert!(live.turns.is_empty());
        assert!(
            live.send("hi".into(), "/repo".into(), Some(&caps))
                .is_some()
        );
        assert!(
            live.router(Some(&caps)).is_none(),
            "wait for the session handshake"
        );
        assert!(live.cancel().is_none());
        caps.features.remove(&CapabilityId::Approval);
        live.apply(capabilities_event(caps.clone()));
        live.apply(approval("unsupported"));
        assert!(live.decide(true, false, None).is_none());
        assert!(live.action().is_none());
        assert!(live.cancel().is_some());
        live.apply(finished(TurnOutcome::Succeeded));
        caps.features.remove(&CapabilityId::StreamingMessages);
        live.apply(capabilities_event(caps));
        let initial = crate::session_router::test_capabilities(AgentKind::ClaudeCode);
        assert!(
            !live.can_send(Some(&initial)),
            "session capabilities override preflight"
        );
        assert!(
            live.send("next".into(), "/repo".into(), Some(&initial))
                .is_none()
        );
    }

    #[test]
    fn reopening_keeps_only_the_running_turn() {
        let mut live = session();
        send(&mut live, "one");
        live.apply(finished(TurnOutcome::Canceled));
        send(&mut live, "two");
        live.forget_finished();
        let turns = live.turns();
        assert_eq!(turns.len(), 1);
        assert!(matches!(&turns[0].items[0], AgentItem::UserMessage { text, .. } if text == "two"));
    }
}
