//! 会话交互的 live 状态：在已读历史之后发出的轮次、运行中的 turn 和待决审批。
//!
//! 纯数据结构，只借用 `gpui::Image` 保存发出的图片原图；Shell 负责把 daemon 事件按 sessionId 交给对应会话，
//! 再把 `turns()` 渲染在历史记录之后。

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use agentdeck_protocol::{
    ActionDecision, ActionDecisionKind, ActionRequest, AgentItem, AgentItemMeta,
    ClaudeCodePermissionMode, ClaudeCodeVendorPanelEvent, ClientCommand, HistoryListItem,
    HistoryTurn, ImageAttachment, InitialTurn, SUPPORTED_IMAGE_TYPES, ServerEvent,
    SessionCapabilities, SessionId, SessionStart, TurnId, TurnOutcome, VendorPanelPayload,
};
use base64::{Engine, prelude::BASE64_STANDARD};
use gpui::Image;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Activity {
    Working,
    /// 有待决审批或提问。
    AwaitingUser,
}

pub struct LiveTurn {
    prompt: String,
    /// 随本轮发出的图片原图，记录里直接显示；同一个 Arc 保证滚动时不重复解码。
    images: Vec<Arc<Image>>,
    /// 按 itemId upsert：流式快照和工具开始/完成共用同一个 id。
    items: Vec<(String, AgentItem)>,
    finished: bool,
}

pub struct LiveSession {
    pub key: SessionKey,
    /// 新建会话：key 里是占位 thread id，SessionStart 不带 resume；SessionStarted 后由 Shell 取走换成真实 id。
    pub draft: Option<HistoryListItem>,
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
    /// 待决提问每题已选的选项标签。
    pub picks: Vec<Vec<String>>,
    /// 待决提问每题是否选了“其他”（自由输入）。
    pub others: Vec<bool>,
    /// 草稿随会话保留，切走再回来时重建输入框。
    pub other_texts: Vec<String>,
    /// 同 requestId 的题目变化时也重建输入框，避免恢复旧题草稿。
    pub question_revision: u64,
    /// 提问卡当前页：0..题数为各题，多题时最后一页是汇总提交页。
    pub question_tab: usize,
    /// 当前页键盘光标：0..选项数为各选项，等于选项数时是“其他”。
    pub question_cursor: usize,
}

impl LiveSession {
    pub fn new(key: SessionKey) -> Self {
        Self {
            key,
            draft: None,
            session_id: None,
            started: false,
            running: None,
            turns: Vec::new(),
            actions: VecDeque::new(),
            capabilities: None,
            error: None,
            mode: ClaudeCodePermissionMode::Default,
            picks: Vec::new(),
            others: Vec::new(),
            other_texts: Vec::new(),
            question_revision: 0,
            question_tab: 0,
            question_cursor: 0,
        }
    }

    fn question_count(&self) -> usize {
        self.action()
            .and_then(|action| action.questions.as_ref())
            .map_or(0, Vec::len)
    }

    /// 页数：一题时没有汇总页，和 Claude Code TUI 一致。
    pub fn tab_count(&self) -> usize {
        match self.question_count() {
            0 | 1 => self.question_count(),
            count => count + 1,
        }
    }

    pub fn on_summary_tab(&self) -> bool {
        self.tab_count() > self.question_count() && self.question_tab == self.question_count()
    }

    pub fn set_tab(&mut self, tab: usize) {
        if tab < self.tab_count() {
            self.question_tab = tab;
            self.question_cursor = 0;
        }
    }

    /// 左右切页，不循环。
    pub fn step_tab(&mut self, forward: bool) {
        let tab = if forward {
            self.question_tab + 1
        } else {
            self.question_tab.saturating_sub(1)
        };
        self.set_tab(tab);
    }

    /// 上下移动光标，范围含末尾的“其他”。
    pub fn move_cursor(&mut self, down: bool) {
        let Some(options) = self
            .action()
            .and_then(|action| action.questions.as_ref())
            .and_then(|questions| questions.get(self.question_tab))
            .map(|question| question.options.len())
        else {
            return;
        };
        self.question_cursor = if down {
            (self.question_cursor + 1).min(options)
        } else {
            self.question_cursor.saturating_sub(1)
        };
    }

    /// 某题的答案：选项按原顺序，加上“其他”的草稿，用 ", " 连接。没答或“其他”留空为 None。
    pub fn answer_text(&self, question: usize) -> Option<String> {
        let asked = self.action()?.questions.as_ref()?.get(question)?;
        let picks = self.picks.get(question)?;
        let mut chosen: Vec<&str> = asked
            .options
            .iter()
            .filter(|option| picks.contains(&option.label))
            .map(|option| option.label.as_str())
            .collect();
        if self.others.get(question).copied().unwrap_or(false) {
            let other = self.other_texts.get(question).map(|text| text.trim())?;
            if other.is_empty() {
                return None;
            }
            chosen.push(other);
        }
        (!chosen.is_empty()).then(|| chosen.join(", "))
    }

    fn question_is_multi(&self, question: usize) -> Option<bool> {
        self.action()?
            .questions
            .as_ref()?
            .get(question)
            .map(|asked| asked.multi_select)
    }

    pub fn set_other_text(
        &mut self,
        request_id: &str,
        revision: u64,
        question: usize,
        text: String,
    ) {
        if revision == self.question_revision
            && self
                .action()
                .is_some_and(|action| action.request_id == request_id)
            && let Some(saved) = self.other_texts.get_mut(question)
        {
            *saved = text;
        }
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

    /// 单选题点选即替换，多选题点选即切换。
    pub fn toggle_pick(&mut self, question: usize, label: &str) {
        let Some(asked) = self
            .action()
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

    /// 作答。有题没答或“其他”留空时停到那题，并返回给用户看的提示。
    pub fn answer(&mut self) -> Result<ClientCommand, String> {
        let session_id = self.session_id.clone().ok_or("会话已结束")?;
        let questions = self
            .action()
            .and_then(|action| action.questions.clone())
            .ok_or("没有待回答的问题")?;
        let mut answers = std::collections::BTreeMap::new();
        for (ix, question) in questions.iter().enumerate() {
            let Some(text) = self.answer_text(ix) else {
                self.set_tab(ix);
                return Err(if self.others.get(ix).copied().unwrap_or(false) {
                    format!("“{}”选了其他，请填写内容", question.question)
                } else {
                    format!("还没回答“{}”", question.question)
                });
            };
            answers.insert(question.question.clone(), text);
        }
        let request = self.actions.pop_front().expect("checked above");
        self.reset_questions();
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
        images: Vec<(Arc<Image>, ImageAttachment)>,
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
        let (thumbnails, images): (Vec<_>, Vec<_>) = images.into_iter().unzip();
        self.turns.push(LiveTurn {
            prompt: prompt.clone(),
            images: thumbnails,
            items: Vec::new(),
            finished: false,
        });
        if let Some(session_id) = &self.session_id {
            return Some(ClientCommand::TurnStart {
                session_id: session_id.clone(),
                turn_id,
                prompt,
                images,
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
            resume_thread_id: self.draft.is_none().then(|| thread_id.clone()),
            initial_turn: Some(InitialTurn {
                turn_id,
                prompt,
                images,
            }),
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
        let request = self.action()?;
        if approve && request.questions.is_some() {
            return None;
        }
        let session_id = self.session_id.clone()?;
        let request = self.actions.pop_front()?;
        self.reset_questions();
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
                answers: None,
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
    /// 新建会话的 SessionStarted 带回真实 thread id：换掉占位 key，返回旧 key 和侧栏条目。
    pub fn adopt_thread(&mut self, event: &ServerEvent) -> Option<(SessionKey, HistoryListItem)> {
        let ServerEvent::SessionStarted {
            thread_id: Some(thread_id),
            ..
        } = event
        else {
            return None;
        };
        let mut item = self.draft.take()?;
        item.thread_id = thread_id.clone();
        let old = std::mem::replace(&mut self.key.2, thread_id.clone());
        Some(((self.key.0.clone(), self.key.1, old), item))
    }

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
                let reset = if let Some(index) = self
                    .actions
                    .iter()
                    .position(|action| action.request_id == request.request_id)
                {
                    let changed = index == 0 && self.actions[index].questions != request.questions;
                    self.actions[index] = request;
                    changed
                } else {
                    let first = self.actions.is_empty();
                    self.actions.push_back(request);
                    first
                };
                if reset {
                    self.reset_questions();
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
        self.reset_questions();
        if let Some(turn) = self.turns.last_mut() {
            turn.finished = true;
        }
    }

    fn reset_questions(&mut self) {
        let count = self
            .actions
            .front()
            .and_then(|action| action.questions.as_ref())
            .map_or(0, Vec::len);
        self.picks = vec![Vec::new(); count];
        self.others = vec![false; count];
        self.other_texts = vec![String::new(); count];
        self.question_revision += 1;
        self.question_tab = 0;
        self.question_cursor = 0;
    }

    /// 侧栏用的工作状态：等用户确认优先于工作中；空闲为 `None`。
    pub fn activity(&self) -> Option<Activity> {
        if self.action().is_some() {
            Some(Activity::AwaitingUser)
        } else {
            self.running.is_some().then_some(Activity::Working)
        }
    }

    /// 本轮已发出但 agent 还没有任何输出，也没有待决审批。
    pub fn waiting(&self) -> bool {
        self.running.is_some()
            && self.actions.is_empty()
            && self.turns.last().is_some_and(|turn| turn.items.is_empty())
    }

    /// 每轮连同首条用户输入附带的图片。
    pub fn turns(&self) -> Vec<(HistoryTurn, Vec<Arc<Image>>)> {
        self.turns
            .iter()
            .map(|turn| {
                let items = std::iter::once(AgentItem::UserMessage {
                    text: turn.prompt.clone(),
                    images: Vec::new(),
                    meta: AgentItemMeta::default(),
                })
                .chain(turn.items.iter().map(|(_, item)| item.clone()))
                .collect();
                (HistoryTurn { items }, turn.images.clone())
            })
            .collect()
    }
}

/// 单张图片原始字节上限：base64 后仍在 Claude 单图 5MB 限制内。
/// ponytail: 超限直接拒绝；全屏 Retina 截图这类大图需要时再做缩放重编码。
const MAX_IMAGE_BYTES: usize = 3_750_000;

/// 粘贴来的图片转成随轮发送的附件；格式或大小不合适时给出可显示的原因。
pub fn image_attachment(media_type: &str, bytes: &[u8]) -> Result<ImageAttachment, String> {
    if !SUPPORTED_IMAGE_TYPES.contains(&media_type) {
        return Err("只支持粘贴 PNG、JPEG、GIF、WebP 图片".into());
    }
    if bytes.len() > MAX_IMAGE_BYTES {
        return Err(format!(
            "图片 {:.1} MB，超过 {:.2} MB 上限",
            bytes.len() as f64 / 1e6,
            MAX_IMAGE_BYTES as f64 / 1e6
        ));
    }
    Ok(ImageAttachment {
        media_type: media_type.into(),
        data: BASE64_STANDARD.encode(bytes),
    })
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
            .send(prompt.into(), Vec::new(), "/repo".into(), Some(&caps))
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
                questions: None,
                vendor: ActionRequestVendor::ClaudeCode {
                    permission_mode_at_decision: ClaudeCodePermissionMode::Default,
                    tool_name: "Bash".into(),
                    can_persist: true,
                },
            },
        }
    }

    fn question(id: &str, multi: bool) -> ServerEvent {
        let ServerEvent::ActionRequest { mut request, .. } = approval(id) else {
            unreachable!()
        };
        request.kind = ActionKind::AnswerQuestions;
        request.questions = Some(vec![agentdeck_protocol::UserQuestion {
            question: "选择".into(),
            header: None,
            options: ["A", "B"]
                .map(|label| agentdeck_protocol::UserQuestionOption {
                    label: label.into(),
                    description: None,
                })
                .into(),
            multi_select: multi,
        }]);
        ServerEvent::ActionRequest {
            session_id: SessionId("s".into()),
            thread_id: ThreadId("thread".into()),
            agent_kind: AgentKind::ClaudeCode,
            request,
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
    fn draft_starts_a_new_thread_and_adopts_the_started_id() {
        let mut live = session();
        live.draft = Some(agentdeck_protocol::HistoryListItem {
            thread_id: ThreadId("thread".into()),
            agent_kind: AgentKind::ClaudeCode,
            title: Some("hi".into()),
            cwd: "/tmp".into(),
            last_active_ms: 0,
            archived: false,
        });
        let ClientCommand::SessionStart(start) = send(&mut live, "hi") else {
            panic!("first send must start a session");
        };
        assert_eq!(start.resume_thread_id, None);

        let started = ServerEvent::SessionStarted {
            session_id: start.session_id,
            thread_id: Some(ThreadId("real".into())),
            agent_kind: AgentKind::ClaudeCode,
        };
        let (old, item) = live.adopt_thread(&started).unwrap();
        assert_eq!(old.2, ThreadId("thread".into()));
        assert_eq!(item.thread_id, ThreadId("real".into()));
        assert_eq!(live.key.2, ThreadId("real".into()));
        assert!(live.adopt_thread(&started).is_none());
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
    fn activity_follows_running_turn() {
        let mut live = session();
        assert_eq!(live.activity(), None);
        send(&mut live, "hi");
        assert_eq!(live.activity(), Some(super::Activity::Working));
        live.apply(approval("a"));
        assert_eq!(live.activity(), Some(super::Activity::AwaitingUser));
        live.apply(error("cc-not-authenticated"));
        assert_eq!(live.activity(), None);
    }

    #[test]
    fn streaming_snapshots_upsert_by_item_id() {
        let mut live = session();
        send(&mut live, "hi");
        live.apply(message("m:0", "Hel"));
        live.apply(message("m:0", "Hello"));
        live.apply(message("m:1", "next"));
        let turns = live.turns();
        assert_eq!(turns[0].0.items.len(), 3, "prompt + two distinct items");
        assert!(
            matches!(&turns[0].0.items[1], AgentItem::AssistantMessage { text, .. } if text == "Hello")
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
            .send("plan".into(), Vec::new(), "/repo".into(), Some(&caps))
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
    fn questions_need_an_answer_each_and_join_multi_select_in_option_order() {
        use agentdeck_protocol::{UserQuestion, UserQuestionOption};
        let option = |label: &str| UserQuestionOption {
            label: label.into(),
            description: None,
        };
        let mut live = session();
        send(&mut live, "hi");
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
        assert_eq!(live.tab_count(), 3, "two questions plus the summary");
        live.move_cursor(true);
        live.move_cursor(true);
        live.move_cursor(true);
        assert_eq!(live.question_cursor, 2, "two options plus 其他");
        live.step_tab(true);
        assert_eq!((live.question_tab, live.question_cursor), (1, 0));
        live.step_tab(true);
        assert!(live.on_summary_tab());
        live.step_tab(true);
        assert!(live.on_summary_tab(), "no wrap past the summary");

        live.toggle_pick(0, "红");
        live.toggle_other(0);
        assert!(
            live.picks[0].is_empty(),
            "single select: other replaces the option"
        );
        live.toggle_pick(0, "蓝");
        assert!(!live.others[0], "single select: an option replaces other");
        assert_eq!(live.answer_text(0).as_deref(), Some("蓝"));
        assert_eq!(live.answer_text(1), None);
        assert!(live.answer().unwrap_err().contains("水果"));
        assert_eq!(
            live.question_tab, 1,
            "a blocked submit jumps to the question"
        );

        live.toggle_pick(1, "橙子");
        live.toggle_pick(1, "香蕉");
        live.toggle_pick(1, "苹果");
        live.toggle_pick(1, "香蕉");
        live.toggle_other(1);
        assert_eq!(live.answer_text(1), None, "an empty other is no answer");
        assert!(
            live.answer().unwrap_err().contains("其他"),
            "an empty other is rejected"
        );
        live.set_other_text("ask-1", live.question_revision, 1, " 芒果 ".into());
        live.forget_finished();
        assert_eq!(
            live.other_texts[1], " 芒果 ",
            "reopening keeps the answer draft"
        );
        live.set_other_text(
            "old-request",
            live.question_revision,
            1,
            "stale input".into(),
        );
        let Ok(ClientCommand::ActionDecision { decision, .. }) = live.answer() else {
            panic!("every question is answered");
        };
        let answers = decision.answers.unwrap();
        assert_eq!(answers["颜色"], "蓝");
        assert_eq!(answers["水果"], "苹果, 橙子, 芒果");
        assert!(live.action().is_none());
        assert!(live.other_texts.is_empty());
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
                questions: None,
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
    fn queued_questions_and_approvals_preserve_the_current_answer() {
        let mut live = session();
        send(&mut live, "hi");
        live.apply(question("q1", true));
        let revision = live.question_revision;
        live.toggle_pick(0, "A");
        live.toggle_other(0);
        live.set_other_text("q1", revision, 0, "自定义".into());
        live.apply(question("q2", false));
        live.apply(approval("tool"));
        live.apply(question("q1", true));
        assert_eq!(live.question_revision, revision);
        assert_eq!(live.picks, vec![vec!["A"]]);
        assert_eq!(live.others, vec![true]);
        assert_eq!(live.other_texts, vec!["自定义"]);
        let ClientCommand::ActionDecision { decision, .. } = live.answer().unwrap() else {
            panic!("expected answer");
        };
        assert_eq!(decision.request_id, "q1");
        assert_eq!(decision.answers.unwrap()["选择"], "A, 自定义");
        assert_eq!(live.action().unwrap().request_id, "q2");
        assert_eq!(live.answer_text(0), None);
        assert_eq!(live.tab_count(), 1, "one question has no summary tab");
        assert_eq!(live.other_texts, vec![""]);
        assert!(live.decide(true, false, None).is_none());
        live.toggle_pick(0, "B");
        let ClientCommand::ActionDecision { decision, .. } = live.answer().unwrap() else {
            panic!("expected second answer");
        };
        assert_eq!(decision.request_id, "q2");
        assert_eq!(decision.answers.unwrap()["选择"], "B");
        assert!(
            matches!(live.decide(true, true, None), Some(ClientCommand::ActionDecision { decision, .. }) if decision.request_id == "tool" && decision.persist)
        );
        live.apply(question("skip", false));
        assert!(
            matches!(live.decide(false, false, None), Some(ClientCommand::ActionDecision { decision, .. }) if decision.request_id == "skip" && decision.decision == ActionDecisionKind::Deny)
        );
        assert!(live.actions.is_empty() && live.other_texts.is_empty());
    }

    #[test]
    fn changed_questions_and_disconnect_discard_old_drafts() {
        let mut live = session();
        send(&mut live, "hi");
        live.apply(question("q1", true));
        let revision = live.question_revision;
        live.toggle_pick(0, "A");
        live.toggle_other(0);
        live.set_other_text("q1", revision, 0, "旧草稿".into());
        live.apply(question("q1", false));
        assert_ne!(live.question_revision, revision);
        assert_eq!(live.picks, vec![Vec::<String>::new()]);
        assert_eq!(live.others, vec![false]);
        live.set_other_text("q1", revision, 0, "迟到的旧输入".into());
        assert_eq!(live.other_texts, vec![""]);
        live.toggle_other(0);
        live.set_other_text("q1", live.question_revision, 0, "新草稿".into());
        live.apply(question("q2", true));
        live.disconnected("断线");
        assert!(live.actions.is_empty());
        assert!(live.picks.is_empty() && live.others.is_empty() && live.other_texts.is_empty());
        assert!(live.answer().is_err());
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
        assert!(
            live.send("hi".into(), Vec::new(), "/repo".into(), None)
                .is_none()
        );
        assert!(live.turns.is_empty());
        assert!(
            live.send("hi".into(), Vec::new(), "/repo".into(), Some(&caps))
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
            live.send("next".into(), Vec::new(), "/repo".into(), Some(&initial))
                .is_none()
        );
    }

    #[test]
    fn pasted_images_are_validated_and_sent_with_the_turn() {
        assert!(image_attachment("image/tiff", b"x").is_err());
        assert!(image_attachment("image/png", &vec![0; MAX_IMAGE_BYTES + 1]).is_err());
        let png = image_attachment("image/png", b"png").unwrap();
        assert_eq!(png.data, "cG5n");

        let mut live = session();
        let caps = crate::session_router::test_capabilities(AgentKind::ClaudeCode);
        let thumbnail = Arc::new(Image::from_bytes(gpui::ImageFormat::Png, b"png".to_vec()));
        let command = live
            .send(
                String::new(),
                vec![(thumbnail.clone(), png.clone())],
                "/repo".into(),
                Some(&caps),
            )
            .unwrap();
        let ClientCommand::SessionStart(start) = command else {
            panic!("first turn starts the session");
        };
        assert_eq!(start.initial_turn.unwrap().images, vec![png]);
        let (turn, images) = &live.turns()[0];
        assert!(matches!(&turn.items[0], AgentItem::UserMessage { text, .. } if text.is_empty()));
        assert_eq!(images, &vec![thumbnail]);
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
        assert!(
            matches!(&turns[0].0.items[0], AgentItem::UserMessage { text, .. } if text == "two")
        );
    }
}
