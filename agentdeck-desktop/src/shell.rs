//! 桌面端外壳：全高侧栏 + 主区，主区在空态与会话态之间切换。
//!
//! 会话列表和会话记录都来自本机 `agentdeckd`，通过 `daemon` 模块按 agent 拉取；
//! 本期只读历史，不启动 session、不发 turn。

use std::collections::VecDeque;
use std::rc::Rc;
use std::time::{Duration, Instant};

use agentdeck_protocol::{AgentKind, HistoryListItem, MAX_HISTORY_LIST_LIMIT, ThreadId};
use gpui::{
    App, Context, Entity, IntoElement, ListAlignment, ListState, ParentElement, SharedString,
    Window, div, prelude::*, px,
};
use gpui_component::{
    ActiveTheme, InteractiveElementExt, StyledExt, button::Button, h_flex, input::InputState,
    v_flex,
};

use crate::composer;
use crate::daemon;
use crate::sidebar;
use crate::transcript;

/// 首屏和每次扩展的显示条数；多读一条用于判断是否还有会话。
const SIDEBAR_LIMIT: usize = 50;

// 只在 background executor 上调用；短暂失败重试一次，持续失败交给用户处理。
fn read_with_retry<T>(mut read: impl FnMut() -> daemon::Result<T>) -> daemon::Result<T> {
    match read() {
        Ok(value) => Ok(value),
        Err(_) => {
            std::thread::sleep(Duration::from_secs(1));
            read()
        }
    }
}

/// 主区当前展示的形态。
pub enum Stage {
    /// 空态：居中大标题、composer 和本机 agent 卡片。
    Empty,
    /// 会话态：thread header、会话记录和底部悬浮 composer。
    Session {
        item: HistoryListItem,
        transcript: Transcript,
        /// 会话记录的虚拟列表状态（滚动位置、已测量的块高）；每次读取完成时重置。
        list: ListState,
        read_id: u64,
    },
}

/// 虚拟列表在可见区上下额外排版的高度，避免快速滚动时出现空白。
const TRANSCRIPT_OVERDRAW: f32 = 1000.;

fn transcript_list() -> ListState {
    ListState::new(0, ListAlignment::Top, px(TRANSCRIPT_OVERDRAW))
}

/// 选中会话的记录加载状态。
pub enum Transcript {
    Loading,
    Ready(Rc<[transcript::TextBlock]>),
    Failed(String),
}

impl Stage {
    fn finish_read(
        &mut self,
        completed_id: u64,
        read: Result<Vec<transcript::TextBlock>, String>,
    ) -> bool {
        if let Stage::Session {
            transcript,
            list,
            read_id,
            ..
        } = self
            && *read_id == completed_id
        {
            *transcript = match read {
                Ok(turns) => {
                    list.reset(turns.len());
                    Transcript::Ready(turns.into())
                }
                Err(message) => Transcript::Failed(message),
            };
            return true;
        }
        false
    }

    /// 会话态的项目名；空态没有会话上下文。
    pub fn project_name(&self) -> Option<String> {
        match self {
            Stage::Empty => None,
            Stage::Session { item, .. } => Some(project_name(item)),
        }
    }

    pub fn thread_id(&self) -> Option<&ThreadId> {
        match self {
            Stage::Empty => None,
            Stage::Session { item, .. } => Some(&item.thread_id),
        }
    }
}

struct ReadRequest {
    id: u64,
    kind: AgentKind,
    thread_id: ThreadId,
}

#[derive(Default)]
struct ReadQueue {
    active: bool,
    pending: Option<ReadRequest>,
}

impl ReadQueue {
    fn push(&mut self, request: ReadRequest) -> Option<ReadRequest> {
        if self.active {
            self.pending = Some(request);
            None
        } else {
            self.active = true;
            Some(request)
        }
    }

    fn finish(&mut self) -> Option<ReadRequest> {
        let next = self.pending.take();
        self.active = next.is_some();
        next
    }

    fn clear_pending(&mut self) {
        // 执行中的 daemon 仍会正常完成；回到会话时也必须继续受单请求限制。
        self.pending = None;
    }
}

/// 会话标题：历史里没有标题就退回 thread id。
pub fn session_title(item: &HistoryListItem) -> String {
    let title = item.title.as_deref().unwrap_or("").trim();
    if title.is_empty() {
        return item.thread_id.0.clone();
    }
    title.lines().next().unwrap_or(title).trim().to_string()
}

/// 项目名：取 cwd 的最后一段。Claude Code 的 cwd 是从目录名还原的，可能不精确，
/// 因此只用于显示，不用于分组或定位。
pub fn project_name(item: &HistoryListItem) -> String {
    item.cwd
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| item.cwd.display().to_string())
}

/// agent 展示名：直接由中立 `AgentKind` 的 wire 名派生，不按 vendor 分支。
pub fn agent_label(kind: AgentKind) -> String {
    kind.as_str()
        .split('_')
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

pub(crate) struct AgentHistory {
    pub kind: AgentKind,
    /// None 表示仍在读取；成功与失败都必须保留来源，不能把失败显示成零条。
    result: Option<Result<(), String>>,
    loaded: usize,
    limit: usize,
    has_more: bool,
}

impl AgentHistory {
    fn new(kind: AgentKind) -> Self {
        Self {
            kind,
            result: None,
            loaded: 0,
            limit: SIDEBAR_LIMIT,
            has_more: false,
        }
    }

    fn request_limit(&self) -> usize {
        (self.limit + 1).min(MAX_HISTORY_LIST_LIMIT)
    }

    fn complete(&mut self, listed: &mut Result<Vec<HistoryListItem>, String>) {
        if let Ok(items) = listed {
            self.has_more = items.len() > self.limit || items.len() == MAX_HISTORY_LIST_LIMIT;
            items.truncate(self.limit);
            self.loaded = items.len();
        }
        self.result = Some(listed.as_ref().map(|_| ()).map_err(Clone::clone));
    }

    pub fn can_load_more(&self) -> bool {
        matches!(self.result, Some(Ok(()))) && self.has_more && self.limit < MAX_HISTORY_LIST_LIMIT
    }

    fn load_more(&mut self) -> bool {
        if !self.can_load_more() {
            return false;
        }
        // ponytail: 复用有上限的列表查询；数据规模超出 2,000 条时再引入 IPC 游标。
        self.limit = (self.limit + SIDEBAR_LIMIT).min(MAX_HISTORY_LIST_LIMIT);
        self.result = None;
        true
    }

    pub fn list_hint(&self) -> Option<&'static str> {
        if !matches!(self.result, Some(Ok(()))) {
            None
        } else if self.loaded == MAX_HISTORY_LIST_LIMIT {
            Some("已达 2,000 条上限")
        } else if !self.has_more {
            Some("已全部加载")
        } else {
            None
        }
    }

    fn retry(&mut self) -> bool {
        if self.error().is_none() {
            return false;
        }
        self.result = None;
        true
    }

    pub fn status(&self) -> String {
        match &self.result {
            None if self.loaded > 0 => format!("已加载 {} · 加载中…", self.loaded),
            None => "读取中…".to_string(),
            Some(Ok(())) => format!("已加载 {} 个会话", self.loaded),
            Some(Err(_)) if self.loaded > 0 => format!("已加载 {} · 加载失败", self.loaded),
            Some(Err(_)) => "读取失败".to_string(),
        }
    }

    pub fn error(&self) -> Option<&str> {
        self.result.as_ref()?.as_ref().err().map(String::as_str)
    }
}

fn empty_hint(agents: &[AgentHistory], pending: usize, error: Option<&str>) -> String {
    if let Some(error) = error {
        return error.to_string();
    }
    if agents.is_empty() {
        return if pending > 0 {
            "正在连接本机 agentdeckd…"
        } else {
            "本机 agentdeckd 没有注册任何 agent"
        }
        .to_string();
    }
    if agents.iter().any(|agent| agent.loaded > 0) {
        "选择左侧会话查看记录，或试着输入任务"
    } else if pending > 0 {
        "正在读取会话…"
    } else {
        "没有可显示的会话"
    }
    .to_string()
}

/// 开发者模式的帧统计：只记录真实发生的绘制，GPUI 按需重绘，空闲时帧率本来就低。
#[derive(Default)]
pub(crate) struct FrameStats {
    frames: VecDeque<Instant>,
}

impl FrameStats {
    /// 记录一帧，返回最近 1s 的帧数和与上一帧的间隔（毫秒）。
    fn record(&mut self, now: Instant) -> (usize, f64) {
        let interval = self
            .frames
            .back()
            .map_or(0.0, |last| now.duration_since(*last).as_secs_f64() * 1000.0);
        self.frames.push_back(now);
        while let Some(first) = self.frames.front()
            && now.duration_since(*first) >= Duration::from_secs(1)
        {
            self.frames.pop_front();
        }
        (self.frames.len(), interval)
    }
}

pub struct Shell {
    stage: Stage,
    /// Some 表示开启开发者模式，右上角显示 FPS。
    frame_stats: Option<FrameStats>,
    next_read_id: u64,
    reads: ReadQueue,
    composer: Entity<InputState>,
    /// daemon 已注册的 agent，决定侧栏按哪些来源拉历史。
    pub(crate) agents: Vec<AgentHistory>,
    /// 所有来源合并后的会话，按最近活动倒序。
    pub(crate) sessions: Vec<HistoryListItem>,
    /// 尚未返回的 daemon 请求数；用于区分"还在加载"和"确实没有会话"。
    pub(crate) pending: usize,
    /// AgentList 的失败原因；各来源历史的错误由 AgentHistory 保留。
    pub(crate) error: Option<String>,
}

impl Shell {
    /// `connect_daemon=false` 用于 selfcheck：只验证 GPUI 起得来，不碰 daemon 和
    /// 本机 vendor 历史。
    pub fn new(
        window: &mut Window,
        connect_daemon: bool,
        dev_mode: bool,
        cx: &mut Context<Self>,
    ) -> Self {
        let composer = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("描述任务，预览输入效果…")
                .multi_line(true)
                .auto_grow(1, 8)
        });

        // 打开窗口即可直接输入。切换形态时的聚焦留到接入真实会话时一并处理。
        composer.update(cx, |input, cx| input.focus(window, cx));

        let mut shell = Self {
            stage: Stage::Empty,
            frame_stats: dev_mode.then(FrameStats::default),
            next_read_id: 0,
            reads: ReadQueue::default(),
            composer,
            agents: Vec::new(),
            sessions: Vec::new(),
            pending: 0,
            error: None,
        };
        if connect_daemon {
            shell.load_sessions(cx);
        }
        if dev_mode {
            // 空闲时每秒补一帧，让 FPS 数字回落到真实值而不是停在最后一次交互。
            cx.spawn(async move |this, cx| {
                loop {
                    cx.background_executor().timer(Duration::from_secs(1)).await;
                    if this.update(cx, |_, cx| cx.notify()).is_err() {
                        break;
                    }
                }
            })
            .detach();
        }
        shell
    }

    /// 先问 daemon 注册了哪些 agent，再按 agent 分别拉历史：谁先返回谁先进侧栏，
    /// 慢的来源不挡住快的。
    fn load_sessions(&mut self, cx: &mut Context<Self>) {
        self.pending += 1;
        cx.spawn(async move |this, cx| {
            let agents = cx
                .background_executor()
                .spawn(async { read_with_retry(daemon::agent_list) })
                .await;
            this.update(cx, |shell, cx| {
                shell.pending -= 1;
                match agents {
                    Ok(kinds) => {
                        shell.agents = kinds.iter().copied().map(AgentHistory::new).collect();
                        for kind in kinds {
                            shell.load_agent_sessions(kind, cx);
                        }
                    }
                    Err(message) => shell.error = Some(message),
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn load_agent_sessions(&mut self, kind: AgentKind, cx: &mut Context<Self>) {
        let Some(agent) = self.agents.iter().find(|agent| agent.kind == kind) else {
            return;
        };
        let limit = agent.request_limit();
        self.pending += 1;
        cx.spawn(async move |this, cx| {
            let mut listed = cx
                .background_executor()
                .spawn(async move { read_with_retry(|| daemon::history_list(kind, limit)) })
                .await;
            this.update(cx, |shell, cx| {
                shell.pending -= 1;
                if let Some(agent) = shell.agents.iter_mut().find(|agent| agent.kind == kind) {
                    agent.complete(&mut listed);
                }
                if let Ok(mut items) = listed {
                    shell.sessions.retain(|item| item.agent_kind != kind);
                    shell.sessions.append(&mut items);
                    shell
                        .sessions
                        .sort_by(|a, b| b.last_active_ms.cmp(&a.last_active_ms));
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    pub fn retry_connection(&mut self, cx: &mut Context<Self>) {
        if self.error.take().is_some() {
            self.load_sessions(cx);
            cx.notify();
        }
    }

    pub fn retry_agent(&mut self, kind: AgentKind, cx: &mut Context<Self>) {
        if self
            .agents
            .iter_mut()
            .find(|agent| agent.kind == kind)
            .is_some_and(AgentHistory::retry)
        {
            self.load_agent_sessions(kind, cx);
            cx.notify();
        }
    }

    pub fn load_more_agent(&mut self, kind: AgentKind, cx: &mut Context<Self>) {
        if self
            .agents
            .iter_mut()
            .find(|agent| agent.kind == kind)
            .is_some_and(AgentHistory::load_more)
        {
            self.load_agent_sessions(kind, cx);
            cx.notify();
        }
    }

    fn retry_transcript(&mut self, cx: &mut Context<Self>) {
        if let Stage::Session {
            item,
            transcript: Transcript::Failed(_),
            ..
        } = &self.stage
        {
            self.open_session(item.clone(), cx);
        }
    }

    pub fn open_session(&mut self, item: HistoryListItem, cx: &mut Context<Self>) {
        let (kind, thread_id) = (item.agent_kind, item.thread_id.clone());
        self.next_read_id += 1;
        let read_id = self.next_read_id;
        self.stage = Stage::Session {
            item,
            transcript: Transcript::Loading,
            list: transcript_list(),
            read_id,
        };
        cx.notify();

        if let Some(request) = self.reads.push(ReadRequest {
            id: read_id,
            kind,
            thread_id,
        }) {
            self.start_read(request, cx);
        }
    }

    fn start_read(&mut self, request: ReadRequest, cx: &mut Context<Self>) {
        cx.spawn(async move |this, cx| {
            let read_id = request.id;
            let read = cx
                .background_executor()
                .spawn(async move {
                    read_with_retry(|| {
                        daemon::history_read(request.kind, request.thread_id.clone())
                    })
                    .map(transcript::prepare)
                })
                .await;
            this.update(cx, |shell, cx| {
                // 回到同一会话也属于新请求，不能接受上次读取的迟到结果。
                if shell.stage.finish_read(read_id, read) {
                    cx.notify();
                }
                if let Some(next) = shell.reads.finish() {
                    shell.start_read(next, cx);
                }
            })
            .ok();
        })
        .detach();
    }

    pub fn show_empty(&mut self, cx: &mut Context<Self>) {
        self.stage = Stage::Empty;
        self.reads.clear_pending();
        cx.notify();
    }

    fn render_empty(&self, cx: &App) -> impl IntoElement + use<> {
        let cards: Vec<_> = self
            .agents
            .iter()
            .map(|agent| connector_card(&agent_label(agent.kind), &agent.status(), cx))
            .collect();

        let hint = empty_hint(&self.agents, self.pending, self.error.as_deref());

        v_flex()
            .flex_1()
            .h_full()
            .child(sidebar::titlebar_area("empty-titlebar"))
            .child(
                v_flex()
                    .flex_1()
                    .items_center()
                    .justify_center()
                    .gap_8()
                    .px_10()
                    .pb_10()
                    .child(
                        v_flex()
                            .items_center()
                            .gap_2()
                            .child(div().text_3xl().child("今天要做什么？"))
                            .child(
                                div()
                                    .text_sm()
                                    .text_color(cx.theme().muted_foreground)
                                    .child(hint),
                            ),
                    )
                    .child(composer::render(&self.composer, None, None, cx))
                    .child(h_flex().gap_3().children(cards)),
            )
    }

    fn render_session(
        &self,
        item: &HistoryListItem,
        transcript: &Transcript,
        list: &ListState,
        cx: &mut Context<Self>,
    ) -> impl IntoElement + use<> {
        let body = match transcript {
            Transcript::Loading => placeholder("正在读取会话记录…", cx).into_any_element(),
            Transcript::Failed(message) => v_flex()
                .flex_1()
                .items_center()
                .justify_center()
                .gap_3()
                .child(div().text_sm().child(message.clone()))
                .child(
                    Button::new("retry-transcript")
                        .label("重试读取")
                        .on_click(cx.listener(|shell, _, _, cx| shell.retry_transcript(cx))),
                )
                .into_any_element(),
            Transcript::Ready(blocks) if blocks.is_empty() => {
                placeholder("这个会话没有可显示的记录", cx).into_any_element()
            }
            Transcript::Ready(blocks) => {
                transcript::render(blocks.clone(), list.clone()).into_any_element()
            }
        };

        v_flex()
            .flex_1()
            .h_full()
            // 裁剪在这一层：长会话记录不能顶穿底部 composer。
            .overflow_hidden()
            .child(
                // thread header：左标题，右上环境信息。高度同时吃掉红绿灯占位。
                h_flex()
                    .id("session-titlebar")
                    .w_full()
                    .h(px(52.))
                    .flex_shrink_0()
                    .px_5()
                    .gap_3()
                    .items_center()
                    .justify_between()
                    .border_b_1()
                    .border_color(cx.theme().border)
                    .on_double_click(|_, window: &mut Window, _| window.titlebar_double_click())
                    .child(
                        div()
                            .flex_1()
                            .min_w(px(0.))
                            .whitespace_normal()
                            .line_clamp(1)
                            .text_ellipsis()
                            .text_sm()
                            .font_semibold()
                            .child(session_title(item)),
                    )
                    .child(
                        div()
                            .flex_shrink_0()
                            .text_sm()
                            .text_color(cx.theme().muted_foreground)
                            .child(format!(
                                "{} · {}",
                                agent_label(item.agent_kind),
                                project_name(item)
                            )),
                    ),
            )
            .child(body)
            .child(
                // 底部悬浮 composer：固定高度，不被上方记录挤压或盖住。
                h_flex()
                    .w_full()
                    .flex_shrink_0()
                    .justify_center()
                    .px_6()
                    .pb_6()
                    .child(composer::render(
                        &self.composer,
                        self.stage.project_name().as_deref(),
                        Some(&agent_label(item.agent_kind)),
                        cx,
                    )),
            )
    }
}

fn placeholder(text: &str, cx: &App) -> impl IntoElement + use<> {
    v_flex().flex_1().items_center().justify_center().child(
        div()
            .text_sm()
            .text_color(cx.theme().muted_foreground)
            .child(text.to_string()),
    )
}

fn connector_card(name: &str, status: &str, cx: &App) -> impl IntoElement + use<> {
    v_flex()
        .w(px(220.))
        .gap_1()
        .p_4()
        .rounded_lg()
        .bg(cx.theme().secondary)
        .border_1()
        .border_color(cx.theme().border)
        .child(div().text_sm().font_semibold().child(name.to_string()))
        .child(
            div()
                .text_sm()
                .text_color(cx.theme().secondary_foreground)
                .child(status.to_string()),
        )
}

impl Render for Shell {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let main = match &self.stage {
            Stage::Empty => self.render_empty(cx).into_any_element(),
            Stage::Session {
                item,
                transcript,
                list,
                ..
            } => self
                .render_session(item, transcript, list, cx)
                .into_any_element(),
        };
        let selected: Option<SharedString> = self
            .stage
            .thread_id()
            .map(|thread_id| thread_id.0.clone().into());

        let fps = self.frame_stats.as_mut().map(|stats| {
            let (fps, interval) = stats.record(Instant::now());
            div()
                .absolute()
                .top_2()
                .right_2()
                .px_2()
                .py_1()
                .rounded_md()
                .bg(gpui::black().opacity(0.6))
                .text_color(gpui::white())
                .text_xs()
                .font_family("Menlo")
                .child(format!("{fps} fps · {interval:.1} ms"))
        });

        h_flex()
            .relative()
            .size_full()
            .bg(cx.theme().background)
            .text_color(cx.theme().foreground)
            .child(sidebar::render(self, selected, cx))
            .child(main)
            .children(fps)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AgentHistory, FrameStats, ReadQueue, ReadRequest, Stage, Transcript, agent_label,
        empty_hint, project_name, read_with_retry, session_title, transcript_list,
    };
    use agentdeck_protocol::{AgentKind, HistoryListItem, ThreadId};

    fn item(title: Option<&str>) -> HistoryListItem {
        HistoryListItem {
            thread_id: ThreadId("7330efa6".into()),
            agent_kind: AgentKind::ClaudeCode,
            title: title.map(|title| title.to_string()),
            cwd: "/Users/dev/Documents/AgentDeck".into(),
            last_active_ms: 1_790_058_256_247,
            archived: false,
        }
    }

    #[test]
    fn navigation_keeps_the_selected_thread_and_project_together() {
        let mut stage = Stage::Empty;
        assert_eq!((stage.thread_id(), stage.project_name()), (None, None));

        stage = Stage::Session {
            item: item(Some("修复记录收尾")),
            transcript: Transcript::Loading,
            list: transcript_list(),
            read_id: 1,
        };
        assert_eq!(stage.thread_id().map(|id| id.0.as_str()), Some("7330efa6"));
        assert_eq!(stage.project_name(), Some("AgentDeck".to_string()));

        stage = Stage::Empty;
        assert_eq!((stage.thread_id(), stage.project_name()), (None, None));
    }

    #[test]
    fn reopening_a_thread_rejects_results_from_its_previous_read() {
        let first = item(Some("A"));
        let mut other = item(Some("B"));
        other.thread_id = ThreadId("other-thread".into());
        let mut stage = Stage::Session {
            item: other,
            transcript: Transcript::Loading,
            list: transcript_list(),
            read_id: 2,
        };
        assert!(!stage.finish_read(1, Ok(vec![])));

        stage = Stage::Session {
            item: first,
            transcript: Transcript::Loading,
            list: transcript_list(),
            read_id: 3,
        };
        assert!(stage.finish_read(3, Ok(vec![("助手", "新的 A 记录".into())])));
        assert!(!stage.finish_read(1, Err("旧读取超时".into())));
        assert!(!stage.finish_read(1, Ok(vec![])));
        assert!(matches!(
            &stage,
            Stage::Session { transcript: Transcript::Ready(turns), list, .. }
                if turns.len() == 1 && list.item_count() == 1
        ));

        stage = Stage::Empty;
        assert!(!stage.finish_read(3, Ok(vec![])));
    }

    fn read_request(id: u64, thread: &str) -> ReadRequest {
        ReadRequest {
            id,
            kind: AgentKind::Codex,
            thread_id: ThreadId(thread.into()),
        }
    }

    #[test]
    fn read_retry_recovers_once_and_stops_on_persistent_failure() {
        for failures in [0, 1, 2] {
            let mut attempts = 0;
            let result = read_with_retry(|| {
                attempts += 1;
                if attempts <= failures {
                    Err(format!("attempt {attempts}"))
                } else {
                    Ok("loaded")
                }
            });
            assert_eq!(attempts, (failures + 1).min(2));
            if failures == 2 {
                assert_eq!(result.unwrap_err(), "attempt 2");
            } else {
                assert_eq!(result.unwrap(), "loaded");
            }
        }
    }

    #[test]
    fn failed_source_can_retry_without_restarting_a_pending_or_successful_read() {
        let mut source = AgentHistory::new(AgentKind::Codex);
        assert!(!source.retry());
        source.complete(&mut Err("timeout".into()));
        assert!(source.retry());
        assert_eq!(source.status(), "读取中…");
        assert!(source.error().is_none());
        assert!(!source.retry());
        source.complete(&mut Err("still unavailable".into()));
        assert!(source.retry());
        source.complete(&mut Ok(vec![item(None)]));
        assert_eq!(source.status(), "已加载 1 个会话");
        assert!(!source.retry());
    }

    #[test]
    fn load_more_uses_lookahead_and_stops_at_end_or_protocol_limit() {
        for total in [0, 49, 50, 51, 100, 101, 1_999, 2_000, 2_001] {
            let mut source = AgentHistory::new(AgentKind::Codex);
            let mut expected = 50;
            loop {
                assert_eq!(source.limit, expected);
                assert!(!source.load_more());
                let mut listed = Ok(vec![item(None); total.min(source.request_limit())]);
                source.complete(&mut listed);
                assert_eq!(listed.unwrap().len(), total.min(expected));
                assert_eq!(source.loaded, total.min(expected));
                if !source.can_load_more() {
                    assert_eq!(source.loaded, total.min(2_000));
                    assert_eq!(
                        source.list_hint(),
                        Some(if total >= 2_000 {
                            "已达 2,000 条上限"
                        } else {
                            "已全部加载"
                        })
                    );
                    assert!(!source.load_more());
                    break;
                }
                assert!(source.list_hint().is_none());
                assert!(source.load_more());
                expected = (expected + 50).min(2_000);
            }
        }
    }

    #[test]
    fn failed_load_more_keeps_count_and_retries_the_same_limit() {
        let mut source = AgentHistory::new(AgentKind::Codex);
        source.complete(&mut Ok(vec![item(None); 51]));
        assert!(source.load_more());
        assert_eq!(source.status(), "已加载 50 · 加载中…");
        assert_eq!(source.request_limit(), 101);
        assert!(!source.load_more());
        source.complete(&mut Err("timeout".into()));
        assert_eq!(source.status(), "已加载 50 · 加载失败");
        assert_eq!(source.error(), Some("timeout"));
        assert!(!source.load_more());
        assert!(source.retry());
        assert_eq!(source.request_limit(), 101);
        assert!(!source.retry());
        source.complete(&mut Ok(vec![item(None); 100]));
        assert_eq!(source.status(), "已加载 100 个会话");
        assert_eq!(source.list_hint(), Some("已全部加载"));
    }

    #[test]
    fn slow_read_only_runs_the_last_pending_selection() {
        let mut reads = ReadQueue::default();
        let first = reads.push(read_request(1, "A")).unwrap();
        assert_eq!(first.thread_id.0, "A");
        assert!(reads.push(read_request(2, "B")).is_none());
        assert!(reads.push(read_request(3, "C")).is_none());

        let next = reads.finish().unwrap();
        assert_eq!(next.thread_id.0, "C");
        assert_eq!(next.id, 3);
        assert!(reads.active);
        assert!(reads.finish().is_none());
        assert!(!reads.active);

        assert!(reads.push(read_request(4, "A")).is_some());
        assert!(reads.push(read_request(5, "B")).is_none());
        reads.clear_pending();
        assert!(reads.active);
        assert!(reads.finish().is_none());

        assert!(reads.push(read_request(6, "A")).is_some());
        reads.clear_pending();
        assert!(reads.push(read_request(7, "C")).is_none());
        assert_eq!(reads.finish().unwrap().id, 7);
    }

    #[test]
    fn each_agent_keeps_its_loading_failure_and_empty_result_distinct() {
        let mut fast = AgentHistory::new(AgentKind::ClaudeCode);
        let mut slow = AgentHistory::new(AgentKind::Codex);
        fast.complete(&mut Ok(vec![item(None)]));
        assert_eq!(fast.status(), "已加载 1 个会话");
        assert_eq!(slow.status(), "读取中…");

        slow.complete(&mut Err("历史读取超时".into()));
        assert_eq!(slow.status(), "读取失败");
        assert_eq!(slow.error(), Some("历史读取超时"));
        assert_eq!(fast.status(), "已加载 1 个会话");
        assert_eq!(fast.error(), None);

        fast.complete(&mut Ok(vec![]));
        assert_eq!(fast.status(), "已加载 0 个会话");
        assert_eq!(slow.error(), Some("历史读取超时"));
    }

    #[test]
    fn empty_hint_does_not_offer_selection_after_failure_and_zero_results() {
        let mut agents = [
            AgentHistory::new(AgentKind::Codex),
            AgentHistory::new(AgentKind::ClaudeCode),
        ];
        agents[0].complete(&mut Err("历史读取超时".into()));
        assert_eq!(empty_hint(&agents, 1, None), "正在读取会话…");

        agents[1].complete(&mut Ok(vec![]));
        assert_eq!(empty_hint(&agents, 0, None), "没有可显示的会话");

        agents[1].complete(&mut Ok(vec![item(None)]));
        assert_eq!(
            empty_hint(&agents, 0, None),
            "选择左侧会话查看记录，或试着输入任务"
        );
    }

    #[test]
    fn session_title_falls_back_to_the_thread_id_and_keeps_one_line() {
        assert_eq!(session_title(&item(None)), "7330efa6");
        assert_eq!(session_title(&item(Some("   "))), "7330efa6");
        assert_eq!(session_title(&item(Some("第一行\n第二行"))), "第一行");
    }

    #[test]
    fn project_name_uses_the_last_path_segment() {
        assert_eq!(project_name(&item(None)), "AgentDeck");
    }

    #[test]
    fn agent_label_comes_from_the_neutral_wire_name() {
        assert_eq!(agent_label(AgentKind::Codex), "Codex");
        assert_eq!(agent_label(AgentKind::ClaudeCode), "Claude Code");
    }

    #[test]
    fn frame_stats_counts_frames_within_last_second() {
        use std::time::{Duration, Instant};
        let start = Instant::now();
        let mut stats = FrameStats::default();
        assert_eq!(stats.record(start), (1, 0.0));
        let (fps, interval) = stats.record(start + Duration::from_millis(500));
        assert_eq!(fps, 2);
        assert!((interval - 500.0).abs() < 1e-6);
        // 第一帧已超出 1s 窗口。
        assert_eq!(stats.record(start + Duration::from_millis(1200)).0, 2);
    }
}
