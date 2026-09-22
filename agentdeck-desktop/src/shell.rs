//! 桌面端外壳：全高侧栏 + 主区，主区在空态与会话态之间切换。
//!
//! 会话列表和会话记录都来自本机 `agentdeckd`，通过 `daemon` 模块按 agent 拉取；
//! 本期只读历史，不启动 session、不发 turn。

use agentdeck_protocol::{AgentKind, HistoryListItem, ThreadId};
use gpui::{
    App, Context, Entity, IntoElement, ParentElement, SharedString, Window, div, prelude::*, px,
};
use gpui_component::{
    ActiveTheme, InteractiveElementExt, StyledExt, h_flex, input::InputState, v_flex,
};

use crate::composer;
use crate::daemon;
use crate::sidebar;
use crate::transcript;

/// 侧栏每个 agent 拉取的会话条数。控制首屏延迟：Codex 的 `thread/list` 按页
/// 聚合，页数越多越接近 daemon 的历史超时。
const SIDEBAR_LIMIT: usize = 50;

/// 主区当前展示的形态。
pub enum Stage {
    /// 空态：居中大标题、composer 和本机 agent 卡片。
    Empty,
    /// 会话态：thread header、会话记录和底部悬浮 composer。
    Session {
        item: HistoryListItem,
        transcript: Transcript,
        read_id: u64,
    },
}

/// 选中会话的记录加载状态。
pub enum Transcript {
    Loading,
    Ready(Vec<transcript::TextBlock>),
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
            read_id,
            ..
        } = self
            && *read_id == completed_id
        {
            *transcript = match read {
                Ok(turns) => Transcript::Ready(turns),
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
    result: Option<Result<usize, String>>,
}

impl AgentHistory {
    fn new(kind: AgentKind) -> Self {
        Self { kind, result: None }
    }

    fn complete(&mut self, listed: &Result<Vec<HistoryListItem>, String>) {
        self.result = Some(listed.as_ref().map(Vec::len).map_err(Clone::clone));
    }

    pub fn status(&self) -> String {
        match &self.result {
            None => "读取中…".to_string(),
            Some(Ok(count)) => format!("{count} 个会话"),
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
    if agents
        .iter()
        .any(|agent| matches!(agent.result, Some(Ok(count)) if count > 0))
    {
        "选择左侧会话查看记录，或试着输入任务"
    } else if pending > 0 {
        "正在读取会话…"
    } else {
        "没有可显示的会话"
    }
    .to_string()
}

pub struct Shell {
    stage: Stage,
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
    pub fn new(window: &mut Window, connect_daemon: bool, cx: &mut Context<Self>) -> Self {
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
        shell
    }

    /// 先问 daemon 注册了哪些 agent，再按 agent 分别拉历史：谁先返回谁先进侧栏，
    /// 慢的来源不挡住快的。
    fn load_sessions(&mut self, cx: &mut Context<Self>) {
        self.pending += 1;
        cx.spawn(async move |this, cx| {
            let agents = cx
                .background_executor()
                .spawn(async { daemon::agent_list() })
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
        self.pending += 1;
        cx.spawn(async move |this, cx| {
            let listed = cx
                .background_executor()
                .spawn(async move { daemon::history_list(kind, SIDEBAR_LIMIT) })
                .await;
            this.update(cx, |shell, cx| {
                shell.pending -= 1;
                if let Some(agent) = shell.agents.iter_mut().find(|agent| agent.kind == kind) {
                    agent.complete(&listed);
                }
                if let Ok(mut items) = listed {
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

    pub fn open_session(&mut self, item: HistoryListItem, cx: &mut Context<Self>) {
        let (kind, thread_id) = (item.agent_kind, item.thread_id.clone());
        self.next_read_id += 1;
        let read_id = self.next_read_id;
        self.stage = Stage::Session {
            item,
            transcript: Transcript::Loading,
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
                    daemon::history_read(request.kind, request.thread_id).map(transcript::prepare)
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
        cx: &App,
    ) -> impl IntoElement + use<> {
        let body = match transcript {
            Transcript::Loading => placeholder("正在读取会话记录…", cx).into_any_element(),
            Transcript::Failed(message) => placeholder(message, cx).into_any_element(),
            Transcript::Ready(blocks) if blocks.is_empty() => {
                placeholder("这个会话没有可显示的记录", cx).into_any_element()
            }
            Transcript::Ready(blocks) => transcript::render(blocks, cx).into_any_element(),
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
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let main = match &self.stage {
            Stage::Empty => self.render_empty(cx).into_any_element(),
            Stage::Session {
                item, transcript, ..
            } => self.render_session(item, transcript, cx).into_any_element(),
        };
        let selected: Option<SharedString> = self
            .stage
            .thread_id()
            .map(|thread_id| thread_id.0.clone().into());

        h_flex()
            .size_full()
            .bg(cx.theme().background)
            .text_color(cx.theme().foreground)
            .child(sidebar::render(self, selected, window, cx))
            .child(main)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AgentHistory, ReadQueue, ReadRequest, Stage, Transcript, agent_label, empty_hint,
        project_name, session_title,
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
            read_id: 2,
        };
        assert!(!stage.finish_read(1, Ok(vec![])));

        stage = Stage::Session {
            item: first,
            transcript: Transcript::Loading,
            read_id: 3,
        };
        assert!(stage.finish_read(3, Ok(vec![("助手", "新的 A 记录".into())])));
        assert!(!stage.finish_read(1, Err("旧读取超时".into())));
        assert!(!stage.finish_read(1, Ok(vec![])));
        assert!(matches!(
            &stage,
            Stage::Session { transcript: Transcript::Ready(turns), .. } if turns.len() == 1
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
        fast.complete(&Ok(vec![item(None)]));
        assert_eq!(fast.status(), "1 个会话");
        assert_eq!(slow.status(), "读取中…");

        slow.complete(&Err("历史读取超时".into()));
        assert_eq!(slow.status(), "读取失败");
        assert_eq!(slow.error(), Some("历史读取超时"));
        assert_eq!(fast.status(), "1 个会话");
        assert_eq!(fast.error(), None);

        fast.complete(&Ok(vec![]));
        assert_eq!(fast.status(), "0 个会话");
        assert_eq!(slow.error(), Some("历史读取超时"));
    }

    #[test]
    fn empty_hint_does_not_offer_selection_after_failure_and_zero_results() {
        let mut agents = [
            AgentHistory::new(AgentKind::Codex),
            AgentHistory::new(AgentKind::ClaudeCode),
        ];
        agents[0].complete(&Err("历史读取超时".into()));
        assert_eq!(empty_hint(&agents, 1, None), "正在读取会话…");

        agents[1].complete(&Ok(vec![]));
        assert_eq!(empty_hint(&agents, 0, None), "没有可显示的会话");

        agents[1].complete(&Ok(vec![item(None)]));
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
}
