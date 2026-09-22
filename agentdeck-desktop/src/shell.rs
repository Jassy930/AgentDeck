//! 桌面端外壳：全高侧栏 + 主区，主区在空态与会话态之间切换。
//!
//! 会话列表和会话记录都来自本机 `agentdeckd`，通过 `daemon` 模块按 agent 拉取；
//! 本期只读历史，不启动 session、不发 turn。

use agentdeck_protocol::{AgentKind, HistoryListItem, HistoryTurn, ThreadId};
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
    },
}

/// 选中会话的记录加载状态。
pub enum Transcript {
    Loading,
    Ready(Vec<HistoryTurn>),
    Failed(String),
}

impl Stage {
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

pub struct Shell {
    stage: Stage,
    composer: Entity<InputState>,
    /// daemon 已注册的 agent，决定侧栏按哪些来源拉历史。
    pub(crate) agents: Vec<AgentKind>,
    /// 所有来源合并后的会话，按最近活动倒序。
    pub(crate) sessions: Vec<HistoryListItem>,
    /// 尚未返回的 daemon 请求数；用于区分"还在加载"和"确实没有会话"。
    pub(crate) pending: usize,
    /// 最近一次失败原因；成功的来源仍会正常展示。
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
                        shell.agents = kinds.clone();
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
                match listed {
                    Ok(mut items) => {
                        shell.sessions.append(&mut items);
                        shell
                            .sessions
                            .sort_by(|a, b| b.last_active_ms.cmp(&a.last_active_ms));
                    }
                    Err(message) => shell.error = Some(message),
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    pub fn open_session(&mut self, item: HistoryListItem, cx: &mut Context<Self>) {
        let (kind, thread_id) = (item.agent_kind, item.thread_id.clone());
        self.stage = Stage::Session {
            item,
            transcript: Transcript::Loading,
        };
        cx.notify();

        let requested = thread_id.clone();
        cx.spawn(async move |this, cx| {
            let read = cx
                .background_executor()
                .spawn(async move { daemon::history_read(kind, thread_id) })
                .await;
            this.update(cx, |shell, cx| {
                // 读取期间用户可能已经切走：只回填仍然选中的那个会话。
                if shell.stage.thread_id() != Some(&requested) {
                    return;
                }
                if let Stage::Session { transcript, .. } = &mut shell.stage {
                    *transcript = match read {
                        Ok(turns) => Transcript::Ready(turns),
                        Err(message) => Transcript::Failed(message),
                    };
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    pub fn show_empty(&mut self, cx: &mut Context<Self>) {
        self.stage = Stage::Empty;
        cx.notify();
    }

    /// 某个 agent 已加载到的会话数，用于空态卡片。
    fn session_count(&self, kind: AgentKind) -> usize {
        self.sessions
            .iter()
            .filter(|item| item.agent_kind == kind)
            .count()
    }

    fn render_empty(&self, cx: &App) -> impl IntoElement + use<> {
        let cards: Vec<_> = self
            .agents
            .iter()
            .map(|kind| {
                let status = if self.pending > 0 {
                    "读取中…".to_string()
                } else {
                    format!("{} 个会话", self.session_count(*kind))
                };
                connector_card(&agent_label(*kind), &status, cx)
            })
            .collect();

        let hint = match (&self.error, self.agents.is_empty(), self.pending > 0) {
            (Some(message), _, _) => message.clone(),
            (None, true, true) => "正在连接本机 agentdeckd…".to_string(),
            (None, true, false) => "本机 agentdeckd 没有注册任何 agent".to_string(),
            _ => "选择左侧会话查看记录，或试着输入任务".to_string(),
        };

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
            Transcript::Ready(turns) if turns.is_empty() => {
                placeholder("这个会话没有可显示的记录", cx).into_any_element()
            }
            Transcript::Ready(turns) => transcript::render(turns, cx).into_any_element(),
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
                    .items_center()
                    .justify_between()
                    .border_b_1()
                    .border_color(cx.theme().border)
                    .on_double_click(|_, window: &mut Window, _| window.titlebar_double_click())
                    .child(div().text_sm().font_semibold().child(session_title(item)))
                    .child(
                        div()
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
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let main = match &self.stage {
            Stage::Empty => self.render_empty(cx).into_any_element(),
            Stage::Session { item, transcript } => {
                self.render_session(item, transcript, cx).into_any_element()
            }
        };
        let selected: Option<SharedString> = self
            .stage
            .thread_id()
            .map(|thread_id| thread_id.0.clone().into());

        h_flex()
            .size_full()
            .bg(cx.theme().background)
            .text_color(cx.theme().foreground)
            .child(sidebar::render(self, selected, cx))
            .child(main)
    }
}

#[cfg(test)]
mod tests {
    use super::{Stage, Transcript, agent_label, project_name, session_title};
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
        };
        assert_eq!(stage.thread_id().map(|id| id.0.as_str()), Some("7330efa6"));
        assert_eq!(stage.project_name(), Some("AgentDeck".to_string()));

        stage = Stage::Empty;
        assert_eq!((stage.thread_id(), stage.project_name()), (None, None));
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
