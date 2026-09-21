//! 桌面端外壳：全高侧栏 + 主区，主区在空态与会话态之间切换。
//!
//! 当前只有静态骨架，不连接 daemon、IPC 或任何 vendor 进程。

use gpui::{App, Context, Entity, IntoElement, ParentElement, SharedString, Window, div, prelude::*, px};
use gpui_component::{ActiveTheme, StyledExt, h_flex, input::InputState, v_flex};

use crate::composer;
use crate::sidebar;

/// 主区当前展示的形态。
pub enum Stage {
    /// 空态：居中大标题、composer 和连接卡片。
    Empty,
    /// 会话态：thread header、transcript 区和底部悬浮 composer。
    Session { title: SharedString },
}

impl Stage {
    /// 会话态的 header 标题；空态没有 header。
    pub fn header_title(&self) -> Option<&str> {
        match self {
            Stage::Empty => None,
            Stage::Session { title } => Some(title.as_ref()),
        }
    }
}

/// 空态下并列展示的接入入口。两家并列由数据驱动，UI 不按 vendor 分支。
const CONNECTORS: [(&str, &str); 2] = [
    ("Codex", "本机 CLI · 未连接"),
    ("Claude Code", "本机 CLI · 未连接"),
];

pub struct Shell {
    stage: Stage,
    composer: Entity<InputState>,
}

impl Shell {
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let composer = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("交给 agent 一个任务…")
                .multi_line(true)
                .auto_grow(1, 8)
        });

        Self {
            stage: Stage::Empty,
            composer,
        }
    }

    pub fn open_session(&mut self, title: SharedString, cx: &mut Context<Self>) {
        self.stage = Stage::Session { title };
        cx.notify();
    }

    pub fn show_empty(&mut self, cx: &mut Context<Self>) {
        self.stage = Stage::Empty;
        cx.notify();
    }

    fn render_empty(&self, cx: &App) -> impl IntoElement {
        v_flex()
            .flex_1()
            .h_full()
            .items_center()
            .justify_center()
            .gap_8()
            .p_10()
            .child(
                v_flex()
                    .items_center()
                    .gap_2()
                    .child(div().text_3xl().child("今天要做什么？"))
                    .child(
                        div()
                            .text_sm()
                            .text_color(cx.theme().muted_foreground)
                            .child("选择一个项目，或直接描述任务"),
                    ),
            )
            .child(composer::render(&self.composer, cx))
            .child(
                h_flex().gap_3().children(
                    CONNECTORS
                        .iter()
                        .map(|(name, status)| connector_card(name, status, cx)),
                ),
            )
            .child(
                div()
                    .text_xs()
                    .text_color(cx.theme().muted_foreground)
                    .child("本机运行 · 尚未接入 daemon"),
            )
    }

    fn render_session(&self, title: &str, cx: &App) -> impl IntoElement {
        v_flex()
            .flex_1()
            .h_full()
            .child(
                // thread header：左标题，右上环境信息占位。
                h_flex()
                    .w_full()
                    .h(px(52.))
                    .flex_shrink_0()
                    .px_5()
                    .items_center()
                    .justify_between()
                    .border_b_1()
                    .border_color(cx.theme().border)
                    .child(div().text_sm().font_semibold().child(title.to_string()))
                    .child(
                        div()
                            .text_xs()
                            .text_color(cx.theme().muted_foreground)
                            .child("本机 · 分支未知"),
                    ),
            )
            .child(
                // transcript 区：本期只有占位，不渲染消息流。
                v_flex()
                    .flex_1()
                    .items_center()
                    .justify_center()
                    .child(
                        div()
                            .text_sm()
                            .text_color(cx.theme().muted_foreground)
                            .child("transcript 尚未接入"),
                    ),
            )
            .child(
                // 底部悬浮 composer。
                h_flex()
                    .w_full()
                    .justify_center()
                    .px_6()
                    .pb_6()
                    .child(composer::render(&self.composer, cx)),
            )
    }
}

fn connector_card(name: &str, status: &str, cx: &App) -> impl IntoElement {
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
                .text_xs()
                .text_color(cx.theme().muted_foreground)
                .child(status.to_string()),
        )
}

impl Render for Shell {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let main = match self.stage.header_title() {
            None => self.render_empty(cx).into_any_element(),
            Some(title) => self.render_session(title, cx).into_any_element(),
        };

        h_flex()
            .size_full()
            .bg(cx.theme().background)
            .text_color(cx.theme().foreground)
            .child(sidebar::render(cx))
            .child(main)
    }
}

#[cfg(test)]
mod tests {
    use super::Stage;

    #[test]
    fn empty_stage_has_no_header_title() {
        assert_eq!(Stage::Empty.header_title(), None);
        assert_eq!(
            Stage::Session {
                title: "demo".into()
            }
            .header_title(),
            Some("demo")
        );
    }
}
