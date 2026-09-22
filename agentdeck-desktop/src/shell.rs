//! 桌面端外壳：全高侧栏 + 主区，主区在空态与会话态之间切换。
//!
//! 当前只有静态骨架，不连接 daemon、IPC 或任何 vendor 进程。

use gpui::{
    App, Context, Entity, IntoElement, ParentElement, SharedString, Window, div, prelude::*, px,
};
use gpui_component::{
    ActiveTheme, InteractiveElementExt, StyledExt, h_flex, input::InputState, v_flex,
};

use crate::composer;
use crate::sidebar;

/// 主区当前展示的形态。
pub enum Stage {
    /// 空态：居中大标题、composer 和连接卡片。
    Empty,
    /// 会话态：thread header、transcript 区和底部悬浮 composer。
    Session {
        title: SharedString,
        project: SharedString,
    },
}

impl Stage {
    /// 会话态的 header 标题；空态没有 header。
    pub fn header_title(&self) -> Option<&str> {
        match self {
            Stage::Empty => None,
            Stage::Session { title, .. } => Some(title.as_ref()),
        }
    }

    pub fn project_name(&self) -> Option<&str> {
        match self {
            Stage::Empty => None,
            Stage::Session { project, .. } => Some(project.as_ref()),
        }
    }
}

/// 空态下并列展示的接入入口。两家并列由数据驱动，UI 不按 vendor 分支。
pub const CONNECTORS: [(&str, &str); 2] = [("Codex", "尚未接入"), ("Claude Code", "尚未接入")];

pub struct Shell {
    stage: Stage,
    composer: Entity<InputState>,
}

impl Shell {
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let composer = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("描述任务，预览输入效果…")
                .multi_line(true)
                .auto_grow(1, 8)
        });

        // 打开窗口即可直接输入。切换形态时的聚焦留到接入真实会话时一并处理。
        composer.update(cx, |input, cx| input.focus(window, cx));

        Self {
            stage: Stage::Empty,
            composer,
        }
    }

    pub fn open_session(
        &mut self,
        title: SharedString,
        project: SharedString,
        cx: &mut Context<Self>,
    ) {
        self.stage = Stage::Session { title, project };
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
                                    .child("选择示例项目，或试着输入任务"),
                            ),
                    )
                    .child(composer::render(&self.composer, None, cx))
                    .child(
                        h_flex().gap_3().children(
                            CONNECTORS
                                .iter()
                                .map(|(name, status)| connector_card(name, status, cx)),
                        ),
                    ),
            )
    }

    fn render_session(&self, title: &str, cx: &App) -> impl IntoElement {
        v_flex()
            .flex_1()
            .h_full()
            .child(
                // thread header：左标题，右上环境信息占位。高度同时吃掉红绿灯占位。
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
                    .child(div().text_sm().font_semibold().child(title.to_string()))
                    .child(
                        div()
                            .text_sm()
                            .text_color(cx.theme().muted_foreground)
                            .child("示例会话"),
                    ),
            )
            .child(
                // transcript 区：本期只有占位，不渲染消息流。
                v_flex().flex_1().items_center().justify_center().child(
                    div()
                        .text_sm()
                        .text_color(cx.theme().muted_foreground)
                        .child("任务记录将在这里显示"),
                ),
            )
            .child(
                // 底部悬浮 composer。
                h_flex()
                    .w_full()
                    .justify_center()
                    .px_6()
                    .pb_6()
                    .child(composer::render(
                        &self.composer,
                        self.stage.project_name(),
                        cx,
                    )),
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
                .text_sm()
                .text_color(cx.theme().secondary_foreground)
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
            .child(sidebar::render(self.stage.header_title(), cx))
            .child(main)
    }
}

#[cfg(test)]
mod tests {
    use super::Stage;

    #[test]
    fn navigation_keeps_the_selected_item_and_project_together() {
        let mut stage = Stage::Empty;
        assert_eq!((stage.header_title(), stage.project_name()), (None, None));

        stage = Stage::Session {
            title: "修复记录收尾".into(),
            project: "agentdeckd".into(),
        };
        assert_eq!(
            (stage.header_title(), stage.project_name()),
            (Some("修复记录收尾"), Some("agentdeckd"))
        );

        stage = Stage::Empty;
        assert_eq!((stage.header_title(), stage.project_name()), (None, None));
    }
}
