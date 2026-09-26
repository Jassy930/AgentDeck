//! 圆角悬浮 composer：输入区、项目上下文和预览状态。

use gpui::{App, Entity, IntoElement, ParentElement, div, prelude::*, px};
use gpui_component::{
    ActiveTheme, Disableable, Sizable,
    button::{Button, ButtonVariants},
    h_flex,
    input::{Input, InputState},
    v_flex,
};

pub fn render(
    state: &Entity<InputState>,
    project: Option<&str>,
    agent: Option<&str>,
    cx: &App,
) -> impl IntoElement {
    // 两行布局：输入行 + 上下文/状态行，尽量少占会话记录的纵向空间。
    v_flex()
        .w_full()
        .max_w(px(720.))
        .gap_1()
        .px_3()
        .py_2()
        .rounded_xl()
        .bg(cx.theme().background)
        .border_1()
        .border_color(cx.theme().border)
        .shadow_lg()
        .child(Input::new(state).appearance(false))
        .child(
            h_flex()
                .items_center()
                .justify_between()
                .gap_2()
                .child(
                    div()
                        .flex_1()
                        .min_w_0()
                        .text_xs()
                        .text_color(cx.theme().muted_foreground)
                        .truncate()
                        .child(format!(
                            "项目：{} · Agent：{} · 只读历史预览，暂不能发送",
                            project.unwrap_or("未选择"),
                            agent.unwrap_or("未选择")
                        )),
                )
                .child(
                    Button::new("composer-send")
                        .primary()
                        .xsmall()
                        .label("发送")
                        .disabled(true),
                ),
        )
}
