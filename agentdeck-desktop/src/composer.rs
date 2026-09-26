//! 圆角悬浮 composer：输入区、项目上下文和预览状态。

use gpui::{App, Entity, IntoElement, ParentElement, div, prelude::*, px};
use gpui_component::{
    ActiveTheme, Disableable,
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
    v_flex()
        .w_full()
        .max_w(px(720.))
        .gap_2()
        .p_3()
        .rounded_xl()
        .bg(cx.theme().muted)
        .border_1()
        .border_color(cx.theme().border)
        .shadow_lg()
        .child(div().text_sm().child(format!(
            "项目：{} · Agent：{}",
            project.unwrap_or("未选择"),
            agent.unwrap_or("未选择")
        )))
        .child(Input::new(state).appearance(false))
        .child(
            h_flex()
                .items_center()
                .justify_between()
                .child(
                    v_flex()
                        .gap_1()
                        .text_sm()
                        .child("只读历史预览，暂不能发送任务")
                        .child(
                            div()
                                .text_color(cx.theme().muted_foreground)
                                .child("模型 / 审批 / 沙箱：暂不可用"),
                        ),
                )
                .child(
                    Button::new("composer-send")
                        .primary()
                        .label("发送")
                        .disabled(true),
                ),
        )
}
