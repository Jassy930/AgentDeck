//! 圆角悬浮 composer：输入区 + 工具行。工具行当前是静态占位。

use gpui::{App, Entity, IntoElement, ParentElement, div, prelude::*, px};
use gpui_component::{
    ActiveTheme,
    button::{Button, ButtonVariants},
    h_flex,
    input::{Input, InputState},
    v_flex,
};

/// composer 工具行上的能力入口。真实控件接入 capability router 后再替换。
const TOOLS: [&str; 3] = ["模型", "审批", "沙箱"];

pub fn render(state: &Entity<InputState>, cx: &App) -> impl IntoElement {
    v_flex()
        .w_full()
        .max_w(px(720.))
        .gap_3()
        .p_3()
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
                .child(h_flex().gap_2().children(TOOLS.iter().map(|tool| chip(tool, cx))))
                .child(Button::new("composer-send").primary().label("发送")),
        )
}

fn chip(label: &str, cx: &App) -> impl IntoElement {
    div()
        .px_2()
        .py_1()
        .rounded_md()
        .text_xs()
        .bg(cx.theme().muted)
        .text_color(cx.theme().muted_foreground)
        .child(label.to_string())
}
