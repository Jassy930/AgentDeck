//! 全高左侧栏：顶部快捷入口、项目区、底部账号区。条目当前是静态占位。

use gpui::{Context, IntoElement, ParentElement, SharedString, div, prelude::*, px};
use gpui_component::{
    ActiveTheme,
    button::{Button, ButtonVariants},
    v_flex,
};

use crate::shell::Shell;

/// 侧栏宽度，与 Codex Desktop 的全高侧栏一致。
const WIDTH: f32 = 248.;

/// 透明标题栏下给红绿灯留出的顶部空间。
const TRAFFIC_LIGHT_INSET: f32 = 44.;

/// 项目区占位条目，接入真实会话列表后替换。
const PROJECTS: [&str; 3] = ["AgentDeck", "agentdeckd", "protocol"];

pub fn render(cx: &mut Context<Shell>) -> impl IntoElement {
    let mut projects = Vec::with_capacity(PROJECTS.len());
    for name in PROJECTS {
        projects.push(project_row(name, cx));
    }

    v_flex()
        .w(px(WIDTH))
        .h_full()
        .flex_shrink_0()
        .pt(px(TRAFFIC_LIGHT_INSET))
        .pb_3()
        .px_3()
        .gap_4()
        .bg(cx.theme().sidebar)
        .text_color(cx.theme().sidebar_foreground)
        .border_r_1()
        .border_color(cx.theme().sidebar_border)
        .child(
            Button::new("new-session")
                .primary()
                .w_full()
                .label("新建会话")
                .on_click(cx.listener(|shell, _, _, cx| shell.show_empty(cx))),
        )
        .child(
            v_flex()
                .gap_1()
                .child(section_label("项目", cx))
                .children(projects),
        )
        .child(div().flex_1())
        .child(
            v_flex()
                .gap_1()
                .pt_3()
                .border_t_1()
                .border_color(cx.theme().sidebar_border)
                .child(section_label("账号", cx))
                .child(div().text_sm().child("未登录")),
        )
}

fn section_label(text: &str, cx: &Context<Shell>) -> impl IntoElement {
    div()
        .px_2()
        .text_xs()
        .text_color(cx.theme().muted_foreground)
        .child(text.to_string())
}

fn project_row(name: &'static str, cx: &mut Context<Shell>) -> impl IntoElement + use<> {
    let title: SharedString = name.into();

    Button::new(name)
        .ghost()
        .w_full()
        .justify_start()
        .label(name)
        .on_click(cx.listener(move |shell, _, _, cx| shell.open_session(title.clone(), cx)))
}
