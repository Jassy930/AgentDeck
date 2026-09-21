//! 全高左侧栏：品牌行、快捷入口、置顶会话、项目区、底部账号区。
//!
//! 条目当前全部是占位常量，点击只切换主区形态，不加载任何数据。

use gpui::{Context, IntoElement, ParentElement, SharedString, Window, div, prelude::*, px};
use gpui_component::{
    ActiveTheme, InteractiveElementExt, StyledExt,
    button::{Button, ButtonVariants},
    h_flex, v_flex,
};

use crate::shell::Shell;

/// 侧栏宽度，与 Codex Desktop 的全高侧栏一致。
const WIDTH: f32 = 248.;

/// 透明标题栏下给红绿灯留出的顶部空间，同时作为窗口拖动区。
pub const TRAFFIC_LIGHT_INSET: f32 = 44.;

/// 置顶会话占位条目，接入真实会话列表后替换。
const PINNED_SESSIONS: [&str; 3] = ["修复记录收尾", "对齐桌面外壳", "梳理协议快照"];

/// 项目占位条目，接入真实项目扫描后替换。
const PROJECTS: [&str; 3] = ["AgentDeck", "agentdeckd", "protocol"];

pub fn render(cx: &mut Context<Shell>) -> impl IntoElement {
    let mut sessions = Vec::with_capacity(PINNED_SESSIONS.len());
    for title in PINNED_SESSIONS {
        sessions.push(session_row(title, cx));
    }

    let mut projects = Vec::with_capacity(PROJECTS.len());
    for name in PROJECTS {
        projects.push(session_row(name, cx));
    }

    v_flex()
        .w(px(WIDTH))
        .h_full()
        .flex_shrink_0()
        .pb_3()
        .bg(cx.theme().sidebar)
        .text_color(cx.theme().sidebar_foreground)
        .border_r_1()
        .border_color(cx.theme().sidebar_border)
        .child(titlebar_area("sidebar-titlebar"))
        .child(
            v_flex()
                .px_3()
                .gap_4()
                .flex_1()
                .overflow_hidden()
                .child(
                    // 品牌行：对应 Codex Desktop 侧栏顶部的 workspace 切换位，当前不可切换。
                    h_flex()
                        .px_2()
                        .pb_1()
                        .justify_between()
                        .items_center()
                        .child(div().text_sm().font_semibold().child("AgentDeck"))
                        .child(
                            div()
                                .text_xs()
                                .text_color(cx.theme().muted_foreground)
                                .child("本机"),
                        ),
                )
                .child(
                    v_flex()
                        .gap_1()
                        .child(
                            Button::new("new-session")
                                .ghost()
                                .w_full()
                                .justify_start()
                                .label("新建会话")
                                .on_click(cx.listener(|shell, _, _, cx| shell.show_empty(cx))),
                        )
                        // 搜索入口只占位，没有行为。
                        .child(
                            div()
                                .px_3()
                                .py_1()
                                .text_sm()
                                .text_color(cx.theme().muted_foreground)
                                .child("搜索"),
                        ),
                )
                .child(
                    v_flex()
                        .gap_1()
                        .child(section_label("置顶", cx))
                        .children(sessions),
                )
                .child(
                    v_flex()
                        .gap_1()
                        .child(section_label("项目", cx))
                        .children(projects),
                ),
        )
        .child(
            v_flex()
                .mx_3()
                .gap_1()
                .pt_3()
                .border_t_1()
                .border_color(cx.theme().sidebar_border)
                .child(section_label("账号", cx))
                .child(div().px_2().text_sm().child("未登录")),
        )
}

/// 透明标题栏下的顶部留白：给红绿灯让位，并接管标题栏双击行为。
///
/// 注意：gpui 0.2.2 在 macOS 上**无法**把任意区域声明为窗口拖动区——
/// `on_hit_test_window_control` 是空实现，`start_window_move` 也只有 trait 默认空实现，
/// 两者都只对 Windows/Linux 生效。macOS 的窗口拖动仍由系统标题栏区域处理，
/// 这里只做布局留白，不假装提供 drag hitbox。
pub fn titlebar_area(id: &'static str) -> impl IntoElement {
    div()
        .id(id)
        .h(px(TRAFFIC_LIGHT_INSET))
        .w_full()
        .flex_shrink_0()
        .on_double_click(|_, window: &mut Window, _| window.titlebar_double_click())
}

fn section_label(text: &str, cx: &Context<Shell>) -> impl IntoElement {
    div()
        .px_2()
        .text_xs()
        .text_color(cx.theme().muted_foreground)
        .child(text.to_string())
}

/// 会话行与项目行共用同一形状；两者当前都只是切到会话态占位。
fn session_row(label: &'static str, cx: &mut Context<Shell>) -> impl IntoElement + use<> {
    let title: SharedString = label.into();

    Button::new(label)
        .ghost()
        .w_full()
        .justify_start()
        .label(label)
        .on_click(cx.listener(move |shell, _, _, cx| shell.open_session(title.clone(), cx)))
}
