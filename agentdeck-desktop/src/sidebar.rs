//! 全高左侧栏：品牌行、快捷入口、置顶会话、项目区、本机 Agent 状态。
//!
//! 条目当前全部是占位常量，点击只切换主区形态，不加载任何数据。

use std::sync::{Arc, LazyLock};

use gpui::{
    Context, Image, ImageFormat, IntoElement, ParentElement, SharedString, Window, div, img,
    prelude::*, px,
};
use gpui_component::{
    ActiveTheme, Disableable, InteractiveElementExt, Selectable, StyledExt,
    button::{Button, ButtonVariants},
    h_flex, v_flex,
};

use crate::shell::{CONNECTORS, Shell};

/// 侧栏宽度，与 Codex Desktop 的全高侧栏一致。
const WIDTH: f32 = 248.;

static BRAND_ICON: LazyLock<Arc<Image>> = LazyLock::new(|| {
    Arc::new(Image::from_bytes(
        ImageFormat::Png,
        include_bytes!("../../assets/brand/agentdeck.png").to_vec(),
    ))
});

/// 透明标题栏下给红绿灯留出的顶部空间。
pub const TRAFFIC_LIGHT_INSET: f32 = 44.;

/// 置顶会话占位条目，接入真实会话列表后替换。
const PINNED_SESSIONS: [(&str, &str); 3] = [
    ("修复记录收尾", "agentdeckd"),
    ("对齐桌面外壳", "AgentDeck"),
    ("梳理协议快照", "protocol"),
];

/// 项目占位条目，接入真实项目扫描后替换。
const PROJECTS: [&str; 3] = ["AgentDeck", "agentdeckd", "protocol"];

pub fn render(selected: Option<&str>, cx: &mut Context<Shell>) -> impl IntoElement + use<> {
    let mut sessions = Vec::with_capacity(PINNED_SESSIONS.len());
    for (title, project) in PINNED_SESSIONS {
        sessions.push(session_row(title, project, selected == Some(title), cx));
    }

    let mut projects = Vec::with_capacity(PROJECTS.len());
    for name in PROJECTS {
        projects.push(session_row(name, name, selected == Some(name), cx));
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
                        .child(
                            h_flex()
                                .gap_2()
                                .items_center()
                                .child(img(BRAND_ICON.clone()).size(px(24.)).flex_shrink_0())
                                .child(div().text_sm().font_semibold().child("AgentDeck")),
                        )
                        .child(
                            div()
                                .text_sm()
                                .text_color(cx.theme().sidebar_foreground.opacity(0.72))
                                .child("本机"),
                        ),
                )
                .child(
                    v_flex()
                        .gap_1()
                        .child(
                            Button::new("new-session")
                                .ghost()
                                .selected(selected.is_none())
                                .w_full()
                                .justify_start()
                                .label("新建会话")
                                .on_click(cx.listener(|shell, _, _, cx| shell.show_empty(cx))),
                        )
                        .child(
                            Button::new("search")
                                .ghost()
                                .w_full()
                                .justify_start()
                                .label("搜索（未开放）")
                                .disabled(true),
                        ),
                )
                .child(
                    v_flex()
                        .gap_1()
                        .child(section_label("置顶 · 示例", cx))
                        .children(sessions),
                )
                .child(
                    v_flex()
                        .gap_1()
                        .child(section_label("项目 · 示例", cx))
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
                .child(section_label("本机 Agent", cx))
                .children(CONNECTORS.iter().map(|(name, status)| {
                    h_flex()
                        .px_2()
                        .text_sm()
                        .justify_between()
                        .child(*name)
                        .child(
                            div()
                                .text_color(cx.theme().sidebar_foreground.opacity(0.72))
                                .child(*status),
                        )
                })),
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
        .text_sm()
        .font_semibold()
        .text_color(cx.theme().sidebar_foreground.opacity(0.72))
        .child(text.to_string())
}

/// 会话行与项目行共用同一形状；两者当前都只是切到会话态占位。
fn session_row(
    label: &'static str,
    project: &'static str,
    selected: bool,
    cx: &mut Context<Shell>,
) -> impl IntoElement + use<> {
    let title: SharedString = label.into();

    Button::new(label)
        .ghost()
        .selected(selected)
        .w_full()
        .justify_start()
        .label(label)
        .on_click(
            cx.listener(move |shell, _, _, cx| {
                shell.open_session(title.clone(), project.into(), cx)
            }),
        )
}
