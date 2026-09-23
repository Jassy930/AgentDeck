//! 全高左侧栏：品牌行、快捷入口、真实会话列表、本机 Agent 状态。
//!
//! 会话条目来自 daemon 的跨 agent 历史列表，点击即读取该会话记录。

use std::ops::Range;
use std::sync::{Arc, LazyLock};

use agentdeck_protocol::HistoryListItem;
use gpui::{
    Context, Image, ImageFormat, IntoElement, ParentElement, SharedString, Window, div, img,
    prelude::*, px, uniform_list,
};
use gpui_component::{
    ActiveTheme, Disableable, InteractiveElementExt, Selectable, StyledExt,
    button::{Button, ButtonVariants},
    h_flex, v_flex,
};

use crate::shell::{Shell, agent_label, session_title};

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

pub fn render(
    shell: &Shell,
    selected: Option<SharedString>,
    cx: &mut Context<Shell>,
) -> impl IntoElement + use<> {
    // 行高一致，用 uniform_list 只渲染可见行；行内容在布局阶段回到 Shell 取。
    let is_new_session = selected.is_none();
    let sessions = uniform_list(
        "session-list",
        shell.sessions.len(),
        cx.processor(move |shell, range: Range<usize>, window, cx| {
            shell.sessions[range]
                .iter()
                .map(|item| {
                    let is_selected = selected.as_ref().map(SharedString::as_ref)
                        == Some(item.thread_id.0.as_str());
                    // 行间距用 padding：uniform_list 按首行测量行高。
                    div()
                        .pb_1()
                        .child(session_row(item, is_selected, window, cx))
                })
                .collect()
        }),
    );

    let status = if shell.pending > 0 {
        Some("正在读取会话…".to_string())
    } else if !shell.sessions.is_empty() {
        None
    } else {
        Some(
            shell
                .error
                .clone()
                .unwrap_or_else(|| "没有可显示的会话".to_string()),
        )
    };

    let agents: Vec<_> = shell
        .agents
        .iter()
        .map(|agent| {
            (
                agent.kind,
                agent_label(agent.kind),
                agent.status(),
                agent.error().map(str::to_string),
                agent.can_load_more(),
                agent.list_hint(),
            )
        })
        .collect();

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
                                .selected(is_new_session)
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
                        .flex_1()
                        .gap_1()
                        .overflow_hidden()
                        .child(section_label("最近会话", cx))
                        .children(status.map(|text| {
                            div()
                                .px_2()
                                .text_sm()
                                .text_color(cx.theme().sidebar_foreground.opacity(0.72))
                                .child(text)
                        }))
                        .when(shell.error.is_some(), |section| {
                            section.child(
                                Button::new("retry-connection").label("重试连接").on_click(
                                    cx.listener(|shell, _, _, cx| shell.retry_connection(cx)),
                                ),
                            )
                        })
                        .child(
                            sessions
                                .flex_1()
                                // 同 transcript：flex item 需要 min_h(0) 才会真正滚动。
                                .min_h(px(0.)),
                        ),
                ),
        )
        .child(
            v_flex()
                .flex_shrink_0()
                .mx_3()
                .gap_1()
                .pt_3()
                .border_t_1()
                .border_color(cx.theme().sidebar_border)
                .child(section_label("本机 Agent", cx))
                .children(agents.into_iter().map(
                    |(kind, name, status, error, can_load_more, list_hint)| {
                        v_flex()
                            .px_2()
                            .text_sm()
                            .gap_1()
                            .child(
                                v_flex().gap_1().child(name).child(
                                    div()
                                        .text_color(cx.theme().sidebar_foreground.opacity(0.72))
                                        .child(status),
                                ),
                            )
                            .when(can_load_more, |section| {
                                section.child(
                                    Button::new(SharedString::from(format!(
                                        "load-more-{}",
                                        kind.as_str()
                                    )))
                                    .label("加载更多")
                                    .on_click(cx.listener(move |shell, _, _, cx| {
                                        shell.load_more_agent(kind, cx)
                                    })),
                                )
                            })
                            .children(list_hint.map(|hint| {
                                div()
                                    .text_xs()
                                    .text_color(cx.theme().sidebar_foreground.opacity(0.72))
                                    .child(hint)
                            }))
                            .children(error.map(|message| {
                                v_flex()
                                    .gap_1()
                                    .child(
                                        div()
                                            .text_xs()
                                            .text_color(cx.theme().sidebar_foreground.opacity(0.72))
                                            .child(message),
                                    )
                                    .child(
                                        Button::new(SharedString::from(format!(
                                            "retry-{}",
                                            kind.as_str()
                                        )))
                                        .label("重试")
                                        .on_click(
                                            cx.listener(move |shell, _, _, cx| {
                                                shell.retry_agent(kind, cx)
                                            }),
                                        ),
                                    )
                            }))
                    },
                )),
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

/// 会话行：id 用 threadId，点击后读取该会话的真实记录。
fn session_row(
    item: &HistoryListItem,
    selected: bool,
    window: &Window,
    cx: &mut Context<Shell>,
) -> impl IntoElement + use<> {
    let id: SharedString = item.thread_id.0.clone().into();
    let payload = item.clone();
    // Button 的内部 label 容器不会收缩，正文需先扣除侧栏/按钮 padding 与三条边框。
    let title_width = px(WIDTH - 3.) - window.rem_size() * 3.5;

    Button::new(id)
        .ghost()
        .selected(selected)
        .w_full()
        .justify_start()
        .child(
            div()
                .w(title_width)
                // nowrap 的文字缓存不随截断宽度变化；单行 clamp 保留按宽度重新测量。
                .whitespace_normal()
                .line_clamp(1)
                .text_ellipsis()
                .child(session_title(item)),
        )
        .on_click(cx.listener(move |shell, _, _, cx| shell.open_session(payload.clone(), cx)))
}
