//! 全高左侧栏：品牌行、新建与搜索、按日期分组的会话列表、底部页面入口（机器管理）。
//!
//! 会话条目来自各台机器 daemon 的跨 agent 历史列表，点击即读取该会话记录。

use std::ops::Range;
use std::sync::{Arc, LazyLock};

use agentdeck_protocol::AgentKind;
use gpui::{
    App, Context, FontWeight, Image, ImageFormat, IntoElement, ParentElement, Pixels, SharedString,
    Window, div, img, prelude::*, px, uniform_list,
};
use gpui_component::{
    ActiveTheme, Disableable, Icon, InteractiveElementExt, Selectable, Sizable, StyledExt,
    button::{Button, ButtonVariants},
    h_flex,
    input::Input,
    tooltip::Tooltip,
    v_flex,
};

use crate::live::Activity;
use crate::shell::{
    Session, SessionKey, Shell, SidebarRow, Stage, machine_label, project_name, session_title,
};

/// 侧栏宽度，与 Codex Desktop 的全高侧栏一致。
const WIDTH: f32 = 248.;
const AGENT_ICON_SIZE: f32 = 16.;
/// 会话行与分组标题共用的行高：uniform_list 按首行测量，两者必须一致。
const ROW_HEIGHT: f32 = 36.;
/// 会话行尾时间列宽度，容纳 "12/31" 或 "23:59"。
const TIME_WIDTH: f32 = 36.;
/// 远端会话行的主机标签宽度，过长时省略。
const HOST_WIDTH: f32 = 40.;

// 2x PNG 保留 Retina 下的像素边界；单独灰图保持 HSL 去饱和后的亮度。
static AGENT_ICONS: LazyLock<[[Arc<Image>; 2]; 2]> = LazyLock::new(|| {
    let sources: [[&[u8]; 2]; 2] = [
        [
            include_bytes!("../../assets/agents/codex.png"),
            include_bytes!("../../assets/agents/codex-gray.png"),
        ],
        [
            include_bytes!("../../assets/agents/claude.png"),
            include_bytes!("../../assets/agents/claude-gray.png"),
        ],
    ];
    sources.map(|variants| {
        variants.map(|bytes| Arc::new(Image::from_bytes(ImageFormat::Png, bytes.to_vec())))
    })
});

pub fn agent_icon(kind: AgentKind, grayscale: bool) -> impl IntoElement + use<> {
    let index = match kind {
        AgentKind::Codex => 0,
        AgentKind::ClaudeCode => 1,
    };
    img(AGENT_ICONS[index][usize::from(grayscale)].clone())
        .size(px(AGENT_ICON_SIZE))
        .flex_shrink_0()
}

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
    selected: Option<SessionKey>,
    cx: &mut Context<Shell>,
) -> impl IntoElement + use<> {
    // 行高一致，用 uniform_list 只渲染可见行；行内容在布局阶段回到 Shell 取。
    let is_new_session = matches!(shell.stage, Stage::Empty);
    let sessions = uniform_list(
        "session-list",
        shell.rows.len(),
        cx.processor(move |shell, range: Range<usize>, window, cx| {
            let cursor = shell
                .sidebar_focus
                .is_focused(window)
                .then(|| shell.sidebar_cursor_row())
                .flatten();
            let start = range.start;
            shell.rows[range]
                .iter()
                .enumerate()
                .map(|(offset, row)| {
                    let row_div = div().h(px(ROW_HEIGHT));
                    match row {
                        SidebarRow::Header(label) => row_div
                            .flex()
                            .items_end()
                            .pb_1()
                            .child(section_label(label, cx)),
                        SidebarRow::Session { index, time } => {
                            let session = &shell.sessions[*index];
                            let is_selected = selected.as_ref().is_some_and(|key| session.is(key));
                            // 行间距用 padding：uniform_list 按首行测量行高。
                            row_div.pb_1().child(session_row(
                                session,
                                time.clone(),
                                shell.session_activity(session),
                                is_selected,
                                cursor == Some(start + offset),
                                window,
                                cx,
                            ))
                        }
                    }
                })
                .collect()
        }),
    )
    .track_scroll(shell.sidebar_scroll.clone())
    .track_focus(&shell.sidebar_focus.clone().tab_stop(!shell.rows.is_empty()))
    .on_key_down(
        cx.listener(|shell, event: &gpui::KeyDownEvent, window, cx| {
            if !shell.sidebar_focus.is_focused(window) || event.keystroke.modifiers.modified() {
                return;
            }
            match event.keystroke.key.as_str() {
                "up" => shell.navigate_sidebar(-1, cx),
                "down" => shell.navigate_sidebar(1, cx),
                "enter" => shell.open_sidebar_cursor(cx),
                _ => return,
            }
            cx.stop_propagation();
        }),
    );

    let status = if !shell.rows.is_empty() {
        None
    } else if shell.pending > 0 {
        Some("正在读取会话…".to_string())
    } else if !shell.sessions.is_empty() {
        Some("没有匹配的会话".to_string())
    } else if shell.machines.iter().any(|machine| machine.has_error()) {
        Some("读取失败，详情见「机器」页".to_string())
    } else {
        Some("没有可显示的会话".to_string())
    };

    // 机器入口带摘要：失败不能只靠用户主动点进去发现。
    let failed = shell
        .machines
        .iter()
        .filter(|machine| machine.has_error())
        .count();
    let machines_tooltip = if shell.machines.iter().any(|machine| machine.connecting) {
        "机器管理 · 连接中…".to_string()
    } else if failed > 0 {
        format!("机器管理 · {failed} 台失败")
    } else {
        "机器管理".to_string()
    };
    let can_load_more = !shell.load_more_targets().is_empty();
    let connecting = shell.machines.iter().any(|machine| machine.connecting);

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
                    h_flex().px_2().pb_1().items_center().child(
                        h_flex()
                            .gap_2()
                            .items_center()
                            .child(img(BRAND_ICON.clone()).size(px(24.)).flex_shrink_0())
                            .child(div().text_sm().font_semibold().child("AgentDeck")),
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
                                .icon(Icon::empty().path(crate::PLUS_ICON))
                                .label("新建会话")
                                .on_click(cx.listener(|shell, _, _, cx| shell.show_empty(cx))),
                        )
                        .child(
                            h_flex()
                                .gap_1()
                                .child(Input::new(&shell.search).small().cleanable(true).flex_1())
                                .child(
                                    Button::new("refresh-sessions")
                                        .ghost()
                                        .small()
                                        .icon(Icon::empty().path(crate::REFRESH_ICON))
                                        .disabled(!shell.can_refresh_sessions())
                                        .tooltip(if shell.can_refresh_sessions() {
                                            "重新读取最新会话列表"
                                        } else {
                                            "正在刷新会话列表…"
                                        })
                                        .on_click(cx.listener(|shell, _, _, cx| {
                                            shell.refresh_sessions(cx)
                                        })),
                                ),
                        ),
                )
                .child(
                    v_flex()
                        .flex_1()
                        .gap_1()
                        .overflow_hidden()
                        .children(status.map(|text| {
                            div()
                                .px_2()
                                .text_sm()
                                .text_color(cx.theme().muted_foreground)
                                .child(text)
                        }))
                        .child(
                            sessions
                                .flex_1()
                                // 同 transcript：flex item 需要 min_h(0) 才会真正滚动。
                                .min_h(px(0.)),
                        )
                        .when(can_load_more, |section| {
                            section.child(
                                Button::new("load-more")
                                    .ghost()
                                    .small()
                                    .w_full()
                                    .label("加载更多")
                                    .on_click(cx.listener(|shell, _, _, cx| shell.load_more(cx))),
                            )
                        }),
                ),
        )
        .children(update_button(shell, cx))
        .child(
            // 底部页面入口：一排图标按钮，后续设置、信息页在此并列。
            h_flex()
                .flex_shrink_0()
                .mx_3()
                .gap_1()
                .pt_3()
                .border_t_1()
                .border_color(cx.theme().sidebar_border)
                .child(
                    // 带文字和机器摘要的整行入口：失败时摘要变红，不必悬停才知道。
                    Button::new("show-machines")
                        .ghost()
                        .small()
                        .w_full()
                        .justify_start()
                        .selected(matches!(shell.stage, Stage::Machines))
                        .icon(Icon::empty().path(crate::SERVER_ICON))
                        .label("机器")
                        .child(div().flex_1())
                        .child(
                            // 健康度圆点：绿 = 全部连上，灰 = 连接中，红 = 有失败。
                            div().size(px(6.)).rounded_full().bg(if failed > 0 {
                                cx.theme().danger
                            } else if connecting {
                                cx.theme().muted_foreground
                            } else {
                                cx.theme().success
                            }),
                        )
                        .child(
                            div()
                                .text_xs()
                                .text_color(if failed > 0 {
                                    cx.theme().danger
                                } else {
                                    cx.theme().muted_foreground
                                })
                                .child(if failed > 0 {
                                    format!("{failed} 台失败")
                                } else {
                                    format!("{} 台", shell.machines.len())
                                }),
                        )
                        .tooltip(machines_tooltip)
                        .on_click(
                            cx.listener(|shell, _, window, cx| shell.show_machines(window, cx)),
                        ),
                ),
        )
}

/// 有新版本时机器入口上方多一行；本地构建和已是最新时不占位。
fn update_button(shell: &Shell, cx: &mut Context<Shell>) -> Option<impl IntoElement + use<>> {
    use crate::update::Status::*;
    let (label, tooltip) = match &shell.update {
        Idle => return None,
        Available(version) => (
            format!("更新到 v{version}"),
            "下载并安装，完成后再重启".into(),
        ),
        Installing(version) => (format!("正在下载 v{version}…"), String::new()),
        Ready(version) => (
            format!("重启以更新到 v{version}"),
            "有会话在工作时会等它们空闲再重启".into(),
        ),
        Waiting(_) => ("等会话空闲后重启…".into(), "再点一次立即重启".into()),
        Failed(_, error) => ("更新失败，点击重试".into(), error.clone()),
    };
    let failed = matches!(shell.update, Failed(..));
    let button = Button::new("update-app")
        .small()
        .w_full()
        .justify_start()
        .icon(Icon::empty().path(crate::REFRESH_ICON))
        .label(label)
        .loading(matches!(shell.update, Installing(_)))
        .on_click(cx.listener(|shell, _, _, cx| shell.click_app_update(cx)));
    let button = if failed {
        button.danger()
    } else {
        button.primary()
    };
    Some(
        div()
            .flex_shrink_0()
            .mx_3()
            .pt_3()
            .child(if tooltip.is_empty() {
                button
            } else {
                button.tooltip(tooltip)
            }),
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
        .font_semibold()
        .text_color(cx.theme().muted_foreground)
        .child(text.to_string())
}

fn session_row(
    session: &Session,
    time: SharedString,
    activity: Option<Activity>,
    selected: bool,
    keyboard_cursor: bool,
    window: &Window,
    cx: &mut Context<Shell>,
) -> impl IntoElement + use<> {
    let item = &session.item;
    let machine = machine_label(&session.host);
    // 不同 agent 可以使用相同 threadId，按钮交互状态必须按来源隔离。
    let id: SharedString = format!(
        "{machine}-{}-{}",
        item.agent_kind.as_str(),
        item.thread_id.0
    )
    .into();
    let payload = session.clone();
    let title: SharedString = session_title(item).into();
    let folder: SharedString = project_name(item).into();
    let path: SharedString = format!("{machine} · {}", item.cwd.display()).into();
    let host_badge = session.host.clone();
    let time_width = if time.len() > 5 { 72. } else { TIME_WIDTH };
    // Button 的内部 label 容器不会收缩，扣除 padding、边框、图标、时间列与两个 gap_2；
    // 远端行再扣主机标签和它的 gap_2。
    let mut title_width = px(WIDTH - 3. - AGENT_ICON_SIZE - time_width) - window.rem_size() * 4.5;
    if host_badge.is_some() {
        title_width -= px(HOST_WIDTH) + window.rem_size() * 0.5;
    }

    let mut button = Button::new(id)
        .group("session-row")
        .ghost()
        .selected(selected)
        .tab_stop(false)
        .when(keyboard_cursor, |button| {
            button.border_color(cx.theme().ring)
        })
        .w_full()
        .justify_start()
        .child(
            div()
                .relative()
                .size(px(AGENT_ICON_SIZE))
                .flex_shrink_0()
                .child(agent_icon(item.agent_kind, true))
                .child(
                    div()
                        .absolute()
                        .inset_0()
                        // 选中行常亮彩色图标，与只有底色的悬停态拉开差别。
                        .opacity(if keyboard_cursor || selected { 1. } else { 0. })
                        .group_hover("session-row", |style| style.opacity(1.))
                        .child(agent_icon(item.agent_kind, false)),
                ),
        )
        .child(
            div()
                .w(title_width)
                .when(selected, |title| title.font_medium())
                // nowrap 的文字缓存不随截断宽度变化；单行 clamp 保留按宽度重新测量。
                .whitespace_normal()
                .line_clamp(1)
                .text_ellipsis()
                .child(title.clone()),
        )
        .when_some(host_badge, |button, host| {
            button.child(
                div()
                    .w(px(HOST_WIDTH))
                    .flex_shrink_0()
                    .whitespace_normal()
                    .line_clamp(1)
                    .text_ellipsis()
                    .text_right()
                    .text_xs()
                    .text_color(cx.theme().muted_foreground)
                    .child(host),
            )
        })
        .child({
            // 工作中的会话用状态替换时间，切走后也能看出哪个还在跑。
            let (text, color) = match activity {
                Some(Activity::Working) => ("工作中".into(), cx.theme().success),
                Some(Activity::AwaitingUser) => ("待确认".into(), cx.theme().warning),
                None => (time, cx.theme().muted_foreground),
            };
            div()
                .w(px(time_width))
                .flex_shrink_0()
                .whitespace_nowrap()
                .text_right()
                .text_xs()
                .text_color(color)
                .child(text)
        })
        .on_click(cx.listener(move |shell, _, window, cx| {
            shell.sidebar_focus.focus(window);
            shell.open_session(payload.clone(), cx);
        }));

    button.interactivity().tooltip(move |window, cx| {
        let (title, folder, path) = (title.clone(), folder.clone(), path.clone());
        Tooltip::element(move |window, cx| {
            let width = px(320.);
            v_flex()
                .w(width)
                .gap_3()
                .whitespace_normal()
                .child(tooltip_title(title.clone(), width, window, cx))
                .child(
                    v_flex()
                        .gap_1()
                        .child(div().line_clamp(1).text_ellipsis().child(folder.clone()))
                        .child(
                            div()
                                .text_xs()
                                .text_color(cx.theme().muted_foreground)
                                .child(path.clone()),
                        ),
                )
        })
        .p_3()
        .rounded(px(12.))
        .build(window, cx)
    });
    button
}

fn tooltip_title(title: SharedString, width: Pixels, window: &Window, cx: &App) -> gpui::Div {
    let mut style = window.text_style();
    style.font_family = cx.theme().font_family.clone();
    style.font_weight = FontWeight::SEMIBOLD;
    let third_line_start = window
        .text_system()
        .shape_text(
            title.clone(),
            window.rem_size() * 0.875,
            &[style.to_run(title.len())],
            Some(width),
            None,
        )
        .ok()
        .and_then(|lines| {
            let line = lines.first()?;
            (line.wrap_boundaries().len() > 2).then(|| {
                let boundary = line.wrap_boundaries()[1];
                line.runs()[boundary.run_ix].glyphs[boundary.glyph_ix].index
            })
        });
    v_flex().w(width).font_semibold().map(|this| {
        if let Some(start) = third_line_start {
            // GPUI 多行省略可能把后缀裁掉；按实际换行点保留前两行，最后一行单独省略。
            this.child(title[..start].trim_end().to_owned()).child(
                div()
                    .line_clamp(1)
                    .text_ellipsis()
                    .child(title[start..].to_owned()),
            )
        } else {
            this.child(title)
        }
    })
}
