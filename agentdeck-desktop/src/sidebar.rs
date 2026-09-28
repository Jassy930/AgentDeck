//! 全高左侧栏：品牌行、新建与搜索、按日期分组的会话列表、按机器分组的 Agent 状态。
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
    ActiveTheme, InteractiveElementExt, Selectable, Sizable, StyledExt,
    button::{Button, ButtonVariants},
    h_flex,
    input::Input,
    tooltip::Tooltip,
    v_flex,
};

use crate::shell::{
    AgentHistory, Host, Machine, Session, SessionKey, Shell, SidebarRow, agent_label,
    machine_label, project_name, session_title,
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
    let is_new_session = selected.is_none();
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
    } else if shell.machines.iter().any(|machine| machine.error.is_some()) {
        Some("连接失败，详情见下方机器列表".to_string())
    } else {
        Some("没有可显示的会话".to_string())
    };

    let machines: Vec<_> = shell
        .machines
        .iter()
        .map(|machine| machine_section(machine, shell.agent_filter.as_ref(), cx))
        .collect();
    let can_load_more = !shell.load_more_targets().is_empty();
    let brand_hint = match shell.machines.len() {
        0 | 1 => "本机".to_string(),
        count => format!("{count} 台机器"),
    };

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
                                .text_color(cx.theme().muted_foreground)
                                .child(brand_hint),
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
                        .child(Input::new(&shell.search).small().cleanable(true)),
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
        .child(
            v_flex()
                .flex_shrink_0()
                .mx_3()
                .gap_1()
                .pt_3()
                .border_t_1()
                .border_color(cx.theme().sidebar_border)
                .child(
                    v_flex()
                        .id("machine-list")
                        .max_h(px(240.))
                        .overflow_y_scroll()
                        .gap_1()
                        .children(machines),
                )
                .child(remote_form(shell, cx)),
        )
}

/// 一台机器：标题行（名称、状态、重试 / 断开）+ 该机器上的 agent 行。
fn machine_section(
    machine: &Machine,
    filter: Option<&(Host, AgentKind)>,
    cx: &mut Context<Shell>,
) -> impl IntoElement + use<> {
    let id = machine.id;
    let label = machine_label(&machine.host);
    let status = if machine.connecting {
        Some("连接中…")
    } else if machine.error.is_some() {
        Some("连接失败")
    } else {
        None
    };
    let error: Option<SharedString> = machine.error.clone().map(Into::into);

    let header = h_flex()
        .id(SharedString::from(format!("machine-{label}")))
        .h_6()
        .px_2()
        .gap_2()
        .items_center()
        .text_xs()
        .text_color(cx.theme().muted_foreground)
        .child(
            div()
                .flex_1()
                .min_w(px(0.))
                .text_ellipsis()
                .child(label.clone()),
        )
        .children(status)
        .when_some(error, |header, error| {
            header.tooltip(move |window, cx| {
                let error = error.clone();
                Tooltip::element(move |_, _| {
                    div()
                        .w(px(320.))
                        .whitespace_normal()
                        .text_xs()
                        .child(error.clone())
                })
                .p_3()
                .rounded(px(12.))
                .build(window, cx)
            })
        })
        .when(machine.error.is_some(), |header| {
            header.child(
                Button::new(SharedString::from(format!("retry-machine-{label}")))
                    .ghost()
                    .xsmall()
                    .label("重试")
                    .on_click(cx.listener(move |shell, _, _, cx| shell.retry_machine(id, cx))),
            )
        })
        .when(machine.host.is_some(), |header| {
            header.child(
                Button::new(SharedString::from(format!("remove-machine-{label}")))
                    .ghost()
                    .xsmall()
                    .label("断开")
                    .on_click(cx.listener(move |shell, _, _, cx| shell.remove_machine(id, cx))),
            )
        });

    let agents: Vec<_> = machine
        .agents
        .iter()
        .map(|agent| {
            let filtered =
                filter.is_some_and(|(host, kind)| *host == machine.host && *kind == agent.kind);
            agent_row(machine, agent, filtered, cx)
        })
        .collect();
    v_flex()
        .flex_shrink_0()
        .gap_1()
        .child(header)
        .children(agents)
}

/// 连接远端：折叠时是一个按钮，展开后是 ssh 主机输入框（回车或点"连接"）。
fn remote_form(shell: &Shell, cx: &mut Context<Shell>) -> impl IntoElement + use<> {
    let toggle = Button::new("toggle-remote-form")
        .ghost()
        .xsmall()
        .w_full()
        .justify_start()
        .label(if shell.remote_form {
            "取消"
        } else {
            "+ 连接远端机器"
        })
        .on_click(cx.listener(|shell, _, window, cx| shell.toggle_remote_form(window, cx)));
    v_flex()
        .gap_1()
        .when(shell.remote_form, |form| {
            form.child(
                h_flex()
                    .gap_1()
                    .child(
                        div()
                            .flex_1()
                            .child(Input::new(&shell.remote_input).xsmall()),
                    )
                    .child(
                        Button::new("connect-remote")
                            .xsmall()
                            .label("连接")
                            .on_click(cx.listener(|shell, _, _, cx| shell.connect_remote(cx))),
                    ),
            )
        })
        .when_some(shell.remote_error.clone(), |form, error| {
            form.child(
                div()
                    .px_2()
                    .text_xs()
                    .whitespace_normal()
                    .text_color(cx.theme().danger)
                    .child(error),
            )
        })
        .child(toggle)
}

/// agent 状态一行：图标、名称、计数；点击只看该机器上该 agent 的会话。
/// 完整状态、兼容性警告和错误详情放在悬停提示里，读取失败时行尾给出重试。
fn agent_row(
    machine: &Machine,
    agent: &AgentHistory,
    filtered: bool,
    cx: &mut Context<Shell>,
) -> impl IntoElement + use<> {
    let kind = agent.kind;
    let (id, host) = (machine.id, machine.host.clone());
    let key = format!("{}-{}", machine_label(&host), kind.as_str());
    let mut details: Vec<SharedString> = vec![agent.status().into()];
    details.extend(agent.list_hint().map(SharedString::from));
    details.extend(
        agent
            .warnings
            .iter()
            .map(|warning| format!("兼容性警告：{}", warning.message).into()),
    );
    details.extend(agent.error().map(|error| error.to_string().into()));
    let failed = agent.error().is_some();

    // 自绘行而不是 Button：Button 的内部容器不随宽度伸展，计数无法右对齐。
    let row = h_flex()
        .id(SharedString::from(format!("agent-{key}")))
        .flex_1()
        .min_w(px(0.))
        .h_7()
        .px_2()
        .gap_2()
        .items_center()
        .rounded_md()
        .border_1()
        .border_color(if filtered {
            cx.theme().ring
        } else {
            gpui::transparent_black()
        })
        .text_sm()
        .cursor_pointer()
        .when(filtered, |row| row.bg(cx.theme().accent))
        .hover(|style| style.bg(cx.theme().accent))
        .child(agent_icon(kind, false))
        .child(div().flex_1().child(agent_label(kind)))
        .when(!agent.warnings.is_empty(), |row| {
            row.child(div().text_color(crate::theme_tokens::WARN).child("⚠"))
        })
        .child(
            div()
                .text_color(cx.theme().muted_foreground)
                .child(agent.count_label()),
        )
        .on_click(
            cx.listener(move |shell, _, _, cx| shell.toggle_agent_filter(host.clone(), kind, cx)),
        )
        .tooltip(move |window, cx| {
            let details = details.clone();
            Tooltip::element(move |_, cx| {
                v_flex()
                    .w(px(320.))
                    .gap_1()
                    .whitespace_normal()
                    .text_xs()
                    .children(details.iter().enumerate().map(|(ix, line)| {
                        div()
                            .when(ix > 0, |line| line.text_color(cx.theme().muted_foreground))
                            .child(line.clone())
                    }))
            })
            .p_3()
            .rounded(px(12.))
            .build(window, cx)
        });

    h_flex()
        .gap_1()
        .items_center()
        .child(row)
        .when(failed, |row| {
            row.child(
                Button::new(SharedString::from(format!("retry-{key}")))
                    .ghost()
                    .xsmall()
                    .label("重试")
                    .on_click(cx.listener(move |shell, _, _, cx| shell.retry_agent(id, kind, cx))),
            )
        })
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
        .text_color(cx.theme().muted_foreground)
        .child(text.to_string())
}

/// 会话行：id 用机器 + threadId，点击后读取该会话的真实记录；远端会话带主机标签。
fn session_row(
    session: &Session,
    time: SharedString,
    selected: bool,
    keyboard_cursor: bool,
    window: &Window,
    cx: &mut Context<Shell>,
) -> impl IntoElement + use<> {
    let item = &session.item;
    let machine = machine_label(&session.host);
    let id: SharedString = format!("{machine}-{}", item.thread_id.0).into();
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
                        .opacity(if keyboard_cursor { 1. } else { 0. })
                        .group_hover("session-row", |style| style.opacity(1.))
                        .child(agent_icon(item.agent_kind, false)),
                ),
        )
        .child(
            div()
                .w(title_width)
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
        .child(
            div()
                .w(px(time_width))
                .flex_shrink_0()
                .text_right()
                .text_xs()
                .text_color(cx.theme().muted_foreground)
                .child(time),
        )
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
