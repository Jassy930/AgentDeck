//! 全高左侧栏：品牌行、新建与搜索、按日期分组的会话列表、本机 Agent 状态。
//!
//! 会话条目来自 daemon 的跨 agent 历史列表，点击即读取该会话记录。

use std::ops::Range;
use std::sync::{Arc, LazyLock};

use agentdeck_protocol::{AgentKind, HistoryListItem};
use gpui::{
    App, Bounds, Context, FontWeight, Hsla, Image, ImageFormat, IntoElement, ParentElement, Pixels,
    SharedString, Window, canvas, div, fill, img, point, prelude::*, px, rgb, size, uniform_list,
};
use gpui_component::{
    ActiveTheme, InteractiveElementExt, Selectable, Sizable, StyledExt,
    button::{Button, ButtonVariants},
    h_flex,
    input::Input,
    tooltip::Tooltip,
    v_flex,
};

use crate::shell::{AgentHistory, Shell, SidebarRow, agent_label, project_name, session_title};

/// 侧栏宽度，与 Codex Desktop 的全高侧栏一致。
const WIDTH: f32 = 248.;
const AGENT_ICON_SIZE: f32 = 16.;
/// 会话行与分组标题共用的行高：uniform_list 按首行测量，两者必须一致。
const ROW_HEIGHT: f32 = 36.;
/// 会话行尾时间列宽度，容纳 "12/31" 或 "23:59"。
const TIME_WIDTH: f32 = 36.;

const CODEX_PIXELS: [&[u8; 16]; 16] = [
    b".....bbb........",
    b"...bbbbbbbb.....",
    b"..bbbbbbbbbbb...",
    b".bbbbbbbbbbbbb..",
    b".bbbddddddddbb..",
    b".bbbdfddddddbb..",
    b".bbbddfdddddbb..",
    b".bbbdfddfffdbb..",
    b"..bbddddddddbb..",
    b"...bbbbbbbbbb...",
    b"....bbbbbbb.....",
    b"...bbbbbbbbb....",
    b"..bbbfbbffbbb...",
    b"..bb.bbbbbb.bb..",
    b".....bb.bb......",
    b".....bb.bb......",
];

const CLAUDE_PIXELS: [&[u8; 16]; 16] = [
    b"................",
    b"................",
    b"................",
    b"...cccccccccc...",
    b"...cccccccccc...",
    b"...cccccccccc...",
    b".cccc.cccc.cccc.",
    b".cccc.cccc.cccc.",
    b".cccccccccccccc.",
    b"...cccccccccc...",
    b"...cccccccccc...",
    b"...cc.c..c.cc...",
    b"...cc.c..c.cc...",
    b"...cc.c..c.cc...",
    b"................",
    b"................",
];

pub fn agent_icon(kind: AgentKind) -> impl IntoElement + use<> {
    let pixels = match kind {
        AgentKind::Codex => &CODEX_PIXELS,
        AgentKind::ClaudeCode => &CLAUDE_PIXELS,
    };
    canvas(
        |_, _, _| (),
        move |bounds, _, window, _| {
            for (y, row) in pixels.iter().enumerate() {
                for (x, pixel) in row.iter().enumerate() {
                    let color = match pixel {
                        b'b' => rgb(0x7495ff),
                        b'd' => rgb(0x25386f),
                        b'f' => rgb(0xa7f3f0),
                        b'c' => rgb(0xc87555),
                        _ => continue,
                    };
                    window.paint_quad(fill(
                        Bounds::new(
                            bounds.origin + point(px(x as f32), px(y as f32)),
                            size(px(1.), px(1.)),
                        ),
                        Hsla::from(color),
                    ));
                }
            }
        },
    )
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
    selected: Option<SharedString>,
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
                            let item = &shell.sessions[*index];
                            let is_selected = selected.as_ref().map(SharedString::as_ref)
                                == Some(item.thread_id.0.as_str());
                            // 行间距用 padding：uniform_list 按首行测量行高。
                            row_div.pb_1().child(session_row(
                                item,
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
        .map(|agent| agent_row(agent, shell.agent_filter == Some(agent.kind), cx))
        .collect();
    let can_load_more = !shell.load_more_kinds().is_empty();

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
                .children(agents),
        )
}

/// 本机 agent 状态一行：图标、名称、计数；点击只看该 agent 的会话。
/// 完整状态、兼容性警告和错误详情放在悬停提示里，读取失败时行尾给出重试。
fn agent_row(
    agent: &AgentHistory,
    filtered: bool,
    cx: &mut Context<Shell>,
) -> impl IntoElement + use<> {
    let kind = agent.kind;
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
        .id(SharedString::from(format!("agent-{}", kind.as_str())))
        .flex_1()
        .min_w(px(0.))
        .h_7()
        .px_2()
        .gap_2()
        .items_center()
        .rounded_md()
        .text_sm()
        .cursor_pointer()
        .when(filtered, |row| row.bg(cx.theme().accent))
        .hover(|style| style.bg(cx.theme().accent))
        .child(agent_icon(kind))
        .child(div().flex_1().child(agent_label(kind)))
        .when(!agent.warnings.is_empty(), |row| {
            row.child(div().text_color(crate::theme_tokens::WARN).child("⚠"))
        })
        .child(
            div()
                .text_color(cx.theme().muted_foreground)
                .child(agent.count_label()),
        )
        .on_click(cx.listener(move |shell, _, _, cx| shell.toggle_agent_filter(kind, cx)))
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
                Button::new(SharedString::from(format!("retry-{}", kind.as_str())))
                    .ghost()
                    .xsmall()
                    .label("重试")
                    .on_click(cx.listener(move |shell, _, _, cx| shell.retry_agent(kind, cx))),
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

/// 会话行：id 用 threadId，点击后读取该会话的真实记录。
fn session_row(
    item: &HistoryListItem,
    time: SharedString,
    selected: bool,
    keyboard_cursor: bool,
    window: &Window,
    cx: &mut Context<Shell>,
) -> impl IntoElement + use<> {
    let id: SharedString = item.thread_id.0.clone().into();
    let payload = item.clone();
    let title: SharedString = session_title(item).into();
    let folder: SharedString = project_name(item).into();
    let path: SharedString = item.cwd.display().to_string().into();
    // Button 的内部 label 容器不会收缩，扣除 padding、边框、图标、时间列与两个 gap_2。
    let title_width = px(WIDTH - 3. - AGENT_ICON_SIZE - TIME_WIDTH) - window.rem_size() * 4.5;

    let mut button = Button::new(id)
        .ghost()
        .selected(selected)
        .tab_stop(false)
        .when(keyboard_cursor, |button| {
            button.border_color(cx.theme().ring)
        })
        .w_full()
        .justify_start()
        .child(agent_icon(item.agent_kind))
        .child(
            div()
                .w(title_width)
                // nowrap 的文字缓存不随截断宽度变化；单行 clamp 保留按宽度重新测量。
                .whitespace_normal()
                .line_clamp(1)
                .text_ellipsis()
                .child(title.clone()),
        )
        .child(
            div()
                .w(px(TIME_WIDTH))
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
