//! 会话记录渲染：把中立 `AgentItem` 转成只读块。
//!
//! 对话消息直接展开；命令、思考、工具、变更等过程块默认折叠成一行摘要，点击展开。
//! 连续两个以上的过程块再合成一组，默认只显示一行组摘要。
//! 助手、思考与过程块正文按 Markdown 渲染（代码走围栏高亮）；用户消息仍是纯文本。

use std::collections::HashSet;
use std::rc::Rc;

mod markdown_fallback;

use agentdeck_protocol::{
    AgentItem, AgentKind, CONTEXT_KIND_KEY, HistoryTurn, PlanStepStatus, ShellStatus,
};
use gpui::{
    ClipboardItem, ElementId, IntoElement, ListState, ParentElement, SharedString, Window, div,
    list, prelude::*, px, relative,
};
use gpui_component::{
    ActiveTheme, Icon, Sizable, StyledExt,
    button::Button,
    button::ButtonVariants,
    h_flex,
    scroll::{Scrollbar, ScrollbarShow},
    text::TextView,
    v_flex,
};

/// 单条内容的展示上限；历史里的工具结果可能是几十 KB 的整页文本。
const BODY_LIMIT: usize = 2_000;
/// 折叠摘要的字符上限。
const SUMMARY_LIMIT: usize = 120;
/// 只折叠明确带 base64 标记的 data URI，普通文本不能靠字符集判断。
const BINARY_MIN_LEN: usize = 256;
const EDGE_FADE_HEIGHT: f32 = 28.;

#[derive(Debug, Clone, PartialEq)]
pub struct Block {
    pub label: &'static str,
    /// `Some` 表示过程块：折叠时只显示这一行；`None` 表示对话消息，正文总是显示。
    pub summary: Option<SharedString>,
    pub status: Option<SharedString>,
    /// 过程块展开后的正文；为空表示没有可展开的内容。
    pub body: SharedString,
    /// 正文按 Markdown 渲染；用户消息里常夹带 `<in-app-browser-context>` 这类注入标签，
    /// TextView 会静默丢弃未识别的内联 HTML，所以用户消息保持纯文本。
    pub markdown: bool,
    unsupported: bool,
    continued_assistant: bool,
    /// 命令失败等需要醒目提示的状态。
    pub failed: bool,
    /// 所在连续过程块组的 `(起始下标, 块数)`；连续两个以上过程块才成组。
    pub group: Option<(usize, usize)>,
    /// 只存于组首块，避免滚动时重新统计整个组。
    group_summary: Option<(SharedString, usize)>,
}

impl Block {
    fn message(label: &'static str, body: &str, markdown: bool) -> Self {
        let body = truncate(body.trim());
        let body = if markdown {
            markdown_fallback::images_as_links(&body)
        } else {
            body
        };
        Self {
            label,
            summary: None,
            status: None,
            body: body.into(),
            markdown,
            unsupported: false,
            continued_assistant: false,
            failed: false,
            group: None,
            group_summary: None,
        }
    }

    fn detail(label: &'static str, summary: String, body: String) -> Self {
        Self {
            label,
            summary: Some(one_line(&summary).into()),
            status: None,
            body: markdown_fallback::images_as_links(body.trim()).into(),
            markdown: true,
            unsupported: false,
            continued_assistant: false,
            failed: false,
            group: None,
            group_summary: None,
        }
    }

    fn is_empty(&self) -> bool {
        self.body.is_empty() && self.summary.as_ref().is_none_or(|s| s.is_empty())
    }
}

/// 过程块行尾状态：“运行中 · 30.0s”“失败 · 退出码 1 · 2.0s”。
fn status_tail(state: Option<String>, duration_ms: Option<u64>) -> Option<SharedString> {
    let tail: Vec<String> = state
        .into_iter()
        .chain(duration_ms.map(|ms| format!("{:.1}s", ms as f64 / 1000.)))
        .collect();
    (!tail.is_empty()).then(|| tail.join(" · ").into())
}

pub fn describe(item: &AgentItem) -> Block {
    match item {
        AgentItem::UserMessage { text, meta } => {
            match meta
                .vendor_extensions
                .get(CONTEXT_KIND_KEY)
                .and_then(|kind| kind.as_str())
            {
                // CLI 注入的上下文、命令输出与通知不是用户输入，按过程块默认折叠。
                Some(kind) => {
                    let label = match kind {
                        "output" | "error" => "命令输出",
                        "notification" => "通知",
                        _ => "上下文",
                    };
                    let summary = text.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
                    Block {
                        status: (kind == "error").then(|| "错误".into()),
                        failed: kind == "error",
                        ..Block::detail(
                            label,
                            summary.to_string(),
                            fence("", &truncate(text.trim())),
                        )
                    }
                }
                None => Block::message("你", text, false),
            }
        }
        AgentItem::AssistantMessage { text, .. } => Block::message("助手", text, true),
        AgentItem::Raw { raw_kind, .. } => Block {
            unsupported: true,
            ..Block::message(
                "暂不支持的内容",
                &format!("类型：{raw_kind}\n当前 AgentDeck 无法展示此内容，请检查更新"),
                false,
            )
        },
        AgentItem::Reasoning { text, .. } => {
            let text = text.trim();
            let first = text
                .lines()
                .find(|line| !line.trim().is_empty())
                .unwrap_or("");
            let summary = first
                .trim()
                .trim_matches(|c| c == '*' || c == '#' || c == ' ');
            Block::detail("思考", summary.to_string(), truncate(text))
        }
        AgentItem::Shell {
            command,
            status,
            exit_code,
            duration_ms,
            ..
        } => {
            let summary = format!("$ {}", command.trim());
            let state = match status {
                ShellStatus::Running => Some("运行中".to_string()),
                ShellStatus::Completed => None,
                ShellStatus::Failed => Some(match exit_code {
                    Some(code) => format!("失败 · 退出码 {code}"),
                    None => "失败".to_string(),
                }),
                ShellStatus::Canceled => Some("已取消".to_string()),
            };
            let body = fence("sh", &truncate(command.trim()));
            Block {
                status: status_tail(state, *duration_ms),
                failed: matches!(status, ShellStatus::Failed),
                ..Block::detail("命令", summary, body)
            }
        }
        AgentItem::ToolCall {
            name,
            args,
            result,
            meta,
        } => {
            // Codex 与 CC 都把工具状态与耗时放在这两个扩展键里。
            let ext = &meta.vendor_extensions;
            let status = ext.get("status").and_then(|v| v.as_str()).unwrap_or("");
            let failed = status == "failed";
            let state = match status {
                "inProgress" => Some("运行中".to_string()),
                "failed" => Some("失败".to_string()),
                "declined" => Some("已拒绝".to_string()),
                _ => None,
            };
            let duration_ms = ext.get("durationMs").and_then(|v| v.as_u64());
            let summary = match arg_hint(args) {
                Some(hint) => format!("{name}  {hint}"),
                None => name.clone(),
            };
            let mut body = String::new();
            if !args.is_null() && args.as_object().is_none_or(|map| !map.is_empty()) {
                let args = serde_json::to_string_pretty(&scrub(args)).unwrap_or_default();
                body.push_str(&format!(
                    "**参数**\n\n{}\n\n",
                    fence("json", &truncate(&args))
                ));
            }
            if let Some(result) = result {
                let (lang, text) = match scrub(result) {
                    serde_json::Value::String(text) => ("", text),
                    other => (
                        "json",
                        serde_json::to_string_pretty(&other).unwrap_or_default(),
                    ),
                };
                if !text.trim().is_empty() {
                    body.push_str(&format!(
                        "**结果**\n\n{}",
                        fence(lang, &truncate(text.trim()))
                    ));
                }
            }
            Block {
                status: status_tail(state, duration_ms),
                failed,
                ..Block::detail("工具", summary, body)
            }
        }
        AgentItem::Diff { files, .. } => {
            let paths: Vec<String> = files
                .iter()
                .map(|file| file.path.display().to_string())
                .collect();
            let summary = format!("{} 个文件：{}", files.len(), paths.join("、"));
            let body = files
                .iter()
                .map(|file| {
                    let path = file.path.display();
                    match &file.patch {
                        Some(patch) if !patch.trim().is_empty() => {
                            format!("`{path}`\n\n{}", fence("diff", &truncate(patch.trim())))
                        }
                        _ => format!("`{path}`"),
                    }
                })
                .collect::<Vec<_>>()
                .join("\n\n");
            Block::detail("变更", summary, body)
        }
        AgentItem::Plan { steps, .. } => {
            let text = steps
                .iter()
                .map(|step| {
                    let mark = match step.status {
                        PlanStepStatus::Pending => "○",
                        PlanStepStatus::InProgress => "◐",
                        PlanStepStatus::Done => "●",
                        PlanStepStatus::Failed => "✕",
                    };
                    format!("{mark} {}", step.title)
                })
                .collect::<Vec<_>>()
                .join("\n");
            Block::message("计划", &text, false)
        }
        AgentItem::ImageReference {
            saved_path,
            original_path,
            ..
        } => {
            let path = saved_path
                .as_ref()
                .or(original_path.as_ref())
                .map(|path| path.display().to_string())
                .unwrap_or_default();
            let body = if path.is_empty() {
                String::new()
            } else {
                fence("", &truncate(&path))
            };
            Block::detail("图片", path, body)
        }
    }
}

/// 工具参数里最能代表这次调用的字段，放进折叠摘要。
fn arg_hint(args: &serde_json::Value) -> Option<String> {
    const KEYS: [&str; 9] = [
        "command",
        "cmd",
        "file_path",
        "path",
        "pattern",
        "query",
        "url",
        "description",
        "prompt",
    ];
    let map = args.as_object()?;
    KEYS.iter()
        .find_map(|key| map.get(*key)?.as_str())
        .map(one_line)
}

/// 把 JSON 里明确标记的 base64 data URI 替换成占位说明，其余原样保留。
fn scrub(value: &serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match value {
        Value::String(text) if is_binary(text) => {
            Value::String(format!("[二进制内容 {:.1} KB]", text.len() as f64 / 1024.))
        }
        Value::Array(items) => Value::Array(items.iter().map(scrub).collect()),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, value)| (key.clone(), scrub(value)))
                .collect(),
        ),
        other => other.clone(),
    }
}

fn is_binary(text: &str) -> bool {
    let Some((_, data)) = text
        .strip_prefix("data:")
        .and_then(|rest| rest.split_once(";base64,"))
    else {
        return false;
    };
    data.len() >= BINARY_MIN_LEN
        && data
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+/=_-\n\r".contains(&b))
}

/// 用比正文里最长反引号串更长的围栏包住代码，避免正文自带 ``` 提前闭合。
pub(crate) fn fence(lang: &str, code: &str) -> String {
    let mut longest = 0;
    let mut run = 0;
    for c in code.chars() {
        run = if c == '`' { run + 1 } else { 0 };
        longest = longest.max(run);
    }
    let ticks = "`".repeat(longest.max(2) + 1);
    format!("{ticks}{lang}\n{code}\n{ticks}")
}

fn one_line(text: &str) -> String {
    let line = text.lines().next().unwrap_or("").trim();
    let more = text.trim().contains('\n');
    if line.chars().count() > SUMMARY_LIMIT {
        let head: String = line.chars().take(SUMMARY_LIMIT).collect();
        format!("{head}…")
    } else if more {
        format!("{line} …")
    } else {
        line.to_string()
    }
}

pub(crate) fn truncate(body: &str) -> String {
    if body.chars().count() <= BODY_LIMIT {
        return body.to_string();
    }
    let head: String = body.chars().take(BODY_LIMIT).collect();
    format!("{head}…（已截断）")
}

pub fn prepare(turns: Vec<HistoryTurn>) -> Vec<Block> {
    let mut blocks = Vec::new();
    for turn in turns {
        let mut previous_assistant = false;
        for item in turn.items {
            let mut block = describe(&item);
            if block.is_empty() {
                continue;
            }
            if block.summary.is_none() {
                block.continued_assistant = block.markdown && previous_assistant;
                previous_assistant = block.markdown;
            }
            blocks.push(block);
        }
    }
    let mut start = 0;
    while start < blocks.len() {
        let len = blocks[start..]
            .iter()
            .take_while(|block| block.summary.is_some())
            .count();
        if len >= 2 {
            let (summary, failed) = group_summary(&blocks[start..start + len]);
            blocks[start].group_summary = Some((summary.into(), failed));
            for block in &mut blocks[start..start + len] {
                block.group = Some((start, len));
            }
        }
        start += len.max(1);
    }
    blocks
}

/// 历史块后接 live 块：live 块单独 `prepare`，组下标整体平移，免得每个流式快照
/// 都把整段历史重算一遍。
pub fn append(history: &[Block], live: Vec<Block>) -> Vec<Block> {
    let offset = history.len();
    history
        .iter()
        .cloned()
        .chain(live.into_iter().map(|mut block| {
            block.group = block.group.map(|(start, len)| (start + offset, len));
            block
        }))
        .collect()
}

pub fn collapsed_indices(blocks: &[Block]) -> impl Iterator<Item = usize> + '_ {
    blocks.iter().enumerate().filter_map(|(ix, block)| {
        block
            .group
            .is_none_or(|(start, _)| start == ix)
            .then_some(ix)
    })
}

struct VisibleRows {
    /// 列表位置会随折叠变化，内容和展开状态始终使用原始块下标。
    indices: Vec<usize>,
    expanded_groups: HashSet<usize>,
    /// 构建 `indices` 时的块；live 更新换成新的一份后需要重算。
    source: Rc<[Block]>,
}

impl VisibleRows {
    fn new(blocks: &Rc<[Block]>) -> Self {
        Self {
            indices: collapsed_indices(blocks).collect(),
            expanded_groups: HashSet::new(),
            source: blocks.clone(),
        }
    }

    /// 块内容变了（live 追加或流式快照）：保留已展开的组重算可见行。
    /// 返回 true 表示调用方要重置列表。
    fn sync(&mut self, blocks: &Rc<[Block]>) -> bool {
        if Rc::ptr_eq(&self.source, blocks) {
            return false;
        }
        self.source = blocks.clone();
        self.indices = blocks
            .iter()
            .enumerate()
            .filter_map(|(ix, block)| {
                block
                    .group
                    .is_none_or(|(start, _)| start == ix || self.expanded_groups.contains(&start))
                    .then_some(ix)
            })
            .collect();
        true
    }

    fn toggle_group(&mut self, row: usize, start: usize, len: usize, list: &ListState) {
        let (removed, inserted) = if self.expanded_groups.remove(&start) {
            (len, 1)
        } else {
            self.expanded_groups.insert(start);
            (1, len)
        };
        self.indices
            .splice(row..row + removed, start..start + inserted);
        // 首行也会改变高度；splice 同时保留替换区之后的滚动锚点。
        list.splice(row..row + removed, inserted);
    }
}

/// 组摘要：步数加按首次出现顺序的各类计数，如“5 步 · 命令 3 · 思考 2”；另返回失败数。
fn group_summary(blocks: &[Block]) -> (String, usize) {
    let mut counts: Vec<(&str, usize)> = Vec::new();
    for block in blocks {
        match counts.iter_mut().find(|(label, _)| *label == block.label) {
            Some((_, n)) => *n += 1,
            None => counts.push((block.label, 1)),
        }
    }
    let parts: Vec<String> = std::iter::once(format!("{} 步", blocks.len()))
        .chain(counts.iter().map(|(label, n)| format!("{label} {n}")))
        .collect();
    let failed = blocks.iter().filter(|block| block.failed).count();
    (parts.join(" · "), failed)
}

/// 折叠行：箭头、标签、截断摘要和可选状态；`failed` 标红状态，`failed_summary` 同时标红摘要。
#[allow(clippy::too_many_arguments)]
fn summary_row(
    id: ElementId,
    arrow: &'static str,
    label: &'static str,
    summary: SharedString,
    status: Option<SharedString>,
    failed: bool,
    failed_summary: bool,
    cx: &gpui::App,
) -> gpui::Stateful<gpui::Div> {
    let (muted, danger) = (cx.theme().muted_foreground, cx.theme().danger);
    let hover = cx.theme().secondary;
    let tag_bg = cx.theme().foreground.opacity(0.06);
    h_flex()
        .id(id)
        .gap_2()
        .min_w(px(0.))
        .mx(px(-8.))
        .px_2()
        .py_1()
        .rounded_md()
        .text_sm()
        .text_color(muted)
        .hover(move |style| style.bg(hover))
        .child(div().w(px(12.)).flex_shrink_0().flex().items_center().when(
            !arrow.is_empty(),
            |slot| {
                slot.child(Icon::empty().xsmall().path(if arrow == "▾" {
                    crate::CHEVRON_DOWN_ICON
                } else {
                    crate::CHEVRON_RIGHT_ICON
                }))
            },
        ))
        // 类别做成小标签，扫读时先看类别再看摘要。
        .child(
            div()
                .flex_shrink_0()
                .px_1p5()
                .rounded(px(5.))
                .bg(tag_bg)
                .text_xs()
                .font_semibold()
                .child(label),
        )
        .child(
            div()
                .flex_1()
                .min_w(px(0.))
                .truncate()
                .when(failed_summary, |text| text.text_color(danger))
                .child(summary),
        )
        .when_some(status, |header, status| {
            header.child(
                div()
                    .flex_shrink_0()
                    .when(failed, |text| text.text_color(danger))
                    .child(status),
            )
        })
}

pub(crate) fn markdown(
    id: ElementId,
    body: &SharedString,
    window: &mut Window,
    cx: &mut gpui::App,
) -> TextView {
    TextView::markdown(id, body.clone(), window, cx)
        .selectable(true)
        .code_block_actions(|code, _, _| {
            // TextView 缓存各代码块的 SharedString；同内容的不同块也要有独立按钮状态。
            let code = code.code();
            Button::new(ElementId::Integer(code.as_ptr() as u64))
                .ghost()
                .xsmall()
                .label("复制")
                .on_click(move |_, _, cx| {
                    cx.stop_propagation();
                    cx.write_to_clipboard(ClipboardItem::new_string(code.to_string()));
                })
        })
}

/// 只渲染可见区域附近的块：长会话有几百块，逐帧全量排版会拖慢滚动。
///
/// `read_id` 进入 Markdown 与展开状态的 key：TextView 按 id 缓存解析结果，换会话后
/// 同一下标若沿用旧 key，会先显示上个会话的内容再延迟 200ms 重新解析。
pub fn render(
    blocks: Rc<[Block]>,
    agent: AgentKind,
    state: ListState,
    read_id: u64,
    window: &mut Window,
    cx: &mut gpui::App,
) -> impl IntoElement {
    // 展开集合挂在列表外层：列表每帧都渲染，状态随会话存活，滚出可见区也不丢。
    let expanded = window.use_keyed_state(
        SharedString::from(format!("transcript-expanded-{read_id}")),
        cx,
        |_, _| HashSet::<usize>::new(),
    );
    let visible = window.use_keyed_state(
        SharedString::from(format!("transcript-groups-{read_id}")),
        cx,
        |_, _| VisibleRows::new(&blocks),
    );
    visible.update(cx, |rows, _| {
        let changed = rows.sync(&blocks);
        if !changed && state.item_count() != rows.indices.len() {
            // 读完历史时列表按历史块数重置过，这时已拼上了运行中的 live 轮次。
            state.reset(rows.indices.len());
        }
        if changed {
            // ponytail: 有新内容就跟到底部；用户往上翻看时也会被拉回，
            // 需要时改成"只在原本就停在底部时跟随"。
            state.reset(rows.indices.len());
            if let Some(last) = rows.indices.len().checked_sub(1) {
                state.scroll_to_reveal_item(last);
            }
        }
    });
    let list_state = state.clone();
    // 常驻显示：长会话需要随时看到当前位置，不跟随系统的自动隐藏。
    let scrollbar = Scrollbar::vertical(&state).scrollbar_show(ScrollbarShow::Always);
    let rows = list(state, move |row, window, cx| {
        let ix = visible.read(cx).indices[row];
        let block = &blocks[ix];
        let group_open = block
            .group
            .map(|(start, _)| visible.read(cx).expanded_groups.contains(&start));
        let md_id = ElementId::NamedInteger(format!("transcript-{read_id}").into(), ix as u64);
        let theme = cx.theme();
        let (muted, border) = (theme.muted_foreground, theme.border);

        let content = match &block.summary {
            None => {
                let body = if block.markdown {
                    markdown(md_id, &block.body, window, cx).into_any_element()
                } else {
                    block.body.clone().into_any_element()
                };
                // 用户消息靠右成气泡；助手消息以 agent 身份铺在底色上；不支持的内容用虚线框降级。
                let theme = cx.theme();
                let surface = theme.secondary;
                if block.label == "你" {
                    h_flex()
                        .w_full()
                        .justify_end()
                        .child(
                            div()
                                .max_w(relative(0.82))
                                .px_4()
                                .py_2p5()
                                .rounded(px(16.))
                                .rounded_tr(px(6.))
                                .bg(surface)
                                .border_1()
                                .border_color(border)
                                .text_sm()
                                .child(body),
                        )
                        .into_any_element()
                } else if block.markdown {
                    v_flex()
                        .gap_2()
                        .when(!block.continued_assistant, |message| {
                            message.child(
                                h_flex()
                                    .gap_2()
                                    .items_center()
                                    .child(crate::sidebar::agent_icon(agent, false))
                                    .child(
                                        div()
                                            .text_xs()
                                            .font_semibold()
                                            .text_color(muted)
                                            .child(crate::shell::agent_label(agent)),
                                    ),
                            )
                        })
                        .child(div().text_sm().child(body))
                        .into_any_element()
                } else {
                    v_flex()
                        .gap_2()
                        .when(block.unsupported, |message| {
                            message
                                .px_4()
                                .py_3()
                                .rounded(px(12.))
                                .border_1()
                                .border_dashed()
                                .border_color(border)
                                .text_color(muted)
                        })
                        .child(
                            h_flex()
                                .gap_2()
                                .items_center()
                                .when(block.unsupported, |header| {
                                    header.child(
                                        Icon::empty()
                                            .xsmall()
                                            .path(crate::ALERT_ICON)
                                            .text_color(theme.warning),
                                    )
                                })
                                .child(div().text_xs().font_semibold().child(block.label)),
                        )
                        .child(div().text_sm().child(body))
                        .into_any_element()
                }
            }
            Some(summary) => {
                let expandable = !block.body.is_empty();
                let open = expandable && expanded.read(cx).contains(&ix);
                let header = summary_row(
                    ElementId::NamedInteger("transcript-toggle".into(), ix as u64),
                    match (expandable, open) {
                        (false, _) => "",
                        (true, false) => "▸",
                        (true, true) => "▾",
                    },
                    block.label,
                    summary.clone(),
                    block.status.clone(),
                    block.failed,
                    block.failed,
                    cx,
                )
                .when(expandable, |header| {
                    let expanded = expanded.clone();
                    header.cursor_pointer().on_click(move |_, _, cx| {
                        expanded.update(cx, |set, cx| {
                            if !set.remove(&ix) {
                                set.insert(ix);
                            }
                            cx.notify();
                        });
                    })
                });
                v_flex()
                    .gap_2()
                    .child(header)
                    .when(open, |this| {
                        this.child(
                            div()
                                .ml(px(4.))
                                .pl_4()
                                .border_l_1()
                                .border_color(border)
                                .text_sm()
                                .when(block.label == "思考", |text| text.text_color(muted))
                                .child(markdown(md_id, &block.body, window, cx)),
                        )
                    })
                    .into_any_element()
            }
        };
        let content = match (block.group, group_open) {
            (Some((start, len)), Some(open)) => {
                let indented = div()
                    .ml(px(4.))
                    .pl_4()
                    .border_l_1()
                    .border_color(border)
                    .child(content);
                if start != ix {
                    indented.into_any_element()
                } else {
                    let (summary, failed) = block.group_summary.as_ref().expect("group summary");
                    let visible = visible.clone();
                    let list_state = list_state.clone();
                    let header = summary_row(
                        ElementId::NamedInteger("transcript-group".into(), start as u64),
                        if open { "▾" } else { "▸" },
                        "过程",
                        summary.clone(),
                        (*failed > 0).then(|| format!("{failed} 个失败").into()),
                        *failed > 0,
                        false,
                        cx,
                    )
                    .cursor_pointer()
                    .on_click(move |_, _, cx| {
                        visible.update(cx, |rows, cx| {
                            rows.toggle_group(row, start, len, &list_state);
                            cx.notify();
                        });
                    });
                    v_flex()
                        .gap_2()
                        .child(header)
                        .when(open, |this| this.child(indented))
                        .into_any_element()
                }
            }
            _ => content,
        };

        // 相邻的过程块挤在一起更易扫读；对话消息之间留大间距。
        let gap = if block.summary.is_some() {
            px(8.)
        } else {
            px(20.)
        };
        div()
            .w_full()
            .child(
                div()
                    .w_full()
                    .max_w(px(760.))
                    .mx_auto()
                    .px_6()
                    .pb(gap)
                    .child(content),
            )
            .into_any_element()
    })
    .size_full()
    .py(px(EDGE_FADE_HEIGHT));
    // min_h(0)：flex item 默认按内容撑高，不加这行长记录会顶穿底部 composer。
    div()
        .relative()
        .flex_1()
        .min_h(px(0.))
        .w_full()
        .child(rows)
        // 上下缘渐隐：记录滚入滚出时不被硬边切断。无交互的 div 不拦截滚动。
        .child(edge_fade(true, cx))
        .child(edge_fade(false, cx))
        // Scrollbar 自身是绝对定位但不带 inset，直接放在列表后面会落到列表下方。
        .child(div().absolute().inset_0().child(scrollbar))
}

fn edge_fade(top: bool, cx: &gpui::App) -> gpui::Div {
    let bg = cx.theme().background;
    let fade = div()
        .absolute()
        .left_0()
        .right(px(12.))
        .h(px(EDGE_FADE_HEIGHT))
        .bg(gpui::linear_gradient(
            if top { 180. } else { 0. },
            gpui::linear_color_stop(bg, 0.),
            gpui::linear_color_stop(bg.opacity(0.), 1.),
        ));
    if top { fade.top_0() } else { fade.bottom_0() }
}

#[cfg(test)]
mod tests {
    use super::{
        BODY_LIMIT, Block, CONTEXT_KIND_KEY, VisibleRows, append, collapsed_indices, describe,
        fence, is_binary, prepare, truncate,
    };
    use agentdeck_protocol::{
        AgentItem, AgentItemMeta, HistoryTurn, PlanStep, PlanStepStatus, ShellStatus,
    };
    use gpui::{ListAlignment, ListOffset, ListState, px};
    use std::rc::Rc;

    fn meta() -> AgentItemMeta {
        AgentItemMeta::default()
    }

    #[test]
    fn only_raw_content_uses_unsupported_presentation() {
        let plan = describe(&AgentItem::Plan {
            steps: vec![PlanStep {
                title: "运行测试".into(),
                status: PlanStepStatus::InProgress,
                detail: None,
            }],
            meta: meta(),
        });
        assert!(!plan.unsupported);
        assert_eq!(plan.label, "计划");
        assert_eq!(plan.body, "◐ 运行测试");

        let raw = describe(&AgentItem::Raw {
            raw_kind: "futureItem".into(),
            raw_payload: "withheld".into(),
            meta: meta(),
        });
        assert!(raw.unsupported);
        assert!(raw.body.contains("futureItem"));
    }

    #[test]
    fn assistant_identity_restarts_each_turn_and_skips_process_blocks() {
        let assistant = || AgentItem::AssistantMessage {
            text: "测试结果".into(),
            meta: meta(),
        };
        let blocks = prepare(vec![
            HistoryTurn {
                items: vec![
                    assistant(),
                    AgentItem::Reasoning {
                        text: "检查结果".into(),
                        meta: meta(),
                    },
                    assistant(),
                ],
            },
            HistoryTurn {
                items: vec![assistant()],
            },
            HistoryTurn {
                items: vec![
                    AgentItem::UserMessage {
                        text: " ".into(),
                        meta: meta(),
                    },
                    assistant(),
                ],
            },
        ]);
        let continued: Vec<_> = blocks
            .iter()
            .filter(|block| block.label == "助手")
            .map(|block| block.continued_assistant)
            .collect();
        assert_eq!(continued, [false, true, false, false]);
    }

    #[test]
    fn prepare_preserves_order_and_drops_empty_items() {
        let message = |text: String| AgentItem::UserMessage { text, meta: meta() };
        let blocks = prepare(vec![
            HistoryTurn {
                items: vec![message("  首条\n".into()), message(" \n\t".into())],
            },
            HistoryTurn {
                items: vec![
                    AgentItem::Raw {
                        raw_kind: "futureItem".into(),
                        raw_payload: "withheld".into(),
                        meta: meta(),
                    },
                    message(format!("  {}\n", "字".repeat(BODY_LIMIT + 1))),
                ],
            },
        ]);
        let bodies: Vec<_> = blocks
            .iter()
            .map(|b| (b.label, b.body.to_string()))
            .collect();
        assert_eq!(
            bodies,
            vec![
                ("你", "首条".to_string()),
                (
                    "暂不支持的内容",
                    "类型：futureItem\n当前 AgentDeck 无法展示此内容，请检查更新".to_string()
                ),
                ("你", format!("{}…（已截断）", "字".repeat(BODY_LIMIT))),
            ]
        );
        assert!(blocks.iter().all(|b| b.summary.is_none()));
    }

    #[test]
    fn shell_collapses_to_command_with_status() {
        let shell = describe(&AgentItem::Shell {
            command: "cargo test".into(),
            status: ShellStatus::Failed,
            exit_code: Some(101),
            duration_ms: Some(1500),
            meta: meta(),
        });
        assert_eq!(
            shell.summary.as_ref().map(|s| s.as_str()),
            Some("$ cargo test")
        );
        assert_eq!(
            shell.status.as_ref().map(|s| s.as_str()),
            Some("失败 · 退出码 101 · 1.5s")
        );
        assert!(shell.failed);
        assert!(shell.body.contains("cargo test"));

        let command = format!("cargo test -- {}", "long_test_name_".repeat(15));
        let long = describe(&AgentItem::Shell {
            command: command.clone(),
            status: ShellStatus::Failed,
            exit_code: Some(101),
            duration_ms: Some(1500),
            meta: meta(),
        });
        assert!(long.summary.as_ref().unwrap().ends_with('…'));
        assert!(long.body.contains(&command));
        assert_eq!(long.status, shell.status);
    }

    #[test]
    fn tool_shows_status_and_duration_from_extensions() {
        let tool = |status: &str, duration: serde_json::Value| {
            let mut meta = meta();
            meta.vendor_extensions
                .insert("status".into(), status.into());
            meta.vendor_extensions.insert("durationMs".into(), duration);
            describe(&AgentItem::ToolCall {
                name: "WebFetch".into(),
                args: serde_json::json!({}),
                result: None,
                meta,
            })
        };
        let running = tool("inProgress", 30_000.into());
        assert_eq!(
            running.status.as_ref().map(|s| s.as_str()),
            Some("运行中 · 30.0s")
        );
        assert!(!running.failed);
        let failed = tool("failed", 1500.into());
        assert_eq!(
            failed.status.as_ref().map(|s| s.as_str()),
            Some("失败 · 1.5s")
        );
        assert!(failed.failed);
        assert_eq!(tool("completed", serde_json::Value::Null).status, None);
    }

    #[test]
    fn tool_summarizes_args_and_hides_binary_results() {
        let base64 = format!("data:image/png;base64,{}", "iVBORw0KGgo".repeat(40));
        let tool = describe(&AgentItem::ToolCall {
            name: "Read".into(),
            args: serde_json::json!({"file_path": "/tmp/a.png"}),
            result: Some(serde_json::json!([{"type": "image", "data": base64}])),
            meta: meta(),
        });
        assert_eq!(
            tool.summary.as_ref().map(|s| s.as_str()),
            Some("Read  /tmp/a.png")
        );
        assert!(tool.body.contains("[二进制内容 0.5 KB]"));
        assert!(!tool.body.contains("iVBORw0KGgo"));

        let plain = (1..=100).map(|n| format!("{n}\n")).collect::<String>();
        let value = serde_json::json!({"output": plain, "data": "abc123\n".repeat(50)});
        assert_eq!(super::scrub(&value), value);
    }

    #[test]
    fn single_line_details_keep_expandable_bodies() {
        let one = describe(&AgentItem::Reasoning {
            text: "**我检查试玩页的桌面布局。**".into(),
            meta: meta(),
        });
        assert_eq!(
            one.summary.as_ref().map(|s| s.as_str()),
            Some("我检查试玩页的桌面布局。")
        );
        assert_eq!(one.body, "**我检查试玩页的桌面布局。**");

        let text = "需要检查调用点并验证错误路径。".repeat(15);
        let long = describe(&AgentItem::Reasoning {
            text: text.clone(),
            meta: meta(),
        });
        assert!(long.summary.unwrap().ends_with('…'));
        assert_eq!(long.body, text);

        let path = format!("/tmp/{}/image.png", "directory/".repeat(20));
        let image = describe(&AgentItem::ImageReference {
            saved_path: None,
            original_path: Some(path.clone().into()),
            meta: meta(),
        });
        assert!(image.summary.unwrap().ends_with('…'));
        assert!(image.body.contains(&path));

        let many: Block = describe(&AgentItem::Reasoning {
            text: "**标题**\n\n细节".into(),
            meta: meta(),
        });
        assert_eq!(many.summary.as_ref().map(|s| s.as_str()), Some("标题"));
        assert_eq!(many.body, "**标题**\n\n细节");
    }

    #[test]
    fn binary_detection_and_fences() {
        assert!(!is_binary(&"A".repeat(300)));
        assert!(is_binary(&format!(
            "data:image/png;base64,{}",
            "A".repeat(300)
        )));
        assert!(!is_binary("短文本"));
        assert!(!is_binary(&"word ".repeat(100)));

        assert_eq!(fence("sh", "ls"), "```sh\nls\n```");
        assert_eq!(fence("", "a ```` b"), "`````\na ```` b\n`````");
    }

    #[test]
    fn truncate_keeps_short_bodies_and_marks_long_ones() {
        assert_eq!(truncate("短文本"), "短文本");
        let truncated = truncate(&"字".repeat(BODY_LIMIT + 1));
        assert!(truncated.ends_with("…（已截断）"));
    }

    #[test]
    fn consecutive_process_blocks_form_groups() {
        let user = |text: &str| AgentItem::UserMessage {
            text: text.into(),
            meta: meta(),
        };
        let think = |text: &str| AgentItem::Reasoning {
            text: text.into(),
            meta: meta(),
        };
        let shell = |status| AgentItem::Shell {
            command: "ls".into(),
            status,
            exit_code: None,
            duration_ms: None,
            meta: meta(),
        };
        let blocks = prepare(vec![HistoryTurn {
            items: vec![
                user("问"),
                think("想"),
                shell(ShellStatus::Completed),
                shell(ShellStatus::Failed),
                user("再问"),
                think("单独一个"),
                user("结束"),
            ],
        }]);
        let groups: Vec<_> = blocks.iter().map(|b| b.group).collect();
        assert_eq!(
            groups,
            vec![
                None,
                Some((1, 3)),
                Some((1, 3)),
                Some((1, 3)),
                None,
                None,
                None
            ]
        );
        assert_eq!(
            blocks[1].group_summary,
            Some(("3 步 · 思考 1 · 命令 2".into(), 1))
        );
    }

    #[test]
    fn cli_context_user_messages_fold_but_typed_commands_stay() {
        let context = |kind: &str, text: &str| {
            let mut meta = meta();
            meta.vendor_extensions
                .insert(CONTEXT_KIND_KEY.into(), kind.into());
            describe(&AgentItem::UserMessage {
                text: text.into(),
                meta,
            })
        };
        let typed = describe(&AgentItem::UserMessage {
            text: "/model opus".into(),
            meta: meta(),
        });
        assert_eq!((typed.label, typed.summary), ("你", None));

        let output = context("output", "Set model\nmore");
        assert_eq!(output.label, "命令输出");
        assert_eq!(output.summary, Some("Set model".into()));
        assert!(!output.failed);
        assert!(output.body.contains("Set model\nmore"));

        let error = context("error", "boom");
        assert!(error.failed);
        assert_eq!(context("notification", "done").label, "通知");
        assert_eq!(context("context", "<x>y</x>").label, "上下文");
    }

    #[test]
    fn collapsed_groups_remove_hidden_rows_and_preserve_following_scroll_anchor() {
        let message = || AgentItem::UserMessage {
            text: "消息".into(),
            meta: meta(),
        };
        let process = || AgentItem::Reasoning {
            text: "步骤".into(),
            meta: meta(),
        };
        let items = std::iter::once(message())
            .chain((0..1000).map(|_| process()))
            .chain(std::iter::once(message()))
            .chain((0..3).map(|_| process()))
            .chain(std::iter::once(message()))
            .collect();
        let blocks: Rc<[Block]> = prepare(vec![HistoryTurn { items }]).into();
        let mut rows = VisibleRows::new(&blocks);
        let list = ListState::new(
            collapsed_indices(&blocks).count(),
            ListAlignment::Top,
            px(1000.),
        );
        assert_eq!(rows.indices, [0, 1, 1001, 1002, 1005]);
        assert_eq!(list.item_count(), 5);
        list.scroll_to(ListOffset {
            item_ix: 4,
            offset_in_item: px(7.),
        });

        // 先展开后面的组，再改变前面的组；原块身份和后方滚动锚点不能串位。
        rows.toggle_group(3, 1002, 3, &list);
        assert_eq!(rows.indices, [0, 1, 1001, 1002, 1003, 1004, 1005]);
        assert_eq!(list.item_count(), 7);
        rows.toggle_group(1, 1, 1000, &list);
        assert_eq!(rows.indices, (0..blocks.len()).collect::<Vec<_>>());
        assert_eq!(list.item_count(), blocks.len());
        assert_eq!(list.logical_scroll_top().item_ix, 1005);

        rows.toggle_group(1, 1, 1000, &list);
        assert_eq!(rows.indices, [0, 1, 1001, 1002, 1003, 1004, 1005]);
        assert_eq!(list.item_count(), 7);
        assert!(rows.expanded_groups.contains(&1002));
        rows.toggle_group(3, 1002, 3, &list);
        assert_eq!(rows.indices, [0, 1, 1001, 1002, 1005]);
        assert_eq!(list.item_count(), 5);
        assert_eq!(list.logical_scroll_top().item_ix, 4);
        assert_eq!(list.logical_scroll_top().offset_in_item, px(7.));
        assert!(rows.expanded_groups.is_empty());
    }

    #[test]
    fn appended_live_blocks_shift_groups_and_keep_expanded_history_groups() {
        let process = || AgentItem::Reasoning {
            text: "步骤".into(),
            meta: meta(),
        };
        let message = |text: &str| AgentItem::UserMessage {
            text: text.into(),
            meta: meta(),
        };
        let history: Rc<[Block]> = prepare(vec![HistoryTurn {
            items: vec![message("旧"), process(), process()],
        }])
        .into();
        let mut rows = VisibleRows::new(&history);
        let list = ListState::new(rows.indices.len(), ListAlignment::Top, px(1000.));
        rows.toggle_group(1, 1, 2, &list);
        assert!(!rows.sync(&history), "same blocks need no reset");

        let live = prepare(vec![HistoryTurn {
            items: vec![message("新"), process(), process()],
        }]);
        let combined: Rc<[Block]> = append(&history, live).into();
        assert_eq!(combined[4].group, Some((4, 2)));
        assert!(rows.sync(&combined));
        assert_eq!(rows.indices, [0, 1, 2, 3, 4]);
    }
}
