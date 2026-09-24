//! 会话记录渲染：把中立 `AgentItem` 转成只读块。
//!
//! 对话消息直接展开；命令、思考、工具、变更等过程块默认折叠成一行摘要，点击展开。
//! 连续两个以上的过程块再合成一组，默认只显示一行组摘要。
//! 助手、思考与过程块正文按 Markdown 渲染（代码走围栏高亮）；用户消息仍是纯文本。

use std::collections::HashSet;
use std::rc::Rc;

mod markdown_fallback;

use agentdeck_protocol::{AgentItem, HistoryTurn, PlanStepStatus, ShellStatus};
use gpui::{
    ClipboardItem, ElementId, IntoElement, ListState, ParentElement, SharedString, Window, div,
    list, prelude::*, px,
};
use gpui_component::{
    ActiveTheme, Sizable, StyledExt,
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
    /// 命令失败等需要醒目提示的状态。
    pub failed: bool,
    /// 所在连续过程块组的 `(起始下标, 块数)`；连续两个以上过程块才成组。
    pub group: Option<(usize, usize)>,
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
            failed: false,
            group: None,
        }
    }

    fn detail(label: &'static str, summary: String, body: String) -> Self {
        Self {
            label,
            summary: Some(one_line(&summary).into()),
            status: None,
            body: markdown_fallback::images_as_links(body.trim()).into(),
            markdown: true,
            failed: false,
            group: None,
        }
    }

    fn is_empty(&self) -> bool {
        self.body.is_empty() && self.summary.as_ref().is_none_or(|s| s.is_empty())
    }
}

pub fn describe(item: &AgentItem) -> Block {
    match item {
        AgentItem::UserMessage { text, .. } => Block::message("你", text, false),
        AgentItem::AssistantMessage { text, .. } => Block::message("助手", text, true),
        AgentItem::Raw { raw_kind, .. } => Block::message(
            "暂不支持的内容",
            &format!("类型：{raw_kind}\n当前 AgentDeck 无法展示此内容，请检查更新"),
            false,
        ),
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
            let tail: Vec<String> = state
                .into_iter()
                .chain(duration_ms.map(|ms| format!("{:.1}s", ms as f64 / 1000.)))
                .collect();
            let body = fence("sh", &truncate(command.trim()));
            Block {
                status: (!tail.is_empty()).then(|| tail.join(" · ").into()),
                failed: matches!(status, ShellStatus::Failed),
                ..Block::detail("命令", summary, body)
            }
        }
        AgentItem::ToolCall {
            name, args, result, ..
        } => {
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
            Block::detail("工具", summary, body)
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
fn fence(lang: &str, code: &str) -> String {
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

fn truncate(body: &str) -> String {
    if body.chars().count() <= BODY_LIMIT {
        return body.to_string();
    }
    let head: String = body.chars().take(BODY_LIMIT).collect();
    format!("{head}…（已截断）")
}

pub fn prepare(turns: Vec<HistoryTurn>) -> Vec<Block> {
    let mut blocks: Vec<Block> = turns
        .into_iter()
        .flat_map(|turn| turn.items)
        .map(|item| describe(&item))
        .filter(|block| !block.is_empty())
        .collect();
    let mut start = 0;
    while start < blocks.len() {
        let len = blocks[start..]
            .iter()
            .take_while(|block| block.summary.is_some())
            .count();
        if len >= 2 {
            for block in &mut blocks[start..start + len] {
                block.group = Some((start, len));
            }
        }
        start += len.max(1);
    }
    blocks
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
    h_flex()
        .id(id)
        .gap_2()
        .min_w(px(0.))
        .text_sm()
        .text_color(muted)
        .child(div().w(px(10.)).flex_shrink_0().child(arrow))
        .child(div().flex_shrink_0().font_semibold().child(label))
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

fn markdown(
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
    // 展开的组按起始下标记录；组默认折叠。
    let groups = window.use_keyed_state(
        SharedString::from(format!("transcript-groups-{read_id}")),
        cx,
        |_, _| HashSet::<usize>::new(),
    );
    let list_state = state.clone();
    // 常驻显示：长会话需要随时看到当前位置，不跟随系统的自动隐藏。
    let scrollbar = Scrollbar::vertical(&state).scrollbar_show(ScrollbarShow::Always);
    let rows = list(state, move |ix, window, cx| {
        let block = &blocks[ix];
        let group_open = block
            .group
            .map(|(start, _)| groups.read(cx).contains(&start));
        // 折叠组里除首块外都渲染成零高度，首块位置改画组摘要。
        if group_open == Some(false) && block.group.is_some_and(|(start, _)| start != ix) {
            return div().into_any_element();
        }
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
                v_flex()
                    .gap_1()
                    .child(
                        div()
                            .text_sm()
                            .font_semibold()
                            .text_color(muted)
                            .child(block.label),
                    )
                    .child(div().text_sm().child(body))
                    .into_any_element()
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
                    let (summary, failed) = group_summary(&blocks[start..start + len]);
                    let groups = groups.clone();
                    let list_state = list_state.clone();
                    let header = summary_row(
                        ElementId::NamedInteger("transcript-group".into(), start as u64),
                        if open { "▾" } else { "▸" },
                        "过程",
                        summary.into(),
                        (failed > 0).then(|| format!("{failed} 个失败").into()),
                        failed > 0,
                        false,
                        cx,
                    )
                    .cursor_pointer()
                    .on_click(move |_, _, cx| {
                        groups.update(cx, |set, cx| {
                            if !set.remove(&start) {
                                set.insert(start);
                            }
                            cx.notify();
                        });
                        // 组内其余块高度在 0 与实际之间切换，屏幕外的缓存高度需要作废。
                        list_state.splice(start + 1..start + len, len - 1);
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
                    .when(ix == 0, |block| block.pt_4())
                    .pb(gap)
                    .child(content),
            )
            .into_any_element()
    })
    .size_full();
    // min_h(0)：flex item 默认按内容撑高，不加这行长记录会顶穿底部 composer。
    div()
        .relative()
        .flex_1()
        .min_h(px(0.))
        .w_full()
        .child(rows)
        // Scrollbar 自身是绝对定位但不带 inset，直接放在列表后面会落到列表下方。
        .child(div().absolute().inset_0().child(scrollbar))
}

#[cfg(test)]
mod tests {
    use super::{BODY_LIMIT, Block, describe, fence, group_summary, is_binary, prepare, truncate};
    use agentdeck_protocol::{AgentItem, AgentItemMeta, HistoryTurn, ShellStatus};

    fn meta() -> AgentItemMeta {
        AgentItemMeta::default()
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
            group_summary(&blocks[1..4]),
            ("3 步 · 思考 1 · 命令 2".to_string(), 1)
        );
    }
}
