//! 会话记录渲染：把中立 `AgentItem` 转成只读块。
//!
//! 对话消息直接展开；命令、思考、工具、变更等过程块默认折叠成一行摘要，点击展开。
//! 助手、思考与过程块正文按 Markdown 渲染（代码走围栏高亮）；用户消息仍是纯文本。

use std::collections::HashSet;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::rc::Rc;

use agentdeck_protocol::{AgentItem, HistoryTurn, PlanStepStatus, ShellStatus};
use gpui::{
    ClipboardItem, ElementId, IntoElement, ListState, ParentElement, SharedString, Window, div,
    list, prelude::*, px,
};
use gpui_component::{
    ActiveTheme, Sizable, StyledExt, button::Button, button::ButtonVariants, h_flex,
    text::TextView, v_flex,
};

/// 单条内容的展示上限；历史里的工具结果可能是几十 KB 的整页文本。
const BODY_LIMIT: usize = 2_000;
/// 折叠摘要的字符上限。
const SUMMARY_LIMIT: usize = 120;
/// 至少这么长、且几乎全是 base64 字符的串视为二进制内容。
const BINARY_MIN_LEN: usize = 256;

#[derive(Debug, Clone, PartialEq)]
pub struct Block {
    pub label: &'static str,
    /// `Some` 表示过程块：折叠时只显示这一行；`None` 表示对话消息，正文总是显示。
    pub summary: Option<SharedString>,
    /// 过程块展开后的正文；为空表示没有可展开的内容。
    pub body: SharedString,
    /// 正文按 Markdown 渲染；用户消息里常夹带 `<in-app-browser-context>` 这类注入标签，
    /// TextView 会静默丢弃未识别的内联 HTML，所以用户消息保持纯文本。
    pub markdown: bool,
    /// 命令失败等需要醒目提示的状态。
    pub failed: bool,
}

impl Block {
    fn message(label: &'static str, body: &str, markdown: bool) -> Self {
        Self {
            label,
            summary: None,
            body: truncate(body.trim()).into(),
            markdown,
            failed: false,
        }
    }

    fn detail(label: &'static str, summary: String, body: String) -> Self {
        Self {
            label,
            summary: Some(one_line(&summary).into()),
            body: body.trim().to_string().into(),
            markdown: true,
            failed: false,
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
            // 只有一行的思考，摘要就是全部内容，不必再展开。
            let body = if text.lines().filter(|l| !l.trim().is_empty()).count() > 1 {
                truncate(text)
            } else {
                String::new()
            };
            Block::detail("思考", summary.to_string(), body)
        }
        AgentItem::Shell {
            command,
            status,
            exit_code,
            duration_ms,
            ..
        } => {
            let mut summary = format!("$ {}", command.trim());
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
            let multiline = command.trim().contains('\n');
            summary = one_line(&summary);
            if !tail.is_empty() {
                summary = format!("{summary}  ·  {}", tail.join(" · "));
            }
            let body = if multiline {
                fence("sh", &truncate(command.trim()))
            } else {
                String::new()
            };
            Block {
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
            Block::detail("图片", path, String::new())
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

/// 把 JSON 里的 base64 大串替换成占位说明，其余原样保留。
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
    let text = text
        .strip_prefix("data:")
        .and_then(|rest| rest.split_once(";base64,"))
        .map_or(text, |(_, data)| data);
    text.len() >= BINARY_MIN_LEN
        && text
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
    turns
        .into_iter()
        .flat_map(|turn| turn.items)
        .map(|item| describe(&item))
        .filter(|block| !block.is_empty())
        .collect()
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
            // 按钮 id 用内容哈希区分同一条消息里的多个代码块。
            let code = code.code();
            let mut hasher = DefaultHasher::new();
            code.hash(&mut hasher);
            Button::new(ElementId::Integer(hasher.finish()))
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
    // min_h(0)：flex item 默认按内容撑高，不加这行长记录会顶穿底部 composer。
    list(state, move |ix, window, cx| {
        let block = &blocks[ix];
        let md_id = ElementId::NamedInteger(format!("transcript-{read_id}").into(), ix as u64);
        let theme = cx.theme();
        let (muted, danger, border) = (theme.muted_foreground, theme.danger, theme.border);

        let content =
            match &block.summary {
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
                    let header =
                        h_flex()
                            .id(ElementId::NamedInteger(
                                "transcript-toggle".into(),
                                ix as u64,
                            ))
                            .gap_2()
                            .min_w(px(0.))
                            .text_sm()
                            .text_color(muted)
                            .child(div().w(px(10.)).flex_shrink_0().child(
                                match (expandable, open) {
                                    (false, _) => "",
                                    (true, false) => "▸",
                                    (true, true) => "▾",
                                },
                            ))
                            .child(div().flex_shrink_0().font_semibold().child(block.label))
                            .child(
                                div()
                                    .min_w(px(0.))
                                    .truncate()
                                    .when(block.failed, |text| text.text_color(danger))
                                    .child(summary.clone()),
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
    .flex_1()
    .min_h(px(0.))
    .w_full()
}

#[cfg(test)]
mod tests {
    use super::{BODY_LIMIT, Block, describe, fence, is_binary, prepare, truncate};
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
            Some("$ cargo test  ·  失败 · 退出码 101 · 1.5s")
        );
        assert!(shell.failed);
        assert!(shell.body.is_empty(), "单行命令没有可展开的内容");
    }

    #[test]
    fn tool_summarizes_args_and_hides_binary_results() {
        let base64 = "iVBORw0KGgo".repeat(40);
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
        assert!(tool.body.contains("[二进制内容 0.4 KB]"));
        assert!(!tool.body.contains("iVBORw0KGgo"));
    }

    #[test]
    fn reasoning_summary_strips_markdown_and_single_line_is_not_expandable() {
        let one = describe(&AgentItem::Reasoning {
            text: "**我检查试玩页的桌面布局。**".into(),
            meta: meta(),
        });
        assert_eq!(
            one.summary.as_ref().map(|s| s.as_str()),
            Some("我检查试玩页的桌面布局。")
        );
        assert!(one.body.is_empty());

        let many: Block = describe(&AgentItem::Reasoning {
            text: "**标题**\n\n细节".into(),
            meta: meta(),
        });
        assert_eq!(many.summary.as_ref().map(|s| s.as_str()), Some("标题"));
        assert_eq!(many.body, "**标题**\n\n细节");
    }

    #[test]
    fn binary_detection_and_fences() {
        assert!(is_binary(&"A".repeat(300)));
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
}
