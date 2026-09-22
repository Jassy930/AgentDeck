//! 会话记录渲染：把中立 `AgentItem` 转成只读文本块。
//!
//! 本期只做纯文本。Markdown、diff 高亮、工具折叠和 streaming 都属于后续切片。

use agentdeck_protocol::{AgentItem, HistoryTurn};
use gpui::{App, IntoElement, ParentElement, SharedString, div, prelude::*, px};
use gpui_component::{ActiveTheme, StyledExt, v_flex};

/// 单条内容的展示上限；历史里的工具结果可能是几十 KB 的整页文本。
const BODY_LIMIT: usize = 2_000;

pub type TextBlock = (&'static str, SharedString);

/// 条目的角色标签与正文。空正文的条目不渲染。
pub fn describe(item: &AgentItem) -> (&'static str, String) {
    match item {
        AgentItem::UserMessage { text, .. } => ("你", text.clone()),
        AgentItem::AssistantMessage { text, .. } => ("助手", text.clone()),
        AgentItem::Reasoning { text, .. } => ("思考", text.clone()),
        AgentItem::Shell { command, .. } => ("命令", format!("$ {command}")),
        AgentItem::Diff { files, .. } => (
            "变更",
            files
                .iter()
                .map(|file| file.path.display().to_string())
                .collect::<Vec<_>>()
                .join("\n"),
        ),
        AgentItem::Plan { steps, .. } => (
            "计划",
            steps
                .iter()
                .map(|step| step.title.clone())
                .collect::<Vec<_>>()
                .join("\n"),
        ),
        AgentItem::ImageReference {
            saved_path,
            original_path,
            ..
        } => (
            "图片",
            saved_path
                .as_ref()
                .or(original_path.as_ref())
                .map(|path| path.display().to_string())
                .unwrap_or_default(),
        ),
        AgentItem::ToolCall { name, result, .. } => (
            "工具",
            match result {
                Some(result) => format!("{name}\n{}", value_text(result)),
                None => name.clone(),
            },
        ),
        AgentItem::Raw {
            raw_kind,
            raw_payload,
            ..
        } => ("原始", format!("{raw_kind}\n{raw_payload}")),
    }
}

/// JSON 结果里字符串直接取内容，其余保留原始 JSON。
fn value_text(value: &serde_json::Value) -> String {
    match value.as_str() {
        Some(text) => text.to_string(),
        None => value.to_string(),
    }
}

fn truncate(body: &str) -> String {
    if body.chars().count() <= BODY_LIMIT {
        return body.to_string();
    }
    let head: String = body.chars().take(BODY_LIMIT).collect();
    format!("{head}…（已截断）")
}

pub fn prepare(turns: Vec<HistoryTurn>) -> Vec<TextBlock> {
    turns
        .into_iter()
        .flat_map(|turn| turn.items)
        .filter_map(|item| {
            let (label, body) = describe(&item);
            let body = body.trim();
            if body.is_empty() {
                return None;
            }
            Some((label, truncate(body).into()))
        })
        .collect()
}

pub fn render(blocks: &[TextBlock], cx: &App) -> impl IntoElement + use<> {
    let blocks: Vec<_> = blocks
        .iter()
        .map(|(label, body)| {
            v_flex()
                .gap_1()
                .child(
                    div()
                        .text_sm()
                        .font_semibold()
                        .text_color(cx.theme().muted_foreground)
                        .child(*label),
                )
                .child(div().text_sm().child(body.clone()))
        })
        .collect();

    // min_h(0)：flex item 默认按内容撑高，不加这行长记录会顶穿底部 composer。
    div()
        .id("transcript")
        .flex_1()
        .min_h(px(0.))
        .overflow_y_scroll()
        .child(
            v_flex()
                .w_full()
                .max_w(px(760.))
                .mx_auto()
                .px_6()
                .py_4()
                .gap_5()
                .children(blocks),
        )
}

#[cfg(test)]
mod tests {
    use super::{BODY_LIMIT, describe, prepare, truncate};
    use agentdeck_protocol::{AgentItem, AgentItemMeta, HistoryTurn, ShellStatus};

    #[test]
    fn prepare_preserves_order_and_normalizes_bodies_once() {
        let message = |text: String| AgentItem::UserMessage {
            text,
            meta: AgentItemMeta::default(),
        };
        let blocks = prepare(vec![
            HistoryTurn {
                items: vec![message("  首条\n".into()), message(" \n\t".into())],
            },
            HistoryTurn {
                items: vec![
                    AgentItem::ToolCall {
                        name: "read".into(),
                        args: serde_json::json!({}),
                        result: Some(serde_json::json!({"ok": true})),
                        meta: AgentItemMeta::default(),
                    },
                    message(format!("  {}\n", "字".repeat(BODY_LIMIT + 1))),
                ],
            },
        ]);
        assert_eq!(
            blocks,
            vec![
                ("你", "首条".into()),
                ("工具", "read\n{\"ok\":true}".into()),
                (
                    "你",
                    format!("{}…（已截断）", "字".repeat(BODY_LIMIT)).into()
                ),
            ]
        );
    }

    #[test]
    fn describe_labels_items_by_neutral_kind() {
        let user = AgentItem::UserMessage {
            text: "接入真实会话".into(),
            meta: AgentItemMeta::default(),
        };
        assert_eq!(describe(&user), ("你", "接入真实会话".to_string()));

        let shell = AgentItem::Shell {
            command: "cargo test".into(),
            status: ShellStatus::Completed,
            exit_code: Some(0),
            duration_ms: None,
            meta: AgentItemMeta::default(),
        };
        assert_eq!(describe(&shell), ("命令", "$ cargo test".to_string()));

        let tool = AgentItem::ToolCall {
            name: "WebSearch".into(),
            args: serde_json::json!({}),
            result: Some(serde_json::json!("命中 3 条")),
            meta: AgentItemMeta::default(),
        };
        assert_eq!(
            describe(&tool),
            ("工具", "WebSearch\n命中 3 条".to_string())
        );
    }

    #[test]
    fn truncate_keeps_short_bodies_and_marks_long_ones() {
        assert_eq!(truncate("短文本"), "短文本");

        let long = "字".repeat(BODY_LIMIT + 1);
        let truncated = truncate(&long);
        assert!(truncated.ends_with("…（已截断）"));
        assert_eq!(
            truncated.chars().count(),
            BODY_LIMIT + "…（已截断）".chars().count()
        );
    }
}
