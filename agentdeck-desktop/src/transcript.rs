//! 会话记录渲染：把中立 `AgentItem` 转成只读文本块。
//!
//! 助手与思考按 Markdown 渲染，其余仍是纯文本。diff 高亮、工具折叠和 streaming 属于后续切片。

use std::hash::{DefaultHasher, Hash, Hasher};
use std::rc::Rc;

use agentdeck_protocol::{AgentItem, HistoryTurn};
use gpui::{
    ElementId, IntoElement, ListState, ParentElement, SharedString, div, list, prelude::*, px,
};
use gpui_component::{ActiveTheme, StyledExt, clipboard::Clipboard, text::TextView, v_flex};

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
        AgentItem::Raw { raw_kind, .. } => (
            "暂不支持的内容",
            format!("类型：{raw_kind}\n当前 AgentDeck 无法展示此内容，请检查更新"),
        ),
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

/// 只有模型输出按 Markdown 渲染：TextView 会静默丢弃未识别的内联 HTML，
/// 用户消息里常夹带 `<in-app-browser-context>` 这类注入标签，按 Markdown 会吞字。
// ponytail: 按标签判断，块类型再多就改成 TextBlock 结构体带 kind。
fn is_markdown(label: &str) -> bool {
    matches!(label, "助手" | "思考")
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

/// 只渲染可见区域附近的块：长会话有几百块，逐帧全量排版会拖慢滚动。
///
/// `read_id` 进入 Markdown 状态的 key：TextView 按 id 缓存解析结果，换会话后同一
/// 下标若沿用旧 key，会先显示上个会话的内容再延迟 200ms 重新解析。
pub fn render(blocks: Rc<[TextBlock]>, state: ListState, read_id: u64) -> impl IntoElement {
    // min_h(0)：flex item 默认按内容撑高，不加这行长记录会顶穿底部 composer。
    list(state, move |ix, window, cx| {
        let (label, body) = &blocks[ix];
        let body = if is_markdown(label) {
            TextView::markdown(
                ElementId::NamedInteger(format!("transcript-{read_id}").into(), ix as u64),
                body.clone(),
                window,
                cx,
            )
            .selectable(true)
            .code_block_actions(|code, _, _| {
                // 复制按钮的"已复制"状态按 id 存；同一条消息里多个代码块要各自区分。
                let code = code.code();
                let mut hasher = DefaultHasher::new();
                code.hash(&mut hasher);
                Clipboard::new(ElementId::Integer(hasher.finish())).value(code)
            })
            .into_any_element()
        } else {
            body.clone().into_any_element()
        };
        div()
            .w_full()
            .child(
                v_flex()
                    .w_full()
                    .max_w(px(760.))
                    .mx_auto()
                    .px_6()
                    .when(ix == 0, |block| block.pt_4())
                    .pb_5()
                    .gap_1()
                    .child(
                        div()
                            .text_sm()
                            .font_semibold()
                            .text_color(cx.theme().muted_foreground)
                            .child(*label),
                    )
                    .child(
                        div()
                            .text_sm()
                            .when(*label == "思考", |text| {
                                text.text_color(cx.theme().muted_foreground)
                            })
                            .child(body),
                    ),
            )
            .into_any_element()
    })
    .flex_1()
    .min_h(px(0.))
    .w_full()
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
                    AgentItem::Raw {
                        raw_kind: "futureItem".into(),
                        raw_payload: "withheld".into(),
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
                    "暂不支持的内容",
                    "类型：futureItem\n当前 AgentDeck 无法展示此内容，请检查更新".into()
                ),
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
