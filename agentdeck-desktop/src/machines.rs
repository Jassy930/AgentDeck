//! 机器管理页：连接远端 agentdeckd，逐台查看连接状态、各 agent 的读取状态与错误。
//!
//! 错误和兼容性警告在这里完整展开；侧栏只保留入口与失败摘要。

use gpui::{Context, IntoElement, ParentElement, SharedString, div, prelude::*, px};
use gpui_component::{
    ActiveTheme, Sizable, StyledExt,
    button::{Button, ButtonVariants},
    h_flex,
    input::Input,
    v_flex,
};

use crate::shell::{AgentHistory, Host, Machine, Shell, agent_label, machine_label};
use crate::sidebar;
use agentdeck_protocol::AgentKind;

/// 内容列宽度上限，宽窗口下保持居中可读。
const CONTENT_WIDTH: f32 = 720.;

pub fn render(shell: &Shell, cx: &mut Context<Shell>) -> impl IntoElement + use<> {
    let cards: Vec<_> = shell
        .machines
        .iter()
        .map(|machine| machine_card(machine, shell.agent_filter.as_ref(), cx))
        .collect();

    v_flex()
        .flex_1()
        .h_full()
        .child(sidebar::titlebar_area("machines-titlebar"))
        .child(
            div()
                .id("machines-page")
                .flex_1()
                // flex item 需要 min_h(0) 才会真正滚动。
                .min_h(px(0.))
                .overflow_y_scroll()
                .px_10()
                .pb_10()
                .child(
                    v_flex()
                        .w_full()
                        .max_w(px(CONTENT_WIDTH))
                        .mx_auto()
                        .gap_6()
                        .child(
                            v_flex()
                                .gap_1()
                                .child(div().text_2xl().child("机器"))
                                .child(
                                    div()
                                        .text_sm()
                                        .text_color(cx.theme().muted_foreground)
                                        .child("本机与经 ssh 连接的远端 agentdeckd。点击 agent 只看它的会话，再点取消。"),
                                ),
                        )
                        .child(remote_form(shell, cx))
                        .child(v_flex().gap_3().children(cards)),
                ),
        )
}

/// 连接远端：ssh 目标输入框，回车或点"连接"。
fn remote_form(shell: &Shell, cx: &mut Context<Shell>) -> impl IntoElement + use<> {
    v_flex()
        .gap_1()
        .child(
            h_flex()
                .gap_2()
                .child(Input::new(&shell.remote_input).small().flex_1())
                .child(
                    Button::new("connect-remote")
                        .small()
                        .label("连接")
                        .on_click(cx.listener(|shell, _, _, cx| shell.connect_remote(cx))),
                ),
        )
        .when_some(shell.remote_error.clone(), |form, error| {
            form.child(
                div()
                    .text_xs()
                    .whitespace_normal()
                    .text_color(cx.theme().danger)
                    .child(error),
            )
        })
}

/// 一台机器：状态圆点、名称、状态、重试 / 断开，完整错误，以及各 agent 行。
fn machine_card(
    machine: &Machine,
    filter: Option<&(Host, AgentKind)>,
    cx: &mut Context<Shell>,
) -> impl IntoElement + use<> {
    let id = machine.id;
    let label = machine_label(&machine.host);
    let (status, dot) = if machine.connecting {
        ("连接中…", cx.theme().muted_foreground)
    } else if machine.error.is_some() {
        ("连接失败", cx.theme().danger)
    } else {
        ("已连接", cx.theme().success)
    };

    let header = h_flex()
        .gap_2()
        .items_center()
        .child(div().size_2().rounded_full().flex_shrink_0().bg(dot))
        .child(
            div()
                .min_w(px(0.))
                .text_ellipsis()
                .font_semibold()
                .child(label.clone()),
        )
        .child(
            div()
                .flex_1()
                .text_sm()
                .text_color(cx.theme().muted_foreground)
                .child(status),
        )
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
        .gap_3()
        .p_4()
        .rounded_lg()
        .bg(cx.theme().muted)
        .border_1()
        .border_color(cx.theme().border)
        .child(header)
        .when_some(machine.error.clone(), |card, error| {
            card.child(
                div()
                    .text_xs()
                    .whitespace_normal()
                    .text_color(cx.theme().danger)
                    .child(error),
            )
        })
        .children(agents)
}

/// agent 一行：图标、名称、完整状态、警告与错误；点击只看该机器上该 agent 的会话。
fn agent_row(
    machine: &Machine,
    agent: &AgentHistory,
    filtered: bool,
    cx: &mut Context<Shell>,
) -> impl IntoElement + use<> {
    let kind = agent.kind;
    let (id, host) = (machine.id, machine.host.clone());
    let key = format!("{}-{}", machine_label(&host), kind.as_str());
    let status = match agent.list_hint() {
        Some(hint) => format!("{} · {hint}", agent.status()),
        None => agent.status(),
    };
    let error: Option<SharedString> = agent.error().map(|error| error.to_string().into());
    let failed = error.is_some();

    // 重试放在可点击行之外，避免同时触发筛选。
    let row = h_flex()
        .id(SharedString::from(format!("agent-{key}")))
        .flex_1()
        .min_w(px(0.))
        .px_3()
        .py_2()
        .gap_3()
        .items_start()
        .rounded_md()
        .border_1()
        .border_color(if filtered {
            cx.theme().ring
        } else {
            gpui::transparent_black()
        })
        .cursor_pointer()
        .when(filtered, |row| row.bg(cx.theme().accent))
        .hover(|style| style.bg(cx.theme().accent))
        .on_click(
            cx.listener(move |shell, _, _, cx| shell.toggle_agent_filter(host.clone(), kind, cx)),
        )
        .child(div().pt_0p5().child(sidebar::agent_icon(kind, false)))
        .child(
            v_flex()
                .flex_1()
                .min_w(px(0.))
                .gap_0p5()
                .child(
                    h_flex()
                        .gap_2()
                        .items_baseline()
                        .child(div().text_sm().child(agent_label(kind)))
                        .when_some(agent.version.as_deref().map(short_version), |line, v| {
                            line.child(
                                div()
                                    .text_xs()
                                    .text_color(cx.theme().muted_foreground)
                                    .child(v),
                            )
                        }),
                )
                .child(
                    div()
                        .text_xs()
                        .text_color(cx.theme().muted_foreground)
                        .child(if filtered {
                            format!("{status} · 已筛选")
                        } else {
                            status
                        }),
                )
                .children(agent.warnings.iter().map(|warning| {
                    div()
                        .text_xs()
                        .whitespace_normal()
                        .text_color(crate::theme_tokens::WARN)
                        .child(format!("兼容性警告：{}", warning.message))
                }))
                .when_some(error, |details, error| {
                    details.child(
                        div()
                            .text_xs()
                            .whitespace_normal()
                            .text_color(cx.theme().danger)
                            .child(error),
                    )
                }),
        );

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

/// "2.1.191 (Claude Code)" / "codex-cli 0.156.1" → "v…"；探测失败的 "claude unknown" → "版本未知"。
fn short_version(raw: &str) -> String {
    if raw.ends_with("unknown") {
        return "版本未知".into();
    }
    raw.split_whitespace()
        .find(|part| part.starts_with(|c: char| c.is_ascii_digit()))
        .map_or_else(|| raw.into(), |v| format!("v{v}"))
}

#[cfg(test)]
mod tests {
    #[test]
    fn short_version_drops_product_suffix() {
        assert_eq!(super::short_version("2.1.191 (Claude Code)"), "v2.1.191");
        assert_eq!(super::short_version("codex-cli 0.156.1"), "v0.156.1");
        assert_eq!(super::short_version("codex unknown"), "版本未知");
    }
}
