//! 机器管理页：连接远端 agentdeckd，逐台查看连接状态、各 agent 的读取状态与错误。
//!
//! 错误和兼容性警告在这里完整展开；侧栏只保留入口与失败摘要。

use gpui::{Context, IntoElement, ParentElement, SharedString, div, prelude::*, px};
use gpui_component::{
    ActiveTheme, Disableable, Icon, Sizable, StyledExt,
    button::{Button, ButtonVariants},
    h_flex,
    input::Input,
    tooltip::Tooltip,
    v_flex,
};

use crate::remotes;
use crate::shell::{AgentHistory, Machine, Shell, agent_label, machine_label};
use crate::sidebar;
use crate::versions;
use std::cmp::Ordering;

/// 内容列宽度上限，宽窗口下保持居中可读。
const CONTENT_WIDTH: f32 = 720.;

pub fn render(shell: &Shell, cx: &mut Context<Shell>) -> impl IntoElement + use<> {
    let cards: Vec<_> = shell
        .machines
        .iter()
        .map(|machine| machine_card(shell, machine, cx))
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

/// 连接远端：ssh 目标输入框，回车或点"连接"；下方可展开 ssh config 里可快速添加的主机。
fn remote_form(shell: &Shell, cx: &mut Context<Shell>) -> impl IntoElement + use<> {
    // ssh config 里尚未连接的主机，一键添加。
    let quick: Vec<_> = shell
        .ssh_hosts
        .iter()
        .filter(|host| !shell.is_connected(host))
        .map(|host| {
            let target = host.clone();
            let tip: SharedString = format!("连接 {host}").into();
            h_flex()
                .id(SharedString::from(format!("quick-add-{host}")))
                .min_w(px(0.))
                .gap_1p5()
                .px_2p5()
                .py_1()
                .items_center()
                .rounded_md()
                .border_1()
                .border_dashed()
                .border_color(cx.theme().border)
                .text_sm()
                .text_color(cx.theme().muted_foreground)
                .cursor_pointer()
                .hover(|style| {
                    style
                        .bg(cx.theme().accent)
                        .border_color(cx.theme().ring)
                        .text_color(cx.theme().foreground)
                })
                .tooltip(move |window, cx| Tooltip::new(tip.clone()).build(window, cx))
                .on_click(
                    cx.listener(move |shell, _, _, cx| shell.connect_host(target.clone(), cx)),
                )
                .child(
                    Icon::empty()
                        .path(crate::PLUS_ICON)
                        .xsmall()
                        .flex_shrink_0(),
                )
                .child(div().flex_1().min_w(px(0.)).truncate().child(host.clone()))
        })
        .collect();

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
        .when(!quick.is_empty(), |form| {
            // 默认折叠成一行，展开后才占位置。
            let open = shell.quick_add_open;
            form.child(
                h_flex()
                    .id("quick-add-toggle")
                    .pt_1()
                    .gap_1()
                    .items_center()
                    .text_xs()
                    .text_color(cx.theme().muted_foreground)
                    .cursor_pointer()
                    .hover(|style| style.text_color(cx.theme().foreground))
                    .on_click(cx.listener(|shell, _, _, cx| shell.toggle_quick_add(cx)))
                    .child(Icon::empty().xsmall().path(if open {
                        crate::CHEVRON_DOWN_ICON
                    } else {
                        crate::CHEVRON_RIGHT_ICON
                    }))
                    .child(format!("从 ssh config 快速添加（{} 台）", quick.len())),
            )
            // flex_wrap 在此布局下只按一行算高度，会压到下方卡片；固定列数的 grid 高度可靠。
            .when(open, |form| {
                form.child(div().pt_1().grid().grid_cols(4).gap_2().children(quick))
            })
        })
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
    shell: &Shell,
    machine: &Machine,
    cx: &mut Context<Shell>,
) -> impl IntoElement + use<> {
    let filter = shell.agent_filter.as_ref();
    let id = machine.id;
    let label = machine_label(&machine.host);
    let (status, dot) = if machine.installing {
        ("安装 agentdeckd 中…", cx.theme().muted_foreground)
    } else if machine.connecting {
        ("连接中…", cx.theme().muted_foreground)
    } else if machine.daemon_missing() {
        ("未安装 agentdeckd", cx.theme().danger)
    } else if machine.error.is_some() {
        ("连接失败", cx.theme().danger)
    } else {
        ("已连接", cx.theme().success)
    };
    let (install, outdated) = daemon_install_offer(machine);

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
            h_flex()
                .flex_1()
                .gap_2()
                .text_sm()
                .text_color(cx.theme().muted_foreground)
                .child(status)
                .when_some(machine.daemon_version.as_deref(), |line, version| {
                    line.child(format!("· agentdeckd {}", short_version(version)))
                })
                .when(outdated, |line| {
                    line.child(
                        div()
                            .text_color(crate::theme_tokens::WARN)
                            .child(format!("可更新到 v{}", remotes::DAEMON_VERSION)),
                    )
                }),
        )
        .when_some(install, |header, label_text| {
            header.child(
                Button::new(SharedString::from(format!("install-daemon-{label}")))
                    .ghost()
                    .xsmall()
                    .label(if machine.installing {
                        "安装中…"
                    } else {
                        label_text
                    })
                    .disabled(
                        machine.installing || machine.agents.iter().any(|agent| agent.updating),
                    )
                    .tooltip(format!(
                        "下载与桌面端同版本的预编译 agentdeckd v{}，装到该机器的 ~/.local/bin",
                        remotes::DAEMON_VERSION
                    ))
                    .on_click(cx.listener(move |shell, _, _, cx| shell.install_daemon(id, cx))),
            )
        })
        .when(machine.error.is_some() && !machine.installing, |header| {
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
                    .disabled(machine.installing)
                    .when(machine.installing, |button| {
                        button.tooltip("请等待 agentdeckd 安装完成后再断开")
                    })
                    .on_click(cx.listener(move |shell, _, _, cx| shell.remove_machine(id, cx))),
            )
        });

    let agents: Vec<_> = machine
        .agents
        .iter()
        .map(|agent| {
            let filtered =
                filter.is_some_and(|(host, kind)| *host == machine.host && *kind == agent.kind);
            let hint = version_hint(agent, shell.latest_version(agent.kind), cx);
            let armed = shell.update_armed == Some((machine.id, agent.kind));
            agent_row(machine, agent, filtered, hint, armed, cx)
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
            let error = if machine.daemon_missing() {
                "目标机的 login PATH 与 ~/.local/bin 里都找不到 agentdeckd，可点「安装」装上预编译二进制。".to_string()
            } else {
                error
            };
            card.child(
                div()
                    .text_xs()
                    .whitespace_normal()
                    .text_color(cx.theme().danger)
                    .child(error),
            )
        })
        .when_some(machine.install_result.clone(), |card, result| {
            let (text, color) = match result {
                Ok(version) => (format!("安装完成：{version}"), cx.theme().muted_foreground),
                Err(error) => (format!("安装失败：{error}"), cx.theme().danger),
            };
            card.child(
                div()
                    .text_xs()
                    .whitespace_normal()
                    .text_color(color)
                    .child(text),
            )
        })
        .children(agents)
}

/// 远端 daemon 缺失、版本拿不到或旧于桌面端时，给出安装按钮文案；第二项表示是否已知过旧。
fn daemon_install_offer(machine: &Machine) -> (Option<&'static str>, bool) {
    if machine.host.is_none() || machine.connecting {
        return (None, false);
    }
    if machine.daemon_missing() {
        return (Some("安装"), false);
    }
    if machine.daemon_version.is_some()
        && machine.daemon_protocol != Some(u64::from(agentdeck_protocol::PROTOCOL_VERSION))
    {
        return (Some("重装 agentdeckd"), false);
    }
    match machine.daemon_version.as_deref().map(versions::extract) {
        Some(Some(version)) => {
            let outdated = versions::compare(version, remotes::DAEMON_VERSION) == Ordering::Less;
            (outdated.then_some("更新 agentdeckd"), outdated)
        }
        Some(None) => (Some("重装 agentdeckd"), false),
        None => (None, false),
    }
}

/// agent 一行：图标、名称、完整状态、警告与错误；点击只看该机器上该 agent 的会话。
fn agent_row(
    machine: &Machine,
    agent: &AgentHistory,
    filtered: bool,
    hint: Option<(String, gpui::Hsla)>,
    armed: bool,
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
                        })
                        .when_some(hint, |line, (text, color)| {
                            line.child(div().text_xs().text_color(color).child(text))
                        })
                        .when(!agent.warnings.is_empty(), |line| {
                            line.child(compat_badge(&key, agent))
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
                .when_some(agent.update_result.clone(), |details, result| {
                    let (text, color) = match result {
                        Ok(output) => (
                            format!("更新完成：{}", last_line(&output)),
                            cx.theme().muted_foreground,
                        ),
                        Err(error) => (format!("更新失败：{error}"), cx.theme().danger),
                    };
                    details.child(
                        div()
                            .text_xs()
                            .whitespace_normal()
                            .text_color(color)
                            .child(text),
                    )
                })
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

    let updating = agent.updating;
    h_flex()
        .gap_1()
        .items_center()
        .child(row)
        .child(
            Button::new(SharedString::from(format!("update-{key}")))
                .ghost()
                .xsmall()
                .label(if updating {
                    "更新中…"
                } else if armed {
                    "✓"
                } else {
                    "更新"
                })
                .disabled(updating || !machine.can_update_agents())
                .when(armed, |button| button.text_color(cx.theme().success))
                .tooltip(if !machine.can_update_agents() {
                    if machine.daemon_version.is_none() {
                        "正在确认 daemon 协议".to_string()
                    } else {
                        "请先更新或重装 agentdeckd，再更新 CLI".to_string()
                    }
                } else if armed {
                    "再点一次确认更新".to_string()
                } else {
                    format!("在该机器上运行 {} 自带的更新命令", agent_label(kind))
                })
                .on_hover({
                    let shell = cx.entity().downgrade();
                    move |hovered, _, cx| {
                        if !hovered {
                            shell
                                .update(cx, |shell, cx| shell.disarm_update(id, kind, cx))
                                .ok();
                        }
                    }
                })
                .on_click(cx.listener(move |shell, _, _, cx| shell.click_update(id, kind, cx))),
        )
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

/// 兼容性警告收成「图标 + 兼容性」，完整内容放在悬停提示里。
fn compat_badge(key: &str, agent: &AgentHistory) -> impl IntoElement + use<> {
    let messages: Vec<String> = agent.warnings.iter().map(|w| w.message.clone()).collect();
    h_flex()
        .id(SharedString::from(format!("compat-{key}")))
        .gap_1()
        .items_center()
        .text_xs()
        .text_color(crate::theme_tokens::WARN)
        .child(Icon::empty().xsmall().path(crate::ALERT_ICON))
        .child("兼容性")
        .tooltip(move |window, cx| {
            let messages = messages.clone();
            Tooltip::element(move |_, _| {
                v_flex()
                    .max_w(px(420.))
                    .gap_1()
                    .whitespace_normal()
                    .child(div().font_semibold().child("兼容性警告"))
                    .children(messages.iter().map(|message| div().child(message.clone())))
            })
            .build(window, cx)
        })
}

/// "2.1.191 (Claude Code)" / "codex-cli 0.156.1" → "v…"；探测或查询失败（"… unknown"）→ "拿不到版本号"。
fn short_version(raw: &str) -> String {
    if raw.ends_with("unknown") {
        return "拿不到版本号".into();
    }
    versions::extract(raw).map_or_else(|| raw.into(), |v| format!("v{v}"))
}

/// 与 npm 最新版比较后的提示；安装版本未知或比最新还新（预览通道等）时不下结论。
fn version_hint(
    agent: &AgentHistory,
    latest: Option<&Result<String, String>>,
    cx: &Context<Shell>,
) -> Option<(String, gpui::Hsla)> {
    let installed = versions::extract(agent.version.as_deref()?)?;
    match latest? {
        Err(_) => Some(("无法获取最新版本".into(), cx.theme().muted_foreground)),
        Ok(latest) => match versions::compare(installed, latest) {
            Ordering::Less => Some((
                format!("可更新到 v{latest}"),
                crate::theme_tokens::WARN.into(),
            )),
            Ordering::Equal => Some(("已是最新".into(), cx.theme().success)),
            Ordering::Greater => None,
        },
    }
}

/// 更新命令的输出可能多行，只取最后一行非空内容作摘要。
fn last_line(output: &str) -> &str {
    output
        .lines()
        .rev()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("无输出")
}

#[cfg(test)]
mod tests {
    #[test]
    fn short_version_drops_product_suffix() {
        assert_eq!(super::short_version("2.1.191 (Claude Code)"), "v2.1.191");
        assert_eq!(super::short_version("codex-cli 0.156.1"), "v0.156.1");
        assert_eq!(super::short_version("codex unknown"), "拿不到版本号");
        assert_eq!(super::short_version("unknown"), "拿不到版本号");
    }
}
