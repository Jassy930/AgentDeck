use std::env;

use gpui::{
    App, Application, Context, IntoElement, ParentElement, Render, Window, WindowOptions,
    prelude::*,
};
use gpui_component::{
    Root,
    button::{Button, ButtonVariants},
    v_flex,
};

const SELFCHECK_REPORT: &str =
    r#"{"status":"ok","surface":"desktop","ui":"gpui","relay":"disabled"}"#;

struct AgentDeckView;

impl Render for AgentDeckView {
    fn render(&mut self, _: &mut Window, _: &mut Context<Self>) -> impl IntoElement {
        v_flex()
            .size_full()
            .items_center()
            .justify_center()
            .gap_2()
            .child("AgentDeck")
            .child("GPUI 桌面端已启动")
            .child(
                Button::new("quit")
                    .primary()
                    .label("关闭")
                    .on_click(|_, _, cx| cx.quit()),
            )
    }
}

fn open_main_window(cx: &mut App, show: bool) {
    cx.open_window(
        WindowOptions {
            show,
            focus: show,
            ..Default::default()
        },
        |window, cx| {
            let view = cx.new(|_| AgentDeckView);
            cx.new(|cx| Root::new(view, window, cx))
        },
    )
    .expect("open AgentDeck window");
}

fn main() {
    let selfcheck = env::args_os().any(|arg| arg == "--selfcheck");

    Application::new().run(move |cx| {
        gpui_component::init(cx);

        if selfcheck {
            open_main_window(cx, false);
            println!("{SELFCHECK_REPORT}");
            cx.quit();
            return;
        }

        open_main_window(cx, true);
        cx.activate(true);
    });
}

#[cfg(test)]
mod tests {
    use super::SELFCHECK_REPORT;

    #[test]
    fn selfcheck_report_declares_the_minimal_scope() {
        assert_eq!(
            SELFCHECK_REPORT,
            r#"{"status":"ok","surface":"desktop","ui":"gpui","relay":"disabled"}"#
        );
    }
}
