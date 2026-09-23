mod composer;
mod daemon;
mod shell;
mod sidebar;
mod transcript;

use std::env;

use gpui::{App, Application, TitlebarOptions, WindowOptions, point, prelude::*, px, size};
use gpui_component::Root;

use shell::Shell;

const SELFCHECK_REPORT: &str = r#"{"status":"ok","surface":"desktop","ui":"gpui"}"#;

fn open_main_window(cx: &mut App, show: bool) {
    cx.open_window(
        WindowOptions {
            show,
            focus: show,
            titlebar: Some(TitlebarOptions {
                title: Some("AgentDeck".into()),
                appears_transparent: true,
                traffic_light_position: Some(point(px(16.), px(16.))),
            }),
            window_min_size: Some(size(px(900.), px(620.))),
            ..Default::default()
        },
        |window, cx| {
            // 隐藏窗口只出现在 selfcheck 路径；那里不连接 daemon。
            // 开发者模式（FPS 叠加层）在 debug 构建默认开启，release 用 AGENTDECK_DEBUG=1 打开。
            let dev_mode = show
                && (cfg!(debug_assertions) || env::var("AGENTDECK_DEBUG").as_deref() == Ok("1"));
            let view = cx.new(|cx| Shell::new(window, show, dev_mode, cx));
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
            r#"{"status":"ok","surface":"desktop","ui":"gpui"}"#
        );
    }
}
