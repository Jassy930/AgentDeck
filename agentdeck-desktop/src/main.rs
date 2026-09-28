mod daemon;
mod machines;
mod remotes;
mod shell;
mod sidebar;
mod theme;
mod theme_tokens;
mod transcript;
mod versions;

use std::borrow::Cow;
use std::env;

use gpui::{
    App, Application, AssetSource, KeyBinding, Menu, MenuItem, SharedString, TitlebarOptions,
    WindowOptions, actions, point, prelude::*, px, size,
};
use gpui_component::Root;

use shell::Shell;

actions!(agentdeck, [Quit]);

/// 编译期嵌入的 SVG 图标；gpui 按路径向 AssetSource 取，渲染时随文字颜色着色。
struct Assets;

pub const SERVER_ICON: &str = "icons/server.svg";
pub const PLUS_ICON: &str = "icons/plus.svg";
pub const CHEVRON_RIGHT_ICON: &str = "icons/chevron-right.svg";
pub const CHEVRON_DOWN_ICON: &str = "icons/chevron-down.svg";
pub const ALERT_ICON: &str = "icons/triangle-alert.svg";

impl AssetSource for Assets {
    fn load(&self, path: &str) -> gpui::Result<Option<Cow<'static, [u8]>>> {
        let bytes: &'static [u8] = match path {
            SERVER_ICON => include_bytes!("../../assets/icons/server.svg"),
            PLUS_ICON => include_bytes!("../../assets/icons/plus.svg"),
            CHEVRON_RIGHT_ICON => include_bytes!("../../assets/icons/chevron-right.svg"),
            CHEVRON_DOWN_ICON => include_bytes!("../../assets/icons/chevron-down.svg"),
            ALERT_ICON => include_bytes!("../../assets/icons/triangle-alert.svg"),
            _ => return Ok(None),
        };
        Ok(Some(Cow::Borrowed(bytes)))
    }

    fn list(&self, _path: &str) -> gpui::Result<Vec<SharedString>> {
        Ok([
            SERVER_ICON,
            PLUS_ICON,
            CHEVRON_RIGHT_ICON,
            CHEVRON_DOWN_ICON,
            ALERT_ICON,
        ]
        .map(SharedString::from)
        .to_vec())
    }
}

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

    Application::new().with_assets(Assets).run(move |cx| {
        gpui_component::init(cx);
        theme::apply(cx);
        cx.on_action(|_: &Quit, cx| cx.quit());
        cx.bind_keys([KeyBinding::new("cmd-q", Quit, None)]);
        cx.set_menus(vec![Menu {
            name: "AgentDeck".into(),
            items: vec![MenuItem::action("退出 AgentDeck", Quit)],
        }]);

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
