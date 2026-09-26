//! 把设计系统 codex 主题（designs/agentdeck-design-system/tokens/tokens.json）映射到 gpui-component。
//! codex 只有深色定义，故锁定深色，不跟随系统外观。

use gpui::{App, Hsla};
use gpui_component::{Colorize, Theme, ThemeMode};

use crate::theme_tokens as tokens;

pub fn apply(cx: &mut App) {
    // Theme::change 会恢复默认配置，必须先切换模式，再应用 token 映射。
    Theme::change(ThemeMode::Dark, None, cx);
    let t = Theme::global_mut(cx);

    let text = tokens::TEXT.into();
    let accent: Hsla = tokens::ACCENT.into();
    let surface2: Hsla = tokens::SURFACE2.into();
    let warning: Hsla = tokens::WARN.into();

    t.background = tokens::BG.into();
    t.foreground = text;
    t.muted = tokens::SURFACE.into();
    t.muted_foreground = tokens::TEXT2.into();
    t.border = tokens::BORDER.into();
    t.input = tokens::BORDER.into();
    t.ring = accent;
    t.caret = accent;
    t.selection = tokens::ACCENT_WEAK.into();

    t.sidebar = tokens::SIDEBAR_BG.into();
    t.sidebar_foreground = text;
    t.sidebar_border = tokens::BORDER.into();

    // Ghost 悬停/按下由组件从 secondary 派生；只有选中态使用 secondary_active。
    t.secondary = surface2;
    t.secondary_hover = surface2.lighten(0.15);
    t.secondary_active = surface2.lighten(0.35);
    t.secondary_foreground = text;
    t.accent = surface2;
    t.accent_foreground = text;
    t.popover = tokens::SURFACE.into();
    t.popover_foreground = text;

    t.primary = accent;
    t.primary_hover = accent.lighten(0.1);
    t.primary_active = accent.darken(0.1);
    t.primary_foreground = tokens::TEXT_ON_ACCENT.into();

    t.warning = warning;
    t.warning_hover = warning.lighten(0.1);
    t.warning_active = warning.darken(0.1);
    t.warning_foreground = tokens::TEXT_ON_ACCENT.into();
    t.danger = tokens::DANGER.into();
    t.success = tokens::SUCCESS.into();
    t.info = tokens::INFO.into();
}
