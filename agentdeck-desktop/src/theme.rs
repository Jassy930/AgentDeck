//! 把设计系统 codex 主题（designs/agentdeck-design-system/tokens/tokens.json）映射到 gpui-component。
//! codex 只有深色定义，故锁定深色，不跟随系统外观。
// ponytail: 手写映射，tokens.json 改色时需同步；漂移成问题再让 build.mjs 生成。

use gpui::{App, Hsla, rgb, rgba};
use gpui_component::{Theme, ThemeMode};

fn c(hex: u32) -> Hsla {
    rgb(hex).into()
}

pub fn apply(cx: &mut App) {
    Theme::change(ThemeMode::Dark, None, cx);
    let t = Theme::global_mut(cx);

    let text: Hsla = rgba(0xffffffed).into(); // text 0.93
    let text2: Hsla = rgba(0xffffff99).into(); // text2 0.60
    let accent = c(0xff7d2e);

    t.background = c(0x131313);
    t.foreground = text;
    t.muted = c(0x1c1c1c); // surface：卡片、composer
    t.muted_foreground = text2;
    t.border = c(0x2f2f2f);
    t.input = c(0x2f2f2f);
    t.ring = accent;
    t.caret = accent;
    t.selection = rgba(0xff7d2e40).into();

    t.sidebar = c(0x202121);
    t.sidebar_foreground = text;
    t.sidebar_border = c(0x2f2f2f);

    // ghost 按钮悬停 / 选中走 secondary_*，对应 surface2 一级。
    t.secondary = c(0x262626);
    t.secondary_hover = c(0x2c2c2c);
    t.secondary_active = c(0x333333);
    t.secondary_foreground = text;
    t.accent = c(0x262626);
    t.accent_foreground = text;
    t.popover = c(0x1c1c1c);
    t.popover_foreground = text;

    t.primary = accent;
    t.primary_hover = c(0xff8f4a);
    t.primary_active = c(0xe86a1c);
    t.primary_foreground = c(0x1c0f04);

    // 警告用琥珀色，与品牌橙区分。
    t.warning = c(0xf5b544);
    t.warning_hover = c(0xf7c263);
    t.warning_active = c(0xe0a232);
    t.warning_foreground = c(0x1f1503);
    t.danger = c(0xff5c5c);
    t.success = c(0x57cf7c);
    t.info = c(0x4a9bff);
}
