# GPUI 桌面外壳布局实施

日期：2026-09-21

## Goal

把 GPUI 桌面端从"单按钮最小壳"推进到与 Codex Desktop 一致的外壳布局骨架，为后续
纵向切片准备稳定的挂载点。本切片只做布局与形态切换，不接入任何真实数据。

对齐参照是 `2026-07-01-codex-desktop-chrome-sync.md` 记录的 Codex Desktop 视觉范式：
透明标题栏 + 全高左侧栏；空态居中大标题、圆角 composer、接入卡片；会话态 thread
header + 底部悬浮 composer。该文档描述的是已移除的 AppKit 实现，本切片只复用它定义
的视觉范式，不复用其代码。

## 非目标

- 不连接 daemon、IPC 或 typed local client（沿用 `2026-08-17-gpui-desktop-reset-design.md`
  的非目标）。
- 不渲染真实会话、历史、消息流、审批或 Markdown。
- 不把 `designs/agentdeck-design-system` 的 token 桥接进 Rust；颜色全部取自
  `gpui_component::ActiveTheme`。
- 不引入 vendor 分支。空态两张接入卡片由 `CONNECTORS` 常量数组驱动，UI 不按 vendor
  写 `if`/`match`（N1、N2）。

## Architecture

```text
agentdeck-desktop
├─ main.rs      Application / 透明标题栏窗口 / --selfcheck（报告不变）
└─ Shell (Entity, Render)
   ├─ sidebar.rs   全高侧栏，条目回调走 cx.listener 改 Shell.stage
   ├─ shell.rs     Stage::Empty | Stage::Session，空态与会话态两套主区
   └─ composer.rs  圆角 composer，持有 Entity<InputState>
```

`Shell` 持有唯一状态 `stage` 和 composer 的 `InputState`；`sidebar` / `composer` 只是
渲染函数，不各自持有状态。两种形态共用同一个 composer entity，输入内容在切换时保留。

## Tech Stack

沿用 P0 锁定版本 `gpui = 0.2.2`、`gpui-component = 0.5.1`。注意该版本的输入组件叫
`gpui_component::input::Input`（不是 `TextInput`），主题颜色没有 `card` 字段，卡片背景
用 `secondary`。

## 文件清单

- `agentdeck-desktop/src/main.rs`：挂载 `Shell`；`TitlebarOptions { appears_transparent,
  traffic_light_position }`；`window_min_size` 900×620。`SELFCHECK_REPORT` 保持原样。
- `agentdeck-desktop/src/shell.rs`：`Stage` 枚举与 `header_title()`、`Shell` 状态与两套主区渲染、
  `CONNECTORS` 常量、接入卡片。
- `agentdeck-desktop/src/sidebar.rs`：侧栏宽度 248、顶部 44px 红绿灯留白、`PROJECTS` 占位、
  新建会话按钮。
- `agentdeck-desktop/src/composer.rs`：圆角 composer 与 `TOOLS` 工具行占位。

## 已知坑点

- Rust 2024 的 `impl Trait` 捕获规则会让"在循环里用 `&mut Context` 生成子元素"报借用冲突。
  返回类型写成 `impl IntoElement + use<>` 即可显式排除捕获。
- 主区必须显式 `.h_full()`。只写 `.flex_1()` 时子树高度按内容计算，会被父 `h_flex`
  垂直居中，表现为 thread header 浮在窗口中部。

## 验证

```bash
cargo test -p agentdeck-desktop
cargo run -p agentdeck-desktop -- --selfcheck
./script/build_and_run.sh --verify
```

布局改动额外做目视检查：启动 `dist/AgentDeck.app` 后 `screencapture` 截图确认侧栏、
空态、会话态三块实际渲染。会话态截图通过临时把初始 `stage` 改为 `Stage::Session`
获得，截图后还原；不要用模拟鼠标点击驱动 GPUI 窗口（GPUI 不响应 AX click，坐标点击
会落到其他应用上）。

2026-09-21 本机验证结果：desktop 单测 2 passed；selfcheck 输出
`{"status":"ok","surface":"desktop","ui":"gpui"}` 且退出码 0；bundle verify 三项 OK；
空态与会话态截图均符合预期。

## 追加切片（同日，第二轮）

补上第一轮遗留的两个可用性缺口，并把侧栏从"按钮 + 一组项目"推进到 Codex Desktop 的
两层结构。

**文件变更**

- `sidebar.rs`：加品牌行（`AgentDeck` + `本机`，对应 Codex 侧栏顶部 workspace 位，
  当前不可切换）、快捷入口（新建会话可点；搜索为无行为占位）、`PINNED_SESSIONS`
  置顶会话分组与 `PROJECTS` 项目分组两层列表、底部账号区；导出 `titlebar_area()`。
- `shell.rs`：`Shell::new` 里对 composer 调一次 `focus`，打开窗口即可直接输入；
  空态主区顶部加 `titlebar_area`（会话态由 52px header 自己吃掉这段高度）。

**刻意不做**

- 不照搬 Codex 侧栏的 Pull Request / 定时任务 / 插件 / 探索入口 —— 那是 Codex 的产品
  特性，AgentDeck 不承诺。
- 不加图标。gpui-component 0.5.1 不内置 SVG 资源，`IconName::*` 需要应用自己注册
  `AssetSource` 提供 `icons/*.svg`；接图标是独立切片。
- 形态切换时不重新聚焦 composer，留到接入真实会话时一并处理。

**坑点**

- **gpui 0.2.2 在 macOS 上无法把任意区域声明为窗口拖动区**。查平台层可证：
  `platform/mac/window.rs` 的 `on_hit_test_window_control` 是空实现（`{}`），
  `start_window_move` 只有 `platform.rs` 里的 trait 默认空实现且 macOS 未覆盖，
  两者都只服务 Windows/Linux。gpui-component 的 `TitleBar` 同时用这两条路也是为了
  非 macOS 平台。曾一度按 `window_control_area(WindowControlArea::Drag)` 实现并写进
  文档，实际是死代码，已删除。macOS 的窗口拖动仍由系统标题栏区域处理。
  同一文件里的 `titlebar_double_click` 反而**有**真实 macOS 实现（读
  `AppleActionOnDoubleClick` 偏好），所以双击行为是真的。
- `font_semibold` 来自 `gpui_component::StyledExt`，`on_double_click` 来自
  `gpui_component::InteractiveElementExt`，两个 trait 都要显式 import。

**验证边界（重要）**

- 目视验证改用**窗口级截图**：`uv run --with pyobjc-framework-Quartz` 取窗口 ID，再
  `screencapture -x -o -l <winid>`。这样不依赖屏幕可见性，也比全屏截图清晰。
  2026-09-21 全屏截图被 ChatGPT 桌面端的 "ChatGPT is Using Your Mac" 遮罩挡住，
  窗口级截图不受影响。
- **未验证项**：composer 实际键入与聚焦、窗口鼠标拖动。聚焦本可用"间隔连拍看光标
  闪烁"零成本判定，但未激活窗口不画闪烁光标（三帧截图字节完全一致），当时屏幕被
  ChatGPT 桌面端接管、窗口无法成为前台，故判不了；注入键盘事件同理不适合做。

## 后续

- 侧栏置顶会话、项目区、账号区和 composer 工具行接入真实数据时，替换对应常量数组，
  保持"数据驱动、不加 vendor 分支"的形状。
- 真实能力控件应按 `SessionCapabilities` 由 typed router 装配进 composer 工具行。
- 图标资源：注册 `AssetSource` 后可用 `IconName::*` 替换侧栏纯文字行。
