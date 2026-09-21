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

## 后续

- 侧栏项目区、账号区和 composer 工具行接入真实数据时，替换对应常量数组，
  保持"数据驱动、不加 vendor 分支"的形状。
- 真实能力控件应按 `SessionCapabilities` 由 typed router 装配进 composer 工具行。
- 透明标题栏下窗口拖动区域尚未处理，接入真实 header 内容时一并补。
