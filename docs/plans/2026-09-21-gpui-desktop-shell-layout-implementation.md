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
- 不引入 vendor 分支。空态两张接入卡片与侧栏本机 Agent 状态共用 `CONNECTORS`
  常量数组，UI 不按 vendor 写 `if`/`match`（N1、N2）。

## Architecture

```text
agentdeck-desktop
├─ main.rs      Application / 透明标题栏窗口 / --selfcheck（报告不变）
└─ Shell (Entity, Render)
   ├─ sidebar.rs   全高侧栏，条目回调走 cx.listener 改 Shell.stage
   ├─ shell.rs     Stage::Empty | Stage::Session，空态与会话态两套主区
   └─ composer.rs  圆角 composer，接收 Entity<InputState> 与项目上下文
```

`Shell` 持有唯一状态 `stage` 和 composer 的 `InputState`；`sidebar` / `composer` 只是
渲染函数，不各自持有状态。两种形态共用同一个 composer entity，输入内容在切换时保留。
`Stage::Session` 同时保存示例标题与项目，侧栏选中态由当前 stage 派生，不依赖键盘焦点。

## Tech Stack

沿用 P0 锁定版本 `gpui = 0.2.2`、`gpui-component = 0.5.1`。注意该版本的输入组件叫
`gpui_component::input::Input`（不是 `TextInput`），主题颜色没有 `card` 字段，卡片背景
用 `secondary`。

## 文件清单

- `agentdeck-desktop/src/main.rs`：挂载 `Shell`；`TitlebarOptions { appears_transparent,
  traffic_light_position }`；`window_min_size` 900×620。`SELFCHECK_REPORT` 保持原样。
- `agentdeck-desktop/src/shell.rs`：`Stage` 枚举与标题、项目访问方法，`Shell` 状态与两套主区渲染、
  `CONNECTORS` 常量、接入卡片。
- `agentdeck-desktop/src/sidebar.rs`：侧栏宽度 248、顶部 44px 红绿灯留白、`PROJECTS` 占位、
  新建会话按钮。
- `agentdeck-desktop/src/composer.rs`：圆角 composer、项目与 Agent 上下文、预览说明和禁用发送按钮。

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

布局改动额外做目视检查：启动 `dist/AgentDeck.app` 并确认前台，优先通过真实 UI 的
Tab / Shift-Tab / Return 进入空态与会话态，再用窗口级截图确认侧栏、主区及 composer。
截图使用最终代码构建的窗口，不改初始 `stage`；环境限制下无法完成的交互标为未验证。

2026-09-21 本机验证结果：desktop 单测 2 passed；selfcheck 输出
`{"status":"ok","surface":"desktop","ui":"gpui"}` 且退出码 0；bundle verify 三项 OK；
空态与会话态截图均符合预期。

## 追加切片（同日，第二轮）

补上第一轮遗留的两个可用性缺口，并把侧栏从"按钮 + 一组项目"推进到 Codex Desktop 的
两层结构。

**文件变更**

- `sidebar.rs`：加品牌行（`AgentDeck` + `本机`，对应 Codex 侧栏顶部 workspace 位，
  当前不可切换）、快捷入口（新建会话可点；搜索禁用）、`PINNED_SESSIONS`
  置顶会话分组与 `PROJECTS` 项目分组两层列表、底部本机 Agent 状态；导出 `titlebar_area()`。
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
  非 macOS 平台。macOS 的窗口拖动仍由系统标题栏区域处理。
  同一文件里的 `titlebar_double_click` 有真实 macOS 实现，读取
  `AppleActionOnDoubleClick` 偏好；实际双击交互仍需单独验收。
- `font_semibold` 来自 `gpui_component::StyledExt`，`on_double_click` 来自
  `gpui_component::InteractiveElementExt`，两个 trait 都要显式 import。

**验证边界（重要）**

- 目视验证改用**窗口级截图**：`uv run --with pyobjc-framework-Quartz` 取窗口 ID，再
  `screencapture -x -o -l <winid>`。这样不依赖屏幕可见性，也比全屏截图清晰。
- 2026-09-22 修复前 UI 审查已实际验证直接键入、中文多行粘贴、键盘切换会话与返回
  空态；该结果不替代后续变更验收。窗口鼠标拖动与双击仍无实际验收证据。

## 界面审查修复（2026-09-22）

- 新建会话、项目与置顶条目保留持续选中态；会话态顶部补齐系统标题栏双击处理。
- composer 展示当前示例项目或“未选择”及 Agent 未连接，明确标为界面预览；发送、
  搜索禁用，模型、审批和沙箱改为暂不可用说明。
- 首页和侧栏共用两家 Agent 的“尚未接入”状态，示例条目明确标注；提高分组与状态字号。
- 两种形态继续共用草稿，不接 daemon，也不提供真实 Agent 选择。

本轮验证：

- `cargo test --locked -p agentdeck-desktop`：2 passed；desktop selfcheck 与真实 bundle
  verify 均通过，运行路径为当前 checkout 的 `dist/AgentDeck.app`。
- 实际窗口确认空态与会话态、禁用发送和搜索的样式、本机 Agent 状态及项目上下文；
  键盘和鼠标均可切换示例，焦点移入输入框后侧栏仍保持选中，返回空态保留草稿。
- 会话顶部鼠标双击已验证缩放与恢复；测试草稿已清空。当前仍不验证真实 Agent 链路。

## 后续

- 侧栏置顶会话、项目区、本机 Agent 状态和 composer 接入真实数据时，替换对应示例数据，
  保持"数据驱动、不加 vendor 分支"的形状。
- 真实能力控件应按 `SessionCapabilities` 由 typed router 装配进 composer 工具行。
- 图标资源：注册 `AssetSource` 后可用 `IconName::*` 替换侧栏纯文字行。
