# AgentDeck macOS 前端重写为 AppKit 设计

## 背景

AgentDeck 当前的 macOS 前端以 SwiftUI 为主（`SessionView.swift` 约 1523 行、34 个 View），辅以局部 AppKit（`StreamingTextView` 的 NSTextView 流式内核、`SessionTextSelectionCoordinator`、`RailInteractionNSView`、`NSImage`/`NSOpenPanel`），并依赖纯 SwiftUI 第三方库 `Textual` 渲染 markdown。

模型/逻辑层（`SessionModel / WorkbenchModel / ThreadRuntimeModel / AgentItemReducer / ConversationTurn / ConversationRailNavigator / ToolPresentation / HistoryModel / DaemonClient 全栈 / StreamingTextBuffer / TurnJumpRailLayout`）是框架无关的，使用 Swift Observation 框架（`@Observable`），与 UI 框架解耦。

这是「统一接口层」之后的第 2 个子项目（见 `docs/plans/2026-06-29-unified-interface-cli-design.md` 的范围说明）。目标是把前端从 SwiftUI **整体重写为纯 AppKit**，移除对 SwiftUI 与 `Textual` 的依赖，同时**保持功能/视觉对等**、**模型层零改动**，并补上子项目 1 推迟下来的 **Swift 侧与协议契约的一致性测试**。

## 目标

- 前端视图层**整体重写为纯 AppKit**：入口从 SwiftUI `App` 改为 `NSApplication` + `NSApplicationDelegate` + `NSWindow` + `NSViewController` 树。
- **移除 SwiftUI 与 `Textual` 依赖**：markdown 改用原生 `NSAttributedString` 渲染（喂给复用的 NSTextView）。
- **功能/视觉对等**：1:1 复现现有全部用户可见功能与视觉（含会话流式、审批、历史侧栏、TurnJumpRail、各 item-kind 行、rich markdown、文本选择、空状态、rename、media 预览、状态栏、profile 窗口标题、Cmd-Q）。
- **会话流虚拟化**：会话 transcript 用视图型 `NSTableView`（行复用），支持超长 transcript。
- **历史侧栏用 `NSOutlineView` 源列表**（项目组 → 线程，长期方案）。
- **模型层与 DaemonClient 栈零改动**，AppKit 侧用统一 observation 绑定助手消费 `@Observable`。
- **纳入 Swift↔契约一致性测试**：以子项目 1 提交的 schema 为基准，`swift test` 校验 Swift 解码与契约一致。
- 保留 headless 模式（`--selfcheck`、`--diagnostics-report`）。

## 非目标

- 不改后端 / daemon / 协议 / IPC 线格式。
- 不重构模型层、不改 DaemonClient。
- 不重设计 UX（像素级复现现有布局；不借机改交互）。
- 不做 `.app` bundle 打包 / 签名 / 分发；沿用现有 SwiftPM 可执行 + 程序化前台激活（`setActivationPolicy(.regular)`）。
- 不新增用户可见功能。
- 不引入新的运行时依赖（markdown 用系统 `NSAttributedString`，不引第三方）。

## 架构方案与边界

### 入口切换

`main.swift` 现有的 `AgentDeckApp: App` / `WindowGroup` / `@NSApplicationDelegateAdaptor` / `AgentDeckApp.main()` 改为经典 AppKit 启动：

```text
main.swift
  ├─ 解析 profile；headless 分流（--selfcheck / --diagnostics-report 在建窗口前 return，逻辑不变）
  └─ 否则：NSApplication.shared，设置 AppDelegate，NSApp.run()

AppDelegate: NSApplicationDelegate
  ├─ applicationDidFinishLaunching: setActivationPolicy(.regular) + activate
  ├─ 建 NSWindow(title = profile.windowTitle)，contentViewController = SessionViewController
  └─ Cmd-Q：主菜单 / key 等价物 → NSApp.terminate
```

### 视图层（NSViewController 树，镜像现有区域）

```text
NSWindow
 └─ SessionViewController            顶层容器：状态栏 + 主体
     ├─ StatusBarView (NSView)        相位点 / 状态文本 / 经过秒数 / 项目名 / New session
     └─ NSSplitViewController
         ├─ HistorySidebarViewController   NSSearchField + NSOutlineView（项目组→线程）
         └─ ConversationViewController     会话流(NSTableView) + 输入栏 + 审批卡 + TurnJumpRail
```

### 模型复用与边界

- 模型全部 `@Observable`，AppKit 侧通过统一的 `ObservationBinder`（§Observation 绑定）消费，模型代码零改动。
- `SessionModel` 仍是 ViewController 的单一状态源（已聚合 history / phase / items / timing）。ViewController 职责：**读模型 → 命令式刷新 NSView**。
- DaemonClient 已在 MainActor 投递 `session/event`，MainActor hop 不变。
- 中立边界不变：UI 仍只消费中立 `AgentItem`，不解析供应商 JSON。

## 会话流：虚拟化 NSTableView

会话 transcript 用 `NSScrollView` + **视图型 `NSTableView`（单列，行复用）**。

### 行模型

把 `makeConversationTurns(...)` 摊平成 `[DisplayRow]`，每行粒度小、可复用，同时承载 turn 视觉分组：

- 变体：`.userPrompt(turnId, UIItem)`、`.assistantItem(turnId, UIItem, kind)`、`.approval(ActionRequest)`、`.error(...)`、`.warning(...)`。
- 每行携带 `firstInTurn` / `lastInTurn` 标志，用于左 accent 条、turn 间距等 D3/D7 视觉（「只有审批是卡片」）。
- 每个 kind 一个 reuse identifier（`makeView(withIdentifier:)` 按 kind 回收 cell 视图）。

### 行高（虚拟化的关键）

- `tableView(_:heightOfRow:)` + **高度缓存**，键 = `rowId × contentVersion × width`。
- 宽度变化（表格 resize）→ 失效缓存 + 重算可见行高。
- 某条流式内容变化 → bump 该 item 的 `contentVersion`，`noteHeightOfRows(withIndexesChanged:)`（不带动画）。
- 高度由共享的**文本测量助手**计算（`NSLayoutManager.usedRect(for:)` 或 `NSAttributedString.boundingRect`），与 cell 渲染同源避免漂移。

### 流式 + 复用

- cell 绑定某 `UIItem` 时订阅其 `StreamingTextBuffer`；复用重绑到别的 item 时退订旧的、订阅新的。
- `StreamingTextBuffer` 存在模型里（跨复用持久），滚走再回来显示当前内容。
- buffer 通知 `append`/`replace`（针对当前绑定 item）时：更新 cell 的 NSTextView，并在高度变化时请求 controller `noteHeightOfRows` 该行。

### disclosure 展开态与延迟物化

- 展开/折叠态存模型（`SessionModel`/`UIItem`），不在 cell——复用不丢状态。
- 切换 → 改模型 → `noteHeightOfRows` 该行。
- 大输出 / diff 缓冲沿用「首次展开才物化」的延迟语义。

### 选择协调器

- 单活选择跨可见 cell 的 NSTextView：cell 复用时注销旧 NSTextView、注册新（`SessionTextSelectionCoordinator` 本就 AppKit，去掉其 NSViewRepresentable 包装后直接用）。

### 滚动定位 / TurnJumpRail

- 观察 `scrollView.contentView.boundsDidChange` 计算视口顶部可见行 → 映射其 `turnId` → 驱动 rail 选中态（替代 SwiftUI 的 `PreferenceKey` scroll spy）。
- scroll-to-latest：`scrollRowToVisible(lastRow)`（可选 Core Animation）。

### 追加与节流

- 新 item / 新 delta：`insertRows(at:)` / `reloadData(forRowIndexes:columnIndexes:)` + `noteHeightOfRows`，沿用现有模型 30fps flush 节流。

## 历史侧栏：NSOutlineView 源列表

- `NSOutlineView`，`selectionHighlightStyle = .sourceList`，视图型、行复用。
- 顶层 = 项目组（group row）；子项 = 线程行：agent 图标（`HistoryAgentImageCache`，已用 `NSImage`）、runtime 相位点、未读点、标题/元信息。
- `NSSearchField` 绑 `historySearchTerm`，过滤模型后 reload。
- 行 `contextMenu`：Rename（`NSAlert` + accessory `NSTextField`）/ Archive（`WorkbenchModel`/`DaemonClient`）。
- 项目组行 `+`：在该项目目录新建会话。
- 加载中 / 错误 / 空态：复现现有提示文案。

## 原生 Markdown 渲染单元

新增纯函数式、可单测的 `MarkdownAttributedStringBuilder`：

- 输入 markdown 文本 → `NSAttributedString`，喂给复用的 NSTextView。
- 底座：`NSAttributedString(markdown:options:)`（inline 强调 / 段落 / 列表 / 链接 / 行内与块代码）+ 自定义段落样式、字体、颜色以匹配现有视觉；代码用等宽 + 背景；链接可点。
- 流式：`StreamingTextBuffer` 累积文本 → builder 重算 attributed string → NSTextView 替换（沿用现有 append/replace 节奏）。
- 取舍：markdown 表现力以系统 `NSAttributedString(markdown:)` 能力为界；高级语法（如表格）需自定义渲染或降级为纯文本，本轮**降级为纯文本**并在 builder 内集中处理（避免散落）。

## Observation → AppKit 绑定

- 统一助手 `ObservationBinder`：`withObservationTracking { 读模型字段 } onChange: { 调度到 MainActor → 调用对应区域的 reload/refresh }`，并在每次回调后**重新 arm**（Observation 的 onChange 是一次性的）。
- 每个 ViewController 声明「关心哪些读取 → 刷哪个区域」，避免散落的手写 KVO。
- 绑定助手的 arm / 一次性 onChange / re-arm 行为有单测覆盖。

## Swift↔契约一致性测试（纳入子项目 1 推迟项）

- 保留手写 Swift 类型，新增 conformance 测试（`swift test`）：以仓库内 `protocol/agentdeck/agentdeck-protocol.schema.json` 为基准，断言 Swift 侧 `IpcMessage`/`AgentItem` 等的**字段名、`kind` 取值集合、可选性**与契约一致——契约里有的 kind/字段 Swift 解码器都覆盖，Swift 期望的字段名与 schema 一致。
- 目的：子项目 1 协议 schema 变化时由 `swift test` 失败暴露，而非线上静默漏解。
- 形态：读取仓库内 schema 文件做结构断言，轻量、不引 codegen 工具链。

## 错误处理与可观测性

- A1 daemon 生命周期仍由 DaemonClient/transport 负责，UI 重写不碰。
- 相位 FSM、`ready`/`turnComplete` 顺序、审批流、未留痕 warning 全部来自模型层，行为不变。
- 失败可见、不静默挂起（Eng premise 9）：IPC 错误、daemon 断连、解码失败仍走现有模型错误/警告路径并在 UI 显式呈现。
- headless 自检 / 诊断报告路径保持可跑。

## 测试与验收

### 测试分层

- **存活不变（模型/逻辑层）**：`IpcTests`、`DaemonClientTests`、`DaemonClientBaselineTests`、`ConversationRailNavigatorTests`、`ToolPresentationTests` 原样通过。`ConversationTurn` 分组、`TurnJumpRailLayout` 几何等纯逻辑测试保留。
- **替换**：`TextualCompatibilityTests`（构造 SwiftUI 视图）→ 改为 `MarkdownAttributedStringBuilder` 单测 + 行 presentation 单测。
- **新增纯单元测试**：markdown builder（markdown→attributed string 的关键样式与降级）、`DisplayRow` 摊平映射、行高测量助手、`ObservationBinder` 的 arm/onChange/re-arm。
- **视图接线**：`swift run AgentDeck`（dev profile）手动验证关键流程（选目录→流式会话→审批→历史打开→续聊→搜索/rename/archive→rail 导航）。

### 验证命令

```bash
swift build
swift test
swift run AgentDeck -- --selfcheck
swift run AgentDeck -- --diagnostics-report --json
cargo test            # 确认后端 / 契约未被牵动
scripts/verify-agent-docs.sh
```

### 验收标准

- `Package.swift` 移除 `Textual` 依赖；全仓库无 `import SwiftUI`（除非过渡期被显式记录，目标是零）。
- `swift build` / `swift test` 通过；模型层测试零改动通过。
- 现有用户可见功能在 AppKit 版逐项可用（对照 spec 的功能清单手动核验）。
- 会话流在长 transcript 下保持流畅（虚拟化生效：仅可见行有 cell/NSTextView）。
- markdown 消息渲染视觉与现状基本一致；高级语法降级为纯文本不报错。
- Swift↔契约一致性测试存在并通过；故意改坏 schema 时该测试失败。
- headless `--selfcheck` / `--diagnostics-report` 仍可跑。

## 文件结构（新增 / 改造 / 删除）

- **删除（SwiftUI）**：`SessionView.swift`、`MessageRoleViews.swift`、`RichMessageView.swift`；`main.swift` 的 SwiftUI App 部分；`Package.swift` 的 `Textual` 依赖与 target 依赖。
- **改造**：`StreamingTextView.swift`、`SessionTextSelectionCoordinator.swift` 去掉 NSViewRepresentable 包装，保留 NSView/NSTextView/选择协调内核。
- **新增（AppKit）**：`AppDelegate.swift`、`SessionViewController.swift`、`StatusBarView.swift`、`HistorySidebarViewController.swift`、`ConversationViewController.swift`、`ConversationRowFactory.swift`（按 kind 分发）+ 各行视图、`InputBarView.swift`、`ApprovalCardView.swift`、`TurnJumpRailView.swift`、`MarkdownAttributedStringBuilder.swift`、`ObservationBinder.swift`、`ConversationDisplayRow.swift`（摊平模型）。
- **不动**：全部模型 / 逻辑 / DaemonClient 文件（`SessionModel`、`WorkbenchModel`、`ThreadRuntimeModel`、`AgentItemReducer`、`ConversationTurn`、`ConversationRailNavigator`、`ToolPresentation`、`HistoryModel`、`DaemonClient`、`DaemonTransport`、`ProcessDaemonTransport`、`StreamingTextBuffer`、`TurnJumpRailLayout`）。

## 文档更新

实现时同步更新：

- `ARCHITECTURE.md`：前端从 SwiftUI 改为 AppKit、移除 Textual、会话流虚拟化与侧栏 NSOutlineView 的结构说明；总体结构里 `AgentDeck.app (macOS, SwiftUI + AppKit)` 改为 AppKit。
- `README.md`：构建/运行说明若涉及 SwiftUI 描述同步更新。
- `docs/QUALITY.md`：补 AppKit 重写后的验证命令与手动核验清单、Swift 契约一致性测试。
- `docs/plans/2026-06-29-appkit-frontend-implementation.md`：可执行实施步骤（后续撰写）。
