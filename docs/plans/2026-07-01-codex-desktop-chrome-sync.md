# Codex Desktop 风格外壳同步记录

日期：2026-07-01

## 目标

把 AgentDeck macOS 端 AppKit 外壳同步到当前 Codex Desktop 的视觉范式：

- 透明标题栏 + 全高左侧侧栏。
- 空态使用居中大标题、圆角 composer、连接卡片和底部速率提示。
- 会话态使用右侧 thread header、右上环境信息面板、底部悬浮 composer。
- 保持 v0.2 统一壳边界：不改 daemon、IPC、history 数据结构，不把 UI 写成单 Codex 分支。

## 涉及文件

- `Sources/AgentDeck/CodexDesktopChrome.swift`：共享颜色、右侧 header、环境信息面板。
- `Sources/AgentDeck/AppDelegate.swift`：窗口透明标题栏、全尺寸内容区域、bundle 启动视觉。
- `Sources/AgentDeck/SessionViewController.swift`：左侧全高 split，右侧内容区自带 header。
- `Sources/AgentDeck/EmptyStateView.swift`：Codex 风格空态。
- `Sources/AgentDeck/InputBarView.swift`：圆角悬浮 composer。
- `Sources/AgentDeck/ConversationViewController.swift`：会话态阅读宽度、右上环境面板、底部 composer 约束。
- `Sources/AgentDeck/HistorySidebarViewController.swift`：侧栏顶部快捷入口、项目区、底部账号区。
- `Tests/AgentDeckTests/CodexDesktopChromeTests.swift`：新外壳 smoke 测试。
- `script/build_and_run.sh` 与 `.codex/environments/environment.toml`：GUI bundle 启动入口和 Codex Run action。

## 验证

- `swift test`
- `./script/build_and_run.sh --verify`
- `screencapture -l <AgentDeckWindowID>` 目视检查空态首屏。

## 已知后续

- 右上环境信息面板当前是 UI chrome 占位，只展示本地/分支/提交入口的静态骨架；真实变更计数和来源列表应在后续接入项目扫描或 git 状态服务时补。
- 动态 vendor 控件仍由 `AgentControlBar`/`CapabilityRouter` 装配，当前视觉同步只把顶部独立 control bar 收起；后续可把可交互的 sandbox / approval / reasoning 控件迁入 composer 工具列。
