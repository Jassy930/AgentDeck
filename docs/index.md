# AgentDeck 文档索引

本目录是 AgentDeck 的仓库内记录系统。`AGENTS.md` 只做入口导航；稳定知识必须落到这里或仓库根部的专门文档中。

## 顶层文档

- `../NORTH_STAR.md`：产品北极星、当前必赢目标和不做什么。
- `../README.md`：项目介绍、当前功能、构建运行和测试入口。
- `../ARCHITECTURE.md`：稳定架构、分层边界、依赖方向和不变量。
- `../AGENTS.md`：代理工作入口和仓库导航。

## 运行与诊断

- `AGENT_DIAGNOSTICS.md`：自检命令、诊断日志位置、failure code 和排查流程。
- `AGENTDECKD_STATUS.md`：daemon 当前能力矩阵、完整度、证据边界和 desktop 接入前缺口。
- `QUALITY.md`：按变更范围选择验证命令，以及文档结构检查入口。
- `RUST_BUILD_STORAGE.md`：Rust 构建产物、sccache 容量上限和分 worktree 清理流程。

## 计划与历史

- `plans/README.md`：设计文档和实施计划的命名、内容和归档规则。
- `plans/*-design.md`：功能设计、架构取舍和验收标准。
- `plans/*-implementation.md`：可执行实施步骤、验证命令和收口记录。

### GPUI 桌面端重启（2026-08-17，当前）

- `plans/2026-08-17-gpui-desktop-reset-design.md`：删除旧 AppKit target、建立最小 GPUI 桌面壳的目标、边界和验收标准。
- `plans/2026-08-17-gpui-desktop-reset-implementation.md`：当前切片的逐文件实施与验证命令。

此前 macOS AppKit 文档仅保留为历史事实，不再定义当前桌面实现或默认迭代顺序。

### agentdeckd 最小稳定边界（2026-08-17，当前设计）

- `plans/2026-08-17-codex-app-server-lifecycle-adr.md`：决定由 `agentdeckd` 直接持有 session-scoped Codex app-server stdio 子进程，不采用 managed daemon/proxy。
- `plans/2026-08-17-agentdeckd-minimum-stable-boundary-design.md`：desktop 接入前必须完成的 Codex-only M0、生命周期、不变量和验收门禁；当前状态是设计基线，尚未落地。

### iOS 前端计划（2026-07-03）

- `plans/2026-07-03-ios-uikit-frontend-design.md`：iOS UIKit companion 前端设计（fixture 驱动界面骨架，状态：Implemented）。
- `plans/2026-07-03-ios-uikit-frontend-implementation.md`：iOS UIKit companion 前端实施计划（Task 1–15；文中 `AgentDeckCore` 是实施时原名，现名为 `AgentDeckMobileCore`）。

### macOS AppKit 富文本渲染（2026-07-23，历史）

- `plans/2026-07-23-native-markdown-table-rendering-implementation.md`：在现有 TextKit/NSAttributedString 管线中增加 GFM 表格识别、`NSTextTable` 原生布局、流式降级与像素快照门禁。

## 协议资料

- `../protocol/SPIKE_FINDINGS.md`：Codex app-server wire framing、方法和 schema 事实源。
- `../protocol/CODEX_VERSION.txt`：生成当前 schema 时使用的 Codex 版本。
- `../protocol/*.json`：官方 schema 快照。
- `../protocol/agentdeck/`：AgentDeck 自身中立协议 schema 与说明。`agentdeck-protocol.schema.json` 由 schemars 从 Rust 类型派生生成（非手写），`README.md` 说明生成与更新流程。

## 更新规则

- 代码行为变化时，同步更新对应产品、架构、诊断或计划文档。
- 文档不要重复大段实现细节；稳定事实放专门文档，临时决策放计划文档。
- 如果某条规则需要长期执行，优先补测试、脚本或 CI 检查，而不是只写自然语言。
- 每次阶段性收口前运行 `scripts/verify-agent-docs.sh`，确认文档入口没有漂移。
