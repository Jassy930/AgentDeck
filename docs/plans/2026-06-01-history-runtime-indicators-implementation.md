# History Runtime Indicators Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 移除左侧独立 Runtime 区块，并在 History 会话行内显示缓存、运行、审批、失败和未读状态点。

**Architecture:** Swift 继续保留 `WorkbenchModel` / `ThreadRuntimeModel` 作为运行时状态源。`SessionView` 在渲染每个 `HistoryThreadSummary` 时按 `thread.id` 查询匹配 runtime，把 phase 和 unread count 传给 `HistoryThreadRowPresentation`，由行内小圆点表达状态。

**Tech Stack:** SwiftUI、Swift Testing、SwiftPM。

---

### Task 1: History 行状态模型

**Files:**
- Modify: `Sources/AgentDeck/HistoryModel.swift`
- Test: `Tests/AgentDeckTests/IpcTests.swift`

**Steps:**

1. 写失败测试：`HistoryThreadRowPresentation` 接收 `runtimePhase` 和 `unreadEventCount`。
2. 运行：`swift test --filter historyRowPresentationExposesCachedRuntimeIndicator`，期望编译失败。
3. 在 presentation 中加入 `runtimePhase`、`unreadEventCount`、`hasRuntimeIndicator`、`hasUnreadIndicator` 和 `runtimeStatusLabel`。
4. 重新运行同一测试，期望通过。

### Task 2: 侧栏 UI 调整

**Files:**
- Modify: `Sources/AgentDeck/SessionView.swift`
- Delete: `Sources/AgentDeck/RuntimeSelectorView.swift`
- Modify: `Tests/AgentDeckTests/TextualCompatibilityTests.swift`

**Steps:**

1. 从 History sidebar 移除 `RuntimeSelectorView` 和分隔线。
2. 在 `historyThreadRow` 中读取 `model.workbench.runtime(sessionId: thread.id)`。
3. 在 agent 图标之后显示 runtime 状态圆点，未读时使用更醒目的 accent 小点。
4. 删除过时的 `RuntimeSelectorView` 构造测试。
5. 运行：`swift test --filter HistoryModelTests`，期望通过。

### Task 3: 文档与验证

**Files:**
- Modify: `README.md`
- Create: `docs/plans/2026-06-01-history-runtime-indicators-design.md`
- Create: `docs/plans/2026-06-01-history-runtime-indicators-implementation.md`

**Steps:**

1. 更新 README 中 History runtime 状态显示说明。
2. 记录设计和实施计划。
3. 运行 `swift test`。
4. 运行 `scripts/verify-agent-docs.sh`。
5. 检查 `git status --short --branch`。
