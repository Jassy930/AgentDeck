# Folder New Session Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 在 History 文件夹分组标题右侧增加加号按钮，用于在对应文件夹下开启新会话。

**Architecture:** Swift UI 只增加项目分组级入口，点击后更新 `SessionModel.cwd` 并复用现有新会话重置逻辑。不会预创建 runtime 或 daemon thread；第一条 prompt 仍走现有 `submit()` 创建 live runtime。

**Tech Stack:** SwiftUI、Swift Testing、SwiftPM。

---

### Task 1: 模型入口

**Files:**
- Modify: `Tests/AgentDeckTests/IpcTests.swift`
- Modify: `Sources/AgentDeck/SessionModel.swift`

**Step 1: Write the failing test**

在 `SessionModelTests` 附近新增测试：先应用一个历史详情选中 `/tmp/old`，再调用 `startNewSession(inProjectCwd: "/tmp/new")`，断言 `cwd.path == "/tmp/new"`、`selectedHistoryThreadId == nil`、`workbench.selectedRuntime == nil`、`selectedItems.isEmpty`、`selectedPhase == .ready`。

**Step 2: Run test to verify it fails**

Run: `swift test --filter startNewSessionFromHistoryGroupSwitchesProject`

Expected: 编译失败或测试失败，因为 `SessionModel` 尚无 `startNewSession(inProjectCwd:)`。

**Step 3: Write minimal implementation**

在 `SessionModel` 中新增：

```swift
func startNewSession(inProjectCwd projectCwd: String) {
    cwd = URL(fileURLWithPath: projectCwd)
    startNewSessionFromCurrentProject()
}
```

**Step 4: Run test to verify it passes**

Run: `swift test --filter startNewSessionFromHistoryGroupSwitchesProject`

Expected: PASS。

### Task 2: 侧栏按钮

**Files:**
- Modify: `Sources/AgentDeck/SessionView.swift`

**Step 1: Update group header UI**

把 `historyGroup(_:)` 的文件夹标题改为 `HStack`，左侧保留 `Text(group.projectName)`，右侧增加：

```swift
Button {
    model.startNewSession(inProjectCwd: group.cwd)
} label: {
    Image(systemName: "plus")
}
.buttonStyle(.borderless)
.help("New session in \(group.projectName)")
```

**Step 2: Run focused tests**

Run: `swift test --filter HistoryModelTests`

Expected: PASS。

### Task 3: 文档与收口

**Files:**
- Modify: `README.md`
- Create: `docs/plans/2026-06-01-folder-new-session-design.md`
- Create: `docs/plans/2026-06-01-folder-new-session-implementation.md`

**Steps:**

1. 更新 README 的 History 说明，记录文件夹标题右侧的加号可从对应项目开启新会话。
2. 运行 `swift test`。
3. 运行 `scripts/verify-agent-docs.sh`。
4. 运行 `git status --short --branch`。
