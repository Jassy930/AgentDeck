# Conversation Turn Rail Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 在右侧历史/当前会话流增加竖排轮次导航点，支持 hover 摘要、点击跳转、跳到最新和 rail 上滚轮按轮跳转。

**Architecture:** 复用现有 `ConversationTurn` 分组作为导航数据源，新增纯 Swift presentation model 生成跳转项。`SessionView` 用 `ScrollViewReader` 包住会话流，为每个 turn 和底部 sentinel 设置稳定 id，并 overlay 一个无背板的轻量 `TurnJumpRail`。Rail 的视觉层只画固定间距、居中排列的点位和 hover 浮层，并用累计位移模拟 Dock 式整体拉伸；透明 AppKit 交互层统一负责 hover、点击和滚轮事件。点位溢出时 rail 跟随当前轮次自动揭示点位，但不单独消费滚轮，跳转边界不循环。主会话手动滚动时，每个 turn 通过 SwiftUI preference 上报视口位置，scroll spy 规则被动更新 rail 高亮。

**Tech Stack:** Swift 6、SwiftUI、AppKit `NSViewRepresentable` 捕获 rail 区域滚轮事件、Swift Testing。

---

### Task 1: 导航项 presentation model

**Files:**
- Modify: `Sources/AgentDeck/ConversationTurn.swift`
- Test: `Tests/AgentDeckTests/TextualCompatibilityTests.swift`

**Step 1: Write the failing test**

新增测试：`conversation turn navigation items summarize user turns`。

验证：
- 只有包含用户消息的 turn 生成导航项。
- `index` 从 1 开始。
- `summary` 折叠多余空白并截断。
- `attachmentCount` 来自用户消息附件数量。

**Step 2: Run test to verify it fails**

Run: `swift test --filter conversationTurnNavigationItemsSummarizeUserTurns`

Expected: FAIL，因为 `ConversationTurnNavigationItem` 和生成函数不存在。

**Step 3: Write minimal implementation**

在 `ConversationTurn.swift` 中新增：
- `ConversationTurnNavigationItem`
- `makeConversationTurnNavigationItems(from:)`
- 私有摘要 helper

**Step 4: Run test to verify it passes**

Run: `swift test --filter conversationTurnNavigationItemsSummarizeUserTurns`

Expected: PASS。

### Task 2: SwiftUI scroll anchor 和最新 sentinel

**Files:**
- Modify: `Sources/AgentDeck/SessionView.swift`

**Step 1: Refactor conversation stream around ScrollViewReader**

将 `conversationStream` 改为：
- 先计算 `turns` 和 `navigationItems`。
- `ScrollViewReader { proxy in ScrollView { ... } }`。
- 每个 `conversationTurn(turn)` 加 `.id(turn.id)`。
- 流底部放透明 sentinel：`.id(conversationLatestAnchorId)`。

**Step 2: Add latest jump action**

点击最新点调用：

```swift
withAnimation(.easeInOut(duration: 0.18)) {
    proxy.scrollTo(conversationLatestAnchorId, anchor: .bottom)
}
```

**Step 3: Add submit-to-latest request**

`SessionModel.submit(_:)` 在用户消息成功追加到 `items` 后递增 `scrollToLatestRequest`。
`SessionView` 在 `ScrollViewReader` 内监听该请求，下一轮主线程滚到 `conversationLatestAnchorId`。
这只处理用户主动发送后的定位，不用 `conversationViewportIdentity` 重建会话视图。

测试：`submitting a user prompt requests scroll to latest`。

### Task 3: TurnJumpRail 视图

**Files:**
- Modify: `Sources/AgentDeck/SessionView.swift`
- Test: `Tests/AgentDeckTests/TextualCompatibilityTests.swift`

**Step 1: Write constructibility test**

新增测试：`turn jump rail can be constructed`。

验证 `TurnJumpRail` 可以用空列表和多轮列表构造，避免 API 破裂。

**Step 2: Run test to verify it fails**

Run: `swift test --filter turnJumpRailCanBeConstructed`

Expected: FAIL，因为 `TurnJumpRail` 不存在。

**Step 3: Implement TurnJumpRail**

在 `SessionView.swift` 内新增私有/内部 SwiftUI view：
- 竖排点位。
- hover 使用自绘浮层，避免系统 `.help` 在小命中区上触发不稳定。
- 普通点 button 调用 `onJump(item.turnId)`。
- 最新点 button 调用 `onJumpLatest()`。
- 支持空列表时只显示最新点。

**Step 4: Run test to verify it passes**

Run: `swift test --filter turnJumpRailCanBeConstructed`

Expected: PASS。

### Task 4: Rail 滚轮按轮跳转

**Files:**
- Modify: `Sources/AgentDeck/SessionView.swift`

**Step 1: Add wheel capture view**

新增透明 `RailInteractionView: NSViewRepresentable`，覆盖 rail 可交互区域，同时处理 hover、点击和滚轮。

**Step 2: Implement wheel routing**

`scrollWheel(with:)` 根据 `event.scrollingDeltaY`：
- 小于 0：下一轮。
- 大于 0：上一轮。

为避免触控板连续事件过快，增加 120ms 节流。

**Step 3: Wire to rail state**

`TurnJumpRail` 维护 `selectedTurnIndex`，点击或滚轮跳转时更新；打开新会话后由于 `conversationViewportIdentity` 变化，rail state 随视图重建。

### Task 5: 文档与完整验证

**Files:**
- Modify: `README.md`
- Modify: `docs/plans/2026-05-20-codex-thread-history-design.md`

**Step 1: Update docs**

补充历史会话支持右侧轮次 rail、点击跳转、最新跳转和 rail 滚轮跳转。

**Step 2: Run full tests**

Run: `swift test`

Expected: all tests pass。

**Step 3: Inspect git status**

Run: `git status --short --branch`

Expected: 只包含本功能改动和进入任务前已有的资源图标改动。
