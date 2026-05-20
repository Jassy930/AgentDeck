# 会话文本选择协调实现记录

## 目标

会话流里不同消息、reasoning、shell output、diff 都可能使用独立的可选文本视图。用户在一段文本中完成选择后，再到另一段文本拖选时，上一段不应继续显示高亮，否则会像同时存在多个有效选择，造成阅读和复制预期混乱。

## 实现

- 新增 `SessionTextSelectionCoordinator`，维护当前 active selection owner。
- 新增 `SessionTextSelectionOwner`，每个可选区域提供自己的清空 selection 回调。
- `StreamingTextView` 的 AppKit `NSTextView` 改为 `CoordinatedStreamingTextView`，在 `mouseDown` 和 `selectAll` 前激活 owner，并在切换到其他 owner 时清空自身 selection。
- `RichMessageView` 为 Textual 富文本区域安装轻量 AppKit mouse-down monitor。鼠标按下落在该富文本区域内时激活 owner；如果它是上一个 owner，被清空时通过递增 `resetGeneration` 重建 Textual selection 层。
- `UserPromptBlock` 不再使用 SwiftUI 原生 `Text(...).textSelection(.enabled)`，改为 `StaticRichMessageView`，复用 Codex 回复的 `RichMessageView` / Textual 渲染路径，确保用户消息和 Codex 消息在渲染与选择协调上走同一套机制。

## 验证

- 新增 `StreamingTextKitRendererTests/activatingDifferentSessionTextOwnerClearsPreviousSelection` 覆盖 coordinator 行为：重复激活同一 owner 不清空，切换到另一个 owner 时只清空前一个 owner。
- `TextualCompatibilityTests/documentReaderRoleViewsCanBeCreated` 覆盖 `StaticRichMessageView` 可创建，避免用户消息退回 SwiftUI 原生选择路径或单独的 TextKit 渲染路径。

## 边界

该实现覆盖会话主渲染路径里的用户消息 `StaticRichMessageView`、Codex 富文本 `RichMessageView` 和长文本 `StreamingTextView`。少量直接使用 SwiftUI `Text(...).textSelection(.enabled)` 的辅助元信息仍依赖系统默认选择行为，后续如发现同类困惑，应迁移到同一个 owner/coordinator 模式。
