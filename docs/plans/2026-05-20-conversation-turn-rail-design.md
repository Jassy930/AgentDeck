# Conversation Turn Rail 设计

## 背景

历史会话默认从顶部打开更适合回放和审阅，但长会话需要快速定位到后续轮次和最新内容。现有会话流已经通过 `makeConversationTurns(from:)` 按用户消息分组，天然可以把每条用户消息作为跳转锚点。

## 目标

- 在右侧会话内容区增加一条竖排小点导航 rail。
- 每个小点对应一个用户消息开头，也就是一轮对话的起点。
- 最下面固定一个“最新”点，用于跳到会话底部。
- hover 小点时展示该轮用户消息摘要。
- 点击小点跳到对应用户消息；点击“最新”跳到底部。
- 鼠标悬停在 rail 上滚轮滚动时，按轮次快速跳转，而不是像素级滚动。

## 参考模式

该设计结合三类成熟模式：

- Minimap / overview ruler：长文档右侧总览与快速定位。
- Scrollspy / vertical dot nav：按 section 显示竖排点位，并高亮当前位置。
- Timeline event marker：事件以点显示，hover 展示详情，点击跳转到事件。

AgentDeck 不做完整内容缩略图，而是做轻量的 conversation turn rail。这样符合当前 v0.1 信息架构，也避免增加 TextKit / SwiftUI 渲染负担。

## 交互

- Rail 位于右侧会话流内部右边缘，宽度控制在 28-36pt，不遮挡正文主要阅读区；rail 本身不绘制背板。
- 普通轮次点为 6pt 圆点；当前轮次点放大或使用 accent color；hover 时当前点临时放大，邻近点向外位移并轻微放大，放大造成的额外间距会向上下两侧累积传播，让整条 rail 的视觉总长度变长，形成类似 macOS Dock magnification 的挤出反馈。
- 点位使用固定纵向间距，点数较少时整体居中；点数超过可用高度时 rail 跟随当前轮次自动调整可见窗口，不单独消费滚轮步进，不拉伸间距铺满全高。
- “最新”点固定在 rail 最底部，使用向下箭头或实心终点样式，与普通轮次点区分。
- hover 详情使用自绘浮层而非系统 `.help`，命中区由透明 AppKit 交互层覆盖，详情显示：
  - `第 N 轮`
  - 用户消息前 80 个字符摘要
  - 有附件时显示附件数量
- 点击轮次点使用 `ScrollViewReader.scrollTo(turn.id, anchor: .top)`。
- 点击最新点使用底部 sentinel，例如 `conversation-latest`，并 `anchor: .bottom`。
- 主会话区手动滚动时，每个用户 turn 会上报相对滚动视口的位置；rail 高亮取最接近视口顶部且已进入顶部阈值的用户 turn，被动跟随当前阅读位置。
- 用户主动发送新消息且消息成功进入本地流时，自动滚到底部 sentinel；这和“跳到最新”共用同一个 anchor，不重建会话视口。
- 在 rail 上滚轮由透明 AppKit 交互层捕获，但每次滚轮都直接转换为会话轮次跳转，不先滚 rail 自己的列表：
  - 向下跳到下一轮。
  - 向上跳到上一轮。
  - 最后一轮继续向下跳到最新。
  - 已经在最新时继续向下无反应；已经在第一轮时继续向上无反应，不做循环。

## 状态与数据

新增轻量展示模型：

- `ConversationTurnNavigationItem`
  - `id`
  - `turnId`
  - `index`
  - `summary`
  - `attachmentCount`

生成规则：

- 基于 `makeConversationTurns(from: model.items)` 的结果。
- 只为包含 `user` 的 turn 生成点位。
- 摘要来自用户消息文本，折叠空白并截断。
- 当前第一版不持久化 rail 状态。

## 可访问性

- 每个点是按钮，accessibility label 为 `Jump to turn N, <summary>`。
- 最新点 label 为 `Jump to latest message`。
- tooltip 只是增强，不能成为唯一可读信息。

## 测试

- 模型测试：用户消息导航项按 turn 顺序生成，摘要截断，附件计数正确。
- 视图构造测试：rail 可用空数据、多轮数据和当前轮次数据构造。
- 模型行为测试：提交用户消息后发出一次“滚到最新”请求。
- 行为测试优先覆盖纯函数和 presentation model；实际 `scrollTo` 由 SwiftUI 集成路径承担。

## 非目标

- 不做完整 minimap 缩略图。
- 不做 per-thread 滚动位置持久化。
- 不在第一版实现拖拽 rail 选择范围。
