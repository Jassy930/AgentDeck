# Optimistic User Prompt Dedupe

## 背景

普通 live runtime 提交 prompt 时，Swift 会先本地插入一条 `kind=user` 的乐观
消息，保证输入立即出现在会话流里。Codex app-server 随后也会通过 daemon stream
返回同一条用户消息；由于 server item 使用不同 id，原实现会把它追加成第二个
`user` item。`makeConversationTurns` 遇到连续 user 会 flush 当前 turn，因此界面
表现为同一 prompt 显示两层用户块。

## 处理

采用显式 correlation id，而不是按文本猜测：

- Swift 提交 prompt 时，`ThreadRuntimeModel.appendUserPrompt` 返回本地乐观
  user item id。
- `DaemonClient.runtimeTurnRequest` 在 `startSession` / `startTurn` payload 中
  携带 `optimisticUserItemId`。
- daemon 解析该字段并把它传入 turn worker。
- turn worker 在该 turn 第一条 `kind=user` item 到达时，把 server item id
  重写为 `optimisticUserItemId` 后再发给 Swift。
- Swift 继续只按 `AgentItem.id` upsert；本地占位和 server 回包使用同一个 id，
  因此不会生成第二个 user turn。

这个方案保留即时回显，也避免 Swift 用文本内容做启发式去重。`optimisticUserItemId`
是 AgentDeck 自己的 IPC correlation 字段，不要求 Swift 理解 Codex vendor JSON。

## 验证

- `swift test --filter serverUserItemUpsertsOptimisticLocalPromptByCorrelatedId`
- `swift test --filter runtimeTurnRequestEncodesSessionRouting`
- `cargo test start_turn`
- `cargo test optimistic_user_item_mapping_reuses_client_id`
