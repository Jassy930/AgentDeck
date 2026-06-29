# AgentDeck 中立协议 schema

`agentdeck-protocol.schema.json` 是**生成产物**，由 `agentdeck-protocol::protocol_schema()`
从 Rust 类型生成，**不要手写**。

## 重新生成
- 推荐：`agentdeck protocol schema > protocol/agentdeck/agentdeck-protocol.schema.json`
- 或：`UPDATE_SCHEMA=1 cargo test -p agentdeck-protocol schema_matches_committed_snapshot`

## 版本
`protocolVersion` = `agentdeck-protocol::PROTOCOL_VERSION`。改动协议形态时 +1 并重生成快照，
`cargo test` 的 drift 测试会在类型与快照脱节时失败。

## actionDecision 线形态（非 typed 结构，故不在 schema）
`{ "kind": "actionDecision", "id": <u64>, "sessionId": <string>,
   "payload": { "requestId": <u64>, "decision": "approve"|"deny"|"cancel" } }`
