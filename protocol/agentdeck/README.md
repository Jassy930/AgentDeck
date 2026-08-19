# AgentDeck 中立协议 schema

`agentdeck-protocol.schema.json` 是**生成产物**，由 `agentdeck-protocol::protocol_schema()`
从 Rust 类型生成，**不要手写**。

## 重新生成
- 推荐：`agentdeck protocol schema > protocol/agentdeck/agentdeck-protocol.schema.json`
- 或：`UPDATE_SCHEMA=1 cargo test -p agentdeck-protocol schema_matches_committed_snapshot`

## 版本
`protocolVersion` = `agentdeck-protocol::PROTOCOL_VERSION`。改动本地 wire 形态时 +1 并
重生成快照；仅清除不属于本地 IPC 的聚合根不改变版本。`cargo test` 的 drift 测试
会在类型与快照脱节时失败。

## actionDecision wire 形态

`ActionDecision` 自 protocol v3 起就是 `ClientCommand` 的 typed variant；当前 protocol
v4 继续保留该 wire 形态，并包含在 schema：

```json
{
  "command": "actionDecision",
  "sessionId": "<string>",
  "decision": {
    "requestId": "<string>",
    "decision": "approve",
    "persist": false
  }
}
```

`decision.decision` 只接受 `approve` / `deny`；协议没有顶层 numeric `id`、`payload`
包装或 `cancel` decision。

## v0.2 起：两层协议

v0.2 引入了严格的两层协议结构：

### Layer A — 事件主干（中立，vendor 中性）

包含：`AgentItem` / `ActionRequest` / `SessionStarted` / `SessionCapabilities` /
`TurnStarted` / `TurnFinished` / `SessionClosed` / `Error`。`TurnComplete` 暂只作为
尚未迁移的 Claude Code legacy terminal 保留。

**守护规则**：主干类型严禁出现 `Codex`、`OpenAI`、`Anthropic`、`Claude` 字样。
由 `agentdeck-protocol/src/neutrality_tests.rs` 中的静态断言守护（N1 不变量）。

每条主干事件必须带 `agentKind` 字段（K4 升级）。`SessionCapabilities` 必须
先于该 session 的任何 `AgentItem`（N7 不变量）。

protocol v4 的每个 `AgentItem` envelope 还必须带 `turnId`、稳定 `itemId` 和
`state=streaming|completed`。同一个 `itemId` 的后续事件是截至当前的完整快照，客户端
按 ID 替换；不得把它重新当作裸 delta 拼接。

### Layer B — Vendor 控件命名空间

包含：`VendorControl` / `VendorPanelEvent`。

payload 是 enum-by-AgentKind，类型化，禁止 `serde_json::Value` 透传（N4 不变量）。
vendor 字段只能出现在 `capabilities.*` / `vendorControl.*` / `vendorPanel.*` 三个
命名空间下。

### 四道守护测试

`agentdeck-protocol` 通过一组测试守护协议正确性，其中四道核心守护：

1. `schema_matches_committed_snapshot` — 协议类型变更必须重生成 schema 快照（K10）
2. `protocol_neutrality_main_trunk` — 主干类型不出现 vendor 字样（N1）
3. `capabilities_namespace_is_typed` — vendor enum variant 不含 `serde_json::Value` 或裸 `String` raw payload（N4）
4. `agent_kind_appears_on_every_trunk_event` — 主干 enum 全部 variant 都有 `agent_kind` 字段（K4）

### UPDATE_SCHEMA 命令

改动 `agentdeck-protocol` 中任何公开类型后，须重生成 schema 快照，否则
`schema_matches_committed_snapshot` 测试失败：

```bash
UPDATE_SCHEMA=1 cargo test -p agentdeck-protocol schema_matches_committed_snapshot
```

重生成后须将快照提交进仓库：

```bash
git add protocol/agentdeck/agentdeck-protocol.schema.json
```

独立验证 schema 与当前代码同步（无需运行 test）：

```bash
cargo build --locked \
  -p agentdeckd --bin agentdeckd \
  -p agentdeck-cli --bin agentdeck
AGENTDECK_DAEMON_BIN="$PWD/target/debug/agentdeckd" \
  ./target/debug/agentdeck \
  --data-dir /tmp/agentdeck-schema protocol schema \
  | diff - protocol/agentdeck/agentdeck-protocol.schema.json \
  && echo "schema in sync"
```
