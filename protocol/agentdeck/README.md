# AgentDeck 中立协议 schema

本目录下的四份 `*.schema.json` 都是**生成产物**，各自由 `agentdeck-protocol`
里对应的聚合 schema 函数从 Rust 类型生成，**不要手写**。四份快照对应四条
彼此独立、互不联动的版本轴——改动其中一条轴的 wire 形态只需 +1 该轴自己的
版本常量并重生成对应快照，不影响另外三条轴。

| 版本轴 | 版本常量 | 快照文件 | 聚合 schema 函数 | CLI 导出命令 | 重生成命令 |
| --- | --- | --- | --- | --- | --- |
| 本地 IPC（CLI/Swift ⇄ daemon） | `agentdeck_protocol::PROTOCOL_VERSION` = 2 | `agentdeck-protocol.schema.json` | `agentdeck_protocol::protocol_schema()` | `agentdeck protocol schema` | `UPDATE_SCHEMA=1 cargo test -p agentdeck-protocol schema_matches_committed_snapshot` |
| Runtime（daemon ⇄ 远端 Runtime 端点） | `agentdeck_protocol::runtime::RUNTIME_PROTOCOL_VERSION` = 2 | `runtime-protocol.schema.json` | `agentdeck_protocol::runtime::runtime_schema()` | `agentdeck protocol runtime-schema` | `UPDATE_RUNTIME_SCHEMA=1 cargo test -p agentdeck-protocol runtime_schema_matches_committed_snapshot` |
| Relay v2（endpoint ⇄ relay 外层可见字段） | `agentdeck_protocol::relay_v2::RELAY_PROTOCOL_VERSION` = 2 | `relay-v2.schema.json` | `agentdeck_protocol::relay_v2::relay_v2_schema()` | `agentdeck protocol relay-schema` | `UPDATE_RELAY_SCHEMA=1 cargo test -p agentdeck-protocol relay_v2_schema_matches_committed_snapshot` |
| E2EE（endpoint 侧密文/签名契约） | `agentdeck_protocol::e2ee::E2EE_FORMAT_VERSION` = 1 | `e2ee-v1.schema.json` | `agentdeck_protocol::e2ee::e2ee_schema()` | `agentdeck protocol e2ee-schema` | `UPDATE_E2EE_SCHEMA=1 cargo test -p agentdeck-protocol e2ee_schema_matches_committed_snapshot` |

Runtime v2 Rust contract、schema 与 current fixture 已由 P3.9-C0-A1a2 的 `c28a968` 完成，真实
Runtime v1/schema v4 persisted readback 由 `c36a4f9` 收口。Swift production mirror/cutover 仍属于
P3.9-C0-A2；冻结的 `runtime-v1-wire.jsonl` 仅供 A2 前的 Swift compatibility 回归读取，不是当前
Runtime contract gate。

四个 `agentdeck protocol <op>` 子命令（连同 `protocol version`）都是纯本地
计算：它们直接调用上表对应的聚合 schema 函数并原样打印，**不 spawn
daemon、不建 transport**（P1.3）。`protocol` 命令组的 dispatch 发生在构造
`Client`/连接 daemon 之前，`agentdeck-cli/tests/protocol_schema_exports.rs`
在一个 daemon 必然探测不到的沙盒环境里验证了这一点。

Relay v1 草案的 `crate::remote` namespace、schema、server/client 与行为测试已在
P2.9 物理删除；当前只存在表中的 Relay v2 版本轴。公开 HTTP `/v1/connect`
只保留无状态 426 tombstone，不升级 WebSocket、不进入 Auth/Core/Store，也不构成
可协商协议版本。R0/R1 文档和 git 历史只能用于理解迁移背景，不能作为当前 schema
或兼容接口使用。

## actionDecision 线形态（非 typed 结构，故不在本地 IPC schema）
`{ "kind": "actionDecision", "id": <u64>, "sessionId": <string>,
   "payload": { "requestId": <u64>, "decision": "approve"|"deny"|"cancel" } }`

## v0.2 起：两层协议

v0.2 引入了严格的两层协议结构：

### Layer A — 事件主干（中立，vendor 中性）

包含：`AgentItem` / `ActionRequest` / `TurnComplete` / `SessionStarted` /
`SessionCapabilities` / `Error`。

**守护规则**：主干类型严禁出现 `Codex`、`OpenAI`、`Anthropic`、`Claude` 字样。
由 `agentdeck-protocol/src/neutrality_tests.rs` 中的静态断言守护（N1 不变量）。

每条主干事件必须带 `agentKind` 字段（K4 升级）。`SessionCapabilities` 必须
先于该 session 的任何 `AgentItem`（N7 不变量）。

### Layer B — Vendor 控件命名空间

包含：`VendorControl` / `VendorPanelEvent`。

payload 是 enum-by-AgentKind，类型化，禁止 `serde_json::Value` 透传（N4 不变量）。
vendor 字段只能出现在 `capabilities.*` / `vendorControl.*` / `vendorPanel.*` 三个
命名空间下。

### 四道守护测试

`agentdeck-protocol` 共有 30 个测试守护协议正确性，其中四道核心守护：

1. `schema_matches_committed_snapshot` — 协议类型变更必须重生成 schema 快照（K10）
2. `protocol_neutrality_main_trunk` — 主干类型不出现 vendor 字样（N1）
3. `capabilities_namespace_is_typed` — vendor enum variant 不含 `serde_json::Value` 或裸 `String` raw payload（N4）
4. `agent_kind_appears_on_every_trunk_event` — 主干 enum 全部 variant 都有 `agent_kind` 字段（K4）

### UPDATE_*_SCHEMA 命令

改动某条版本轴聚合 schema 引用到的任何公开类型后，须用该轴自己的
`UPDATE_*_SCHEMA=1` 命令（见文首表格最后一列）重生成对应快照，否则该轴的
`*_schema_matches_committed_snapshot` 测试会失败并提示漂移：

```bash
UPDATE_SCHEMA=1         cargo test -p agentdeck-protocol schema_matches_committed_snapshot          # 本地 IPC
UPDATE_RUNTIME_SCHEMA=1 cargo test -p agentdeck-protocol runtime_schema_matches_committed_snapshot   # Runtime
UPDATE_RELAY_SCHEMA=1   cargo test -p agentdeck-protocol relay_v2_schema_matches_committed_snapshot  # Relay v2
UPDATE_E2EE_SCHEMA=1    cargo test -p agentdeck-protocol e2ee_schema_matches_committed_snapshot      # E2EE
```

重生成后须将对应快照提交进仓库（改了哪条轴就 `git add` 哪份文件）：

```bash
git add protocol/agentdeck/agentdeck-protocol.schema.json
git add protocol/agentdeck/runtime-protocol.schema.json
git add protocol/agentdeck/relay-v2.schema.json
git add protocol/agentdeck/e2ee-v1.schema.json
```

独立验证四份快照都与当前代码同步（无需运行 test；`agentdeck protocol <op>`
不 spawn daemon，可直接跑）：

```bash
cargo run -q -p agentdeck-cli -- protocol schema \
  | diff - protocol/agentdeck/agentdeck-protocol.schema.json \
  && echo "IPC schema in sync"
cargo run -q -p agentdeck-cli -- protocol runtime-schema \
  | diff - protocol/agentdeck/runtime-protocol.schema.json \
  && echo "Runtime schema in sync"
cargo run -q -p agentdeck-cli -- protocol relay-schema \
  | diff - protocol/agentdeck/relay-v2.schema.json \
  && echo "Relay v2 schema in sync"
cargo run -q -p agentdeck-cli -- protocol e2ee-schema \
  | diff - protocol/agentdeck/e2ee-v1.schema.json \
  && echo "E2EE schema in sync"
```
