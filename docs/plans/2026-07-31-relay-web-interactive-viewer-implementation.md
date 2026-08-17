# Relay Web 交互式会话查看器实施计划

状态：Implemented，automatic gates PASS，等待最终人工读回与提交（2026-07-31）

## Goal

在不增加第二套协议或本地旁路的前提下，让测试人员在隔离 Chrome 中亲手读取并查看经真实 Relay/E2EE 返回的 fixed-topology 会话和内容，并在退出时获得可机器判定的清理证据。

## Architecture

- Rust/WASM：在既有 W2 business core 的验签、解密和 Runtime 准入之后生成 Catalog/Conversation UI 投影。
- TypeScript：只用 `textContent` 渲染 typed 投影；不解析 wire，不持有 key/counter，不写 Web Storage。
- Playwright：只把 0600 PairInvite 注入当前页面内存，等待用户点击，检查页面读回与零持久化。
- Bash runner：继续拥有 Relay、daemon host、批准、ledger 读回、明文扫描和全量 cleanup。

## Tasks

- [x] 为 `SnapshotItem` 增加中立 `AgentItem` 只读 accessor，不改变 wire/schema。
- [x] W2 evidence 增加 conversation 列表、canonical item 和 approval summary。
- [x] 页面增加交互 viewer、数据源标签、会话列表、内容区与结束清理按钮。
- [x] 新增 `--interactive` headed Chrome runner；人工操作窗口由外层 marker 控制，host 单次 wait 保持 120 秒安全上限。
- [x] 新增真实 fixed-topology 浏览器测试，断言 Catalog、user/assistant、approval 内容与 Web Storage/IndexedDB 为零。
- [x] 更新 README、QUALITY、诊断、文档索引和计划入口。
- [x] 原有 `--business`、`--durable`、协议 schema 与 docs gate 回归。
- [x] 完整 `cargo test`、no-net、最终 diff 与 Git 状态收口；2026-07-31 fresh
  `cargo test` exit 0，`cargo fmt --all -- --check`、`scripts/check-daemon-no-net.sh`、
  `scripts/verify-agent-docs.sh` 与 `git diff --check` 均 PASS。
- [ ] 人工点击读取并确认页面视觉内容，随后点击结束并读回 cleanup terminal。

## Validation

```bash
cargo test -p agentdeck-web-core --features w2-test-fixture
cd web/relay-test-companion && bun run check && bun run test:unit
AGENTDECK_WEB_INTERACTIVE_AUTORUN=1 scripts/run-relay-web-companion-e2e.sh --interactive
scripts/run-relay-web-companion-e2e.sh --business
scripts/run-relay-web-companion-e2e.sh --durable
cargo test -p agentdeck-protocol
scripts/verify-agent-docs.sh
git diff --check
git status --short --branch
```

## Expected terminal

交互入口最终一行 JSON 必须为 `status=PASS`，且包含：

- `dataSource=fixed-topology-synthetic`
- `catalogEntryCount=1`
- `conversationContentRendered=true`
- command/completed `1/1`
- approval total/applied `1/1`
- Relay、browser output、browser persistent plaintext absent
- 全部 cleanup 字段为 `true`

个人真实 Codex/Claude Code 历史经 production Relay 展示继续受 release signing、production remote identity、持久配对和真实 vendor 门禁约束，保持 W4 `BLOCKED`。
