# AgentDeck Async Runtime Hub 设计

## 背景

历史会话详情读取和 streaming turn 曾经共享同一个 stdout reader。当前 turn 正在流式输出 `agentItem` 时，如果前台同时读取另一个历史 thread，Swift 可能把 stream item 当成 `historyThread` reply，表现为 `malformed reply from agentdeckd: expected historyThread, got agentItem`。

长期方案采用一个 `agentdeckd` 作为 async runtime hub：daemon 主循环持续接收请求，每个 turn 在独立 worker 中运行，历史读写走 request id reply，Swift 侧按 `sessionId/threadId` 路由 runtime event。

## 目标

- 多个后台 runtime 可以同步运行或排队。
- 前台历史列表、历史详情读取和 runtime 切换不禁用、不阻塞。
- Swift 只有一个 daemon reader，所有 request reply 按 id 分发。
- streaming event 带 `sessionId/threadId`，按 runtime 路由，不串到历史 reply。
- 保持 agent-neutral IPC 边界，Codex 细节只在 Rust adapter 内。

## 架构

```text
AgentDeck.app
  SessionView
  SessionModel
  WorkbenchModel
    └── ThreadRuntimeModel(sessionId/threadId)
          ▲
          │ session/event
  DaemonClient single reader
    ├── pending replies by id
    ├── session event dispatcher
    └── legacy stream compatibility handler
          │ JSONL IPC
          ▼
agentdeckd
  stdin main loop
    ├── request classifier
    ├── history short workers
    └── turn workers
  stdout writer channel
          │
          ▼
CodexAdapter workers
```

## IPC 路由

`IpcMessage` 增加两个可选顶层路由字段：

- `sessionId`：Swift runtime id，也是 daemon event wrapper 的主要路由键。
- `threadId`：Codex thread id；新 session 初始可为空，daemon 拿到真实 thread 后随 event 回传。

turn worker 不直接输出 legacy `agentItem/sessionState/turnComplete` 到顶层，而是输出：

```json
{
  "kind": "session/event",
  "sessionId": "session_a",
  "threadId": "thread_a",
  "payload": {
    "event": { "kind": "agentItem", "payload": {} }
  }
}
```

历史请求仍是普通 request/reply：`history/listThreads`、`history/readThread`、`history/archiveThread` 等 reply 通过 request id 进入 pending reply table，不参与 session event 路由。

## Swift 分工

- `DaemonClient` 拥有唯一 stdout reader，负责 request id reply 分发、session event dispatch，以及旧 raw stream 兼容。
- `WorkbenchModel` 管理多个 `ThreadRuntimeModel`，按 `sessionId` ingest event，并维护 selected runtime。
- `ThreadRuntimeModel` 承载单个 runtime 的 phase、items、queued prompts、unread count 和 deferred content materialize。
- `SessionModel` 保留旧 facade，同时把 selected runtime 的 items/phase/error/queue 暴露给 UI。
- `RuntimeSelectorView` 只切换 selected runtime 并清 unread，不停止后台 worker。

## Daemon 分工

- stdin main loop 只分类请求，不直接执行长 turn。
- `startSession/startTurn` 先返回 `turnAccepted`，再 spawn turn worker。
- history list/read/manage 进入短 worker，避免历史 I/O 阻塞 stdin main loop。
- 所有 worker 通过统一 stdout writer channel 输出，避免多线程直接写 stdout。
- shutdown 会停止 writer；不承诺 graceful cancel 已运行 worker。

## 不做项

- 不引入共享持久 daemon；daemon 仍由 Swift app 生命周期拥有。
- 不把 Codex 历史复制成 AgentDeck 唯一真相源。
- 不在 Swift 解析 Codex vendor JSON。
- 不实现跨 runtime cancel、fork、rollback 或 worker graceful cancellation。

## 验证

- Swift router 测试覆盖 session event 与 history reply 不混淆。
- Swift workbench 测试覆盖后台 runtime unread、选中清零、per-runtime queue drain。
- Rust dispatch 测试覆盖 turn worker 分类和 history foreground action 分类。
- 全量质量门：`cargo fmt --check`、`cargo clippy --all-targets -- -D warnings`、`cargo test`、`swift test`、`cargo build`、`swift build`。
