# AgentDeck 架构

本文件记录稳定架构边界。产品定位、使用方式和构建命令见 `README.md`；具体功能设计和实施历史见 `docs/plans/`。

## 北极星

AgentDeck 是 macOS 原生的本地 Coding Agent 工作台。它不替代 Codex Desktop，不做 IDE，也不做通用多 agent 聊天界面。

v0.1 只验证两个核心能力：

1. 原生流式会话：实时展示 reasoning、shell、file edit 等 agent 工作过程，并在高风险操作前让用户 approve / deny。
2. agent-中立适配器边界：Swift UI 不知道 Codex 存在，社区未来可以平行贡献 Claude Code、SSH 或云端 adapter。

## 总体结构

```text
AgentDeck.app  (macOS, SwiftUI + AppKit)
      │  stdio JSONL IPC，中立 AgentItem
      ▼
agentdeckd  (Rust daemon)
      │  ├── RuntimeHub（stdin main loop + stdout writer）
      │  ├── stdout writer
      │  ├── turn/history workers
      │  ├── run record / diagnostic log
      │  └── CodexAdapter
      ▼
codex app-server  (子进程, JSON-RPC over stdio)
```

## 分层边界

- `Sources/AgentDeck/`：macOS 原生 UI、会话模型、历史回放和本地交互。这里只能依赖中立 IPC shape。
- `agentdeckd/src/ipc.rs`：AgentDeck 自己的 stdio JSONL IPC 协议，是 Swift 与 daemon 的物理边界。
- `agentdeckd/src/codex.rs`：Codex app-server adapter。Codex vendor JSON、方法名和 schema 翻译只能留在这里或紧邻模块。
- `agentdeckd/src/record.rs`：AgentDeck 管理的 run record 写入与脱敏。
- `agentdeckd/src/diag.rs`：诊断日志、自检和机器可读诊断报告。
- `protocol/`：官方 Codex app-server schema 快照和 spike 事实源。
- `docs/plans/`：设计、实施计划和决策历史。

## 不变量

- Swift 层不得解析 Codex vendor JSON，也不得出现需要理解 Codex schema 才能工作的 UI 分支。
- 中立 IPC 中面向 Swift 的核心事件使用 `AgentItem`，不要把供应商特定字段扩散到 UI。
- daemon 的 stdin 主循环不得被单个 turn 阻塞；长时间工作放到 worker。
- daemon 的 RuntimeHub 必须按 `sessionId` 阻止同一 runtime 并发 turn，并对 history worker 保持有界并发；超限时返回可诊断 busy error。
- streaming event 必须携带 `sessionId/threadId`，避免历史读取和正在运行的 turn 串流互相抢 reader。
- run record 与 diagnostic log 是 AgentDeck 管理的数据，写入 `~/Library/Application Support/AgentDeck/`，不得写入用户项目仓库。
- 写入前必须做 best-effort 密钥脱敏；写失败不能静默，必须在可诊断位置暴露。
- `protocol/` 里的 schema 必须来自官方 `codex app-server generate-json-schema`，不要手写或逆向猜测协议。
- AgentDeck 不读取、不保存、不转发 Codex token，只沿用用户已有 `codex login` 状态。

## 依赖方向

```text
Swift UI
  -> WorkbenchModel / ThreadRuntimeModel / SessionModel
  -> AgentDeck IPC models
  -> daemon stdio

daemon main
  -> ipc
  -> codex adapter
  -> record / diag
  -> codex app-server child process
```

允许的跨层访问应沿上图向下。新增功能如果需要反向依赖，先把接口下沉到中立模型或 daemon adapter，不要让 UI 穿透到供应商协议。

## 变更指引

- 改 UI 行为：先看相关 `Sources/AgentDeck/*Model.swift` 与最近的 `docs/plans/*design.md`。
- 改 IPC：同步更新 Swift/Rust 两侧模型、测试和 README/架构文档。
- 改 Codex 协议翻译：先看 `protocol/SPIKE_FINDINGS.md` 和 `protocol/CODEX_VERSION.txt`，再改 adapter。
- 改诊断或记录：同步更新 `docs/AGENT_DIAGNOSTICS.md` 和 `docs/QUALITY.md`。
- 新增 adapter：不得要求 Swift 侧知道该 adapter 的 vendor JSON。
