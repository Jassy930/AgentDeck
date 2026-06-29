# AgentDeck 统一接口层（CLI 契约）设计

## 背景

AgentDeck 当前已有一条中立边界：Swift app 通过 stdio JSONL IPC 与 `agentdeckd` 通信，
daemon 把 Codex item 翻译成中立 `AgentItem`，Swift 永远不知道 Codex 存在
（见 `ARCHITECTURE.md`、`NORTH_STAR.md`）。

但这份协议有两个结构性缺口：

1. **协议没有被形式化**。它实际上散落在 `agentdeckd/src/ipc.rs` 与
   `Sources/AgentDeck/DaemonClient.swift` 两侧的手写实现里，没有独立、版本化、
   机器可校验的契约产物。两侧靠人工保持一致，drift 只能靠 review 发现。
2. **没有一个可被任意前端 / 测试复用的统一接口入口**。未来要做不同前端（AppKit 重写，
   乃至更多前端），以及"开发过程中的自动端到端测试"，都需要一个稳定、文档化、可脚本化的
   接口标准，而不是各自对着 Swift/Rust 实现细节复刻协议。

本设计把"IPC 协议即边界"升级为"**协议即契约 + CLI 作参考客户端 / 测试驱动**"：

- 抽出一份**版本化、从 Rust 类型生成**的协议事实源；
- 新增参考客户端 `agentdeck` CLI，作为该契约的可执行体现与开发期 E2E 驱动；
- 该 CLI **不进入前端实时数据通路**（前端继续直连 JSONL），只负责"把契约钉死 + 可脚本化驱动"。

> 范围说明：这是两个子项目中的第 1 个。第 2 个子项目（macOS 前端重写为 AppKit、
> 并成为本契约的消费者）单独立 spec，不在本文件范围内。

## 目标

- 把中立协议类型抽到独立的 `agentdeck-protocol` crate，作为协议**唯一事实源**。
- 用 `schemars` 从 Rust 类型生成版本化 JSON Schema，提交快照，并以 **drift 测试**
  防止类型与快照脱节（与仓库对 Codex schema "必须生成、不手写" 的纪律同构）。
- 新增 `agentdeck` CLI（crate `agentdeck-cli`），作为 daemon 的参考客户端：
  spawn `agentdeckd`、讲 JSONL、暴露与协议 1:1 的子命令，并输出**稳定的 JSON / JSONL +
  退出码契约**。
- 提供契约级 **门控 Rust 集成测试**（E2E）：spawn 真实 `agentdeck` binary、驱动真实
  Codex、断言契约形态不变量。默认 `cargo test` / CI 跳过。
- CLI 与 protocol crate 保持 agent 中立（零 Codex / OpenAI 词汇，guard test 覆盖），
  并沿用现有 A1 进程生命周期、profile / 数据目录语义与脱敏不变量。
- 同步更新 `ARCHITECTURE.md`、`README.md`、`AGENTS.md`、`docs/QUALITY.md`、
  `docs/index.md` 与 `protocol/`。

## 非目标

- **本轮不改 Swift 代码**。Swift 侧与契约的对齐（一致性测试 / 代码生成）留到 AppKit
  重写子项目一起做。
- **不引入 mock / scripted adapter**。E2E 直打真实 Codex（已确认的取舍，代价见"错误处理
  与可观测性"）。
- **不新增后端能力**。命令目录冻结为现有协议操作 + 协议自省；不在本轮加入 turn cancel /
  中断、login 状态、config 等新能力。
- **不引入 wire 级协议版本握手**。只给契约产物一个版本号（`PROTOCOL_VERSION`），不改
  `IpcMessage` 线格式、不要求 Swift 改动。
- 不改变 Codex adapter、RuntimeHub 并发模型、history 读取或 approval 语义。
- 不读取、不保存、不复制、不转发 Codex token。
- CLI 不是前端运行期通路；不追求"CLI 封装/吸收 daemon"。

## 架构方案与边界

### 组件与依赖方向

cargo workspace 由 1 个成员扩为 3 个，依赖单向向下：

```text
                 ┌───────────────────────────┐
  AppKit / Swift │  agentdeck-protocol (crate)│  ← 中立类型 + schemars
  （本轮不动）   │  = 协议事实源（新）         │     生成版本化 JSON Schema
                 └──────────┬────────────────┘
            ┌───────────────┴────────────────┐
            ▼                                 ▼
   agentdeckd (daemon)               agentdeck-cli (binary: agentdeck)
   行为不变，改为依赖                参考客户端：spawn agentdeckd、
   agentdeck-protocol                speak JSONL、暴露子命令 + 稳定 JSON 输出
            │                                 │
            └─────────── spawn ───────────────┘   CLI 复用 daemon 的 A1 生命周期：
            ▼                                      启动它、退出时杀掉它
   codex app-server 子进程
```

- **`agentdeck-protocol`（新 crate）**：把 `ipc.rs` 中的中立类型
  （`IpcMessage / AgentItem / AgentItemKind / SessionState / Lifecycle / ActionRequest /
  ActionDecision / HistoryThreadSummary / HistoryThreadList / HistoryThreadDetail` 及相关
  结构）整体移出，加 `#[derive(JsonSchema)]`。中立性 guard test（"序列化产物不得含 codex /
  openai"）随类型迁入本 crate。
- **`agentdeckd`**：逻辑不变，`ipc` 模块改为 `pub use agentdeck_protocol::*` 或直接依赖该
  crate；`codex.rs` 仍是唯一知道 Codex 的模块。daemon 对外 stdio JSONL 行为字节级不变。
- **`agentdeck-cli`**：新 binary，名 `agentdeck`。它是 daemon 的**客户端**，spawn
  `agentdeckd` 并讲同一套 JSONL（复用与 `DaemonClient` 等价的传输 / 路由 / 生命周期逻辑，
  Rust 侧自有实现，不与 Swift 共享代码）。

### 边界不变量

- CLI 与 protocol crate **零 Codex / OpenAI 词汇**；guard test 覆盖。
- **A1 生命周期**：CLI 启动 daemon，进程退出（正常或异常）时杀掉 daemon，无孤儿进程；
  daemon 进程组继续 own codex app-server 子进程。
- profile / `--data-dir` 语义与 daemon 现状一致：CLI 透传 `--profile` →
  `AGENTDECK_PROFILE`，`--data-dir` → `AGENTDECK_DATA_DIR`（后者优先）。
- 不读不存不转发 token；写入前 best-effort 脱敏由 daemon 现有逻辑负责，CLI 不新增持久化。

## 协议事实源：schema 生成 + 漂移测试

- protocol crate 类型上 `#[derive(JsonSchema)]`；提供生成入口，由 CLI 子命令
  `agentdeck protocol schema` 输出版本化 JSON Schema。
- crate 内定义常量 `PROTOCOL_VERSION`（语义化或单调整数，初值在实现阶段定，建议 `1`）。
- 快照提交到 `protocol/agentdeck/`：
  - `protocol/agentdeck/agentdeck-protocol.schema.json`（生成的 schema，内含 version 字段）
  - `protocol/agentdeck/README.md`（说明这份 schema 是生成产物、如何重生成、版本含义）
- **drift 测试**（随 `cargo test` 运行）：在测试里重新生成 schema，与提交快照逐字节比对，
  不一致即失败，并在失败信息里给出"运行 `agentdeck protocol schema > 快照路径` 重生成"的提示。
- **中立性测试**：迁入 protocol crate，对代表性样本断言序列化产物不含 `codex` / `openai`。

## CLI 命令目录与 I/O 契约

子命令与协议操作 1:1。**输出形态是 E2E 断言对象，需稳定且文档化。**

| 命令 | 协议操作 | 输出 |
|---|---|---|
| `agentdeck ping` | `ping`/`pong` | 单条 JSON |
| `agentdeck session run --cwd <p> --prompt <s>` | `startSession` | **JSONL** 流：逐行中立事件，终止于 `turnComplete` 或 `error` |
| `agentdeck session continue --thread-id <id> --prompt <s>` | `startTurn`(resume) | 同上 |
| `agentdeck history list [--cwd --search --cursor --limit]` | `history/listThreads` | 单条 JSON（`HistoryThreadList`） |
| `agentdeck history read --thread-id <id>` | `history/readThread` | 单条 JSON（`HistoryThreadDetail`） |
| `agentdeck history archive --thread-id <id>` | `history/archiveThread` | 单条 JSON |
| `agentdeck history unarchive --thread-id <id>` | `history/unarchiveThread` | 单条 JSON |
| `agentdeck history rename --thread-id <id> --name <s>` | `history/renameThread` | 单条 JSON |
| `agentdeck selfcheck` | `selfcheck/logging` | 单条 JSON |
| `agentdeck diagnostics report [--limit --since-seconds --run-id]` | `diagnostics/report` | 单条 JSON |
| `agentdeck protocol schema` | —（本地） | JSON Schema |
| `agentdeck protocol version` | —（本地） | `{"protocolVersion": N}` |

### 审批脚本化（E2E 必需）

`session run` / `session continue` 是全双工：

- **stdout**：流式逐行吐中立事件（含 `sessionState=waitingApproval` 与 `actionRequest`）。
- **stdin**：逐行读决策 `{"requestId": <u64>, "decision": "approve|deny|cancel"}`，
  转成 `actionDecision` 发回 daemon。
- 便捷开关 `--approval-policy auto-approve|auto-deny|prompt`（默认 `prompt` = 读 stdin）。
  非交互 E2E 用 `auto-approve` / `auto-deny`，无需喂 stdin。

### 全局约定

- `--profile stable|dev`、`--data-dir <path>`。
- 输出默认机器 JSON（紧凑、每行一个 JSON）；`--pretty` 仅用于人读，E2E 不依赖 pretty。
- 流式命令输出的每一行是一个**中立事件对象**（`kind` + 相应 payload），而非内部 `session/event`
  包裹层；终止事件为 `turnComplete`（成功）或 `error`（失败）。

### 退出码与错误信封契约

退出码集合保持小而稳定：

| 退出码 | 含义 |
|---|---|
| 0 | 成功（一次性命令成功；或流式会话以 `turnComplete` 正常结束） |
| 2 | 用法 / 参数错误（clap 默认） |
| 3 | 协议错误（daemon 返回 `error` kind，或回包形态不符） |
| 4 | 传输错误（daemon spawn 失败 / EOF / 断连） |
| 5 | 会话失败（流式会话以 `error` 事件或 `Failed` 状态终止） |

错误信封：一次性命令失败时，stdout 输出 `{"error": {"code": "<stable-code>", "message": "<text>"}}`
并给非零退出码；人读诊断走 stderr。流式命令的失败通过最后一行 `error` 事件 + 退出码 5 表达。

## 错误处理与可观测性

- 每个失败都是命名、可见的错误，不静默挂起（沿用 Eng premise 9）。
- CLI 复用 daemon 的诊断 / record 行为，不新增持久化通道；`diagnostics report` 直接透传
  daemon 报告。
- **无 mock 的取舍（已确认）**：契约级 E2E 直打真实 Codex，因此
  - 不可在无 `codex login` 的 CI 跑；
  - agent 生成内容不确定。
  → E2E 断言**收敛到契约形态不变量**（事件 `kind` 序列、JSON 字段存在性与类型、退出码、
  schema 一致性），**不断言** agent 生成的具体文本。这一点在 `docs/QUALITY.md` 中写明。

## 测试与验收

### 测试分层

- **单元 / 协议测试（随 `cargo test`，CI 默认跑）**
  - protocol crate：中立性 guard test、序列化往返、per-kind 结构断言（迁移自 `ipc.rs`）。
  - schema **drift 测试**：重生成 schema == 提交快照。
  - CLI：参数解析、JSON / 退出码映射、错误信封（可用进程内的 fake transport 或对
    daemon 行为的契约断言，不需真实 Codex）。
- **门控 E2E（Rust 集成测试，默认跳过）**
  - 位置：`agentdeck-cli/tests/`。
  - 门控：`AGENTDECK_E2E=1` 环境变量（需 `codex login`）。未设置时测试 early-return / skip。
  - 内容：spawn 真实 `agentdeck` binary，覆盖 `ping`、`session run`（含 `--approval-policy
    auto-approve`）、`history list/read`、`selfcheck`、`protocol schema/version`；断言契约
    形态不变量与退出码。

### 验证命令

```bash
cargo test                              # 含中立性、schema drift、CLI 单元
agentdeck protocol schema               # 输出 schema，可与快照核对
agentdeck protocol version              # 输出协议版本
agentdeck selfcheck                     # IPC 生命周期 + logging 自检
AGENTDECK_E2E=1 cargo test -p agentdeck-cli   # 本地、需 codex login
scripts/verify-agent-docs.sh            # 文档入口无漂移
```

### 验收标准

- `agentdeck-protocol` crate 独立编译；`agentdeckd` 行为（对外 stdio JSONL）字节级不变，
  既有 `cargo test` / `swift test` 全绿。
- `agentdeck protocol schema` 输出与 `protocol/agentdeck/agentdeck-protocol.schema.json`
  一致；改动协议类型但不更新快照时 drift 测试失败。
- 每个子命令的成功 / 失败输出与退出码符合上表契约。
- `session run --approval-policy auto-approve` 能在真实 Codex 下走完一个需审批的 turn，
  以 `turnComplete` + 退出码 0 结束。
- CLI / protocol crate 通过中立性 guard test（零 Codex / OpenAI 词汇）。
- CLI 进程退出后无孤儿 `agentdeckd` / codex 子进程（A1）。
- 默认 `cargo test` 不触发需登录的 E2E；`AGENTDECK_E2E=1` 时才运行。

## 文档更新

实现时同步更新：

- `ARCHITECTURE.md`：新增 `agentdeck-protocol` crate 与 `agentdeck-cli` 组件、依赖方向、
  "协议即契约 + CLI 参考客户端" 的边界说明。
- `README.md`：`agentdeck` CLI 的安装 / 用法、命令目录、输出与退出码契约摘要。
- `AGENTS.md`：验证入口补 `agentdeck` 相关命令与门控 E2E 说明。
- `docs/QUALITY.md`：schema drift 测试、门控 E2E（前置 `codex login`、`AGENTDECK_E2E=1`、
  断言收敛到契约形态）的验证规则。
- `docs/index.md`：协议资料章节补 `protocol/agentdeck/`。
- `protocol/agentdeck/README.md`：schema 为生成产物、重生成方式、版本语义。
- `docs/plans/2026-06-29-unified-interface-cli-implementation.md`：可执行实施步骤（后续撰写）。
