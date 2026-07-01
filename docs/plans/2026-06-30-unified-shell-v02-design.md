# 统一壳 v0.2 设计：Codex 与 Claude Code 一等公民

| 字段 | 值 |
|---|---|
| 状态 | Design — 等待批准 |
| 日期 | 2026-06-30 |
| 主题 | 把 AgentDeck 从「Codex 单家流式客户端」演进为「Coding Agent 的统一原生桌面工作台」，v0.2 在 macOS AppKit 上端到端验证 Codex + Claude Code 双一等公民 |
| 关联 | `NORTH_STAR.md`（待重写）、`ARCHITECTURE.md`（待重写）、`AgentDeck_v0.1_Product_Definition_Workbench.md`（待归档） |

## 0. 文档使用说明

本 design 覆盖一个**远大于单 v0.2** 的产品方向，但所有"实施"内容**只限 v0.2**。后续版本（v0.3 … v1.0）以**路线图条目**形式出现，提供方向锚定，但每个版本会在临近时另写独立 design。

阅读顺序：节 1（北极星）→ 节 2（路线图）→ 节 3（架构边界）→ 节 4（IPC v2）→ 节 5（CC adapter）→ 节 6（UI 改造）→ 节 7（测试矩阵）→ 节 8（验收清单）→ 节 9（风险与开放问题）→ 节 10（文档同步）。

---

## 1. 背景与产品定位修订

### 1.1 当前状态摘要

v0.1 已交付：
- 纯 AppKit macOS 客户端（已移除 SwiftUI 与 Textual 依赖）
- Rust daemon `agentdeckd` 通过中立 IPC 翻译 Codex app-server
- 参考客户端 `agentdeck-cli` + 门控 E2E
- 协议 crate `agentdeck-protocol`（schemars 派生 + 漂移测试 + 中立性测试）

v0.1 的根本不变量（即将被本设计部分推翻）：
- **W1**: Swift 层不得解析 Codex vendor JSON
- **W2**: 中立 IPC 中不出现 vendor 字样
- **W3**: Codex 持久化策略字段只能留在 daemon adapter

### 1.2 新方向

把产品**重新定位**为：

> AgentDeck 是 Coding Agent 的统一原生桌面客户端。
> 它把 OpenAI Codex 和 Anthropic Claude Code 作为**绝对一等公民**，
> 两家的功能、概念和原始语义都被完整保留——AgentDeck 不强行
> 统一它们，而是为它们提供同一个工作台。

核心承诺：

1. **一等公民**：Codex 和 Claude Code 能用到的功能都是 100%，不为对方阉割
2. **语义保留**：vendor 原始概念（Codex `approval policy/sandbox`、CC `permission mode/hooks`）UI 上保留原词，不强译为中立词
3. **统一壳**：整体 UI 范式（会话流、历史侧栏、prompt 输入、approval 卡片骨架）一致；vendor-specific 控件按 capability 路由到对应 SubView
4. **多端原生**：macOS=AppKit、iOS=UIKit、Windows/Linux/Web=Rust 壳 + Web UI（Tauri 风格）。**不追求跨平台共享 UI 框架**
5. **AgentDeck 自带能力**：Project/Task/Run 工作台、Skill 管理、插件系统、SSH 远程、移动伴侣（v0.4+ 路线图）
6. **事实唯一来源**：vendor 自管的数据（CC 会话历史、session rename、archive）一律走 vendor 原生接口，AgentDeck **不**自管元数据层

### 1.3 v0.1 北极星修订（必须执行）

`NORTH_STAR.md` 整体重写为以下草案，旧的"双拍"叙述被新方向替换：

```markdown
# AgentDeck North Star

AgentDeck 是 Coding Agent 的统一原生桌面客户端。

它把 OpenAI Codex 和 Anthropic Claude Code 作为绝对一等公民，
两家的功能、概念和原始语义都被完整保留——AgentDeck 不强行
统一它们，而是为它们提供同一个工作台。

AgentDeck 不是 IDE。
AgentDeck 不是 Codex Desktop 替代品（它的对标对象是 Codex Desktop
的体验，但服务范围远大于单一 vendor）。
AgentDeck 不是通用多 agent 聊天界面。

Codex 写代码，Claude Code 写代码。
AgentDeck 是工作台、控制台、管理面。

## 一等公民承诺

- Codex 和 Claude Code 在 AgentDeck 里能用到的功能都是 100%，
  不为对方阉割、不为统一打折。
- Vendor 的原始概念语义（如 Codex 的 approval policy、CC 的
  permission mode）在 UI 上保留原词，不强译为中立词。
- 未来社区贡献的 adapter 同样按"一等公民"标准接入。

## 多端形态

AgentDeck 的"原生体验"意思是每个平台都用平台原生 UI 框架：
- macOS：AppKit
- iOS：UIKit
- Windows / Linux / Web：Rust 壳 + Web UI（Tauri 风格）

共享层是一个 Rust daemon `agentdeckd` + 中立 IPC 协议
`agentdeck-protocol`。所有客户端通过统一协议消费同一个 daemon。

## AgentDeck 自带能力（跨 agent）

- 跨项目的 Project / Task / Run 工作台
- Skill 管理
- 插件系统
- SSH 远程执行
- 移动端伴侣

这些能力按版本路线图分阶段交付，不在 v0.2 范围内。

## v0.2 必赢

在 macOS AppKit 上端到端验证「统一壳」架构：
1. IPC 协议 v2 引入 agent capabilities，支持两层（控件 + 事件）。
2. ClaudeCodeAdapter MVP 上线，CC 的特色能力（permission 模式、
   hooks、output-style 等）完整可用。
3. UI 整体范式统一，vendor-specific 控件保留原始语义。
4. Codex Desktop 对标点：Approval + Sandbox + Persistence 完整
   控件、Reasoning Effort + Token/Auth 小面板。
```

`AgentDeck_v0.1_Product_Definition_Workbench.md` 归档到 `docs/archive/2026-06-27-original-pdw.md`，其中 Projects/Tasks/Runs 实体定义会在 v0.4 design 时被引用。

---

## 2. 范围拆解与版本路线图

### 2.1 路线图全景

| 版本 | 必赢一件事 | 周期估算 |
|---|---|---|
| **v0.2** | 统一壳端到端验证（macOS AppKit + Codex + CC + IPC v2） | 5–7 周 |
| v0.3 | Codex Desktop 对标补齐 + CC 特色补齐（Worktree、MCP 面板、CC hooks 编辑、Codex skills 浏览、Diff 浏览器升级） | 4–6 周 |
| v0.4 | AgentDeck 工作台（Projects / Tasks / Runs）+ AgentDeck 自管 Skill v1 | 8–12 周 |
| v0.5 | daemon 远程化 + Web UI v0.1（仅会话流，验证跨客户端中立） | 6–10 周 |
| v0.6 | Web/Tauri 发布 + Win/Linux 包装 | 4–8 周 |
| v0.7 | 插件 SDK（双层：vendor passthrough + AgentDeck 自有）+ 插件市场 MVP | 8–12 周 |
| v1.0 | iOS UIKit 伴侣 + macOS Menu Bar Radar / 通知 / 全局快捷键 / 多端统一发布 | 10–14 周 |

### 2.2 v0.2 范围（do）

- IPC 协议 v2：两层结构（事件主干中立 + vendor 控件命名空间）、agent capabilities、远程 transport trait 预留
- ClaudeCodeAdapter MVP（节 5）：CLI 子进程接入，CC 特色能力完整可用
- AppKit UI 改造：CapabilityRouter + vendor SubView + 新会话向导
- Codex Desktop 对标点：**Approval + Sandbox + Persistence 完整 Codex 三维度**、**Reasoning Effort + Token/Auth mini 面板**
- 跨 agent 历史聚合（侧栏默认合并显示，不提供 agent 切换或过滤入口）
- 协议 schema 重生成 + 中立性测试 + agent kind 标注测试

### 2.3 v0.2 范围（don't）

| 项 | 推迟到 | 备注 |
|---|---|---|
| Worktree 可视化面板 | v0.3 | capability 在 v0.2 声明，UI v0.3 |
| MCP Server 管理面板 | v0.3 | v0.2 仅声明 capability |
| CC hooks 完整编辑器 | v0.3 | v0.2 仅显示当前 hooks + 流式接收 hook 事件 |
| Diff 浏览器升级 | v0.3 | v0.2 沿用现有简易渲染 |
| Codex skills / custom prompts 浏览 | v0.3 | |
| CC subagents 管理 | v0.4+ | |
| Projects / Tasks / Runs 实体 | v0.4 | v0.2 仅在 IPC 字段中预留 ID |
| AgentDeck 自管 Skill 平台 | v0.4 | 与 vendor 自带 skill 系统并存 |
| daemon 远程化 | v0.5 | v0.2 仅做 Transport trait 抽象 |
| Web UI / Tauri / Win / Linux | v0.5–0.6 | |
| 插件 SDK | v0.7 | CC 已有 `--plugin-dir`，v0.7 设计两层架构 |
| iOS UIKit | v1.0 | |
| AgentDeck 自管 CC 元数据 (`cc-meta`) | **永远不做** | 事实唯一来源在 CC 原生接口（节 5.6） |
| Claude Agent SDK in-process 集成 | v1.0+ 选做 | 鉴权强制 API key，破坏"复用 claude login"准则 |

---

## 3. v0.2 架构边界与新不变量

### 3.1 v0.2 后的架构图

```
┌────────────────────────────────────────────────────────────────┐
│  AgentDeck.app (macOS, AppKit)                                 │
│                                                                │
│  SessionViewController                                         │
│   ├─ StatusBarView (显示当前 agentKind + auth)                  │
│   ├─ HistorySidebarVC (跨 agent 合并列表)                       │
│   ├─ AgentControlBar (capability 路由 → vendor SubView)         │
│   ├─ ConversationVC (虚拟化 NSTableView, 中立 AgentItem)        │
│   ├─ ApprovalCardView (主干壳 + vendor 高级区 SubView)          │
│   └─ AgentTokenAuthMiniPanel                                   │
│                                                                │
│  CapabilityRouter           ← 新增：UI 渲染按 capabilities 派发   │
│  ObservationBinder          ← 保留                              │
└────────────────────┬───────────────────────────────────────────┘
                     │ Layer A 中立事件主干 (AgentItem)
                     │ Layer B Vendor 控件命名空间
                     │ Layer C 启动配置 (SessionStart)
                     ▼
┌────────────────────────────────────────────────────────────────┐
│  agentdeckd (Rust)                                             │
│  RuntimeHub (stdin loop, stdout writer, per-session lock)      │
│       │                                                        │
│       └─→ AgentRouter (按 sessionId.agentKind 路由)             │
│            ├─ CodexAdapter      (capabilities = {...})         │
│            └─ ClaudeCodeAdapter (capabilities = {...})         │
│                                                                │
│  共享层：record / diag / profile / capabilities registry        │
└────────────────────────────────────────────────────────────────┘
   ▼ spawn (turn-scoped)                  ▼ spawn (turn-scoped)
codex app-server                       claude CLI (--print --stream-json)
```

### 3.2 不变量变更表

#### 3.2.1 废止的不变量

| # | 旧不变量 | 废止理由 |
|---|---|---|
| W1 | Swift 层不得解析 Codex vendor JSON | 新方向要求 vendor SubView 直接消费 vendor 类型 |
| W2 | 中立 IPC 中不出现 vendor 字样 | 改成「主干中立 + vendor 命名空间允许 vendor 前缀」 |
| W3 | Codex 持久化策略字段只能留在 daemon adapter | persistence 必须在 UI 暴露 |

#### 3.2.2 保留的不变量

K1（stdin 不阻塞）、K2（sessionId 并发锁）、K3（释放后发 ready）、K4（事件带 sessionId/threadId）、K5（数据目录隔离）、K6（profile 隔离）、K7（密钥脱敏 + 失败可诊断）、K8（vendor schema 不手写）、K9（不接触 vendor token）、K10（schema 漂移测试）全部保留。

K2 微调：session 创建时 agentKind 不可变，整个生命周期固定到一个 adapter。

#### 3.2.3 新增的不变量

| # | 不变量 | 守护方式 |
|---|---|---|
| **N1** | **两层协议**：`AgentItem` / `ActionRequest` / `TurnComplete` / `SessionStarted` / `SessionCapabilities` / `Error` 主干必须 vendor 中立；vendor 字段只能出现在 `capabilities.*` / `vendorControl.*` / `vendorPanel.*` 三个命名空间下 | schemars 派生 + `neutrality_tests.rs` 静态断言主干类型不出现 vendor 字样 |
| **N2** | **Capabilities Handshake**：每个 session 启动时 daemon 必须先发 `SessionCapabilities` 事件；UI 必须按它路由控件渲染；禁止 UI 硬编码 `if agentKind == .codex` 分支 | Swift 端 `NoVendorBranchInUITests` 用 grep + AST 扫描 |
| **N3** | **Adapter 互不知晓**：CodexAdapter 不依赖 ClaudeCodeAdapter 任何类型；共享逻辑下沉到 `agentdeckd/src/agent.rs` trait | cargo 模块依赖检查 |
| **N4** | **Adapter 内 vendor JSON 不外泄**：被 IPC 推到 UI 的 vendor 字段必须经过 adapter 显式建模，禁止 `serde_json::Value` 透传 | `capabilities_namespace_is_typed` 测试断言所有 vendor enum variant 不含 `serde_json::Value` / 裸 `String` raw payload |
| **N5** | **一等公民对称约束**：CodexAdapter 实现的每个 capability，ClaudeCodeAdapter 必须有等价实现或文档化"不适用"原因（不为统一阉割） | 文档化 capability 矩阵 + cargo test |
| **N6** | **远程 transport 抽象预留**：v0.2 实现 `Transport` trait（仅 stdio），但 trait 必须能支持 remote（异步、可重连、可携带 auth context） | 编译期：trait 定义；运行期：v0.5 实现 remote 时不破坏 v0.2 调用方 |
| **N7** | **`SessionCapabilities` 必须先于该 session 任何 `AgentItem`** | 集成测试断言序 |
| **N8** | **CC 数据事实唯一来源**：AgentDeck 不为 CC 维护任何元数据层（rename/archive/list 全用 CC 原生接口）；不在 `~/Library/Application Support/AgentDeck/` 下创建 `cc-meta/` 目录 | code review + cargo test 文件存在性断言 |

### 3.3 分层边界

```text
Sources/AgentDeck/              ← macOS UI；可知 vendor 概念，但渲染必须经 CapabilityRouter
agentdeck-protocol/             ← IPC 协议事实源；分 trunk / capabilities / vendor / transport
agentdeckd/src/runtime/         ← RuntimeHub + AgentRouter
agentdeckd/src/agent.rs         ← Agent trait + AgentKind 枚举
agentdeckd/src/codex/           ← 现 codex.rs 拆为子模块（adapter/translate/capabilities）
agentdeckd/src/claude_code/     ← 新增 CC adapter 子模块
agentdeckd/src/record.rs        ← 写入按 agentKind 打标
agentdeckd/src/diag.rs          ← 诊断事件带 agentKind
agentdeck-cli/                  ← 加 --agent codex|claude-code 路由 + agent 子命令组
protocol/                       ← Codex 官方 schema；CC 协议参考（若有）
docs/plans/                     ← 设计与实施计划
```

依赖方向严格向下，禁止反向：
- UI 不允许跳过 CapabilityRouter 直读 vendor 字段
- CodexAdapter 不允许调 ClaudeCodeAdapter

---

## 4. IPC 协议 v2

### 4.1 版本号策略

```
PROTOCOL_VERSION: 1 → 2     (直接 bump，不做 dual support)
```

AgentDeck.app 永远 spawn 同版本 daemon，不存在线上跨版本兼容问题。漂移测试守护。

### 4.2 整体结构

```
Layer A — 事件主干（neutral）
  AgentItem / ActionRequest / TurnComplete / SessionStarted /
  SessionCapabilities / Error
  ▸ 严禁出现 vendor 字样

Layer B — Vendor 控件命名空间
  VendorControl / VendorPanelEvent
  ▸ payload 是 enum-by-AgentKind，类型化（禁 serde_json::Value 透传）

Layer C — 会话启动配置
  SessionStart { agent_kind, vendor_options: enum-by-AgentKind, ... }
```

### 4.3 AgentKind 与 SessionId 语义

```rust
pub enum AgentKind { Codex, ClaudeCode }
// 字符串值: "codex" | "claude_code"

pub struct SessionId(String);    // 不透明，daemon 生成
pub struct ThreadId(String);     // 不透明，由 adapter 提供
```

- `sessionId` 本身不携带 agentKind 信息（不透明字符串）
- 事件主干所有消息**新增** `agentKind` 字段（K4 升级）
- session 创建后 agentKind 不可变（K2 升级）
- 对 CC：`ThreadId` = CC session UUID

### 4.4 Capabilities 数据模型

```rust
pub struct SessionCapabilities {
    pub agent_kind: AgentKind,
    pub agent_version: String,
    pub features: BTreeSet<CapabilityId>,
    pub vendor: VendorCapabilities,
}

pub enum CapabilityId {
    // —— Shared ——
    StreamingMessages, StreamingReasoning, Shell, Diff, Approval,
    Mcp, TokenCounters, AuthStatus, ReasoningEffort, ImageInput,
    Worktree,                      // CC 也有：claude --worktree
    
    // —— Codex-only ——
    CodexSandboxMode,
    CodexApprovalPersistence,
    CodexSkills,
    CodexCustomPrompts,
    
    // —— Claude-Code-only ——
    ClaudeCodePermissionMode,
    ClaudeCodeHooks,
    ClaudeCodeOutputStyle,
    ClaudeCodeSlashCommands,
    ClaudeCodePlanMode,
    ClaudeCodeBackgroundAgents,    // claude agents 后台并行会话
    ClaudeCodePluginDir,           // CC 已有插件系统
    ClaudeCodeForkSession,         // --fork-session
}

pub enum VendorCapabilities {
    Codex(CodexCapabilities),
    ClaudeCode(ClaudeCodeCapabilities),
}
```

`features` 是 `BTreeSet`（确定性序列化）。UI 严禁假设 "agentKind=Codex → 一定有 X"，必须 `features.contains(.codexSandboxMode)` 显式查询（N2 守护）。

### 4.5 会话启动配置

```rust
pub struct SessionStart {
    pub agent_kind: AgentKind,
    pub cwd: PathBuf,
    pub prompt: Option<String>,
    pub vendor_options: VendorSessionOptions,
    pub runtime_options: RuntimeOptions,
}

pub enum VendorSessionOptions {
    Codex(CodexSessionOptions),
    ClaudeCode(ClaudeCodeSessionOptions),
}

pub struct CodexSessionOptions {
    pub approval_policy: CodexApprovalPolicy,        // OnRequest | Never | Always
    pub sandbox: CodexSandboxMode,                   // ReadOnly | WorkspaceWrite | FullAccess
    pub persist_approval: bool,
    pub reasoning_effort: CodexReasoningEffort,      // Minimal | Low | Medium | High
    pub mcp_overrides: Vec<McpOverride>,
}

pub struct ClaudeCodeSessionOptions {
    pub permission_mode: ClaudeCodePermissionMode,
    // Default | AcceptEdits | Plan | Auto | DontAsk | BypassPermissions (6 种)
    pub model: Option<String>,                       // sonnet | opus | haiku | fable | full id
    pub effort: Option<String>,                      // low | medium | high | xhigh | max
    pub hooks: Vec<ClaudeCodeHookConfig>,
    pub output_style: Option<String>,
    pub allowed_tools: Option<Vec<String>>,
    pub disallowed_tools: Option<Vec<String>>,
    pub mcp_config_path: Option<PathBuf>,
    pub plugin_dirs: Vec<PathBuf>,
    pub worktree: Option<String>,                    // claude --worktree <name>
    pub session_name: Option<String>,                // claude --name <name>
    pub session_id: Option<String>,                  // claude --session-id <UUID>
}
```

### 4.6 事件主干（Layer A）

```rust
pub enum ServerEvent {
    SessionStarted { session_id, thread_id, agent_kind },
    SessionCapabilities { session_id, capabilities },   // 必须先于 AgentItem
    AgentItem { session_id, thread_id, agent_kind, item },
    ActionRequest { session_id, thread_id, agent_kind, request },
    TurnComplete { session_id, thread_id, agent_kind, summary },
    Error { session_id: Option<SessionId>, code, message, diagnostic_ref },
    
    // Layer B：vendor 命名空间
    VendorControl { session_id, agent_kind, payload },
    VendorPanelEvent { session_id, agent_kind, payload },
}

pub enum AgentItem {
    UserMessage { ... },
    AssistantMessage { ... },
    Reasoning { ... },
    Shell { command, status, exit_code, duration, ... },
    Diff { files, ... },
    Plan { steps, meta: AgentItemMeta },          // 两家都有，meta 携带 vendor 扩展
    ImageReference { saved_path, original_path, ... },
    ToolCall { name, args, result, meta: AgentItemMeta },
    Raw { kind, raw_payload: String },
}

pub struct AgentItemMeta {
    pub vendor_extensions: BTreeMap<String, serde_json::Value>,
}
```

**主干规则**：消息**必须**两家都能产生。某家独有的事件不进主干，走 `VendorPanelEvent`。

### 4.7 Vendor 控件协议（Layer B）

```rust
pub enum VendorControlPayload {
    Codex(CodexVendorControl),
    ClaudeCode(ClaudeCodeVendorControl),
}

pub enum CodexVendorControl {
    UpdateSandbox(CodexSandboxMode),
    UpdateApprovalPolicy(CodexApprovalPolicy),
    UpdateReasoningEffort(CodexReasoningEffort),
}

pub enum ClaudeCodeVendorControl {
    UpdatePermissionMode(ClaudeCodePermissionMode),
    UpdateOutputStyle(Option<String>),
    AddHook(ClaudeCodeHookConfig),
    RemoveHook(String),
}
```

### 4.8 Approval / Permission 双轨

```rust
pub struct ActionRequest {
    pub session_id, pub thread_id, pub agent_kind,
    pub request_id: String,
    pub kind: ActionKind,            // 中立：ExecuteCommand | EditFiles | GrantExtraPermission
    pub summary: String,             // 中立摘要
    pub vendor: ActionRequestVendor, // 携带 vendor 原词
}

pub enum ActionRequestVendor {
    Codex {
        approval_policy_at_decision: CodexApprovalPolicy,
        sandbox_at_decision: CodexSandboxMode,
        can_persist: bool,
    },
    ClaudeCode {
        permission_mode_at_decision: ClaudeCodePermissionMode,
        tool_name: String,
    },
}
```

UI 端 `ApprovalCardView` 共享主干壳（kind + summary），底部 `vendorBottomView` 插槽渲染 vendor SubView。

### 4.9 历史协议

```rust
pub enum HistoryRequest {
    List {
        agent_kind: Option<AgentKind>,   // None = 跨 agent 全列
        cwd_filter: Option<PathBuf>,
    },
    Read { thread_id, agent_kind },
    Archive { thread_id, agent_kind },
    Unarchive { thread_id, agent_kind },  // CC 上等同 no-op（claude rm 是软删，--resume 仍能找回）
    Rename { thread_id, agent_kind, title },
}
```

跨 agent 聚合是 v0.2 AgentDeck 区别于 Codex Desktop 的**第一个**面向用户的价值。读取/操作必须带 `agent_kind`（两家持久化结构不同）。

CC 端实现细节见节 5.6。

### 4.10 run record 适配

`runs/<runId>.jsonl` 文件内容**不变**（仍是中立 AgentItem 流）；新增文件元信息字段 `agent_kind`、`agent_version`，便于回放、诊断和 adapter 路由。

### 4.11 K 不变量延伸

| 不变量 | v0.2 起的精确定义 |
|---|---|
| K1 | 不变（stdin 不阻塞） |
| K2 | 不变；session 创建时 agentKind 不可变 |
| K3 | 不变（释放后发 ready） |
| K4 | 加强：所有事件主干必须带 `agentKind` |
| K5–K10 | 不变 |
| N7 | 新增：SessionCapabilities 必须先于 AgentItem |
| N8 | 新增：禁建 `cc-meta/` 目录 |

---

## 5. ClaudeCodeAdapter MVP

### 5.1 接入方式：CLI 子进程

唯一选择：`claude --print --output-format stream-json --input-format stream-json`。

**理由（基于官方文档调研）：**

| 路径 | 鉴权 | 与"无缝衔接"准则 |
|---|---|---|
| **CLI**（`claude auth login`） | 用户 Pro/Max 订阅 OR Console API key（用户自选）| ✅ 复用用户已有 login；写入 `~/.claude/projects/` 与 CLI/web/SDK 共享 |
| Claude Agent SDK | 强制 API key（明确禁止 claude.ai login） | ❌ 强制改变鉴权，破坏复用 |

**SDK 唯一独占能力**是 in-process callback（hooks / canUseTool / custom tools），但 v0.2 不需要——`--include-hook-events` 已能流式接收 hook 事件用于显示。

### 5.2 进程生命周期

| 维度 | CodexAdapter | ClaudeCodeAdapter |
|---|---|---|
| 生命周期 | turn 级 spawn，Drop kill 进程组 | **turn 级 spawn**（与 Codex 对称） |
| 新会话命令 | `codex app-server` | `claude --print -p "<prompt>" --output-format stream-json --input-format stream-json --session-id <UUID>` 或省略 `--session-id` 让 CC 自动生成 |
| 继续历史 | `thread/resume(threadId)` | `claude --print --resume <id> -p "<prompt>" ...` |
| threadId 映射 | Codex thread id | CC session UUID（来自 SystemMessage init 抓取） |
| stderr 处理 | 内存尾部 + 断连时附诊断 | 同 |

### 5.3 v0.2 CC MUST 清单

#### Shared（与 Codex 对称）

| Capability | CC 实现 | 工作量 |
|---|---|---|
| 新会话启动 | `claude --print -p ...` | 小 |
| 继续历史会话 | `claude --resume <id>` | 小 |
| 流式 assistant 文本 | stream-json `assistant` message | 小 |
| 流式 reasoning | `thinking` content block | 小 |
| Shell 命令 | `tool_use(Bash)` | 中 |
| 文件 Diff | `tool_use(Edit/Write/MultiEdit)` | 中 |
| 通用 tool call | 其它 `tool_use` | 中 |
| Approval / Permission 请求 | CC permission prompt（详见 5.5） | **大** |
| Image input | image content block | 小 |
| Token usage | stream-json `usage` | 小 |
| Auth 状态 | `claude auth status` (JSON + exit code) | 小 |
| Reasoning Effort | `--effort low|medium|high|xhigh|max` | 小 |
| MCP server 列表（仅声明 + 列表显示） | 读 `~/.claude/settings.json` MCP 配置 + `claude --mcp-config` | 中 |
| Worktree（仅 capability 声明 + 启动参数支持） | `claude --worktree <name>` 启动；UI 可视化推到 v0.3 | 小 |
| 历史读取 | `claude agents --json --all --cwd <path>` + 直读 `.jsonl` | 中 |

#### Claude-Code-only（保留语义）

| Capability | 实现 | 工作量 |
|---|---|---|
| Permission Mode 切换（6 种） | `--permission-mode <mode>` 启动；运行中切换走新 turn | 中 |
| Plan Mode 渲染 | plan 模式输出 → `AgentItem::Plan` + meta.vendor=cc | 中 |
| Output Style 选择 | `--output-style <name>` 启动 | 小 |
| Slash Commands 浏览（仅列表） | 扫 `~/.claude/skills/` 与 `.claude/commands/` | 小 |
| Hooks 触发显示（不编辑） | `--include-hook-events --output-format stream-json` | 小 |
| CLAUDE.md 检测与显示 | 读项目根 `CLAUDE.md` | 小 |

#### MAY — 推到 v0.3 以后

- MCP server 完整管理面板（v0.3）
- Hooks 完整编辑器（v0.3）
- Slash commands 自定义编辑（v0.4+）
- Subagents 管理（v0.4+）
- Skills 完整管理（v0.4+）
- `claude agents` 后台并行会话接入（v0.4 Workbench 阶段；v0.2 仅 capability 声明）

### 5.4 CC 输出 → AgentItem 映射表

```text
CC stream-json 输出                       AgentItem 主干
─────────────────────────────────────     ─────────────────────────────
system message (subtype=init)             → SessionStarted + 抓 session_id
system message (诊断 subtype)             → VendorPanelEvent::systemStatus（不入主干）
assistant message: text                   AssistantMessage
assistant message: thinking               Reasoning
assistant message: tool_use(Bash)         Shell { command, ... }
assistant message: tool_use(Edit/Write/   Diff { files, ... }
                          MultiEdit)
assistant message: tool_use(Read/Grep)    ToolCall
assistant message: tool_use(其他 MCP)     ToolCall { meta.tool_kind=mcp }
assistant message: tool_use 需 approve    + ActionRequest（节 5.5）
user message: tool_result                 → 回填到对应 ToolCall/Shell
plan_mode 输出                            Plan { meta.vendor=cc }
image content                             ImageReference
result message (final)                    → TurnComplete
hook event (来自 --include-hook-events)   VendorPanelEvent（不入主干）
未识别                                    Raw { kind, raw_payload }
```

### 5.5 Approval / Permission 双轨（具体）

UI 端 `ApprovalCardView` 主干壳显示 `kind + summary`（共用），底部按 `agent_kind` 渲染：

- **Codex 卡片底部**：Sandbox 切换、Persist 复选框、Policy 切换
- **CC 卡片底部**：当前 permission mode 显示、is-plan-mode 提示、工具名

这是"整体范式统一 + vendor 语义保留"在最敏感场景的具体兑现。

### 5.6 历史层（事实唯一来源）

| 操作 | 实现 |
|---|---|
| List | `claude agents --json --all [--cwd <path>]` 解析 JSON 数组（已有官方接口，不扫文件） |
| Read | 解析 `claude agents --json` 拿到 session_id，再读 `~/.claude/projects/<encoded_cwd>/<id>.jsonl` |
| Rename | `claude --resume <id> --name <new> -p ""` 即刻 detach（用 CC 原生 `--name`）或下次启动时改名 |
| Archive | `claude rm <id>` —— CC 官方"软删"，transcript 仍可 `--resume` |
| Unarchive | 不需要——`--resume <id>` 永远能找到（archive 是软隐藏） |

**`cc-meta/` 不存在**（N8 守护）。

### 5.7 认证

- AgentDeck **不读 / 不存 / 不转发** Claude 凭证
- 子进程继承 user environment → 复用 `claude login` 已有状态
- Capabilities 中 `auth_status` 通过 `claude auth status` (exit code 0/1 + JSON) 探测，不读凭证内容
- 与 Codex "不接触 token" 完全对称（K9）

### 5.8 失败处理

| 失败场景 | 行为 |
|---|---|
| `claude` 二进制不存在 | adapter 启动返回 `Error { code: "cc-not-installed" }` + 友好诊断（提示 `npm install -g @anthropic-ai/claude-code`） |
| `claude` 版本太老（不支持 `--output-format stream-json`） | `Error { code: "cc-version-too-old" }` + 最低版本提示 |
| 用户未 login | `Error { code: "cc-not-authenticated" }` + 引导命令 |
| stream-json 解析失败 | 同 Codex 处理：保留尾部 stderr、写诊断、UI 显示可见错误 |

---

## 6. macOS UI 改造清单（AppKit）

**硬约束**：v0.2–v0.4 macOS UI **继续 AppKit**，不引入 SwiftUI。

### 6.1 现有 25 个 Swift 文件处置

详见对应表（节 6 的处置矩阵保留，本 spec 摘要如下）：

- **流式渲染层 14 个文件**：全部保留，零改动或微调（保护 v0.1 已交付的 19 个 commit）
- **入口与组装层 5 个**：微改造（`SessionViewController` 加 ToolBar 槽位、`StatusBarView` 显示 agentKind、`InputBarView` 显示 plan 徽章、`AppDelegate`/`main` 不变）
- **协议传输层 4 个**：升级到 v2（`DaemonClient`、`DaemonTransport` 抽象、`ProcessDaemonTransport`、`AgentItemReducer`）
- **模型层 3 个**：改造加 agentKind/capabilities（`WorkbenchModel`、`ThreadRuntimeModel`、`SessionModel`）
- **历史层 3 个**：改造跨 agent 聚合（`HistoryModel`、`HistorySidebarViewController`、`HistoryRowViews`）
- **审批层 1 个**：重大改造（`ApprovalCardView` 拆"主干壳 + vendor SubView"）

### 6.2 新增 13 个 Swift 文件

```text
Sources/AgentDeck/
├── capability/
│   ├── CapabilityRouter.swift                  ← 核心：capability → SubView 路由
│   └── AgentKindIcon.swift                     ← SF Symbol / SVG 资源映射
├── session/
│   ├── NewSessionDialog.swift                  ← 新会话向导：选 agent → 配 vendor options → cwd
│   └── AgentControlBar.swift                   ← 顶部控件条主壳
├── agent/codex/
│   ├── CodexApprovalPanel.swift                ← ApprovalCard Codex 底部
│   ├── CodexControlsView.swift                 ← Codex 顶部 mini
│   └── CodexSessionOptionsForm.swift           ← NewSession Codex 配置
├── agent/claudecode/
│   ├── ClaudeCodePermissionPanel.swift         ← ApprovalCard CC 底部
│   ├── ClaudeCodeControlsView.swift            ← CC 顶部 mini（含 plan 徽章）
│   ├── ClaudeCodeSessionOptionsForm.swift      ← NewSession CC 配置
│   └── ClaudeCodeAuthStatusBadge.swift         ← claude auth status 探测显示
├── common/
│   ├── AgentTokenAuthMiniPanel.swift           ← 通用 token + auth mini
│   └── ReasoningEffortPicker.swift             ← 两家通用 reasoning effort 下拉
└── Resources/
    └── claude.svg                              ← CC 图标（LobeHub Icons）
```

### 6.3 Rust 侧镜像改造

```text
agentdeck-protocol/src/
├── lib.rs                  (拆分多 mod 入口)
├── trunk.rs               (新增) ← Layer A
├── capabilities.rs        (新增)
├── vendor/
│   ├── mod.rs            (新增)
│   ├── codex.rs          (新增)
│   └── claude_code.rs    (新增)
├── transport.rs          (新增) ← Transport trait
└── neutrality_tests.rs   (新增) ← N1/N4 守护

agentdeckd/src/
├── main.rs               (保留)
├── ipc.rs                (改：re-export v2)
├── runtime/              (新增模块)
│   ├── mod.rs
│   ├── hub.rs            ← 现 RuntimeHub 内容迁入
│   └── router.rs         (新增 AgentRouter)
├── agent.rs              (新增 Agent trait + AgentKind)
├── codex/                (新增：现 codex.rs 拆入)
│   ├── mod.rs
│   ├── adapter.rs
│   ├── translate.rs
│   └── capabilities.rs
├── claude_code/          (新增 CC adapter)
│   ├── mod.rs
│   ├── adapter.rs        ← spawn claude CLI + stream-json 解析
│   ├── translate.rs      ← CC message → AgentItem 映射
│   ├── capabilities.rs
│   ├── auth.rs           ← claude auth status 探测
│   └── history.rs        ← claude agents --json + 直读 .jsonl
├── record.rs             (改：加 agentKind)
└── diag.rs               (改：诊断事件加 agentKind)

agentdeck-cli/src/
├── commands.rs           (改：加 --agent codex|claude-code 路由)
├── commands_agent.rs     (新增) ← agent list / capabilities 子命令
└── client.rs             (改：v2 协议)
```

### 6.4 agentdeck-cli v0.2 新增子命令

```bash
agentdeck agent list                           # 列出可用 adapter
agentdeck agent capabilities --agent <kind>    # 列某 adapter capabilities (JSON)
agentdeck session run --agent codex --cwd . \
  --sandbox workspace-write --approval on-request --persist-approval
agentdeck session run --agent claude-code --cwd . \
  --permission acceptEdits --output-style explanatory
agentdeck history list                         # 默认跨 agent
agentdeck history list --agent claude-code     # 仅 CC
agentdeck history read <id> --agent <kind>     # 读取（必须带 agent_kind）
agentdeck history archive <id> --agent <kind>
agentdeck history rename <id> --agent <kind> <title>
```

---

## 7. 测试矩阵（用户硬约束：尽可能完善自动化 + E2E）

**测试是 v0.2 的一等交付物**。下表覆盖从单元到端到端的所有层次，所有项目都必须随 v0.2 入主分支。

### 7.1 协议契约测试（`agentdeck-protocol`）

| 测试 | 守护点 |
|---|---|
| `schema_matches_committed_snapshot` | 改协议必须重生成快照 |
| `protocol_neutrality_main_trunk` | N1：主干类型不出现 `Codex` / `OpenAI` / `Anthropic` / `Claude` 字样 |
| `capabilities_namespace_is_typed` | N4：vendor enum variant 不含 `serde_json::Value` 或裸 `String` raw payload |
| `agent_kind_appears_on_every_trunk_event` | K4：扫主干 enum 全部 variant 都有 `agent_kind` 字段 |
| `vendor_options_enum_exhaustive` | 每个 `AgentKind` 都在 `VendorSessionOptions` 有对应 variant |
| `transport_trait_remote_ready` | N6：Transport trait 异步 + 可重连 + 可携带 auth context（编译期断言） |

### 7.2 Rust 单元测试

| 模块 | 测试 |
|---|---|
| `agentdeckd/src/runtime/router.rs` | sessionId → adapter 路由；agentKind 不可变；并发锁 |
| `agentdeckd/src/agent.rs` | Agent trait 默认实现；capabilities 注册 |
| `agentdeckd/src/codex/translate.rs` | Codex item → AgentItem 映射（已有，扩展）|
| `agentdeckd/src/codex/capabilities.rs` | 返回的 capabilities 覆盖 Codex 已支持的能力 |
| `agentdeckd/src/claude_code/translate.rs` | CC stream-json → AgentItem 映射（fixture 重放） |
| `agentdeckd/src/claude_code/capabilities.rs` | CC capabilities 完整；N5 对称约束验证 |
| `agentdeckd/src/claude_code/auth.rs` | `claude auth status` 退出码解析 |
| `agentdeckd/src/claude_code/history.rs` | `claude agents --json` 解析；`.jsonl` 读取；archive 调 `claude rm` |
| `agentdeckd/src/record.rs` | agentKind 字段写入 |
| `agentdeckd/src/diag.rs` | 诊断事件 agentKind 标注 |

### 7.3 Rust 集成测试（fixture 重放）

| 测试 | fixture 来源 |
|---|---|
| `codex_session_e2e_fixture` | 既有 Codex fixture（保留） |
| `claude_code_session_e2e_fixture` | 录制 `claude --print --output-format stream-json` 的真实输出作 fixture（**v0.2 必须建**） |
| `cc_permission_prompt_fixture` | 录制 CC 触发 tool_use(Bash) 需 permission 的输出 |
| `cc_plan_mode_fixture` | 录制 `--permission-mode plan` 模式输出 |
| `cc_hook_events_fixture` | 录制 `--include-hook-events` 输出 |
| `cc_image_input_fixture` | 含图片输入的会话 |
| `session_capabilities_before_agent_item` | N7 序约束 |
| `runtime_hub_concurrent_sessions` | 两个不同 agentKind 的 session 同时跑互不影响 |

fixture 文件位置：`agentdeckd/tests/fixtures/{codex,claude_code}/*.jsonl`

### 7.4 Swift 单元测试

| 测试 | 内容 |
|---|---|
| `ProtocolSchemaConformanceTests` | 已有，升级到 v2 |
| `LineFramingTests` | 已有 |
| `HeadlessRequestEncodingTests` | 已有 + 加 CC session start 编码 |
| `CapabilityRouterTests`（新） | 给不同 capabilities 集合，路由出正确 vendor SubView 类型 |
| `AgentKindAnnotationTests`（新） | 所有事件主干消息都带 agentKind |
| `ClaudeCodeSessionEncodingTests`（新） | CC SessionStart 编码符合 v2 |
| `HistorySidebarUnifiedHistoryTests`（新） | 侧栏不暴露 agent 切换控件；历史行不显示 agent 来源文案或图标 |
| `ApprovalCardVendorBottomViewTests`（新） | 主干壳 + vendor 底部 SubView 装配 |
| `NewSessionDialogFlowTests`（新） | 选 agent → vendor options 表单显示正确字段 → 提交编码 |
| `ClaudeCodeAuthStatusBadgeTests`（新） | 模拟 auth status 三态显示 |

### 7.5 Lint / 静态约束测试

| 测试 | 守护点 |
|---|---|
| `NoVendorBranchInUITests`（Swift） | grep + AST 扫描禁止 `if .*agentKind\s*==\s*\.(codex|claudeCode)` 这种硬编码分支（N2） |
| `NoCcMetaDirCreated`（Rust） | 扫源代码禁止创建 `cc-meta/` 目录或文件路径（N8） |
| `AdaptersMutualIgnorance`（Rust） | `codex` 模块不能 use `claude_code` 任何类型，反之亦然（N3） |
| `NoSdkValueTransport`（Rust） | vendor enum variant 不含 `serde_json::Value` 字段（N4，与 7.1 互补） |

### 7.6 CLI 门控 E2E（真实 vendor）

`AGENTDECK_E2E=1` 门控（默认 cargo test 跳过）：

```bash
AGENTDECK_E2E=1 cargo test -p agentdeck-cli --test e2e_codex
AGENTDECK_E2E=1 cargo test -p agentdeck-cli --test e2e_claude_code
AGENTDECK_E2E=1 cargo test -p agentdeck-cli --test e2e_cross_agent_history
```

每个 E2E 必须涵盖：

| E2E 流程 | Codex | CC |
|---|---|---|
| `agentdeck ping` → pong | ✅ | ✅ |
| `agentdeck selfcheck` | ✅ | ✅ |
| `agentdeck agent list` 包含两家 | ✅ | ✅ |
| `agentdeck agent capabilities --agent <kind>` 返回非空 | ✅ | ✅ |
| `agentdeck session run` 单 turn 完成 | ✅ | ✅ |
| `agentdeck session run` 触发 approval → approve → 完成 | ✅ | ✅ |
| `agentdeck session continue` 继续历史 | ✅ | ✅ |
| `agentdeck history list` 跨 agent 包含两家创建的 thread | ✅ | ✅ |
| `agentdeck history read <id> --agent <kind>` 返回 turns | ✅ | ✅ |
| `agentdeck history archive <id> --agent claude-code` 后 `list` 不可见，再 `read` 仍可读 | — | ✅ |
| `agentdeck history rename <id> --agent claude-code <title>` 生效 | — | ✅ |
| 错误码：`agentdeck session run --agent claude-code`（卸载 `claude` 后）→ exit 5 + `cc-not-installed` | — | ✅ |

### 7.7 Swift 手动 QA 清单（写入 `docs/QUALITY.md`）

每次 v0.2 发布前必须勾选：

- [ ] 同窗口可启动 Codex 会话 / CC 会话 / 在两者间切换
- [ ] CC 流式消息、reasoning、shell、diff 渲染对等于 Codex
- [ ] CC permission mode（6 种）下拉可切换，新 turn 生效
- [ ] Plan mode 进入后 UI 显示 Plan 内容并可批准/拒绝
- [ ] CC tool use 触发 approval 时显示卡片，底部 vendor 区显示"当前 permission mode + tool name"
- [ ] Codex tool use 触发 approval 时显示卡片，底部 vendor 区显示 sandbox + policy + persist
- [ ] CC 历史 thread 在侧栏与 Codex 历史共存，左侧默认合并显示且不提供 agent 切换
- [ ] CC 历史 thread 点开可回放 + 继续
- [ ] CC archive (`claude rm` 调用) 后侧栏不可见，且不影响 Codex 历史显示
- [ ] CC rename 后侧栏标题更新；终端 `claude --resume <id>` 看到同名
- [ ] CC 未登录 → 明确诊断错误，不静默
- [ ] CC 二进制不存在 → 明确诊断错误，附 `npm install` 提示
- [ ] Token usage 在 mini 面板显示
- [ ] Output Style 下拉可见
- [ ] CC capability、Codex 没的，UI 仅在 CC session 显示对应控件
- [ ] Codex capability、CC 没的，UI 仅在 Codex session 显示对应控件
- [ ] AgentDeck 创建的 CC 会话，在终端 `claude --resume <id>` 能看见且能继续（事实唯一来源验证）
- [ ] `cargo test` + `swift test` + `agentdeck selfcheck` + `scripts/verify-agent-docs.sh` 全绿

### 7.8 性能与回归

| 测试 | 阈值 |
|---|---|
| `cc_streaming_throughput_bench` | 单 session 在 100KB/s stream-json 持续输入下，主循环不阻塞（>30fps 刷新） |
| `concurrent_sessions_bench` | 8 个并发 session（Codex × 4 + CC × 4），无死锁、无并发 turn 违反 K2 |
| `history_load_5k_threads_bench` | 5000 条混合 agent 历史 list/分组 < 200ms |

---

## 8. 验收清单（v0.2 release gate）

发布 v0.2 前必须全部满足：

- [ ] 节 7.1 协议契约测试全绿
- [ ] 节 7.2 Rust 单元测试全绿
- [ ] 节 7.3 fixture 重放测试全绿（含 CC 全部 fixture）
- [ ] 节 7.4 Swift 单元测试全绿
- [ ] 节 7.5 lint / 静态约束测试全绿
- [ ] 节 7.6 门控 E2E 真实 vendor 全绿（`AGENTDECK_E2E=1`）
- [ ] 节 7.7 Swift 手动 QA 清单全部勾选
- [ ] 节 7.8 性能基准达标
- [ ] `NORTH_STAR.md` / `README.md` / `ARCHITECTURE.md` 重写完成
- [ ] `AgentDeck_v0.1_Product_Definition_Workbench.md` 归档至 `docs/archive/`
- [ ] `docs/AGENT_DIAGNOSTICS.md` 新增 CC failure code
- [ ] `docs/QUALITY.md` 新增 v0.2 手动 QA 清单
- [ ] `protocol/agentdeck/agentdeck-protocol.schema.json` 重生成（v2）
- [ ] `scripts/verify-agent-docs.sh` 通过

---

## 9. 风险与开放问题

### 9.1 已知风险

| 风险 | 缓解 |
|---|---|
| `claude` CLI 输出格式（stream-json）在 minor 版本间变化 | fixture 重放 + 在 README 标注最低支持版本；启动时探测版本（`claude --version`）不符则警告 |
| CC 会话 UUID 与 Codex thread id 命名冲突的可能 | sessionId 与 threadId 都是不透明字符串，UI 只查 agentKind 路由，本质无冲突 |
| Capabilities enum 修改频繁打破 schema 漂移 | v0.2 是早期阶段，接受这种摩擦；用户已明示"能力第一" |
| ApprovalCardView 拆 vendor SubView 带来的 view layout 复杂度 | v0.1 已有 ApprovalCard 实现可参考；新增 vendor SubView 走 AutoLayout 标准模式 |
| CC 的 `--worktree` 与 Codex 的 worktree 语义不完全对等（Codex 是 thread 绑定，CC 是路径绑定） | v0.2 仅声明 `Worktree` capability，UI 推到 v0.3 一起设计 |
| Subagent 驱动开发时 vendor 控件并行实现可能冲突 | 使用 `agent/codex/` 与 `agent/claudecode/` 严格目录隔离；用 git worktree 隔离任务 |

### 9.2 开放问题

| 问题 | 决策时机 |
|---|---|
| Codex 也有 `reasoning_effort` 但值集和 CC 不同（high/medium/low/minimal vs low/medium/high/xhigh/max）— 是否在 IPC 主干用 enum 统一？ | 实施时决定。倾向：各家保留各自 enum，UI 端 `ReasoningEffortPicker` 按 capability 渲染不同选项 |
| `claude --remote-control` / `--remote` 这种 CC 原生远程能力，v0.5 远程化时是否复用？ | v0.5 design 时再决定 |
| CC 已有插件系统 (`--plugin-dir`)，v0.7 AgentDeck 插件如何与之分层？ | v0.7 design 时展开（已在节 2 标注分两层方向） |
| `claude agents` 后台并行会话模型是否进入 v0.4 Workbench？ | v0.4 design 时决定 |
| v1.0 是否引入 Claude Agent SDK 作为"高级模式"（用户提供 API key 时启用）以解锁 in-process hooks？ | v1.0 设计时再议 |

---

## 10. 文档同步与变更清单

### 10.1 重写

| 文件 | 状态 |
|---|---|
| `NORTH_STAR.md` | 整体重写（草案见节 1.2） |
| `README.md` | 重写架构图与"v0.1 范围"段；加"CC 一等公民"段 |
| `ARCHITECTURE.md` | 废止 W1/W2/W3；新增 N1–N8；更新分层与依赖方向图 |

### 10.2 修订

| 文件 | 改动 |
|---|---|
| `AGENTS.md` | 必读顺序加上新 spec 路径；提及 CC adapter 注意事项 |
| `docs/index.md` | 顶层导航补充 |
| `docs/QUALITY.md` | 新增 v0.2 手动 QA 清单（节 7.7） |
| `docs/AGENT_DIAGNOSTICS.md` | 新增 CC failure code |
| `protocol/agentdeck/agentdeck-protocol.schema.json` | 自动重生成（v2） |
| `protocol/agentdeck/README.md` | 说明两层结构与 vendor 命名空间 |

### 10.3 归档

| 文件 | 目标位置 |
|---|---|
| `AgentDeck_v0.1_Product_Definition_Workbench.md` | `docs/archive/2026-06-27-original-pdw.md` |

### 10.4 新增

| 文件 | 用途 |
|---|---|
| `docs/plans/2026-06-30-unified-shell-v02-design.md` | 本 spec |
| `docs/plans/2026-06-30-unified-shell-v02-implementation.md` | 实施计划（由 writing-plans skill 在 spec 批准后产出） |
| `docs/archive/README.md` | 解释归档目录用途（如不存在） |

---

## 11. 实施推进方式

按用户既定偏好（[[agentdeck-workflow-prefs]]）：

- 直接在 `master` 上实现，不另开 worktree（除非任务级隔离需要）
- 未经明确请求**不 `git push`**
- 接受 **subagent 驱动开发**（每任务派子代理 + 两阶段评审）
- 提交信息**不带 co-author / Codex 协作者信息**
- 每个阶段性收口前运行 `cargo test` + `swift test` + `agentdeck selfcheck` + `scripts/verify-agent-docs.sh`

具体任务拆分、依赖关系和并行度分析由 implementation 计划（节 10.4 第二行）覆盖，由 writing-plans skill 在本 spec 批准后产出。
