# agentdeckd 功能完整度

本文持续追踪 `agentdeckd` 已落地能力、当前缺口和验证证据。它描述当前代码事实，
不代替产品北极星、稳定架构或具体实施计划。

- 首次盘点基线：`7bebadc`（2026-08-17）
- 当前桌面边界：GPUI 桌面尚未连接 daemon；本页的 backend 能力不能直接视为
  桌面端可用能力。
- 当前 Codex 接入：`agentdeckd` 直接启动 `codex app-server` 子进程；不使用 managed
  daemon/proxy。
- desktop 接入前的目标边界：
  `docs/plans/2026-08-17-codex-app-server-lifecycle-adr.md` 与
  `docs/plans/2026-08-17-agentdeckd-minimum-stable-boundary-design.md`；两者是已接受设计，
  不是当前实现状态。

## 状态定义

本页只使用以下四种状态：

| 状态 | 含义 |
| --- | --- |
| 较完整 | 主要路径和失败路径已经实现并有对应测试；剩余问题不阻断该能力在当前边界内使用。 |
| 部分 | 主要路径可运行，但存在会影响受支持用法的明确缺口，或缺少关键真实链路证据。 |
| 骨架 | 类型、接口、helper 或局部测试已存在，但尚未接入生产事件流或没有形成可操作闭环。 |
| 未接通 | 当前入口无法使用该能力，或实现明确返回不支持、丢弃关键事件、仅返回无效果 Ack。 |

## 事实源

判断按以下优先级取证：

1. `agentdeck-protocol/src/`：AgentDeck 中立 IPC 类型、capabilities 和 schema 派生源。
2. `agentdeckd/src/runtime/`、`agentdeckd/src/agent.rs`：daemon 调度、session 路由和
   adapter 契约。
3. `agentdeckd/src/codex/`、`agentdeckd/src/claude_code/`：两家 vendor 的启动、
   翻译、审批、取消和历史实现。
4. `agentdeckd/src/record.rs`、`agentdeckd/src/diag.rs`：运行记录与诊断基础设施。
5. `agentdeck-cli/src/`、`agentdeck-cli/tests/`：当前可操作入口与 E2E 证据。
6. `protocol/`：由官方 `codex app-server generate-json-schema` 生成的 Codex 协议快照。

README、架构、诊断和计划文档用于解释目标与不变量；当文档描述和可执行代码不一致
时，以代码、协议快照及可复验结果为当前状态依据，同时修正文档漂移。

## 能力矩阵

| 范围 | 能力 | 状态 | 当前事实与边界 | 主要证据 |
| --- | --- | --- | --- | --- |
| daemon runtime | JSONL stdin/stdout 与单 writer | 较完整 | 能解析 `ClientCommand`，统一串行写出 streaming event 与 admin reply；坏 JSON 会返回结构化错误。 | `agentdeckd/src/runtime/hub.rs` |
| daemon runtime | 长任务不阻塞控制命令 | 较完整 | start、continue、history 由独立 task 执行，ping、cancel 等仍可被读取；history 有总 timeout。 | `agentdeckd/src/runtime/hub.rs` |
| daemon runtime | adapter 注册与 typed router | 较完整 | Codex、Claude Code 通过同一 `Agent` trait 注册，按 `AgentKind` 和 `sessionId` 路由；两家实现互不依赖。 | `agentdeckd/src/agent.rs`、`agentdeckd/src/runtime/router.rs` |
| daemon runtime | session 生命周期与并发约束 | 部分 | session 所有权映射与取消路由存在；当前映射并不真正阻止同一 thread/session 并发 turn，turn 自然结束后也没有完整的自动清理闭环。 | `agentdeckd/src/runtime/hub.rs`、`agentdeckd/src/runtime/router.rs` |
| daemon runtime | cancel | 部分 | 能中止 pump 并结束 vendor 进程组；语义是结束整个短生命周期 vendor 进程，不是 vendor 原生 turn interrupt，也没有 steer。 | 两个 adapter 的 `cancel` 实现 |
| admin | ping、协议版本/schema、agent list/capabilities | 较完整 | 已有 typed command 和 CLI 入口，回复由单 writer 输出。 | `agentdeckd/src/runtime/hub.rs`、`agentdeck-cli/src/` |
| admin | selfcheck | 部分 | `agentdeckd --selfcheck` 验证数据目录、诊断和 record 写入；CLI selfcheck 验证 daemon IPC 与静态 adapter 注册。两者都不证明 vendor CLI 登录、握手、真实 turn 或历史来源健康。 | `agentdeckd/src/main.rs`、`agentdeckd/src/runtime/hub.rs` |
| Codex | app-server 进程与 JSON-RPC | 部分 | 已有二进制定位、独立进程组、initialize response 关联、timeout 和 stderr drain；但没有发送规范握手所需的 `initialized` notification，`turn/start` 只写 frame 而不等待 response，mid-turn EOF 可静默结束 pump；当前也没有 Ready 后在同一 session 发起下一轮的命令路径，以及显式 SessionClose、child wait 和 session 路由清理闭环。 | `agentdeckd/src/codex/app_server.rs`、`agentdeckd/src/codex/adapter.rs` |
| Codex | 新 session | 部分 | 能执行 `thread/start` 与 `turn/start` 并产出中立事件；真实链路仍需门控 E2E，部分协议终态字段尚未正确消费。 | `agentdeckd/src/codex/adapter.rs`、`agentdeckd/src/codex/translate.rs` |
| Codex | continue | 部分 | `thread/resume` 实际只传 `threadId`，随后 `turn/start` 只下发固定的 medium effort。workspace-write/on-request 只是本地 translator 的审批上下文假定，没有恢复或下发到已有 thread。 | `agentdeckd/src/codex/adapter.rs` |
| Codex | 消息、reasoning、plan、shell、diff、tool 翻译 | 部分 | 常见 completed item 能映射到中立类型，未知 item 有受限 raw 降级；若干 progress、usage 和 vendor panel 信息未进入主干。 | `agentdeckd/src/codex/translate.rs` |
| Codex | 客户端可见实时 delta | 未接通 | translator 在 daemon 内累积 delta，只在 item completed 时发一次完整 `AgentItem`；客户端看不到 token/tool progress 流。 | `agentdeckd/src/codex/translate.rs` |
| Codex | turn 终态 | 部分 | 已发 `TurnComplete`，但官方 status 与 duration 位于 `params.turn`，当前 translator 却读取 `params` 顶层，也没有把 completed/interrupted/failed 可靠映射为 succeeded/canceled/failed。usage 来自独立的 `thread/tokenUsage/updated` notification，不在 `params.turn`；该 notification 当前被忽略。 | `agentdeckd/src/codex/translate.rs`、`protocol/ServerNotification.json` |
| Codex | command/file/permission 审批 | 部分 | JSON-RPC request 可映射为 `ActionRequest`，approve/deny 可按 rpc id 回写；`persist` 未真正参与响应，用户输入类请求也未形成统一回答闭环。 | `agentdeckd/src/codex/adapter.rs`、`agentdeckd/src/codex/translate.rs` |
| Codex | history list/read | 部分 | 使用官方 `thread/list`、`thread/read(includeTurns=true)`，短生命周期 app-server 有方法级和总 timeout；但同样只等待 initialize response，没有发送 `initialized` notification，尚不满足固定协议版本的完整握手。 | `agentdeckd/src/codex/history.rs`、`agentdeckd/src/codex/app_server.rs` |
| Codex | history archive/unarchive/rename | 未接通 | 三项当前都返回明确的 `codex-*-not-supported` 错误。 | `agentdeckd/src/codex/history.rs` |
| Claude Code | 安装、版本、认证预检 | 部分 | 有结构化 failure code 和启动前探测；selfcheck 本身不执行完整真实 turn。 | `agentdeckd/src/claude_code/auth.rs`、`agentdeckd/src/claude_code/capabilities.rs` |
| Claude Code | 新 session | 部分 | 能以 `--print`、stream-json 启动并翻译结果；真实 vendor 行为仍受本机版本、登录及门控 E2E 约束。 | `agentdeckd/src/claude_code/adapter.rs` |
| Claude Code | continue | 部分 | 能按 session id resume；当前强制使用 `bypassPermissions`，没有恢复原 session 的 permission mode 及其余启动配置。 | `agentdeckd/src/claude_code/adapter.rs` |
| Claude Code | 消息、tool、hook、system status 翻译 | 部分 | completed result 和主要事件可中立化；partial `stream_event` 被丢弃，工具进度与部分终态信息不保真。 | `agentdeckd/src/claude_code/translate.rs` |
| Claude Code | 客户端可见实时 delta | 未接通 | `stream_event` partial delta 明确不发给客户端，只消费最终 snapshot。 | `agentdeckd/src/claude_code/translate.rs` |
| Claude Code | 审批 | 骨架 | 有 request route 与 decision 写回代码，但 `permission_response` wire shape 在源码中仍标为 speculative，缺真实 fixture 与 E2E 证明。 | `agentdeckd/src/claude_code/adapter.rs` |
| Claude Code | history list/read | 部分 | 能扫描 CC 原生 JSONL 并构造列表和读取结果；这是本地格式解析，需随受支持 CC 版本持续验证保真性。 | `agentdeckd/src/claude_code/history.rs` |
| Claude Code | history rename | 部分 | 通过 CC 原生 resume/name 命令更新标题；单测只覆盖 custom-title 解析，真实 rename 仅存在门控 E2E，本次盘点未记录该 E2E 的实跑回执。 | `agentdeckd/src/claude_code/history.rs`、`agentdeck-cli/tests/e2e_claude_code.rs` |
| Claude Code | history archive/unarchive | 未接通 | archive 对普通 print session 没有稳定原生语义，可能返回不支持；unarchive 当前只是无效果 Ack。 | `agentdeckd/src/claude_code/history.rs`、`agentdeckd/src/claude_code/adapter.rs` |
| shared history | 跨 agent list | 较完整 | 两个来源并发查询、独立 deadline、best-effort 合并、按最近活动排序并应用总 limit；全部失败与合法空结果可区分。 | `agentdeckd/src/runtime/router.rs` |
| vendor control | session 内控制更新 | 骨架 | typed payload 与路由存在；Codex 返回 requires-new-turn，CC 多数控制返回 requires-new-turn 或 not-supported。 | 两个 adapter 的 `submit_vendor_control` |
| observability | run record | 骨架 | JSONL、脱敏、header/event/footer helper 与测试存在；生产 RuntimeHub 和 adapter 事件流尚未调用 `RunRecord`。 | `agentdeckd/src/record.rs` |
| observability | diagnostic log/report | 骨架 | 有结构化日志、数据目录和聚合报告；生产写入主要覆盖 daemon 启停/selfcheck，尚未贯穿 session、adapter、approval、history，`diagnosticRef` 多为空。 | `agentdeckd/src/diag.rs`、`agentdeckd/src/main.rs` |
| quality | 默认测试离线安全 | 未接通 | `cargo test -p agentdeckd` 会发现 shape integration tests；`cc_adapter_shape` 只按 `claude` 是否在 PATH 决定是否发送真实 prompt，`codex_adapter_shape` 也只按 PATH 决定是否 spawn 真实 app-server/thread，均未统一受 `AGENTDECK_E2E` 门控。 | `agentdeckd/tests/cc_adapter_shape.rs`、`agentdeckd/tests/codex_adapter_shape.rs` |
| CLI | admin、session、history | 部分 | ping/selfcheck、协议、agent、run/continue 和 history 已暴露；没有完整的顶层 cancel、交互审批和 vendor-control 使用闭环。 | `agentdeck-cli/src/main.rs`、`agentdeck-cli/src/commands.rs` |
| product integration | GPUI desktop → daemon | 未接通 | 当前桌面 bundle 不携带、不启动、不连接 `agentdeckd`，也没有会话、审批或历史 UI。 | `README.md`、`docs/QUALITY.md`、`agentdeck-desktop/` |

## 关键缺口

以下缺口会阻断“desktop 接入前，先稳定一条 daemon 最小完整功能”：

1. **事件更新契约尚未闭合。** 两家 adapter 都只发 completed snapshot；协议中的
   `AgentItem` 没有足以支持客户端稳定更新同一条消息或工具执行的 item identity。
2. **turn 终态不够可信。** 至少 Codex 的成功、失败、中断、usage 与耗时没有按官方
   结构完整映射，客户端无法只靠终态判断本轮结果。
3. **session 生命周期不完整。** 缺少可靠的单 turn 所有权、自然结束清理、同一 thread
   并发约束和后续 turn 的配置恢复；Codex 还缺 `initialized`、`turn/start` response、
   EOF terminal 和 child wait 的规范闭环。
4. **审批声明超过证据。** Codex 的 `persist` 未落实；Claude Code decision wire 尚未
   真实验证。capabilities 不应把这些描述成已稳定能力。
5. **可观测链没有接入运行路径。** 发生 vendor 启动、翻译、审批或历史错误时，run
   record 和 `diagnosticRef` 还不能提供完整关联证据。新的 M0 边界已经把可回放 record
   与关联 diagnostics 纳入验收，因此两项都是 M0 阻断，不是可推迟的增强。
6. **默认测试不是离线安全门禁。** 安装了 `claude` 或 `codex` 时，broad daemon test
   可能启动真实 vendor、创建 thread 或发送 prompt；这会让默认验证产生外部副作用。
7. **当前操作入口不能覆盖协议表面。** CLI 缺少可交互的 cancel、审批回写和 vendor
   control；GPUI desktop 仍完全未接入。

## 证据与验证边界

### 当前不创建真实 vendor session 的验证

```bash
env -u AGENTDECK_E2E cargo test -p agentdeck-protocol --lib
env -u AGENTDECK_E2E cargo test -p agentdeckd --lib
env -u AGENTDECK_E2E cargo test -p agentdeckd --test agent_trait_shape
env -u AGENTDECK_E2E cargo test -p agentdeckd --test agent_router
env -u AGENTDECK_E2E cargo test -p agentdeckd --test codex_translate
env -u AGENTDECK_E2E cargo test -p agentdeckd --test cc_translate
env -u AGENTDECK_E2E cargo test -p agentdeckd --test cc_fixture_replay
env -u AGENTDECK_E2E cargo test -p agentdeckd --test cc_system_events
```

- 上述 lib 和 focused targets 不包含已知会启动真实 vendor session 的 shape tests，能证明
  协议序列化、fixture 翻译、router 行为、timeout 与本地 helper 的确定性行为。但
  `agentdeckd --lib` 的 capability probe 当前仍会对 PATH 中的 `codex` / `claude` 执行
  本地 `--version`；它不发 prompt、不建 session，也不读真实 history，但不是零 vendor
  process 的 hermetic 验证。
- 在“默认测试离线安全”修复前，不要把 `cargo test`、`cargo test -p agentdeckd` 或
  `cargo test --workspace` 作为默认离线验证入口。
- daemon/CLI selfcheck 和 diagnostics report 仍可用于显式 plumbing 排查，但它们会访问
  AgentDeck 数据目录，也不证明 vendor 可用、M0 record 已接线或真实 session 已闭环。

### 真实链路必须额外证明什么

```bash
AGENTDECK_E2E=1 cargo test -p agentdeck-cli --test e2e_codex -- --nocapture
AGENTDECK_E2E=1 cargo test -p agentdeck-cli --test e2e_claude_code -- --nocapture
AGENTDECK_E2E=1 cargo test -p agentdeck-cli --test e2e_cross_agent_history -- \
  --nocapture --test-threads=1
```

- 这些测试会真实使用本机 vendor CLI、登录状态和用户配置，只能在明确允许创建真实
  vendor 会话的环境运行。
- 当前门控不统一：CLI E2E 用“环境变量存在”判断，`AGENTDECK_E2E=0` 也会启用；部分
  daemon E2E 要求值严格等于 `1`；两个 adapter shape 文件则只看 vendor binary 是否在
  PATH，完全不看该变量。上述不创建 session/prompt 的 focused/lib 命令必须用
  `env -u AGENTDECK_E2E`，真实验证统一显式使用 `AGENTDECK_E2E=1`。
- 未启用真实门禁时显示 passed 可能只是测试提前返回；该结果不能作为真实 Codex 或
  Claude Code 链路证据。
- E2E 当前主要验证响应契约形态，不证明流式 delta、审批、取消、配置恢复和所有历史
  管理语义。
- `cargo run -p agentdeck-desktop -- --selfcheck` 只验证 GPUI/Metal/窗口初始化，与
  daemon 或 vendor 链路无关。

## 更新规则

1. 影响 daemon、IPC、adapter、CLI、history、record 或 diagnostics 的变更，必须在同一
   工作切片检查本页对应行是否需要更新。
2. 状态升级必须同时给出实现事实和与风险相称的验证；真实 vendor 行为不能只凭 fixture、
   mock、普通 `cargo test` 或 selfcheck 升级。
3. 若实现明确丢弃关键事件、返回 not-supported、使用 speculative wire，或 Ack 不产生
   可观察效果，保持为“骨架”或“未接通”，不要按类型已经存在来提升状态。
4. capabilities 必须与本页和真实实现一致；能力降级或暂未验证时，优先收紧声明。
5. 每次更新记录新的审计提交和日期；已解决缺口从本页删除，设计取舍与实施步骤写入
   `docs/plans/`，不要把本页扩成实施日志。
6. 在默认测试离线安全修复前，收口只运行明确审计为不创建真实 session/prompt 的
   lib/focused targets，并披露 lib 的本地 `--version` probe；真实 vendor 验证必须显式
   授权并使用 `AGENTDECK_E2E=1`。随后运行
   `scripts/verify-agent-docs.sh` 和 `git diff --check`，只报告实际运行过的命令。
