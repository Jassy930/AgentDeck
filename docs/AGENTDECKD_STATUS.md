# agentdeckd 功能完整度

本文持续追踪 `agentdeckd` 已落地能力、当前缺口和验证证据。它描述当前代码事实，
不代替产品北极星、稳定架构或具体实施计划。

- 首次盘点基线：`7bebadc`（2026-08-17）
- 当前验证：2026-09-21，基于 `32f10e6` 的本次变更。完整离线门禁、8 项实际 CLI
  fake 集成、Swift 和 CLI 自检通过；真实 Codex 四轮 M0 在下述临时配置覆盖环境通过，
  默认本机配置仍不兼容，历史列表首轮超时、复验通过但耗时接近 deadline。
  iOS iPhone 17 Simulator 已执行 21 项测试且全部通过。详见 [M0 CLI 实施记录](plans/2026-09-21-backend-m0-cli-implementation.md)。
- 当前桌面边界：GPUI 桌面尚未连接 daemon；本页的 backend 能力不能直接视为
  桌面端可用能力。
- 当前 Codex 接入：`agentdeckd` 直接启动 `codex app-server` 子进程；不使用 managed
  daemon/proxy。session-scoped owner 与 protocol v4 已实现累计消息、持久 CLI 和生产运行记录；
  真实 vendor 证据必须与离线结果单独记录。
- desktop 接入前的目标边界：
  `docs/plans/2026-08-17-codex-app-server-lifecycle-adr.md` 与
  `docs/plans/2026-08-17-agentdeckd-minimum-stable-boundary-design.md`。代码实现包含生命周期、streaming/item identity、持久 CLI 与 RunRecord/diagnostics；
  M0 已完成限定环境验收；GPUI desktop 尚未接入。

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
| daemon runtime | lifecycle 有序且不阻塞 admin | 较完整 | stdin loop 只把 SessionStart/TurnStart/TurnCancel/SessionClose 入一个有序 worker，防止生命周期命令互相越过；admin 与 history 留在独立路径，因此慢 handshake/control 期间 Ping 仍可响应，history 有总 timeout。stdin EOF 会先 drain 已读 lifecycle 命令，再关闭并等待 retained session；stdout 写失败则立即停止 intake、丢弃尚未执行的 lifecycle 命令、关闭/回收已 retained session，并由 daemon 返回原始 I/O error。 | `agentdeckd/src/runtime/hub.rs` |
| daemon runtime | adapter 注册与 typed router | 较完整 | Codex、Claude Code 通过同一 `Agent` trait 注册，按 `AgentKind` 和 `sessionId` 路由；两家实现互不依赖。 | `agentdeckd/src/agent.rs`、`agentdeckd/src/runtime/router.rs` |
| daemon runtime | session 生命周期与并发约束 | 部分 | protocol v4 使用 caller-owned sessionId/turnId；同一 Codex owner 复用 child/thread，并拒绝并发或重复 turn。SessionClosed 在 child wait、进程组消失、pump join 和路由清理后发出；cleanup 失败 poison 并退出。Codex 真实四轮在临时配置覆盖环境通过，同 PID/threadId 与单次 spawn 已读回；Claude Code 仍为 one-shot。 | `agentdeckd/src/codex/session.rs`、`agentdeck-cli/tests/support/live.rs` |
| daemon runtime | turn cancel / session close | 部分 | Codex TurnCancel 使用官方 interrupt，健康会话回 Ready；SessionClose 才回收 child。session live 暴露完整控制命令，run/continue 保留自动 close/wait；真实四轮已证明第三轮取消后第四轮成功，最终 child/进程组消失。证据限定于下述覆盖环境，Claude Code 尚未迁移。 | `agentdeckd/src/codex/session.rs`、`agentdeck-cli/src/commands.rs` |
| admin | ping、协议版本/schema、agent list/capabilities | 较完整 | 已有 typed command 和 CLI 入口，回复由单 writer 输出。 | `agentdeckd/src/runtime/hub.rs`、`agentdeck-cli/src/` |
| admin | selfcheck | 部分 | `agentdeckd --selfcheck` 验证数据目录、诊断和 record 写入；CLI selfcheck 验证 daemon IPC 与静态 adapter 注册。两者都不证明 vendor CLI 登录、握手、真实 turn 或历史来源健康。 | `agentdeckd/src/main.rs`、`agentdeckd/src/runtime/hub.rs` |
| Codex | app-server 进程与 JSON-RPC | 部分 | locator 解析并固定一个绝对 binary，`--version` 与 `app-server --listen stdio://` 使用同一路径且严格要求 0.145.0。单 owner/reader/RPC allocator 串行关联 initialize、thread、turn 和 interrupt；live 与 short-lived 路径都会按官方 `ClientNotification.json` 在 initialize response 后发送 `initialized`。malformed JSON、未关联 response、EOF 和 unsupported server request 有显式失败路径；live close 在 direct child wait 后还会确认 Unix 进程组消失并 join stderr pump。临时 launcher exec 固定 binary 并覆盖配置后，真实四轮已通过；默认本机配置仍阻断 thread/start。 | `agentdeckd/src/codex/app_server.rs`、`agentdeckd/src/codex/session.rs`、`protocol/ClientNotification.json` |
| Codex | 新 session | 部分 | `SessionStart` 先完成 initialize → initialized → thread/start|resume，再发 `SessionStarted`、`SessionCapabilities`；可携 initial turn，且启动前校验 caller ID、cwd 和固定 M0 options。临时配置覆盖环境已验证原生登录态下的新 thread、握手和 prompt；默认配置的 thread/start 失败未伪造 session ready，cleanup 已确认。 | `agentdeckd/src/codex/adapter.rs`、`agentdeckd/src/codex/session.rs` |
| Codex | resume 与 live 后续 turn | 部分 | resume 验证 threadId 和固定选项；session live 可在同一 daemon/owner/thread 上启动后续 turn。限定环境的真实四轮及 one-shot run/continue 均通过；run/continue 仍各自新建 daemon，该结果不证明原 session 全部启动配置恢复。 | `agentdeckd/src/codex/session.rs`、`agentdeck-cli/tests/e2e_codex.rs` |
| Codex | 固定 M0 options / capabilities | 部分 | 仅接受 never/read-only/medium、persistApproval=false、无 MCP；只声明 StreamingMessages。审批、工具展示和正式 coding session 默认配置不在 M0 范围。 | `agentdeckd/src/codex/adapter.rs`、`agentdeckd/src/codex/capabilities.rs` |
| Codex | 消息、reasoning、plan、shell、diff、tool 翻译 | 部分 | 常见 completed item 能映射到中立类型，未知 item 有受限 raw 降级；若干 progress、usage 和 vendor panel 信息未进入主干。 | `agentdeckd/src/codex/translate.rs` |
| Codex | 客户端可见累计 streaming | 较完整 | 每个非空 assistant delta 发累计快照，带官方 itemId、caller turnId 和 streaming/completed；最终文本不回退、completed 不重复，终态清空缓存。官方形状 fixture、实际 CLI fake 和限定环境的真实四轮链路均覆盖跨轮复用及顺序。 | `agentdeckd/src/codex/translate.rs`、`agentdeckd/src/codex/session.rs` |
| Codex | turn 终态 | 部分 | lifecycle owner 从 `turn/completed.params.turn` 读取 id/status/duration，把 completed/failed/interrupted 映射为 succeeded/failed/canceled；`inProgress` 和未知状态按 fatal protocol failure 收口。每个已接受 turn 使用 typed `TurnFinished(outcome,nextState)`；旧 `TurnComplete` 仅留给未迁移的 Claude Code。真实 succeeded/canceled 已在限定环境验收；真实 failed turn 仍未验收，token usage 尚未进入 summary。 | `agentdeckd/src/codex/session.rs`、`protocol/ServerNotification.json` |
| Codex | command/file/permission 审批 | 未接通 | M0 固定 `approvalPolicy=never`，capabilities 不宣称 approval，`submit_decision` 明确返回不支持。owner 收到任意带 id 的 server request 会回匹配 JSON-RPC not-supported error，并 interrupt/fail 当前 turn，避免静默悬挂；交互式 typed approval 留在 M0 外。 | `agentdeckd/src/codex/adapter.rs`、`agentdeckd/src/codex/session.rs` |
| Codex | history list/read | 部分 | 使用官方 `thread/list`、`thread/read(includeTurns=true)`，短生命周期 app-server 有方法级和总 timeout，并按已提交的官方 `ClientNotification.json` 在 initialize response 后发送 `initialized`；本轮真实 list 首轮超时，默认 500 条复验通过但耗时 27.57 秒，五页聚合接近 deadline，稳定性风险保留；read 尚无本轮真实验收。 | `agentdeckd/src/codex/history.rs`、`agentdeckd/src/codex/app_server.rs`、`protocol/ClientNotification.json` |
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
| observability | run record | 较完整 | router 在 spawn 前打开 session record，单 writer 按事件顺序 append，Codex SessionClosed / CC TurnComplete 后写 footer；启动失败或 legacy EOF/cancel 的遗留记录在 writer drain 后收尾。open/append/close 失败发非终态告警，诊断成功落盘时提供引用；连续 append 失败仅首次及终态告警。CLI 仍等待真实 terminal。JSONL/脱敏/数据目录格式保持不变。 | `agentdeckd/src/runtime/router.rs`、`agentdeckd/src/runtime/hub.rs`、`agentdeckd/src/record.rs` |
| observability | diagnostic log/report | 部分 | Codex lifecycle 已覆盖 spawn/version/PID、RPC、turn outcome、interrupt、cleanup；failure diagnosticRef 仅在成功落盘后返回，对应实际 runId/eventSeq。写失败省略引用并保留 stderr fallback；审批/history 等 M0 外路径尚未贯通。 | `agentdeckd/src/diag.rs`、`agentdeckd/src/codex/session.rs` |
| quality | 默认测试离线安全 | 较完整 | 真实 session、prompt、history、auth 和 vendor process 测试统一只认 `AGENTDECK_E2E=1`；普通 version/auth probe 使用可注入 fake。marker tripwire 通过临时 HOME 隔离用户 vendor history 与默认 AgentDeck data dir，并验证标准 workspace tests 不执行 PATH 中的 vendor shim；macOS workflow 已配置该门禁，首个 hosted run 已在 2026-08-18 通过。普通 passed 仍不代表真实 E2E 已执行。 | `agentdeckd/tests/support/mod.rs`、`scripts/verify-offline-tests.sh`、`.github/workflows/offline-ci.yml` |
| CLI | admin、session、history | 部分 | session live 在一个 daemon 连接上双向转发 typed JSONL，支持顺序多轮、cancel、close、Ping，EOF 有序关闭。run/continue 保持 one-shot；record_write_failed 不终止健康会话。live 是协议驱动入口，尚无交互式审批产品界面。 | `agentdeck-cli/src/commands.rs`、`agentdeck-cli/src/client.rs`、`agentdeck-cli/tests/session_live.rs` |
| product integration | GPUI desktop → daemon | 未接通 | 当前桌面 bundle 不携带、不启动、不连接 `agentdeckd`，也没有会话、审批或历史 UI。 | `README.md`、`docs/QUALITY.md`、`agentdeck-desktop/` |

## 当前验收边界

- #4 的累计 streaming、#5 的持久 CLI 和 #6 的生产记录/诊断已经实现，离线 CLI 用例覆盖同一进程四轮、取消恢复、EOF 和记录写失败。
- 真实四轮 M0 已在 Codex 0.145.0、当前 checkout daemon、`AGENTDECK_E2E=1` 下通过（首版 58.39 秒，PR 修复后复验 50.40 秒）。临时 PATH launcher 使用 `-c features.context_management=false` 覆盖本机不兼容配置；全局配置未改，原生登录未复制。
- 默认本机配置的 `features.context_management` 是 table，0.145.0 要求 bool：initialize 成功后 thread/start 失败，失败路径 cleanup 已确认。该结果不是 failed 模型 turn；覆盖环境的成功也不表示默认环境已修复。
- 真实四轮为 succeeded/succeeded/canceled/succeeded，streaming 快照数为 29/30/2/28；PID `9186`、threadId `01a0c1d3-2841-75e1-93f7-fb678dd68b4a` 全程复用。唯一 SessionClosed(closed)、完整 record/footer、IPC 同序和进程组消失断言通过，diagnostics report 已生成。
- 验收回执目录：`/tmp/agentdeck-m0-real-launcher-efmchgel/`；record 与 diagnostics：`/var/folders/zy/fn4lmxbx1cd5flcp81mk2xx80000gn/T/agentdeck-codex-live-e2e-9179-1789958234236367000/`。其余 7 项 Codex E2E 中，agent list、capabilities、Ping、selfcheck、one-shot run、continue 通过，history list 首轮在 30 秒总 deadline 超时。
- history list 同条件复验返回 500 条并通过（27.57 秒）；独立官方探测确认 500 条分五页，总耗时 25.64 秒，接近 28 秒工作截止时间。8 项均有单项通过回执，但首轮套件不是全绿，历史查询时延风险未修复；真实 failed turn 仍未验收。
- Codex 交互审批、Claude Code lifecycle/partial streaming、history 管理语义和远程能力仍在 M0 外。
- GPUI desktop 尚未连接 daemon，后端验证通过也不等于桌面产品闭环完成。

## 证据与验证边界

### 默认离线验证

```bash
scripts/verify-offline-tests.sh

# tripwire 内的标准 Cargo 入口
env -u AGENTDECK_E2E cargo test --workspace --locked

# 单独复验当前 checkout 的 daemon / CLI plumbing
cargo build --locked \
  -p agentdeckd --bin agentdeckd \
  -p agentdeck-cli --bin agentdeck
AGENTDECK_DAEMON_BIN="$PWD/target/debug/agentdeckd" \
  ./target/debug/agentdeck \
  --data-dir /tmp/agentdeck-selfcheck selfcheck
```

- tripwire 在临时目录放置会写 marker 并失败的 `codex` / `claude` shim，把它们置于 PATH
  首位，并使用临时 HOME 隔离用户 vendor history 与默认 AgentDeck data dir；未设置和 `0`
  各跑完整 workspace tests，空值、`false` 和其他值跑全部 gated integration targets，每次都断言
  marker 不存在。
  Rust gate 单测另行覆盖纯值矩阵。
- CLI selfcheck 必须用绝对 `AGENTDECK_DAEMON_BIN` 绑定当前 checkout 构建物；变量一旦
  存在但为空、相对、不可执行或不存在就立即失败，不得回退到旧 sibling 或系统安装。
- Issue #3 的 focused 离线证据入口为：

  ```bash
  cargo test -p agentdeck-protocol
  cargo test -p agentdeck-cli --bin agentdeck
  cargo test -p agentdeckd --lib codex::
  cargo test -p agentdeckd --lib runtime::hub
  cargo test -p agentdeckd --lib runtime::router
  cargo test -p agentdeckd --test codex_adapter_shape
  swift test
  ```

  这些测试用于发现 protocol v4/schema 漂移、错误的 binary/argv/握手顺序、session owner
  状态机与 RPC 关联、路由/terminal 顺序、固定 option/resume 参数漂移和 Swift mirror
  漂移。Issue #3 当前确定性用例还覆盖同 connection 两轮、interrupt 后复用、running
  close、malformed/unmatched/EOF、handshake failure、unsupported server request、terminal
  status、direct child wait 后进程组消失确认与 stderr join，以及 stdin EOF/cleanup failure
  的 poison→daemon exit。
  全部使用 fake、duplex 或 stub；通过也不等于真实 vendor 已验收。
- Issue #3 已实现“probe 与 spawn 使用同一绝对 binary，并拒绝与
  `protocol/CODEX_VERSION.txt` 不匹配的版本”。生产路径是否能在当前用户登录态完成
  session，仍只能由单独授权的真实门禁回答。
- daemon/CLI selfcheck 和 diagnostics report 仍只用于 plumbing 排查。它们不证明 vendor
  可用或真实 session 已闭环；生产记录由实际 CLI integration 另行验收。

### 真实链路必须额外证明什么

```bash
cargo build --locked -p agentdeckd --bin agentdeckd
AGENTDECK_DAEMON_BIN="$PWD/target/debug/agentdeckd" AGENTDECK_E2E=1 \
  cargo test -p agentdeck-cli --test e2e_codex -- --nocapture
AGENTDECK_DAEMON_BIN="$PWD/target/debug/agentdeckd" AGENTDECK_E2E=1 \
  cargo test -p agentdeck-cli --test e2e_claude_code -- --nocapture
AGENTDECK_DAEMON_BIN="$PWD/target/debug/agentdeckd" AGENTDECK_E2E=1 \
  cargo test -p agentdeck-cli --test e2e_cross_agent_history -- \
  --nocapture --test-threads=1
```

- 这些测试会真实使用本机 vendor CLI、登录状态和用户配置，只能在明确允许创建真实
  vendor 会话的环境运行。
- 所有真实路径统一要求 `AGENTDECK_E2E=1` 严格等值；unset、空值、`0`、`false` 或其他
  值都在 vendor I/O 前提前返回。真实验证仍必须单独授权并显式使用 `1`。
- 未启用真实门禁时显示 passed 可能只是测试提前返回；该结果不能作为真实 Codex 或
  Claude Code 链路证据。
- `e2e_codex_live_four_turn_lifecycle` 经实际 CLI 验证同 PID/threadId 两轮、第三轮取消、
  第四轮成功及最终回收，并核对 run record 与 diagnostics。原 one-shot run/continue
  仍只证明单轮和新进程 resume；审批、配置恢复及其他历史管理语义是独立验收范围。
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
6. 默认收口运行 `scripts/verify-offline-tests.sh`；真实 vendor 验证必须显式授权并使用
   `AGENTDECK_E2E=1`。随后运行 `scripts/verify-agent-docs.sh` 和 `git diff --check`，只报告
   实际运行过的命令；普通 Cargo passed 不得记录成真实 E2E 证据。
