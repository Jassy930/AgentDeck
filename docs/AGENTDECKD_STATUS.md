# agentdeckd 功能完整度

本文持续追踪 `agentdeckd` 已落地能力、当前缺口和验证证据。它描述当前代码事实，
不代替产品北极星、稳定架构或具体实施计划。

- 首次盘点基线：`7bebadc`（2026-08-17）
- 当前桌面边界：GPUI 桌面尚未连接 daemon；本页的 backend 能力不能直接视为
  桌面端可用能力。
- 当前 Codex 接入：`agentdeckd` 直接启动 `codex app-server` 子进程；不使用 managed
  daemon/proxy。Issue #3 已落地 session-scoped owner，Issue #4 已把累计 assistant
  streaming 与稳定 item identity 落到 protocol v4；当前状态仍以离线 fake/fixture 证据
  为主，没有本轮真实 Codex session/prompt 回执。
- desktop 接入前的目标边界：
  `docs/plans/2026-08-17-codex-app-server-lifecycle-adr.md` 与
  `docs/plans/2026-08-17-agentdeckd-minimum-stable-boundary-design.md`。Issue #3 生命周期与
  #4 streaming/item identity 切片已落地；#5 持久 CLI E2E、#6 RunRecord/diagnostics 仍是
  M0 阻断。

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
| daemon runtime | session 生命周期与并发约束 | 部分 | protocol v4 由 caller 提供 `sessionId` / `turnId`；router 预登记 session，Codex adapter 同时只允许一个 live session，owner 同时只接受一个 in-flight turn，并拒绝复用该 session 已接受的 `turnId`。owner 在 direct child wait、Unix 进程组有界轮询至 `ESRCH` 与 stderr pump join 后报告 cleanup；RuntimeHub 在共享 session-admission 临界区内登记 terminal tombstone、清 router/handle、释放 confirmed active slot 并入队唯一 `SessionClosed`，随后才允许 replacement start，因此新 session 不会越过旧 terminal 或撞到旧 slot。`SessionClosed` 后不再发该 ID 的 lifecycle/control error，也不复用该 ID。无法确认 cleanup 时发 failed terminal、poison 并退出 daemon，不释放 slot 或接受后续 session。确定性测试覆盖 EOF、进程组探测超时/错误和 cleanup failure；尚缺持久 CLI/真实 vendor 的同 PID 多轮验收，Claude Code 仍是 one-shot 路径。 | `agentdeck-protocol/src/trunk.rs`、`agentdeckd/src/codex/session.rs`、`agentdeckd/src/runtime/hub.rs`、`agentdeckd/src/runtime/router.rs` |
| daemon runtime | turn cancel / session close | 部分 | Codex `TurnCancel` 会保留 pending cancel，取得 vendor turn id 后发送 `turn/interrupt`；健康 terminal 回 Ready，不把 cancel 当 close。若权威 terminal 先于 rejected interrupt response 到达，owner 会消费已缓存 terminal，避免误报 fatal 或产生双 terminal。`SessionClose` 才关闭 stdin、必要时终止进程组，回收 direct child 并确认进程组消失。one-shot CLI 会在 `TurnFinished` 后自动发送 close，并在匹配的 clean `SessionClosed` 与 daemon wait 后才交付 turn terminal；但 CLI 尚无持久 cancel/后续 turn 控制入口，真实 interrupt/close 未验收，Claude Code 也未迁移到这一生命周期。 | `agentdeck-cli/src/client.rs`、`agentdeckd/src/codex/session.rs`、`agentdeckd/src/codex/adapter.rs`、`agentdeckd/src/runtime/hub.rs` |
| admin | ping、协议版本/schema、agent list/capabilities | 较完整 | 已有 typed command 和 CLI 入口，回复由单 writer 输出。 | `agentdeckd/src/runtime/hub.rs`、`agentdeck-cli/src/` |
| admin | selfcheck | 部分 | `agentdeckd --selfcheck` 验证数据目录、诊断和 record 写入；CLI selfcheck 验证 daemon IPC 与静态 adapter 注册。两者都不证明 vendor CLI 登录、握手、真实 turn 或历史来源健康。 | `agentdeckd/src/main.rs`、`agentdeckd/src/runtime/hub.rs` |
| Codex | app-server 进程与 JSON-RPC | 部分 | locator 解析并固定一个绝对 binary，`--version` 与 `app-server --listen stdio://` 使用同一路径且严格要求 0.145.0。单 owner/reader/RPC allocator 串行关联 initialize、thread、turn 和 interrupt；live 与 short-lived 路径都会按官方 `ClientNotification.json` 在 initialize response 后发送 `initialized`。malformed JSON、未关联 response、EOF 和 unsupported server request 有显式失败路径；live close 在 direct child wait 后还会确认 Unix 进程组消失并 join stderr pump。fake 证据已落地，但真实 session/prompt 未运行。 | `agentdeckd/src/codex/app_server.rs`、`agentdeckd/src/codex/session.rs`、`protocol/ClientNotification.json` |
| Codex | 新 session | 部分 | `SessionStart` 先完成 initialize → initialized → thread/start|resume，再发 `SessionStarted`、`SessionCapabilities`；可携 initial turn，且启动前校验 caller ID、cwd 和固定 M0 options。启动失败不再伪造 session ready。真实 Codex 登录、握手和 prompt 本轮未验收。 | `agentdeckd/src/codex/adapter.rs`、`agentdeckd/src/codex/session.rs` |
| Codex | resume 与 live 后续 turn | 部分 | `resumeThreadId` 走新 session 的 `thread/resume`，并显式携带 caller `cwd`、`sandbox=read-only`、`approvalPolicy=never`，响应 thread id 不一致会失败；Ready 后的 `TurnStart` 在同一 owner/connection/thread 上发起顺序下一轮。确定性 fake 覆盖 resume 参数与同 connection 两轮。当前 CLI `session continue` 仍会新建 daemon/session，且没有顶层 live `TurnStart`，所以不构成持久多轮真实 E2E。 | `agentdeck-cli/src/client.rs`、`agentdeckd/src/codex/session.rs` |
| Codex | 固定 M0 options / capabilities | 部分 | 只接受 `approvalPolicy=never`、`sandbox=read-only`、`reasoningEffort=medium`、`persistApproval=false`、无 MCP；其他值在 spawn 前返回 `unsupported-session-options`。feature set 精确为 `StreamingMessages`，未宣称 approval、reasoning streaming、shell、diff、MCP 或 persistence。真实 vendor 对这组参数尚未验收。 | `agentdeckd/src/codex/adapter.rs`、`agentdeckd/src/codex/capabilities.rs` |
| Codex | 消息、reasoning、plan、shell、diff、tool 翻译 | 部分 | protocol v4 的每个 `AgentItem` 都带 `turnId`、稳定 `itemId` 与 state；常见 completed item 能映射到中立类型，未知 item 有受限 raw 降级。assistant message 支持累计 streaming；若干其他 progress、usage 和 vendor panel 信息未进入主干。 | `agentdeckd/src/codex/translate.rs` |
| Codex | 客户端可见 assistant streaming | 部分 | 每个非空 `item/agentMessage/delta` 在 daemon 内追加后，以同一 `itemId` 发完整文本快照；`item/completed` 发至多一次 completed 快照。离线测试覆盖多 delta、completed-only、重复/terminal 后帧、文本不回退和 turn 隔离；真实持久 vendor 链路仍待 #5。 | `agentdeckd/src/codex/translate.rs`、`agentdeckd/src/codex/session.rs`、`agentdeckd/tests/codex_translate.rs` |
| Codex | turn 终态 | 部分 | lifecycle owner 从 `turn/completed.params.turn` 读取 id/status，把 completed/failed/interrupted 映射为 succeeded/failed/canceled；`elapsedMs` 使用 daemon 单调时钟，`inProgress` 和未知状态按 fatal protocol failure 收口。每个已接受 turn 使用 typed `TurnFinished(outcome,nextState)`，并在其前交付该 turn 的 completed `AgentItem`；旧 `TurnComplete` 仅留给未迁移的 Claude Code。token usage 仍未进入 summary，真实 failed/cancel 状态尚未用 vendor 验收。 | `agentdeckd/src/codex/session.rs`、`protocol/ServerNotification.json` |
| Codex | command/file/permission 审批 | 未接通 | M0 固定 `approvalPolicy=never`，capabilities 不宣称 approval，`submit_decision` 明确返回不支持。owner 收到任意带 id 的 server request 会回匹配 JSON-RPC not-supported error，并 interrupt/fail 当前 turn，避免静默悬挂；交互式 typed approval 留在 M0 外。 | `agentdeckd/src/codex/adapter.rs`、`agentdeckd/src/codex/session.rs` |
| Codex | history list/read | 部分 | 使用官方 `thread/list`、`thread/read(includeTurns=true)`，短生命周期 app-server 有方法级和总 timeout，并按已提交的官方 `ClientNotification.json` 在 initialize response 后发送 `initialized`；仍缺本轮真实 history E2E。 | `agentdeckd/src/codex/history.rs`、`agentdeckd/src/codex/app_server.rs`、`protocol/ClientNotification.json` |
| Codex | history archive/unarchive/rename | 未接通 | 三项当前都返回明确的 `codex-*-not-supported` 错误。 | `agentdeckd/src/codex/history.rs` |
| Claude Code | 安装、版本、认证预检 | 部分 | 有结构化 failure code 和启动前探测；selfcheck 本身不执行完整真实 turn。 | `agentdeckd/src/claude_code/auth.rs`、`agentdeckd/src/claude_code/capabilities.rs` |
| Claude Code | 新 session | 部分 | 能以 `--print`、stream-json 启动并翻译结果；真实 vendor 行为仍受本机版本、登录及门控 E2E 约束。 | `agentdeckd/src/claude_code/adapter.rs` |
| Claude Code | continue | 部分 | 能按 session id resume；当前强制使用 `bypassPermissions`，没有恢复原 session 的 permission mode 及其余启动配置。 | `agentdeckd/src/claude_code/adapter.rs` |
| Claude Code | 消息、tool、hook、system status 翻译 | 部分 | completed result 和主要事件以 protocol v4 identity/state 中立化；partial `stream_event` 被丢弃，工具进度与部分终态信息不保真。 | `agentdeckd/src/claude_code/translate.rs` |
| Claude Code | 客户端可见实时 delta | 未接通 | `stream_event` partial message/reasoning delta 明确不发给客户端，只消费最终 snapshot，因此 capability 不包含 `StreamingMessages` 或 `StreamingReasoning`。 | `agentdeckd/src/claude_code/translate.rs`、`agentdeckd/src/claude_code/capabilities.rs` |
| Claude Code | 审批 | 骨架 | 有 request route 与 decision 写回代码，但 `permission_response` wire shape 在源码中仍标为 speculative，缺真实 fixture 与 E2E 证明。 | `agentdeckd/src/claude_code/adapter.rs` |
| Claude Code | history list/read | 部分 | 能扫描 CC 原生 JSONL 并构造列表和读取结果；这是本地格式解析，需随受支持 CC 版本持续验证保真性。 | `agentdeckd/src/claude_code/history.rs` |
| Claude Code | history rename | 部分 | 通过 CC 原生 resume/name 命令更新标题；单测只覆盖 custom-title 解析，真实 rename 仅存在门控 E2E，本次盘点未记录该 E2E 的实跑回执。 | `agentdeckd/src/claude_code/history.rs`、`agentdeck-cli/tests/e2e_claude_code.rs` |
| Claude Code | history archive/unarchive | 未接通 | archive 对普通 print session 没有稳定原生语义，可能返回不支持；unarchive 当前只是无效果 Ack。 | `agentdeckd/src/claude_code/history.rs`、`agentdeckd/src/claude_code/adapter.rs` |
| shared history | 跨 agent list | 较完整 | 两个来源并发查询、独立 deadline、best-effort 合并、按最近活动排序并应用总 limit；全部失败与合法空结果可区分。 | `agentdeckd/src/runtime/router.rs` |
| vendor control | session 内控制更新 | 骨架 | typed payload 与路由存在；Codex 返回 requires-new-turn，CC 多数控制返回 requires-new-turn 或 not-supported。 | 两个 adapter 的 `submit_vendor_control` |
| observability | run record | 骨架 | JSONL、脱敏、header/event/footer helper 与测试存在；生产 RuntimeHub 和 adapter 事件流尚未调用 `RunRecord`。 | `agentdeckd/src/record.rs` |
| observability | diagnostic log/report | 骨架 | 有结构化日志、数据目录和聚合报告；生产写入主要覆盖 daemon 启停/selfcheck，尚未贯穿 session、adapter、approval、history，`diagnosticRef` 多为空。 | `agentdeckd/src/diag.rs`、`agentdeckd/src/main.rs` |
| quality | 默认测试离线安全 | 较完整 | 真实 session、prompt、history、auth 和 vendor process 测试统一只认 `AGENTDECK_E2E=1`；普通 version/auth probe 使用可注入 fake。marker tripwire 通过临时 HOME 隔离用户 vendor history 与默认 AgentDeck data dir，并验证标准 workspace tests 不执行 PATH 中的 vendor shim；macOS workflow 已配置该门禁，首个 hosted run 已在 2026-08-18 通过。普通 passed 仍不代表真实 E2E 已执行。 | `agentdeckd/tests/support/mod.rs`、`scripts/verify-offline-tests.sh`、`.github/workflows/offline-ci.yml` |
| CLI | admin、session、history | 部分 | ping/selfcheck、协议、agent、run/continue 和 history 已暴露；run/continue 已生成 protocol v4 `SessionStart` 和 caller-owned ID，并能解码带 identity/state 的 `AgentItem`。Codex one-shot turn 完成后会自动执行 `SessionClose` / 等待 `SessionClosed` / 回收 daemon；只有 daemon clean exit 才交付成功 terminal，非零退出或有界 shutdown 失败改为 `daemon-shutdown-failed`。每个 CLI 调用仍新建 daemon，顶层没有可交互的 live `TurnStart`、`TurnCancel`、手动 `SessionClose`、审批或 vendor-control，不能作为同 session 多轮生命周期驱动。 | `agentdeck-cli/src/main.rs`、`agentdeck-cli/src/client.rs`、`agentdeck-cli/src/commands.rs`、`agentdeck-cli/src/transport.rs` |
| product integration | GPUI desktop → daemon | 未接通 | 当前桌面 bundle 不携带、不启动、不连接 `agentdeckd`，也没有会话、审批或历史 UI。 | `README.md`、`docs/QUALITY.md`、`agentdeck-desktop/` |

## 关键缺口

以下缺口会阻断“desktop 接入前，先稳定一条 daemon 最小完整功能”：

1. **#5：缺少持久 client 与真实生命周期证据。** Issue #3 owner 已能在一个 connection
   上执行顺序多轮、interrupt 和 close，但当前 CLI 每次命令都会新建 daemon/session。
   one-shot CLI 的自动 `SessionClose` / `SessionClosed` / daemon wait 已有确定性单测；
   Issue #4 也已闭合本地 protocol v4、累计 assistant streaming 和离线 fixture 证据。
   但本轮没有运行真实 Codex session/prompt，因此尚未证明真实同 PID/threadId 两轮、
   completed 前快照、cancel 后续轮和持久连接最终回收。
2. **#6：可观测链没有接入生产运行路径。** `RunRecord` helper 与 diagnostic report
   存在，Issue #3 的部分错误也能携带 session-scoped `diagnosticRef`；但生命周期事件
   尚未写入同一个 run record，引用也不能回读到实际 diagnostic 行。M0 的记录与关联
   diagnostics 仍未验收。
3. **M0 外能力仍未稳定。** Codex 交互式 approval 被明确关闭，Claude Code decision
   wire 仍缺真实验证；CLI 也没有审批回写或 vendor-control 的可操作闭环。capabilities
   已收紧，后续不得仅因旧 translator/helper 仍存在而重新放宽。
4. **产品接入仍为空。** GPUI desktop 尚未携带或连接 daemon；只有 #5/#6 和完整 M0
   门禁通过后才允许开始 typed local client 接入。

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
- Issue #3/#4 的 focused 离线证据入口为：

  ```bash
  cargo test -p agentdeck-protocol
  cargo test -p agentdeck-cli --bin agentdeck
  cargo test -p agentdeckd --lib codex::
  cargo test -p agentdeckd --test codex_translate
  cargo test -p agentdeckd --lib runtime::hub
  cargo test -p agentdeckd --lib runtime::router
  cargo test -p agentdeckd --test codex_adapter_shape
  cargo test -p agentdeckd --test cc_fixture_replay
  swift test
  ```

  这些测试用于发现 protocol v4/schema/Swift mirror 漂移、累计文本或 item identity
  回退、错误的 binary/argv/握手顺序、session owner 状态机与 RPC 关联、路由/terminal
  顺序和固定 option/resume 参数漂移。Issue #3 当前确定性用例还覆盖同 connection 两轮、
  interrupt 后复用、running close、malformed/unmatched/EOF、handshake failure、unsupported
  server request、terminal status、direct child wait 后进程组消失确认与 stderr join，以及
  stdin EOF/cleanup failure 的 poison→daemon exit；Issue #4 覆盖多 delta 累计、
  completed-only/duplicate completed、terminal 后 delta、跨 turn 隔离、单调 elapsed 和
  `AgentItem` 先于 `TurnFinished`。
  全部使用 fake、duplex 或 stub；通过也不等于真实 vendor 已验收。
- Issue #3 已实现“probe 与 spawn 使用同一绝对 binary，并拒绝与
  `protocol/CODEX_VERSION.txt` 不匹配的版本”。生产路径是否能在当前用户登录态完成
  session，仍只能由单独授权的真实门禁回答。
- daemon/CLI selfcheck 和 diagnostics report 仍只用于 plumbing 排查。它们不证明 vendor
  可用、M0 record 已接线或真实 session 已闭环。

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
- E2E 当前主要验证 one-shot run/continue 与响应契约形态；`continue` 会新建 CLI、daemon
  和 vendor session-scoped child，只按已知 `threadId` resume。Codex one-shot 会在内部
  自动 close/wait，但它不证明同一 live session 的后续 `TurnStart`、流式 delta、取消后
  继续、最终持久连接回收、审批、配置恢复或所有历史管理语义；这些属于 #5 的持久
  driver 验收。
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
