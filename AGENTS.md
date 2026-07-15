# AgentDeck 代理工作入口

本文件只作为仓库地图和执行规则，不承载详细百科。更深的产品、架构、诊断和计划信息必须写入下游文档，并随代码同步更新。

## 必读顺序

1. `NORTH_STAR.md`：产品北极星和 v0.2 必赢目标。
2. `README.md`：当前用户可见能力、架构摘要、构建与测试命令。
3. `ARCHITECTURE.md`：稳定架构、分层边界、依赖方向和不变量（v0.2 含 N1–N8 新不变量）。
4. `docs/index.md`：文档记录系统导航。
5. `docs/AGENT_DIAGNOSTICS.md`：自检、诊断日志和 failure code（含 CC adapter failure codes）。
6. `docs/QUALITY.md`：验证命令、质量门禁和文档结构检查（含 v0.2 手动 QA 清单）。
7. `docs/plans/README.md` 与 `docs/plans/`：设计文档和实施计划规则。当前实现基线仍以 `docs/plans/2026-06-30-unified-shell-v02-design.md` / implementation 为准；Relay 以已批准的 `docs/plans/2026-07-10-relay-companion-mvp-design.md` 和 `docs/plans/2026-07-10-relay-companion-mvp-implementation.md` 为目标事实源与执行清单。P2.10、P3.5、P3.6-A/B/C/D 已完成；P3.7 已裁决采用 cooperative-descendant PGID 边界，主体实现、prepare 唯一 reaper、typed clean/unknown disposition、fresh 完整门禁与独立终审均已完成，现只待 scoped commit。fixture / typed adapter prepare / typed execution journal 的前置提交为 `819aa5e` / `1acf8b8` / `3f22cf0`。真实 provisioned signed Keychain roundtrip 仍有 1 项 ignored 且 gated BLOCKED，P3.8/P3.9 singleton UDS、P3.10 LaunchAgent、P4 remote owner/E2EE、P5/P6 客户端与实机证据仍未完成，因此不得宣称 P3.1/P3、远程 Companion 或整个方案完成。
8. `protocol/SPIKE_FINDINGS.md` 与 `protocol/`：Codex app-server 协议事实源。

## 项目边界

- AgentDeck 是 Coding Agent 的统一原生桌面客户端，把 Codex 和 Claude Code 作为绝对一等公民，不是 IDE、不是 Codex Desktop 替代品、不是通用多 agent 聊天界面。
- v0.2 核心：IPC v2 双层协议 + ClaudeCodeAdapter MVP + CapabilityRouter + 跨 agent 历史聚合。
- UI 必须通过 `CapabilityRouter` 按 `SessionCapabilities` 路由渲染路径，禁止 `if agentKind == .codex` 硬编码分支（N2）。
- IPC 主干类型严禁出现 vendor 字样；vendor 字段只能出现在 `capabilities.*` / `vendorControl.*` / `vendorPanel.*` 命名空间（N1）。
- Codex 细节只能留在 `agentdeckd/src/codex/` 子模块；CC 细节只能留在 `agentdeckd/src/claude_code/` 子模块；两者互不知晓（N3）。
- `protocol/` 中 Codex schema 必须来自官方 `codex app-server generate-json-schema`，不要手写或逆向猜测协议（K8）。
- AgentDeck 不读取、不保存、不转发任何 vendor token（Codex 或 Claude Code）；CC 原生 history/session 文件仍是唯一权威事实源。仅允许 Runtime DB 的 `claude_code_adapter_state` 保存 StorageKEK 保护、可从本机唯一 regular/non-memory native JSONL 明确重建的 `adapterStateKey → session id` 派生索引；不按 title/cwd/mtime 猜旧 key，不保存 title/archive/status/transcript，不建 `cc-meta/`，不进入 common catalog、日志、Relay 或客户端 wire（K9、N8）。
- AgentDeck stable run record 与 diagnostic log 固定写入当前 EUID 的 OS account home 下 `Library/Application Support/AgentDeck/`；ephemeral 实例写入随机 0700 temp namespace，均不得写入用户项目 git（K5）。
- `Sources/AgentDeckCore/` 是 macOS/iOS 共享的平台无关层，禁止 import AppKit/UIKit；`ios/` 是 fixture 驱动的 UIKit companion 前端，唯一数据入口是 `MobileSessionSource`，本期不含网络代码（设计见 `docs/plans/2026-07-03-ios-uikit-frontend-design.md`）。

## 工作规则

- 永远使用中文回答用户；项目文档默认使用中文。
- Python 使用 `uv`；JS/TS 使用 `bun`。
- 代码变更必须同步更新相关文档。若行为、架构、协议、诊断或用户可见流程变化，更新 `README.md`、`docs/` 或对应计划文档。
- 每个阶段性工作结束后，整理工作区并查看 `git status --short --branch`。
- 不添加 co-author / Codex 合作者信息。
- 不把本地构建产物、运行记录、诊断日志、token、`.env` 或用户项目数据提交进仓库。

## 验证入口

按变更范围选择最小但足够的验证：

```bash
cargo test
swift test
swift run AgentDeck -- --selfcheck
swift run AgentDeck -- --diagnostics-report --json
scripts/verify-agent-docs.sh
```

涉及 daemon、IPC、记录、诊断、协议翻译时至少运行 `cargo test` 和自检。涉及 Swift UI、会话模型、历史回放、富文本渲染时至少运行 `swift test`。涉及诊断、日志或数据目录时同时运行 diagnostics report。

### iOS 前端验证

```bash
# iOS 工程生成 + 构建 + 单测（fixture 驱动，无真实链路）
cd ios && xcodegen generate && \
  xcodebuild -project AgentDeckMobile.xcodeproj -scheme AgentDeckMobile \
    -destination 'platform=iOS Simulator,name=iPhone 17' test
```

涉及 `Sources/AgentDeckCore/` 或 `ios/` 时至少运行 `swift test` 与上述 iOS 测试。

### 统一接口层补充验证

```bash
# 打印 IPC 协议 JSON Schema（可与快照核对）
cargo run -p agentdeck-cli -- protocol schema

# 核对快照与代码是否同步（漂移测试也随 cargo test 自动运行）
cargo run -q -p agentdeck-cli -- protocol schema \
  | diff - protocol/agentdeck/agentdeck-protocol.schema.json \
  && echo "schema in sync"

# 通过 CLI 执行 IPC + logging 自检
cargo run -p agentdeck-cli -- selfcheck

# 门控 E2E（本地执行，需要 codex login；默认 cargo test 跳过）
AGENTDECK_E2E=1 cargo test -p agentdeck-cli --test e2e_codex -- --nocapture
AGENTDECK_E2E=1 cargo test -p agentdeck-cli --test e2e_claude_code -- --nocapture
AGENTDECK_E2E=1 cargo test -p agentdeck-cli --test e2e_cross_agent_history -- --nocapture --test-threads=1
```

协议 schema 漂移测试随标准 `cargo test` 运行；改动 `agentdeck-protocol` 中的类型后须用以下命令重新生成快照：

```bash
UPDATE_SCHEMA=1 cargo test -p agentdeck-protocol schema_matches_committed_snapshot
```

### Relay Companion MVP P2.10

Relay R0/R1 计划与测试只保留为历史记录；v1 协议、server、client、daemon bridge
和兼容 feature 已物理删除，不得再使用 `--bootstrap-secret`、`ws://` v1 命令或
R1b 测试作为当前验证。production binary 只运行 Relay v2 Direct TLS/WSS；loopback
明文或 proxy 只能显式用于受控开发。`/v1/connect` 只是无状态 HTTP 426 tombstone。

```bash
# 当前统一 P2 门禁
bash scripts/verify-relay-companion-mvp.sh p2

# Relay v2 安全与故障专项
cargo test -p agentdeck-relay --features server,tls \
  --test relay_v2_hardening_e2e -- --test-threads=1
cargo test -p agentdeck-relay --features server,tls \
  --test relay_v2_security_e2e -- --test-threads=1
cargo test -p agentdeck-relay-client

# Relay v2 production config selfcheck：真实 TLS preflight + Store/Core 打开/关闭
relay_selfcheck_dir="$(mktemp -d)"
cargo run -p agentdeck-relay --features server,tls -- \
  --selfcheck \
  --config agentdeck-relay/tests/fixtures/relay-selfcheck.toml \
  --storage "$relay_selfcheck_dir/relay.db"
rm -rf "$relay_selfcheck_dir"

# daemon 仍无网络依赖
bash scripts/check-daemon-no-net.sh
```

真实外部 Direct TLS/SPKI synthetic 由本机 admin UDS 先生成一次性 bundle，再执行：

```bash
agentdeck remote synthetic --bundle /secure/path/machine-enrollment-bundle.json
```

该命令只使用临时 machine/device identity，不建立持久状态。P4 前其余
`remote pair/machines/sessions/watch/send/...` 必须返回
`remote.persistent.unsupported`。旧 v1 credential marker 只允许做 metadata
存在性探测；production CLI 不读取、不删除、不拨号。需要清理时只能显式运行
`scripts/reset-relay-v1-dev-state.sh`，成功后重新配对，不提供恢复。

改动任一协议轴后，使用对应的 `UPDATE_*_SCHEMA=1` 测试更新快照，并确认以下
四条导出都与仓库快照逐字节一致：本地 IPC、Runtime、Relay v2、E2EE。

### Relay Companion MVP P3.1（尚有 gated 签名门禁）

```bash
cargo test -p agentdeckd --test daemon_namespace --test storage_kek \
  --test daemon_startup -- --test-threads=1
cargo test -p agentdeckd
cargo test -p agentdeck-cli
swift test
cargo run -q -p agentdeck-cli -- selfcheck
bash scripts/check-daemon-no-net.sh
```

unsigned 开发实例必须显式使用 `--ephemeral --no-remote --profile dev`；stable daemon
不接受 `HOME`、`AGENTDECK_DATA_DIR`、`AGENTDECK_PROFILE` 或运行时 access-group override。
真实 Keychain `set → load → delete` ignored test 只有在编译值、codesign entitlement 与
provisioning profile 一致的 helper 上实际运行后才算通过；当前本机无匹配 provisioning
profile，已签名尝试均被 AMFI 以 exit 137 终止。ignored 不能计作 PASS，也不能据此完成 P3.1。

### Relay Companion MVP P3.2（Runtime store 组件门禁）

```bash
cargo test -p agentdeckd \
  --test runtime_store --test runtime_store_admission \
  --test runtime_store_capacity --test runtime_store_cipher \
  --test runtime_store_identity --test runtime_store_sequence \
  --test runtime_store_queue --test runtime_store_journal \
  --test runtime_store_hardening --test runtime_store_boundaries \
  --test runtime_store_commit_outcome --test runtime_store_recovery \
  --test runtime_store_shutdown \
  -- --test-threads=1
cargo test -p agentdeckd
bash scripts/check-daemon-no-net.sh
```

P3.2 必须保持 caller-owned stable conversation/adapter IDs、全部事务精确重试、24h TTL、
fence/release、32/1,024/256MiB、2GiB admission、safety tail/bounded checkpoint、真实 COMMIT
unknown、认证 metadata/ledger、三业务 lane count/byte bound、paged recovery（单页一个
conversation、80MiB、exact cursor/finish、恢复期 mutation fence）和 shutdown
优先级。P3.4 RuntimeCore 已接入该组件，但 compatibility RuntimeHub/App/CLI 尚未迁到 singleton
UDS；不得把 store/Core 测试表述为 UDS、
远程或 Companion E2E。标准 SQLite 无 custom quota VFS，不能声称 active WAL 瞬时零超冲。

### Relay Companion MVP P3.3（typed catalog + adapter 私域门禁）

```bash
cargo test -p agentdeckd --lib -- --test-threads=1
cargo test -p agentdeckd --test adapter_state_boundary --test agent_router \
  --test cc_adapter_shape --test codex_adapter_shape -- --test-threads=1
cargo test -p agentdeckd --lib runtime::store::sqlite::migration_tests -- --test-threads=1
cargo test -p agentdeckd
AGENTDECK_E2E=1 cargo test -p agentdeckd --test codex_adapter_shape \
  real_codex_canonical_start_binds_private_state_then_emits_capabilities -- --exact
AGENTDECK_E2E=1 cargo test -p agentdeckd --test cc_adapter_shape \
  real_claude_streams_at_least_one_assistant_or_turn_complete -- --exact
bash scripts/check-daemon-no-net.sh
```

P3.3 必须证明 common catalog 只接受 canonical typed `ConversationDescriptor`，未知 vendor
identity 字段在 migration 前零写拒绝；v1→v2 before-COMMIT rollback 对 main/WAL/SHM/journal
逐字节无副作用，COMMIT 后才启用 persistent WAL。canonical Agent handle/event/history 禁止
`ThreadId`，Raw vendor frame fail-close；Codex bind 位于首个 turn 前，CC 必须区分首次
`--session-id` 与已 materialized native history 的 `--resume`，并在 authoritative init 匹配前
不返回/不发布。Codex resume response 必须返回 exact thread id；CC private history 只有经
`O_NOFOLLOW` 有界读回有效 JSONL 才算 materialized，fresh home 重试继续复用原 session id。
state repository 不公开，adapter 不拿通用 store/另一 namespace vault，不创建 `cc-meta/`。
所有真实 CLI/model/history smoke 必须先检查 `AGENTDECK_E2E=1`。这些与 P3.4 RuntimeCore 仍是
分层组件门禁，不能表述为 UDS、远程或 Companion E2E。

### Relay Companion MVP P3.4（RuntimeCore / actor 门禁）

```bash
cargo test -p agentdeckd --lib runtime:: -- --test-threads=1
cargo test -p agentdeckd --test runtime_core --test runtime_store_p34 -- --test-threads=1
cargo test -p agentdeck-protocol -- --test-threads=1
swift test --filter RuntimeV1ProtocolTests
cargo test -p agentdeckd
bash scripts/check-daemon-no-net.sh
```

P3.4 的 Start 必须与首 prompt 分离，并由 StorageKEK 域分离 capability 生成跨重启稳定 ID；
出站 writer 只接受保留 version/messageId 的完整 RuntimeEnvelope。per-conversation actor 以 durable
commandSeq FIFO 裁决，多 reader/multi-writer 不按 transport 赋予本地优先级。prompt COMMIT
unknown 的重试必须把仍为 Accepted 的 command 幂等补回 actor；shutdown/recovery-blocked 不得
abort 已 dispatch 的 admission 而丢 outcome。取消或 completion channel 失败只有在
`cancel_and_wait_fenced` 证明精确 process group 已退出后才能写 terminal；否则 conversation
保持 RecoveryBlocked；release permit 必须绑定 committed command/boot/nonce，completion 成功也
必须证明精确 process group 已 reap/fence。durable conversation/actor 最多 1,024，connection
writer 最多 128，principal lease（含 revoked tombstone）最多 1,024；frame/byte/read/control
队列同样必须有硬上界。Core 先 Closing 并等待 operation/start lease 静默，再公开 Draining；
shutdown/Drop 后不得残留自持有 writer 或 detached actor 子任务。P3.4 的阶段测试继续使用
disabled/side-effect-free coordinator，只证明 Core contract；当前 production exec 必须另跑 P3.7
current-binary gate 门禁，fake 仍不是真实 vendor exec 证据。

### Relay Companion MVP P3.6（canonical stream / snapshot / transfer 门禁）

```bash
# P3.6-C 固定 integration contract
cargo test -p agentdeckd --test runtime_stream -- --test-threads=1
cargo test -p agentdeckd --test runtime_transfer -- --test-threads=1

# Store v4、snapshot/read-pool 与全部 daemon-private Runtime 行为
cargo test -p agentdeckd --test runtime_store_stream_v4 \
  --test runtime_store_read_pool --test runtime_snapshot -- --test-threads=1
cargo test -p agentdeckd --lib runtime:: -- --test-threads=1

# Rust/Swift contract、完整 daemon 回归与静态边界
cargo test -p agentdeck-protocol -- --test-threads=1
swift test
cargo run -q -p agentdeck-cli -- protocol schema \
  | diff - protocol/agentdeck/agentdeck-protocol.schema.json
cargo test -p agentdeckd
cargo fmt --all -- --check
cargo clippy -p agentdeckd --all-targets -- -D warnings
bash scripts/check-daemon-no-net.sh
git diff --check
scripts/verify-agent-docs.sh
```

该门禁只证明 StoreCommitHub、Catalog/Conversation 共用 barrier、连续 backfill/snapshot-required、
authenticated snapshot、paced JSON TransferPart、bounded reducer 与 fake sealed publication
freeze/COMMIT/ACK/restart。P3.6-C 已由 `694f2d9` 收口；最终回归包含 daemon lib 464/464、
`runtime::` 366 项、默认并发 `cargo test -p agentdeckd` exit 0，以及 Swift 256 XCTest +
35 Swift Testing。真实签名 Keychain roundtrip 的 1 项 ignored 仍是外部 BLOCKED，不得计入 PASS。

subscription `commit` 只登记可取消后台 job，不等待 socket egress gate。terminal Failure 会持有
per-connection gate 到 flush ACK/cancel；同 target 被新 generation 取代时旧 job 不发迟到 receipt，
未来客户端发起 replacement 时必须同步取消旧 request waiter。pending capture 在 Store capture/spawn
前受 4/connection、128/global 硬上界。测试 harness 为防 macOS 默认并行测试用多个真实 Store
（每个 1 writer + 8 WAL readers）耗尽 soft FD，仅在 unit/integration test 进程把并发 Store fixture
限制为 4；production Store、8-reader ReadPool 和所有运行时配额不变。

P3.6 不执行真实 E2EE seal、MachineDataSign、Keychain CounterGuard 或 Relay Publish，
transfer/publication 也尚无 production remote owner；Simulator fixture 不是远程链路。P3.7 exec gate
已完成 fresh 完整门禁和独立终审，仍待 scoped commit；P3.8/P3.9 UDS、P3.10 LaunchAgent 与 P4 remote
仍是后续任务。

### Relay Companion MVP P3.7（exec-gate + typed production execution）

```bash
cargo test -p agentdeckd --lib runtime::store::execution_event::tests -- --test-threads=1
cargo test -p agentdeckd --test runtime_store_execution_event -- --test-threads=1
cargo test -p agentdeckd --test runtime_store_execution_event_commit -- --test-threads=1
cargo test -p agentdeckd --test runtime_store_execution_event_tamper -- --test-threads=1
cargo test -p agentdeckd --test runtime_store_legacy_terminal -- --test-threads=1
cargo test -p agentdeckd --lib runtime::conversation::runtime_execution_fixture_tests -- --test-threads=1
cargo test -p agentdeckd --test exec_gate -- --test-threads=1
cargo test -p agentdeckd --test runtime_crash_recovery -- --test-threads=1
cargo test -p agentdeckd --test runtime_store_recovery -- --test-threads=1
cargo test -p agentdeckd --test runtime_approval -- --test-threads=1
cargo test -p agentdeckd --test typed_spawn_ownership -- --test-threads=1
cargo test -p agentdeckd --test production_execution_wiring -- --test-threads=1
cargo test -p agentdeckd --lib -- --test-threads=1
cargo test -p agentdeckd --tests -- --test-threads=1
cargo fmt --all -- --check
cargo clippy -p agentdeckd --all-targets -- -D warnings
bash scripts/check-daemon-no-net.sh
git diff --check
scripts/verify-agent-docs.sh
```

fresh Item/Error/approval 必须匹配 authenticated Started/turn 与 released Fence；release 失败必须
丢弃 prepared event receiver，不能注册预排 approval。`ExecSpec` 必须绑定 exact execution/state，
daemon handle 在 consumption 时重新校验虚 getter。adapter 只能从 exec-gate 固定目录集合解析
vendor basename，不得使用继承 PATH。adapter fixture 只允许筛选脱敏帧，来源/hash/历史 security debt
见 `agentdeckd/tests/fixtures/README.md`。`production_execution_wiring` 的 `/bin/sh` helper 只证明真实
current-binary gate 与 durable ACK/terminal 接线，不是已登录 Codex/Claude Code、真机或远程链路证据。

P3.7 的 PGID 保证只覆盖不主动 `setsid`/`setpgid`、不另起 `launchd`/launch service 脱离继承
PGID 的 cooperative vendor/tool descendants。显式自守护/逃逸是流程外不支持行为，当前机制不声称
检测、枚举、收割或把它分类为 RecoveryBlocked；仍必须保证 release 前零 vendor/tool 副作用，并在
cancel、崩溃、owner drop 或 vendor 先退出时 TERM→KILL/reap 全部同组子孙。blocked gate 从 prepare 起
必须有唯一 reaper；确认没有创建 child 的普通 prepare failure 直接 Interrupted，只有 gate identity/
同组清理不确定时才 RecoveryBlocked。canonical CC Approval 已由 recorded
`control_request(can_use_tool)` 接通并广告，legacy compatibility 与未建模 Hooks 继续隐藏；fixture 不是
live vendor evidence。Codex/CC approval summary 只能持久化经 source pre-cap、secret redaction、控制字符
边界显式处理与 UTF-8 限长后的最小动作字段，不能退化为盲签或保存完整 raw frame：Codex 用可见 JSON
编码保留换行/控制符且超界 fail-close，CC 才折叠控制字符并截断。Codex completed kind/status
必须严格校验，`declined` 为 Canceled；CC wire 没有权威退出码时 canonical/legacy/history 都写
`exit_code=None`，不能由 `is_error` 伪造 0/1。Codex command 缺具体 command/完整 commandActions/已验证
network target，file request 未绑定同一 in-flight fileChange 的非空 proposed changes，CC 缺具体动作或
tool 未建模，以及 permission profile 为空/过大时必须 fail-close；可选 grantRoot/reason 不能单独构成
file action。Codex permission summary 必须展示 response builder 同一 validator 接受的完整 profile，
但字段值使用脱敏投影，response builder 仍回送已验证的原始字段值；approval route/output Debug 不得
展开 raw params。

## 浏览与外部资料

需要网页资料时优先使用当前环境可用的官方浏览工具和一手来源。不要引入项目级外部浏览 skill 依赖，也不要要求安装额外工具才能在本仓库工作。
