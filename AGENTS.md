# AgentDeck 代理工作入口

本文件只作为仓库地图和执行规则，不承载详细百科。更深的产品、架构、诊断和计划信息必须写入下游文档，并随代码同步更新。

## 必读顺序

1. `NORTH_STAR.md`：产品北极星和 v0.2 必赢目标。
2. `README.md`：当前用户可见能力、架构摘要、构建与测试命令。
3. `ARCHITECTURE.md`：稳定架构、分层边界、依赖方向和不变量（v0.2 含 N1–N8 新不变量）。
4. `docs/index.md`：文档记录系统导航。
5. `docs/AGENT_DIAGNOSTICS.md`：自检、诊断日志和 failure code（含 CC adapter failure codes）。
6. `docs/QUALITY.md`：验证命令、质量门禁和文档结构检查（含 v0.2 手动 QA 清单）。
7. `docs/plans/README.md` 与 `docs/plans/`：设计文档和实施计划规则。当前实现基线仍以 `docs/plans/2026-06-30-unified-shell-v02-design.md` / implementation 为准；Relay 以 `docs/plans/2026-07-10-relay-companion-mvp-design.md`、`docs/plans/2026-07-10-relay-companion-mvp-implementation.md` 和上位增量 `docs/plans/2026-07-18-relay-companion-mvp-course-correction.md` 为事实源。Relay 主线恢复 Task 粒度门禁；P3.9-C0-B3a/B3b/B4/B5/C0-C、P3.9-A/B/C3/D/E 已完成 Task 门禁和独立 `spec/security`、`quality` 终审。D code/test `b818f81` 完成普通 GUI、Rust CLI 与 Swift `main.swift --selfcheck` 的 OS-account shared-daemon UDS cutover；E code/test `d68cc02` 收口 exact/fresh retry、composer owner/LRU、history latest-intent、close barrier、有界 reconnect 与 64-slot subscription admission。P3.10 已由 `19622ab` 完成当时的 schema v7/admin ledger、flush-ACK-gated `StageUpgrade` 与 LaunchAgent lifecycle；Phase review 又由 `773a2b3`、`0057824`、`81cc314`、`9efb28d` 补齐安装 verifier 资源/进程组收口及 legacy v1–v6 pre-RW 全量认证（新增显式 v1–v4 committed-WAL 矩阵）。基于 code baseline `9efb28d` 的独立 `p3` Phase verifier 已 exit 0，四 schema/network/docs/smoke/diagnostics 全绿，双路 code review P0/P1/P2 = 0，故 P3 Phase complete（MVP automatic scope）。P3.1 继续采用方案 b：provisioned signed Keychain 保留 post-MVP ignored/BLOCKED，不阻塞主线，也不表示 stable production signing PASS。同 UID 在线攻击作为 residual risk 不再扩展。P4.1 已完成 machine identity/guard；P4.2 code/test 由 `a6842bc` 完成 Runtime v3、schema v9/25 表、certificate/enrollment/receipt、control-only RemoteTransport、两条 trust reset 与安全 uninstall purge。P4.3 由 `518380e`、`b28f995`、`55be98f`、`ba3629f`、`4ec3d2f`、`fe3a9ad`、`3b4b977` 完成 Runtime v4、schema v10/30 表、PairInvite/DeviceGrant/DeviceAuthorization/KeyDirectory、本机 auth ledger、revoke、control handoff 与 cancel-safe recovery。P4.4 code/test `cd7d9fb` 已完成唯一 MachineLink business lane、Relay v2 outer 与 DeviceSign/AAD/replay/AEAD ingress 验证、local auth-ledger exact recheck、RemotePrincipal 与 RuntimeCore dispatch。P4.5 code/test `c6ef387`、`88b3c42` 已完成当时 Runtime wire v4、physical schema v14/35 表，以及 CounterGuard reserve→seal once→DB 冻结 exact blob→Relay Publish COMMIT→local ACK 的 signed publication/counter recovery；offline park 后只在 authenticated reconnect 复用同一 frozen blob，counter/publication/transition recovery 全部通过前 admission 保持关闭。P4.6 persistent remote CLI 已完成 automatic Task，current Runtime wire 为 v5；`pair`、`machines`、`conversations`、`watch`、`prompt`、`approve`、`retry-approval`、`revoke-self` 均已接入，是 P4 当时的第 6/7 项。P4.7 automatic Task 与 P4 automatic Phase Exit 已完成，P4 automatic scope 为 7/7；真实 iOS Companion 仍未完成。P5 MVP 仅 iOS Simulator 自动 E2E，本机第二客户端归 P6 synthetic DoD；production signing、物理设备、公网与干净 Linux 证据为 post-MVP BLOCKED 槽位，不得冒充 PASS。
   `p4-auto` focused aggregate 已 PASS，但 `p4` 仍不受支持，且该 aggregate 本身不包含顶层 Rust/Swift、
   最终 diff/status、冻结 hash 或双路 phase review；这些独立门禁与 `spec/security`、`quality` 双路终审已在
   pre-closeout candidate SHA-256 `18654fa9c398383dafcefa1542c8e48f8c460f1f521806880c5dab083bdb29f5`
   上补齐并通过，两路 review 均 Approved，P0/P1/P2=0。
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
- `Sources/AgentDeckCore/` 是 macOS/iOS 共享的平台无关层，禁止 import AppKit/UIKit；`ios/` 是 fixture 驱动的 UIKit companion 前端，唯一数据入口是共享 `SessionSource`；当前发行 composition 仍注入 `FixtureSessionSource`，真实 Relay composition 属后续 P5.6（设计见 `docs/plans/2026-07-03-ios-uikit-frontend-design.md`）。

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
bash scripts/verify-relay-companion-mvp.sh p3
```

独立改动以及 Relay Companion 的 Task 收口/Phase exit：涉及 daemon、IPC、记录、诊断、协议翻译时至少运行 `cargo test` 和自检；涉及 Swift UI、会话模型、历史回放、富文本渲染时至少运行 `swift test`；涉及诊断、日志或数据目录时同时运行 diagnostics report。Relay Companion 内部子片例外：只跑计划指定的 focused tests + scoped clippy + fmt，完整门禁留到 Task 收口与 Phase exit。

### iOS 前端验证

```bash
# iOS 工程生成 + 构建 + 单测（fixture 驱动，无真实链路）
cd ios && xcodegen generate && \
  xcodebuild -project AgentDeckMobile.xcodeproj -scheme AgentDeckMobile \
    -destination 'platform=iOS Simulator,name=iPhone 17' test
```

独立改动以及 Relay Companion 的 Task 收口/Phase exit涉及 `Sources/AgentDeckCore/` 或 `ios/` 时，至少运行 `swift test` 与上述 iOS 测试；Relay 内部子片仍遵守 focused-only 例外。

### 统一接口层补充验证

```bash
# 打印 IPC 协议 JSON Schema（可与快照核对）
cargo run -p agentdeck-cli -- protocol schema

# 核对快照与代码是否同步（漂移测试也随 cargo test 自动运行）
cargo run -q -p agentdeck-cli -- protocol schema \
  | diff - protocol/agentdeck/agentdeck-protocol.schema.json \
  && echo "schema in sync"

# 通过已运行的 canonical shared daemon 执行 Runtime 自检（不会自行 spawn）
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

# daemon 只允许 local UDS 与 agentdeckd/src/remote/ 经纯 relay-client 发起的 allowlisted outbound
bash scripts/check-daemon-network-boundary.sh
```

真实外部 Direct TLS/SPKI synthetic 由本机 admin UDS 先生成一次性 bundle，再执行：

```bash
agentdeck remote synthetic --bundle /secure/path/machine-enrollment-bundle.json
```

该命令只使用临时 machine/device identity，不建立持久状态。P4.2/P4.3 已新增只走 canonical stable Runtime v5
UDS 的 `remote machine enroll --bundle-file FILE`、`remote machine status`、
`remote pairing invite|pending|approve|cancel`、`remote revoke` 与
`remote trust-reset [--admin-purge-receipt-file FILE]`。P4.6 已接入
`remote pair|machines|conversations|watch|prompt|approve|retry-approval|revoke-self`；`remote watch`
输出经过认证边界的 canonical NDJSON。旧 v1 credential marker 只允许做 metadata
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
cargo run -q -p agentdeckd -- \
  --ephemeral --no-remote --profile dev --selfcheck
bash scripts/check-daemon-network-boundary.sh
```

unsigned 开发实例必须显式使用 `--ephemeral --no-remote --profile dev`；stable daemon
不接受 `HOME`、`AGENTDECK_DATA_DIR`、`AGENTDECK_PROFILE` 或运行时 access-group override。
真实 Keychain `set → load → delete` ignored test 只有在编译值、codesign entitlement 与
provisioning profile 一致的 helper 上实际运行后才算通过；当前本机无匹配 provisioning
profile，已签名尝试均被 AMFI 以 exit 137 终止。ignored 不能计作 PASS；P3.1/P3 Phase 的 automatic
completion 只来自完整 dev/ephemeral 门禁，该 provisioned signed 槽位继续保持 post-MVP BLOCKED。

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
bash scripts/check-daemon-network-boundary.sh
```

P3.2 必须保持 caller-owned stable conversation/adapter IDs、全部事务精确重试、24h TTL、
fence/release、32/1,024/256MiB、2GiB admission、safety tail/bounded checkpoint、真实 COMMIT
unknown、认证 metadata/ledger、三业务 lane count/byte bound、paged recovery（单页一个
conversation、80MiB、exact cursor/finish、恢复期 mutation fence）和 shutdown
优先级。P3.4 RuntimeCore 已接入该组件；普通 GUI 后续已由 P3.9-C3、Rust CLI 与 Swift
`main.swift --selfcheck` 已由 P3.9-D 迁到 singleton UDS。P3.2 自身的 store/Core 测试仍不能表述为远程或
Companion E2E。标准 SQLite 无 custom quota VFS，不能声称 active WAL 瞬时零超冲。

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
bash scripts/check-daemon-network-boundary.sh
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
swift test --filter RuntimeProtocolCompatibilityTests
cargo test -p agentdeckd
bash scripts/check-daemon-network-boundary.sh
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
bash scripts/check-daemon-network-boundary.sh
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
已完成 fresh 完整门禁、独立终审、`5568e93` 主体提交与 `c9d2146` / `5713be4` 取消边界补充；
P3.8-A 只接入 accepted-stream primitives；P3.8-B secure bind/permit、P3.9-C3 普通 GUI cutover 与 P3.9-D
Rust CLI / Swift `--selfcheck` cutover 已完成；P3.10 LaunchAgent 已由 `19622ab` 完成 Task verifier 与双路
Task review，Phase hardening 已收口到 `9efb28d`，独立 P3 Phase Exit 也已完成。P4.1 machine identity /
guard 已完成；P4.2 又完成 cert、enrollment、receipt、control-only RemoteTransport 与 trust reset；P4.3
完成 PairInvite/DeviceGrant/DeviceAuthorization/KeyDirectory、本机 auth ledger 与 revoke；P4.4 已完成
唯一 MachineLink ingress 与 RuntimeCore dispatch；P4.5 又完成 signed-sealed publication/counter recovery。
P4.6 persistent remote CLI 已完成 automatic Task，current Runtime wire 为 v5，是 P4 当时的第 6/7 项。
P4.7 automatic Task 与 P4 automatic Phase Exit 现已完成，P4 automatic scope 为 7/7；focused
`p4-auto` 已 PASS，但 `p4` 仍不支持。该 aggregate 不含的顶层 Rust/Swift、最终 diff/status、冻结 hash 与
双路 phase review 已在 pre-closeout candidate SHA-256
`18654fa9c398383dafcefa1542c8e48f8c460f1f521806880c5dab083bdb29f5` 上独立通过；真实 iOS 链路仍未完成。

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
bash scripts/check-daemon-network-boundary.sh
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

### Relay Companion MVP P3.8-A（local Runtime UDS transport primitives）

```bash
cargo test -p agentdeckd --lib local::framing -- --test-threads=1
cargo test -p agentdeckd --lib local::peer -- --test-threads=1
cargo test -p agentdeckd --lib local::unix -- --test-threads=1
cargo test -p agentdeckd --test local_uds -- --test-threads=1
cargo test -p agentdeckd
cargo fmt --all -- --check
cargo clippy -p agentdeckd --all-targets -- -D warnings
bash scripts/check-daemon-network-boundary.sh
scripts/verify-agent-docs.sh
git diff --check
```

same effective UID 必须先于任何 client read；preface 只含版本与 canonical non-nil installation UUID。
Runtime frame 固定 `<1 MiB`，outer version mismatch 只在 header 可信时保留 messageId 并 typed close；
malformed/duplicate/incomplete/exact-cap 零回复。首帧必须 Hello，inner mismatch 仍由 Core 返回。
local-control grant 固定 `ResolveAndRetry`，不得以 `is_local()` 提权。writer 只有 socket write+flush 成功
才 ACK，并把该过程与 Core cancellation 竞争。`local_uds` 必须使用测试自己持有的真实 listener；
P3.8-A 不得暴露 production bind、`LocalReadyPermit` 或 `RemoteStartPermit`。用途感知的
`check-daemon-network-boundary.sh` 是权威 guard；旧 `check-daemon-no-net.sh` 仅保留为兼容 wrapper。
A 阶段 connection actor 必须被 poll/join；
P3.8-B supervisor 必须 graceful cancel + join，禁止用 detached cleanup 掩盖任意 task abort。

### Relay Companion MVP P3.8-B（production UDS/bootstrap）

```bash
cargo test -p agentdeckd --lib local::listener::tests:: -- --test-threads=1
cargo test -p agentdeckd --test local_listener -- --test-threads=1
cargo test -p agentdeckd --test daemon_startup -- --test-threads=1
cargo test -p agentdeckd --test typed_spawn_ownership -- --test-threads=1
cargo test -p agentdeckd
cargo test -p agentdeck-cli --bin agentdeck transport::tests::
swift test --filter ProcessDaemonTransportTests
cargo fmt --all -- --check
cargo clippy -p agentdeckd --all-targets -- -D warnings
bash scripts/check-daemon-network-boundary.sh
bash scripts/check-daemon-no-net.sh
scripts/verify-agent-docs.sh
git diff --check
```

production parser 必须拒绝 `--socket` 和 socket path env override；stable 与默认 ephemeral/no-remote
都只绑定 canonical `DaemonPaths.socket`，后者从 private `TMPDIR/ad-*/s` 派生。stdio 只有完整
`--stdio-compat --ephemeral --no-remote` 才可启动，并只允许 admin/read 命令。listener 必须按值消费
`RecoveryReadyPermit`、持有同一 Core 与 retained singleton dirfd；Darwin FD/path identity 分开验证，
stale/inode replacement fail-closed，shutdown 停止 accept 后 graceful cancel/join 全部连接，再关闭 Core。
该阶段不等于 P3.9 shared-daemon client cutover，也不替代 signed Keychain、真实 vendor 或远程实机门禁。

### Relay Companion MVP P3.9-D（默认入口 + 真实双客户端 smoke）

```bash
cargo test -p agentdeck-cli --locked
cargo test -p agentdeckd -- --test-threads=1
swift test
swift build -Xswiftc -warnings-as-errors
cd ios && xcodegen generate && \
  xcodebuild -project AgentDeckMobile.xcodeproj -scheme AgentDeckMobile \
    -destination 'platform=iOS Simulator,name=iPhone 17' test
cd ..
bash scripts/run-local-runtime-smoke.sh
cargo clippy -p agentdeck-cli --lib --bin agentdeck \
  --test shared_daemon --test runtime_cli_binary --no-deps -- -D warnings
cargo fmt --all --check
bash scripts/check-daemon-network-boundary.sh
scripts/verify-agent-docs.sh
git diff --check
```

canonical `session run` 顺序固定为
`DescribeAgents → Start → Configure(rev0) → Subscribe → SendPrompt(rev1)`；run/continue 必须重发 exact
`SendPrompt`，不得先用 `QueryReceipt` 绕过 payload conflict。reply sequence 使用单一 30 秒 absolute deadline，
中间帧不续期。Rust/Swift 两个 installation 的 receipt 保持 owner-scoped；真实 smoke 必须证明各自查询与
exact replay、cross-owner 拒绝、共同 Backfill、唯一 daemon PID、close-only 和 endpoint 缺失零 fallback。
active-turn sibling-close 复用 listener/RuntimeCore 自动证据，不新增 synthetic execution coordinator。

### Relay Companion MVP P3.9-E（App 会话可靠性收口）

```bash
swift test
swift build -Xswiftc -warnings-as-errors
cd ios && xcodegen generate && \
  xcodebuild -project AgentDeckMobile.xcodeproj -scheme AgentDeckMobile \
    -destination 'platform=iOS Simulator,name=iPhone 17' test
cd ..
bash scripts/run-local-runtime-smoke.sh
bash scripts/check-daemon-network-boundary.sh
scripts/verify-agent-docs.sh
git diff --check
```

P3.9-E 的 retry 分类必须保守：只有 allowlist 明确证明 durable outcome 已知的 definitive reject 可以按失败
stage fresh；transport/closed/unknown 与 `daemon.runtime.store_unavailable` 复用 exact input。catalog +
conversation 共用 64 slots，Unsubscribe ACK
后才改账，Start/History 的腾槽与 Subscribe 也必须经过同一 FIFO admission。stream fault 先完成 close
barrier，下一次用户操作才建新 wire；重连不恢复全部历史 conversation。composer draft 按 logical owner
隔离并受 32-owner、单 draft 256 KiB、总 1 MiB LRU 上界约束。4 个 legacy Swift 文件只要求相对 frozen
baseline 不新增 strict diagnostics；本 Task 实际诊断总数均下降，不能把全文件既有格式债务伪报为 clean。
P3.10 已由 `19622ab` 新增 durable machine-wide admin ledger，并把 switch/exit 许可绑定到
exact `StageUpgrade` reply flush ACK；默认自动门禁仅用隔离 dev/ephemeral + injected verifier，
provisioned production-signed roundtrip 保持 post-MVP BLOCKED，不能写成 PASS。P3.10 Task verifier 与双路
review 已通过；Phase review 的 `773a2b3` / `81cc314` / `9efb28d` 又固定 verifier 10 秒 deadline、
stdout+stderr 合计 256 KiB 上限与同 PGID 回收，超时/超限分别返回
`daemon.install.verifier_timeout` / `daemon.install.verifier_output_too_large`；`0057824` 固定 legacy
v1–v6 在原库 RW 前完成全量认证，新增显式 v1–v4 committed-WAL 篡改矩阵。基于 `9efb28d` 的独立
P3 Phase Exit 已 exit 0，P3 automatic scope complete。P4.1–P4.5 已完成；P4.6 persistent remote CLI
已完成 automatic Task，是 P4 当时的第 6/7 项。P4.5 已接通 signed publication/counter recovery，
其收口时 Runtime wire 为 v4、physical schema 为 v14/35 表；current Runtime wire 已升至 v5。P4.7
automatic Task 与 P4 automatic Phase Exit 也已完成，P4 automatic scope 为 7/7；真实 iOS 链路仍未完成。

### Relay Companion MVP P4.1（Machine identity + guards）

P4.1 code/test 由 `3cd76d2`、`644712c`、`95090c1`、`85df3d2`、`f137112`、`46c6bb8` 收口。
该 Task 收口时 Runtime physical schema 为 v8/24 表，新增 authenticated `machine_identity_state` 与
`runtime_meta.machine_identity_count`；四组 MachineRoot/MachineHPKE/MachineLinkSign/MachineDataSign key
material、key-directory guard、通用 CounterGuard IO 与 Preparing→Active bootstrap 已接入。Active identity
缺 key/guard 或 binding 分叉只阻断 remote，本地 Runtime/UDS 继续；`--ephemeral --no-remote` 对 stable
machine accounts 零 IO。

两路独立终审均 Approved、P0/P1/P2 = 0；完整 `agentdeckd` package exit 0，lib
`916 passed / 3 ignored`、容量项 284.28 秒，selfcheck/diagnostics/network/schema/static/fmt/scoped
Clippy/diff/status 全绿。P4.1 仍为零 cert、零 enrollment workflow、零 enrollment receipt IO、零
RemoteLink；通用 CounterGuard IO 不等于 active key/DB counter reservation或整库历史回滚闭环。P3.1
provisioned signed Keychain roundtrip 继续保持 post-MVP BLOCKED。

### Relay Companion MVP P4.2（certificate + enrollment + control-only RemoteTransport + trust reset）

P4.2 code/test 由 `a6842bc` 收口。该 Task 收口时 Runtime protocol 为 v3，physical schema 为
v9/25 表；本机管理命令固定为：

```bash
agentdeck remote machine enroll --bundle-file /secure/path/machine-enrollment-bundle.json
agentdeck remote machine status
agentdeck remote trust-reset
agentdeck remote trust-reset --admin-purge-receipt-file /secure/path/admin-purge-receipt.json
agentdeck daemon uninstall --purge
```

Task 收口至少运行：

```bash
cargo test -p agentdeckd --locked -- --test-threads=1
cargo test -p agentdeck-cli --locked
cargo test -p agentdeck-relay-client --locked
cargo test -p agentdeck-protocol --locked
cargo test -p agentdeck-relay --features server,tls --locked
cargo test -p agentdeck-crypto --locked
swift test
cd ios && xcodegen generate && \
  xcodebuild -project AgentDeckMobile.xcodeproj -scheme AgentDeckMobile \
    -destination 'platform=iOS Simulator,name=iPhone 17' test
bash scripts/check-daemon-network-boundary.sh
cargo fmt --all -- --check
```

本 Task 的 automatic scope 只证明 root-signed Link/Data cert、durable enrollment/receipt、control-only
MachineLink、root-present/root-lost trust reset、authenticated purge marker/finalizer 与 hermetic
uninstall purge。它不证明业务 RemoteLink、E2EE publication、持久远程 CLI、iOS
真实链路或 production-signed LaunchAgent/Keychain PASS；后者继续保持 post-MVP BLOCKED。

### Relay Companion MVP P4.3（PairInvite + DeviceGrant + auth ledger）

P4.3 收口时 Runtime protocol 为 v4，physical schema 为 v10/30 表。本机管理命令固定为：

```bash
agentdeck remote pairing invite --display-name workstation --idempotency-key invite-001
agentdeck remote pairing pending
agentdeck remote pairing approve 11111111-1111-1111-1111-111111111111
agentdeck remote pairing cancel 11111111-1111-1111-1111-111111111111
agentdeck remote revoke --device <device-route-id> --grant-serial <serial>
```

focused 验证至少覆盖 transport、pairing actor、manager、trust reset、Store pairing/reset guard 与真实
TLS Relay + UDS + CLI pairing E2E；Task 收口再运行上节完整 Rust/Swift/iOS 门禁、schema/network/docs/
fmt/diff/status 与双路独立终审。`PairResponse.info` 必须同时绑定 response hash、HPKE info、
MachineDataSign TBS 与 receipt TBS；invite TTL 固定 298 秒。confirm replay、InstallGrant exact retry、
10 秒 pairing drain、shutdown cancellation、singleflight 与 caller cancellation 都不得降级。

P4.3 最终 code/test 范围为 130 个非 lock 路径（另含 `Cargo.lock`）；`fe3a9ad` 与 `3b4b977` 补齐
Runtime v4 inventory、cancel-safe shutdown/startup、LocalRetry health/admission fence 门禁。最大 production
子片为 Store pairing 1,792 additions，低于 1,800
预拆线；测试与文档不计 production 拆片线。P4.3 本身不证明业务 RemoteLink/E2EE publication、persistent
remote CLI、iOS 真实链路或 production-signed PASS；后续 P4.4 已完成 ingress/Core，P4.5 已完成
signed publication/counter recovery；P4.6 已完成 automatic Task，P4.7 automatic Task 与 P4 automatic
Phase Exit 也已完成。真实 iOS Companion 与 production-signed PASS 仍未完成。

### Relay Companion MVP P4.4（MachineLink ingress + RuntimeCore dispatch）

P4.4 code/test 由 `cd7d9fb` 收口，共 35 个精确 code/test 路径。唯一 MachineLink business lane 复用
P4.2 supervisor/session；完整验证链固定为 Relay v2 outer → DeviceSign/AAD/replay candidate/AEAD → Store
exact-current auth-ledger recheck → RemotePrincipal → RuntimeCore。invalid grant/signature/AAD/replay 与 local
revoke 后的旧 frame 都在 Core 前拒绝；`RouteAccepted` 不代表 daemon 接受或 command success。

RemoteLink 只持易失 generation/replay/connection/reply-route，不持有 canonical conversation、command 或
receipt state，adapter 目录不得 import relay/remote 类型。recovery 完成前 RemoteLink 不启动：Active 可恢复，
Inactive 在 actor install 前终止，Unprovable/legacy 只把对应 conversation 保持只读，健康 sibling 继续服务。
P4.4 仅留下 `DirectedReplySealer` / `RemoteStreamPublisher` 接缝；这是该 Task 收口时的 unavailable seam。
后续 P4.5 已安装真实 sealer/publisher、CounterGuard reservation、MachineDataSign sealing、durable publication
outbox 与 Relay Publish/ACK。P4.6 persistent remote CLI 已完成 automatic Task；P4.7 automatic Task 与
P4 automatic Phase Exit 也已完成。真实 iOS Companion E2E 与 production-signed PASS 仍未完成；
独立 spec/security 与 quality 终审均为 P0/P1/P2=0、Approved。

### Relay Companion MVP P4.5（signed publication + counter/transition recovery）

P4.5 code/test 由 `c6ef387`、`88b3c42` 收口。P4.5 收口时 Runtime wire 为 v4，physical schema 为
v14/35 表。publication 顺序固定为 `CounterGuard reserve → seal once → Runtime DB 冻结 exact blob →
Relay Publish COMMIT → local ACK`；任何 retry、COMMIT outcome unknown 或 daemon restart 都只能复用同一
frozen blob，不得重新 seal。链路离线时 publication park，authenticated reconnect 后从 exact frozen state
继续；counter recovery、publication recovery 与 transition recovery 未全部通过前，production admission
保持关闭。P4.6 persistent remote CLI 已完成 automatic Task，current Runtime wire 为 v5，是 P4 当时的
第 6/7 项；P4.7 automatic Task 与 P4 automatic Phase Exit 现已完成，P4 automatic scope 为 7/7。
P3.1 方案 b 不变，production signing、物理设备与公网证据继续保持 post-MVP BLOCKED；focused
`p4-auto` 已 PASS，但 `p4` 仍不支持，且 focused aggregate 本身不等于完整 Phase Exit 门禁。

### Relay Companion MVP P4.6（persistent remote CLI，automatic Task complete）

current Runtime wire 为 v5。当前命令包括 `pair`、`machines`、`conversations`、`watch`、`prompt`、
`approve`、`retry-approval`、`revoke-self`。`watch` 从 fresh authenticated bootstrap 开始，输出 canonical
NDJSON；SIGINT/SIGTERM 只在当前 exact frame durable apply 与 ACK terminal 后公开 stopped。marker/control
先于 latched signal 输出；Connected+ready signal 零 Subscribe 后 shutdown，verified revoked terminal 优先，
且只有 transport shutdown/drop 与 crash-safe cleanup 完成后才公开 revoked。P4.6 automatic Task 已完成，
计为 P4 当时的第 6/7 项；这份 Task 证据本身不等于后续 P4.7 取得的 `p4-auto` PASS，也不等于
production-signed Keychain PASS。

live partial 跨 disconnect/crash/restart 保留 absolute TTL；runtime 即使收不到下一 Relay frame 也会把到期
binding durable commit 为 `remote.transfer.expired`。paired-state 128 MiB 是 plaintext logical budget，不是
RSS；capacity fallback 保留 replay admission，但不 ACK、不推进 reducer/cursor，并持久化
`remote.transfer.reassembly_full` marker。reducer 声明的 inline + transitive retained 上界固定不超过 64 MiB，
超限必须在 IO/durable mutation 前返回 `remote.runtime.reducer_capacity`。8 MiB lowered-cap seam 仅存在于
`debug_assertions` automatic test build，release artifact 与 production CLI/env/config 不可达。

prepared ADST v2 的 Normal/EmergencyBootstrapMarker mode 位于 AEAD 认证内容内，guard commitment 绑定完整
sealed sidecar；legacy ADST v1 只解释为 Normal。4095→4096 marker 在 guard-first/active-first 两个 crash cut
均可恢复；cleanup 仅由 owner 对 exact sidecar unlink 并允许 retry，缺失后的 reseal 或 commitment conflict
必须 fail-close。legacy over-normal CounterPending active-next 保持零写拒绝。

P4.6 收口运行以下 watch/recovery/exact-receipt focused gate，并以完整
`cargo test -p agentdeck-cli --locked --no-fail-fast` 复核：

```bash
cargo test -p agentdeck-cli --lib --locked remote::watch_tests -- --test-threads=1
cargo test -p agentdeck-cli --lib --locked \
  remote::crypto_state::tests::prepared_stage_capacity_mode_is_authenticated_and_legacy_defaults_fail_closed \
  -- --exact --test-threads=1
cargo test -p agentdeck-cli --lib --locked \
  remote::paired_machine::counter_reservation_tests::state_pending_emergency_mode_recovers_4095_to_4096_marker_at_both_crash_cuts \
  -- --exact --test-threads=1
cargo test -p agentdeck-cli --test remote_runtime_receipts --locked \
  live_ack_phase_signal_is_latched_only_after_durable_apply_and_ack_completion \
  -- --exact --test-threads=1
cargo test -p agentdeck-cli --test remote_runtime_receipts --locked \
  emergency_replay_debt_survives_real_binding_replacement_until_deterministic_pruning_without_cross_binding_loss \
  -- --exact --test-threads=1
```

P4.6 release gate 还必须显式运行常规 `cargo test` 会跳过的 allocator 项：

```bash
cargo test --release -p agentdeck-cli --test remote_transfer_memory --locked \
  production_transfer_peak_is_bounded_across_capacity_completion_and_duplicate -- \
  --ignored --exact --nocapture --test-threads=1
```

2026-07-24 的冻结 code/test scope 为 29 paths，blob-manifest SHA-256 为
`32e7c85620e6e88b407f2403715c52c5a9a5d30aa20d7fb800bdefabe8a1c858`。watch `12/12`、
`remote_persistent_machines` `11/11`、relay-client `25/25`、protocol `244/244` 均通过；完整 CLI
package final run 在同一 hash 上 exit 0（14 分 16 秒，0 failed / 1 expected ignored）。release allocator `1/1`
（24.11 秒），requested-live capacity/complete/duplicate 分别为 `363/190/3 MiB`，该口径不是 RSS。
四 schema、CLI/protocol/relay-client Clippy `-D warnings`、fmt、network/no-net、docs 与 diff 全绿；
`spec/security` 与 `quality` 终审均在同一 hash 上 Approved，P0/P1/P2=0。
P4.6 的既有证据本身不等于后续 P4.7 的 `p4-auto` PASS。`p4-auto` 只聚合 focused
machine/CLI/state-machine/protocol/schema/network/docs 门禁；远端不能确认 pairing 由独立 RuntimeCore
principal gate 证明，不在 machine E2E 内。该入口已 PASS，但仍不包含顶层 `cargo test`、`swift test`、
最终 diff/status、冻结 hash 或双路 phase review；这些门禁已在 pre-closeout candidate SHA-256
`18654fa9c398383dafcefa1542c8e48f8c460f1f521806880c5dab083bdb29f5` 上独立补齐并通过，
`spec/security` 与 `quality` 均 Approved，P0/P1/P2=0。`p4` 仍不受支持。真实槽位 runner 只是静态 fail-closed sentinel：
不读取参数或环境变量，不探测前置条件、不执行真实链路，固定输出完整 `missingInputs` 与
`BLOCKED/mutations=0/evidence=[]/summaryGenerated=false`；真实 preflight/execution 留给 post-MVP。
Linux 只允许 ephemeral test keys，macOS production persistent pairing 必须使用 Keychain 且没有降级面；
MachineRoot 丢失时严格遵循 `docs/RELAY_RUNBOOK.md` 的 portable purge receipt 流程。Task P4.7 complete，
P4 automatic scope 7/7，P4 automatic Phase Exit complete；production-signed Keychain/LaunchAgent、真实
vendor、公网 WSS、物理 iPhone/第二台 Mac、destructive purge 与真实 iOS 链路继续保持 post-MVP BLOCKED。

### Relay Companion MVP P3.9-C0-B3a（configuration pin / prompt admission）

```bash
cargo test -p agentdeckd --test runtime_core -- --test-threads=1
cargo test -p agentdeckd --test runtime_store_command_configuration -- --test-threads=1
cargo test -p agentdeckd --test runtime_store_command_configuration_recovery -- --test-threads=1
cargo test -p agentdeckd --test runtime_store_command_configuration_tamper -- --test-threads=1
cargo test -p agentdeckd --test runtime_store_capacity -- --test-threads=1
cargo test -p agentdeckd
cargo test -p agentdeck-protocol -- --test-threads=1
swift test
swift run AgentDeck -- --selfcheck
cargo fmt --all -- --check
cargo clippy -p agentdeckd --all-targets -- -D warnings
cargo clippy -p agentdeck-protocol --lib -- -D warnings
bash scripts/check-daemon-network-boundary.sh
bash scripts/check-daemon-no-net.sh
scripts/verify-agent-docs.sh
git diff --check
```

B3a code/test 已由 `48594e8`（quota/capacity）与 `09a14b0`（Core/actor admission）提交。Task 收口
读回：daemon package `1138 passed / 6 ignored`，其中 lib `680 passed / 1 ignored`，包含 1,024 ×
256 KiB 的 5-test boundary target `359.75s`；protocol `170/170`、Swift `333/333`、selfcheck、schema、
Clippy/fmt/network/docs/diff 全绿，独立 `spec/security` 与 `quality` 终审 Approved。protocol test-target
Clippy 受 2026-06-29 既有常量断言 warning 阻断，未计 PASS；本 Task 修改 production failure constants，
实际以 protocol 全量测试和 `--lib` Clippy 收口。B3a 只保证 expected revision admission、同事务非零 pin
与 pinned receipt/status/recovery；queued/restart/recovery 加载 exact configuration、Codex/CC argv/control
映射与 recorded fixture 属于独立 Task B3b。

## 浏览与外部资料

需要网页资料时优先使用当前环境可用的官方浏览工具和一手来源。不要引入项目级外部浏览 skill 依赖，也不要要求安装额外工具才能在本仓库工作。
