# AgentDeck 代理工作入口

本文件只作为仓库地图和执行规则，不承载详细百科。更深的产品、架构、诊断和计划信息必须写入下游文档，并随代码同步更新。

## 必读顺序

1. `NORTH_STAR.md`：产品北极星和 v0.2 必赢目标。
2. `README.md`：当前用户可见能力、架构摘要、构建与测试命令。
3. `ARCHITECTURE.md`：稳定架构、分层边界、依赖方向和不变量（v0.2 含 N1–N8 新不变量）。
4. `docs/index.md`：文档记录系统导航。
5. `docs/AGENT_DIAGNOSTICS.md`：自检、诊断日志和 failure code（含 CC adapter failure codes）。
6. `docs/QUALITY.md`：验证命令、质量门禁和文档结构检查（含 v0.2 手动 QA 清单）。
7. `docs/plans/README.md` 与 `docs/plans/`：设计文档和实施计划规则。当前实现基线仍以 `docs/plans/2026-06-30-unified-shell-v02-design.md` / implementation 为准；Relay 以已批准的 `docs/plans/2026-07-10-relay-companion-mvp-design.md` 和 `docs/plans/2026-07-10-relay-companion-mvp-implementation.md` 为目标事实源与执行清单。P2.10 已完成；P3.1/P3.2/P3.3/P3.4 代码分别提交为 `835a7b3`/`8744750`/`3c58f2a`/`a58d84e`，下一项是 P3.5 approval first-wins。真实 provisioned signed Keychain roundtrip 仍 gated BLOCKED，因此不得宣称 P3.1/P3 完成，继续按计划执行 P3–P6。
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
cargo test -p agentdeckd -- --test-threads=1
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
cargo test -p agentdeckd -- --test-threads=1
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
cargo test -p agentdeckd -- --test-threads=1
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
shutdown/Drop 后不得残留自持有 writer 或 detached actor 子任务。P3.7 前 production
execution coordinator 固定 disabled，side-effect-free fake 不是真实 vendor exec 证据。

## 浏览与外部资料

需要网页资料时优先使用当前环境可用的官方浏览工具和一手来源。不要引入项目级外部浏览 skill 依赖，也不要要求安装额外工具才能在本仓库工作。
