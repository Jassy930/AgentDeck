# AgentDeck 质量与验证

本页把可机械执行的质量入口集中起来。新增规则时优先补测试或脚本，让 agent 能在仓库内直接验证，而不是依赖口头记忆。

## 常用验证命令

```bash
cargo test
swift test
./script/build_and_run.sh --verify
swift run AgentDeck -- --selfcheck
swift run AgentDeck -- --diagnostics-report --json
swift run AgentDeck -- --selfcheck --profile dev
swift run AgentDeck -- --diagnostics-report --json --profile dev
scripts/verify-agent-docs.sh
bash scripts/verify-relay-companion-mvp.sh p0
bash scripts/verify-relay-companion-mvp.sh p2
cargo test -p agentdeckd --test daemon_namespace --test storage_kek \
  --test daemon_startup -- --test-threads=1
cargo run -p agentdeckd -- --ephemeral --no-remote --profile dev --selfcheck
```

## Relay Companion MVP P0 门禁

P0 的统一入口只编排批准设计 §16.5 已存在的门禁，不把合成测试冒充真实 vendor
或物理设备验收：

```bash
# 完整 P0 基线：每个子门禁成功后打印 PASS
bash scripts/verify-relay-companion-mvp.sh p0

# 迭代 reset 脚本时只跑这个聚焦 suite
bash scripts/tests/reset-relay-v1-dev-state.sh
```

统一入口依次覆盖完整 Cargo、Relay v2 server+TLS 全矩阵、v2 配置自检、Swift、
iOS Simulator、daemon network-boundary、文档与四份协议 schema snapshot，并检查
`agentdeck-relay-data/` 不出现在 `git status --short`。真实 vendor、公网 WSS 和
物理 iPhone 仍是后续 gated E2E，不属于 P0 通过声明。

下面 P2.1–P2.8 小节保留的是各增量 task 当时的聚焦门禁。文中“与 v1 并列”或
“尚未 cutover”只描述对应历史阶段；当前生产入口已经在 P2.9 原子切到 Relay v2，
不得据此重新启用旧 listener、旧 protocol namespace 或 `v1-compat`。

## Relay Companion MVP P2.1 Store 门禁

P2.1 仍是与 v1 并列的 v2 Store library，不代表生产 listener 已切换。改动
`agentdeck-relay/src/v2/store/` 或 `RelayV2StoreSettings` 后至少运行：

```bash
# v2 Store migration、事务、故障注入、retention/replay/disk gate
cargo test -p agentdeck-relay --features server \
  --test relay_v2_store -- --test-threads=1

# 独立 v2 配置面：全部配额透传、绝对路径与 hard maxima
cargo test -p agentdeck-relay --features server --lib \
  config::tests::v2_store_settings

# v1 server 回归与代码/文档静态门禁
cargo test -p agentdeck-relay --features server
cargo fmt --all --check
rg -n 'expect\(|unwrap\(|panic!|eprintln!' agentdeck-relay/src/v2/store
bash scripts/verify-agent-docs.sh
git diff --check
```

`rg` 预期生产 Store 源码为空输出；测试中的断言不在扫描目录。若 full-target
clippy 被仓库既有 v1/protocol lint 阻塞，仍须运行聚焦 library clippy，并在
阶段报告中逐项记录既有阻塞，不能用它掩盖 v2 Store 新 warning。

## Relay Companion MVP P2.2 Auth 门禁

P2.2 仍不代表 v2 listener 已上线。改动 canonical auth contract、challenge、
MachineLink/DeviceLink 验签、Store trust CAS 或 PairingAccess 后至少运行：

```bash
# 真实 Ed25519、challenge hard bounds、Store restart/CAS、MachineLink COMMIT前rollback与
# COMMIT后exact retry/fail-closed、Transitioning fence、
# singleton owner/store path、caller cancellation、shutdown/Drop、terminal emergency lifecycle、
# bounded control admission、active replacement、pairing allowlist
cargo test -p agentdeck-relay --features server \
  --test relay_v2_auth_e2e -- --test-threads=1

# challenge 内存状态机（含并发双消费与 source/route token bucket）
cargo test -p agentdeck-relay --lib v2::auth::challenge::tests -- --test-threads=1

# shared canonical contract / typed crypto 与 v1+P2.1 回归
cargo test -p agentdeck-protocol
cargo test -p agentdeck-crypto
cargo test -p agentdeck-relay --features server

# P2.2 production library focused clippy（既有 wire enum 不在本 task 改尺寸）
cargo clippy -p agentdeck-relay --features server --lib --no-deps -- -D warnings \
  -A clippy::needless_return -A clippy::collapsible_if \
  -A clippy::doc_lazy_continuation -A clippy::explicit_auto_deref

# production auth/store 不得增加 panic path；先裁掉 challenge.rs 的内联 test module
for file in agentdeck-relay/src/v2/auth/*.rs; do
  awk '/^#\[cfg\(test\)\]/{exit} {print}' "$file"
done | rg -n 'expect\(|unwrap\(|panic!|eprintln!|todo!|unimplemented!|unreachable!'
cargo fmt --all --check
bash scripts/verify-agent-docs.sh
git diff --check
```

生产 auth 扫描预期为空输出；文件内 `#[cfg(test)]` 的断言可以单独排除后复核。字面
protocol `--all-targets -D warnings` 当前仍会命中既有 `trunk.rs` 两处
`large_enum_variant`、`src/lib.rs` 的 `assertions_on_constants` 与
`tests/relay_v2_contract.rs` 的 `needless_borrows_for_generic_args`。阶段门禁使用上面的
production library focused clippy，并在阶段报告记录这些既有 blocker，不能为消 warning
改 Relay wire enum 大小或夹带无关清理。

## Relay Companion MVP P2.3 Stream Core 门禁

P2.3 仍不代表 v2 listener 已上线。改动 `agentdeck-relay/src/v2/core/`、stream Store
语义或 writer/replay 上限后至少运行：

```bash
# 真实 auth context 下的 role/ownership、COMMIT barrier、多 stream FIFO/hot-stream 轮转、
# tiny writer/Store page clamp、WorkerBusy、ACK/gap/reconnect、per-writer/global 背压、
# origin acceptance 优先级、replay transition fence、heartbeat 与 replacement
cargo test -p agentdeck-relay --features server \
  --test relay_v2_stream_e2e -- --test-threads=1

# Store frozen terminal、cursor/gap、ACK/Unsubscribe target-only maintenance、fault gate、
# stream/subscription principal/global metadata count、disk growth gate 与 startup preflight
cargo test -p agentdeck-relay --features server \
  --test relay_v2_store -- --test-threads=1

# v1/P2.1/P2.2 回归与 production Core lint
cargo test -p agentdeck-relay --features server -- --test-threads=1
cargo test -p agentdeck-protocol
cargo clippy -p agentdeck-relay --features server --lib --no-deps -- -D warnings \
  -A clippy::needless_return -A clippy::collapsible_if \
  -A clippy::doc_lazy_continuation -A clippy::explicit_auto_deref

# 静态门禁
cargo fmt --all --check
for file in agentdeck-relay/src/v2/core/*.rs; do
  awk '/^#\[cfg\(test\)\]/{exit} {print}' "$file"
done | rg -n 'expect\(|unwrap\(|panic!|eprintln!|todo!|unimplemented!|unreachable!'
bash scripts/verify-agent-docs.sh
git diff --check
```

production Core panic 扫描预期为空输出；`#[cfg(test)]` 断言必须先裁掉再判定。
`relay_v2_stream_e2e` 的多 stream case 使用仅容纳一页的 writer，必须证明第二个
Subscribe 在第一个 replay 仍受背压时被 FIFO 接纳，且两个 `ReplayComplete` 和后续
catch-up 都不跨 stream 乱序；hot stream 必须在一个 catch-up quantum 后让出执行权。
tiny-writer case 必须证明非空 replay 会按单帧分页，Store page clamp case 必须证明配置小于
Core 默认时仍完整重放；WorkerBusy case 必须证明 retry 前释放 writer/staging 预算。
slow-writer case 必须同时保留一个 fast reader，证明隔离而不是全局停机；global-budget case
必须证明聚合预算在 socket flush 前不释放、normal 不吃 control reserve，且 Publish 先保留
origin acceptance 再隔离慢 reader。transition-fence case 必须让 Store 在 replay page 读完后
阻塞，同时把 device 置为 Revoke `Transitioning`，证明 replay Publish/Gap/ReplayComplete
均不能跨过 fence。Store metadata case 必须同时覆盖后续 INSERT 与较低配置 reopen 的
principal/global count，并证明幂等 retry 不消耗新 row/disk growth 容量。

涉及 replay 调度、预算释放或 actor lifecycle 的改动，阶段收口再重复运行 stream E2E 10 次，
排除只在调度时序下出现的丢帧/饥饿：

```bash
for _ in {1..10}; do
  cargo test -q -p agentdeck-relay --features server \
    --test relay_v2_stream_e2e -- --test-threads=1 || exit 1
done
```

## Relay Companion MVP P2.4 PairRoute / 在线请求门禁

P2.4 同样不代表 v2 listener 已上线。改动 PairRoute、PairingAccess、online request 路由、
active-generation fence 或 Store cached server ID 后至少运行：

```bash
# 真实 Machine/Device auth + PairingHello/view/activate；PairRoute hard bounds、两端 close、
# close/expiry actor race、PairData/Send/Reply target-first、两侧背压、replacement、断线丢失，
# 非空 stream HWM sentinel + 同连接 PRAGMA data_version 零提交证明
cargo test -p agentdeck-relay --features server \
  --test relay_v2_route_e2e -- --test-threads=1

# PairRoute/request helper、双主体 authorization fence、Store server ID cache 与全部既有回归
cargo test -p agentdeck-relay --features server -- --test-threads=1
cargo test -p agentdeck-protocol

# production lint / API docs / 静态门禁
cargo clippy -p agentdeck-relay --features server --lib --no-deps -- -D warnings \
  -A clippy::needless_return -A clippy::collapsible_if \
  -A clippy::doc_lazy_continuation -A clippy::explicit_auto_deref
RUSTDOCFLAGS="-D warnings" cargo doc -p agentdeck-relay --features server --no-deps
cargo fmt --all --check
for file in agentdeck-relay/src/v2/{auth,core}/*.rs; do
  awk '/^#\[cfg\(test\)\]/{exit} {print}' "$file"
done | rg -n 'expect\(|unwrap\(|panic!|eprintln!|todo!|unimplemented!|unreachable!'
bash scripts/verify-agent-docs.sh
git diff --check
```

route E2E 必须证明 target writer 成功入队之后才产生 `RouteAccepted`：target 满只关闭
target 并返回 quota；origin ACK 满只关闭 origin，目标帧保留。accepted Reply 在 target socket
flush 前断线必须丢失且 SQLite 不变。Pairing Close ACK 不确定时，同一已激活 access 在未过期
tombstone 上重试应得到 `AlreadyAbsent`，但 PairData/Pong 不能继续。biased actor-order case
必须分别覆盖 Close 两端先后与 expiry/Data 先后，不能用 wall-clock sleep 猜竞态。

authorization primitive 单测必须证明 origin 或 target 任一进入 `Transitioning` 时双主体 action
都不执行，并在同一 registry 锁内返回两侧 current 位；router E2E 还要证明 replacement 后旧
origin 不投递、也不能关闭健康 target。SQLite 零写入测试必须先创建非空 stream/HWM sentinel，
再用同一只读 connection 的 `PRAGMA data_version` 与八表语义快照证明 PairRoute/PairData/
Send/Reply 没有任何 commit，不能只比较空表行数。

阶段收口重复运行 route E2E 10 次：

```bash
for _ in {1..10}; do
  cargo test -q -p agentdeck-relay --features server \
    --test relay_v2_route_e2e -- --test-threads=1 || exit 1
done
```

## Relay Companion MVP P2.5 Grant / Revoke / Retire 门禁

改动 root-signed control、auth outcome、terminal writer、retired tombstone 或 purge 后至少运行：

```bash
# 真实 MachineRoot/MachineLink/DeviceSign；COMMIT fault、terminal独立槽/2秒、restart重放、
# target-only purge与RetirementCommitted terminal-only reauth
cargo test -p agentdeck-relay --features server \
  --test relay_v2_revocation_e2e -- --test-threads=1

# 两种 root-signed object 的 canonical/TBS golden、当前30种 outer family与最小可见 schema
cargo test -p agentdeck-protocol --test relay_v2_revocation_canonical_contract
cargo test -p agentdeck-protocol --test relay_v2_contract
cargo test -p agentdeck-protocol --test relay_v2_neutrality

# Rust/Swift kind 28、RetireMachine rootKeyId与共享 wire fixture
swift test --filter RelayV2WireTests

# Store/Auth/Core 全回归；Store测试须串行以稳定注入 transaction fault
cargo test -p agentdeck-relay --features server --test relay_v2_store -- --test-threads=1
cargo test -p agentdeck-relay --features server --test relay_v2_auth_e2e -- --test-threads=1
cargo test -p agentdeck-relay --features server
cargo test -p agentdeck-protocol

# schema、lint、API docs与静态门禁
cargo run -q -p agentdeck-cli -- protocol schema \
  | diff - protocol/agentdeck/agentdeck-protocol.schema.json
cargo clippy -p agentdeck-relay --features server --lib --no-deps -- -D warnings \
  -A clippy::needless_return -A clippy::collapsible_if \
  -A clippy::doc_lazy_continuation -A clippy::explicit_auto_deref
RUSTDOCFLAGS="-D warnings" cargo doc -p agentdeck-relay --features server --no-deps
cargo fmt --all --check
bash scripts/verify-agent-docs.sh
git diff --check
```

revocation E2E 必须从真实 current MachineAccess 经 `RelayCore.handle` 进入，不能用 raw Store
mutation冒充安全证据。必须同时证明：签名/route/trust/serial错误零写入；COMMIT 前 fault恢复旧
generation与普通 queue；Install/Revoke/Retire 的 COMMIT 后回执丢失由 exact canonical retry
恢复且不恢复旧 generation；COMMIT后 normal/control满仍只保留一个 terminal；flush立即关闭，
未 flush不早于约1.75秒且不晚于2.5秒观察窗口；重开 SQLite后合法 possession proof逐字节
重放，伪造 proof零 terminal。coordinator 公共 API 不得出现未验签 raw install/revoke/purge；
terminal-only outcome 只能绑定 principal 匹配的 pending writer，不能用于 active entry。

RetireMachine case必须预填两台 machine 的 grant/stream/frame/subscription，只清目标；事务内
readback须按删除前冻结的 stream keys 直查 frame、执行 `PRAGMA foreign_key_check`、核对 exact
retirement terminal，并在 SQLite reopen后满足 `0/1/0/0/0/0/0`；同时证明 PairRoute、machine/device
writer清空，非目标 machine仍能收到 heartbeat。retired proof只能得到 kind 28 terminal，active
registry保持空。writer单测另须覆盖 queued/in-flight ordinary frame、共享单份 terminal payload、
幂等 admission 不重复 deadline、delivery/receiver/shutdown释放 terminal预算、普通 lifecycle不抢关、
emergency fail-close覆盖，以及全局4,096槽硬上限。device route metadata须覆盖 per-machine/global、
duplicate/higher serial、tombstone占容量与降低限额 reopen fail-closed。

阶段收口重复运行 revocation E2E 10 次：

```bash
for _ in {1..10}; do
  cargo test -q -p agentdeck-relay --features server \
    --test relay_v2_revocation_e2e -- --test-threads=1 || exit 1
done
```

## Relay Companion MVP P2.6 TLS / lifecycle / readiness 门禁

P2.6 仍是并列 v2 library server，不能把这些命令通过解释为 production binary 已从 v1
切换。改动 v2 config、TLS、WebSocket、readiness、进程锁、monitor 或 shutdown 后至少运行：

```bash
# 同一 config suite 在三种 feature surface 下都必须成立；server-only 必须证明
# “配置 TLS 但未编译 tls”稳定失败，不能 fallback 明文。
cargo test -p agentdeck-relay --test relay_v2_config
cargo test -p agentdeck-relay --features server --test relay_v2_config
cargo test -p agentdeck-relay --features server,tls --test relay_v2_config

# exact cert pin、binary-only/4 MiB、固定 public path、独立 health、disk-low、
# typed recoverable error、terminal-only reauth、drain、Drop reap、日志 sentinel、selfcheck。
cargo test -p agentdeck-relay --features server,tls \
  --test relay_v2_tls_e2e -- --test-threads=1

# 真实 SIGTERM 子进程、无 shutdown 时的 5 秒 pre-upgrade deadline、1,024 个完整普通
# HTTP keep-alive 饱和/恢复、slow partial HTTP drain，以及真实 proxy WS source contract。
cargo test -p agentdeck-relay --features server \
  --test relay_v2_lifecycle_e2e -- --test-threads=1

# accept permit、TLS/HTTP header deadline 与 64 KiB header limit 的 focused unit contract。
cargo test -p agentdeck-relay --features server,tls preupgrade::tests --lib

# Store readiness/process lock 与 Core/Auth drain fence 回归。
cargo test -p agentdeck-relay --features server \
  --test relay_v2_store -- --test-threads=1
cargo test -p agentdeck-relay --features server \
  --test relay_v2_auth_e2e -- --test-threads=1
cargo test -p agentdeck-relay --features server \
  --test relay_v2_route_e2e -- --test-threads=1
cargo test -p agentdeck-relay --features server
cargo test -p agentdeck-relay --features server,tls

# PairingHello canonical binary kind、schema 与 Swift mirror。
cargo test -p agentdeck-protocol --test relay_v2_contract
cargo test -p agentdeck-protocol --test relay_v2_neutrality
swift test --filter RelayV2WireTests
cargo run -q -p agentdeck-cli -- protocol schema \
  | diff - protocol/agentdeck/agentdeck-protocol.schema.json

# production lint、API docs与静态门禁。
cargo clippy -p agentdeck-relay --features server,tls --lib --no-deps -- -D warnings \
  -A clippy::large-enum-variant -A clippy::needless-return \
  -A clippy::collapsible-if -A clippy::doc-lazy-continuation
RUSTDOCFLAGS="-D warnings" cargo doc -p agentdeck-relay --features server,tls --no-deps
cargo fmt --all --check
bash scripts/check-daemon-network-boundary.sh
bash scripts/verify-agent-docs.sh
git diff --check
```

TLS E2E 的 redaction case 必须先观察到预期 `relay.frame.rejected` 正向事件，再断言 route、
frame sentinel、key/signature 等敏感输入零命中；完全没有日志不能算通过。public listener 必须
对 health、未知 path 和旧 query pairing不提供 redirect，PairRoute只能在 TLS 后 binary
`PairingHello` 出现。selfcheck必须直接读取 fixture 内 cert/key相对路径、真实迁移绝对临时 DB、
readiness/Core 构造并 shutdown/reopen，不能由测试 CLI 覆盖坏 fixture。

AuthorizationCoordinator 与 RelayCore 的 drain fence 测试必须证明：fence 返回后 Authenticate、
InstallGrant、RevokeDevice、RetireMachine、attach/activate/route返回 `relay.server.draining`；
尚未暴露为网络 endpoint 的内部 RegisterMachine同样拒绝且不进入 Store。SQLite
`PRAGMA data_version` 与八表语义快照不变；与 fence 并发的操作只能完整 COMMIT 或完整
draining，不能半提交。Store process-lock测试必须使用真实子进程，不能只依赖进程内 path
registry。

`ProxyLoopback` 的测试必须证明缺失、重复、逗号列表、非 IP 的
`x-agentdeck-client-ip` 都在 HTTP upgrade 前以 400 拒绝，两个合法来源进入不同 challenge
bucket；direct 模式必须忽略该 header。部署时可信反代必须删除外部同名 header 后，以实际
TCP peer IP 覆写单个 canonical 值，并保持 Relay backend 仅绑定 loopback。

公开连接测试还必须真实发送 1,024 个完整的未知 path HTTP/1.1 请求，并证明每个非 101 响应
显式返回 `Connection: close`、server 端及时 EOF，随后第 1,025 个合法 WebSocket 在期限内收到
101。底层 focused test 必须证明“完整 header”本身不会解除 deadline，只有 handler 标记成功
upgrade 后长连接才能越过 5 秒边界。

阶段收口把 TLS E2E 同时按串行与默认并行调度重复 10 轮，排除 tracing subscriber、terminal
flush、drain与 readiness tick 的时序 flake：

```bash
for _ in {1..10}; do
  cargo test -q -p agentdeck-relay --features server,tls \
    --test relay_v2_tls_e2e -- --test-threads=1 || exit 1
done
for _ in {1..10}; do
  cargo test -q -p agentdeck-relay --features server,tls \
    --test relay_v2_tls_e2e || exit 1
done
```

## Relay Companion MVP P2.7 Admin / enrollment / purge 门禁

P2.7 仍未执行 production listener cutover。改动 admin UDS、enrollment canonical request、
TLS SPKI pin、machine inventory/readback 或 root-lost purge 后至少运行：

```bash
# 真实 0600 UDS + 同 binary CLI、exact leaf SPKI、真实 TLS POST、hash-only code、
# 同请求逐字节重放、不同请求/并发双消费、坏签名/坏 endpoint key、64 KiB/no redirect、
# 网络面无 inventory/purge，以及 fingerprint-bound readback/purge。
cargo test -p agentdeck-relay --features server,tls \
  --test relay_v2_admin_e2e -- --test-threads=1

# wrong-confirm零写、COMMIT-unknown全Core fail-closed、target PairRoute/writer清理和其他realm隔离。
cargo test -p agentdeck-relay --features server \
  --test relay_v2_route_e2e -- --test-threads=1
cargo test -p agentdeck-relay --features server \
  --test relay_v2_store -- --test-threads=1

# admin config必须在有/无server/tls三种surface均保持严格解析。
cargo test -p agentdeck-relay --test relay_v2_config
cargo test -p agentdeck-relay --features server --test relay_v2_config
cargo test -p agentdeck-relay --features server,tls --test relay_v2_config

# enrollment canonical bytes/schema 与全部 Relay 回归。
cargo test -p agentdeck-protocol --test relay_v2_contract
cargo test -p agentdeck-relay --features server
cargo test -p agentdeck-relay --features server,tls
cargo clippy -p agentdeck-relay --features server,tls --lib --no-deps -- -D warnings \
  -A clippy::large-enum-variant -A clippy::needless-return \
  -A clippy::collapsible-if -A clippy::doc-lazy-continuation
RUSTDOCFLAGS="-D warnings" cargo doc -p agentdeck-relay --features server,tls --no-deps
cargo fmt --all --check
bash scripts/check-daemon-network-boundary.sh
bash scripts/verify-agent-docs.sh
git diff --check
```

测试必须证明一次性 code、完整 route/root fingerprint、root/link/data public material、signature、
receipt 与 frozen response 不进入 `Debug` 或 tracing。code 只允许出现在 `machine-enroll create`
的 stdout JSON；测试直接查询 SQLite 时只能找到 SHA-256。错误 fingerprint 必须同时拒绝
readback 和 purge，并在 transaction 的任何删除之前返回。admin purge 的 COMMIT response
若连续两次丢失，旧 active generation 不能恢复；全部 writer 与内存 PairRoute 必须随 Core
fail-closed。stale UDS 只可在明确 `ECONNREFUSED` 且 unlink 前 dev/inode 二次一致时删除；
timeout、其他错误或 inode 变化一律视为已有/不确定实例。

`POST /v2/machine-enroll` 只能在 secure admin 配置完整时存在。direct TLS 必须在 DB/bind 前
把配置第一 pin 与真实 leaf DER SPKI SHA-256 比较；proxy 模式由可信部署显式提供一至两个 pin；
insecure loopback 禁止 admin/enrollment。公网 unknown/admin path 固定 404，不 redirect。

## Relay Companion MVP P2.8 Rust v2 client 门禁（历史 task，当前已 cutover）

P2.8 产出的默认 client 是纯 outbound 依赖树。P2.9 已删除临时 `v1-compat` 和旧调用方；
改动 WSS、TLS verifier、heartbeat、reconnect、enrollment 或 pairing API 后运行：

```bash
cargo test -p agentdeck-relay-client -- --test-threads=1
cargo test -p agentdeck-relay --features server,tls \
  --test relay_v2_tls_e2e -- --test-threads=1
cargo test -p agentdeck-protocol --test e2ee_canonical_contract

# 命中即失败；默认normal client不得带server/store stack。
if cargo tree -p agentdeck-relay-client -e normal \
  | rg -q 'agentdeck-relay v|axum|rusqlite'; then exit 1; fi

cargo clippy -p agentdeck-relay-client --all-targets --no-deps -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc -p agentdeck-relay-client --no-deps
cargo fmt --all --check
git diff --check
```

测试必须证明：Public CA、CA+current/next pin与pinned-SPKI三种策略不机会式降级；错pin使用
`remote.transport.tls_pin_mismatch`，hostname/CA错在调用signer前失败；redirect不跟随；enrollment
只有TLS完成后才写HTTP，响应同时核对server/route/epoch/receipt。principal每次reconnect重签fresh
challenge；signed revoke/retire terminal逐字节返回。active supervisor必须保留独立1MiB control预算，
自动Pong不被15MiB data预算饿死；send进入sink后失败或flush超时都标记outcome-unknown并取消
generation，stalled child在join deadline后abort而非detach。PairingClient没有raw principal send，
close ACK走urgent槽，所有PairingEvent与PairInvite/PairRequest Debug都脱敏。

## Relay Companion MVP P2 完整阶段门禁

P2.9 已把生产 binary、CLI synthetic 和依赖面原子切到 Relay v2；P2.10 用一条
可机械执行的阶段门禁组合所有专项 suite。该入口只证明本机真实 DirectTLS、SQLite、
协议和故障边界，不把 loopback 证据描述为公网或物理 Companion 验收：

```bash
bash scripts/verify-relay-companion-mvp.sh p2
```

入口会运行完整 workspace、`agentdeck-relay --features server,tls` 全矩阵、两个阶段级
组合测试、outbound client、真实 CLI DirectTLS/SPKI synthetic、Relay v2 config selfcheck、
daemon network-boundary、四份 schema、文档门禁、依赖边界与 v1 生产符号扫描。完整故障矩阵由以下
测试共同承担，不能把新建的单个 hardening 文件写成全部证据：

- `relay_v2_store`：COMMIT 前回滚、COMMIT 后响应丢失的逐字节重试、restart、quota、gap、disk-low。
- `relay_v2_auth_e2e`：challenge 并发竞态、generation/serial 单调性、伪造或跨 machine grant 拒绝。
- `relay_v2_stream_e2e`：replay/live barrier、慢 reader 隔离、bounded writer 与 reconnect。
- `relay_v2_revocation_e2e`：signed revoke/retire terminal、commit-unknown、重启后逐字节 terminal replay。
- `relay_v2_lifecycle_e2e`：生产 SIGTERM adapter、硬 drain 上界与 Store lock 释放。
- `relay_v2_tls_e2e`：真实 WSS、证书/SPKI pin、拒绝日志脱敏和 TLS 生命周期。
- `relay_v2_hardening_e2e`：restart byte-identical replay、disk-low 恢复、精确 quota gap、
  PublishBeforeCommit fault 与 DirectTLS server 同库重启的阶段组合链。
- `relay_v2_security_e2e`：endpoint 六类 sentinel 经真实 AEAD+签名后走生产
  DirectTLS/WSS Challenge、Authenticate、RegisterStream、Publish/Core；扫描 outer、响应、
  tracing、`healthz/readyz`、固定 404 的 `/metrics` surface、SQLite DB/WAL，输出
  `0 plaintext matches`，并证明 ciphertext 可 SQL 读回和重启 replay。
- `remote_v2_synthetic`：外部 CLI 进程连接真实 DirectTLS/SPKI Relay，完成 enrollment、
  machine/device auth、grant、publish/replay、Send/Reply 和 signed revoke。

`agentdeck-cli` 与 `agentdeck-relay-client` 的 normal dependency tree 不得出现
`agentdeck-relay` server、axum 或 rusqlite。`DataEnvelope::Plaintext`、`bootstrap_secret`、
`RelayCredentials`、`FakeRelay`、`req_origin` 任一旧生产符号命中均使门禁失败。

## Relay Companion MVP P3.1 namespace / singleton / StorageKEK 门禁

P3.1 的聚焦门禁只证明 daemon startup ownership、文件系统边界和可注入 keystore
contract；它不证明 P3 RuntimeCore、UDS、LaunchAgent 或远程链路完成。unsigned 开发构建
必须使用完整 `--ephemeral --no-remote` pair；stable 需要真实 provisioned daemon-only
Keychain entitlement，不能通过运行时环境变量模拟。

```bash
# namespace、binary startup、StorageKEK（真实签名 roundtrip 默认 gated ignored）
cargo test -p agentdeckd --test daemon_namespace --test storage_kek \
  --test daemon_startup -- --test-threads=1

# daemon crate 与两个过渡 stdio 调用方
cargo test -p agentdeckd
cargo test -p agentdeck-cli
swift test

# unsigned 开发环境的真实 child/selfcheck
cargo run -q -p agentdeck-cli -- selfcheck
cargo run -p agentdeckd -- --ephemeral --no-remote --profile dev --selfcheck

# 边界与静态质量
cargo fmt --all --check
bash scripts/check-daemon-network-boundary.sh
git diff --check
scripts/verify-agent-docs.sh
```

当前聚焦结果为 `daemon_namespace` 18/18、`daemon_startup` 4/4、`storage_kek`
14 PASS + 1 ignored signed gate；CLI 27/27、Swift 243 XCTest + 35 Swift Testing、no-net、
fmt/diff-check 通过。scoped clippy 在显式允许仓库既有 7 类 baseline lint 后再以
`-D warnings` 通过；不要把这句话解读为已清理全仓既有 lint。真实
`agentdeck-cli selfcheck` 返回 `ok`、`protocolVersion=2` 与 Codex/Claude Code 两个
adapter，测试 temp namespace 已清理。

真实 Keychain gate 仍是 **BLOCKED，不是 PASS**：
`macos_keychain_signed_set_load_delete_roundtrip` 已使用唯一 service/account 与 RAII cleanup，
但必须在编译值、codesign entitlement 与 provisioning profile 三者完全一致的 helper 上去掉
ignore 后运行。本机没有匹配 access group 的 provisioning profile；Apple Development 与
本地 self-signed helper 都能通过 `codesign --verify`，启动却被 AMFI 以 exit 137 终止。
取得该外部条件前不得勾选计划 P3.1 Step 4，不得宣称 P3.1/P3 完成。

## Relay Companion MVP P3.2/P3.3 Runtime store 与 adapter 私表门禁

P3.2/P3.3 只验证 Runtime SQLite 与 adapter-private repository/canonical bridge 组件，不表示
RuntimeCore/UDS/RemoteLink 已接入。所有 store tests
必须串行运行，避免 raw SQLite exhaustion/tamper fixture 与 path lease 相互干扰：

```bash
cargo test -p agentdeckd \
  --test runtime_store \
  --test runtime_store_admission \
  --test runtime_store_capacity \
  --test runtime_store_cipher \
  --test runtime_store_identity \
  --test runtime_store_sequence \
  --test runtime_store_queue \
  --test runtime_store_journal \
  --test runtime_store_hardening \
  --test runtime_store_boundaries \
  --test runtime_store_commit_outcome \
  --test runtime_store_recovery \
  --test runtime_store_shutdown \
  --test adapter_state_boundary \
  -- --test-threads=1

# canonical Agent/adapter contract；默认绝不运行真实 CLI/model/history smoke
cargo test -p agentdeckd --test agent_router \
  --test cc_adapter_shape --test codex_adapter_shape -- --test-threads=1

# 真实 canonical smoke 只能显式 opt-in；会调用本机已登录的 vendor CLI
AGENTDECK_E2E=1 cargo test -p agentdeckd --test codex_adapter_shape \
  real_codex_canonical_start_binds_private_state_then_emits_capabilities \
  -- --exact --test-threads=1
AGENTDECK_E2E=1 cargo test -p agentdeckd --test cc_adapter_shape \
  real_claude_streams_at_least_one_assistant_or_turn_complete \
  -- --exact --test-threads=1

# daemon crate 回归与静态边界
cargo test -p agentdeckd
bash scripts/check-daemon-network-boundary.sh
cargo fmt --all -- --check
cargo clippy -p agentdeckd --all-targets --no-deps -- \
  -A clippy::collapsible_if -A clippy::collapsible_str_replace \
  -A clippy::derivable_impls -A clippy::unwrap_or_default \
  -A clippy::needless_borrows_for_generic_args \
  -A clippy::doc_lazy_continuation -D warnings
git diff --check
scripts/verify-agent-docs.sh
```

`runtime_store_boundaries` 会真实写入并重开 1,024 × 256 KiB Accepted payload（精确
256 MiB），不是只改 ledger 的 synthetic fixture；本机 debug 构建单项约需 3–4 分钟。可先
聚焦复跑：

```bash
cargo test -p agentdeckd --test runtime_store_boundaries \
  global_queue_and_payload_accept_exact_1024_and_256_mib_then_replay_before_rejection \
  -- --exact --test-threads=1
```

门禁至少证明：v1 严格七表可原子迁移到 v2 严格九表/live manifest，physical schema 与冻结的
crypto context v1 解耦且既有 wrapped key/row ciphertext 不重写；错误 KEK 零写；无 KEK
rescue index；caller-owned
stable IDs；catalog/command/event u64 exhaustion；32/1,024/256 MiB/24h 精确边界；全部
before-COMMIT rollback 与 after-COMMIT exact retry（含 rescue receipt 与 expiry outer retry）；
TTL expiry event；blind-token 重算；command/conversation/event metadata MAC、authenticated
RuntimeLedger、descriptor AEAD open scan、逐 conversation actual MAX HWM、空 catalog row/
整组 terminal audit/单审计行删除 fail-close；
ExecutionFence + release authorization；`shutdown > safety > read > normal`、per-lane count/
byte bound；真实 COMMIT failure 分类；shutdown timeout 不释放 singleton；main+WAL+SHM、
`max_page_count`、`wal_autocheckpoint=0` + persistent WAL 读回、checkpoint copy peak、
post-COMMIT DiskLow 不 latch、safety tail reserve、bounded PASSIVE checkpoint 与 SafetyOnly；
paged recovery 的 expiry-before-freeze、exact keyset cursor、单页一个 conversation/80 MiB、
mutation fence、begin/page/finish response-loss retry、累计 ledger 核账与 finish 再验证；两个
adapter 私表 namespace 互斥、resume ref AEAD/盲索引无明文、exact retry/conflict、authenticated
row totals、CC native history 显式重建且全程不创建 `cc-meta/`；common descriptor 只有 typed
canonical shape，unknown vendor identity 在 migration 前零写拒绝；before-COMMIT fault 显式
rollback 后 main/WAL/SHM/journal 逐字节恢复，COMMIT 后才启用 persistent WAL；canonical
handle/event/history 不含 ThreadId，Raw frame fail-close，Codex resume exact thread id、CC
authoritative init match 与首次 `--session-id`/已 materialized `--resume` 分支均有门禁；CC
materialization/rebuild 还必须 `O_NOFOLLOW` 有界读回有效 JSONL，fresh home 可继续复用已持久化
session id。未设置 `AGENTDECK_E2E=1` 时，真实 CLI/model/history smoke 必须在 binary probe/spawn
前安全跳过。标准 SQLite 没有 custom quota VFS，因此不得把这些门禁表述成 active WAL 任意
瞬间的 2 GiB 零超冲证明。

该门禁重点守护：

- stable home 来自当前 EUID 的 `getpwuid_r`，不接受 `HOME`/data-dir/runtime access-group
  override；ephemeral/no-remote 与 profile 组合必须严格匹配。
- data root 原子 0700；stable 旧目录只允许当前 UID、实体目录且权限精确 0755 时在
  directory fd 上收紧到 0700；0775/0777/01755、ephemeral 宽权限、symlink、非当前 UID
  entry 都拒绝。
- lock 经持有的 directory fd `openat`，在 `flock` 前后复核 owner/mode/nlink/dev/ino；
  第二 owner 必须立即得到 `daemon.singleton.already_running`。
- stable 只能选择 macOS protected Keychain，ephemeral 只能选择 memory store；没有任何
  stable memory/明文 fallback。
- Runtime DB、`-wal` 或 `-shm` 任一已存在 state 而 `storage-kek.v1` 缺失时拒绝生成替代 key；
  fresh 生成后必须 reload byte-identical，secret Debug 脱敏、Drop 清零。
- Swift/Rust stdio compatibility transport 必须固定传
  `--ephemeral --no-remote --profile dev`，并从 child environment 删除
  `AGENTDECK_DATA_DIR` / `AGENTDECK_PROFILE`；P3.9 UDS cutover 前不触碰 stable namespace。

## Relay Companion MVP P3.4 RuntimeCore 门禁

P3.4 证明 transport-neutral Core、journal actor 与 Runtime v1 精确契约；该阶段的 execution
固定 fail-closed，不能把 fake coordinator 当作后续 P3.7 vendor exec 证据：

```bash
# Core/actor/connection/read pool + 100路Start single-flight
cargo test -p agentdeckd --lib runtime:: -- --test-threads=1
cargo test -p agentdeckd --test runtime_core -- --test-threads=1

# Accepted cancel/revoke、compact receipt、Start replay/COMMIT unknown
cargo test -p agentdeckd --test runtime_store_p34 -- --test-threads=1

# Rust/Swift wire、schema、fixture
cargo test -p agentdeck-protocol -- --test-threads=1
swift test --filter RuntimeV1ProtocolTests

# P3.4 production新增范围 lint；allow 项是仓库既有 trunk/CC/Codex lint，不能扩展
cargo clippy -p agentdeckd --all-targets -- -D warnings \
  -A clippy::large-enum-variant -A clippy::collapsible-if \
  -A clippy::collapsible-str-replace -A clippy::derivable-impls \
  -A clippy::unwrap-or-default -A clippy::needless-borrows-for-generic-args \
  -A clippy::doc-lazy-continuation

cargo fmt --all -- --check
bash scripts/check-daemon-network-boundary.sh
git diff --check
scripts/verify-agent-docs.sh
```

门禁必须覆盖：Start 与首 prompt 分离、100 路同 key 只能 1 Created + 99 Replayed、跨重启
replay bit 与稳定 IDs；QueryReceipt 的 conversation+owner 双绑定及八种 CommandStatus；同
conversation journal FIFO/单 active、跨 conversation 并行、有界 control 公平点；共享强
authorization lease、无 lost wakeup、runner Started 前二次 guard、Accepted revoke/cancel
Safety transaction；恢复 finish 前不调度、P4 前 remote Accepted fail-close；512 frames/16 MiB
预算保持到 socket flush ACK、未 ACK drop 清 registry；ReadPool 满载立即 overload；prepare
cancel/fence/release 失败都 cancel blocked gate；cold release capability 只能消费 durable release
COMMIT permit 后产生 completion future；permit 精确绑定 command/boot/nonce，completion 成功前
精确 process group 已 reap/fence；1,024 conversation/actor、128 writer、1,024 principal lease
硬上界；Core 先 Closing+operation/start-lease quiescence、后发布 Draining，且 shutdown 后
actor/writer/router ownership 归零。

P3.4 的阶段门禁刻意使用 disabled coordinator，因此其中 fake process identity 只验证
store/actor ordering，不能作为真实 vendor 运行证据。当前 production `agentdeckd --exec-gate` 必须
另跑下方 P3.7 门禁；
stable Keychain signed roundtrip 仍受 P3.1 provisioning 外部门禁阻塞。

## Relay Companion MVP P3.5 approval 门禁

P3.5 的退出证据来自 daemon-private Rust unit/store/actor/fault tests。固定 16 项
`runtime_approval` 是聚合 gate：它逐项锁定接口、关键实现 seam 和 wire receipt shape，补足
private API 无法从 integration crate 直接调用的边界，但其中的 `include_str!`/source-shape 断言
本身不是行为证明。不得只跑这 16 项就宣称 CAS、COMMIT unknown、worker 或 terminal safety
事务通过；对应私有行为测试必须一起全绿。

```bash
# 固定 16 项聚合 gate（包含 source-shape 补充，不单独作为行为证据）
cargo test -p agentdeckd --test runtime_approval -- --test-threads=1

# schema v3、migration、1 MiB/active safety reserve 与 approval store/fault 行为
cargo test -p agentdeckd --lib runtime::store::schema::tests:: -- --test-threads=1
cargo test -p agentdeckd --lib runtime::store::sqlite::tests:: -- --test-threads=1
cargo test -p agentdeckd --lib runtime::store::approval::tests:: -- --test-threads=1
cargo test -p agentdeckd --test runtime_store -- --test-threads=1

# permission、policy、8 次/60 秒 worker、actor single-flight/recovery/terminal ordering
cargo test -p agentdeckd --lib runtime::connection::tests:: -- --test-threads=1
cargo test -p agentdeckd --lib runtime::approval::tests:: -- --test-threads=1
cargo test -p agentdeckd --lib runtime::conversation::tests:: -- --test-threads=1
cargo test -p agentdeckd --lib runtime::core::tests:: -- --test-threads=1

# adapter write+newline+flush、route retention/single-flight 与 CC capability gate
cargo test -p agentdeckd --lib codex::adapter::tests:: -- --test-threads=1
cargo test -p agentdeckd --lib claude_code::adapter::tests:: -- --test-threads=1
cargo test -p agentdeckd --lib claude_code::capabilities::tests:: -- --test-threads=1
cargo test -p agentdeckd --test codex_adapter_shape \
  --test cc_adapter_shape -- --test-threads=1

# Runtime receipt/schema/fixture 与 daemon 全回归；显式禁止误入 live vendor smoke
cargo test -p agentdeck-protocol -- --test-threads=1
swift test --filter RuntimeV1ProtocolTests
env -u AGENTDECK_E2E cargo test -p agentdeckd

# 静态边界与文档
cargo fmt --all -- --check
cargo clippy -p agentdeckd --all-targets -- -D warnings \
  -A clippy::large-enum-variant -A clippy::collapsible-if \
  -A clippy::collapsible-str-replace -A clippy::derivable-impls \
  -A clippy::unwrap-or-default -A clippy::needless-borrows-for-generic-args \
  -A clippy::doc-lazy-continuation
bash scripts/check-daemon-network-boundary.sh
git diff --check
scripts/verify-agent-docs.sh
```

行为门禁至少逐项证明：

- schema v3 fresh/v1→v3/v2→v3 migration 保留 crypto context v1 与既有 ciphertext；
  approval row AEAD/metadata MAC、event linkage、deadline/attempt/decision token、
  `approval_count/active_approval_count` ledger MAC 的任一 tamper 都 fail-close；每个 active approval
  预留 1 MiB，普通注册低空间拒绝后 terminal safety lane 仍可收口。open/recovery 必须按全部
  conversation 分批、最多 16 MiB compact projection，并用 keyed full-request digest + 有序常量空间
  event fold 验证无限 manual retry；不得收集全部解密 record/event，零-row orphan event 也要拒绝。
- Pending 注册与 ActionRequest event/high-water/count 原子；100 路 Resolve 只有一个 SQLite CAS
  winner；每个 mutation 的 Before/AfterCommit exact retry 不产生第二个 winner、event 或 adapter
  调用。actor 对 Register/Claim/Retry 只重试 operation 完全匹配的 `CommitOutcomeUnknown`，并始终
  重用原 stable input；其他 outcome 不得安装 route 或启动 worker。Pending Expired 没有 decision；
  Claimed 后 Expired 保留原 winner。
- guard 覆盖 claim COMMIT，connection disconnect/revoke 不取消 daemon-owned delivery；每个
  approval 只有一个 worker，panic 被监督且 route 可显式 retry；每轮最多 8 次/60 秒，默认
  deadline 30 分钟，更短 capability deadline 阻止越界 attempt。Begin COMMIT 成功或 exact replay
  后必须刷新时钟并复核持久化 deadline/round budget；越界时 adapter 调用数为 0，只走 store-only
  Expired/DeliveryFailed。store preflight 与 `BEGIN IMMEDIATE` reload 两次都要对
  `max(stateChanged, roundStarted, lastAttempt)` 做 ClockRegressed 校验；事务内回退不得改变 row、
  event 或签发 permit。
- `AppliedAck` 只在完整 write+newline+flush 后成立；`OutcomeUnknown`/永久失败转
  DeliveryFailed 且不自动重投，manual retry 只能重用 sealed winner；Applied COMMIT unknown 只
  重试 store。adapter 已产生结果但 durable closure 无法安全收敛的 `FatalClosure` 必须让当前 actor
  进入 RecoveryBlocked、清理 approval task 且禁止重投。Completed/Failed/Interrupted 与同 turn
  全部非 Applied approval Expired 必须同一 Safety transaction，先 durable 收口再 cancel/await
  worker；Applied 不得被 terminal transaction 改写。terminal AfterCommit unknown 必须用同一
  completion input 精确重放后正常清 route/启动 successor；route 不存在或 generation 不匹配的迟到
  FatalClosure 必须忽略，不能污染已经 terminal 的 conversation。
- RecoveryBlocked 只停止进程内 worker，不恢复 active delivery，也不在缺少 process fencing 证据
  时伪造 Expired/Interrupted。Codex adapter shape 证明精确 route 和 kind/persist/flush；P3.5 时 CC
  Approval 必须隐藏，P3.7 只有 canonical typed builder 可基于 recorded `control_request` fixture 广告，
  legacy compatibility builder 继续隐藏。

P3.5 没有真实 vendor 或 UI 手动 QA 退出项：production coordinator、
`RuntimeExecutionEvent` 与 `agentdeckd --exec-gate` 的真实接线由 P3.7 单独验证。没有
Codex/CC 登录或没有公开 WSS 时，结果只能记为 GATED/BLOCKED，不能用 fake delivery、shape test
或本地 compatibility stdio 冒充端到端通过。

## Relay Companion MVP P3.6 canonical stream / snapshot / transfer 门禁

P3.6 的退出证据分三层：P3.6-A 的 Rust/Swift/wire contract、P3.6-B 的 Runtime store v4/read-only
WAL pool，以及 P3.6-C 的 StoreCommitHub/subscription/snapshot/transfer/publication component。
任何一层通过都不能替代后两层，更不能冒充 P4 E2EE/Relay Publish 或 P5 Simulator/物理设备 E2E。

```bash
# P3.6-A：Runtime/transfer/E2EE kind 与 Rust↔Swift wire
cargo test -p agentdeck-protocol -- --test-threads=1
swift test
cargo run -q -p agentdeck-cli -- protocol schema \
  | diff - protocol/agentdeck/agentdeck-protocol.schema.json

# P3.6-B/P3.6-C：固定 integration contract 与真实 store/read-pool/snapshot 路径
cargo test -p agentdeckd --test runtime_stream -- --test-threads=1
cargo test -p agentdeckd --test runtime_transfer -- --test-threads=1
cargo test -p agentdeckd --test runtime_store_stream_v4 \
  --test runtime_store_read_pool --test runtime_snapshot -- --test-threads=1

# daemon-private race/resource/fault matrix与完整 daemon 回归
cargo test -p agentdeckd --lib runtime:: -- --test-threads=1
cargo test -p agentdeckd

# 静态边界与文档
cargo fmt --all -- --check
cargo clippy -p agentdeckd --all-targets -- -D warnings
bash scripts/check-daemon-network-boundary.sh
git diff --check
scripts/verify-agent-docs.sh
```

当前 scoped 证据（2026-07-15）：P3.6-A=`7731d1e`，P3.6-B=`02cc640`，P3.6-C=`694f2d9`。
`runtime_stream` 45/45、`runtime_transfer` 17/17、subscription 串行门禁 36/36、daemon lib
464/464（`runtime::` filter 366 项）均通过；默认并发 `cargo test -p agentdeckd` 已读回 exit 0。
Swift 为 256 XCTest + 35 Swift Testing；`agentdeck-protocol`、CLI protocol schema diff、fmt、
clippy `-D warnings`、daemon network-boundary 与 `git diff --check` 全通过。真实 codesigned Keychain
roundtrip 仍有 1 项 ignored/BLOCKED；ignored 不计 PASS，也不影响“P3.6 component 已收口、P3.1
仍未完成”的分层结论。

完整 daemon 门禁必须保持上面的默认并发命令；`--test-threads=1` 只用于聚焦 suite 的可重复 race/
资源时序，不得替代默认调度。威胁场景是 macOS `libtest` 在 soft FD limit 256 下并发创建多份各含
1 个 writer + 8 个 WAL readers 的真实 RuntimeStore，在业务断言前耗尽 FD。为此 unit
`cfg(test)` worker 与 integration fixture 各自在单个 test binary 把同时存活的 Store 限为 4；permit
覆盖 ReadPool/path lease 的完整 teardown。它只稳定测试 harness，production Store、固定 8-reader
ReadPool、配额与调度完全不变。

门禁至少逐项证明：

- Runtime cursor 的 BeforeFirst/checked-next/u64 exhaustion、tagged Catalog/Conversation inner target、
  required-null identity matrix、directed SyncComplete、连续非空 Backfill 与 JSON/UDS 700 KiB / remote
  3.5 MiB carrier 分界在 Rust/Swift/schema/fixture 一致；既有 event ciphertext/nonce/wrapped key 不因
  legacy bridge 重写。
- schema v4 只新增六张 stream 表，event audit append-only；v1/v2/v3 migration、每行 token、v4
  ledger count/bytes/floor、range digest、snapshot hash、publication inner/outer gap/overlap 与
  FK/orphan 任一 tamper 都 fail-close。logical retention 不得写成物理 audit 回收承诺。
- ReadPool 固定 8 个 `mode=ro/query_only=ON` WAL connection、128 MiB retained pages、每页
  64 rows/8 MiB；慢 page/snapshot consumer 持有 memory lease 但不持有 SQLite read transaction，
  writer/checkpoint 仍可推进。槽/byte cap 满立即 typed overload，不排无界 waiter。
- StoreCommitHub 先注册 H+1 watch，再在线性化短 operation 捕获 inner H、Relay-committed outer cut、
  retained floor 与 snapshot source；所有 event COMMIT（含 approval/expiry safety path）只在 durable
  outcome 后 coalesce HWM。before-COMMIT 不通知，after-COMMIT unknown 必须 readback 后通知，坏 target
  bucket fail-close 不能改变原 mutation 或阻断健康 target。
- backfill/snapshot pin 必须在 oneshot send 前绑定 cleanup owner；receiver drop/caller cancellation 不能
  留下 orphan pin。worker 初始化/migration 的 ready error 必须在 path lease release 后才可见，随后
  exact reopen 不需要 polling 且不能返回短暂 `StoreAlreadyOpen`。
- 单 reply pump 严格 `snapshot/backfill → SyncComplete → catchup/live`；Catalog 与 conversation 共用
  barrier 算法，空流从 BeforeFirst 精确交付 0。disconnect/Unsubscribe/5 分钟 absolute TTL/stale
  generation 幂等释放 watch/pin/task/count/bytes；partial TransferPart 或任一 send outcome unknown
  fail-close connection，不补发矛盾 terminal。TTL/前置错误进入无 deadline terminal Failure wait 前
  必须先 exact release live/barrier/snapshot-sender registry quota；测试在 terminal ACK 前读回 quota=0，
  同时允许 terminal writer job 保留到 ACK/disconnect；focused core subscription suite 共 36 项并覆盖
  ACK 前 `(live, barrier, snapshotSender, job)=(0,0,0,1)`、ACK 后 `(0,0,0,0)`。另须覆盖旧 unacked
  terminal Failure 被 resubscribe 取消后，新 generation 保持 connected 并完成 receipt/snapshot/sync；
  control cancellation 是正常 handoff，真实 writer/connection error 仍 fail-close。
- terminal gate 的 6 项专门回归还必须覆盖：disconnect 无 coordination/egress 锁环；pending sibling
  Unsubscribe/shutdown 不等 Failure ACK；同 target replacement 只让最新 generation 出帧；gate wait
  超时立即释放 snapshot pin；第五个 pending capture 在 Store capture/spawn 前拒绝；disconnect 胜出
  后 stale prepare 不重建 per-connection slot。`commit` 必须先登记可取消 job 再返回，激活锁序固定为
  `egress → coordination`，teardown 在 coordination 内只 detach/cancel、释放锁后再 await handle。
- pre-delivery error 必须持有 per-connection egress gate 直到 terminal Failure flush ACK/cancel；在此期间
  sibling job 不得撞单槽 paced reservation，也不得因此 fail-close 健康 connection。同 target 被
  supersede 的 pending job 不发 stale receipt；未来客户端发 replacement 时必须同步取消旧 waiter。
  pending capture 硬上界为 4/connection、128/global，且在 Store capture/spawn 前准入。
- snapshot single-item/10,000 items/64 MiB、global 128 MiB build permit 与 512 MiB ready cap均在真实
  payload 上验证；caller cancel 后已入队 Store command继续持 shared permit/TEMP pin，error 在 terminal
  writer wait 前先压缩并释放 retry payload。Catalog frozen cache 计入同一预算，旧 expiry version 不
  删除续期 cache，每 snapshot 至多一个 sleeper。
- transfer 的 active count、connection/global bytes、64 parts/64 MiB、5 分钟 TTL、metadata/duplicate
  conflict、hash/length、stale generation 与 completed tombstone 使用 checked accounting；只有 clone
  reducer 完整验证后才原子推进 inner cursor 一次，失败/重试不产生部分 apply。
- publication 只验证注入 opaque/fake sealed blob 的 generation/seq/counter/hash/inner range、
  COMMIT-unknown byte-identical retry、ACK、restart 与 per-stream fairness。真实 seal、MachineDataSign、
  CounterGuard、Relay network publish、设备 open/readback 都必须保持未执行状态；Simulator fixture 也
  不能计入本门禁。`TransferStateMachine` 与 publication dispatcher 目前没有 production remote
  owner，component test outcome 不能写成 WSS ingress/egress 证据。

P3.1 provisioned signed Keychain roundtrip 仍是外部 BLOCKED gate；P3.7 exec gate 边界、prepare findings、
fresh 完整门禁与独立终审已收口，并由 `5568e93` 完成主体 scoped commit、`c9d2146` / `5713be4`
补齐真实 current-binary release 前取消门禁与 sentinel leader 退出窗口；P3.8/P3.9 UDS 和 P4 remote 尚未完成。
因此即使本节全绿，也只能收口 P3.6 component，不得宣称 P3、Companion MVP 或真实跨网链路完成。

## Relay Companion MVP P3.7 exec-gate 与 production execution 门禁

本节同时验证 typed journal 前置 contract、真实 current-binary `agentdeckd --exec-gate`、私有 FD、
PGID/start-time、TERM→KILL orphan recovery、typed driver attach 与 durable ACK terminal barrier。
筛选录制和 `/bin/sh` 无副作用 helper 仍不能替代已登录 vendor、真实 approval 或跨设备证据。

```bash
# typed builder、release gate、exact replay、竞态与真实 byte boundary
cargo test -p agentdeckd --lib runtime::store::execution_event::tests -- --test-threads=1
cargo test -p agentdeckd --test runtime_store_execution_event -- --test-threads=1
cargo test -p agentdeckd --test runtime_store_execution_event_commit -- --test-threads=1
cargo test -p agentdeckd --test runtime_store_execution_event_tamper

# typed prepare binding 与 crate 外 UFCS compile-fail
cargo test -p agentdeckd --lib typed_boundary_tests
cargo test -p agentdeckd --test agent_router
cargo test -p agentdeckd --test agent_trait_shape
cargo test -p agentdeckd --doc

# v1 terminal 兼容、open-time dynamic audit、schema migration
cargo test -p agentdeckd --test runtime_store_legacy_terminal -- --test-threads=1
cargo test -p agentdeckd --test runtime_store_hardening -- --test-threads=1
cargo test -p agentdeckd --lib runtime::store::sqlite::migration_tests -- --test-threads=1

# 真实 adapter 录制 → typed RuntimeTranslator/AdapterItemKey → reopen/backfill，以及 terminal reserve 样本
cargo test -p agentdeckd --lib runtime::conversation::runtime_execution_fixture_tests -- --test-threads=1
cargo test -p agentdeckd --test runtime_store_capacity \
  released_terminal_closes_on_fragmented_real_sqlite_with_a_pinned_wal_reader
cargo test -p agentdeckd --lib \
  released_terminal_expires_maximum_approvals_on_fragmented_sqlite_with_pinned_wal

# 真实 oversized replay/backfill 与 subscription resource path
cargo test -p agentdeckd --lib nine_mib_canonical_event_replays_through_backfill_and_snapshot_pages -- --test-threads=1
cargo test -p agentdeckd --lib regular_near_limit_backfill_pages_charge_dto_and_payload_in_one_pool -- --test-threads=1
cargo test -p agentdeckd --lib oversized_backfill_payload_holds_exclusive_read_lease_until_flush_and_cancel -- --test-threads=1

# current-binary gate、production owner、driver/ACK 与两遍 recovery
cargo test -p agentdeckd --lib exec_gate::tests::trusted_program_resolution_ignores_arbitrary_paths_and_stays_in_safe_path
cargo test -p agentdeckd --lib dropping_registered_approval_route_does_not_complete_the_waiting_driver -- --test-threads=1
cargo test -p agentdeckd --lib runtime::conversation::tests::pending_approval_deadline_fences_vendor_and_releases_actor_for_successor -- --exact --test-threads=1
cargo test -p agentdeckd --lib runtime::conversation::tests::approval_expiry_watchdog_fail_closes_a_stalled_terminal_pipeline -- --exact --test-threads=1
cargo test -p agentdeckd --lib runtime::conversation::tests::outcome_unknown_approve_expiry_never_sends_a_synthetic_deny -- --exact --test-threads=1
cargo test -p agentdeckd --test exec_gate -- --test-threads=1
cargo test -p agentdeckd --test runtime_crash_recovery -- --test-threads=1
cargo test -p agentdeckd --test runtime_store_recovery -- --test-threads=1
cargo test -p agentdeckd --test runtime_approval -- --test-threads=1
cargo test -p agentdeckd --test typed_spawn_ownership -- --test-threads=1
cargo test -p agentdeckd --test production_execution_wiring -- --test-threads=1

# 分片 merge gate；默认并发 daemon 回归不可被串行 focused suites 替代
cargo test -p agentdeckd
cargo fmt --all -- --check
cargo clippy -p agentdeckd --all-targets -- -D warnings
cargo run -q -p agentdeck-cli -- protocol schema \
  | diff - protocol/agentdeck/agentdeck-protocol.schema.json
bash scripts/check-daemon-network-boundary.sh
cargo run -p agentdeckd -- --ephemeral --no-remote </dev/null
swift test
git diff --check
scripts/verify-agent-docs.sh
```

typed journal 分片至少证明：adapter 不能提交 raw `RuntimeEvent`/bytes/`ProtocolError`；fresh Item/Error 只在
authenticated Started、精确 turn 与 durable release 之后写入；Error 只能使用固定
`daemon.runtime.execution_failed`；eventId 撞 Started/terminal pointer、错 command/turn、terminal 后
fresh append 全部拒绝，而 COMMIT-unknown、disk-low、clock regression 与 terminal 后的同 eventId
exact replay仍逐字节返回原 event。canonicalization 使用单 build permit，并在已按 retained capacity
计费的 template 上原地写入真实 transactional eventSeq；seq 9→10、`u64::MAX`、最终 64 MiB/+1、
小 payload/巨大 caller capacity 都有直接证据。

event row、conversation HWM、retention/index、runtime ledger 与 live watcher 必须同一 COMMIT；
before-COMMIT 零推进/零通知，after-COMMIT unknown 已推进且只通知一次。open-time audit 遍历真实
authenticated event rows，逐 conversation 验连续 seq、时间单调、command/turn/start/terminal 区间、
approval event totals 与 ledger totals，并拒绝 Raw、空 item/entity identity、orphan/gap 与错误 binding。
持有旧 row key 的旧进程或错误迁移即使能为 release 时间重算有效 MAC，reopen 也必须同时验证
`startedAt <= releaseAuthorizedAt <= terminalAt`（无 terminal 时只验下界）；Started-only 与 released
terminal 各有独立 authenticated tamper case。
legacy v1/v2 terminal 只能由 token domain 选择，不能按 payload shape sniff；Completed/Failed 继续要求
released fence，Interrupted/Canceled 保留历史三种 fence shape。

terminal safety tail 本分片不做未经校准的优化，继续保留旧版 132 MiB 保守 reserve。无 active
approval 的真实 fragmented SQLite + pinned WAL 样本已完成 released terminal 并读回：
`page_count=1141`、`freelist=1057`、checkpoint `log=1116/checkpointed=52`、terminal WAL 增量
74,160 bytes。另一个样本在同样的 fragmentation/pinned-reader 条件下注册每 turn 上限 32 条、
每条精确 256 KiB 的 active approval；terminal 后 32 条全部 Expired、active ledger 清零并成功
reopen/inspect，读回 `page_count=5247`、`freelist=1057`、checkpoint
`log=5798/checkpointed=4734`，WAL 从 23,887,792 增至 32,473,872 bytes。两者仍未覆盖接近 2 GiB
主库的最坏页分配，因此只作为真实基线，不足以授权收窄 reserve；不能用 typed payload 的结构上限
代替近容量上限的实测。

Codex `simple_turn.jsonl` 是一次真实 app-server 运行筛选、固定脱敏后的 6 帧片段；两份 Claude
Code fixture 也已从 2.1.191 真实录制收窄为 assistant/result 与 Bash tool_use/tool_result 最小片段，
移除用户环境、插件清单、绝对路径、思考签名和随机身份；未被测试消费且含短期授权材料的旧
`plan_mode.jsonl` 已删除。capture、筛选、hash 与原始临时文件清理边界见
`agentdeckd/tests/fixtures/README.md`。门禁要求 Raw 立即失败，并逐字节读回 daemon event/item/entity/
command identity、modeled Item 与唯一 terminal；它不替代 live vendor 登录。

exec-gate 门禁必须另外证明：adapter 只从与 gate 相同的固定目录集合（系统目录加 macOS 当前 OS
account 的 `~/.local/bin`，后者由 `getpwuid_r(geteuid())` 获取而非继承 HOME）解析 vendor basename，
继承 PATH 和带 `/` 名称均不能选中 program；gate spec、prompt、nonce/release token 不进 argv/env；exact
release 前 vendor side effect 为零；control FD 关闭会收割 blocked group；release 后所有 child 仍在同一
PGID，completion/actor owner drop 与 vendor 先退出都必须继续清理同组 child；忽略 TERM 的真实 group
必须升级 KILL 并 reap。五个 crash cut、PID start-time mismatch、TERM→KILL 仍失败、healthy/blocked
conversation 隔离、P4 前 remote Accepted 全局拒绝与两遍 recovery cut 都必须通过。

P3.7 已裁决只覆盖始终留在继承 sentinel PGID 内的 cooperative descendants：release 前 vendor/tool
副作用必须为零，cancel、owner drop、vendor 先退出与 crash recovery 都必须 TERM→KILL/reap 全部同组
子孙。主动 `setsid`/`setpgid`，或另起 `launchd`/launch service 等 supervisor 的显式自守护/逃逸是
流程外不支持行为；当前机制不声称检测、枚举或收割，也不得声称逃逸会触发 `RecoveryBlocked`。真实
逃逸样本只作为边界证据保留，不计入受支持的清理用例。

两个 prepare finding 已关闭：blocked gate 从 Ready 起由唯一并行 reaper 持有 `Child`，release 前
cancel/cleanup 必须 KILL 后 await/reap；只有 pre-spawn 且确认无 child 的失败可返回
`PrepareFailedClean`；`current_exe`、socketpair/timeout 配置等调用 Tokio `Command::spawn()` 前的错误可
进入该分类，从调用 Tokio spawn 起的所有错误以及任一无法证明 exact kill/reap 的 attach cleanup
都保持 `PrepareFailed` 并进入 RecoveryBlocked。execution unit、actor queue、clean terminal
COMMIT-unknown exact retry 均有聚焦回归；最终树的完整 package 退出码仍须由本轮门禁读回，不能复用旧的
lib 计数。33 MiB 真实 snapshot 测试只把 harness deadlock deadline 对齐为 120 秒，
未改变预算、flush ACK 或产品超时语义。

approval deadline 组合门禁还必须证明：Codex/Claude Code transient route 被 drop 时，等待中的 driver
不会自行完成或写 response；durable Expired 只能触发 exact fence，不能生成 synthetic Deny；已排队
successor 会在唯一 `Interrupted` terminal 后自动启动。若 fence 已成功但 daemon completion pipeline
仍永久 pending，10 秒 watchdog 必须把 exact conversation fail-close 为 RecoveryBlocked、保留 Started
与 queued Accepted，不得伪造 terminal 或继续执行后续命令。

`production_execution_wiring` 调用真实 daemon binary 内部的 debug-only production probe，并用
`/bin/sh` 无副作用 helper，贯穿 RuntimeCore recovery/actor、production coordinator、typed
router/driver、current-binary gate、durable event ACK 与 terminal；完成路径关闭并 reopen Store 后必须
读回 1 条 canonical item 和 1 条 terminal。取消路径把唯一 Store writer 卡在
`PersistFenceBeforeCommit`，通过 probe 自建临时 DB 的独立 read-only WAL 连接只读已提交 Started/turnId，
再经 RuntimeCore 发起 Cancel；必须读回 Canceled、零 vendor side effect、exact gate PGID 已退出和唯一
Interrupted terminal。两种 probe 都有 30 秒内部 async deadline，先 drop Core/gate owner，再由 35 秒
subprocess watchdog 兜底，不能遗留独立 gate PGID。该只读旁路只存在于 debug probe，不进入 production
RuntimeCore。
probe 不接受 binary/root 注入，内部原子创建随机临时目录并 RAII 清理；release build 不暴露该 CLI。
此门禁证明组合 wiring，不证明 Codex/Claude Code 登录态、live vendor CC approval、UDS、RemoteLink
或物理设备。canonical CC builder 当前已广告 Approval，并把 recorded
`control_request(can_use_tool)` 接到 durable `control_response`；legacy compatibility 与未建模 Hooks
继续隐藏 Approval。canonical CC 2.1.207 status/hook/task/tool lifecycle 必须以封闭 shape 校验后
非持久化消费，未知 subtype/patch fail-close；deferred 或缺失精确 terminal 字段的 result 不得写
TurnComplete。translator 终审门禁还必须覆盖：Codex/CC 两条可区分动作产生不同的有界、脱敏、UTF-8
安全 summary；Codex 自由文本以 JSON 可见转义保留控制边界且超界拒绝，CC 控制字符折叠并截断；非选中
raw 字段不落盘；Codex completed kind 漂移、`inProgress`、未知/缺失 terminal
status 拒绝且保留 in-flight，`declined` 为 Canceled；CC canonical/legacy/history 对无权威退出码的
`tool_result` 均写 `exit_code=None`，fixture byte-equivalence 不漂移。还必须覆盖 command 缺 concrete
command/完整 commandActions/已验证 network target、file request 未绑定同一 in-flight fileChange 的
非空 proposed changes、CC tool 缺具体动作或未知，以及空/过大 permission profile 均不产生 Approval；
file 的 proposed patch 必须先于 approval 可见，optional grantRoot/reason 不能单独授权；permission summary 与
adapter 实际返回的 validated profile 复用同一 validator，并完整保留字段结构；summary 中字段值使用
脱敏投影，adapter 响应仍回送已验证的原始字段值；Debug 不含 request/raw params。Codex 官方
PatchChangeKind object、memoryCitation identity 过滤与 non-authoritative notification 只影响最终
authoritative item 的行为也要由 schema 行为测试锁定，但不能写成 live fixture 证据。

当前树的 credential/用户绝对路径 scan 为空，但祖先提交 `68b6cfd` 仍可读到原
`plan_mode.jsonl`。未经明确授权不得在本 task 用 rebase/filter-repo 改写已共享历史，且当前没有
该 OAuth flow 的撤销/过期读回证据；因此完整 Git history 的 credential 处置仍是明确 security debt，
不能用当前树扫描结果宣称历史已清理。

P3.7 主体代码与 translator 终审修复已由 `5568e93` 提交，真实 release 前取消与 sentinel 退出窗口
补充由 `c9d2146` / `5713be4` 提交；fresh 完整门禁与独立终审已通过。P3.1
provisioned signed Keychain 仍外部 BLOCKED；
P3.8-A 只增加 accepted-stream UDS transport primitives；production secure bind/permit 属于 P3.8-B，
App/CLI 默认 UDS 属于 P3.9。P3.10 LaunchAgent、P4 RemoteLink/E2EE 与 P5/P6 实机证据也必须继续保持未完成。

## Relay Companion MVP P3.8-A local Runtime UDS transport primitives 门禁

本门禁防御的具体场景是：其他 UID、错误版本、超长/歧义 JSON 或慢 socket 在本地控制面获得权限、
拖住 Core budget，或把单连接故障扩散到 sibling。P3.8-A 只验证测试 listener accept 后的连接 actor，
不证明 production pathname bind、stable daemon readiness、App/CLI cutover 或 RemoteLink 已完成。

```bash
# strict preface/header/framing 与 kernel peer gate
cargo test -p agentdeckd --lib local::framing -- --test-threads=1
cargo test -p agentdeckd --lib local::peer -- --test-threads=1
cargo test -p agentdeckd --lib local::unix -- --test-threads=1

# 显式 local-control grant、ConnectionWrite cancellation 与 sibling isolation
cargo test -p agentdeckd --lib \
  verified_local_control_has_fixed_approval_permissions_and_cannot_upgrade_a_lease \
  -- --test-threads=1
cargo test -p agentdeckd --lib \
  connection_write_exposes_shared_bytes_and_observes_core_side_cancellation \
  -- --test-threads=1
cargo test -p agentdeckd --lib \
  core_disconnect_cancels_only_the_slow_writer_and_rejects_ack_after_cancel \
  -- --test-threads=1

# 真实本机 Tokio UDS：双连接、Hello reply、typed close、exact-cap 零回复
cargo test -p agentdeckd --test local_uds -- --test-threads=1

# 完整回归与用途感知 network boundary
cargo test -p agentdeckd
cargo fmt --all -- --check
cargo clippy -p agentdeckd --all-targets -- -D warnings
bash scripts/check-daemon-network-boundary.sh
scripts/verify-agent-docs.sh
git diff --check
```

same-EUID 必须先于 preface 的任何 read；preface payload 最多 4,095 bytes，只含版本与 canonical non-nil
installation UUID。Runtime frame 固定 `<1 MiB`；可信 header 的 outer version mismatch 必须保留原
messageId 并 flush typed failure 后 EOF，malformed/duplicate/incomplete/exact-cap 零回复关闭。首帧只允许
`Request::Hello`，inner version mismatch 仍由 Core 给普通 typed reply。

UDS principal 只能经显式 local-control issuer 获得 `ResolveAndRetry`，read-only issuer 仍为 `None`，
同 identity 不得静默换 grant。transport writer 必须把共享 bytes 的 `write+flush` 与
`ConnectionWrite::cancelled()` 竞争；取消获胜不得 ACK，单连接 EOF/lag 不能停止 Core 或 sibling。
真实 UDS test listener 由测试直接持有；`agentdeckd/src/local/` 在本阶段不得提供 production bind。
P3.8-A 调用方必须 poll/join connection actor，不能用 arbitrary task abort 制造无 owner 的异步收割；
P3.8-B listener supervisor 必须用 graceful cancel + join 收口所有连接后再 shutdown Core。
新 guard 检查 daemon normal dependency tree 与 source allowlist：只放行本机 Unix transport 和 P3.7
私有 socketpair，仍禁止 TCP/UDP/HTTP/WSS stack；`check-daemon-network-boundary.sh` 是权威实现，
旧 `check-daemon-no-net.sh` 仅保留为兼容 wrapper。

## AppKit 重写后的验证清单

前端已完成 SwiftUI→AppKit 全量重写（Tasks 1–12）。以下验证项应在每次涉及前端改动后运行，也是里程碑收口的最低门控。

### 必跑验证命令

```bash
# 零 SwiftUI / Textual import（必须为空输出）
grep -rn "import SwiftUI" Sources Tests

# 构建与测试
swift build
swift test   # 覆盖：markdown builder、display-row、observation binder、
             #         行高缓存、契约一致性、rail 几何、Codex chrome smoke tests

# GUI bundle 启动验证（避免 raw SwiftPM GUI 启动差异）
./script/build_and_run.sh --verify

# headless 自检（IPC 生命周期 + 日志/脱敏）
swift run AgentDeck -- --selfcheck

# 文档结构检查
bash scripts/verify-agent-docs.sh

# Rust 后端（确认后端/协议未被牵动）
cargo test
```

### 手动 `swift run AgentDeck` 核验清单

下列项目无法通过单元测试覆盖，须每次发布前人工验证：

- [ ] 应用可通过 `./script/build_and_run.sh --verify` 启动为 `dist/AgentDeck.app`
- [ ] 应用正常启动，窗口标题显示 `AgentDeck Dev`（debug 构建）
- [ ] 空态首屏对齐 Codex Desktop：透明标题栏、全高左侧侧栏、居中大标题、圆角 composer、连接卡片和底部速率提示
- [ ] 会话态对齐 Codex Desktop：右侧 thread header、右上环境信息面板、底部悬浮 composer
- [ ] 左侧历史侧栏（NSOutlineView）宽度约 260pt，可自由拖动分割线
- [ ] 拖动左侧历史侧栏分割线后，点击/切换会话时分割线保持在用户拖动后的宽度
- [ ] 历史列表刷新后按项目 `cwd` 分组展示
- [ ] 新建会话（点击项目旁加号）→ 右侧显示空状态视图
- [ ] 发送第一条 prompt → 会话流开始流式渲染（reasoning / shell / file-edit 行）
- [ ] 高风险操作触发 approve / deny 控件
- [ ] TurnJumpRail 导航点随轮次更新；点击可跳转
- [ ] 继续历史会话：点击历史行 → 右侧回放历史 items
- [ ] Cmd-Q 正常退出
- [ ] 选中一段会话文字 → 点击会话区空白处 → 选区清除；点击另一段文字 → 选区切换（跨 cell 单选）

### 已知功能对等差异

- 当前无已知差异。（曾遗落的「点击空白处清除文字选中」已补回：`SessionTextSelectionCoordinator.clearActiveSelection()` 配合 `ConversationViewController` 的 leftMouseDown 本地监视器；跨 cell 的 active selection 仍由 `SessionTextSelectionCoordinator` 维护。）

## 测试覆盖率

测量命令：

```bash
cargo llvm-cov --summary-only

swift test --enable-code-coverage
xcrun llvm-cov report \
  .build/x86_64-apple-macosx/debug/AgentDeckPackageTests.xctest/Contents/MacOS/AgentDeckPackageTests \
  -instr-profile=.build/x86_64-apple-macosx/debug/codecov/default.profdata \
  $(pwd)/Sources
```

首次需要：

```bash
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov
```

### 当前基线（2026-06-02 实测）

| 范围 | 行覆盖 | 目标 | 备注 |
| --- | --- | --- | --- |
| Rust 整体 | 71.74% | ≥ 70% | `ipc.rs` 100% / `diag.rs` 97.22% / `record.rs` 92.83% / `codex.rs` 82.31% / `main.rs` 53.92% |
| Swift 整体 | 30.69% | ≥ 30% | 模型层 ≥ 73%；视图层按策略接受低覆盖（见下） |
| 加权整体 | 48.17% | ≥ 45% | (Rust 3175 + Swift 1831) / 10394 |

### 显式不强求覆盖率的范围

下列文件按策略接受低覆盖，靠 `swift run AgentDeck -- --selfcheck`、`--diagnostics-report --json` 和人工 QA 把关。新加代码不得借此豁免；只有进程入口、AppKit 视图控制器装配、真实 IO 桥接才合规。

- `Sources/AgentDeck/SessionViewController.swift`（AppKit 视图控制器装配；纯逻辑已在 `ObservationBinder` / `TurnJumpRailLayout` / `ConversationRailNavigator` / `SessionTextSelectionCoordinator` 等测试中覆盖）
- `Sources/AgentDeck/HistorySidebarViewController.swift`、`Sources/AgentDeck/ConversationViewController.swift`（NSOutlineView / NSTableView delegate 与数据源；与 AppKit 运行时强耦合）
- `Sources/AgentDeck/ConversationRowFactory.swift`、`Sources/AgentDeck/ConversationRowViews.swift`（AppKit NSView 行视图）
- `Sources/AgentDeck/StatusBarView.swift`、`Sources/AgentDeck/TurnJumpRailView.swift`、`Sources/AgentDeck/EmptyStateView.swift`（AppKit 视图渲染）
- `Sources/AgentDeck/main.swift`（应用 bootstrapping）
- `Sources/AgentDeck/AppDelegate.swift`（NSApplication 生命周期）
- `Sources/AgentDeck/ProcessDaemonTransport.swift`（真实 `Process` / `Pipe` / reader 线程；测试用 `Tests/AgentDeckTests/StubDaemonTransport.swift` 走 `DaemonTransport` 协议路径）
- `agentdeckd/src/main.rs` 中 `HubAction::SpawnTurn` / `HubAction::ActionDecision` / `HubAction::History` 三条 worker 分派路径（需要 mock `RuntimeHub` 内部 channel 与 `ActionDecision` 协调，工作量与产出比偏低；其余 `fn run` 分派路径已由 `dispatch_tests` 覆盖）

### 失败处理

如果某次改动让覆盖率显著下降（如 Rust < 70% 或 Swift < 30%），先评估：

- 是否新增了视图层 / 进程入口 / AppKit 桥接代码（按策略接受）→ 在显式不测清单里追加该文件。
- 是否新增了核心路径代码（IPC、adapter、模型层）→ 补测试或拒绝该改动。

仓库目前无 CI。`scripts/verify-relay-companion-mvp.sh p0` 是 Companion MVP 实施期
的本地统一门禁，不代表已经接入 CI；覆盖率仍按本页记录的命令人工复核。

## 按变更范围选择验证

| 变更范围 | 最小验证 |
| --- | --- |
| Rust daemon、IPC、Codex adapter、history list 性能、run record、diagnostics | `cargo test`；涉及运行态再跑 `swift run AgentDeck -- --selfcheck` |
| Swift UI、会话模型、历史回放、live session 侧栏可见性、富文本渲染、选择/滚动行为 | `swift test` |
| approval / action request / action decision | `cargo test approval`；`swift test --filter approval`；再跑完整 `cargo test`、`swift test`、`swift run AgentDeck -- --selfcheck` |
| 诊断日志、自检、数据目录、profile、密钥脱敏 | `cargo test`；`swift run AgentDeck -- --selfcheck`；`swift run AgentDeck -- --diagnostics-report --json`；涉及 profile 时加跑 `swift run AgentDeck -- --selfcheck --profile dev` 和 `swift run AgentDeck -- --diagnostics-report --json --profile dev` |
| 文档结构、AGENTS 入口、计划规则 | `scripts/verify-agent-docs.sh` |
| 协议 schema 或 app-server 方法 | `cargo test`；核对 `protocol/SPIKE_FINDINGS.md` 和 `protocol/CODEX_VERSION.txt` |
| agentdeck-protocol 类型变更 | `cargo test`（漂移测试自动运行）；若漂移测试失败须先重新生成快照（见下） |
| 参考客户端 CLI（agentdeck-cli）、Transport、Client | `cargo test -p agentdeck-cli`；再跑完整 `cargo test` |
| Relay Companion MVP P0 基线或 v1 reset | 迭代时跑 `bash scripts/tests/reset-relay-v1-dev-state.sh`；提交前跑一次 `bash scripts/verify-relay-companion-mvp.sh p0` |
| Relay Companion MVP P3.1 daemon namespace / singleton / StorageKEK | 运行本页 P3.1 聚焦矩阵、`cargo test -p agentdeckd`、CLI/Swift transport tests、daemon network-boundary；stable Keychain 必须另有真实 provisioned signed helper 证据，ignored 不算通过 |
| Relay Companion MVP P3.2/P3.3 Runtime SQLite / journal / adapter 私表 | 运行本页十四组 store/boundary tests（含真实 256 MiB、paged recovery 与 v1→v2 migration）、canonical router/双 adapter tests、默认并发 `cargo test -p agentdeckd`、daemon network-boundary、fmt/clippy/diff/docs；只证明组件，不冒充 RuntimeCore/UDS/Companion E2E |
| Relay Companion MVP P3.4 RuntimeCore / principal / actor | 运行本页 P3.4 Core+Store+Rust/Swift contract 矩阵、100 路 Start 竞态、daemon 全回归、network-boundary/fmt/clippy/diff/docs；该历史阶段用 disabled coordinator，只证明 Core contract，不能替代 P3.7 exec-gate 或 P3.8/P3.9 UDS E2E |
| Relay Companion MVP P3.5 approval CAS / delivery | 运行本页 P3.5 固定 16 项聚合 gate，并以 private schema/sqlite/store/permission/worker/actor fault tests 作为行为证据；补跑 adapter shape、Rust/Swift contract、daemon 全回归与静态边界。P3.5/legacy CC Approval 隐藏；P3.7 canonical typed builder 的 recorded fixture 也不冒充 live vendor E2E |
| Relay Companion MVP P3.6 canonical stream / snapshot / transfer | 运行本页 P3.6 Rust/Swift contract、`runtime_stream`、`runtime_transfer`、store v4/read-pool/snapshot、daemon-private `runtime::` 与完整 daemon 回归；补跑 fmt/network-boundary/diff/docs。fake sealed publication 只证明状态机，不冒充 P4 E2EE/Relay Publish、UDS 或 Companion E2E |
| Relay Companion MVP P3.7 exec-gate / typed production execution | 运行本页 prepare disposition、gate/recovery/driver/typed fixture/production wiring 矩阵、完整 daemon package、clippy/fmt/network-boundary/schema/docs/diff；固定 PATH、私有 FD、唯一 reaper、cooperative-descendant PGID fencing、COMMIT-unknown 与 reopen/backfill 必须有行为证据。显式自守护/逃逸不受支持，helper/fixture 不冒充 live vendor approval、UDS 或实机 E2E |
| Relay Companion MVP P3.8-A local Runtime UDS primitives | 运行本页 framing/peer、local-control/cancellation、真实双连接 `local_uds`、完整 daemon、fmt/clippy/network-boundary/docs/diff；只证明 accepted stream actor，不冒充 P3.8-B secure bind/permit、P3.9 App/CLI cutover 或 remote E2E |
| 测试覆盖率回归怀疑 | `cargo llvm-cov --summary-only`；`swift test --enable-code-coverage` + `xcrun llvm-cov report ...`；对照 `当前基线` 表 |

## 协议 schema 漂移测试

`cargo test` 会在 `agentdeck-protocol` 测试套件中运行 `schema_matches_committed_snapshot`：比较 schemars 从 Rust 类型实时生成的 JSON Schema 与 `protocol/agentdeck/agentdeck-protocol.schema.json` 快照。若两者不一致，说明协议类型已变更但快照未更新，测试失败。

重新生成快照：

```bash
UPDATE_SCHEMA=1 cargo test -p agentdeck-protocol schema_matches_committed_snapshot
```

重新生成后须将快照提交进仓库（`git add protocol/agentdeck/agentdeck-protocol.schema.json`）。

核对快照与当前代码是否同步（独立验证，无需构建测试二进制）：

```bash
cargo run -q -p agentdeck-cli -- protocol schema \
  | diff - protocol/agentdeck/agentdeck-protocol.schema.json \
  && echo "schema in sync"
```

## 门控 E2E 测试

`agentdeck-cli/tests/e2e_codex.rs`、`e2e_claude_code.rs` 和
`e2e_cross_agent_history.rs` 是真实 daemon / vendor CLI 的 E2E 集成测试。
启用方式：

```bash
AGENTDECK_E2E=1 cargo test -p agentdeck-cli --test e2e_codex -- --nocapture
AGENTDECK_E2E=1 cargo test -p agentdeck-cli --test e2e_claude_code -- --nocapture
AGENTDECK_E2E=1 cargo test -p agentdeck-cli --test e2e_cross_agent_history -- --nocapture --test-threads=1
```

**门控机制：** 每个测试在未设置环境变量 `AGENTDECK_E2E` 时 `eprintln!("skipped...")` 后直接早返回（不是 `#[ignore]`，因此不能用 `--ignored` 启用；标准 `cargo test` 中显示为 passed 而非 ignored）。设 `AGENTDECK_E2E=1`（需 `codex login`）才真正运行。

**前置条件：** `codex login` 已完成（测试会真实 spawn daemon 并发送 IPC）。

**断言策略：** E2E 测试只断言响应的契约形态（消息 kind、必要字段存在、退出码等），不断言 agent 返回的具体文本内容，以避免测试因模型输出变化而 flaky。

**CI 默认跳过：** 不设置 `AGENTDECK_E2E=1` 时，标准 `cargo test` 不触发真实 E2E，不需要 `codex login`。

## 文档结构检查

`scripts/verify-agent-docs.sh` 是当前最小 doc-gardening 检查。它验证：

- 关键文档入口存在。
- `AGENTS.md` 链接到项目北极星、README、架构、诊断、质量、计划和协议事实源。
- `README.md` 链接到架构、文档索引和质量文档。
- 项目没有重新引入已剥离的外部 skill 强制绑定。
- `docs/plans/README.md` 存在，计划文档不再只是散落文件。

后续接入 CI 时，先把这个脚本作为独立 job，再逐步增加更严格的结构检查。

## 失败处理

- 验证失败时，不要只重跑。先读失败输出，定位是哪条不变量被破坏。
- 如果失败来自文档漂移，优先更新真实文档或检查脚本，不要绕过规则。
- 如果失败来自 flaky 外部条件，记录命令、错误和复验结果到对应计划文档。

## v0.2 手动 QA 清单（每次 v0.2 发布前必须勾选）

下列项目须人工验证，在 `swift run AgentDeck` 真实运行时逐项确认：

- [ ] 同窗口可启动 Codex 会话 / CC 会话 / 在两者间切换
- [ ] CC 流式消息、reasoning、shell、diff 渲染对等于 Codex
- [ ] CC permission mode（6 种）下拉可切换，新 turn 生效
- [ ] Plan mode 进入后 UI 显示 Plan 内容并可批准/拒绝
- [ ] CC tool use 触发 approval 时显示卡片，底部 vendor 区显示"当前 permission mode + tool name"
- [ ] Codex tool use 触发 approval 时显示卡片，底部 vendor 区显示 sandbox + policy + persist
- [ ] CC 历史 thread 在侧栏与 Codex 历史共存，左侧默认合并显示且不提供 agent 切换
- [ ] CC 历史 thread 点开可回放 + 继续
- [ ] CC archive（`claude rm` 调用）后侧栏不可见，且不影响 Codex 历史显示
- [ ] CC rename 后侧栏标题更新；终端 `claude --resume <id>` 看到同名
- [ ] CC 未登录 → 明确诊断错误，不静默
- [ ] CC 二进制不存在 → 明确诊断错误，附 `npm install` 提示
- [ ] Token usage 在 mini 面板显示
- [ ] Output Style 下拉可见
- [ ] CC capability、Codex 没的，UI 仅在 CC session 显示对应控件
- [ ] Codex capability、CC 没的，UI 仅在 Codex session 显示对应控件
- [ ] AgentDeck 创建的 CC 会话，在终端 `claude --resume <id>` 能看见且能继续（事实唯一来源验证）
- [ ] `cargo test` + `swift test` + `agentdeck selfcheck` + `scripts/verify-agent-docs.sh` 全绿

## 收口清单

阶段性工作结束前至少完成：

1. 更新相关文档。
2. 运行与变更范围匹配的验证命令。
3. 运行 `git status --short --branch`。
4. 摘要说明哪些验证已跑、哪些未跑以及原因。
