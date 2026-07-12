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
iOS Simulator、daemon no-net、文档与四份协议 schema snapshot，并检查
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
bash scripts/check-daemon-no-net.sh
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
bash scripts/check-daemon-no-net.sh
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
daemon no-net、四份 schema、文档门禁、依赖边界与 v1 生产符号扫描。完整故障矩阵由以下
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
