# AgentDeck 质量与验证

本页把可机械执行的质量入口集中起来。新增规则时优先补测试或脚本，让 agent 能在仓库内直接验证，而不是依赖口头记忆。

## 常用验证命令

```bash
cargo test
swift test
./script/build_and_run.sh --verify
swift run AgentDeck -- --selfcheck
swift run AgentDeck -- --diagnostics-report --json
swift run AgentDeck -- --diagnostics-report --json --profile dev
scripts/verify-agent-docs.sh
bash scripts/verify-relay-companion-mvp.sh p0
bash scripts/verify-relay-companion-mvp.sh p2
bash scripts/verify-relay-companion-mvp.sh p3
cargo test -p agentdeckd --test daemon_namespace --test storage_kek \
  --test daemon_startup -- --test-threads=1
cargo run -p agentdeckd -- --ephemeral --no-remote --profile dev --selfcheck
```

## Relay Companion MVP Task 粒度门禁（2026-07-18）

Relay Companion 主线恢复 Task 粒度执行。B3a、B3b、B4、B5、C0-C、P3.9-A/B/C3/D/E 及后续编号
task 才是完整收口单位；内部子片只运行行为相关 focused tests、scoped clippy 与 fmt，并做执行者自查。
约 255 秒的完整 package 慢门禁、跨语言全量回归、双路独立终审（spec/security 与 quality）、文档同步与
docs commit 只在 Task 收口执行一次；Phase exit 再运行一次 phase 级双路终审、完整慢门禁与 phase
verifier。1,800/2,000 additions 刹车线只统计单个 production 实现子片的代码新增行，Task aggregate、测试
和文档不计；超过阈值只继续拆 production 子片，不把子片升格为收口 Task。RED→GREEN、精确 pathspec 不放宽，no-net/neutrality/sentinel
等安全矩阵在相关 Task 收口与 Phase exit 按变更范围执行，不扩张为每个子片的重复门禁。

Runtime store 的 P3 验证只承诺已有 committed artifact 中，缺 KEK 或无法通过当前
KEK/database/domain 认证的行/页改删及跨库移植在 open/recovery 全库认证中 fail-close 且拒绝零改写；
整套 DB/main/WAL/SHM 消失与内部自洽的整库历史回滚均由 P4 CounterGuard 覆盖。
同 UID 在线攻击者可读取 daemon 内存密钥或替换进程，属于 accepted residual risk；`974f9b1` 后不再新增
此类 SQLite 竞态测试、hook 或取证门禁。

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
contract；它不证明 P3 RuntimeCore、UDS、LaunchAgent 或远程链路完成。MVP 采用方案 b：开发构建
接受完整 `--ephemeral --no-remote` pair 与 dev/ephemeral Keychain 路径，不把它冒充 stable namespace。
stable production signing 仍需要真实 provisioned daemon-only Keychain entitlement，不能通过运行时
环境变量模拟，相关 roundtrip 已移入 post-MVP 证据槽位。

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

provisioned signed Keychain 证据槽位仍是 **post-MVP BLOCKED，不是 PASS**：
`macos_keychain_signed_set_load_delete_roundtrip` 已使用唯一 service/account 与 RAII cleanup，
但必须在编译值、codesign entitlement 与 provisioning profile 三者完全一致的 helper 上去掉
ignore 后运行。本机没有匹配 access group 的 provisioning profile；Apple Development 与
本地 self-signed helper 都能通过 `codesign --verify`，启动却被 AMFI 以 exit 137 终止。
2026-07-18 已采用方案 b：MVP/P3 phase exit 以已验证的 dev/ephemeral 路径验收，signed roundtrip
移入 post-MVP，不再作为 MVP、P3 或 P4 主线阻塞项，也不再尝试通过代码或本地签名绕过 AMFI。
自动 Task/Phase 门禁仍须逐项读回该 ignored test 为 `BLOCKED`，不得删槽位、记为 PASS，或宣称 stable
production signing 已完成。

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
  `--stdio-compat --ephemeral --no-remote --profile dev`，并从 child environment 删除
  `AGENTDECK_DATA_DIR` / `AGENTDECK_PROFILE`；P3.9 UDS cutover 前不触碰 stable namespace。

## Relay Companion MVP P3.4 RuntimeCore 门禁

P3.4 证明当时的 transport-neutral Core、journal actor 与 Runtime v1 精确契约；当前 wire 已由
P3.9-C0-A1a2 的 `c28a968` / `c36a4f9` 升为 Runtime v2 并完成阶段门禁。P3.4 的 execution
固定 fail-closed，不能把 fake coordinator 当作后续 P3.7 vendor exec 证据：

```bash
# Core/actor/connection/read pool + 100路Start single-flight
cargo test -p agentdeckd --lib runtime:: -- --test-threads=1
cargo test -p agentdeckd --test runtime_core -- --test-threads=1

# Accepted cancel/revoke、compact receipt、Start replay/COMMIT unknown
cargo test -p agentdeckd --test runtime_store_p34 -- --test-threads=1

# Rust/Swift wire、schema、fixture
cargo test -p agentdeck-protocol -- --test-threads=1
swift test --filter RuntimeProtocolCompatibilityTests

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
Safety transaction；恢复 finish 前不调度、P4 durable device-auth readback 接入前 remote Accepted fail-close；512 frames/16 MiB
预算保持到 socket flush ACK、未 ACK drop 清 registry；ReadPool 满载立即 overload；prepare
cancel/fence/release 失败都 cancel blocked gate；cold release capability 只能消费 durable release
COMMIT permit 后产生 completion future；permit 精确绑定 command/boot/nonce，completion 成功前
精确 process group 已 reap/fence；1,024 conversation/actor、128 writer、1,024 principal lease
硬上界；Core 先 Closing+operation/start-lease quiescence、后发布 Draining，且 shutdown 后
actor/writer/router ownership 归零。

P3.4 的阶段门禁刻意使用 disabled coordinator，因此其中 fake process identity 只验证
store/actor ordering，不能作为真实 vendor 运行证据。当前 production `agentdeckd --exec-gate` 必须
另跑下方 P3.7 门禁；
stable Keychain signed roundtrip 仍是 P3.1 post-MVP provisioning BLOCKED 槽位，不计 PASS，但不阻塞
MVP/P3 exit。

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
swift test --filter RuntimeProtocolCompatibilityTests
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
- transfer 的 active count、connection/global bytes、JSON/UDS 94 parts、compact 64 parts、共同
  64 MiB、5 分钟 TTL、metadata/duplicate
  conflict、hash/length、stale generation 与 completed tombstone 使用 checked accounting；只有 clone
  reducer 完整验证后才原子推进 inner cursor 一次，失败/重试不产生部分 apply。
- publication 只验证注入 opaque/fake sealed blob 的 generation/seq/counter/hash/inner range、
  COMMIT-unknown byte-identical retry、ACK、restart 与 per-stream fairness。真实 seal、MachineDataSign、
  CounterGuard、Relay network publish、设备 open/readback 都必须保持未执行状态；Simulator fixture 也
  不能计入本门禁。`TransferStateMachine` 与 publication dispatcher 目前没有 production remote
  owner，component test outcome 不能写成 WSS ingress/egress 证据。

P3.1 provisioned signed Keychain roundtrip 仍是 post-MVP BLOCKED 槽位；P3.7 exec gate 边界、prepare findings、
fresh 完整门禁与独立终审已收口，并由 `5568e93` 完成主体 scoped commit、`c9d2146` / `5713be4`
补齐真实 current-binary release 前取消门禁与 sentinel leader 退出窗口；P3.8-B production UDS 已由
`1e7f9ea` / `459f32a` 完成。本 P3.6 Task 收口当时 P3.9 shared-daemon client 尚未完成；现已由
P3.9-A/B/C3/D 完成，P4 remote 仍未完成。
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
cargo run -p agentdeckd -- --stdio-compat --ephemeral --no-remote --profile dev </dev/null
swift test
git diff --check
scripts/verify-agent-docs.sh
```

typed journal 分片至少证明：adapter 不能提交 raw `RuntimeEvent`/bytes/`ProtocolError`；fresh Item 只在
authenticated Started、精确 turn 与 durable release 之后写入。P5.5 后 execution lane 不再写 Error；fixed
`daemon.runtime.execution_failed` 只由 command terminal builder 写入；eventId 撞 Started/terminal pointer、错 command/turn、terminal 后
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
conversation 隔离、P4 durable device-auth readback 接入前 remote Accepted 全局拒绝与两遍 recovery cut 都必须通过。

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
P3.8-A 增加 accepted-stream UDS transport primitives，P3.8-B production secure bind/permit、默认 UDS
lifecycle 与 stdio compatibility 收窄已由 `1e7f9ea` / `459f32a` 完成；App/CLI 默认连接 shared daemon 属于 P3.9。
P3.10 LaunchAgent 已由 `19622ab` 完成完整 `p3` Task verifier 与双路 Task 终审；Phase hardening 已由
`773a2b3`、`0057824`、`81cc314`、`9efb28d` 收口，基于 `9efb28d` 的独立 P3 Phase Exit 也已
exit 0。P4.1 machine identity/guard automatic Task 已在 `46c6bb8` 收口；P4.2 又由
`a6842bc` 收口 certificate/enrollment/receipt、control-only RemoteTransport 与 trust reset。
P4.3 已由 `518380e`、`b28f995`、`55be98f`、`ba3629f`、`4ec3d2f`、`fe3a9ad`、`3b4b977` 收口 PairInvite/
DeviceGrant/auth ledger/revoke/control handoff；P4.4 又由 `cd7d9fb` 收口 MachineLink ingress/
RuntimeCore dispatch；P4.5 由 `c6ef387`、`88b3c42` 收口 signed publication、key/counter/replay crash
recovery。P4.6 persistent remote CLI 已完成 automatic Task，current Runtime wire 为 v5；
P4.7 automatic Task 与 P4 automatic Phase Exit 已完成，P4 按 Task 进度为 7/7。P5.1 shared facade、
P5.2 crash-safe client storage、P5.3 WSS/pin/per-connection transfer primitive、P5.4
MachineConnection/bounded source、P5.5 canonical fixture/receipt UI、P5.6 iOS production
composition/pairing lifecycle 与 P5.7 macOS SessionSource registry automatic Task 已完成。P5/P6 当前进度为
7/9、0/4；P5.8–P5.9 与 P5 Phase Exit 尚未完成。

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

## Relay Companion MVP P3.8-B production UDS/bootstrap 门禁

本门禁防御的具体场景是：daemon 在 recovery 前开放入口、stale/pathname replacement 被误删、
Darwin FD/path inode 被错误等同、stdin EOF 误杀共享 daemon，或 stdio compatibility 漏放
execution/control 命令。P3.8-B 只证明本机 production ingress 与生命周期；App/CLI 默认连接同一
singleton、LaunchAgent、RemoteLink 和实机 Companion 仍分别属于 P3.9 以后。

```bash
# retained-dirfd bind、stale/inode replacement、Darwin identity 与 graceful supervisor
cargo test -p agentdeckd --lib local::listener::tests:: -- --test-threads=1
cargo test -p agentdeckd --test local_listener -- --test-threads=1
cargo test -p agentdeckd --lib local::unix::tests:: -- --test-threads=1
cargo test -p agentdeckd --test local_uds -- --test-threads=1

# config/stdio allowlist/bootstrap ownership 与真实 binary 生命周期
cargo test -p agentdeckd --test daemon_namespace --test storage_kek \
  --test typed_spawn_ownership -- --test-threads=1
cargo test -p agentdeckd --test daemon_startup -- --test-threads=1
cargo test -p agentdeckd

# P3.9 shared-daemon client cutover 前的 Rust/Swift 进程兼容 transport 必须显式选择 stdio
cargo test -p agentdeck-cli --bin agentdeck transport::tests::
swift test --filter ProcessDaemonTransportTests

# 静态与文档边界
cargo fmt --all -- --check
cargo clippy -p agentdeckd --all-targets -- -D warnings
bash scripts/check-daemon-network-boundary.sh
bash scripts/check-daemon-no-net.sh
scripts/verify-agent-docs.sh
git diff --check
```

真实 binary 测试必须在 private exact-0700 `TMPDIR` 下发现且只发现一个 `ad-*/s`，完成
preface + Hello reply 后才算 ready；stdin 为 `/dev/null` 时 PID 继续存活，SIGTERM 后 exit 0 且
exact socket 消失。`AGENTDECK_DAEMON_SOCKET` 不得改变 endpoint，`--socket` 必须 typed unknown。
显式 stdio 三 flag 在 EOF 后退出且不创建 socket，Ping 可用而 SessionCancel 等 control 返回
`daemon.runtime.stdio_command_forbidden`。P3.1 provisioned signed Keychain roundtrip 继续单列
post-MVP BLOCKED 槽位，不阻塞 MVP/P3 exit。

## Relay Companion MVP P3.9-C0-A1a2 Runtime v2 cutover 门禁

本门禁防御的具体场景是：真实 DB v4 里的 Runtime v1 catalog/snapshot ciphertext 在 schema version
未变化时被新 daemon 误判损坏、启动期 reseal，或经 UDS 仍发送缺少 v2 必填字段的旧 plaintext。

A1a2 因新增行口径达到 2,143 行，拆成 1,748 行 main cutover `c28a968` 与 395 行真实 reader
`c36a4f9`；两者均低于 2,000 行刹车线。独立 spec/security/quality review 的 1 个 P1 与 4 个 P2
均已修复并复核，无残留 P0/P1/P2。A1a complete；总 A1 已由下节 A1b 一并收口。

标准回归至少运行：

```bash
# Runtime v2 contract、deny-unknown、neutrality/private-handle、schema drift 与 current fixture
cargo test -p agentdeck-protocol -- --test-threads=1
cargo test -p agentdeck-cli --test protocol_schema_exports
cargo run -q -p agentdeck-cli -- protocol runtime-schema \
  | diff - protocol/agentdeck/runtime-protocol.schema.json

# Runtime-bound TBS/HPKE 与 Relay fixture metadata 的 Rust/Swift 共享向量
cargo test -p agentdeck-crypto -- --test-threads=1
swift test --filter RelayCryptoVectorTests
cargo test -p agentdeckd --test adapter_state_boundary -- --test-threads=1

cargo test -p agentdeckd --lib \
  runtime::store::snapshot::tests::legacy_runtime_v1_catalog_baseline_dual_decodes_without_rewrite \
  -- --exact
cargo test -p agentdeckd --lib \
  runtime::snapshot::tests::canonical_legacy_v4_snapshot_dual_decodes_to_v2_wire -- --exact
cargo test -p agentdeckd --lib \
  runtime::subscription::egress::tests::production_egress_sends_the_sixty_fifth_json_part \
  -- --exact
cargo test -p agentdeckd --lib \
  runtime::subscription::pump::tests::legacy_v1_snapshot_expansion_keeps_payload_too_large_wire_code \
  -- --exact
```

真实样本门禁固定由 cutover 前 `3b83391`（Runtime v1/schema v4/crypto context v1）的真实 writer 在
exact-0700 临时目录生成 `runtime.db`/WAL/SHM 与 exact-0600 临时 KEK；当前 reader 用显式
`AGENTDECK_A1A2_FIXTURE_DIR` 运行 ignored test，完成 catalog delta、既有 catalog baseline、conversation
snapshot `TransferPart`/逐帧 ACK/`SyncComplete` readback，并比较 authenticated ciphertext manifest：

```bash
AGENTDECK_A1A2_FIXTURE_DIR=/absolute/private/artifact \
cargo test --locked -p agentdeckd --lib \
  'runtime::core::tests::subscription_tests::a1a2_legacy_readback::reads_runtime_v1_v4_sample_as_v2_without_rewrite' \
  -- --ignored --exact --nocapture --test-threads=1
```

2026-07-16 实跑 manifest before/after 均为
`488193ed84b3c777fb0cf394845e5068ff0f6b21f8d782a13bf2ebffa7ad779a`；legacy plaintext 与 v2 wire
分别为 `e48db4fcec7a42edf6b2d94de719216cc9bfc1f65d9cdb9f88237727cc139491`、
`d5607fa2d85ea9ee97f0359761c7bd442d15456b40419ce47ff4b6788f013e5e`。临时 artifact/KEK 与 archive
target 必须在记录非秘密哈希后删除，不能提交。该证据不替代 production Keychain entitlement、live vendor
或 crash durability gate。

```text
wrapped_key_bundle_sha256=bebfaca607960649843eb31d340b388d83d9079cb40c980f4c0a9e29dc9edf76
catalog_delta_ciphertext_sha256=6b9042a0ef4f24dc7de3ace24bd76f3acb24583197bd446317c6953c76f8ce11
catalog_snapshot_ciphertext_sha256=2d820488043f7cfb27d88bf3011fa12777065db0618edd84863d646fd437e3eb
conversation_snapshot_ciphertext_sha256=9198f808c44e90bf160d411bd18638b1926ea3a7fca5c730aee70fcfe41eadcb
legacy_snapshot_plaintext_sha256=e48db4fcec7a42edf6b2d94de719216cc9bfc1f65d9cdb9f88237727cc139491
v2_snapshot_wire_sha256=d5607fa2d85ea9ee97f0359761c7bd442d15456b40419ce47ff4b6788f013e5e
logical_manifest_before=488193ed84b3c777fb0cf394845e5068ff0f6b21f8d782a13bf2ebffa7ad779a
logical_manifest_after=488193ed84b3c777fb0cf394845e5068ff0f6b21f8d782a13bf2ebffa7ad779a
```

## Relay Companion MVP P3.9-C0-A1b signed-material hard-cutover 门禁

本门禁防御的具体场景是：开发环境遗留的 Runtime v1 根签 cert/grant/revocation/retirement 若在
Runtime v2 cutover 后仍被接受，会绕过强制 reset/re-enroll/re-pair，并把旧信任材料提交到当前
Relay Store。测试必须使用真实 Ed25519 旧 TBS 签名；翻转签名 bit、零签名或 dummy fixture 不算证据。

标准回归至少运行：

```bash
# persisted cert/grant 重连、current MachineAccess control material、五个 Store tripwire
cargo test -p agentdeck-relay --features server \
  --test relay_v2_auth_e2e runtime_v1 -- --test-threads=1

# 独立 TLS enrollment verifier：旧 Link/Data cert 403，原 code 的 v2 request 随后成功
cargo test -p agentdeck-relay --features server,tls \
  --test relay_v2_admin_e2e \
  runtime_v1_signed_enrollment_certificates_are_rejected_without_consuming_code \
  -- --exact --test-threads=1

# 相关授权/撤销回归与 Runtime-bound contract
cargo test -p agentdeck-relay --features server,tls \
  --test relay_v2_admin_e2e --test relay_v2_auth_e2e --test relay_v2_revocation_e2e \
  -- --test-threads=1
cargo test -p agentdeck-protocol -- --test-threads=1
cargo test -p agentdeck-crypto -- --test-threads=1
swift test --filter RelayCryptoVectorTests
```

`ef830cd` 新增 730 行 integration tests，低于单 task 2,000 行刹车线。零提交证据必须同时包含：
同一只读 SQLite connection 的 `PRAGMA data_version`、八表计数与授权语义行全等；
`MachineLinkAuthBeforeCommit`、`DeviceAuthBeforeConfirm`、`InstallGrantBeforeCommit`、
`RevokeBeforeCommit`、`PurgeBeforeCommit` 五个 tripwire 不增加；current machine/device access 保持且
无 lifecycle invalidation。Link/Data enrollment 各自使用 fresh code，legacy 403 后同一 code 的 untouched
v2 request 必须 200 并完成 typed server/route readback。最终 spec/security/quality 三路 Approved，无
P0/P1/P2；A1 complete。真实 P4 凭据仍必须在投产前按 runbook 受控 reset/re-enroll/re-pair。

## Relay Companion MVP P3.9-C0-A2 Swift Runtime v2 mirror 门禁

本门禁防御的具体场景是：daemon 已发送 Runtime v2 canonical wire，但 Swift 共享层仍宽松接受未知字段、
把 required-null 当成可缺省，或按错误的 identity/discriminator 解释事件，最终让 App 与 daemon 的
catalog/stream 状态静默分叉。

A2a 已冻结 configuration/metadata/upgrade/agent/changed receipt；A2b 已冻结 catalog、Runtime 专用
strict vendor-panel、canonical event、snapshot/backfill 与 v1 compatibility symbol boundary。A2c1 已冻结
request/reply/message/stream/envelope 与 JSON/UDS 700 KiB × 94 parts；A2c2 已冻结 current facade、
`ADRT1` version 2 compact carrier、98 fixtures 全量、JSON/compact frame cap、production no-v1/source/import
boundary 与真实 UDS Swift readback。A2 complete 仍只表示共享 wire/API 完成，不代表 App/CLI 默认 UDS
client 已 cutover。

```bash
# A2a strict changed DTO 与 A2b1 stream projection focused gate
swift test --filter RuntimeV2ProtocolTests
swift test --filter RuntimeV2StreamProtocolTests
swift test --filter RuntimeV2SnapshotBackfillTests

# A2c1 outer + JSON transfer focused gate（必须实际执行 8 个 XCTest）
swift test --filter RuntimeV2OuterJSONTests

# A2c2 current/compact/source gate（必须分别实际执行 7、1 个 XCTest）
swift test --filter RuntimeV2WireCodecTests
swift test --filter RuntimeV2PublicAPITests

# frozen v1 compatibility（必须实际执行 26 个 XCTest）
swift test --filter RuntimeProtocolCompatibilityTests

# 共享 Core 完整回归与 App 当前构建自检
swift test
swift run AgentDeck -- --selfcheck

# iOS 编译/单测
cd ios
xcodegen generate
xcodebuild -project AgentDeckMobile.xcodeproj -scheme AgentDeckMobile \
  -destination 'platform=iOS Simulator,name=iPhone 17' test
cd ..

# 文档与补丁卫生
scripts/verify-agent-docs.sh
git diff --check
```

A2b1 focused 必须实际执行 6 个 XCTest，A2b2 focused 必须实际执行 7 个 XCTest，均不能接受 0-test
filter。A2b1 证明 500/501 row、bare encoded exact 64 MiB、Removed 的 `conversation_id`、CC optional
missing/null/non-null、全部 event body identity 与 standalone/flattened exact round-trip；A2b2 证明
capabilities-first/config agent、backfill 1…512/sequence/scope/bare 64 MiB、Rust-produced 三条 payload
readback与 compatibility 0/2/6 source boundary。A2c1 另以硬编码 typed path 锁定 97 条 JSON case、
25/45/26 outer 分布、required-null/default、UTF-8 ID 与 standalone/reply/stream transfer 双向负向矩阵；
阶段记录为 focused 8/8、Rust fixture generator 1/1。A2c2 以 focused 7/7、非 `@testable` public API
1/1、frozen v1 26/26 锁定 96 envelope + 1 JSON transfer + 1 compact carrier、25/45/26 outer 分布、
compact byte-exact、18/19-part representability、v1/v2 mismatch、三类 JSON frame 与 compact 双向负向矩阵；
完整 Swift 为 298 XCTest + 35 Swift Testing，iOS 为 20/20，App selfcheck 为 OK。

A2-0 的仓库外样本在 Swift gate 前再次核对为 0600、128 bytes、SHA-256
`393a3201225ef18ae13d4238ba99ea3db612ded4aa86b5819bfab54f01d3421e`。current Swift codec 对同一 raw
Hello reply 的一次性 focused gate实际执行 1 test、0 skipped、0 failures，完成 version/message ID/Hello
语义与 JSON 等价重编码；随后外部样本已删除并确认不存在，一次性测试方法也已退役，不进入长期测试集。

## Relay Companion MVP P3.9-C0-B1b legacy v4 real-writer migration 门禁

**具体威胁场景：** 同 UID writer 在 migration 首轮 preflight 与 DDL 之间替换 legacy meta/token/行，或
合成 fixture 漏掉真实 WAL、sealed row 与 wrapped key 的组合，可能让损坏输入被发布为当时的 current v7，或让迁移
静默重封/重包旧数据。

本门禁的信任根是仓库外、由提交 `28619a8` 的 production v4 writer 生成并在流程外锁定的 main DB、WAL
和 StorageKEK 文件及其 SHA-256；测试只证明这些输入在当前 reader 下通过认证、迁移和 byte-exact
readback，不证明样本生成过程可重放，也不检测内部自洽的整库历史回滚。后者仍依赖 P4 Keychain
CounterGuard。

```bash
# schema / migration / store 边界
cargo test -p agentdeckd --lib runtime::store::schema::tests::
cargo test -p agentdeckd --lib runtime::store::sqlite::migration_tests:: -- --test-threads=1
cargo test -p agentdeckd --test runtime_store
cargo test -p agentdeckd --test runtime_store_boundaries
cargo test -p agentdeckd --test runtime_store_cipher

# 默认完整回归与静态边界
cargo test -p agentdeckd
cargo clippy -p agentdeckd --all-targets -- -D warnings
cargo fmt --all -- --check
RUSTC_WRAPPER= bash scripts/check-daemon-no-net.sh
swift run AgentDeck -- --selfcheck

# 真实 v4 writer 样本经 v5/v6/v7 中间迁移到 current v8；必须实际执行 1 test / 0 ignored
AGENTDECK_B1B_V4_FIXTURE_DIR=/tmp/agentdeck-v4-migration.GQXkAh \
cargo test -p agentdeckd --test runtime_v4_v5_real_migration \
  real_v4_writer_sample_migrates_to_current_v8_with_byte_exact_immutable_rows \
  -- --ignored --exact --nocapture --test-threads=1

# 文档与补丁卫生
scripts/verify-agent-docs.sh
git diff --check
```

B1b scoped code commit 为 `3d0002d`，实际 `+1,399/-64`，低于 1,800 additions 预拆线。收口读回为
migration 21/21、schema 12/12、`runtime_store` 29/29、`runtime_store_boundaries` 5/5、
`runtime_store_cipher` 13/13；默认 `cargo test -p agentdeckd` 的 lib 为 659 passed / 1 ignored，后续
integration/doc tests 也 exit 0。唯一既有 ignored 是 P3.1 provisioned signed Keychain post-MVP 槽位；真实
migration gate 另以显式 `--ignored` 实际执行 1/1。

真实样本哈希固定为 main
`5f3546ea210f042fb06d17cc42c01cf5d35c855b7b5cd97e79a51cb663f11776`、WAL
`7c7c4255a3b4c98edacefcbc0e3d0706ae22d3a975ec9b2c0311308272559bb9`、KEK
`fc8b64001c5fdd0f2f40fb67dae4a865a2c5bd17836676d6d5b58b7917e33717`。它覆盖 1 conversation、
1 Started + 1 Accepted command，以及实际非空的 intent/event/catalog/snapshot；reader 验证对应 sealed
columns、非 `runtime_meta` MAC/blind token 与 wrapped key 迁移前后逐字节一致。未填充的 fence、adapter
state、approval、publication、terminal result 只沿用各自 authenticated regression，不冒充真实非空样本。
最终 1/1 gate 与代码提交完成后，`/tmp/agentdeck-v4-migration.GQXkAh` 和
`/tmp/agentdeck-v4-real.uNbBAf` 已按一次性产物约定删除并确认不存在；长期测试保留显式 ignored reader，
没有真实 writer 样本时不会伪造通过。

本门禁只收口 production schema v5、v1–v4 authenticated migration、fresh/migrated
`conversation_state` 与六项 ledger totals。B2 Configure CAS/snapshot 后续已由 `9330f78`、`fa24782`、
`c54ddc8`、`30103c1` 完成；B3 pin/admission/exact execution、B4 metadata writer、P4 E2EE/CounterGuard、
App/CLI UDS cutover 和 Companion E2E 仍不在 B1b 完成范围。

## Relay Companion MVP P3.9-C0-B2 configuration / Core 门禁

**具体威胁场景：** 已认证 client 在 Configure COMMIT 前断开，或对同一 configuration 做 exact retry / CAS
conflict / reconnect；若 authorization guard 只留在 caller 栈，或 Core 与 Store 各自广播，可能出现撤销已完成
但写入仍提交、重复 `ConfigurationChanged`、Catalog 漂移，或旧 snapshot 与 backfill revision 分叉。

本门禁的信任根是 Runtime Store 已认证的 conversation/configuration/event 链、transport 签发的 opaque
principal lease，以及两个 adapter 在代码中冻结的 default configuration。测试证明这些输入经 B2 writer、
frozen cursor selector 与 Core route 保持一致；不证明 P3.1 provisioned signed Keychain、B3 command pin、
B4 metadata mutation、P4 whole-database rollback detection 或 live vendor login。

```bash
# Router defaults / required trait / cursor snapshot
cargo test -p agentdeckd --test agent_router
cargo test -p agentdeckd --test agent_trait_shape
cargo test -p agentdeckd --test runtime_snapshot

# Core receipt、普通/取消 caller 授权与 subscriber/reconnect/unknown outcome
cargo test -p agentdeckd --lib \
  configure_conversation_returns_exact_replay_conflict_and_typed_failures
cargo test -p agentdeckd --lib \
  configure_authorization_guard_covers_the_store_commit
cargo test -p agentdeckd --lib \
  canceled_configure_caller_keeps_authorization_until_store_completion
cargo test -p agentdeckd --lib \
  configure_applied_replay_and_conflict_have_exact_stream_effects
cargo test -p agentdeckd --lib \
  reconnect_uses_frozen_snapshot_then_configuration_backfill
cargo test -p agentdeckd --lib \
  configure_after_commit_unknown_notifies_once_and_exact_retry_replays

# 完整回归与静态边界
cargo test -p agentdeckd
cargo clippy -p agentdeckd --all-targets -- -D warnings
cargo fmt --all -- --check
bash scripts/check-daemon-no-net.sh
swift run AgentDeck -- --selfcheck
scripts/verify-agent-docs.sh
git diff --check
```

B2c scoped code commit 为 `30103c1`，实际 `+1,333/-72`，低于 1,800 additions 预拆线。收口读回为
Router 8/8、trait shape 1/1、runtime snapshot 23 passed / 1 ignored、daemon lib 672 passed / 1 ignored；
完整 package 含 1,024 × 256 KiB exact boundary（总量 256 MiB）255.29 秒、stream 45/45、transfer 17/17、StorageKEK
14 passed / 1 ignored，全部 exit 0。两路独立终审均 Approved，无 P0/P1/P2。B2 只完成 configuration
CAS/snapshot/Core/defaults；B3–B5、P4–P6 当时仍未完成，P3.1 signed Keychain 则保留为 post-MVP
BLOCKED 槽位。

## Relay Companion MVP P3.9-C0-B3a command pin / prompt admission 门禁

**具体威胁场景：** fresh v5 command 若未与 Accepted journal 同事务持久化 exact configuration pin，或
Core caller/actor shutdown 在 Store COMMIT 前释放 authorization guard，queued/restart/recovery 可能失去原
revision 证据，或在 revocation 已完成后仍提交副作用准入。B3a 只关闭 admission 与 pinned receipt 边界；
按 pin 加载 exact configuration 并映射 adapter argv/control 属于 B3b。

```bash
# B3a Store/Core focused matrix
cargo test -p agentdeckd --test runtime_core -- --test-threads=1
cargo test -p agentdeckd --test runtime_store_command_configuration -- --test-threads=1
cargo test -p agentdeckd --test runtime_store_command_configuration_recovery -- --test-threads=1
cargo test -p agentdeckd --test runtime_store_command_configuration_tamper -- --test-threads=1
cargo test -p agentdeckd --test runtime_store_capacity -- --test-threads=1

# Task 收口完整 package / 跨语言 / 自检
cargo test -p agentdeckd
cargo test -p agentdeck-protocol -- --test-threads=1
swift test
cargo run -q -p agentdeck-cli -- protocol schema \
  | diff - protocol/agentdeck/agentdeck-protocol.schema.json
swift run AgentDeck -- --selfcheck

# 静态、network 与文档
cargo clippy -p agentdeckd --all-targets -- -D warnings
cargo clippy -p agentdeck-protocol --lib -- -D warnings
cargo fmt --all -- --check
bash scripts/check-daemon-network-boundary.sh
bash scripts/check-daemon-no-net.sh
scripts/verify-agent-docs.sh
git diff --check
git status --short --branch
```

实现证据：B3a2-C code/test commit 为 `48594e8`，production additions `+8/-2`；B3a3 code/test
commit 为 `09a14b0`，production additions `195`、tests additions `551`。B3a3 移除了 production
`feature_unavailable`/test-only unconfigured prompt bypass，并让 Store-owned authorization guard 覆盖
durable outcome、通知、reply 与 actor queue registration。

**Task gate 读回（2026-07-18）：** `cargo test -p agentdeckd` exit 0，聚合 `1138 passed / 6 ignored`，
总墙钟约 691 秒；lib `680 passed / 1 ignored`（156.11 秒），包含 1,024 × 256 KiB 边界的 5-test
target `5/5`（359.75 秒）。focused matrix 依次为 Core `3/3`、configuration `14/14`、recovery
`1 passed / 1 ignored`、tamper `2/2`、capacity `9/9`。protocol `170/170`、schema snapshot 逐字一致、
Swift XCTest `298/298` + Swift Testing `35/35`、App selfcheck、daemon all-target Clippy、protocol lib
Clippy、fmt、network/no-net、docs 与 diff 均 exit 0。独立 `spec/security` 与 `quality` 终审最终 Approved，
无剩余 P0/P1/P2。

protocol test-target Clippy 在 Rust 1.96 上受 2026-06-29 既有 `protocol_version_is_positive` 常量断言
`assertions_on_constants` warning 阻断，本轮未把该命令计为 PASS，也没有为 B3a 夹带 baseline 修复；
production `failure.rs` 以 protocol 全量测试和 `cargo clippy ... --lib` 收口。6 个 ignored 均是现有显式
gated/manual artifact fixture；其中 P3.1 provisioned signed Keychain 作为 post-MVP 槽位继续单列
BLOCKED、不计 PASS，也不阻塞 MVP/P3 exit。

## Relay Companion MVP P3.9-C0-B3b exact execution 门禁

**具体威胁场景：** Accepted command 虽有 authenticated configuration pin，但 Start 若只读取 current head、
只认证目标 configuration row，或让普通 live/replay command 把 rev0 解释为当前 defaults，配置在排队期间推进
后就可能改变原命令的 vendor argv/control 与 approval at-decision metadata。B3b 因此要求 Store 在同一
transaction 认证 command、pin 与完整 `1...head` chain，按 pin 选择 historical revision，并只允许真实
migration cutoff 内 command 的 startup recovery 使用冻结 P3.7 rev0 defaults。

```bash
# B3b Store/Core/adapter focused matrix
cargo test -p agentdeckd --test runtime_store_command_configuration_recovery -- --test-threads=1
cargo test -p agentdeckd --lib \
  runtime::conversation::runtime_execution_fixture_tests:: -- --test-threads=1
cargo test -p agentdeckd --test production_execution_wiring -- --test-threads=1
cargo test -p agentdeckd --test runtime_crash_recovery -- --test-threads=1
cargo test -p agentdeckd --lib codex::driver_tests:: -- --test-threads=1
cargo test -p agentdeckd --lib claude_code::driver_tests:: -- --test-threads=1
cargo test -p agentdeckd --lib codex::runtime_translate_tests:: -- --test-threads=1
cargo test -p agentdeckd --lib claude_code::runtime_translate_tests:: -- --test-threads=1
cargo clippy -p agentdeckd --lib --tests -- -D warnings
cargo fmt --all -- --check

# Task 收口完整 package / 跨语言 / 自检
cargo test -p agentdeckd
cargo test -p agentdeck-protocol -- --test-threads=1
swift test
cargo run -q -p agentdeck-cli -- protocol schema \
  | diff - protocol/agentdeck/agentdeck-protocol.schema.json
swift run AgentDeck -- --selfcheck

# 静态、network 与文档
cargo clippy -p agentdeckd --all-targets -- -D warnings
cargo clippy -p agentdeck-protocol --lib -- -D warnings
cargo fmt --all -- --check
bash scripts/check-daemon-network-boundary.sh
bash scripts/check-daemon-no-net.sh
scripts/verify-agent-docs.sh
git diff --check
git status --short --branch
```

实现证据：`c0ed6cd` 接通 exact configuration execution 与两家 adapter 映射，`f4141f0` 收紧 rev0
startup-only provenance 并让 production probe 跨真实 Store shutdown/reopen，`fb1629a` 把中立
`ClaudeCodePermissionMode::Default` 映射到当前 vendor CLI 的 `--permission-mode manual`。B3b production
additions 合计 658；测试和文档 additions 不计入 1,800/2,000 刹车线。

**Task gate 已确认读回（2026-07-18）：** daemon lib `691 passed / 1 ignored`（126.04 秒）；完整 daemon
package exit 0，经 test list 复核共 1,156 tests，即 `1150 passed / 6 ignored`；1,024 × 256 KiB 容量
target `5/5`（278.46 秒）；4,096 行完整 configuration chain target `1/1`（55.97 秒）；protocol
`170/170`；Swift XCTest `298/298` + Swift Testing `35/35`；schema snapshot、自检、daemon all-target
Clippy、protocol lib Clippy、fmt、network/no-net、docs 与 diff 均全绿。6 个 ignored 继续
作为显式 gated/manual 项，其中 P3.1 provisioned signed Keychain 保持 post-MVP BLOCKED、不计 PASS，
也不阻塞 MVP/P3 exit。

production wiring probe 使用 non-default rev1 Accept command，随后把 head 推进到 rev2，并跨 Store
shutdown/reopen + startup recovery 证明 synthetic `ProbeAgent` 仍只取得 rev1。仓库内 recorded
argv/control/translator fixture 只证明 builder/translator 字段映射；这些自动证据都不是 live Codex/Claude
Code login、真实 vendor approval、P4 RemoteLink 或 Companion E2E。

## Relay Companion MVP P3.9-C0-B4 managed metadata 门禁

**具体威胁场景：** rename/archive 若分别更新 descriptor、lifecycle、entry revision、catalog revision 与
CatalogDelta，崩溃或并发 writer 会暴露跨层撕裂；若 idempotency 只看 key、不认证完整 request/outcome，
重试可能覆盖另一意图；若容量只估 ledger row，近上限 descriptor 与 CatalogDelta 可能在 COMMIT 后突破
保留尾。B4 要求 managed mutation 在一个 authenticated transaction 内收敛，conversation event 恒为零，
并在 open/recovery 对 ledger、row MAC、AEAD、totals、CatalogDelta 与 conversation state 做完整审计。

```bash
# B4 focused Store/Core/Catalog/integrity/capacity matrix
cargo test -p agentdeckd --test runtime_metadata_mutation -- --test-threads=1
cargo test -p agentdeckd --test runtime_metadata_integrity -- --test-threads=1
cargo test -p agentdeckd --test runtime_metadata_capacity -- --test-threads=1
cargo test -p agentdeckd --lib runtime::store::metadata::tests:: -- --test-threads=1
cargo test -p agentdeckd --lib \
  runtime::store::sqlite::tests::active_metadata_projection_reserves_the_complete_terminal_write_set \
  -- --test-threads=1
cargo test -p agentdeckd --lib \
  runtime::core::tests::metadata_update_returns_applied_replayed_conflict_and_typed_failures \
  -- --test-threads=1
cargo test -p agentdeckd --lib \
  runtime::core::tests::subscription_tests::metadata_applied_emits_one_exact_catalog_delta_and_no_conversation_event \
  -- --test-threads=1

# Task 收口完整 package / 跨语言 / 自检
cargo test -p agentdeckd
cargo test -p agentdeck-protocol -- --test-threads=1
swift test
cargo run -q -p agentdeck-cli -- protocol schema \
  | diff - protocol/agentdeck/agentdeck-protocol.schema.json
swift run AgentDeck -- --selfcheck

# 静态、network 与文档
cargo clippy -p agentdeckd --all-targets -- -D warnings
cargo clippy -p agentdeck-protocol --lib -- -D warnings
cargo fmt --all -- --check
bash scripts/check-daemon-network-boundary.sh
bash scripts/check-daemon-no-net.sh
scripts/verify-agent-docs.sh
git diff --check
git status --short --branch
```

实现证据：`5f1ca1c` 落地 managed rename/archive/unarchive、durable Conflict、exact replay、同事务
entry/catalog revision + CatalogDelta、authenticated ledger 与完整容量投影；`347a0f0` 只对齐完整
pre-RW 审计更早返回的密文错误分类。production additions 合计 1,983，低于 2,000 硬线；测试和文档
不计入刹车线。

**Task gate 已确认读回（2026-07-18）：** metadata mutation `5/5`、离线篡改矩阵 `10/10`、capacity
`2/2`、metadata unit `2/2`、terminal reserve `1/1`、Core receipt `1/1`、subscription/Catalog `1/1`；
完整 daemon package `1172 passed / 6 ignored`，lib `696 passed / 1 ignored`，1,024 × 256 KiB target
`5/5`（276.71 秒）；protocol `170/170`；Swift XCTest `298/298` + Swift Testing `35/35`；schema、
selfcheck、Clippy、fmt、network/no-net、docs 与 diff 全绿。双路独立终审无 P0/P1/P2。

B4 收口时只允许 managed mutation，`nativeProjected` 当时返回 typed feature-unavailable 且零 claim；
后续 C0-C 的当前边界见本页 C0-C Task 门禁：安全 substrate 已实现，production 请求改为更精确的
`daemon.conversation.metadata_unsupported` pre-claim gate。
同 UID 在线攻击仍是 accepted residual risk，不为 B4 添加竞态测试或 hook；整库历史回滚仍由 P4
CounterGuard 检测。

## Relay Companion MVP P3.9-C0-B5 cross-layer closeout 门禁

**具体威胁场景：** configuration 与 managed metadata 虽各自在 Store 内原子提交，但若真实 UDS/Core
路径把 installation owner、authorization guard、after-COMMIT outcome、通知或 frozen cursor 接错，两个
principal 并发写时仍可能出现错误 replay、revision 轴串线、重复 CatalogDelta，或重启后 receipt、Catalog、
conversation snapshot 与 backfill 互相矛盾。B5 用纯测试增量验证既有 production 路径的跨层收敛，不新增
writer，也不把 native projection 或同 UID 在线竞态纳入范围。

```bash
# B5 真实 UDS、authorization 与 after-COMMIT focused gate
cargo test -p agentdeckd --test runtime_configuration_metadata_cross_layer -- --test-threads=1
cargo test -p agentdeckd --lib \
  runtime::core::tests::metadata_authorization_guard_covers_store_commit_and_reply \
  -- --test-threads=1
cargo test -p agentdeckd --lib \
  runtime::core::tests::canceled_metadata_caller_keeps_authorization_until_store_completion \
  -- --test-threads=1
cargo test -p agentdeckd --lib \
  runtime::core::tests::subscription_tests::metadata_after_commit_unknown_notifies_once_and_exact_retry_replays \
  -- --test-threads=1

# Task 收口完整 package / 跨语言 / Simulator / 自检
cargo test -p agentdeckd -- --test-threads=1
cargo test -p agentdeck-protocol -- --test-threads=1
swift test
cd ios && xcodegen generate && \
  xcodebuild -project AgentDeckMobile.xcodeproj -scheme AgentDeckMobile \
    -destination 'platform=iOS Simulator,name=iPhone 17' test
cargo run -q -p agentdeck-cli -- protocol schema \
  | diff - protocol/agentdeck/agentdeck-protocol.schema.json
swift run AgentDeck -- --selfcheck

# 静态、network 与文档
cargo clippy -p agentdeckd --all-targets -- -D warnings
cargo clippy -p agentdeck-protocol --lib -- -D warnings
cargo fmt --all -- --check
bash scripts/check-daemon-network-boundary.sh
bash scripts/check-daemon-no-net.sh
scripts/verify-agent-docs.sh
git diff --check
git status --short --branch
```

实现证据：`aebc8d0` 只增加 1,283 行测试，production additions 为 0。真实 UDS 使用两个稳定
installation identity 建立两个 authenticated principal，覆盖并发 Configure/Rename、same-owner exact
replay 与 cross-owner same-key 独立语义、conflict、receipt、configuration event、CatalogDelta、snapshot、
backfill，以及 shutdown/reopen 后的相同读回。Core fault tests 使用显式进入/释放同步点，不以 50 ms sleep
推断调度；revoke/caller cancellation 的 join 均有界。

**Task gate 已确认读回（2026-07-18）：** 跨层主测试及 metadata authorization、caller cancellation、
after-COMMIT unknown 三条专项分别稳定重复 `20/20`；完整 daemon package `1176 passed / 6 ignored`，lib
`699 passed / 1 ignored`，1,024 × 256 KiB target `5/5`（280.10 秒）；protocol `170/170`；Swift
XCTest `298/298` + Swift Testing `35/35`；iOS Simulator `20/20` 且 `TEST SUCCEEDED`；schema、
selfcheck、daemon/protocol Clippy、fmt、network/no-net、docs 与 diff 全绿。独立 spec/security 与 quality
终审均 Approved、无 P0/P1/P2。6 个 ignored 继续是显式 gated/manual 槽位，其中 provisioned signed
Keychain 是 post-MVP BLOCKED，不计 PASS，也不阻塞自动主线。

B5 证明 configuration/event 与 metadata/catalog 两条 revision 轴在现有 managed Runtime 路径上独立且
最终一致；不证明 C0-C native importer/dynamic snapshot/native side effect、P4 CounterGuard/RemoteLink，
也不证明真实 vendor login 或 Companion E2E。

## Relay Companion MVP P3.9-C0-C native projection Task 门禁

**具体威胁场景：** 原生 JSONL 若按路径字符串或内部 session ID 猜 identity，会暴露 raw vendor handle、
重复导入或错误续接；若 incomplete generation、Store hard cap 或 busy actor 也 ACK candidate/执行 Removed，
会永久丢失投影；若 Snapshot 复制正文进 SQLite，会产生第二权威源。native metadata 若绕过 Runtime claim、
effect fence 或 current-binary gate，还可能在未持久化授权时调用 vendor。C0-C 要求 secure source、原子
projection、completed witness、dynamic-only Snapshot 与 authenticated side-effect substrate 分层闭环。

```bash
# secure source、projection lifecycle、dynamic snapshot/history-only
cargo test -p agentdeckd --lib claude_code::history::native_tests:: -- --test-threads=1
cargo test -p agentdeckd --lib runtime::store::native_projection_lifecycle_tests:: -- --test-threads=1
cargo test -p agentdeckd --lib runtime::core::tests::subscription_tests::dynamic_native:: -- --test-threads=1
cargo test -p agentdeckd --lib runtime::native_projector::tests:: -- --test-threads=1

# native metadata Store/fence/coordinator 与 typed spawn boundary
cargo test -p agentdeckd --lib \
  runtime::store::metadata::runtime_native_metadata_mutation_tests:: -- --test-threads=1
cargo test -p agentdeckd --lib runtime::store::native_metadata_effect_tests:: -- --test-threads=1
cargo test -p agentdeckd --lib runtime::native_metadata::tests:: -- --test-threads=1
cargo test -p agentdeckd --test typed_spawn_ownership -- --test-threads=1
cargo test -p agentdeckd --test adapter_state_boundary -- --test-threads=1
cargo test -p agentdeckd --test router_both_agents -- --test-threads=1

# 真实当前 OS account JSONL 只读 smoke；标准全包因 #[ignore] 不会执行本项
AGENTDECK_E2E=1 cargo test -p agentdeckd --lib \
  'runtime::core::tests::subscription_tests::dynamic_native::real_current_account_jsonl_projects_through_catalog_and_dynamic_snapshot' \
  -- --exact --ignored --nocapture --test-threads=1

# Task 收口完整 package / 跨语言 / Simulator / 自检
cargo test -p agentdeckd
cargo test -p agentdeck-protocol -- --test-threads=1
swift test
(cd ios && xcodegen generate && \
  xcodebuild -project AgentDeckMobile.xcodeproj -scheme AgentDeckMobile \
    -destination 'platform=iOS Simulator,name=iPhone 17' test)
cargo run -q -p agentdeck-cli -- selfcheck

# 静态、network 与文档
cargo clippy -p agentdeckd --all-targets -- -D warnings
cargo fmt --all -- --check
bash scripts/check-daemon-network-boundary.sh
bash scripts/check-daemon-no-net.sh
scripts/verify-agent-docs.sh
git diff --check
git status --short --branch
```

**Task 完成证据（2026-07-19，code/test `5355497`）：** CC native history `42/42`、projector `13/13`、
native projection Store `11/11`、native metadata Store `6/6`、typed spawn ownership `9/9`、
adapter-state boundary `3/3`；production post-MVP gate 与 harmless current-binary synthetic coordinator
roundtrip 均有独立行为测试。真实当前账号 JSONL 的只读 list→import→Catalog→dynamic Snapshot smoke 已
PASS 且重复 `10/10`；dynamic focused `6 passed / 1 ignored`。final-tree daemon 全包 exit 0，lib
`885 passed / 3 ignored`（635.39 秒）、256 MiB boundary `5/5`（285.59 秒），全部 integration/doc tests
通过；protocol 全包、Swift `298 XCTest + 35 Swift Testing`、iOS Simulator `20/20`、schema sync、App
selfcheck、diagnostics、Clippy/fmt/network/no-net/docs/diff 均 PASS。spec/security 与 quality 双路终审
Approved、无 P0/P1/P2。

Store hard cap 必须返回 typed diagnostic、保留当前 candidate pending 且零 ACK，并进入固定 30 秒 refresh；
source unavailable、坏或 incomplete generation、read failure 都走相同 refresh 级退避，不能形成 250 ms 热
循环。MVP production native Rename 在 claim 前返回 `daemon.conversation.metadata_unsupported`，ledger 与
effect fence 保持零；synthetic current-binary gate 只证明 claim→fence→release→reap→readback substrate，
不得写成真实 Claude binary mutation PASS。legacy CC Rename/Archive/Unarchive 统一要求 Runtime gate。

## Relay Companion MVP P3.9-A Rust shared-daemon client Task 门禁

P3.9-A 只交付 Rust client component，不切换 `agentdeck` binary 默认入口；该切换和双客户端真实 smoke
属于 P3.9-D。production component 必须从当前 EUID 的 passwd home 派生 installation record 与 canonical
socket，拒绝 symlink/hardlink/owner/mode/corrupt，不读 `HOME`，也不包含 daemon spawn/fallback。Hello、
exact messageId、reply/stream/transfer 与 close-only 都必须有界且 typed fail-close。

```bash
export CARGO_TARGET_DIR="$(mktemp -d /tmp/agentdeck-p39a-target.XXXXXX)"
env -u AGENTDECK_E2E cargo test -p agentdeck-cli -- --test-threads=1
cargo clippy -p agentdeck-cli --lib --bin agentdeck --test shared_daemon --no-deps -- -D warnings
cargo fmt --all -- --check
git diff --check -- Cargo.lock agentdeck-cli
```

**Task 完成证据（2026-07-19，`c29faa4`）：** fresh target CLI 全包 `103/103`、lib `12/12`、
shared-daemon `27/27`，全部 0 failure；上述 scoped Clippy、fmt 与 diff check 通过。字面
`cargo clippy -p agentdeck-cli --all-targets -- -D warnings` 被未修改的 Relay 三项 lint 阻断，添加
`--no-deps` 后仍会命中既有 `protocol_schema_exports` / `e2e_*` doc/collapsible-if lint，因此两条字面命令
均未计 PASS，也未扩 scope 顺手改动。installation 与 Unix transport production 子片分别少于 570 / 1,402
additions，低于 1,800 预拆线；spec/security 与 quality 双路终审 Approved、无 P0/P1/P2。

## Relay Companion MVP P3.9-B Swift shared-daemon client Task 门禁

P3.9-B 只交付 Swift client component，不把 production App model/composition 切到该 client；model cutover
与默认入口/双客户端真实 smoke 分别属于 P3.9-C3/D。installation 必须只从 current EUID 的 passwd home
派生，UDS 必须 strict preface + `<1 MiB` framing，actor client 的 reply/stream/transfer 必须同时受 count、
retained bytes 与 TTL 约束；close/deinit 只能关闭当前 fd，不能停止 daemon。

```bash
swift test --filter 'AgentDeckTests\.(LocalClientInstallationTests|UnixSocketDaemonTransportTests|RuntimeEnvelopeClientTests|RuntimeV2WireCodecTests)'
swift test
swift build
swift format lint --strict \
  Sources/AgentDeck/LocalClientInstallation.swift \
  Sources/AgentDeck/UnixSocketDaemonTransport.swift \
  Sources/AgentDeck/RuntimeEnvelopeClient.swift \
  Tests/AgentDeckTests/LocalClientInstallationTests.swift \
  Tests/AgentDeckTests/UnixSocketDaemonTransportTests.swift \
  Tests/AgentDeckTests/RuntimeEnvelopeClientTests.swift
swift build -Xswiftc -warnings-as-errors
scripts/verify-agent-docs.sh
git diff --check
```

**Task 完成证据（2026-07-19，`397ef9d` / `94adf92` / `913a156` / `deb0e1b`）：** focused
installation `7/7`、transport `15/15`、client `24/24`、current codec `7/7`，合计 `53/53`；完整
Swift `344 XCTest + 35 Swift Testing`、普通 build、strict format 与 diff check 均 PASS。quality 首轮终审
发现普通 event/catalogDelta 固定按 1 byte 计费的 P2；新增两帧编码总字节减 1 的 RED test 后，修复为按
transport 实收 frame bytes 计费，复审 Approved。spec/security 与 quality 最终均无剩余 P0/P1/P2/P3。
production additions 424 / 810 / 1,583，均低于 1,800 预拆线。

字面 `swift build -Xswiftc -warnings-as-errors` **未通过、不得记为 PASS**：唯一阻断是未修改的
`Sources/AgentDeck/Preview/MockDaemonTransport.swift:93` 非 Sendable capture 既有 warning；P3.9-B 三个
production 文件没有新增 warning。该 baseline 不扩入 B 的 component scope；后续已由 P3.9-C3 的不可变
handler snapshot 收口，并在 P3.9-C3 及后续相关 Task 门禁读回 warnings-as-errors build。独立 P3 Phase
verifier 运行 `swift test`，没有重复执行这条字面 build 命令。

## Relay Companion MVP P3.9-C3 App model cutover Task 门禁

P3.9-C3 把普通 macOS GUI 的 `SessionModel`、`WorkbenchModel` 与 `ThreadRuntimeModel` 切到 Runtime v2
canonical conversation/event/item/entity/command identity，并由惰性的 OS-account shared UDS wire 组合
production App。构造 model/view 不打开 installation、不连接 socket、也不 spawn daemon；首次 Runtime 操作
才解析 current-EUID installation 与 canonical socket。socket 缺失、不安全、连接或协议失败必须保留
`daemon.client.*` typed failure，**不得 fallback** `ProcessDaemonTransport`、legacy stdio 或新 daemon 子进程。
Rust CLI binary 默认入口与 `Sources/AgentDeck/main.swift --selfcheck` 当时属于 P3.9-D，不计入本 Task；
后续已由 `b818f81` 完成。

```bash
swift test --filter 'AgentDeckTests\.(AppRuntimeCoordinatorTests|ThreadRuntimeModelCanonicalTests|WorkbenchRuntimeV2Tests|SessionModelRuntimeReliabilityTests|PreviewBootstrapTests)'
swift test
swift build
swift build -Xswiftc -warnings-as-errors
git show --format= --name-only b4e9565 -- '*.swift' | xargs swift format lint --strict
cd ios && xcodegen generate && \
  xcodebuild -project AgentDeckMobile.xcodeproj -scheme AgentDeckMobile \
    -destination 'platform=iOS Simulator,name=iPhone 17' test
cd ..
scripts/verify-agent-docs.sh
git diff --check
```

**Task 完成证据（2026-07-19，`b4e9565`）：** focused 五组 `46/46`；完整 Swift
`435 XCTest + 35 Swift Testing`；普通 build 与 `-warnings-as-errors` build；iOS Simulator `20/20`；
production source purge、changed-source strict format、docs 与 diff check 均 PASS。spec/security 与 quality
两路独立终审无 P0/P1/P2。终审期间另外以 RED→GREEN 收口四项跨层竞态：

- 同步归约接受 daemon 的合法 `Snapshot → Backfill* → SyncComplete`，仍拒绝
  `Backfill → Snapshot`、重复 Snapshot、cursor gap 与半发布；
- prompt receipt 为 `Replayed` 时，只有同 conversation 的 exact canonical terminal command 匹配才恢复
  `ready` 并继续队列；`Accepted`、不同 command 或 active turn 不得借此提前完成；
- 显式 `--preview` fixture 生成同 command/turn、连续 event sequence 的
  `TurnStarted → User → Assistant → TurnCompleted` synthetic stream，不再让 preview prompt 永久停在
  `starting`；该 synthetic identity 不进入 production composition；
- `SyncComplete` 后 live stream 可在 `completeConversationStart` 返回前推进 cursor；收口接受
  runtime cursor 等于或晚于 terminal，仍拒绝落后 cursor，并依赖 canonical reducer 保证 exact-next。

### P3.9-D canonical CLI 与组合 smoke Task 门禁

P3.9-D 由 `b818f81` 完成。Rust binary 默认 dispatcher 与 App `main.swift --selfcheck` 都连接 stable
shared UDS；用户可见主身份统一为 `conversationId`，旧 `threadId/sessionId` 和无法无损映射的 vendor option
在连接前 typed reject。`session run` 固定执行
`DescribeAgents → Start → Configure(rev0) → Subscribe → SendPrompt(rev1)`；prompt retry 始终重发 exact
`SendPrompt`，让 daemon 返回 `Replayed` 或 payload conflict，不能用 `QueryReceipt` preflight 绕过哈希裁决。
完整 reply sequence 使用单一 30 秒 absolute deadline，中间帧不续期。

```bash
cargo test -p agentdeck-cli --locked
cargo test -p agentdeckd -- --test-threads=1
swift test
swift build
swift build -Xswiftc -warnings-as-errors
swift format lint --strict \
  Sources/AgentDeck/main.swift \
  Sources/AgentDeck/RuntimeSelfcheckRunner.swift \
  Sources/AgentDeck/RuntimeSmokeRunner.swift \
  Tests/AgentDeckTests/RuntimeSelfcheckRunnerTests.swift \
  Tests/AgentDeckTests/RuntimeSmokeRunnerTests.swift
cd ios && xcodegen generate && \
  xcodebuild -project AgentDeckMobile.xcodeproj -scheme AgentDeckMobile \
    -destination 'platform=iOS Simulator,name=iPhone 17' test
cd ..
bash scripts/run-local-runtime-smoke.sh
cargo test -p agentdeckd --lib \
  local::listener::tests::production_backpressure_and_bad_clients_preserve_sibling_active_turn \
  -- --exact --test-threads=1
cargo test -p agentdeckd --test local_uds \
  real_uds_two_connections_handshake_and_disconnect_isolation -- --exact --test-threads=1
cargo test -p agentdeck-cli --test shared_daemon \
  close_only_does_not_send_daemon_shutdown_or_prevent_a_second_client -- --exact
cargo clippy -p agentdeck-cli --lib --bin agentdeck \
  --test shared_daemon --test runtime_cli_binary --no-deps -- -D warnings
cargo run -q -p agentdeck-cli -- protocol schema \
  | diff - protocol/agentdeck/agentdeck-protocol.schema.json
cargo run -q -p agentdeck-cli -- protocol runtime-schema \
  | diff - protocol/agentdeck/runtime-protocol.schema.json
cargo run -q -p agentdeck-cli -- protocol relay-schema \
  | diff - protocol/agentdeck/relay-v2.schema.json
cargo run -q -p agentdeck-cli -- protocol e2ee-schema \
  | diff - protocol/agentdeck/e2ee-v1.schema.json
cargo fmt --all --check
bash scripts/check-daemon-network-boundary.sh
scripts/verify-agent-docs.sh
git diff --check
```

Release binary 还必须证明 DEBUG endpoint/smoke seam 不可达，且完整隐藏 flag 字面量没有进入产物：

```bash
set -euo pipefail
cargo build -p agentdeck-cli --release --locked
swift build -c release --product AgentDeck
rust_release=target/release/agentdeck
swift_release="$(swift build -c release --show-bin-path)/AgentDeck"

assert_rust_release_rejects() {
  if output="$("$rust_release" "$@" 2>&1)"; then return 1; else result=$?; fi
  test "$result" -eq 2 && printf '%s' "$output" | rg -q 'unexpected argument|unrecognized subcommand'
}
assert_swift_release_rejects() {
  if output="$("$swift_release" "$@" 2>&1)"; then return 1; else result=$?; fi
  test "$result" -eq 2 && printf '%s' "$output" | rg -q 'daemon.client.test_only_argument_rejected'
}
assert_rust_release_rejects --runtime-temp-root-for-test /tmp ping
assert_rust_release_rejects --runtime-temp-root-for-test=/tmp ping
assert_rust_release_rejects runtime-smoke-for-test installation
assert_swift_release_rejects --selfcheck --runtime-temp-root-for-test /tmp
assert_swift_release_rejects --selfcheck --runtime-temp-root-for-test=/tmp
assert_swift_release_rejects --runtime-smoke-for-test installation --runtime-temp-root-for-test /tmp
assert_swift_release_rejects --runtime-smoke-for-test=installation --runtime-temp-root-for-test=/tmp
for binary in "$rust_release" "$swift_release"; do
  ! strings "$binary" | rg -F -- '--runtime-temp-root-for-test'
  ! strings "$binary" | rg -F -- 'runtime-smoke-for-test'
done
```

**Task 完成证据（2026-07-19，`b818f81`）：** Runtime CLI binary `12/12`、shared-daemon `27/27`、
CLI package exit 0；daemon lib `885 passed / 3 ignored`、完整 package exit 0，1,024 × 256 KiB 容量 target
`5/5`（285.43 秒）；Swift `458 XCTest + 35 Swift Testing`、普通与 warnings-as-errors build、iOS Simulator
`20/20` 全绿。真实 smoke 证明 Rust/Swift 两个稳定且不同的 installation 各自提交、查询、exact replay，
cross-owner commandId 查询拒绝、共同 Backfill 收敛、daemon PID 不变与 endpoint 缺失零 fallback；active-turn、
双 UDS connection 与 close-only 三项组合证据各 `1/1`。Rust/Swift release 隐藏测试入口动态拒绝及 strings
扫描、四份 schema、network/docs/fmt/diff 均通过；spec/security 与 quality 双路终审无 P0/P1/P2。

首次与 Swift/iOS 重负载并行的 daemon 全包中，exec-gate handshake-abort 用例单次失败；隔离重复 `10/10`
通过，无并行重负载的完整 daemon package 随后最终 exit 0，只有后者计为 Task PASS。P3.1 provisioned signed
Keychain 继续是 post-MVP ignored/BLOCKED；真实 vendor login 不在 D 的 synthetic transport 证据内。

### P3.9-E App retry/reconnect/subscription Task 门禁

P3.9-E 由 `d68cc02` 完成。门禁覆盖 Start/Configure/Prompt 的 exact/fresh retry 分类、logical composer
owner 与有界 draft LRU、history latest-intent 单 drain、stream close barrier、重连有界恢复，以及 catalog +
conversation 共用 64-slot LRU/FIFO admission。真实 AF_UNIX EOF 用两个独立 peer 证明旧 wire 收到 EOF 后
不会热重连，下一次用户操作才使用新 wire。

```bash
swift test --filter AppRuntimeCoordinatorTests
swift test --filter ComposerInteractionTests
swift test --filter LocalRuntimeWireSessionTests
swift test --filter SessionModelRuntimeReliabilityTests
swift test --filter SessionViewControllerSmokeTests
swift test --filter ThreadRuntimeModelCanonicalTests
swift test --filter EndToEndWindowAssemblyTests
swift test --filter NewSessionDialogEncodingTests
swift test --filter PreviewBootstrapTests
swift test --filter WorkbenchRuntimeV2Tests
swift test
swift build
swift build -Xswiftc -warnings-as-errors
cd ios && xcodegen generate && \
  xcodebuild -project AgentDeckMobile.xcodeproj -scheme AgentDeckMobile \
    -destination 'platform=iOS Simulator,name=iPhone 17' test
cd ..
bash scripts/run-local-runtime-smoke.sh
cargo run -q -p agentdeck-cli -- protocol schema \
  | diff - protocol/agentdeck/agentdeck-protocol.schema.json
cargo run -q -p agentdeck-cli -- protocol runtime-schema \
  | diff - protocol/agentdeck/runtime-protocol.schema.json
cargo run -q -p agentdeck-cli -- protocol relay-schema \
  | diff - protocol/agentdeck/relay-v2.schema.json
cargo run -q -p agentdeck-cli -- protocol e2ee-schema \
  | diff - protocol/agentdeck/e2ee-v1.schema.json
bash scripts/check-daemon-network-boundary.sh
scripts/verify-agent-docs.sh
git diff --check
```

冻结提交的 changed-source strict/baseline-parity 可机械复算；candidate 不得比 base 增加 diagnostics：

```bash
base=d68cc02^
candidate=d68cc02
for file in $(git diff --name-only --diff-filter=ACMR "$base" "$candidate" -- '*.swift'); do
  before=$(git show "$base:$file" \
    | swift format lint --strict --assume-filename "$file" - 2>&1 \
    | awk '/: error:/{n++} END{print n+0}')
  after=$(git show "$candidate:$file" \
    | swift format lint --strict --assume-filename "$file" - 2>&1 \
    | awk '/: error:/{n++} END{print n+0}')
  test "$after" -le "$before" || exit 1
done
```

**Task 完成证据（2026-07-19，`d68cc02`）：** focused 主组合 `108/108`，其余 touched suites
`40/40`；subscription admission 与真实 UDS EOF 各重复 `10/10`。完整 Swift
`527 XCTest + 35 Swift Testing`、普通/warnings-as-errors build、iOS Simulator `20/20`、真实
local-runtime smoke、四 schema、network/docs/diff 全绿。changed-source strict gate 中 15 个
baseline-clean 文件保持 `0→0`；4 个 legacy 文件 diagnostics 分别从 `596→592`、`295→268`、
`317→308`、`83→82`，按“零新增且总债务下降”的 baseline parity 记 PASS，不把 legacy 全文件表述为
strict clean。spec/security 与 quality 双路终审在冻结 diff SHA-256
`66c4151af524caae6373571fcc0dd72b1d2c8789b5d7ffe64d05def416edbf6a` 上 Approved，无 P0/P1/P2。
P3.1 provisioned signed Keychain 与真实 vendor login 继续 post-MVP BLOCKED；P3.9 complete，P3.10 已由
`19622ab` 完成 Task 门禁与双路终审，独立 P3 Phase Exit 也已在 `9efb28d` 上收口。

### P3.10 Task gate 与 P3 Phase Exit（PASS）

`19622ab` 已新增 P3.10 当时的 current schema v7 authenticated machine-wide `admin_commands` ledger，覆盖 30 天
retention、容量准入、exact replay/conflict、COMMIT-unknown 与 open/recovery 审计；`StageUpgrade` 的
switch/exit 许可绑定到 local writer 的 exact reply flush ACK。partial write、flush failure、cancel 或 ACK 前
disconnect 都必须保持 `bin/current`、PID 与 launchd state 不变；ACK 后 client close 不得撤销已提交动作。
active→idle fence、候选 artifact/hash/owner/mode/nlink、原子 current 切换与 install/status/uninstall lifecycle
均有 focused/ephemeral smoke 证据；stopped `loaded=true,pid=null` job 会 kickstart 并二次读回 live PID，CLI
只对 `socket_missing` / `connect_failed` 做有界 15 秒 retry。P3.10 当时的 `--purge` 在 P4.2 接线前 typed
fail-close 且零删除；当前已由 P4.2 authenticated trust-reset/finalizer 替换。同 UID 在线换路径测试已删除，
后续不得为 accepted residual risk 新增测试。

子片/focused 检查可使用：

```bash
cargo test -p agentdeckd --locked --test runtime_store_admin_upgrade -- --test-threads=1
cargo test -p agentdeckd --locked --test upgrade_idle -- --test-threads=1
cargo test -p agentdeckd --locked --lib runtime::upgrade::tests -- --test-threads=1
cargo test -p agentdeck-cli --locked daemon:: --lib
cargo test -p agentdeck-cli --locked --bin agentdeck daemon_cli_tests
cargo test -p agentdeck-cli --locked --test daemon_install -- --test-threads=1
bash scripts/verify-daemon-install.sh automatic
cargo clippy -p agentdeckd -p agentdeck-cli --all-targets -- -D warnings
cargo fmt --all -- --check
```

**Task 收口证据（2026-07-20，code/test `19622ab`）：** 冻结 candidate 的完整聚合门禁已 exit 0：
两轮 1,024 × 256 KiB capacity 为 286.88s / 286.64s，daemon lib 两轮均
`904 passed / 3 ignored`；Swift `527 XCTest + 35 Swift Testing`，iOS Simulator `20/20`。CLI focused 为
lib/bin/integration `13/13 + 8/8 + 2/2`；local-runtime/install harness、exact signed BLOCKED contract、
四 schema、network/docs/diff 全绿，temp root/残留进程均为 0。`spec/security` 与 `quality` 两路 Task review
均 Approved、无 P0/P1/P2。

**Phase review hardening（code baseline `9efb28d`）：** `773a2b3` 为安装 verifier 增加资源上界，
`0057824` 统一 v1–v6 legacy store 在原库 RW 前的 ledger/既有行全量认证，并新增显式 v1–v4
committed-WAL 篡改矩阵；`81cc314` 回收
verifier 同 PGID 子孙，`9efb28d` 通过保留 leader wait identity 与连续静默扫描稳定收口进程组。
verifier 使用 10 秒绝对 deadline、stdout+stderr 合计 256 KiB 上限；超时/同组无法按期静默与输出超限
分别映射为 `daemon.install.verifier_timeout`、`daemon.install.verifier_output_too_large`，两类失败都不得
发布候选或切换 `bin/current`。

**P3 Phase Exit 证据（2026-07-20，code baseline `9efb28d`）：** 在 Task 文档状态冻结后独立运行：

```bash
bash scripts/verify-relay-companion-mvp.sh p3
```

最终 exit 0。daemon lib 两轮均为 `905 passed / 3 ignored`，耗时 218.23s / 154.45s；1,024 ×
256 KiB capacity boundary 两轮均为 `5/5`，耗时 284.97s / 286.07s；Swift 为
`527 XCTest + 35 Swift Testing`，iOS Simulator 为 `20/20`。四份 schema、network boundary、docs、
`scripts/run-local-runtime-smoke.sh`、daemon install hermetic harness 与 diagnostics report 全绿；
`spec/security`、`quality` 双路 code review 均为 P0/P1/P2 = 0。

production-signed LaunchAgent/Keychain roundtrip 继续精确输出 post-MVP
`BLOCKED/mutations=0/evidence=[]/summaryGenerated=false`。该 exact BLOCKED contract 是 verifier 的必过
自动项；整体 exit 0 只表示契约与 automatic scope 通过，不表示 production signing PASS。P3.1 继续采用
方案 b，stable production signing 仍未完成。P3 Phase 至此 complete（MVP automatic scope）。P4.1–P4.5
已按下节 automatic Task gate 收口；P4.6 persistent remote CLI 已完成 automatic Task，
P4.7 automatic Task 与 P4 automatic Phase Exit 也已完成，P4 按 Task 进度为 7/7。P4.5 已在
P4.4 的唯一 business ingress/Core dispatch 上安装 production directed sealer、shared publisher、
crash-safe CounterGuard/outbox/replay recovery；这段仍只描述 P4.5 Task PASS，P4 Phase PASS 由后续
P4.7 的独立门禁与双路 review 证明。

## Relay Companion MVP P4.1 machine identity / Keychain guard Task gate（PASS）

P4.1 由六个 code/test commit 收口：`3cd76d2` 建立四组 machine key material、key-directory guard 与
通用 CounterGuard IO；`644712c` 建立 authenticated machine identity Store state，并把 current Runtime
schema 从 v7 升到 **v8 / 24 张表**；`95090c1` 强化 Keychain exact readback、canonical scope 与删除门禁；
`85df3d2` 接入 Preparing→Active bootstrap、三态 outcome 与 startup composition；`f137112` 收紧
rollback/fork、store fatal、key owner 与 remote-start permit 生命周期；`46c6bb8` 同步最终 daemon startup
生命周期 oracle。v8 只新增 `machine_identity_state` 与 `runtime_meta.machine_identity_count`，ledger domain
升级到 v8；既有 crypto context/key generation 仍为 v1，v7→v8 migration 保持既有 wrapped key、ciphertext、
row token 与 rescue receipt 逐字节不变。

内部子片使用以下 focused gate；完整慢门禁与双路终审只在 P4.1 Task 收口运行一次：

```bash
cargo test -p agentdeckd --test machine_identity_bootstrap -- --test-threads=1
cargo test -p agentdeckd --test machine_identity_keys -- --test-threads=1
cargo test -p agentdeckd --test runtime_store_machine_identity -- --test-threads=1
cargo test -p agentdeckd --lib remote::bootstrap::tests::root_key_id -- --test-threads=1
cargo test -p agentdeckd --lib \
  runtime::store::sqlite::migration_tests::populated_v7_migrates_to_v8_with_byte_exact_existing_authenticated_rows \
  -- --exact --test-threads=1
```

**Task 收口证据（2026-07-20，code baseline `46c6bb8`）：** bootstrap `18/18`、machine keys
`11/11`、machine identity Store `11/11`、RootKeyId entropy/全零拒绝 `2/2`、populated v7→v8 exact
migration `1/1`。完整 `cargo test -p agentdeckd` exit 0，其中 daemon lib 为
`916 passed / 3 ignored`；1,024 × 256 KiB capacity 慢门禁 exit 0，耗时 284.28 秒。dev/ephemeral
selfcheck、diagnostics、daemon network boundary、schema/manifest、secret/log/static sentinel、scoped
Clippy、fmt、diff/status 等快速门禁均绿；`spec/security` 与 `quality` 两路独立终审均 Approved，
P0/P1/P2 = 0。

本 Task 的通过边界严格为：四组长期 key 与 public fingerprint、authenticated
`machine_identity_state`、key-directory guard、通用 CounterGuard IO，以及 active identity 与一次性
`RemoteStartPermit` 的 owner/lifetime。CounterGuard 尚未创建 active symmetric key reservation，也未接入
whole-database rollback 检测。`RemoteBootstrapOutcome::Blocked` 只阻断 remote，本地 Runtime recovery/UDS
继续；Runtime Store open/worker/SQLite failure 或 StorageKEK failure 仍是全局 fatal。P4.1 production source
保持零 Link/Data cert、零 enrollment workflow/code、零 `machine_enrollment_receipts` IO、零 RemoteLink；这些
首次归 P4.2。P3.1 provisioned production-signed Keychain roundtrip 继续是 post-MVP
`BLOCKED/mutations=0/evidence=[]/summaryGenerated=false`，不计 PASS，也不阻塞 P4.2 automatic 主线。

## Relay Companion MVP P4.2 certificate / enrollment / control-only RemoteTransport / trust reset Task gate（PASS）

P4.2 code/test 由 `a6842bc` 收口。该 Task 把 Runtime protocol additive 升为 v3，physical schema
从 v8/24 表升级到 **v9 / 25 张表**；新增 authenticated `machine_remote_state` singleton、root-signed
MachineLinkSign/MachineDataSign cert、durable enrollment/receipt、same-UID local-only machine admin、
control-only RemoteTransport、root-present/root-lost trust reset 与 authenticated purge marker/finalizer。

内部子片只运行 focused tests + scoped Clippy/fmt；Task 收口复跑以下矩阵：

```bash
cargo test -p agentdeckd --locked --lib remote::manager::tests -- --test-threads=1
cargo test -p agentdeckd --locked --lib remote::trust_reset::tests -- --test-threads=1
cargo test -p agentdeckd --locked --lib purge_finalizer::tests -- --test-threads=1
cargo test -p agentdeckd --locked --lib remote::transport::tests -- --test-threads=1
cargo test -p agentdeckd --locked \
  --test machine_certificates --test machine_enrollment \
  --test machine_local_deleted --test machine_transport \
  --test machine_trust_reset -- --test-threads=1
cargo test -p agentdeck-cli --locked daemon::purge::tests --lib
cargo test -p agentdeck-cli --locked daemon::launchd::tests --lib

# Task 级完整 package / 跨语言门禁
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

# schema、network 与静态边界
cargo run -q -p agentdeck-cli -- protocol runtime-schema \
  | diff - protocol/agentdeck/runtime-protocol.schema.json
bash scripts/check-daemon-network-boundary.sh
cargo clippy -p agentdeckd --all-targets -- -D warnings
cargo clippy -p agentdeck-cli --lib -- -D warnings
cargo fmt --all -- --check
git diff --check
```

**Task 收口证据（2026-07-20，code/test `a6842bc`，冻结候选 SHA-256 `1597092e21b4f0a8a8763822598aec651dcc4a5ed6248f28bf2ba100dc92c704`）：** manager `23/23`、trust reset
workflow `9/9`、purge finalizer
`27/27`、CLI purge `20/20`、launchd `11/11`、RemoteTransport `12/12`、certificate/enrollment/
LocalDeleted/transport/trust-reset integration `17/17`、daemon purge 参数 `2/2`。完整
`cargo test -p agentdeckd --locked -- --test-threads=1` exit 0：lib `1031 passed / 3 ignored`，
`runtime_store_boundaries` `5/5`（285.90 秒）；完整 CLI、relay-client、protocol、Swift、schema/manifest/static sentinel、
dev/ephemeral selfcheck、hermetic Runtime smoke 与 diagnostics 均 exit 0。Relay `server,tls` 顶层
`359 passed`，crypto `43 passed`，iOS Simulator `20/20`。scoped Clippy、fmt、network、diff/status 全绿；
冻结 candidate 的 `spec/security` 与 `quality` 双路独立终审均 Approved，P0/P1/P2=0。

通过边界只覆盖 automatic scope：certificate/bundle/response/receipt 的 exact binding，v9 lifecycle 的
expected-state CAS/COMMIT-unknown exact retry，control-only MachineLink，portable signed root-lost proof，以及
marker 先于 reset、bootout/PID+UDS absent、retained helper、StorageKEK last 的 purge 顺序。业务 frame 必须
关闭 transport且 RuntimeCore dispatch 恒为零。业务 RemoteLink、E2EE publication、
持久远程 CLI、iOS 真实链路和真实 destructive production profile 均未证明；3 个 ignored 中的
production-signed Keychain 槽位继续精确记录 post-MVP
`BLOCKED/mutations=0/evidence=[]/summaryGenerated=false`，不能计为 PASS。

## Relay Companion MVP P4.3 PairInvite / DeviceGrant / auth ledger Task gate（PASS）

P4.3 主体 code/test 为 `518380e`；`b28f995`、`55be98f`、`ba3629f`、`4ec3d2f` 收紧 transport/
pairing 所有权、drain/recovery、trust-reset singleflight、caller cancellation 与 pairing→retirement handoff；
`fe3a9ad` 修复 Runtime v4 后遗漏的 Rust/Swift 门禁预期；`3b4b977` 收口 cancel-safe join、startup shutdown
watch、LocalRetry health/admission fence 与 v10 table/ledger/cipher fixture。P4.3 收口时 Runtime protocol 为 v4，physical schema
为 **v10 / 30 张表**，新增五张 authenticated bounded pairing/authorization/key-directory/control-outbox 表。

内部 production 子片只运行 focused tests + scoped Clippy/fmt；Task 收口复跑以下矩阵：

```bash
cargo test -p agentdeckd --locked --lib remote::transport::tests -- --test-threads=1
cargo test -p agentdeckd --locked --lib remote::pairing::tests -- --test-threads=1
cargo test -p agentdeckd --locked --lib remote::manager::tests -- --test-threads=1
cargo test -p agentdeckd --locked --lib remote::trust_reset::tests -- --test-threads=1
cargo test -p agentdeckd --locked --lib runtime::store::pairing -- --test-threads=1
cargo test -p agentdeckd --locked --lib \
  runtime::store::machine_remote::reset_guard_tests -- --test-threads=1
cargo test -p agentdeckd --locked --test pairing_state_machine -- --test-threads=1

# Task 级完整 package / 跨语言门禁
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

# schema、network、文档与静态边界
cargo run -q -p agentdeck-cli -- protocol runtime-schema \
  | diff - protocol/agentdeck/runtime-protocol.schema.json
bash scripts/check-daemon-network-boundary.sh
bash scripts/check-daemon-no-net.sh
scripts/verify-agent-docs.sh
cargo clippy -p agentdeckd --all-targets --locked --no-deps -- -D warnings
cargo fmt --all -- --check
git diff --check
git status --short --branch
```

**Task 收口证据（2026-07-21，reviewed range `4fd8ed8..3b4b977`）：** focused transport `39/39`、
pairing actor `64/64`、manager `41/41`、trust reset `9/9`、Store pairing `68/68`、reset guard `5/5`、
真实 TLS Relay + UDS + CLI pairing E2E `1/1`。`PairResponse.info` 四轴绑定、298 秒 TTL、confirm 只读
replay、InstallGrant exact retry、10 秒 drain、shutdown cancel、singleflight、waiter 回收与 admission epoch
旧命令零执行均有专项证据。
Swift `541 XCTest + 35 Swift Testing` 与 iOS Simulator `20/20` 已在 current code baseline exit 0。
最终 `cargo test -p agentdeckd --locked -- --test-threads=1` exit 0：lib
`1252 passed / 3 ignored`（765.48 秒），`runtime_store_boundaries` 为 `5/5`（331.47 秒），
`runtime_store_command_configuration` 为 `14/14`，current-v10 tamper 为 `2/2`；完整进程中的其余
integration binary 与 doc-test 同样无失败。最终 `3b4b977` 的独立 spec/security 与 quality 终审均为
P0/P1/P2=0、Approved。

最终实际覆盖 130 个非 lock 代码/测试/协议路径，另含 `Cargo.lock`。最大 production 子片 Store pairing
为 1,792 additions，低于 1,800 预拆线；测试、fixture、
schema snapshot 与文档不计 production 拆片线。P4.3 本身不证明业务 Runtime dispatch、E2EE publication/
counter reservation、persistent remote CLI、iOS 真实链路或 production-signed PASS；后续 P4.4 已完成
ingress/Core，P4.5 已完成 signed publication/counter recovery；P4.6 已完成 automatic Task。

## Relay Companion MVP P4.4 MachineLink ingress / RuntimeCore dispatch Task gate（PASS）

P4.4 code/test 由 `cd7d9fb` 精确收口 35 个路径。Runtime protocol 保持 v4，physical schema
保持 v10/30 表，四个版本轴与 schema snapshot 均无漂移。Task 建立唯一 MachineLink business
lane，严格链路为 Relay v2 outer → DeviceSign/AAD/replay candidate/AEAD → Store exact-current
auth-ledger recheck → `RemotePrincipal` → `RuntimeCore`。`RouteAccepted` 不是 command success；
Active/Inactive/Unprovable 恢复只影响对应 conversation。

子片只跑 focused tests + scoped Clippy/fmt；Task 收口的聚焦与静态基线为：

```bash
cargo test -p agentdeck-protocol --locked \
  --test p4_remote_link_protocol_contract -- --test-threads=1
cargo test -p agentdeckd --locked \
  --test machine_remote_link -- --test-threads=1
cargo test -p agentdeckd --locked \
  --test runtime_core -- --test-threads=1
bash scripts/check-daemon-network-boundary.sh
bash scripts/check-daemon-no-net.sh
cargo clippy -p agentdeckd --locked --lib --tests --no-deps -- -D warnings
cargo fmt --all -- --check
scripts/verify-agent-docs.sh
git diff --check
```

**Task 收口证据（2026-07-22，code/test `cd7d9fb`）：** protocol contract `8/8`、
Machine RemoteLink boundary `1/1`、RuntimeCore static gate `3/3`、network boundary、no-net、四 schema、
scoped Clippy、fmt 与 diff 全绿。正式
`cargo test -q -p agentdeckd --locked -- --test-threads=1` exit 0，wall 1322.53 秒；lib
`1291 passed / 3 ignored`（763.78 秒），`runtime_store_boundaries` `5/5`（281.52 秒），
`runtime_stream` `45/45`（41.64 秒），其余 integration target 无失败。target inventory 复核另确认
1,853 个发现项全覆盖：`1845 passed / 8 ignored / 0 failed`。relay-client `18/18`、protocol
`214/214`、crypto `50/50`、CLI `168/168`、Relay server+tls 顶层 `359 passed`、Swift
`541 XCTest + 35 Swift Testing`、iOS Simulator `20/20` 均 exit 0；独立 `spec/security` 与
`quality` 终审均为 P0/P1/P2=0、Approved。

通过边界严格止于 ingress/Core dispatch 与 typed egress seam。RemoteLink 只持有易失
generation/replay/connection/reply-route，不持 canonical conversation/command/receipt state。P4.4
收口时 `DirectedReplySealer` / `RemoteStreamPublisher` 尚未安装、production
`admission_ready=false`；后续 P4.5 已安装这些 production 组合并保持同一所有权边界。P4.6 persistent
remote CLI 已完成 automatic Task，production-signed PASS 仍未完成。当前 verifier 脚本只接受
`p0|p2|p3|p4-auto`；`p4-auto` focused aggregate 已在 P4.7 收口时 PASS，`p4` 仍不受支持。
P4.4 与后续 P4.5 Task 的既有证据本身均不等于 P4.7 `p4-auto` 或 P4 aggregate PASS。

## Relay Companion MVP P4.5 signed publication / counter recovery Task gate（PASS）

P4.5 code/test 由 `88b3c42` 收口，`c6ef387` 同步清零 Relay 全量 Clippy 告警。P4.5 收口时 Runtime wire 为
v4，physical schema 升为 **v14 / 35 张表**；Relay v2 与 E2EE v1 的版本常量均不 bump，E2EE v1
schema 仅 additive 扩展 key-control/publication contract。production 固定执行
`Keychain CounterGuard reserve → seal 一次 → Runtime DB 冻结 exact blob/streamSeq/counter/event range
→ Relay Publish COMMIT → local ACK`，任意 retry 只准复用同一冻结 blob；counter/DB rollback、nonce
reuse、receive replay、key revision rollback 与 retired epoch 均按 authenticated Store/Keychain 状态
fail-close。

**Task 收口证据（2026-07-23，commits `c6ef387` + `88b3c42`）：** remote focused tests
`430/430`；完整 daemon package exit 0，其中 lib `1579 passed / 3 ignored`、main `7/7`、
`runtime_store_boundaries` `5/5`（真实 256 MiB，282.85 秒），其余 integration target 与 doc-test
零失败。Clippy、fmt 与 `git diff --check` 全绿。双路独立终审在冻结 diff SHA-256
`88ac6c486a7446b5fe4613388f66ee25561a7529a2fd0f8904844217730a896f` 上均 Approved，
P0/P1/P2=0。

本 Task 只证明 daemon 侧 MachineDataSign、directed/shared sealing、durable publication outbox、Relay
COMMIT/local ACK、key directory/epoch barrier、counter/replay crash recovery 与恢复期 admission fence。
P4.6 persistent remote CLI 已完成 automatic Task，current Runtime wire 为 v5；P4 按
当时的 Task 进度为 6/7；该值是 P4.6 收口时点，不是当前状态。后续 P4.7 automatic E2E 与 P4
automatic Phase Exit 已完成，当前为 7/7。`scripts/verify-relay-companion-mvp.sh` 支持
`p0|p2|p3|p4-auto`，但 `p4` 仍不受支持；P4 aggregate PASS 由 P4.7 `p4-auto`、独立顶层门禁、
冻结 candidate hash 与双路 phase review 共同证明。P3.1
继续采用方案 b；provisioned production-signed Keychain/LaunchAgent 与真实设备/公网证据继续保留为
post-MVP `BLOCKED/mutations=0/evidence=[]/summaryGenerated=false`，不计 PASS，也不反向否定 P4.5
automatic Task gate。

## Relay Companion MVP P4.6 persistent remote CLI Task gate（automatic complete）

current Runtime wire 为 v5。当前 Task 已接入 `pair`、`machines`、`conversations`、`watch`、`prompt`、
`approve`、`retry-approval`、`revoke-self`。`watch` 从 fresh authenticated bootstrap 开始，以 canonical
NDJSON 公开 `bootstrap|synchronized|live|control|terminal`。SIGINT/SIGTERM 都只在当前 exact frame durable
apply 与 ACK terminal 后公开 stopped；`TransferBootstrapRequired`+signal 必须 marker→stopped，subscription
control 也先输出再 latch signal。Connected+ready signal 零 Subscribe、shutdown 后 stopped；verified revoked
terminal 优先，且握手期/active revoke 均须 transport shutdown/drop→crash-safe cleanup 后才公开 revoked。

paired-state V6 把 binding 与 transfer records 放入同一 sealed CAS。prepared ADST v2 的 Normal/
EmergencyBootstrapMarker mode 位于 AEAD 认证内容，guard sealed commitment 绑定完整 sidecar；legacy ADST v1
只解释为 Normal。4095→4096 marker 覆盖 guard-first/active-first crash cut；cleanup 由 exact owner unlink 并可
retry，缺失后的 reseal/commitment conflict fail-close，legacy over-normal CounterPending active-next 零写拒绝。
P4.6 冻结门禁至少运行：

```bash
cargo test -p agentdeck-cli --test remote_transfer_paired_state --locked -- --test-threads=1
cargo test -p agentdeck-cli --test remote_transfer_persistence --locked -- --test-threads=1
cargo test -p agentdeck-cli --test remote_stream_state --test remote_transfer_state --locked -- --test-threads=1

# watch 编排、signal latch、terminal 顺序与 fresh reducer
cargo test -p agentdeck-cli --lib --locked remote::watch_tests -- --nocapture --test-threads=1
cargo test -p agentdeck-cli --test remote_runtime_receipts --locked \
  live_ack_phase_signal_is_latched_only_after_durable_apply_and_ack_completion -- \
  --exact --nocapture --test-threads=1
cargo test -p agentdeck-cli --test remote_runtime_receipts --locked \
  active_watch_revocation_cleans_up_only_after_exact_verification_and_transport_shutdown -- \
  --exact --nocapture --test-threads=1
cargo test -p agentdeck-relay-client --locked \
  v2::connection::tests::cancelling_pending_exact_receive_preserves_frames_bytes_and_priority -- \
  --exact --nocapture --test-threads=1

# prepared ADST v2 mode/commitment 与 production crash-cut recovery
cargo test -p agentdeck-cli --lib --locked \
  remote::crypto_state::tests::prepared_stage_capacity_mode_is_authenticated_and_legacy_defaults_fail_closed -- \
  --exact --nocapture --test-threads=1
cargo test -p agentdeck-cli --lib --locked \
  remote::paired_machine::counter_reservation_tests::counter_pending_active_next_over_normal_recovery_is_zero_write -- \
  --exact --nocapture --test-threads=1
cargo test -p agentdeck-cli --lib --locked \
  remote::paired_machine::counter_reservation_tests::state_pending_emergency_mode_recovers_4095_to_4096_marker_at_both_crash_cuts -- \
  --exact --nocapture --test-threads=1

# cold restart + future durable watermark：250 ms 内 state_invalid，且零发送/零 reducer-cursor
# mutation/paired-state V6 canonical records byte-exact 零写（完整 receipts target 同样覆盖）
cargo test -p agentdeck-cli --test remote_runtime_receipts --locked \
  restarted_live_transfer_clock_rollback_fails_before_wait_or_mutation -- --exact --nocapture

# normal-cap replay 与 marker 同一 CAS；第二个 distinct binding 仍有独立 emergency reserve
cargo test -p agentdeck-cli --test remote_runtime_receipts --locked \
  emergency_replay_debt_survives_real_binding_replacement_until_deterministic_pruning_without_cross_binding_loss -- \
  --exact --nocapture --test-threads=1
cargo test -p agentdeck-cli --test remote_runtime_receipts --locked \
  consecutive_distinct_bindings_use_emergency_capacity_without_prior_state_loss -- \
  --exact --nocapture --test-threads=1

# exact marker 在 replacement 前同时 fence Publish/Gap/ReplayComplete；后两者也必须 paired bytes 零写
cargo test -p agentdeck-cli --test remote_runtime_receipts --locked \
  bootstrap_marker_fences_gap_and_replay_complete_without_any_state_progress -- \
  --exact --nocapture --test-threads=1

# 显式 ignored 的 production-path release allocator 门禁；常规 cargo test 不会运行
cargo test --release -p agentdeck-cli --test remote_transfer_memory --locked \
  production_transfer_peak_is_bounded_across_capacity_completion_and_duplicate -- \
  --ignored --exact --nocapture --test-threads=1

# 完整 Task 与静态/协议边界
cargo test -p agentdeck-cli --locked --no-fail-fast -- --test-threads=1
cargo test -p agentdeck-relay-client --locked
cargo test -p agentdeck-protocol --locked -- --test-threads=1
cargo run -q -p agentdeck-cli --locked -- protocol schema \
  | diff - protocol/agentdeck/agentdeck-protocol.schema.json
cargo run -q -p agentdeck-cli --locked -- protocol runtime-schema \
  | diff - protocol/agentdeck/runtime-protocol.schema.json
cargo run -q -p agentdeck-cli --locked -- protocol relay-schema \
  | diff - protocol/agentdeck/relay-v2.schema.json
cargo run -q -p agentdeck-cli --locked -- protocol e2ee-schema \
  | diff - protocol/agentdeck/e2ee-v1.schema.json
cargo clippy -p agentdeck-cli -p agentdeck-protocol --locked --all-targets -- -D warnings
cargo clippy -p agentdeck-relay-client --locked --all-targets --no-deps -- -D warnings
cargo fmt --all -- --check
bash scripts/check-daemon-network-boundary.sh
bash scripts/check-daemon-no-net.sh
scripts/verify-agent-docs.sh
git diff --check
```

**Task 收口证据（2026-07-24）：** 冻结 code/test scope 为 29 paths，blob-manifest SHA-256 为
`32e7c85620e6e88b407f2403715c52c5a9a5d30aa20d7fb800bdefabe8a1c858`。watch `12/12`、
`remote_persistent_machines` `11/11`、relay-client `25/25`、protocol `244/244` 均通过。完整 CLI package
final run 在同一 hash 上 exit 0（14 分 16 秒）：lib `194/194`、main `50/50`、
`remote_runtime_receipts` `81/81`（432.35 秒）、`remote_transfer_persistence` `6/6`（256.08 秒）、
`remote_transfer_paired_state` `7/7`（57.27 秒）、`runtime_cli_binary` `17/17`（30.84 秒）、synthetic
`10/10`、shared daemon `27/27`、doc-test `6/6`，仅预期忽略显式 release allocator。release allocator
`1/1`（24.11 秒），counting
allocator requested-live capacity/complete/duplicate 分别为 `363/190/3 MiB`，**不是 RSS、resident
high-water 或 128 MiB physical-memory 承诺**。四 schema、CLI/protocol/relay-client Clippy
`-D warnings`、fmt、network/no-net、docs 与 diff 全绿。`spec/security` 与 `quality` 终审均已在同一
hash 上 Approved，P0/P1/P2=0。

8 MiB lowered-cap seam 只在 `debug_assertions` automatic test build 中存在，release artifact 不编译该入口，
也不存在 CLI/env/config 可配置路径。上述实现以 automatic Task complete 计为 P4 的第 6/7 项；这是
P4.6 的历史 Task 序号，不随当前 P4 7/7 结论改写。
automatic injected keystore/verifier 只证明同一状态机；production-signed CLI/Data Protection Keychain readback
继续作为 post-MVP `BLOCKED`，不得计 PASS。后续 P4.7 focused `p4-auto`、独立顶层门禁、冻结 hash 与
双路 phase review 已通过，P4 automatic Phase Exit complete；iOS 真实链路、物理设备与公网证据仍未完成。

## Relay Companion MVP P4 pairing→key-transition production hardening gate

本 gate 覆盖 P4.3 `PairResponseReceived` 与 P4.5 Add/Renew key transition 的 durable 交界，不新增 Task
完成数。ADKT 写 codec v3、legacy v1/v2 read/replay、target-only ACK、ACK/receipt 时间竞态、GC pin 与 Close
后完整 30 天 receipt window 必须作为一个安全工作单元验证。first-device zero-cut Add 的测试必须仅依赖
exact receipt proof 到达 `BusinessReady`，不得注入冗余 KeyUpdateAck 掩盖 production 接线缺口。

Focused matrix：

```bash
RUSTC_WRAPPER= cargo test -p agentdeckd --lib \
  runtime::store::pairing_delivery_tests -- --test-threads=1
RUSTC_WRAPPER= cargo test -p agentdeckd --lib \
  runtime::store::pairing_terminal_tests -- --test-threads=1
RUSTC_WRAPPER= cargo test -p agentdeckd --lib \
  runtime::store::pairing_receipt_retention_tests -- --test-threads=1
RUSTC_WRAPPER= cargo test -p agentdeckd --lib \
  runtime::store::retired_key_tests -- --test-threads=1
RUSTC_WRAPPER= cargo test -p agentdeckd --lib \
  runtime::store::key_transition -- --test-threads=1
RUSTC_WRAPPER= cargo test -p agentdeckd --lib \
  remote::transition_tests -- --test-threads=1
```

行为验收必须同时证明：

- 独立随机 HPKE ciphertext 在 stable slot/global lineage 相同时可接受；transition 必须同时认证 confirm-time
  完整 global-state hash 与同 revision 稳定 key-lineage digest。retention owner、retired tombstone、
  revoked-secret GC 的合法原地变化不得触发误报；active roster/current epoch/key material 任一分叉、slot/global
  错绑、错误 target/revision/device signature 都零写拒绝，tamper 在 full-open 阶段 fail-closed且不重写
  artifacts。固定 stable-lineage KAT
  `2df91367dc4be4c1404451128961e4f6f99b610402cb1aa3a90818bbb560262e` 还必须经 production transaction
  staging、ADKT v3 seal、SQLite shutdown/reopen 后保持 exact equality，不能只证明 plaintext codec roundtrip。
- proof 只 ACK exact target；非 target 继续 Frozen。正常 ACK 先到保留真实 evidence，fresh receipt 时间回退
  零写拒绝；receipt placeholder 先到后可升级为普通 ACK，但 Completed terminal causal time 不移动。
- proof 后 cancel 被拒；proofful 与 ADKT v1/v2 proofless Completed transition 在 pairing/Close 尚存时都被
  GC pin。当前 ADKT v3 Add/Renew 必须有 nonzero global/stable lineage，不能把 proofless v3 当 legacy。
  exact legacy receipt replay 只在 matching v1/v2 transition、同 revision 且完整 global-state hash 精确一致时
  回填；若 revision 已前进则零写 fail-close。旧版本已收集 transition/update 时只允许
  replay/Close、零 proof forging，matching update 单独残留必须 fail-closed。
- fresh Close ACK 原子 scrub pairing/outbox、保留原 `created_at_ms`、重签 MAC并把 `retain_until_ms` 延到
  ACK 后完整 30 天；clock regression 零写，AfterCommit-unknown 重开不被 startup purge 抢先删除，exact retry
  只读且不二次续期。
- `PairingBootstrapInstallBinding` / `PairingBootstrapInstallProof` 的 Debug/日志输出不包含 receipt、route、hash、
  key lineage 或其他 binding 内容。

在 scoped commit 前还必须运行宽门禁并取得最终 exit 0；focused PASS 不能代替 package/workspace/selfcheck：

```bash
RUSTC_WRAPPER= cargo test -p agentdeckd --locked -- --test-threads=1
RUSTC_WRAPPER= cargo test --workspace --locked -- --test-threads=1
RUSTC_WRAPPER= cargo run -p agentdeck-cli --locked -- selfcheck
RUSTC_WRAPPER= cargo clippy -p agentdeckd --lib --tests -- -D warnings
cargo fmt --all -- --check
bash scripts/check-daemon-network-boundary.sh
RUSTC_WRAPPER= bash scripts/check-daemon-no-net.sh
scripts/verify-agent-docs.sh
git diff --check
git status --short --branch
```

本 gate 通过也只收口该 production hardening；在该 gate 的历史时点 P4 仍为 **6/7**，不能仅凭它勾选
P4.7、`p4-auto` 或 P4 Phase Exit。后续 P4.7 独立 automatic E2E、真实槽位 contract 与 phase review 已完成。

## Relay Companion MVP P4.7 automatic Task / P4 Phase Exit gate（PASS）

`scripts/verify-relay-companion-mvp.sh p4-auto` 已完整 PASS；`p4` 仍不受支持。P4.7 automatic Task 与
P4 automatic Phase Exit 已完成，P4 为 7/7。pre-closeout review candidate SHA-256 为
`18654fa9c398383dafcefa1542c8e48f8c460f1f521806880c5dab083bdb29f5`；`spec/security` 与 `quality`
均 Approved，P0/P1/P2=0。

`p4-auto` 只运行以下 focused aggregate：

```bash
bash scripts/verify-relay-companion-mvp.sh p4-auto
```

其内部覆盖 daemon machine synthetic E2E（由该 target 通过 `PersistentRemoteComposition` 与 persistent
high-level API 承担完整远程 CLI 路径）、独立 RuntimeCore remote-principal cannot-confirm-pairing gate、
CLI paired-state restart/legacy ADSB v3 migration 与真实槽位 contract、current V6 signed-frame crash/readback、
pairing 与 trust-reset state machine、production composition、relay-client/protocol、network boundary、四份
schema 与 agent docs。`agentdeck-cli/tests/e2e_remote_synthetic.rs` 本身不冒充完整 high-level E2E；
cannot-confirm-pairing 必须由独立 RuntimeCore principal gate 证明，也不属于 machine E2E 的自证范围。

该 focused aggregate **不包含**：

- 顶层 `cargo test` 与 `swift test`；
- 最终 `git diff --check` 与 `git status --short --branch`；
- 冻结 candidate hash；
- 同一冻结 hash 上的独立 `spec/security`、`quality` phase review。

P4.7 收口时还单独运行并记录了：

```bash
cargo test --locked
swift test
bash scripts/check-daemon-network-boundary.sh
bash scripts/verify-relay-companion-mvp.sh p4-auto
scripts/verify-agent-docs.sh
git diff --check
git status --short --branch
```

fresh `cargo test --locked`、`swift test`（577/577）、三组 Clippy、fmt、daemon network/no-net、四 schema、
agent docs、diff、local Runtime smoke、ephemeral selfcheck 与 diagnostics 均通过。`p4-auto` 的 focused
PASS 与这些独立门禁、冻结 hash、双路 review 合并后，才构成 P4 automatic Phase Exit；不能把单独的
focused aggregate 写成完整 Phase PASS。

其中 current V6 replay tuple 的非零 signed-frame hash、crash cut 与 cold readback 由以下既有 focused gate
直接证明；legacy ADSB v3 fixture 的零 sentinel 不得替代该证据：

```bash
RUSTC_WRAPPER= cargo test -p agentdeck-cli --locked \
  --test remote_live_key_update \
  directory_advance_crash_after_replay_commit_recovers_exact_signed_frame \
  -- --exact --test-threads=1
```

`scripts/run-relay-companion-p4-real-e2e.sh` 当前不是 prerequisite preflight，而是静态 fail-closed slot
sentinel：不读取参数或环境变量，不探测 release signing、entitlement、WSS、vendor login 或 disposable
profile，也不执行真实链路。每次只固定输出完整 `missingInputs`，并精确保持
`BLOCKED/mutations=0/evidence=[]/summaryGenerated=false`；真实 preflight/execution 留给 post-MVP。Linux
只允许 ephemeral test keys；macOS production persistent pairing 必须使用 Data Protection Keychain，不存在
CLI/env/config injected/file/dev keystore 降级面。MachineRoot 丢失时按
[`RELAY_RUNBOOK.md`](RELAY_RUNBOOK.md#machineroot-丢失后的-portable-purge-receipt) 的 portable purge
receipt 流程处理，不得用 sentinel 或 synthetic receipt 代替。
production-signed Keychain/LaunchAgent、真实 vendor、公网 WSS、物理真机/真实 iOS、第二台 Mac 与
destructive purge 继续保持 post-MVP BLOCKED，不属于 P4 automatic PASS；P5/P6 当前进度为 7/9、0/4，
其中 P5.1 完成 shared facade，P5.2 完成 crash-safe client storage，P5.3 完成 WSS/pin 与
per-connection transfer primitive，P5.4 完成 MachineConnection、shared transfer coordinator 与 bounded
source automatic Task；P5.5 已另行完成 canonical fixture 与 receipt UI 迁移，P5.6 又完成 iOS Release
Relay composition、配对 UI 与前后台 source lifecycle，P5.7 完成 macOS registry 与 recovery/shutdown
hardening。因此当前 P5/P6 进度为 7/9、0/4；真实外部槽位仍不计 PASS。

## Relay Companion MVP P5.1 shared SessionSource facade 门禁

P5.1 只验收共享 Swift facade、公共可见性、target 依赖方向与 macOS/iOS compile-link，不验收
RelaySessionSource、bounded broadcaster、Keychain/WSS、旧 fixture 迁移或真实 Companion 链路。

```bash
# 确认不是 0-test 假绿，再执行全包 warnings-as-errors 编译 + focused behavior tests
swift test list | rg 'AgentDeckSessionSourceTests'
RUSTC_WRAPPER= swift test -Xswiftc -warnings-as-errors \
  --filter AgentDeckSessionSourceTests

# 新共享 target 严格构建与完整 Swift 回归
swift build --target AgentDeckSessionSource -Xswiftc -warnings-as-errors
RUSTC_WRAPPER= swift test

# 公共边界与格式
rg -n 'import (CryptoKit|UIKit|AppKit|Network)|URLSession|streamResource|@MainActor|@unchecked Sendable|@preconcurrency|nonisolated\(unsafe\)' \
  Sources/AgentDeckSessionSource
rg -n 'import (CryptoKit|UIKit|AppKit|Network)' \
  Sources/AgentDeckCore Sources/AgentDeckSessionSource
swift format lint --strict \
  Sources/AgentDeckSessionSource/*.swift \
  Tests/AgentDeckSessionSourceTests/*.swift \
  ios/AgentDeckMobileTests/CoreLinkTests.swift

# XcodeGen 是工程事实源；不得提交生成的 xcodeproj/Info.plist
cd ios && xcodegen generate && \
  xcodebuild -project AgentDeckMobile.xcodeproj -scheme AgentDeckMobile \
    -destination 'platform=iOS Simulator,name=iPhone 17' test

scripts/verify-agent-docs.sh
git diff --check
```

`ResourceState`、`ConversationUpdate`、`PairingProgress` 必须分别保持精确 4/4/5 cases；receipt 必须是
当前 Core 类型的 identity alias。`MachineSummary` 必须公开 typed connection state，不能用 Bool
initializer 压缩离线原因；三份 contract test 必须使用普通 `import AgentDeckSessionSource`，避免
`@testable` 掩盖 public API 缺口。iOS App/Test target 必须显式声明 Core、SessionSource、RelayClient；
SessionSource product 使用 `link: false`，由 RelayClient 的 target edge 提供传递链接，避免重复 product
wrapper。fresh Xcode dependency scan 不得报告缺失 Core edge，`CoreLinkTests` 必须实际 import/构造三模块类型；
若 RelayClient 将来不再依赖 SessionSource，则必须恢复 SessionSource direct link。

当前 Task 自动证据为 focused `15/15`、完整 Swift `557 XCTest + 35 Swift Testing`、iOS Simulator
`21/21`，strict target/full-package compile、格式、平台/fixture 泄漏扫描与 diff 均通过。P5.1 收口时旧
`MobileSessionSource`/models/fixture 仍存在，后续已由 P5.5 单独迁移；这组历史证据只属于 P5.1，不能拿来
替代 P5.5 或 P5 Phase Exit。

## Relay Companion MVP P5.2 Keychain / CryptoState / counter / replay 门禁

P5.2 只验收共享 Apple client 的本地 secret/state primitive，不验收 WSS、MachineConnection、
RelaySessionSource、真实 pairing UI 或远程命令闭环。`KeyStoreKey` 必须保持封闭 typed factory；
`CryptoStateFileV1` 不得复用 transport `OuterContextV1`/JSON AAD；counter 只有最终 Stable exact readback
后才能返回；non-counter state 只有 `statePending` 绑定 exact next full-state commitment 后才可 CAS，replay
floor 以下必须先判 stale。

```bash
# test discovery 先证明七组 storage/state/counter/replay/paired 测试真实存在
swift test list | rg 'AppleKeychainStoreTests|CryptoStateStoreTests|DeviceCryptoStateTests|CounterAllocatorTests|DurableCryptoStateCoordinatorTests|ReplayWindowTests|PairedMachineStoreTests'

# Rust probe 必须显式禁用本机无权限 sccache wrapper
RUSTC_WRAPPER= swift test -Xswiftc -warnings-as-errors \
  --filter AgentDeckRelayClientTests
swift build --target AgentDeckRelayClient -Xswiftc -warnings-as-errors
RUSTC_WRAPPER= swift test

# iOS storage focused + 全量 Simulator；XcodeGen 是工程事实源
cd ios && xcodegen generate && \
  xcodebuild -project AgentDeckMobile.xcodeproj -scheme AgentDeckMobile \
    -destination 'platform=iOS Simulator,name=iPhone 17' \
    -only-testing:AgentDeckMobileTests/RelayClientStorageIntegrationTests test
xcodebuild -project AgentDeckMobile.xcodeproj -scheme AgentDeckMobile \
  -destination 'platform=iOS Simulator,name=iPhone 17' test
cd ..

# public/storage boundary、secret 与格式
swift format lint --strict \
  Sources/AgentDeckRelayClient/Crypto/{CounterAllocator,ReplayWindow}.swift \
  Sources/AgentDeckRelayClient/Storage/*.swift \
  Tests/AgentDeckRelayClientTests/{AppleKeychainStoreTests,CryptoStateStoreTests,DeviceCryptoStateTests,CounterAllocatorTests,DurableCryptoStateCoordinatorTests,ReplayWindowTests,PairedMachineStoreTests}.swift \
  ios/AgentDeckMobileTests/RelayClientStorageIntegrationTests.swift
rg -n '@unchecked Sendable|@preconcurrency|nonisolated\(unsafe\)|kSecAttrSynchronizable.*true|AccessibleAfterFirstUnlock|JSONEncoder.*AAD' \
  Sources/AgentDeckRelayClient
rg -n 'prompt-output-transcript-sentinel|BEGIN (RSA|OPENSSH|PRIVATE) KEY|device-storage-kek' \
  Sources Tests ios
scripts/verify-agent-docs.sh
git diff --check
```

automatic contract 必须覆盖：App/CLI account 分离；immutable insert/exact replace/delete readback；ADCS v1
随机 nonce、五轴 AAD、128 MiB、0600、backup exclusion、Complete policy、同目录原子替换；state 在而 KEK
缺失时零生成；1,024 counter block 的 Pending→sealed-state CAS→Stable 三处 crash cut；rollback/fork/overflow
退休 epoch；non-counter `statePending` 的 previous rollback、exact-next finalize、authenticated sibling
replay/cursor rollback 与 quarantined→active fail-close；4,096 replay window、乱序、duplicate/nonce
reuse/stale 与 `UInt64.max`；真实 sparse oversized durable file 在读取/修复前返回 `inputTooLarge`；paired
commit marker 不含 grant/private key。SwiftPM 未签名 runner 若返回 Keychain `-34018`，真实 SecItem tests 必须明确 SKIP 并保留
post-MVP BLOCKED，不能改成 memory fallback 或计 PASS。Simulator protection readback 的平台固定值也不能
冒充物理 iPhone 锁屏证据。

2026-07-26 收口证据：七组新增 discovery `91` cases；strict RelayClient `121 executed / 4 entitlement
SKIP / 0 failure`，完整 Swift `649 XCTest / 4 SKIP + 35 Swift Testing`，iOS storage `5/5`、全量
Simulator `26/26`，Rust crypto/protocol、strict target/format、production unsafe/弱 Keychain policy、
secret/transcript、agent docs 与 diff 门禁均通过。双路终审 P0/P1/P2=0。production-signed Keychain 与
物理 iPhone locked/unlocked Complete readback 仍是 post-MVP BLOCKED，不计 PASS。

## Relay Companion MVP P5.3 WSS / SPKI pin / transfer assembler 门禁

P5.3 只验收共享 Apple client 的 generation-scoped WSS transport、TLS policy、纯重连策略与
per-connection transfer assembler，不验收 P5.4 `RelaySessionSource`、process-global transfer budget、
真实公网 WSS、物理 iPhone 或端到端 Companion。process-global 512 MiB reassembly 与 8,192 completed
tombstone 必须由 P5.4 shared connection coordinator 在分配前统一预留；单个 assembler 通过不能冒充该门禁。

```bash
# 三组 focused tests；先由 discovery 防止 filter 假绿
swift test list | rg 'RelayWebSocketTransportTests|TLSPinningTests|TransferAssemblerTests'
RUSTC_WRAPPER= swift test -Xswiftc -warnings-as-errors \
  --filter 'RelayWebSocketTransportTests|TLSPinningTests|TransferAssemblerTests'

# RelayClient strict/full Swift 与 iOS 17 Simulator 回归
RUSTC_WRAPPER= swift test -Xswiftc -warnings-as-errors \
  --filter AgentDeckRelayClientTests
swift build --target AgentDeckRelayClient -Xswiftc -warnings-as-errors
RUSTC_WRAPPER= swift test
cd ios && xcodegen generate && \
  xcodebuild -project AgentDeckMobile.xcodeproj -scheme AgentDeckMobile \
    -destination 'platform=iOS Simulator,name=iPhone 17' test
cd ..

# Rust transfer/Runtime 与跨语言 crypto parity
RUSTC_WRAPPER= cargo test -p agentdeck-protocol --test transfer_envelope -- --test-threads=1
RUSTC_WRAPPER= cargo test -p agentdeck-protocol --test runtime_v2_contract -- --test-threads=1
RUSTC_WRAPPER= cargo test -p agentdeck-crypto --test golden_vectors -- --test-threads=1
bash scripts/verify-cross-language-crypto.sh

# 平台边界、格式与文档
swift format lint --strict \
  Sources/AgentDeckRelayClient/Transport/*.swift \
  Sources/AgentDeckRelayClient/Transfer/*.swift \
  Tests/AgentDeckRelayClientTests/{RelayWebSocketTransportTests,TLSPinningTests,TransferAssemblerTests}.swift
cargo fmt --all --check
rg -n '@unchecked Sendable|@preconcurrency|nonisolated\(unsafe\)|ws://|http://' \
  Sources/AgentDeckRelayClient/Transport Sources/AgentDeckRelayClient/Transfer
scripts/verify-agent-docs.sh
git diff --check
```

transport 必须固定唯一 Relay v2 Hello，所有 owner API 绑定不可复用 generation；concurrent connect 只共享
一个 attempt，单 waiter 取消不能误杀 sibling 或让新 caller 收到伪 canceled。connect、socket writer 与
physical close 都有绝对 deadline；write timeout 对 exact generation/outbound ID 返回 outcome unknown，迟到
timer 不得杀新 generation；close 只有依次读取 task `didComplete` 与 session `didBecomeInvalid` 后才解除
generation 屏障，WebSocket `didClose` 单独不够；cleanup 不合作必须 fail-close/poison 当前 transport。
incoming regular 与 urgent、application writer 与 control 各自同时受 frame
和 byte 上界；1009 必须稳定映射 oversized，4 MiB + 1 在应用 decode 前拒绝。TLS 只允许 public CA、public
CA + current/next DER-SPKI pin、pinned self-signed 三种互斥策略，全 redirect/host/scheme downgrade 拒绝。

transfer assembler 必须绑定 connection UUID + generation；64 active、128 MiB parts+assembly peak、5 分钟
absolute TTL 与 256 completed tombstone 都是 per-connection hard cap。metadata/length/hash/duplicate/validation
失败必须释放 offending partial；completed tombstone 保存逐 part hash，cap 满拒绝新 completion且不驱逐 TTL 内
dedup。Swift/Rust 对非法续片的 fail-close 行为必须有 parity regression。

2026-07-26 收口证据：focused `60/60`（Transport 34、TLS 11、Assembler 15）并连续 10 轮稳定；strict
RelayClient `181 executed / 4 entitlement SKIP / 0 failure`，strict target build、完整 Swift
`709 XCTest / 4 SKIP + 35 Swift Testing`、iOS Simulator `26/26`；Rust transfer `24/24`、完整
`agentdeck-protocol`、Runtime contract `50/50`、crypto vectors `20/20`、cross-language、格式/静态/docs/diff
均通过，独立终审 P0/P1/P2=0。首轮 Simulator 已准确暴露 iOS 18-only lock API，并在改用 iOS 16+
`OSAllocatedUnfairLock` 后重跑全量通过。真实公网 WSS、物理设备与 P5 Phase Exit 仍未完成；P5.4 global
coordinator 是后续 blocking gate。

## Relay Companion MVP P5.4 MachineConnection / bounded source 门禁

P5.4 验收 production `MachineConnection`/verified ingress、process-global transfer budget、bounded
broadcaster/reducers、scoped `RelaySessionSource`、typed command/pairing 与 cross-language crypto/wire 接线。
原计划 Step 2 的历史 RED 在接管大型 WIP 时没有保留，不得补写；以 current-tree discovery、fresh focused 与
完整 target/package rerun 替代。filter 必须先由 discovery 证明非空，最终计数只从冻结候选的 fresh 输出回填。

```bash
# 当前 P5.4 行为 suite；先 discovery，禁止 0-test filter 假绿
p54_suites='BoundedBroadcasterTests|DeviceRequestSignerTests|KeyDirectoryVerifierTests|KeyUpdateSetVerifierTests|MachineConnectionTests|MachineDataVerifierTests|MachineRequestCorrelationTests|MachineTerminalVerifierTests|PendingPairingStoreTests|PairedMachineStoreTests|PairingPromotionBuilderTests|PairRequestCryptoTests|PairResponseCryptoTests|PairTerminalVerifierTests|ProductionMachineConnectionVerifiedIngressTests|ProductionRelayPairingCommandHandlerTests|RelayResumeTests|RelayRuntimeCommandClientTests|RelaySessionSourceTests|TransferAssemblyBudgetCoordinatorTests'
swift test list | rg "$p54_suites"
RUSTC_WRAPPER= swift test -Xswiftc -warnings-as-errors --filter "$p54_suites"

# RelayClient strict/full Swift、共享 target 与 iOS Simulator 回归
RUSTC_WRAPPER= swift test -Xswiftc -warnings-as-errors \
  --filter AgentDeckRelayClientTests
swift build --target AgentDeckRelayClient -Xswiftc -warnings-as-errors
RUSTC_WRAPPER= swift test
cd ios && xcodegen generate && \
  xcodebuild -project AgentDeckMobile.xcodeproj -scheme AgentDeckMobile \
    -destination 'platform=iOS Simulator,name=iPhone 17' test
cd ..

# Rust/cross-language pairing、E2EE 与 Relay v2 parity
RUSTC_WRAPPER= cargo test -p agentdeck-crypto
RUSTC_WRAPPER= cargo test -p agentdeck-protocol
RUSTC_WRAPPER= cargo test -p agentdeck-relay --features server,tls
bash scripts/verify-cross-language-crypto.sh

# 临时 slice/worktree 若要复用当前仓库源码，必须使用独立 CARGO_TARGET_DIR；Rust 的 env! 宏会把
# CARGO_MANIFEST_DIR 编入 test binary，共用 target 可能让 snapshot gate 误读已删除的临时路径。
# 若已污染，只清理受影响 package 的生成物后在权威 worktree fresh 重跑，禁止生成或改写 snapshot 来掩盖。

# P5.4 精确 Swift strict-format manifest。禁止替换为整个 Sources/Tests/Swift 目录。
p54_swift_manifest=(
  Sources/AgentDeckCore/Protocol/RuntimeV2WireCodec.swift
  Sources/AgentDeckRelayClient/Connection/MachineConnection.swift
  Sources/AgentDeckRelayClient/Connection/MachineConnectionStateMachine.swift
  Sources/AgentDeckRelayClient/Connection/MachineConnectionUpdates.swift
  Sources/AgentDeckRelayClient/Connection/MachineRequestCorrelation.swift
  Sources/AgentDeckRelayClient/Connection/ProductionMachineConnectionVerifiedIngress.swift
  Sources/AgentDeckRelayClient/Crypto/CanonicalCodec.swift
  Sources/AgentDeckRelayClient/Crypto/DeviceRequestSigner.swift
  Sources/AgentDeckRelayClient/Crypto/KeyControlCodec.swift
  Sources/AgentDeckRelayClient/Crypto/KeyDirectoryVerifier.swift
  Sources/AgentDeckRelayClient/Crypto/KeyLifecycleProofs.swift
  Sources/AgentDeckRelayClient/Crypto/KeyUpdateSetVerifier.swift
  Sources/AgentDeckRelayClient/Crypto/MachineDataVerifier.swift
  Sources/AgentDeckRelayClient/Crypto/MachineTerminalVerifier.swift
  Sources/AgentDeckRelayClient/Crypto/PairRequestCrypto.swift
  Sources/AgentDeckRelayClient/Crypto/PairResponseCrypto.swift
  Sources/AgentDeckRelayClient/Crypto/PairTerminalVerifier.swift
  Sources/AgentDeckRelayClient/Crypto/RelayCredentials.swift
  Sources/AgentDeckRelayClient/Crypto/RelayCrypto.swift
  Sources/AgentDeckRelayClient/Source/CatalogReducer.swift
  Sources/AgentDeckRelayClient/Source/ConversationReducer.swift
  Sources/AgentDeckRelayClient/Source/InboxReducer.swift
  Sources/AgentDeckRelayClient/Source/ProductionRelayPairingCommandHandler.swift
  Sources/AgentDeckRelayClient/Source/RelayConversationResumeCoordinator.swift
  Sources/AgentDeckRelayClient/Source/RelayRuntimeCommandClient.swift
  Sources/AgentDeckRelayClient/Source/RelaySessionSource.swift
  Sources/AgentDeckRelayClient/Storage/AppleKeychainStore.swift
  Sources/AgentDeckRelayClient/Storage/DeviceCryptoState.swift
  Sources/AgentDeckRelayClient/Storage/DurableCryptoStateCoordinator.swift
  Sources/AgentDeckRelayClient/Storage/FileCryptoStateStore.swift
  Sources/AgentDeckRelayClient/Storage/KeyStore.swift
  Sources/AgentDeckRelayClient/Storage/PairedMachineStore.swift
  Sources/AgentDeckRelayClient/Storage/PairingPromotionBuilder.swift
  Sources/AgentDeckRelayClient/Storage/PendingPairingStore.swift
  Sources/AgentDeckRelayClient/Streaming/BoundedBroadcaster.swift
  Sources/AgentDeckRelayClient/Transfer/TransferAssembler.swift
  Sources/AgentDeckRelayClient/Transfer/TransferAssemblyBudgetCoordinator.swift
  Sources/AgentDeckRelayClient/Transport/RelayWebSocketTransport.swift
  Sources/AgentDeckRelayClient/Wire/RelayV2Types.swift
  Tests/AgentDeckRelayClientTests/AppleKeychainStoreTests.swift
  Tests/AgentDeckRelayClientTests/BoundedBroadcasterTests.swift
  Tests/AgentDeckRelayClientTests/CryptoStateStoreTests.swift
  Tests/AgentDeckRelayClientTests/DaemonKeyControlCodecTests.swift
  Tests/AgentDeckRelayClientTests/DeviceCryptoStateTests.swift
  Tests/AgentDeckRelayClientTests/DeviceRequestSignerTests.swift
  Tests/AgentDeckRelayClientTests/DurableCryptoStateCoordinatorTests.swift
  Tests/AgentDeckRelayClientTests/KeyDirectoryVerifierTests.swift
  Tests/AgentDeckRelayClientTests/KeyUpdateSetVerifierTests.swift
  Tests/AgentDeckRelayClientTests/MachineConnectionTests.swift
  Tests/AgentDeckRelayClientTests/MachineDataVerifierTests.swift
  Tests/AgentDeckRelayClientTests/MachineRequestCorrelationTests.swift
  Tests/AgentDeckRelayClientTests/MachineTerminalVerifierTests.swift
  Tests/AgentDeckRelayClientTests/PairRequestCryptoTests.swift
  Tests/AgentDeckRelayClientTests/PairResponseCryptoTests.swift
  Tests/AgentDeckRelayClientTests/PairTerminalVerifierTests.swift
  Tests/AgentDeckRelayClientTests/PairedMachineStoreTests.swift
  Tests/AgentDeckRelayClientTests/PairingPromotionBuilderTests.swift
  Tests/AgentDeckRelayClientTests/PendingPairingStoreTests.swift
  Tests/AgentDeckRelayClientTests/ProductionMachineConnectionVerifiedIngressTests.swift
  Tests/AgentDeckRelayClientTests/ProductionRelayPairingCommandHandlerTests.swift
  Tests/AgentDeckRelayClientTests/RelayResumeTests.swift
  Tests/AgentDeckRelayClientTests/RelayRuntimeCommandClientTests.swift
  Tests/AgentDeckRelayClientTests/RelaySessionSourceTests.swift
  Tests/AgentDeckRelayClientTests/RelayV2TypedPairDataFactoryTests.swift
  Tests/AgentDeckRelayClientTests/RelayV2WireTests.swift
  Tests/AgentDeckRelayClientTests/RelayWebSocketTransportTests.swift
  Tests/AgentDeckRelayClientTests/TransferAssemblerTests.swift
  Tests/AgentDeckRelayClientTests/TransferAssemblyBudgetCoordinatorTests.swift
  Tests/AgentDeckTests/RuntimeV2WireCodecTests.swift
)
for file in "${p54_swift_manifest[@]}"; do test -f "$file" || exit 1; done
diff \
  <(printf '%s\n' "${p54_swift_manifest[@]}" | sort -u) \
  <({ git diff --name-only HEAD -- '*.swift'; git ls-files --others --exclude-standard -- '*.swift'; } | sort -u)

# P5.4 剩余 40 路径同样必须精确冻结；三组并集必须等于当前 109-path 工作集。
p54_rust_manifest=(
  agentdeckd/src/runtime/store/cipher.rs
  agentdeck-crypto/src/lib.rs
  agentdeck-crypto/src/pairing.rs
  agentdeck-crypto/tests/golden_vectors.rs
  agentdeck-crypto/tests/pairing_v1_crypto.rs
  agentdeck-protocol/src/e2ee/context.rs
  agentdeck-protocol/src/e2ee/mod.rs
  agentdeck-protocol/src/e2ee/pairing.rs
  agentdeck-protocol/src/e2ee/pairing_control.rs
  agentdeck-protocol/src/e2ee/schema.rs
  agentdeck-protocol/src/relay_v2/failure.rs
  agentdeck-protocol/src/relay_v2/mod.rs
  agentdeck-protocol/tests/pairing_v1_contract.rs
  agentdeck-protocol/tests/relay_v2_contract.rs
  agentdeck-relay/src/v2/auth/access.rs
  agentdeck-relay/src/v2/core/pair_route.rs
  agentdeck-relay/src/v2/core/writer.rs
  agentdeck-relay/src/v2/server/connection.rs
  agentdeck-relay/tests/relay_v2_auth_e2e.rs
  agentdeck-relay/tests/relay_v2_tls_e2e.rs
  agentdeckd/Cargo.toml
  agentdeckd/src/remote/bootstrap.rs
  agentdeckd/src/remote/pairing.rs
  agentdeckd/src/remote/pairing_tests.rs
  agentdeckd/src/remote/transport.rs
  agentdeckd/src/runtime/model.rs
  agentdeckd/src/runtime/store/pairing.rs
  agentdeckd/src/runtime/store/pairing_grant_allocation_tests.rs
  agentdeckd/src/runtime/store/pairing_terminal.rs
  agentdeckd/src/runtime/store/pairing_terminal_tests.rs
  agentdeckd/src/runtime/store/worker.rs
  protocol/agentdeck/crypto-vectors-v1.json
  protocol/agentdeck/e2ee-v1.schema.json
  protocol/agentdeck/fixtures/relay-v2-wire-vectors.json
)
p54_docs_manifest=(
  ARCHITECTURE.md
  README.md
  docs/AGENT_DIAGNOSTICS.md
  docs/QUALITY.md
  docs/index.md
  docs/plans/2026-07-10-relay-companion-mvp-implementation.md
)
p54_all_manifest=(
  "${p54_rust_manifest[@]}"
  "${p54_swift_manifest[@]}"
  "${p54_docs_manifest[@]}"
)
test "${#p54_rust_manifest[@]}" -eq 34
test "${#p54_docs_manifest[@]}" -eq 6
test "${#p54_all_manifest[@]}" -eq 109
for file in "${p54_all_manifest[@]}"; do test -f "$file" || exit 1; done
diff \
  <(printf '%s\n' "${p54_all_manifest[@]}" | sort -u) \
  <({ git diff --name-only HEAD; git ls-files --others --exclude-standard; } | sort -u)

# 这 4 个既有大文件沿用已提交的 4-space 风格，避免为 P5.4 制造整文件缩进 churn；
# 其余 65 个文件使用当前 swift-format 默认配置。两组并集仍必须精确等于上面的 69-path manifest。
p54_swift_four_space_compat=(
  Sources/AgentDeckRelayClient/Crypto/CanonicalCodec.swift
  Sources/AgentDeckRelayClient/Crypto/RelayCrypto.swift
  Sources/AgentDeckRelayClient/Wire/RelayV2Types.swift
  Tests/AgentDeckRelayClientTests/RelayV2WireTests.swift
)
p54_swift_default_manifest=()
for file in "${p54_swift_manifest[@]}"; do
  case "$file" in
    Sources/AgentDeckRelayClient/Crypto/CanonicalCodec.swift | \
      Sources/AgentDeckRelayClient/Crypto/RelayCrypto.swift | \
      Sources/AgentDeckRelayClient/Wire/RelayV2Types.swift | \
      Tests/AgentDeckRelayClientTests/RelayV2WireTests.swift) ;;
    *) p54_swift_default_manifest+=("$file") ;;
  esac
done
test "${#p54_swift_default_manifest[@]}" -eq 65
test "$((${#p54_swift_default_manifest[@]} + ${#p54_swift_four_space_compat[@]}))" -eq 69
swift format lint --strict "${p54_swift_default_manifest[@]}"
swift format lint --strict --configuration '{"indentation":{"spaces":4}}' \
  "${p54_swift_four_space_compat[@]}"

# production 边界与文档；下列 rg 期望无输出
rg -n '@preconcurrency|nonisolated\(unsafe\)|URLSession|import Network' \
  Sources/AgentDeckRelayClient/Connection \
  Sources/AgentDeckRelayClient/Source \
  Sources/AgentDeckRelayClient/Streaming
rg -n 'RuntimeEnvelopeV2|SignedSealedBlobV1|rawEnvelope|sealedBlob' \
  Sources/AgentDeckRelayClient/Source/{CatalogReducer,ConversationReducer,InboxReducer,RelayConversationResumeCoordinator,RelaySessionSource}.swift
scripts/verify-agent-docs.sh
git diff --check

# 两笔 scoped commit 都必须在正式 index 上复核；禁止目录级 git add。
# 第一笔暂存后传 p54_rust_manifest；提交并清空 index 后，第二笔传 Swift + docs manifest。
verify_p54_staged_manifest() {
  diff \
    <(git diff --cached --name-only | sort -u) \
    <(printf '%s\n' "$@" | sort -u)
  git diff --cached --check
}
verify_p54_staged_manifest "${p54_rust_manifest[@]}"
# verify_p54_staged_manifest "${p54_swift_manifest[@]}" "${p54_docs_manifest[@]}"
```

automatic contract 必须覆盖：五条近 128 MiB owner 与 8,192/+1 global seam；part/final/tombstone
pre-allocation reserve 及全部 terminal release；10,000-event slow consumer、newest-one resource、512
conversation queue、64/+1 observer admission、lag generation + snapshot/barrier；cold/warm resume；scope/multi-
machine/shutdown join；outer→signature→replay→AEAD→Runtime→durable permit→reducer 顺序；forgery/rollback/
bad tag 零进展；exact-next key update、two-slot partial activation、30 秒 deadline、semantic ACK/proof/rebind/
reconnect；pending/live/historical request-route 唯一性、512/+1 cap，以及 cancel 无法安全注销时 exact generation
teardown。最后 observer 退出必须完成 Runtime receipt、Relay outer unsubscribe 与 correlation retirement；同
conversation replacement 在 single-flight retirement 返回前禁止且继续计容量。满 512 update queue 时 shutdown
必须先 finish channel 解锁第 513 个 pending producer，再 teardown/join，并保留恰好 512 条已入队前缀。
production pairing 必须在完整 durable staged promotion 后发送 byte-identical retriable receipt；marker 只有在
matching `PairRouteClosed` 后 committed 可见。exact-correlated `relay.route.not_found` 仍必须保留
responsePrepared + staged marker、零 committed mutation；marker-missing partial rollback 还必须覆盖 malformed 与
foreign-promotion CounterGuard 的零 mutation 反例，且公开源码不得暴露裸 `public func promote(` 写旁路。

Instruments 只做非门控 macOS smoke，不替代 10,000-event deterministic gate，也不产生可提交 artifact。
2026-07-27 的 `Allocations` trace 启动 `dist/AgentDeck.app --selfcheck`，target exit 0、duration
`2.639832s`，trace 为 `/tmp/agentdeck-p54-instruments.rt5Mo5/p54-agentdeck-selfcheck.trace`（约 7.5 MiB）。
可用 `xcrun xctrace export --input <trace> --toc` 读回；`.trace` 必须留在 `/tmp`，不得加入 Git。

**P5.4 automatic 收口证据（2026-07-27）：** 69-path Swift code/test candidate SHA-256 为
`42f47dc2eecfcd0ca312b9178583246aad48b9f59d6413fc9814052cb7e1cd1c`；Rust/fixture candidate
SHA-256 为 `4815d82628992281c3e1e032c91364080237ca34e6d94398d376b75ec1f7c30f`。fresh discovery
`225`，P5.4 warnings-as-errors `225/225`，RelayClient `429 executed / 4 entitlement SKIP / 0 failure`，
strict target build PASS，完整 Swift `958 XCTest / 4 SKIP + 35 Swift Testing`，iOS Simulator `26/26`。
首轮 Simulator 准确暴露 `URLFileProtection` 与 `FileProtectionType` raw-value alias 不同；production setter/
hook 改为显式语义映射、readback 改为同类型比较后，macOS exact `14/14` 与 Simulator 全量重跑均通过。
paired-store test 还把当前 `ADPR`/`ADPM` version byte 精确降为 v1，读回必须 `invalidRecord` 且
Keychain mutation 为 0，锁定 pre-MVP hard cutover 的 fail-closed 行为。
同一未变 Rust candidate 上的 `RUSTC_WRAPPER= cargo test --locked --quiet -- --test-threads=1` exit 0（CLI lib
`199/199`、daemon discovery `1677`、daemon lib `1674 passed / 3 ignored`、Store 慢组 `81/81`、256 MiB
慢项 `5/5`），Relay `server,tls`、cross-language crypto、四 schema、
Clippy、fmt、network/no-net、local Runtime smoke、ephemeral selfcheck 与 diagnostics 均通过。提交拓扑固定为
`34 Rust/fixture → 69 Swift + 6 docs` 的有序依赖栈：第一笔只承诺 Rust scoped-green，第二笔必须以前者为父，
完整门禁与 109-path 证据只属于组合候选。P5.4 收口时 P5 为 4/9；后续 P5.5、P5.6 与 P5.7 已分别独立完成。
P5.8–P5.9 与 P5 Phase Exit 是 automatic 必做项，当前仍未完成；真实公网 WSS、production-signed Keychain、
物理 iPhone、第二台 Mac、真实 vendor 与 destructive purge 才继续属于 post-MVP `BLOCKED`。

## Relay Companion MVP P5.5 canonical fixture / receipt UI 门禁

P5.5 只验收旧 iOS `MobileSessionSource`/models 到共享 `SessionSource` 的迁移、Core canonical reducer 下沉、
canonical fixture 与 ViewModel receipt/乱序/fatal 状态语义，以及这条链路依赖的 Runtime v5 Error 唯一终态
契约。它不验收 `SceneDelegate` 的发行 composition、真实 pairing/lifecycle、AppKit registry、Simulator
Relay E2E 或任何外部设备/公网槽位。

本 Task 的 exact scope 为 52 个 code/test/fixture path + 10 个 tracked docs path = 62 paths。code/test/fixture
content manifest 使用 `blob <git hash-object> <path>` 或 `deleted <path>` 的 C-locale 排序文本计算，SHA-256 固定为
`8dd8610966430a5cf640617da53e34d91bf379fe0ad495ea2ef719a6fec9d5ba`；tracked docs 不进入该 hash，避免文档
记录自身造成自引用。

```bash
p55_code_manifest=(
  Sources/AgentDeck/RuntimeConversationState.swift
  Sources/AgentDeck/RuntimeModelProjection.swift
  Sources/AgentDeck/ThreadRuntimeModel.swift
  Sources/AgentDeckCore/Protocol/RuntimeV2StreamTypes.swift
  Sources/AgentDeckCore/RuntimeConversationState.swift
  Sources/AgentDeckCore/RuntimeModelProjection.swift
  Sources/AgentDeckRelayClient/Source/ConversationReducer.swift
  Tests/AgentDeckRelayClientTests/RelaySessionSourceTests.swift
  Tests/AgentDeckTests/RuntimeCanonicalProjectionTests.swift
  Tests/AgentDeckTests/RuntimeConversationStateTests.swift
  Tests/AgentDeckTests/RuntimeV2StreamProtocolTests.swift
  Tests/AgentDeckTests/ThreadRuntimeModelCanonicalTests.swift
  agentdeck-protocol/src/runtime/event.rs
  agentdeck-protocol/tests/runtime_v2_contract.rs
  agentdeckd/src/agent.rs
  agentdeckd/src/codex/runtime_translate_tests.rs
  agentdeckd/src/runtime/conversation.rs
  agentdeckd/src/runtime/store/execution_event.rs
  agentdeckd/src/runtime/store/journal.rs
  agentdeckd/tests/runtime_store_execution_event.rs
  agentdeckd/tests/runtime_store_execution_event_tamper.rs
  agentdeckd/tests/runtime_store_legacy_terminal.rs
  agentdeckd/tests/support/runtime_event_tamper.rs
  ios/AgentDeckMobile/DataSource/FixtureFormat.swift
  ios/AgentDeckMobile/DataSource/FixtureSessionSource.swift
  ios/AgentDeckMobile/DataSource/MobileSessionModels.swift
  ios/AgentDeckMobile/DataSource/MobileSessionSource.swift
  ios/AgentDeckMobile/Screens/Inbox/InboxViewController.swift
  ios/AgentDeckMobile/Screens/Inbox/InboxViewModel.swift
  ios/AgentDeckMobile/Screens/MachineList/MachineListViewController.swift
  ios/AgentDeckMobile/Screens/MachineList/MachineListViewModel.swift
  ios/AgentDeckMobile/Screens/SessionDetail/Cells/ApprovalCardCell.swift
  ios/AgentDeckMobile/Screens/SessionDetail/Cells/UserPromptCell.swift
  ios/AgentDeckMobile/Screens/SessionDetail/MobileInputBarView.swift
  ios/AgentDeckMobile/Screens/SessionDetail/SessionDetailViewController.swift
  ios/AgentDeckMobile/Screens/SessionDetail/SessionDetailViewModel.swift
  ios/AgentDeckMobile/Screens/SessionList/SessionListViewController.swift
  ios/AgentDeckMobile/Screens/SessionList/SessionListViewModel.swift
  ios/AgentDeckMobileTests/ApprovalCardPresentationTests.swift
  ios/AgentDeckMobileTests/CoreLinkTests.swift
  ios/AgentDeckMobileTests/FixtureDecodingTests.swift
  ios/AgentDeckMobileTests/FixtureSessionSourceTests.swift
  ios/AgentDeckMobileTests/InboxViewModelTests.swift
  ios/AgentDeckMobileTests/MachineListViewModelTests.swift
  ios/AgentDeckMobileTests/SessionDetailViewModelTests.swift
  ios/AgentDeckMobileTests/SessionListViewModelTests.swift
  ios/AgentDeckMobileTests/SessionSourceSpy.swift
  ios/Fixtures/deck.json
  ios/Fixtures/stream-approval-01.json
  ios/Fixtures/stream-cc-01.json
  ios/Fixtures/stream-codex-01.json
  ios/Fixtures/stream-failed-01.json
)
p55_docs_manifest=(
  AGENTS.md
  ARCHITECTURE.md
  README.md
  docs/AGENT_DIAGNOSTICS.md
  docs/QUALITY.md
  docs/RELAY_RUNBOOK.md
  docs/index.md
  docs/plans/2026-07-03-ios-uikit-frontend-design.md
  docs/plans/2026-07-10-relay-companion-mvp-design.md
  docs/plans/2026-07-10-relay-companion-mvp-implementation.md
)
p55_all_manifest=("${p55_code_manifest[@]}" "${p55_docs_manifest[@]}")
test "${#p55_code_manifest[@]}" -eq 52
test "${#p55_docs_manifest[@]}" -eq 10
test "${#p55_all_manifest[@]}" -eq 62
diff \
  <(printf '%s\n' "${p55_all_manifest[@]}" | LC_ALL=C sort -u) \
  <({ git diff --name-only --no-renames HEAD; git ls-files --others --exclude-standard; } | LC_ALL=C sort -u)

p55_candidate_hash="$({
  for manifest_item in "${p55_code_manifest[@]}"; do
    if test -e "$manifest_item"; then
      printf 'blob %s %s\n' "$(git hash-object "$manifest_item")" "$manifest_item"
    else
      printf 'deleted %s\n' "$manifest_item"
    fi
  done
} | LC_ALL=C sort | shasum -a 256 | awk '{print $1}')"
test "$p55_candidate_hash" = \
  8dd8610966430a5cf640617da53e34d91bf379fe0ad495ea2ef719a6fec9d5ba

# 只在所有门禁与独立终审通过后执行；禁止目录级 git add。
git add -- "${p55_all_manifest[@]}"
diff \
  <(printf '%s\n' "${p55_all_manifest[@]}" | LC_ALL=C sort -u) \
  <(git diff --cached --name-only --no-renames | LC_ALL=C sort -u)
git diff --cached --check
```

```bash
# Runtime Error wire + daemon producer/store integrity
RUSTC_WRAPPER= cargo test -p agentdeck-protocol --test runtime_v2_contract
RUSTC_WRAPPER= cargo test -p agentdeckd --lib \
  fatal_adapter_completion_writes_one_store_owned_failed_terminal
RUSTC_WRAPPER= cargo test -p agentdeckd --test runtime_store_execution_event -- \
  --test-threads=1
RUSTC_WRAPPER= cargo test -p agentdeckd --test runtime_store_execution_event_tamper -- \
  --test-threads=1
RUSTC_WRAPPER= cargo test -p agentdeckd --test runtime_store_legacy_terminal -- \
  --test-threads=1
RUSTC_WRAPPER= cargo test -p agentdeckd

# Core、Relay、macOS 与 Swift wire mirror：先 discovery，再 warnings-as-errors focused
RUSTC_WRAPPER= swift test list | \
  rg 'RuntimeCanonicalProjectionTests|RuntimeConversationStateTests|RuntimeV2StreamProtocolTests|ThreadRuntimeModelCanonicalTests|RelaySessionSourceTests'
RUSTC_WRAPPER= swift test -Xswiftc -warnings-as-errors \
  --filter 'RuntimeCanonicalProjectionTests|RuntimeConversationStateTests|RuntimeV2StreamProtocolTests|ThreadRuntimeModelCanonicalTests|RelaySessionSourceTests'

# 顶层共享回归；当前为 980 XCTest / 4 skipped + 35 Swift Testing / 0 failure
RUSTC_WRAPPER= swift test

# iOS fresh DerivedData 全量与三组重点 suite
cd ios
P55_DERIVED_DATA="$(mktemp -d /tmp/agentdeck-p55-derived-data.XXXXXX)"
xcodegen generate
xcodebuild -project AgentDeckMobile.xcodeproj -scheme AgentDeckMobile \
  -destination 'platform=iOS Simulator,name=iPhone 17' \
  -derivedDataPath "$P55_DERIVED_DATA" test
xcodebuild -project AgentDeckMobile.xcodeproj -scheme AgentDeckMobile \
  -destination 'platform=iOS Simulator,name=iPhone 17' \
  -derivedDataPath "$P55_DERIVED_DATA" \
  -only-testing:AgentDeckMobileTests/SessionDetailViewModelTests test
xcodebuild -project AgentDeckMobile.xcodeproj -scheme AgentDeckMobile \
  -destination 'platform=iOS Simulator,name=iPhone 17' \
  -derivedDataPath "$P55_DERIVED_DATA" \
  -only-testing:AgentDeckMobileTests/FixtureSessionSourceTests test
xcodebuild -project AgentDeckMobile.xcodeproj -scheme AgentDeckMobile \
  -destination 'platform=iOS Simulator,name=iPhone 17' \
  -derivedDataPath "$P55_DERIVED_DATA" \
  -only-testing:AgentDeckMobileTests/MachineListViewModelTests \
  -only-testing:AgentDeckMobileTests/SessionListViewModelTests \
  -only-testing:AgentDeckMobileTests/InboxViewModelTests test
cd ..

swift format lint --strict \
  ios/AgentDeckMobile/Screens/SessionDetail/SessionDetailViewModel.swift \
  ios/AgentDeckMobileTests/SessionDetailViewModelTests.swift
swift format lint --strict --configuration '{"indentation":{"spaces":4}}' \
  ios/AgentDeckMobile/DataSource/FixtureSessionSource.swift \
  ios/AgentDeckMobileTests/FixtureSessionSourceTests.swift
for fixture in ios/Fixtures/deck.json \
  ios/Fixtures/stream-approval-01.json \
  ios/Fixtures/stream-cc-01.json \
  ios/Fixtures/stream-codex-01.json \
  ios/Fixtures/stream-failed-01.json; do
  jq empty "$fixture"
done
cargo fmt --all -- --check
RUSTC_WRAPPER= bash scripts/check-daemon-no-net.sh
RUSTC_WRAPPER= cargo run -q -p agentdeck-cli -- protocol schema \
  | diff - protocol/agentdeck/agentdeck-protocol.schema.json
# hermetic 自动门禁：自行启动隔离的 ephemeral/no-remote shared daemon
RUSTC_WRAPPER= bash scripts/run-local-runtime-smoke.sh
# 仅当当前账号的 canonical shared daemon 已运行时，才额外执行直接 UDS selfcheck；该命令不会自行 spawn daemon
# RUSTC_WRAPPER= cargo run -p agentdeck-cli -- selfcheck
scripts/verify-agent-docs.sh
git diff --check
```

必须覆盖以下反例，不能只验证顺序到达的 happy path：

- fixture 首帧是 canonical snapshot，初始 connection 为 connected；512 overflow 后旧 subscriber 收到 lagged
  并终止，late subscriber 从 fresh snapshot 连续恢复；审批精确校验 turnID/approvalID，并依次发布
  Claimed → Applying → Applied。
- Core/Relay reducer 都拒绝同一 turn 内并行 pending 或 resolution 后以新 approvalID 重用 requestID；失败时
  cursor、pending 与 resolution ledger 必须零漂移。pending + resolved identity 合计最多 32；必须覆盖
  `31 resolved + 1 pending`、第 33 个原子拒绝及 overflow 后 ledger 不变。`.at(H)` snapshot 后首个 lifecycle
  可直接 resolution 或 terminal，但一次 mid-turn inference 消费后必须重新 `turnStarted`。
- commandless Error 只记录 diagnostic，active turn、streaming、queued prompt 与 inbox 均不得终态化；其后
  Item/Completed 仍合法。command-bound Error 只接受 fixed
  `daemon.runtime.execution_failed / agent execution failed / diagnosticRef=null`，必须收口 exact active command
  或消费一次 snapshot baseline，并执行 unresolved approval gate；wrong command、重复 terminal、错误 tuple
  都原子拒绝。fatal adapter completion 只写一条 Store-owned terminal Error，startup audit 拒绝历史
  nonterminal command-bound Error。
- prompt single-flight；transport-unknown 同文本重用 idempotency key；receipt commandID 精确过滤；canonical
  user item 到达前保留 pending row，到达后只替换同 commandID，不重复插入。若 matching canonical Failed
  先于 accepted/replayed receipt 到达且没有 user item，迟到 receipt 必须立即收敛为 failed、恢复 draft 并允许
  下一次 prompt，不能永久留下 queued row；上一 command 的 Completed/Interrupted/Failed terminal 不得消费
  下一 prompt 的 Accepted/Replayed receipt。
- approval transport-unknown 只以同决定、同 key 重试；Applied/DeliveryFailed/Expired receipt 先到时，迟到
  Claimed/Applying canonical 不得回退 UI；DeliveryFailed → Applying 只有在 canonical 已看到该 failure 后才算
  新 retry round。fresh recovery snapshot 不得清 context/receipt/retry/in-flight operation/terminal floor；
  transition baseline 跨 generation 单调，lagged snapshot 成功后恢复 connected。重放相同 approvalID 但
  turn/command/request 不同必须 security fail-close，恢复前 DeliveryFailed floor 可被合法 Applied/Expired 覆盖。
  resolve/retry 必须绑定 canonical event-seq fence，retry 只能由 fence 后的新 Applying 推进；canonical 先终态时
  最多保留 32 条 retired-operation 证据继续校验迟到 receipt。新 turn 只有在旧投影为 Applied、Expired 或等价
  terminal AlreadyHandled 时才能清理；pending/submitting/submissionFailed/deliveryFailed 必须 fail-close。
  `.at(H)` snapshot 后首帧 direct turn terminal 同样不能绕过该门禁或留下可点击旧卡。
- bare Expired receipt 只对应 Pending 无 winner 过期，显示 `.expired(nil)`；已 claim 的过期必须由
  `AlreadyHandled(winner, Expired)` 携带赢家。bare Expired 后出现 canonical winner、receipt approvalID、
  canonical identity 或双方 winner 不一致必须 security fail-close。
- `.revoked`、`.incompatible`、`.securityError` 无论从 observation、prompt 还是 approval failure 到达，都取消
  observation/command/approval task 并进入不可逆终态；之后不得再发 prompt 或审批。
- Machine/Session/Inbox 的 retryable `.failed` 必须清空旧 ready rows/groups、保留 typed failure，并精确触发
  一次 `onUpdate`；不能让可重试标记把旧数据继续显示成 ready。fixture 的单条 command-bound Failed 也只能
  推进一次资源 revision，不能因 inbox append 再重复广播。

新 Core/Relay 文件以及重写后的 `SessionDetailViewModel.swift`、对应 tests 与 `SessionSourceSpy.swift` 沿用
2-space strict format；既有 UIKit controller/cell/input 与 fixture source/tests 沿用 4-space strict 配置。
`RuntimeV2StreamTypes.swift` 与 `RuntimeV2StreamProtocolTests.swift` 只允许 legacy 4-space baseline 不增加，不得
递归格式化无关旧文件。fixture 仍只允许 preview/test，pair/revoke 返回 typed refusal；P5.5 candidate 当时
未修改 `SceneDelegate` composition root，该缺口已由后续 P5.6 独立收口，不能倒算为 P5.5 证据。

**P5.5 automatic 收口证据（2026-07-27）：** 顶层 `swift test` 为
`980 XCTest / 4 skipped + 35 Swift Testing / 0 failure`，warnings-as-errors focused 为 `91/91`；
Runtime protocol `51/51`、fatal producer `1/1`、execution event `10/10`、tamper `8/8`、legacy terminal
`4/4`；完整 daemon package 使用默认并发运行，lib `1674 passed / 3 ignored / 0 failed`、main `7/7`，
其余 integration/doc-test target 均 exit 0，`runtime_store_boundaries` 为 `5/5`。fresh DerivedData iOS
Simulator 为 `91/91`，其中 SessionDetail `55/55`、FixtureSessionSource `10/10`、Machine/Session/Inbox
ViewModel 合计 `10/10`。schema、fmt、no-net、agent docs、hermetic local Runtime smoke 与 diff 门禁均重跑通过。
P5.5 收口时 P5 为 5/9，P5.6–P5.9 与 P5 Phase Exit 尚未完成；后续 P5.6 与 P5.7 已分别独立收口。
真实公网 WSS、production-signed Keychain、物理 iPhone、第二台 Mac 与真实 Codex/Claude Code vendor
继续 post-MVP `BLOCKED`，不计 PASS。

## Relay Companion MVP P5.6 iOS production composition / pairing lifecycle 门禁

P5.6 只验收 iOS Release composition、完整邀请的扫码/粘贴与确认流程、paired-material 本机管理，以及
foreground/background source lifecycle。它复用 P5.4 已实现的 production pairing/crypto/receipt handler；
不把 fake transport、Debug fixture 或 Simulator UI 测试描述成 P5.9 的真实 Relay/daemon 编排。

本次 P5.6 iOS/docs closeout exact scope 为 11 个 iOS code/test path + 10 个 tracked docs path = 21 paths。
pairing replacement/source shutdown 的前置 hardening 已单独提交为 `5574b00`，修改 6 个 RelayClient
production/test 路径，不进入本次 diff；shutdown `56/56` 是 parent + candidate 的组合证据。code/test content
manifest 以 C-locale 排序的 `blob <git hash-object> <path>` 文本计算，SHA-256 固定为
`8cf47be71709bcd4648341eaa5cd7b693a00f6e871dfb586fbda76ee8662a2fb`；tracked docs 不进入 hash，避免自引用。

```bash
p56_code_manifest=(
  ios/AgentDeckMobile/App/CompositionRoot.swift
  ios/AgentDeckMobile/App/SceneDelegate.swift
  ios/AgentDeckMobile/Screens/MachineList/MachineListViewController.swift
  ios/AgentDeckMobile/Screens/Pairing/PairingViewController.swift
  ios/AgentDeckMobile/Screens/Pairing/PairingViewModel.swift
  ios/AgentDeckMobile/Screens/Pairing/QRCodeScannerViewController.swift
  ios/AgentDeckMobileTests/AppLifecycleTests.swift
  ios/AgentDeckMobileTests/PairingViewControllerTests.swift
  ios/AgentDeckMobileTests/PairingViewModelTests.swift
  ios/AgentDeckMobileTests/SessionSourceSpy.swift
  ios/project.yml
)
p56_docs_manifest=(
  AGENTS.md
  ARCHITECTURE.md
  README.md
  docs/AGENT_DIAGNOSTICS.md
  docs/QUALITY.md
  docs/RELAY_RUNBOOK.md
  docs/index.md
  docs/plans/2026-07-03-ios-uikit-frontend-design.md
  docs/plans/2026-07-10-relay-companion-mvp-design.md
  docs/plans/2026-07-10-relay-companion-mvp-implementation.md
)
p56_all_manifest=("${p56_code_manifest[@]}" "${p56_docs_manifest[@]}")
test "${#p56_code_manifest[@]}" -eq 11
test "${#p56_docs_manifest[@]}" -eq 10
test "${#p56_all_manifest[@]}" -eq 21
diff \
  <(printf '%s\n' "${p56_all_manifest[@]}" | LC_ALL=C sort -u) \
  <({ git diff --name-only --no-renames HEAD; git ls-files --others --exclude-standard; } | LC_ALL=C sort -u)

p56_candidate_hash="$({
  for manifest_item in "${p56_code_manifest[@]}"; do
    printf 'blob %s %s\n' "$(git hash-object "$manifest_item")" "$manifest_item"
  done
} | LC_ALL=C sort | shasum -a 256 | awk '{print $1}')"
test "$p56_candidate_hash" = \
  8cf47be71709bcd4648341eaa5cd7b693a00f6e871dfb586fbda76ee8662a2fb

# 只在 fresh gates 与独立终审通过后执行；禁止目录级 git add。
git add -- "${p56_all_manifest[@]}"
diff \
  <(printf '%s\n' "${p56_all_manifest[@]}" | LC_ALL=C sort -u) \
  <(git diff --cached --name-only --no-renames | LC_ALL=C sort -u)
git diff --cached --check
```

```bash
# Pairing UI + lifecycle（fresh DerivedData）
cd ios
P56_DERIVED_DATA="$(mktemp -d /tmp/agentdeck-p56-derived-data.XXXXXX)"
xcodegen generate
RUSTC_WRAPPER= xcodebuild -quiet \
  -project AgentDeckMobile.xcodeproj -scheme AgentDeckMobile \
  -destination 'platform=iOS Simulator,name=iPhone 17' \
  -derivedDataPath "$P56_DERIVED_DATA" test
RUSTC_WRAPPER= xcodebuild -quiet \
  -project AgentDeckMobile.xcodeproj -scheme AgentDeckMobile \
  -destination 'platform=iOS Simulator,name=iPhone 17' \
  -derivedDataPath "$P56_DERIVED_DATA" \
  -only-testing:AgentDeckMobileTests/PairingViewModelTests \
  -only-testing:AgentDeckMobileTests/PairingViewControllerTests \
  -only-testing:AgentDeckMobileTests/AppLifecycleTests test

# Release 必须没有 fixture 降级 surface
P56_RELEASE_DERIVED="$(mktemp -d /tmp/agentdeck-p56-release.XXXXXX)"
RUSTC_WRAPPER= xcodebuild -quiet \
  -project AgentDeckMobile.xcodeproj -scheme AgentDeckMobile \
  -configuration Release -destination 'generic/platform=iOS Simulator' \
  -derivedDataPath "$P56_RELEASE_DERIVED" build
P56_RELEASE_BINARY="$P56_RELEASE_DERIVED/Build/Products/Release-iphonesimulator/AgentDeckMobile.app/AgentDeckMobile"
test -x "$P56_RELEASE_BINARY"
! strings "$P56_RELEASE_BINARY" | \
  rg -- '--agentdeck-fixture-source|installFixtureSource|usesFixtureSource'
cd ..

# 2-space 组与 4-space compatibility 组按下面两条命令分别检查；禁止整树重排。
swift format lint --strict \
  ios/AgentDeckMobile/Screens/Pairing/PairingViewController.swift \
  ios/AgentDeckMobile/Screens/Pairing/PairingViewModel.swift \
  ios/AgentDeckMobileTests/PairingViewControllerTests.swift \
  ios/AgentDeckMobileTests/PairingViewModelTests.swift \
  ios/AgentDeckMobileTests/SessionSourceSpy.swift
swift format lint --strict --configuration '{"indentation":{"spaces":4}}' \
  ios/AgentDeckMobile/App/CompositionRoot.swift \
  ios/AgentDeckMobile/App/SceneDelegate.swift \
  ios/AgentDeckMobile/Screens/MachineList/MachineListViewController.swift \
  ios/AgentDeckMobile/Screens/Pairing/QRCodeScannerViewController.swift \
  ios/AgentDeckMobileTests/AppLifecycleTests.swift

# 共享 client、shutdown hardening 与顶层回归
RUSTC_WRAPPER= swift test --filter \
  'ProductionRelayPairingCommandHandlerTests|RelayRuntimeCommandClientTests|RelaySessionSourceTests'
RUSTC_WRAPPER= swift test --filter AgentDeckRelayClientTests
RUSTC_WRAPPER= swift test
swift build --target AgentDeckRelayClient -Xswiftc -warnings-as-errors

scripts/verify-agent-docs.sh
git diff --check
```

必须覆盖以下反例与完成边界：

- Release 普通启动固定走
  `CompositionRoot.production → PairedMachineStore(.iOSApp) → RelaySessionSource(.allPairedMachines)`；
  fixture 参数、解析与安装入口只在 `#if DEBUG`，Release binary 中三条 fixture 字符串均为零命中。
- scene callback 同步 capture intent revision，单一 FIFO worker fulfillment；background 必须取消 opening、
  shutdown/join source 与 WSS，旧 generation 完整退出前不得 cold-open replacement，迟到 foreground 不得覆盖
  较新 background。
- 只接受 8 KiB 内完整 `agentdeck-pair:v1:`；短 PIN/畸形邀请在本地拒绝，inspect/trust preview 与用户确认前
  零 pairing 网络。retry 复用 exact invite，replacement 先 cancel/close/join 旧 worker/WSS。
- `AVCaptureSession` 配置/start/stop 只在专用串行队列执行；只有 view visible + scene active 才持有 UUID，
  scene deactivation 同步失效并排队 stop，reactivation 产生新 generation。permission、start completion、
  metadata proxy 与 stop 全部携带 exact UUID；proxy 保留到 metadata queue barrier 后，旧 callback/stop 即使
  迟到也不能提交邀请或停止新 generation。
- pairing task-slot 清理绑定 exact operation ID；旧 `pair()` 在返回 stream 前迟到 CancellationError 不得 ABA
  清除新 task，页面关闭仍必须取消 replacement stream。
- `.committed` revoke receipt 不删本机材料；generation-bound `CompositionRoot` 常驻观察 verified `.revoked`
  terminal 后才删除 exact record，不能依赖配对页仍打开。local forget 每层确认都重查离线资格；重连取消 flow、
  释放 presentation gate，并让任何迟到 destructive-alert retry 重新核对 exact state + gate ownership。
- Application Support 固定 `AgentDeck/clients/ios-app`，installation UUID canonical/nonzero/不静默轮换，目录与
  identity file 保持 0700/0600、Complete protection 与 backup exclusion。Simulator 不能替代物理 iPhone
  locked/unlocked data-protection readback。

**P5.6 automatic 收口证据（2026-07-28）：** PairingViewModel `15/15`、PairingViewController `7/7`、
AppLifecycle `20/20`，focused 合计 `42/42`；pre-stream ABA 单项重复 10 轮通过。fresh iOS Simulator
`133/133`；一次并行 xcodebuild 抢占同一 Simulator，FBS Busy 发生在建立测试连接前、零测试执行，随后
隔离串行重跑通过，不记作产品测试失败。
Relay shutdown focused `56/56`（handler `14`、command client `7`、session source `35`），RelayClient
`445 executed / 4 entitlement SKIP / 0 failure`，顶层 Swift
`985 XCTest / 4 skipped + 35 Swift Testing / 0 failure`。Release generic Simulator build、strict format、
fixture surface、agent docs 与 diff gates 通过。P5.6 收口时 P5 为 6/9；当时 P5.7–P5.9 与 P5 Phase Exit 未完成，真实
公网 WSS、production-signed Keychain、物理 iPhone、第二台 Mac、真实 vendor 与 destructive purge 继续
post-MVP `BLOCKED`。后续 P5.7 已独立收口，当前 P5 为 7/9；P5.8–P5.9 与 P5 Phase Exit 仍未完成。

## Relay Companion MVP P5.7 macOS SessionSource registry 门禁

P5.7 只验收 macOS 唯一本机 UDS source、按 machine 隔离的 remote source registry、typed local-only
capability、selected-scope generation 与 App termination shutdown/join barrier；并收口其依赖的 first-member
Genesis/business-ready hardening。它不验收 P5.8 的可见 AppKit machine picker、remote pairing/pending-device
approval/receipt UI，也不验收 P5.9 fixed-topology Simulator Relay E2E 或任何 post-MVP 外部门禁。

接管时原始 RED transcript 未保留，不补写不存在的失败记录；本 Task 采用 test discovery、冻结候选 fresh
focused 与完整回归作为完成证据。exact scope 为 63 个 code/test path + 7 个 tracked docs path = 70 paths，
提交拓扑固定为 `40-path prerequisite → 23-path macOS registry + 7 docs`。本地
`.superpowers/sdd/progress.md` 受 `.git/info/exclude` 管理，只同步 ledger，不强行入库。

两个 code/test content manifest 均按 C-locale 排序后计算 SHA-256。存在的路径编码为
`blob <git hash-object> <path>`，本 Task 中两个 move 源路径编码为 `deleted <path>`；tracked docs 不进入 hash，
避免 `QUALITY.md` 自引用。当前冻结值为：

- prerequisite 40-path：`85a46da6d79e56f6da1efd2e67b8851b1b264d7e796ded50334a7769b0af680f`
- macOS registry 23-path：`df38994a015d0bd7014618a75afb6988b9dfec926a19f92cc5e4c8843788bcf6`

```bash
p57_prerequisite_manifest=(
  Sources/AgentDeckRelayClient/Connection/MachineConnection.swift
  Sources/AgentDeckRelayClient/Connection/MachineConnectionUpdates.swift
  Sources/AgentDeckRelayClient/Connection/MachineRequestCorrelation.swift
  Sources/AgentDeckRelayClient/Connection/ProductionMachineConnectionVerifiedIngress.swift
  Sources/AgentDeckRelayClient/Crypto/KeyUpdateSetVerifier.swift
  Sources/AgentDeckRelayClient/Source/RelaySessionSource.swift
  Sources/AgentDeckRelayClient/Storage/DeviceCryptoState.swift
  Sources/AgentDeckRelayClient/Storage/DurableCryptoStateCoordinator.swift
  Sources/AgentDeckRelayClient/Streaming/BoundedBroadcaster.swift
  Sources/AgentDeckSessionSource/Streaming/BoundedBroadcaster.swift
  Tests/AgentDeckRelayClientTests/BoundedBroadcasterTests.swift
  Tests/AgentDeckRelayClientTests/DurableCryptoStateCoordinatorTests.swift
  Tests/AgentDeckRelayClientTests/KeyUpdateSetVerifierTests.swift
  Tests/AgentDeckRelayClientTests/MachineConnectionTests.swift
  Tests/AgentDeckRelayClientTests/MachineRequestCorrelationTests.swift
  Tests/AgentDeckRelayClientTests/ProductionMachineConnectionVerifiedIngressTests.swift
  Tests/AgentDeckRelayClientTests/RelaySessionSourceTests.swift
  Tests/AgentDeckSessionSourceTests/BoundedBroadcasterTests.swift
  agentdeckd/src/remote/key_control.rs
  agentdeckd/src/remote/manager.rs
  agentdeckd/src/remote/manager_tests.rs
  agentdeckd/src/remote/pairing.rs
  agentdeckd/src/remote/transition.rs
  agentdeckd/src/remote/transition_backend.rs
  agentdeckd/src/remote/transition_tests.rs
  agentdeckd/src/runtime/catalog_snapshot.rs
  agentdeckd/src/runtime/core.rs
  agentdeckd/src/runtime/core/subscription_tests.rs
  agentdeckd/src/runtime/store/key_transition.rs
  agentdeckd/src/runtime/store/key_transition/snapshot_permit.rs
  agentdeckd/src/runtime/store/pairing_authorization.rs
  agentdeckd/src/runtime/store/pairing_delivery_tests.rs
  agentdeckd/src/runtime/store/pairing_grant_allocation_tests.rs
  agentdeckd/src/runtime/store/pairing_grant_tx.rs
  agentdeckd/src/runtime/store/publication.rs
  agentdeckd/src/runtime/store/worker.rs
  agentdeckd/src/runtime/store/worker/key_transition_commands.rs
  agentdeckd/src/runtime/store/worker/stream_pipeline.rs
  agentdeckd/src/runtime/subscription/coordinator.rs
  agentdeckd/tests/relay_v2_machine_e2e.rs
)
p57_registry_manifest=(
  Package.swift
  Sources/AgentDeck/AppDelegate.swift
  Sources/AgentDeck/AppRuntimeCoordinator.swift
  Sources/AgentDeck/Preview/PreviewBootstrap.swift
  Sources/AgentDeck/SessionModel.swift
  Sources/AgentDeck/SessionSources/AppSessionSourceComposition.swift
  Sources/AgentDeck/SessionSources/LocalDaemonSessionSource+FailureMapping.swift
  Sources/AgentDeck/SessionSources/LocalDaemonSessionSource+RuntimeOperations.swift
  Sources/AgentDeck/SessionSources/LocalDaemonSessionSource.swift
  Sources/AgentDeck/SessionSources/LocalDaemonSessionSourceSupport.swift
  Sources/AgentDeck/SessionSources/SessionSourceRegistry.swift
  Sources/AgentDeck/WorkbenchModel.swift
  Sources/AgentDeck/main.swift
  Tests/AgentDeckTests/AppDelegateTerminationTests.swift
  Tests/AgentDeckTests/AppRuntimeCoordinatorTests.swift
  Tests/AgentDeckTests/LocalDaemonSessionSourceTests.swift
  Tests/AgentDeckTests/LocalRuntimeWireSessionTests.swift
  Tests/AgentDeckTests/MachineScopeRealIntegrationTests.swift
  Tests/AgentDeckTests/MachineScopeRoutingTests.swift
  Tests/AgentDeckTests/PreviewBootstrapTests.swift
  Tests/AgentDeckTests/SessionModelRuntimeReliabilityTests.swift
  Tests/AgentDeckTests/SessionSourceRegistryTests.swift
  Tests/AgentDeckTests/WorkbenchRuntimeV2Tests.swift
)
p57_docs_manifest=(
  ARCHITECTURE.md
  README.md
  docs/AGENT_DIAGNOSTICS.md
  docs/QUALITY.md
  docs/index.md
  docs/plans/2026-07-10-relay-companion-mvp-design.md
  docs/plans/2026-07-10-relay-companion-mvp-implementation.md
)
p57_all_manifest=(
  "${p57_prerequisite_manifest[@]}"
  "${p57_registry_manifest[@]}"
  "${p57_docs_manifest[@]}"
)
test "${#p57_prerequisite_manifest[@]}" -eq 40
test "${#p57_registry_manifest[@]}" -eq 23
test "${#p57_docs_manifest[@]}" -eq 7
test "${#p57_all_manifest[@]}" -eq 70
diff \
  <(printf '%s\n' "${p57_all_manifest[@]}" | LC_ALL=C sort -u) \
  <({ git diff --name-only --no-renames HEAD; git ls-files --others --exclude-standard; } | \
    LC_ALL=C sort -u)

p57_content_hash() {
  for manifest_item in "$@"; do
    if test -f "$manifest_item"; then
      printf 'blob %s %s\n' "$(git hash-object "$manifest_item")" "$manifest_item"
    else
      printf 'deleted %s\n' "$manifest_item"
    fi
  done | LC_ALL=C sort | shasum -a 256 | awk '{print $1}'
}
test "$(p57_content_hash "${p57_prerequisite_manifest[@]}")" = \
  85a46da6d79e56f6da1efd2e67b8851b1b264d7e796ded50334a7769b0af680f
test "$(p57_content_hash "${p57_registry_manifest[@]}")" = \
  df38994a015d0bd7014618a75afb6988b9dfec926a19f92cc5e4c8843788bcf6

# 只在 fresh gates 与双路独立终审通过后执行；禁止目录级 git add。
git add -- "${p57_prerequisite_manifest[@]}"
diff \
  <(printf '%s\n' "${p57_prerequisite_manifest[@]}" | LC_ALL=C sort -u) \
  <(git diff --cached --name-only --no-renames | LC_ALL=C sort -u)
git diff --cached --check
# 第一笔提交并确认 index 为空后，第二笔才暂存：
# git add -- "${p57_registry_manifest[@]}" "${p57_docs_manifest[@]}"
```

```bash
# Genesis 三个 durable cut + replay/activation/ACK 反例，discovery 必须恰好 6 项
swift test list --skip-build | \
  rg 'BootstrapEpochBarrier|BootstrapBarrier(ExactRetry|StaleCounter|FreshReseal)'
RUSTC_WRAPPER= swift test --skip-build --filter \
  'BootstrapEpochBarrier|BootstrapBarrier(ExactRetry|StaleCounter|FreshReseal)'

# macOS registry/routing/shutdown 与真实 dual-scope host integration
RUSTC_WRAPPER= swift test --skip-build --filter \
  'AppDelegateTerminationTests|LocalDaemonSessionSourceTests|MachineScopeRealIntegrationTests|MachineScopeRoutingTests|SessionSourceRegistryTests'
RUSTC_WRAPPER= swift test --skip-build --filter \
  'CatalogHandlerCanReenterSelect|InboxHandlerCanReenterShutdown|ShutdownCancelsAndJoinsBlockedPrompt|TerminationReplyWaitsForSessionModelOperationJoinBarrier|HandlerSpawnedCloseCannotInheritPumpIdentity|CloseWaitsForCancellationInsensitiveInboundHandler'
RUSTC_WRAPPER= swift test --skip-build --filter NoVendorBranchInUITests
RUSTC_WRAPPER= swift test -Xswiftc -warnings-as-errors

# 完整 Rust、运行态与协议边界
cargo test -p agentdeckd \
  production_actor_store_confirm_materializes_snapshot_then_retries_exactly_once \
  -- --nocapture --test-threads=1
cargo test -p agentdeckd remote::manager::tests -- --test-threads=1
RUSTC_WRAPPER= cargo test --locked --no-fail-fast -- --test-threads=1
RUSTC_WRAPPER= bash scripts/run-local-runtime-smoke.sh
RUSTC_WRAPPER= cargo run -p agentdeckd -- \
  --ephemeral --no-remote --profile dev --selfcheck
RUSTC_WRAPPER= swift run AgentDeck -- --diagnostics-report --json
cargo run -q -p agentdeck-cli --locked -- protocol schema \
  | diff - protocol/agentdeck/agentdeck-protocol.schema.json
cargo run -q -p agentdeck-cli --locked -- protocol runtime-schema \
  | diff - protocol/agentdeck/runtime-protocol.schema.json
cargo run -q -p agentdeck-cli --locked -- protocol relay-schema \
  | diff - protocol/agentdeck/relay-v2.schema.json
cargo run -q -p agentdeck-cli --locked -- protocol e2ee-schema \
  | diff - protocol/agentdeck/e2ee-v1.schema.json
cargo clippy -p agentdeckd --lib --no-deps -- -D warnings
cargo clippy -p agentdeckd --bin agentdeckd --no-deps -- -D warnings
cargo clippy -p agentdeckd --test relay_v2_machine_e2e --no-deps -- -D warnings
cargo fmt --all -- --check
bash scripts/check-daemon-network-boundary.sh
bash scripts/check-daemon-no-net.sh
scripts/verify-agent-docs.sh
git diff --check
```

必须覆盖以下反例与完成边界：

- 本机 scope 只复用一个 current Runtime v5 UDS source；每台 remote machine 固定独立
  `RelaySessionSource(.machine(id))`，本机流量不得绕 Relay。remote/fixture scope 不得取得
  `LocalPairingAdministration`，UI 不得通过 concrete source downcast 或 vendor branch 选择路径。
- selected scope replacement 必须先取消并 join 旧 observation/model/source generation；factory opening、失败重试、
  invalidate、shutdown 与迟到 completion 都不能 ABA 覆盖当前 scope。App termination 只在 composition 全部
  shutdown/join 后回复，且不得向共享 daemon 发送 shutdown。
- observation handler 内重入 `select`/`shutdown` 不得等待或取消自身 task；旧 observation 必须转入 retired
  集合，并由外部 shutdown barrier 最终 join。`SessionModel` 所有异步业务 task 必须进入唯一 operation registry；
  shutdown 停止 admission、cancel 并等待真实 terminal，不能遗漏 blocked prompt 等非结构化 task。
- Preview 必须显式注册 fixture scope 并参与 composition shutdown；`AppRuntimeCoordinator.close()` 必须捕获并
  join exact pump。同步失败先释放 gate，再 cancel/close/join；handler 派生 close 不得继承 pump identity 后
  跳过自身以外的 exact owner join。
- remote transport connected 不等于 business-ready。订阅只能在 exact connection ID + transport generation +
  transition readiness 全部匹配后开始；旧 ready progress、旧 correlation 或另一 machine 的事件不得串入。
- first-member `0 → 1` Genesis barrier 的 replay admission、activation 与 semantic/outer ACK 必须覆盖
  `stateGuardPendingDurable`、`stateDurable`、`guardStableDurable` 三个 crash cut。ACK permit 必须绑定 authority、
  route、generation、sequence、cursor、revision、epoch 与 hash；stale counter 必须零 durable mutation、零 transport
  action，fresh reseal 不得重新 mint ACK。
- active-conversation Genesis snapshot recovery 只在真实 actor/store confirm 返回 typed
  `daemon.runtime.snapshot_required` 时触发；RuntimeCore 只能 materialize Catalog 与缺失 conversation snapshot，
  每轮重新采样 H，最多恢复三轮。首次失败不得提交 grant/transition 或改写无关 durable state；非 snapshot
  failure 必须零 snapshot 写，第四次 prerequisite 原样返回。
- `LocalDaemonSessionSource` production 实现保持按职责拆分，当前四文件分别为 1,617/345/145/76 行，均低于
  1,800 行预拆线；不得为拆文件扩大 actor stored state 或 lease token 可见性。
- 真实 dual-scope integration 的 local 侧必须使用实际 UDS，remote 侧必须使用真实 P4 daemon RemoteLink；
  synthetic adapter 只代替 vendor，不代替 daemon/PairingCoordinator/RemoteLink，不能写成真实 vendor 或公网 E2E。

**P5.7 automatic 收口证据（2026-07-28）：** Genesis focused `6/6`；真实 actor/store snapshot recovery
`1/1`，manager 模块 `73/73`；macOS registry/routing/shutdown、真实 local UDS + P4 daemon RemoteLink integration
与 NoVendorBranchInUI focused 均通过。格式收紧后 fresh 顶层 Swift warnings-as-errors 为
`1061 XCTest / 4 skipped / 0 failure + 35 Swift Testing / 0 failure`，命令 exit 0。
完整 `RUSTC_WRAPPER= cargo test --locked --no-fail-fast -- --test-threads=1` exit 0：daemon lib
`1683 passed / 3 ignored / 0 failed`、main `7/7`、`runtime_store_boundaries` `5/5`，既有慢组
`remote_runtime_receipts` `81/81`、`remote_transfer_persistence` `6/6`、
`remote_transfer_paired_state` `7/7` 及其余 integration/doc-tests 全部通过。local Runtime smoke、ephemeral
selfcheck、diagnostics、四 schema、三组 scoped Clippy、fmt、network/no-net、39 个现存 changed Swift path
strict format（37 default + 2 个 4-space compatibility）、agent docs 与 diff 门禁均通过。stable
`swift run AgentDeck -- --selfcheck` 依赖当前账号 canonical daemon；socket 缺失会 typed 返回
`daemon.client.socket_missing`，本 Task 不把该现场前提伪记为 PASS。

前轮独立 `spec/security` 终审发现的 active-conversation Genesis snapshot recovery、observation handler 重入
self-join、`SessionModel` 非结构化 task join 与 Preview/AppRuntime exact-pump barrier 已逐项修复并加入反例。
最终 40-path prerequisite hash 与 23-path registry hash 已冻结；`spec/security`、`quality` 在最终 70-path
候选上的结论均为 `P0=0 / P1=0 / P2=0`。P5.7 已独立收口，P5 当前为 7/9。P5.8 可见 AppKit machine picker/remote pairing/receipt UI、
P5.9 fixed-topology Simulator Relay E2E 与 P5 Phase Exit 继续未完成；真实公网 WSS、production-signed Keychain、
物理 iPhone、第二台 Mac、真实 Codex/Claude Code vendor 与 destructive purge 继续 post-MVP `BLOCKED`，不计 PASS。

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

下表适用于独立改动以及 Relay Companion 的 Task 收口/Phase exit；Relay 内部子片不据此扩张门禁，
只运行该子片 focused tests + scoped clippy + fmt。Task/Phase 收口时再按表补齐完整矩阵。

| 变更范围 | 最小验证 |
| --- | --- |
| Rust daemon、IPC、Codex adapter、history list 性能、run record、diagnostics | `cargo test`；涉及运行态再跑 `swift run AgentDeck -- --selfcheck` |
| Swift UI、会话模型、历史回放、live session 侧栏可见性、富文本渲染、选择/滚动行为 | `swift test` |
| approval / action request / action decision | `cargo test approval`；`swift test --filter approval`；再跑完整 `cargo test`、`swift test`、`swift run AgentDeck -- --selfcheck` |
| 诊断日志、自检、数据目录、profile、密钥脱敏 | `cargo test`；stable Runtime 用 `swift run AgentDeck -- --selfcheck`；`swift run AgentDeck -- --diagnostics-report --json`；涉及旧 profile 日志时只加跑 `swift run AgentDeck -- --diagnostics-report --json --profile dev`，不得把 Runtime selfcheck 切回 dev namespace |
| 文档结构、AGENTS 入口、计划规则 | `scripts/verify-agent-docs.sh` |
| 协议 schema 或 app-server 方法 | `cargo test`；核对 `protocol/SPIKE_FINDINGS.md` 和 `protocol/CODEX_VERSION.txt` |
| agentdeck-protocol 类型变更 | `cargo test`（漂移测试自动运行）；若漂移测试失败须先重新生成快照（见下） |
| 参考客户端 CLI（agentdeck-cli）、Transport、Client | `cargo test -p agentdeck-cli`；再跑完整 `cargo test` |
| Relay Companion MVP P0 基线或 v1 reset | 迭代时跑 `bash scripts/tests/reset-relay-v1-dev-state.sh`；提交前跑一次 `bash scripts/verify-relay-companion-mvp.sh p0` |
| Relay Companion MVP P3.1 daemon namespace / singleton / StorageKEK | 运行本页 P3.1 聚焦矩阵、`cargo test -p agentdeckd`、CLI/Swift transport tests、daemon network-boundary；MVP 接受完整 dev/ephemeral 路径，provisioned signed helper 是 post-MVP BLOCKED 证据槽位，不计 PASS 但不阻塞 MVP/P3 exit |
| Relay Companion MVP P3.2/P3.3 Runtime SQLite / journal / adapter 私表 | 运行本页十四组 store/boundary tests（含真实 256 MiB、paged recovery 与 v1→v2 migration）、canonical router/双 adapter tests、默认并发 `cargo test -p agentdeckd`、daemon network-boundary、fmt/clippy/diff/docs；只证明组件，不冒充 RuntimeCore/UDS/Companion E2E |
| Relay Companion MVP P3.4 RuntimeCore / principal / actor | 运行本页 P3.4 Core+Store+Rust/Swift contract 矩阵、100 路 Start 竞态、daemon 全回归、network-boundary/fmt/clippy/diff/docs；该历史阶段用 disabled coordinator，只证明 Core contract，不能替代 P3.7 exec-gate 或 P3.8/P3.9 UDS E2E |
| Relay Companion MVP P3.5 approval CAS / delivery | 运行本页 P3.5 固定 16 项聚合 gate，并以 private schema/sqlite/store/permission/worker/actor fault tests 作为行为证据；补跑 adapter shape、Rust/Swift contract、daemon 全回归与静态边界。P3.5/legacy CC Approval 隐藏；P3.7 canonical typed builder 的 recorded fixture 也不冒充 live vendor E2E |
| Relay Companion MVP P3.6 canonical stream / snapshot / transfer | 运行本页 P3.6 Rust/Swift contract、`runtime_stream`、`runtime_transfer`、store v4/read-pool/snapshot、daemon-private `runtime::` 与完整 daemon 回归；补跑 fmt/network-boundary/diff/docs。fake sealed publication 只证明状态机，不冒充 P4 E2EE/Relay Publish、UDS 或 Companion E2E |
| Relay Companion MVP P3.7 exec-gate / typed production execution | 运行本页 prepare disposition、gate/recovery/driver/typed fixture/production wiring 矩阵、完整 daemon package、clippy/fmt/network-boundary/schema/docs/diff；固定 PATH、私有 FD、唯一 reaper、cooperative-descendant PGID fencing、COMMIT-unknown 与 reopen/backfill 必须有行为证据。显式自守护/逃逸不受支持，helper/fixture 不冒充 live vendor approval、UDS 或实机 E2E |
| Relay Companion MVP P3.8-A local Runtime UDS primitives | 运行本页 framing/peer、local-control/cancellation、真实双连接 `local_uds`、完整 daemon、fmt/clippy/network-boundary/docs/diff；只证明 accepted stream actor，不冒充 P3.8-B secure bind/permit、P3.9 App/CLI cutover 或 remote E2E |
| Relay Companion MVP P3.8-B production UDS/bootstrap | 运行本页 secure listener/permit/supervisor、config/stdio exhaustive allowlist、真实 binary lifecycle、Rust/Swift compatibility、完整 daemon、fmt/clippy/network-boundary/schema/docs/diff；只证明 production 本地入口，不冒充 P3.9 shared-daemon client、LaunchAgent 或 remote E2E |
| Relay Companion MVP P3.9-C0-A2 Swift Runtime v2 mirror | 运行本页 A2a/A2b/A2c1/A2c2 focused、public API 与 frozen v1 gate、完整 `swift test`、iOS XcodeGen + Simulator、App selfcheck、docs/diff；A2 完成只证明 current codec、compact/98-fixture 与真实 UDS Swift readback，不得宣称 App/CLI 默认 UDS cutover |
| Relay Companion MVP P3.9-C0-B1b legacy v4 real-writer migration | 运行本页 schema/migration/store/boundary/cipher、默认完整 daemon、Clippy/fmt/no-net/selfcheck/docs/diff 与真实 v4 writer byte-exact gate；当前入口证明 v4 经 v5/v6/v7 中间迁移到 current v8 时的 authenticated migration/materialization，不冒充 active CounterGuard reservation/full rollback 或 Companion E2E |
| Relay Companion MVP P3.9-C0-B3a command pin / prompt admission | 运行本页 B3a Store/Core focused matrix、完整 daemon package、protocol/Swift/selfcheck、Clippy/fmt/network/docs/diff 与双路独立终审；只证明 expected revision admission、同事务 nonzero pin、pinned receipt/status/recovery 与 Store-owned authorization lifetime，不冒充 B3b exact configuration execution、live vendor 或 Companion E2E |
| Relay Companion MVP P3.9-C0-B3b exact execution | 运行本页 B3b Store/Core/driver/translator/restart focused matrix、完整 daemon package、protocol/Swift/selfcheck、Clippy/fmt/network/docs/diff 与双路独立终审；只证明 command-pinned historical configuration、rev0 startup-only、Codex/CC argv/control/at-decision mapping 与 synthetic restart probe，不冒充 live vendor、P4 RemoteLink 或 Companion E2E |
| Relay Companion MVP P3.9-C0-B4 managed metadata | 运行本页 B4 Store/Core/Catalog/integrity/capacity focused matrix、完整 daemon package、protocol/Swift/selfcheck、Clippy/fmt/network/docs/diff 与双路独立终审；只证明 managed rename/archive、durable replay/conflict、同事务 revision/CatalogDelta 与离线篡改审计，不冒充 native projector、P4 CounterGuard/RemoteLink 或 Companion E2E |
| Relay Companion MVP P3.9-C0-B5 cross-layer closeout | 运行本页真实 UDS 双 principal、authorization/cancellation/after-COMMIT focused matrix、完整 daemon/protocol/Swift/iOS Simulator/selfcheck、Clippy/fmt/network/docs/diff 与双路独立终审；只证明 managed configuration/metadata 的 owner-scoped 幂等、双 revision 轴、receipt/event/snapshot/backfill/restart 收敛，不冒充 C0-C native projection、P4 RemoteLink 或真实 Companion E2E |
| Relay Companion MVP P3.9-C0-C native projection | 运行本页 secure source/projection/dynamic snapshot/history-only/native metadata focused matrix、真实当前账号 JSONL ignored smoke、完整 daemon/protocol/Swift/iOS Simulator/selfcheck、Clippy/fmt/network/docs/diff 与双路独立终审；只证明原生历史投影与安全 side-effect substrate，production native mutation 仍是 post-MVP typed gate，不冒充真实 Claude binary、P4 RemoteLink 或 Companion E2E |
| Relay Companion MVP P3.9-B Swift shared-daemon client | 运行本页 installation/UDS/client/current-codec focused `53/53`、完整 `swift test`、普通 build、changed-file strict format、docs/diff 与双路独立终审；warnings-as-errors 的既有 Preview warning 单列未通过。只证明 Swift component，不冒充 P3.9-C3 App model cutover、P3.9-D 默认入口或双客户端 smoke |
| Relay Companion MVP P3.9-C3 App model cutover | 运行本页 App coordinator/canonical model/reliability/Preview focused `46/46`、完整 Swift、普通与 warnings-as-errors build、iOS Simulator、production source purge、strict format/diff 与双路独立终审；普通 GUI 已默认 shared UDS 且 socket failure 零 fallback；Rust CLI、`main.swift --selfcheck` 与双客户端组合 smoke 当时不计入 C3，后由 P3.9-D 完成 |
| Relay Companion MVP P3.9-D 默认入口与组合 smoke | 运行本页 CLI/daemon/Swift/iOS 全量、真实双客户端 smoke、active-turn/双连接/close-only 组合证据、release hidden-surface、四 schema、scoped Clippy/network/docs/fmt/diff 与双路终审。`b818f81` 已完成且全部自动门禁 PASS；真实 vendor login 与 P3.1 provisioned Keychain 仍按 post-MVP BLOCKED 记录，不冒充本 Task 证据 |
| Relay Companion MVP P3.9-E App 会话可靠性 | 运行本页 retry/reconnect/history/subscription/composer focused、完整 Swift/iOS、真实 local-runtime smoke、四 schema、network/docs/diff、changed-source baseline parity 与双路终审。`d68cc02` 已完成且自动门禁 PASS；4 个 legacy 文件只证明诊断数下降，不冒充全文件 strict clean，也不冒充真实 vendor/remote/signed 证据 |
| Relay Companion MVP P3.10 LaunchAgent lifecycle / upgrade 与 P3 Phase Exit | `19622ab` 已完成 admin ledger、upgrade/fence、CLI lifecycle Task；`773a2b3`、`0057824`、`81cc314`、`9efb28d` 完成 verifier 资源/进程组 hardening 与 legacy pre-RW 认证。基于 `9efb28d` 的独立 `bash scripts/verify-relay-companion-mvp.sh p3` exit 0，双路 code review P0/P1/P2 = 0，P3 automatic scope complete；production-signed 槽位仍只能输出 post-MVP `BLOCKED/mutations=0/evidence=[]/summaryGenerated=false`，不得冒充 PASS。后续 P4.1–P4.7 与 P4 automatic Phase Exit 已收口，P4 为 7/7 |
| Relay Companion MVP P4.1 machine identity / Keychain guard | 运行本页 bootstrap、machine keys、machine identity Store、RootKeyId 与 v7→v8 focused gates；Task 收口再跑完整 daemon package/capacity、dev/ephemeral selfcheck、diagnostics、network boundary、schema/manifest、secret/log/static sentinel、Clippy/fmt/diff/status及双路终审。只证明 v8 authenticated identity、四组 key/guard、通用 CounterGuard IO 与 RemoteStartPermit owner；不冒充 active counter reservation/full rollback、cert/enrollment/receipt IO、RemoteLink 或 production-signed Keychain PASS。`46c6bb8` 基线已 PASS；后续 P4.2 已接管 cert/enrollment/control-only transport |
| Relay Companion MVP P4.2 certificate / enrollment / trust reset | 运行本页 manager/finalizer/CLI purge/launchd/transport 与五份 integration focused gates，再跑完整 daemon/CLI/relay-client/protocol/Relay TLS/crypto/Swift/iOS Simulator、dev/ephemeral selfcheck、hermetic smoke、diagnostics、schema/manifest/static sentinel、network、Clippy/fmt/diff/status与双路终审。只证明 v9 authenticated lifecycle、control-only MachineLink、两条 trust reset及安全 uninstall purge；不冒充业务 RemoteLink/E2EE、持久远程 CLI、iOS 真实链路或 production-signed PASS。`a6842bc` 基线 PASS |
| Relay Companion MVP P4.3 PairInvite / DeviceGrant / auth ledger | 运行本页 transport/pairing/manager/trust-reset/Store/reset-guard/真实 TLS+UDS+CLI focused gates，再跑完整 Rust/Swift/iOS、schema/network/docs/Clippy/fmt/diff/status与双路终审。只证明 Runtime v4/schema v10、本机确认 pairing、byte-stable grant/authorization/key-directory、revoke 与 control handoff；本 Task 不冒充业务 RemoteLink/E2EE、persistent remote CLI、iOS 真实链路或 production-signed PASS。`4fd8ed8..3b4b977` 基线 PASS；后续 P4.4 已接线 ingress/Core |
| Relay Companion MVP P4.4 MachineLink ingress / RuntimeCore dispatch | 运行本页 protocol contract `8/8`、MachineLink boundary `1/1`、RuntimeCore static `3/3`、完整 daemon package、跨 crate/Swift/iOS、四 schema、network/no-net/docs/Clippy/fmt/diff 与双路终审。`cd7d9fb` 基线 PASS；本 Task 只证明严格 ingress、Store exact recheck、RemotePrincipal→Core、conversation-scoped recovery 与 typed egress seam。sealer/publisher 在 P4.4 收口时仍 unavailable，后续已由 P4.5 安装；P4.4 自身不冒充 counter/outbox/Relay Publish、persistent CLI、remote E2E 或 production-signed PASS |
| Relay Companion MVP P4.5 signed publication / counter recovery | 核对 `c6ef387` + `88b3c42`，运行 remote focused `430/430`、完整 daemon package（lib `1579/3 ignored`、main `7/7`、256 MiB boundary `5/5`）、Clippy/fmt/diff 与冻结 hash 双路终审。只证明当时 Runtime v4/schema v14/35 下 daemon 侧 exact sealing/outbox/Relay COMMIT/local ACK、key/counter/replay crash recovery；后续 P4.6 完成时 P4 当时为 6/7，该历史 Task 证据本身不等于后续 P4.7 `p4-auto` 或 P4 Phase PASS。P4.7 已另行收口；不得把 automatic PASS 冒充真实设备/公网或 production-signed PASS |
| Relay Companion MVP P4.6 persistent remote CLI | 2026-07-24 automatic Task complete；冻结 29-path code/test scope，blob-manifest SHA-256 `32e7c85620e6e88b407f2403715c52c5a9a5d30aa20d7fb800bdefabe8a1c858`。watch `12/12`、`remote_persistent_machines` `11/11`、完整 CLI package final run exit 0、release allocator `1/1`、relay-client `25/25`、protocol `244/244` 与全部静态门禁均通过；`spec/security` 与 `quality` 均 Approved、P0/P1/P2=0。current Runtime 为 v5；`pair|machines|conversations|watch|prompt|approve|retry-approval|revoke-self` 已接入。P4 在该 Task 收口时为 6/7，production-signed Keychain 保持 post-MVP BLOCKED；既有 Task 证据不等于后续 P4.7 `p4-auto` 或 P4 Phase PASS |
| Relay Companion MVP P4.7 automatic E2E / real slot / phase docs | automatic Task 与 P4 automatic Phase Exit complete，P4 为 7/7。focused `p4-auto`、fresh `cargo test --locked`、Swift 577/577、三组 Clippy、fmt、network/no-net、schema/docs/diff、local smoke/selfcheck/diagnostics 与 pre-closeout hash `18654fa9c398383dafcefa1542c8e48f8c460f1f521806880c5dab083bdb29f5` 上的双路 review 均通过，P0/P1/P2=0；`p4` 仍不受支持。远端 cannot-confirm pairing 由独立 RuntimeCore principal gate 证明。runner 不读参数/env、不探测或执行，只固定输出完整 missingInputs 与 `BLOCKED/mutations=0/evidence=[]/summaryGenerated=false`；production-signed、真实 vendor、公网 WSS、物理真机/真实 iOS、第二台 Mac与 destructive purge 继续 post-MVP BLOCKED |
| Relay Companion MVP P5.1 shared SessionSource facade | 运行本页 test discovery、全包 warnings-as-errors focused `15/15`、strict target build、完整 Swift `557 XCTest + 35 Swift Testing`、iOS Simulator `21/21`、public import、Swift format、平台/fixture 泄漏、docs/diff 门禁。只证明 facade/typed state/receipt 与 Core←SessionSource←RelayClient←App 依赖图；旧 fixture 迁移、RelaySessionSource、bounded stream、Keychain/WSS、真实 iOS 与 P5 Phase Exit 均未完成，P5 当前只计 1/9 |
| Relay Companion MVP P5.2 Keychain / crash-safe CryptoState | 运行本页七组 Swift storage/state/counter/replay/paired tests、strict RelayClient/完整 Swift、iOS storage focused/全量 Simulator、格式/secret/docs/diff 与双路终审。只证明 typed account、ADCS v1 sealed file、counter Pending→state→Stable、non-counter statePending exact commitment、4096 replay window 与 paired marker；SwiftPM `-34018` SecItem 和 Simulator 非真实 Complete readback 均明确保留为 production-signed/物理设备 BLOCKED。该 Task 收口时 P5 只计 2/9；后续 P5.3 已独立完成，RelaySessionSource 与 P5 Phase Exit 仍未完成 |
| Relay Companion MVP P5.3 WSS / SPKI pin / per-connection transfer | 运行本页三组 focused、strict RelayClient/完整 Swift、iOS Simulator、Rust transfer/Runtime/crypto、cross-language、format/static/docs/diff 与独立终审。只证明 generation-scoped WSS、三种 TLS policy、bounded writer/incoming 与 per-connection assembler；P5.4 process-global 512 MiB/8,192 coordinator、RelaySessionSource、真实公网/物理设备与 P5 Phase Exit 均未完成，P5 当前只计 3/9 |
| Relay Companion MVP P5.4 MachineConnection / bounded source | 2026-07-27 automatic Task complete；冻结 69-path Swift candidate `42f47dc2eecfcd0ca312b9178583246aad48b9f59d6413fc9814052cb7e1cd1c` 与 Rust candidate `4815d82628992281c3e1e032c91364080237ca34e6d94398d376b75ec1f7c30f`，并以 34 Rust/fixture + 69 Swift + 6 docs 的 exact 109-path manifest 约束 `34 → 75` 有序提交栈；第一笔只承诺 Rust scoped-green，完整绿色证据属于组合候选。discovery/focused `225/225`、RelayClient `429/4 SKIP`、完整 Swift `958/4 SKIP + 35`、iOS `26/26`、完整 Rust/cross-language/static/docs/diff 与独立终审通过；历史 Step 2 RED 未保留且不伪造。只证明 automatic MachineConnection/key-sync、shared 512 MiB/8,192 budget、bounded broadcaster/reducers、RelaySessionSource 与 typed command/pairing；P5.4 收口时 P5 为 4/9，后续 P5.5 已独立完成。P5 Phase Exit 当时是 automatic 未完成项；真实外部门禁继续 post-MVP `BLOCKED` |
| Relay Companion MVP P5.5 canonical fixture / receipt UI | 2026-07-27 automatic Task complete；52 code/test/fixture content manifest `8dd8610966430a5cf640617da53e34d91bf379fe0ad495ea2ef719a6fec9d5ba` + 10 docs = exact 62 paths；顶层 Swift `980 XCTest / 4 skipped + 35 Swift Testing / 0 failure`、warnings-as-errors focused `91/91`、iOS `91/91`，Rust protocol/producer/store integrity 与其余门禁见本节 fresh 证据。只证明共享 SessionSource 迁移、Core canonical reducer、Runtime v5 command-bound fixed Failed/commandless diagnostic、32 identity cap、snapshot mid-turn inference、canonical fixture、idempotent prompt/approval、event-seq retry fence、retired-operation 校验、receipt/canonical 乱序归并、terminal-before-receipt 收敛、旧 terminal 不消费下一 prompt receipt、terminal-only turn advance/direct-terminal fail-close、单 Failed 单资源广播、资源错误可见性与 fatal fail-close；fixture 仍为 preview/test，`SceneDelegate` 发行 composition 属 P5.6。P5.5 收口时 P5 为 5/9，P5.6–P5.9 与 P5 Phase Exit 当时是 automatic 未完成项；后续 P5.6、P5.7 已完成，当前只剩 P5.8–P5.9 与 Phase Exit 未完成。真实公网、物理 iPhone、production-signed Keychain、第二 Mac 与真实 vendor 继续 post-MVP `BLOCKED` |
| Relay Companion MVP P5.6 iOS production composition / pairing lifecycle | 2026-07-28 automatic Task complete；11 iOS code/test content manifest `8cf47be71709bcd4648341eaa5cd7b693a00f6e871dfb586fbda76ee8662a2fb` + 10 docs = exact 21 paths。Pairing/AppLifecycle focused `42/42`、pre-stream ABA 10 轮、Relay shutdown `56/56`、RelayClient `445/4 entitlement SKIP`、顶层 Swift `985/4 skipped + 35`、fresh iOS `133/133`、Release build/fixture scan、strict format/docs/diff 均通过。只证明 Release Relay composition、完整邀请扫码/粘贴与确认、exact pairing/capture generation/replacement、verified revoke/offline forget 和前后台 source generation；P5.6 收口时 P5 为 6/9，P5.7–P5.9 与 P5 Phase Exit 当时未完成；后续 P5.7 已独立完成。真实公网、物理 iPhone、production-signed Keychain、第二 Mac、真实 vendor 与 destructive purge 继续 post-MVP `BLOCKED` |
| Relay Companion MVP P5.7 macOS SessionSource registry | 2026-07-28 automatic Task complete；`40 prerequisite + 23 registry + 7 docs = 70 paths`，content hash 分别为 `85a46da6d79e56f6da1efd2e67b8851b1b264d7e796ded50334a7769b0af680f` 与 `df38994a015d0bd7014618a75afb6988b9dfec926a19f92cc5e4c8843788bcf6`。完成唯一 local UDS source、per-machine remote registry、typed local capability、真实 dual-scope host、Genesis/business-ready、typed snapshot recovery、observation reentrancy、`SessionModel` operation join 与 Preview/AppRuntime exact-pump barrier；Swift `1061/4 skipped + 35`、Rust daemon lib `1683/3 ignored`、main `7/7`、慢组与双路终审均通过。P5 当前为 7/9；P5.8–P5.9 与 P5 Phase Exit 仍未完成，真实公网、物理设备、production-signed Keychain、第二 Mac、真实 vendor 与 destructive purge 继续 post-MVP `BLOCKED` |
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
- [ ] MVP：CC Rename/Archive/Unarchive 均进入 Runtime gate；production 在 claim 前返回 typed
  `daemon.conversation.metadata_unsupported`，并验证零 ledger/fence/spawn
- [ ] post-MVP gated：CC archive（真实 vendor 调用）后侧栏不可见，且不影响 Codex 历史显示
- [ ] post-MVP gated：CC rename 后侧栏标题更新；终端 `claude --resume <id>` 看到同名
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
