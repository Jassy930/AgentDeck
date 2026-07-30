# Relay Web Test Companion 实施计划

| 字段 | 值 |
|---|---|
| 状态 | Implemented (Web automatic test scope)；W0–W3 complete；W4 BLOCKED |
| 日期 | 2026-07-30 |
| 设计事实源 | `2026-07-30-relay-web-test-companion-design.md` |
| 基线 | `codex/relay-mvp-rescue` / `2aec190` / tree `27c8fbb` |

## 1. Goal

在不新增 daemon、Runtime、Relay/E2EE 版本或业务 bridge 的前提下，交付一个测试型浏览器 Companion，
直接复用 Rust/WASM 协议与 crypto，通过 Playwright 形成第二条可重复的远程业务闭环。

目标链路：

```text
fresh browser profile
+ Web UI / WASM remote core
+ fresh temp TLS Relay
+ existing agentdeckd / RemoteLink / RuntimeCore
+ synthetic Codex / Claude Code

pair → list/open → prompt → approval → reload/reconnect → revoke
```

## 2. Architecture 与 Tech Stack

- Rust：`agentdeck-protocol`、`agentdeck-crypto`、新的 transport-neutral `agentdeck-web-core`。
- WASM：`wasm32-unknown-unknown` + `wasm-bindgen`；打包命令由 Bun script 统一入口调用。
- JS/TS：Bun 管理；TypeScript 只实现 UI、WebSocket/IndexedDB/Web Locks host adapter。
- UI：最小可测页面，复用现有 design tokens；不复制完整 macOS/iOS 产品界面。
- E2E：Playwright Chromium；每轮隔离 user-data-dir、静态 server、Relay/daemon root 和测试证书。
- 后端：既有 `agentdeck-relay` 与 `agentdeckd`；不得新增浏览器业务服务。

计划路径：

```text
agentdeck-web-core/
web/relay-test-companion/
scripts/run-relay-web-companion-e2e.sh
scripts/tests/run-relay-web-companion-e2e.sh
docs/plans/2026-07-30-relay-web-test-companion-*.md
```

W0 已落地前两个目录和计划文档；W1 新增统一 runner 并只接入真实 Relay `/v2/connect`，没有新增 daemon、
业务 bridge 或 Runtime host。daemon/synthetic vendor 的完整纵向编排仍从 W2 开始。

若 W0 发现必须大规模拆分 `agentdeck-cli`，先只抽取 transport-neutral state owner；不得把整个 CLI、Tokio
transport、Keychain 或 filesystem adapter 编译进 WASM。

## 3. 统一阶段节奏

每个阶段按同一顺序执行：

1. 读回 HEAD/tree、Git 状态、允许路径 manifest、运行进程与外部输入。
2. 写最小 RED 或 contract 负例，记录真实退出码和失败原因。
3. 只修改本阶段 manifest，禁止顺手重构 native client 或扩大 UI。
4. focused GREEN：Rust/WASM/TS 单元与静态检查。
5. integration GREEN：真实浏览器/Relay/daemon 切片。
6. 运行读回：UI/terminal/counter/cursor/DB plaintext/cleanup。
7. 更新设计、计划、QUALITY/DIAGNOSTICS 中受影响部分。
8. `git diff --check`、精确暂存、staged diff 检查、一个阶段一个本地提交；不 push。

每个阶段若修改实现，旧 candidate 的运行证据立即失效；不得拼接不同 tree 的 PASS。

## 4. Phase W0：WASM 与浏览器状态可行性

### Goal

在接入真实业务前回答两个硬问题：现有 Rust protocol/crypto 能否不复制地运行于 WASM；IndexedDB +
WebCrypto + Web Locks 能否支持 reload 所需的原子 durable state。

### Tasks

- [x] W0.1：建立 `agentdeck-web-core` 最小 crate，只暴露 Relay v2 codec、Runtime v5 envelope/KAT 和
  crypto golden-vector 测试入口；native 与 WASM 使用同一实现。
- [x] W0.2：建立 Bun workspace、TypeScript strict check、WASM build 和最小静态页面。
- [x] W0.3：在 Chromium 中逐字节核对 Relay codec、Runtime fixture、Ed25519、HPKE、AEAD KAT；加入
  wrong magic/version/length/signature/AAD 的负例。
- [x] W0.4：实现测试版 IndexedDB adapter，验证 non-extractable KEK structured clone、transaction rollback、
  exact revision CAS、Web Locks 单写者与第二 tab 拒绝。
- [x] W0.5：冻结 WASM host contract；静态扫描 TypeScript，确认不存在 wire kind 表、TBS、HPKE/AEAD 或
  private key解析实现。
- [x] W0.6：更新文档、读回 cleanup 和 Git，形成 W0 scoped commit。

### Gates

```bash
cargo test -p agentdeck-web-core
cargo build -p agentdeck-web-core --target wasm32-unknown-unknown
cd web/relay-test-companion
bun install --frozen-lockfile
bun run check
bun run test:unit
bun run test:browser -- --grep 'W0'
cd ../..
cargo run -q -p agentdeck-cli -- protocol relay-schema \
  | diff - protocol/agentdeck/relay-v2.schema.json
cargo run -q -p agentdeck-cli -- protocol runtime-schema \
  | diff - protocol/agentdeck/runtime-protocol.schema.json
scripts/verify-agent-docs.sh
git diff --check
git status --short --branch
```

### Required readback

- 同一 golden vector 的 Rust native、WASM 和既有 Swift 结果 byte-identical。
- 变异 vector 在任何 state mutation 或 WebSocket send 前失败。
- storage transaction 故障后只有 previous 或 exact next revision，不出现 sibling/fork。
- 第二 tab 不消费 counter；关闭 tab 后 lease 可由新 generation 恢复。
- browser profile、static server 和临时文件清理 absent。

### Exit / Stop line

只有“无 TypeScript 协议/crypto 复制 + WASM KAT parity + storage 原子性”全部 PASS 才进入 W1。任一项失败，
状态写为 `BLOCKED` 并回到设计评审；禁止改走 local bridge 或 TS 重写来伪造 W0 PASS。

### W0 完成证据（2026-07-30）

- 首个真实 WASM RED 为 `getrandom` browser backend 未启用；修复只在 `agentdeck-web-core` 的 wasm target
  依赖图打开 `getrandom 0.2/js` 与 `getrandom 0.4/wasm_js`，native crate 行为未变。
- `cargo test -p agentdeck-web-core`：1 个共享 contract integration test 通过；native 与 WASM 均由现有
  `agentdeck-protocol` / `agentdeck-crypto` 产生 Relay Hello、Runtime request roundtrip 与 11 项 KAT 字节。
- `bun run check` 与 `bun run test:unit`：strict TypeScript、protocol-owner 静态扫描和 exact revision 纯函数
  2/2 通过。
- `bun run test:browser -- --grep W0`：本机 Chrome 4/4 通过，覆盖 wrong magic/version/kind/length、Runtime
  unknown field、Ed25519/HPKE ciphertext/info/AAD tamper、IndexedDB KEK structured clone、abort rollback、
  sibling/skipped CAS、第二 tab writer 拒绝/交接与 CSP。
- 浏览器页面自检读回 `W0 核心通过`、共享向量 `11`、密码学负例 `4/4`，console error 为空；测试页面、
  静态 server、浏览器 tab/profile 与生成目录均由测试或 `.gitignore` 收口，不提交构建产物。
- 该证据只关闭 W0 可行性；没有连接真实 Relay，也不改变物理设备、公网 WSS、production SPKI pin 和
  iOS Simulator 权威路径的状态。

## 5. Phase W1：浏览器直连 Relay v2 / E2EE

### Goal

浏览器使用真实 binary WebSocket 直接连 temp TLS Relay，完成 Hello、Challenge、Authenticate、
Authenticated 和一条 sealed sentinel route；不经过业务 bridge。

### Tasks

- [x] W1.1：实现 WebSocket host adapter，只接受 fixed root `wss://` origin，并由 WASM 固定选择
  `/v2/connect`；拒绝 path/query/fragment、text frame 和 redirect。`/v2/pair` 保留给 W2。
- [x] W1.2：把现有 Relay v2 handshake 改造成 transport-neutral core；JS 只发送 WASM 产出的 binary bytes。
- [x] W1.3：加入 per-generation connect/write/cleanup deadline、single-flight 和旧 generation 隔离。
- [x] W1.4：runner 启动 fresh TLS Relay、隔离 Chromium 测试信任和预置 test principal，取得真实
  Hello→Authenticated readback。
- [x] W1.5：覆盖 wrong relayServerId、tampered challenge/signature、replay、text/oversize、断线和 Relay
  restart 负例；所有错误保持零业务 mutation。
- [x] W1.6：扫描 Relay DB/WAL/SHM、browser console/trace 和日志，确认 sentinel/plain secret absent。
- [x] W1.7：更新文档并随本阶段形成 W1 scoped commit。

### Gates

```bash
bash scripts/run-relay-web-companion-e2e.sh --all
bash scripts/run-relay-web-companion-e2e.sh --contract
bash scripts/run-relay-web-companion-e2e.sh --transport
bash scripts/tests/run-relay-web-companion-e2e.sh
cargo test -p agentdeck-protocol -p agentdeck-crypto -p agentdeck-relay-client
cargo test -p agentdeck-relay --features server,tls
bash scripts/verify-relay-companion-mvp.sh p4-auto
cargo clippy -p agentdeck-web-core --all-targets --features w1-test-fixture -- -D warnings
cargo clippy -p agentdeck-relay --features server,tls --test relay_web_companion_w1_e2e -- -D warnings
cargo fmt --all -- --check
bash scripts/check-daemon-network-boundary.sh
bash scripts/check-daemon-no-net.sh
scripts/verify-agent-docs.sh
git diff --check
git status --short --branch
```

### W1 完成证据（2026-07-30）

- `agentdeck-web-core` contract `2/2` 通过：strict root WSS、固定 `/v2/connect`、状态推进、wrong identity 与
  replay fail-close；WASM 只导出 opaque frame action，不导出固定私钥、TBS 或 AEAD plaintext。
- TypeScript unit `2/2` 与 ownership gate 通过；薄 host 只负责 WebSocket lifecycle/deadline/single-flight/
  generation 和 binary forwarding。
- 真实 Chrome→临时 TLS Relay integration `1/1` 通过；内部逐轮执行首次 positive、7 个在线负例、Relay
  unavailable 与 restart 后 positive。页面读回 `W1 真实 Relay 通过`，console error 为空。
- wrong server、challenge/signature 篡改、Authenticate replay、text/oversize 和 disconnect 后 SQLite frame
  count 保持 1；Relay restart 后相同 stream/seq 的重复发布仍保持 1，证明该切片幂等。
- SQLite sealed blob 可按 E2EE v1 canonical wire 解码且不含 sentinel；Relay DB/WAL/SHM、浏览器 stdout/stderr、
  Playwright output 与本轮临时 root 扫描均无 sentinel 明文，`test-results/` absent。
- 既有 protocol/crypto/relay-client、Relay `server,tls` 全矩阵、`p4-auto`、两组 scoped Clippy、fmt、daemon
  network boundary、四 schema、docs 与 diff gate 全绿。

### Exit

真实 browser PID、WSS endpoint、connection generation、Authenticated terminal、sealed sentinel、
明文扫描和 cleanup 全部读回。该 PASS 只证明 test TLS policy 下的直连，不关闭 production SPKI pin。

## 6. Phase W2：完整远程业务纵向链路

### Goal

复用现有 R4 fixed-topology host，把远程 UI 从 iOS Simulator 扩展为独立浏览器 principal，完成一条完整
业务闭环；iOS E2E 继续保留并作为回归门禁。

为避免再次把大功能一次铺开，W2 固定拆成三个可独立提交、独立验证的子阶段：

1. **W2a pairing**：invite inspect、确认前零网络、真实 `/v2/pair`、本机批准与 paired terminal。
2. **W2b business**：paired principal 的 list/open/prompt/approval。
3. **W2c durability**：IndexedDB promotion、reload/reconnect/backfill 与 revoke。

W2c 完成是标记 W2 complete 的必要条件；W2.7 完整负例矩阵与 W2.8 总体收口现已关闭。

### Tasks

- [x] W2.1：实现 PairInvite paste/inspect/trust preview；确认前零网络，确认后才连 `/v2/pair`。
- [x] W2.2：复用 WASM HPKE/签名和 durable state 完成 pair request/response/terminal；被控 Mac 仍只经
  existing same-UID `LocalPairingAdministration` approve/cancel。W2a 完成内存态 terminal，W2c 已完成
  IndexedDB paired promotion、reload recovery 与旧 identity revoke readback。
- [x] W2.3：实现最小 machine/catalog/conversation 页面和 open/prompt/approval 操作；UI 只消费 typed
  WASM view state。
- [x] W2.4：runner 串起真实 RuntimeCore/RemoteLink、synthetic Codex/Claude Code、Relay 和浏览器，读回
  list/open/prompt/assistant/approval terminal。
- [x] W2.5：强制 page reload + WebSocket reconnect，验证 durable cursor/backfill、counter 单调和副作用不重复。
- [x] W2.6：执行 revoke-self，验证 signed terminal、浏览器材料清理、连接关闭和旧 identity 不可重连。
- [x] W2.7：加入 wrong invite/fingerprint、remote cannot-confirm pairing、approval loser、stale/replay/nonce reuse
  反例和零 mutation 断言。wrong invite/fingerprint、remote cannot-confirm、握手 replay 与 revoke 后旧身份零发送
  沿用 W2a/W2c 证据；新增生产 helper、native/WASM typed snapshot 与 daemon SQLite frozen counts 关闭剩余矩阵。
- [x] W2.8：更新 README/ARCHITECTURE/QUALITY/DIAGNOSTICS/runbook 中实际新增边界，形成 W2 overall scoped
  commit。W2.7 文档与独立提交不替代 W2 overall 的完整回归与收口。

### Gates

```bash
bash scripts/run-relay-web-companion-e2e.sh --negative
bash scripts/run-relay-web-companion-e2e.sh --durable
bash scripts/run-relay-web-companion-e2e.sh --all
cd web/relay-test-companion
bun run check
cd ../..
bash scripts/run-relay-companion-simulator-e2e.sh
bash scripts/verify-relay-companion-mvp.sh p5
cargo test -p agentdeck-web-core -p agentdeck-protocol -p agentdeck-crypto
swift test --filter AgentDeckSessionSourceTests
scripts/verify-agent-docs.sh
git diff --check
git status --short --branch
```

### W2a 完成证据（2026-07-30）

- `W2PairingCore` native contract `2/2`：canonical invite 本地 inspect、完整 fingerprint preview、确认前
  `connectUrl` 拒绝、wrong fingerprint 零解锁、确认后 endpoint 精确为 `/v2/pair`、Hello/PairingHello
  类型正确，MachineRoot 绑定篡改和 Hello replay fail-close。
- WASM 使用 browser `getrandom` 生成 DeviceSign/DeviceHPKE/HPKE RNG 材料；TypeScript 不取得 private key、
  TBS、invite secret、grant 或 key directory，只创建 WebSocket、转发 opaque binary 并消费脱敏 evidence。
- `scripts/run-relay-web-companion-e2e.sh --pairing` fresh PASS：真实 Chrome→temp Direct TLS Relay→唯一
  daemon/RemoteLink→same-UID local approve，读回 PairPending、verified PairResponse、receipt 与
  `PairRouteClosed::Closed`。批准前为 `pending=1/grant=0/runtimeCommand=0`，终态为
  `pending=0/activeGrant=1/activeTransition=0/catalogStream=1/runtimeCommand=0`。
- browser/host PID、host root、0600 invite、UDS 与 Playwright artifacts 全部 absent；Relay DB/WAL/SHM 中
  Web device display name 明文 absent。没有新增 Web daemon、本地 bridge、UDS→HTTP 或第二 Runtime。
- 本证据只关闭 W2a；在该时点 verified response/key directory 仍只在 WASM 内存，W2b/W2c 与 W2 overall
  均未完成。后续 W2b 证据见下节；iOS regression、物理设备、公网、production pin 和真实 vendor 状态均
  未由 W2a 切片改变。

### W2b 完成证据（2026-07-30）

- `W2PairingSession` 在 matching Closed 后把原 DeviceSign/DeviceHPKE、`VerifiedPairResponseV1`、grant、
  authorization 与 key directory 移交 `W2BusinessCore`，没有重新创建 identity、Runtime、daemon 或 bridge；
  pairing material 被移走后，`receiptSent` 仍由独立单调证据保持 true。
- Catalog 与 Conversation 均使用现有 `RuntimeRequest::Subscribe`。真实新设备 bootstrap 对两条流分别验证
  `StreamBindingV1`/snapshot/SyncComplete/`EpochBarrierV1`，发送 signed `StreamAppliedAckV1`，在
  `RouteAccepted` 后发送 outer ACK；没有新增 protocol/schema/version。
- prompt、assistant 与 approval sentinel 只存在 Rust/WASM。fresh Chrome 真实观察 prompt Accepted、assistant、
  approval request、首次 `Claimed`、canonical `ApprovalResolved(Applied)`、`RetryApproval` Applied 读回与
  `TurnCompleted`；未补发第二个 approval 决定。
- `scripts/run-relay-web-companion-e2e.sh --business` fresh PASS：host 为 command/completed `1/1`、approval
  total/applied `1/1`、active Catalog stream `1`，活跃窗口 writer/subscription/job 精确为 `2/2/2`；Relay 与
  browser 三项业务明文 absent，browser/host PID、host root、invite、UDS、Playwright artifacts 全部 absent。
- W2a `--pairing` 与 W1 `--transport` 回归 PASS；既有 `scripts/run-relay-companion-simulator-e2e.sh` 完整 PASS，
  读回 daemon generation 2、restart/history recovery、command/completed `1/1`、approval `1/1`、revoke `1`、
  active grant `0`、Relay plaintext absent 与全部 cleanup absent。
- 本证据只关闭 W2b。IndexedDB paired promotion、reload/reconnect/backfill/revoke 与 crash cut 仍由 W2c/W3
  承担；W2 overall、正式 Web 产品、物理设备、公网、production pin/signing 与真实 vendor 均未完成或继续
  BLOCKED。

### W2c 完成证据（2026-07-30）

- paired promotion 复用 W2b 的原 DeviceSign/DeviceHPKE、`VerifiedPairResponseV1`、grant、authorization 与
  key directory。Rust/WASM 导出 opaque canonical state；TypeScript 只用 IndexedDB 中不可导出的 AES-GCM
  KEK 加密并执行 exact revision CAS，private key、grant 与解密 Runtime wire不进入 UI owner。
- promotion 创建 durable revision `0`；首轮业务 checkpoint 把 counter reservation `0→256` 与 state exact
  CAS 提交到 revision `1`。reload 后先解密/验证 paired state，把下一 reservation `256→512` 提交到
  revision `2`，完成前禁止任何网络发送。
- daemon generation `1→2` 后浏览器以原 identity 重新 Authenticate；Catalog/Conversation subscription 恢复，
  Catalog warm backfill 观察到 `R4.4 daemon restart marker`。`StreamBinding.inner_cursor` 按 publication cut
  解释，允许 `SyncComplete.inner_cursor` 更高，control ACK 不再回退 durable reducer cursor；live publication
  overlap 只接受 exact duplicate/连续 next。
- host 的 restart record 冻结 restart + marker COMMIT + active grant 的 base linearization evidence；浏览器
  authenticated evidence 独立证明两条 subscription/backfill。host 不轮询可能被即时 self-revoke 擦除的
  transient live-count，最终 revoke 仍由独立 host `Revoked` readback 证明。
- self-revoke 验证 MachineRoot-signed terminal。连接关闭使 directed committed receipt 不可见时，只从该
  verified terminal 合成同义 committed receipt；随后 exact transaction 删除 paired material/KEK 并写
  revision `3` revoked tombstone。旧 identity reload 后返回 `web.remote.durable.revoked`，binary frames sent
  为 `0`；Relay active grant `0`、revoke tombstone `1`。
- `scripts/run-relay-web-companion-e2e.sh --durable` fresh PASS：command/completed `1/1`、approval
  total/applied `1/1`、runtime revoked authorization `1`，没有重复业务副作用；Relay DB/WAL/SHM、browser
  log/DOM/Playwright output 中 prompt、assistant、approval 与 restart marker 明文 absent，全部本轮进程、
  profile、root、invite、UDS 和 artifacts absent。
- `scripts/run-relay-web-companion-e2e.sh --all` 已包含 W0、W1 transport、W2a、W2b、W2c；runner contract、
  Web core 两组 feature tests/WASM build/Clippy、protocol/crypto 与四份 schema diff、daemon machine E2E、
  daemon no-net/network boundary、agent docs 和 `verify-relay-companion-mvp.sh p5` 均已通过。fixed-topology iOS
  Simulator lifecycle、SessionSource `25/25` 与 RelayClient 457 tests通过；4 个 production Keychain entitlement
  用例按设计 skipped，物理 iPhone 与第二台 Mac继续外部 BLOCKED。
- daemon machine E2E scoped Clippy 在精确允许未修改 Codex adapter 的 `too_many_arguments`、
  `collapsible_if`、`collapsible_str_replace` 后通过；字面全目标 `-D warnings` 仍被这些既有 lint 阻断，且
  lib-test 另有既有 `cmp_owned`。本切片不夹带清理，不能写成全目标零 warning。
- 本证据关闭 W2c automatic slice，不单独关闭 W2 overall；W2.7 的后续证据见下节。W3
  crash-cut/tab contention/三次 fresh run未开始，W4 公网、物理设备、production signing/pin、第二台 Mac 与
  真实 vendor继续 BLOCKED。

### W2.7 完成证据（2026-07-30）

- `agentdeck-web-core` 抽取 approval receipt 分类、stream outer exact-next、nonce uniqueness 与 counter
  reservation 四组生产准入 helper。directed reply 与 stream publish 只在完整验签、解密及 Runtime/stream 语义
  接纳成功后 COMMIT counter，replay/nonce reuse 拒绝不消费 replay slot。
- `W2NegativeSnapshot` 由相同 helper 生成 12 项 typed evidence：approval loser 被识别为 Applied 且不创建第二
  claim；stale/skipped publish 被拒绝且 cursor 不变；reply replay/stream nonce reuse 被拒绝且两个 counter set
  不变；未提交 reservation 与越过 high-water 被拒绝且 command counter 不变。TypeScript 只读取 snapshot JSON，
  不解析或构造 wire/crypto。
- `agentdeckd` machine E2E 在 Codex 与 Claude Code 的后到 approval resolve 前冻结 completed command、approval
  total/applied、revoked authorization 四项 SQLite 计数；`Applied/AlreadyHandled(Approve, Applied)` readback 与
  随后 Applied Retry 后两次比较均逐项不变，证明 loser 与 terminal retry 零 durable ledger mutation。
- `scripts/run-relay-web-companion-e2e.sh --negative` automatic PASS：Web core native contracts、真实 Chromium
  W2.7 snapshot `1/1`、daemon machine E2E `1/1` 全绿。`--all` 已纳入该门禁，并再次读回 W2a/W2b/W2c 正向
  计数 command/completed `1/1`、approval total/applied `1/1`、revoke 后 active grant `0` 与全部 cleanup。
- W2.7 只关闭 negative/zero-mutation matrix；在该独立提交完成时，W2 overall 仍等待 W2.8 总体 runbook、
  iOS/全量回归与 scoped closeout。当前 W2.8 结果见下节；W3/W4 的边界不变。

### W2.8 完成证据（2026-07-30）

- 在 W2.7 committed candidate `64366cb` 上重新运行 `scripts/run-relay-web-companion-e2e.sh --all`，W0/W1、
  W2a pairing、W2b business、W2c durable 与 W2.7 negative 全绿。W2b/W2c 继续读回 command/completed
  `1/1`、approval total/applied `1/1`，revoke 后 active grant `0`，所有浏览器/host/root/invite/UDS/artifact
  cleanup absent。
- `bash scripts/verify-relay-companion-mvp.sh p5` PASS：fixed-topology iOS Simulator 真实完成 pairing、业务、
  daemon generation `1→2`、restart marker/history recovery 与 revoke；最终 Runtime revoke `1`、Relay active grant
  `0`、Simulator/host/root/invite/socket absent。
- SessionSource `25/25` 零失败；RelayClient 执行 `457` 个测试，4 个 production Data Protection Keychain
  entitlement 用例按既定 post-MVP 外部门禁 skipped，其余零失败。物理 iPhone 与第二台 Mac runner 继续输出
  versioned BLOCKED，不被 automatic 证据冒充 PASS。
- Web core 两 feature 合并 contract、protocol/crypto 全矩阵与 schema snapshots、Web/daemon scoped Clippy、
  daemon network/no-net、fmt、TypeScript ownership、agent docs、diff 与 cleanup 全绿。README、ARCHITECTURE、
  QUALITY、DIAGNOSTICS、index 和两份 Web plan 已与实际边界同步。
- W2 automatic overall complete；这不启动或关闭 W3，也不改变 W4 公网、物理设备、production
  signing/pin、第二台 Mac 与真实 vendor 的 BLOCKED 状态。

### Required readback

| 能力 | 必须读回 |
|---|---|
| Pair | 独立 installation/key/grant、pending fingerprint、本机 approve、paired terminal |
| List/Open | 真实 daemon catalog/snapshot，浏览器显示唯一目标 conversation |
| Prompt | daemon Accepted + canonical Completed；业务副作用恰好一次 |
| Approval | first-wins Applied/AlreadyHandled，浏览器 terminal 与 daemon ledger 一致 |
| Reload | 新 page/generation 恢复 cursor/backfill，无重复 command/approval |
| Revoke | signed terminal、旧连接关闭、material absent、旧 identity 重连失败 |
| Security | Relay/console/trace/DOM/截图无 prompt、assistant、approval 和 secret 明文 |
| Cleanup | browser/server/Relay/daemon/temp cert/DB/profile/root absent |

### Exit

W2c 单轮 fresh durable E2E、W2.7 完整负例矩阵与 W2.8 Web/iOS/P5 总体回归已 PASS，W2 automatic overall
complete；该完成仍不能标记物理设备、公网、production signing/pin、第二台 Mac 或真实 vendor PASS。

## 7. Phase W3：durable recovery、隔离与重复性

### Goal

证明浏览器不是只在 happy path 工作：counter/state 三个 durable cut、tab contention、browser crash、Relay
restart 和网络中断都能 fail-close 或恢复到唯一合法状态。

### Tasks

- [x] W3.1：为 counter reservation、sealed state commit、Stable finalize 三个 cut 增加 deterministic fault seam；
  每个 cut 重启后只能整块跳号或 exact finalize。
- [x] W3.2：覆盖 replay/cursor statePending 的 previous rollback、exact next finalize 与 sibling/fork quarantine。
- [x] W3.3：启动第二 tab/worker，验证 Web Locks 排他、旧 generation/BroadcastChannel 失效和零重复发送。
- [x] W3.4：在 prompt/approval/reconnect 各阶段强制 kill browser process，再以同 profile 冷恢复。
- [x] W3.5：使用 runner-owned 故障代理注入断连/延迟/Relay restart；代理只转发 bytes，不解析协议。
- [x] W3.6：同一 committed candidate 连续三次 fresh 完成 W2 business + W3 recovery；任一轮失败重新计数。
- [x] W3.7：执行 spec/security 与 quality/Git 双路 review，清零 P0/P1/P2，更新文档并形成 W3 scoped commit。

### W3.1 evidence（2026-07-30）

- IndexedDB 新增独立 `counterGuard`，提交固定为 Pending guard、encrypted paired state、Stable guard 三段
  transaction + readback；Pending 冻结 previous/next revision、commitment 和 next sealed bytes。
- `scripts/run-relay-web-companion-e2e.sh --crash-cuts` 对三个 cut 各跑一轮 fresh Relay/daemon/Chrome：
  `guardPendingDurable` 从 previous 完成 exact-next，`stateDurable` 从 exact-next 补 Stable，
  `guardStableDurable` exact-open。注入后恢复前均为零 frame。
- 三轮均整块跳过未暴露的 `256→512`，冷恢复后 reservation 为 `512→768`、最终 revision `4`；
  command/completed、approval total/applied 各 `1/1`，revoke 后 active grant `0`，paired/KEK/guard 与所有
  runner artifact absent。
- W3.2 已由下一节关闭；W3.3 tab contention 也已由其后独立阶段关闭。本 Task 收口当时 W3.4–W3.7
  尚未完成；后续均已按下节独立关闭。

### W3.2 evidence（2026-07-30）

- 普通业务 checkpoint 已从 counter reservation 路径拆出，固定使用
  `statePending(previous Stable + exact next full-state commitment)`；counter reservation 仍独占原
  `Pending → encrypted state → Stable` 三段路径，两类 mutation 不再混用恢复语义。
- `scripts/run-relay-web-companion-e2e.sh --state-cuts` 对 `stateGuardPendingDurable`、`stateDurable`、
  `guardStableDurable` 各运行 fresh Relay/daemon/Chrome。冷恢复结果分别为
  `statePendingPreviousRetried`、`statePendingNextFinalized`、`stableExact`，恢复前均为零 binary frame。
- previous 路径先 exact 回滚 guard，再重试同一 staged candidate；exact next 只补 Stable。独立 Chromium
  sibling 负例把同 revision 非 exact-next state 持久化为 `quarantined(stateFork)`，返回
  `web.remote.storage.state_fork_quarantined`，且发送 frame 数为 `0`；再次打开返回
  `web.remote.storage.state_quarantined`，禁止自动合并或重新配对掩盖。
- 三个真实 state cut 均最终 revision `3`、reservation `256→512`、daemon generation `2`、
  command/completed 与 approval total/applied 各 `1/1`；revoke 后 active grant `0`，paired/KEK/guard、
  browser/host/root/invite/UDS/Playwright artifacts 全部 absent。
- `--recovery` 同时重跑 W3.1 与 W3.2 聚合门禁并通过；W3.3 已由下节关闭，W3.4–W3.7 与 W4 外部
  槽位状态不变。

### W3.3 evidence（2026-07-30）

- 新增薄 `writer-generation.ts` host owner：profile 级 Web Lock 决定唯一写者，BroadcastChannel 只传递
  schema-versioned opaque activation token。canonical state 仍只在 IndexedDB/WASM，不经 channel 复制。
- W2c start、recover 与两类 W3 crash入口均实际进入 writer generation 门禁；start/crash 持锁到 reload，
  recover/revoke 或失败 cleanup 后释放。第二 tab 获取不到锁时不进入 paired state load/mutation/send。
- `scripts/run-relay-web-companion-e2e.sh --contention` 在真实 W2c fixed-topology 链路中读回：主 tab paired
  revision `1`/Stable 时第二 tab acquire=false；其迟到探针为
  `web.remote.writer_generation_missing`、binary frames `0`、canonical mutations `0`。
- 主 tab显式 relinquish 后第二 tab取得锁并广播新 generation；旧 tab同时读回
  `relinquished=true`、`invalidatedByPeer=true`，旧 generation 探针返回
  `web.remote.generation_stale`，paired revision/guard 仍为 `1`/Stable，零 frame、零 mutation。
- 随后正常 reload/reconnect/revoke 继续完成，最终 revision `3`、command/completed 与 approval
  total/applied 各 `1/1`、active grant `0`、全部 runner artifact absent。`--recovery` 重跑 W3.1/W3.2 全绿。
- W3.4 已由下一节关闭；W3.5–W3.7 与 W4 外部槽位状态不变。

### W3.4 evidence（2026-07-30）

- 新增 runner-owned 系统 Chrome 与独立 process group；每轮精确 `SIGKILL` 主进程，readback 为
  `code=null/signal=SIGKILL`，同 user-data-dir 冷启动后的主 PID 必须不同。
- `scripts/run-relay-web-companion-e2e.sh --browser-kills` 对 prompt、approval、reconnect 三个 cut 聚合 PASS。
  prompt cut 的新 Chrome 先在 daemon restart 前从 revision `1` 恢复未完成审批并提交 revision `3`，再经历
  daemon restart、第二次 recovery 与 revoke；这避免把 daemon 合法 `Expired` 终态误写为 Applied。
- reconnect cut 在 revision `3` checkpoint 后杀进程；第二次 cold-open 保留由 durable catalog cursor认证的
  单调 restart-marker 事实，从 exact-next cursor 恢复两流，不倒退重放旧 marker。
- prompt/reconnect 最终 revision `5`、reservation `512→768`；approval 最终 revision `3`、reservation
  `256→512`。三轮 host 均为 command/completed `1/1`、approval total/applied `1/1`、revoke `1`、active
  grant `0`，业务明文扫描与全部 cleanup 通过。
- W3.5 已由下一节关闭；本 Task 收口当时 W3.6–W3.7 尚未完成，后续均已关闭；W4 外部槽位状态不变。

### W3.5 evidence（2026-07-30）

- 新增 runner-owned TCP fault proxy；浏览器仍对真实 Relay 执行端到端 TLS/SPKI。代理 evidence 固定
  `parsedProtocol=false`，不解析 WebSocket/Relay/Runtime，不接触 key 或 canonical state。
- `scripts/run-relay-web-companion-e2e.sh --network-faults` 对 disconnect、delay、relayRestart 聚合 PASS。
  disconnect 在 armed connection 累计 2 KiB 后切断，bounded reconnect 最终 revision `3`；delay 对
  client→Relay 每 chunk 延迟 120 ms，最终 revision `3`。
- relayRestart 在 recovery connection 建立后真实关闭 Relay generation `1`，首轮 outcome-unknown；以 exact
  bind/store/cert/receipt signer 重启 generation `2`，host 读回 machine lifecycle active、catalog stream `1`、
  transition `0` 后第二次恢复，最终 revision `4`、reservation `512→768`。
- 三轮 host 均为 command/completed `1/1`、approval total/applied `1/1`、revoke `1`、active grant `0`；
  Relay/browser plaintext 与 proxy/browser/host/root/invite/UDS/paired/KEK/guard cleanup 全部通过。
- W3.6 已由下一节关闭；本 Task 收口当时 W3.7 尚未完成，后续已关闭；W4 外部槽位状态不变。

### W3.6 evidence（2026-07-30）

- 新增唯一 `--repeatability` 入口；启动前冻结 clean worktree 的 `HEAD commit + tree`，并在每个子门禁前后
  拒绝 commit/tree 漂移或 tracked/untracked 工作区变化。
- 每轮固定执行一次 W2b `--business` 与一次 W3.1/W3.2 `--recovery`，解析一个 W2b terminal、六个 W3
  detail terminal 和两个 W3 aggregate terminal；计数、revoke、active grant、明文与 cleanup 逐项验证。
- runner 固定三轮，不暴露降低轮数的环境变量；任一轮失败不会产出 W3.6 terminal，重新执行从第一轮计数。
- candidate `9597c16e2f265bd41ca73d4760f329dcfd0900b6` / tree
  `b21c386b2002fa4052cabb9db1457153c30d4044` 连续三轮 fresh exit 0；每轮候选检查均保持 clean 且无漂移。
- 最终 W3.6 terminal 读回 `freshRuns=3`、W2b terminal `3`、W3 detail terminal `18`、W3 aggregate
  terminal `6`、`allRunsConsistent=true`。三轮 command/completed 与 approval total/applied 各 `1/1`，
  recovery revoke `1`、active grant `0`，plaintext 与 cleanup 全部 absent。
- W3.6 automatic complete；本 Task 收口当时 W3.7 尚未完成，后续已关闭；W4 外部槽位状态不变。

### W3.7 双路终审与 automatic closeout（2026-07-30）

- spec/security 首轮发现 fault proxy 使用跨连接全局字节数证明 armed connection 2 KiB、delay 在 downstream
  backpressure 时提前 resume、stale writer generation 清理后仍抛旧错误，以及 paired/pending ciphertext 与
  revoked tombstone 缺少读前上界/结构校验；均已改为 fail-close，并补 W3.3/W3.5 行为回归。
- quality/Git 首轮发现 W3.6 只验证 recovery detail 的 3+3 数量、没有验证六种 cut唯一覆盖，且本计划误写
  不存在的 `bun run test:e2e`；已增加 exact cut/aggregate 自检并改用真实 W0 browser 命令。
- review fixes 与 Simulator restart contract 修补后的 code/test candidate 固定为
  `d4446ef1e26945458406e6811804a68fa617b7fd` / tree
  `2bb877b37c160d9c35f0f54a835b9451a764cc38`。该候选重新通过 W3.6 三次 fresh：W2b terminal `3`、
  W3 detail `18`、W3 aggregate `6`、`allRunsConsistent=true`；`--all`、`--contention`、
  `--browser-kills` 与 `--network-faults` 也全部 PASS。
- 同一候选通过完整 Rust workspace（daemon `1719 passed / 3 ignored / 0 failed`）、Swift warnings-as-errors
  （`1169 executed / 4 external skips / 0 failed` + Swift Testing `48/48`）、iOS Simulator `134/134`、
  `p4-auto`、完整 `p5`、release allocator `1/1` 与全部静态门禁。完整 `p5` 首次在冷 Simulator 出现一次
  synthetic assistant UI observation timeout；runner 完整 cleanup，随后同候选 focused lifecycle 与完整
  aggregate 均 PASS，因此该瞬时失败不计最终证据，也没有被静默省略。
- 对 `1a74cf7..d4446ef` 整个 W3 增量重新执行 `spec/security` 与 `quality/Git` 终审，两路均 Approved，
  P0/P1/P2=0。Relay/Runtime/E2EE owner/schema 未变，TypeScript ownership 正反例、runner 负例、明文扫描、
  network/no-net、docs/diff/status 与 cleanup 均通过。本次 docs-only scoped commit 只同步事实源，不修改
  production、test、runner、协议或版本；W3 automatic overall complete。

### Gates

```bash
bash scripts/run-relay-web-companion-e2e.sh --crash-cuts
bash scripts/run-relay-web-companion-e2e.sh --recovery
bash scripts/run-relay-web-companion-e2e.sh --repeatability
cd web/relay-test-companion
bun run check
bun run test:unit
bun run test:browser -- --grep W0
cd ../..
cargo test --locked --no-fail-fast -- --test-threads=1
swift test -Xswiftc -warnings-as-errors
bash scripts/verify-relay-companion-mvp.sh p5
cargo fmt --all -- --check
bash scripts/check-daemon-network-boundary.sh
bash scripts/check-daemon-no-net.sh
scripts/verify-agent-docs.sh
git diff --check
git status --short --branch
```

### Exit

- 三次 fresh run 绑定同一 commit/tree，command/approval/revoke 计数一致。
- 所有 crash cut 只有 previous/exact next 合法恢复，nonce/counter 不复用。
- 第二 tab、旧 generation 和迟到 frame 零 canonical mutation。
- 每轮 Relay plaintext absent，runner cleanup 全部 absent，Git clean。
- 双路 review P0/P1/P2=0。

达到上述条件后只写：

```text
Implemented (Web automatic test scope)
external physical/public evidence: BLOCKED
```

## 8. Phase W4：外部公网与独立设备槽位

W4 不由本机 automatic 结果自动解锁。进入前另建执行授权和证据计划，至少需要：

- public-CA WSS endpoint、Relay identity、受控域名与日志/DB/metrics 审计权限；
- 独立物理设备或第二台 Mac上的浏览器、隔离 profile 和不同网络；
- 明确的 PairInvite 传递与本机 fingerprint 确认流程；
- production TLS 决策：普通浏览器无法等价执行 native current/next SPKI pin，必须明确接受 public CA 边界，
  或改用带 Rust 壳的正式 Web UI；
- 真实 pair→list/open→prompt→approval→network switch→reconnect→revoke 和 cleanup/readback；
- 不把真实 vendor token 放入 Relay、网页存储、测试日志或仓库。

缺任一输入时 runner 必须保持 versioned `BLOCKED/mutations=0/evidence=[]/summaryGenerated=false`，不能探测、
配对或生成部分 evidence。

## 9. 总体收口清单

- [x] W0 证明 WASM parity 与 IndexedDB/Web Locks durable contract。
- [x] W1 浏览器直连真实 Relay v2/E2EE，无业务 bridge。
- [x] W2 完成完整远程业务流，iOS E2E 不回归（W2a–W2.8 automatic overall complete）。
- [x] W3 crash/restart/tab contention 与三次 fresh run 全绿。
- [x] TypeScript 无 wire/crypto owner；Relay/Runtime/E2EE 版本未变。
- [x] 文档、diagnostics、quality、runbook 与实际一致。
- [x] candidate 双路 review P0/P1/P2=0，cleanup absent，Git clean。
- [x] W4 外部 evidence 独立保持 BLOCKED，未被 automatic 结果冒充 PASS。
