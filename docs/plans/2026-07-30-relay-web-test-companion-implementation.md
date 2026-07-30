# Relay Web Test Companion 实施计划

| 字段 | 值 |
|---|---|
| 状态 | Proposed；用户确认后从 W0 开始 |
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

拟新增路径：

```text
agentdeck-web-core/
web/relay-test-companion/
scripts/run-relay-web-companion-e2e.sh
scripts/tests/run-relay-web-companion-e2e.sh
docs/plans/2026-07-30-relay-web-test-companion-*.md
```

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

- [ ] W0.1：建立 `agentdeck-web-core` 最小 crate，只暴露 Relay v2 codec、Runtime v5 envelope/KAT 和
  crypto golden-vector 测试入口；native 与 WASM 使用同一实现。
- [ ] W0.2：建立 Bun workspace、TypeScript strict check、WASM build 和最小静态页面。
- [ ] W0.3：在 Chromium 中逐字节核对 Relay codec、Runtime fixture、Ed25519、HPKE、AEAD KAT；加入
  wrong magic/version/length/signature/AAD 的负例。
- [ ] W0.4：实现测试版 IndexedDB adapter，验证 non-extractable KEK structured clone、transaction rollback、
  exact revision CAS、Web Locks 单写者与第二 tab 拒绝。
- [ ] W0.5：冻结 WASM host contract；静态扫描 TypeScript，确认不存在 wire kind 表、TBS、HPKE/AEAD 或
  private key解析实现。
- [ ] W0.6：更新文档、读回 cleanup 和 Git，形成 W0 scoped commit。

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

## 5. Phase W1：浏览器直连 Relay v2 / E2EE

### Goal

浏览器使用真实 binary WebSocket 直接连 temp TLS Relay，完成 Hello、Challenge、Authenticate、
Authenticated 和一条 sealed sentinel route；不经过业务 bridge。

### Tasks

- [ ] W1.1：实现 WebSocket host adapter，只接受 fixed root `wss://` origin，并由 WASM 固定选择
  `/v2/connect` 或 `/v2/pair`；拒绝 path/query/fragment、text frame 和 redirect。
- [ ] W1.2：把现有 Relay v2 handshake 改造成 transport-neutral core；JS 只发送 WASM 产出的 binary bytes。
- [ ] W1.3：加入 per-generation connect/write/cleanup deadline、single-flight 和旧 generation 隔离。
- [ ] W1.4：runner 启动 fresh TLS Relay、隔离 Chromium 测试信任和预置 test principal，取得真实
  Hello→Authenticated readback。
- [ ] W1.5：覆盖 wrong relayServerId、tampered challenge/signature、replay、text/oversize、断线和 Relay
  restart 负例；所有错误保持零业务 mutation。
- [ ] W1.6：扫描 Relay DB/WAL/SHM、browser console/trace 和日志，确认 sentinel/plain secret absent。
- [ ] W1.7：更新文档并形成 W1 scoped commit。

### Gates

```bash
bash scripts/run-relay-web-companion-e2e.sh --contract
bash scripts/run-relay-web-companion-e2e.sh --transport
cd web/relay-test-companion
bun run check
bun run test:unit
bun run test:e2e -- --grep 'W1'
cd ../..
cargo test -p agentdeck-protocol -p agentdeck-crypto -p agentdeck-relay-client
cargo test -p agentdeck-relay --features server,tls --test relay_v2_tls_e2e
bash scripts/check-daemon-network-boundary.sh
bash scripts/check-daemon-no-net.sh
scripts/verify-agent-docs.sh
git diff --check
git status --short --branch
```

### Exit

真实 browser PID、WSS endpoint、connection generation、Authenticated terminal、sealed sentinel、
明文扫描和 cleanup 全部读回。该 PASS 只证明 test TLS policy 下的直连，不关闭 production SPKI pin。

## 6. Phase W2：完整远程业务纵向链路

### Goal

复用现有 R4 fixed-topology host，把远程 UI 从 iOS Simulator 扩展为独立浏览器 principal，完成一条完整
业务闭环；iOS E2E 继续保留并作为回归门禁。

### Tasks

- [ ] W2.1：实现 PairInvite paste/inspect/trust preview；确认前零网络，确认后才连 `/v2/pair`。
- [ ] W2.2：复用 WASM HPKE/签名和 durable state 完成 pair request/response/terminal；被控 Mac 仍只经
  existing same-UID `LocalPairingAdministration` approve/cancel。
- [ ] W2.3：实现最小 machine/catalog/conversation 页面和 open/prompt/approval 操作；UI 只消费 typed
  WASM view state。
- [ ] W2.4：runner 串起真实 RuntimeCore/RemoteLink、synthetic Codex/Claude Code、Relay 和浏览器，读回
  list/open/prompt/assistant/approval terminal。
- [ ] W2.5：强制 page reload + WebSocket reconnect，验证 durable cursor/backfill、counter 单调和副作用不重复。
- [ ] W2.6：执行 revoke-self，验证 signed terminal、浏览器材料清理、连接关闭和旧 identity 不可重连。
- [ ] W2.7：加入 wrong invite/fingerprint、remote cannot-confirm pairing、approval loser、stale/replay/nonce reuse
  反例和零 mutation 断言。
- [ ] W2.8：更新 README/ARCHITECTURE/QUALITY/DIAGNOSTICS/runbook 中实际新增边界，形成 W2 scoped commit。

### Gates

```bash
bash scripts/run-relay-web-companion-e2e.sh --business
cd web/relay-test-companion
bun run test:e2e -- --grep 'W2'
cd ../..
bash scripts/run-relay-companion-simulator-e2e.sh
bash scripts/verify-relay-companion-mvp.sh p5
cargo test -p agentdeck-web-core -p agentdeck-protocol -p agentdeck-crypto
swift test --filter AgentDeckSessionSourceTests
scripts/verify-agent-docs.sh
git diff --check
git status --short --branch
```

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

W2 单轮 fresh business E2E PASS，iOS Simulator 权威 E2E 不回归。该阶段仍不能标记物理设备、公网、
production signing 或真实 vendor PASS。

## 7. Phase W3：durable recovery、隔离与重复性

### Goal

证明浏览器不是只在 happy path 工作：counter/state 三个 durable cut、tab contention、browser crash、Relay
restart 和网络中断都能 fail-close 或恢复到唯一合法状态。

### Tasks

- [ ] W3.1：为 counter reservation、sealed state commit、Stable finalize 三个 cut 增加 deterministic fault seam；
  每个 cut 重启后只能整块跳号或 exact finalize。
- [ ] W3.2：覆盖 replay/cursor statePending 的 previous rollback、exact next finalize 与 sibling/fork quarantine。
- [ ] W3.3：启动第二 tab/worker，验证 Web Locks 排他、旧 generation/BroadcastChannel 失效和零重复发送。
- [ ] W3.4：在 prompt/approval/reconnect 各阶段强制 kill browser process，再以同 profile 冷恢复。
- [ ] W3.5：使用 runner-owned 故障代理注入断连/延迟/Relay restart；代理只转发 bytes，不解析协议。
- [ ] W3.6：同一 committed candidate 连续三次 fresh 完成 W2 business + W3 recovery；任一轮失败重新计数。
- [ ] W3.7：执行 spec/security 与 quality/Git 双路 review，清零 P0/P1/P2，更新文档并形成 W3 scoped commit。

### Gates

```bash
bash scripts/run-relay-web-companion-e2e.sh --recovery
for run in 1 2 3; do
  bash scripts/run-relay-web-companion-e2e.sh --business
done
cd web/relay-test-companion
bun run check
bun run test:unit
bun run test:e2e
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

- [ ] W0 证明 WASM parity 与 IndexedDB/Web Locks durable contract。
- [ ] W1 浏览器直连真实 Relay v2/E2EE，无业务 bridge。
- [ ] W2 完成完整远程业务流，iOS E2E 不回归。
- [ ] W3 crash/restart/tab contention 与三次 fresh run 全绿。
- [ ] TypeScript 无 wire/crypto owner；Relay/Runtime/E2EE 版本未变。
- [ ] 文档、diagnostics、quality、runbook 与实际一致。
- [ ] candidate 双路 review P0/P1/P2=0，cleanup absent，Git clean。
- [ ] W4 外部 evidence 独立保持 BLOCKED 或由真实证据关闭。
