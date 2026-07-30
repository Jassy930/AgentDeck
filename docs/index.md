# AgentDeck 文档索引

本目录是 AgentDeck 的仓库内记录系统。`AGENTS.md` 只做入口导航；稳定知识必须落到这里或仓库根部的专门文档中。

## 顶层文档

- `../NORTH_STAR.md`：产品北极星、v0.1 双拍和不做什么。
- `../README.md`：项目介绍、当前功能、构建运行和测试入口。
- `../ARCHITECTURE.md`：稳定架构、分层边界、依赖方向和不变量。
- `../AGENTS.md`：代理工作入口和仓库导航。

## 运行与诊断

- `AGENT_DIAGNOSTICS.md`：自检命令、诊断日志位置、Relay v2、P4.2–P4.3 machine/pairing lifecycle、
  P4.4 RemoteLink ingress、P4.5 signed publication/counter recovery、P4.6 persistent CLI/watch 与 durable
  transfer recovery、P5.2 client storage、P5.3 WSS/TLS pin/per-connection transfer、conversation-scoped
  recovery、P5.4 MachineConnection/key-sync/bounded source typed failure、P5.5 canonical/receipt 乱序，以及
  P5.6 Release composition/pairing lifecycle、daemon install/upgrade failure code、v1 marker 显式 reset 和排查流程。
- `QUALITY.md`：按变更范围选择验证命令，以及 Companion MVP P2、P3.1–P3.10、P3 Phase、P4.1–P4.7
  machine identity/enrollment/pairing/RemoteLink ingress/signed publication/persistent CLI/watch、production
  UDS/client/install/smoke、P4 automatic Phase Exit/静态 real-slot sentinel、P5.1 shared SessionSource facade、
  P5.2 Keychain/crash-safe CryptoState、P5.3 WSS/SPKI pin/transfer assembler、P5.4 exact Swift manifest/
  MachineConnection/RelaySessionSource、P5.5 canonical fixture/receipt UI、P5.6 iOS production
  composition/pairing lifecycle 与文档结构检查入口。
- `RELAY_RUNBOOK.md`：production Relay v2 Direct TLS、本机 admin UDS、machine
  enrollment、daemon 本机 status/trust-reset、安全 uninstall purge、fingerprint-bound readback、
  portable signed root-lost purge receipt、P4.5 recovery-gated egress admission，以及 P4.6 persistent
  CLI/watch 与 durable transfer 运维边界。

## 计划与历史

- `plans/README.md`：设计文档和实施计划的命名、内容和归档规则。
- `plans/*-design.md`：功能设计、架构取舍和验收标准。
- `plans/*-implementation.md`：可执行实施步骤、验证命令和收口记录。

### iOS 前端计划（2026-07-03）

- `plans/2026-07-03-ios-uikit-frontend-design.md`：iOS UIKit companion 前端设计；记录原 fixture R3 界面骨架，
  并同步 P5.6 Release Relay composition、完整邀请配对与前后台 lifecycle 的当前边界。
- `plans/2026-07-03-ios-uikit-frontend-implementation.md`：iOS UIKit companion 前端实施计划（Task 1–15，含 AgentDeckCore 共享库抽取）。

### macOS 富文本渲染（2026-07-23）

- `plans/2026-07-23-native-markdown-table-rendering-implementation.md`：在现有 TextKit/NSAttributedString 管线中增加 GFM 表格识别、`NSTextTable` 原生布局、流式降级与像素快照门禁。

### Relay R0 契约 spike（2026-07-07，历史）

- `plans/2026-07-07-relay-r0-contract-spike-design.md`：Relay R0 契约 spike 设计（控制面/数据面分层、fleet 协议、内存 FakeRelay + 真实 daemon 组合、CLI remote 接口基线）。
- `plans/2026-07-07-relay-r0-contract-spike-implementation.md`：Relay R0 契约 spike 实施计划（Task 1–9，含 T1–T4 测试矩阵与文档收口）。

### Relay R1a 传输 + 鉴权骨架（2026-07-08，历史）

- `plans/2026-07-08-relay-r1-design-review.md`：Relay R1 设计评审（就绪度评估、决策拍板、R1a/R1b/R1c 切分）。
- `plans/2026-07-08-relay-r1a-transport-auth-design.md`：Relay R1a 传输+鉴权骨架设计。
- `plans/2026-07-08-relay-r1a-transport-auth-implementation.md`：Relay R1a 12 任务 TDD 实施计划（已全部落地）。

### Relay R1b 存储 + Router 健壮化（2026-07-09，历史）

- `plans/2026-07-09-relay-r1b-storage-hardening-design.md`
- `plans/2026-07-09-relay-r1b-storage-hardening-implementation.md`

### Relay Companion MVP（2026-07-10）

- `plans/2026-07-10-relay-companion-mvp-design.md`：已批准的目标架构；固定 singleton daemon、多读者/多写者串行裁决、按机器独立配对、Relay 严格最小可见与真实 iOS Companion 边界。
- `plans/2026-07-28-relay-companion-mvp-rescue-implementation.md`：当前唯一执行计划；R0–R3 已完成基线
  冻结、master 同步、协议治理与 P5.8-lite 本机确认 UI，当前只执行固定拓扑 Simulator E2E 和 automatic
  MVP 收口。每阶段都有入口、自动门禁、运行/UI 读回、证据、双路 review、cleanup 和 clean Git 状态退出
  条件；P6 与真实设备/公网/vendor 证据全部后置。
- `plans/2026-07-30-relay-web-test-companion-design.md` 与配套 implementation：automatic MVP 收口后的候选
  浏览器测试链路，状态为 Proposed。方案只允许 Rust/WASM 复用现有 Relay v2、Runtime v5 与 E2EE v1，
  TypeScript 只做 WebSocket/IndexedDB/UI host；按 W0–W3 关闭可行性、直连、业务与恢复 automatic 证据，
  W4 继续独立保留物理设备、公网与 production TLS 门禁。
- `plans/2026-07-18-relay-companion-mvp-course-correction.md`：历史纠偏决策；其 Task 粒度门禁、Runtime
  store 离线篡改 fail-close / 同 UID 在线 residual risk 继续约束已实现基线，未完成执行范围由 rescue
  计划覆盖。
- `plans/2026-07-10-relay-companion-mvp-implementation.md`：历史 P0–P6 逐文件 TDD 清单；保留已完成证据，
  未完成的 P5.8–P6 已由 2026-07-28 rescue 计划覆盖，不再直接执行。P0–P2、
  P3.2–P3.8、P3.9-C0-A0/A1/A2 已完成；C0-B3a/B3b/B4/B5 已分别完成并通过
  Task 完整门禁与双路终审；C0-C native history projection 已完成并通过 Task 完整门禁与双路终审，真实当前
  账号 JSONL smoke、Swift 与 iOS Simulator 门禁已通过，production native metadata 仍在 claim 前 post-MVP
  typed gated。P3.9-A Rust、P3.9-B Swift shared-daemon client、P3.9-C3 App model cutover、P3.9-D
  Rust CLI/Swift selfcheck 默认入口和真实双客户端 smoke，以及 P3.9-E App 会话可靠性均已完成并通过各自
  Task 门禁与双路终审；D/E code/test 提交分别为 `b818f81` / `d68cc02`。P3.10 已由 `19622ab` 完成
  schema v7/admin ledger、flush-ACK-gated upgrade 与 LaunchAgent lifecycle；`773a2b3`、`0057824`、
  `81cc314`、`9efb28d` 又完成 verifier 资源/进程组 hardening 与 legacy v1–v6 pre-RW 认证（新增显式
  v1–v4 committed-WAL 矩阵）。基于 code
  baseline `9efb28d` 的独立 `p3` Phase verifier exit 0，四 schema/network/docs/smoke/diagnostics 全绿，
  双路 code review P0/P1/P2 = 0，P3 Phase complete（MVP automatic scope）。P3.1 继续采用方案 b：
  provisioned signed Keychain roundtrip 保留 1 项 post-MVP ignored/BLOCKED，不阻塞主线，也不表示
  production signing PASS。P4.1 已由 `3cd76d2`、`644712c`、`95090c1`、`85df3d2`、`f137112`、
  `46c6bb8` 完成 machine identity、schema v8/24 表、key-directory guard、通用 CounterGuard IO 与
  bootstrap；P4.2 code/test 由 `a6842bc` 收口 Runtime v3、schema v9/25 表、root-signed
  Link/Data cert、durable enrollment/receipt、control-only authenticated MachineLink、两条 trust reset 与
  安全 uninstall purge。P4.3 由 `518380e`、`b28f995`、`55be98f`、`ba3629f`、`4ec3d2f`、`fe3a9ad`、`3b4b977`
  收口 Runtime v4、schema v10/30 表、PairInvite/DeviceGrant/DeviceAuthorization/KeyDirectory、本机 auth
  ledger、revoke 与 control handoff。P4.4 code/test `cd7d9fb` 完成唯一 MachineLink business lane、Relay v2
  outer→DeviceSign/AAD/replay/AEAD→Store exact auth recheck→`RemotePrincipal`→`RuntimeCore` dispatch，
  以及 Active/Inactive/Unprovable 按 conversation 隔离的 recovery；`RouteAccepted` 不等于 command success，
  `RemoteLink` 不持 canonical 业务状态。P4.5 code/test `c6ef387`、`88b3c42` 又完成 MachineDataSign
  signed publication、counter/replay/key transition crash recovery 与 production sealer/publisher 接线；P4.5
  收口时 Runtime wire 为 v4，physical schema 为 v14/35 表。完整 daemon lib `1579 passed / 3 gated ignored`、
  main `7/7`、integration/doc-test 零失败，`runtime_store_boundaries` `5/5`（256 MiB，282.85 秒），
  Clippy/fmt/diff 全绿；双路终审在同一冻结 hash
  `88ac6c486a7446b5fe4613388f66ee25561a7529a2fd0f8904844217730a896f` 上 P0/P1/P2=0。
  P4.6 persistent remote CLI 已完成 automatic Task：current Runtime wire 为 v5；`pair`、
  `machines`、`conversations`、`watch`、`prompt`、`approve`、`retry-approval`、`revoke-self` 均已接入。
  watch 使用 fresh authenticated bootstrap、canonical NDJSON 与 SIGINT/SIGTERM 有序 terminal；paired-state
  V6 durable transfer 的 absolute TTL 不依赖下一帧，prepared ADST v2 mode/commitment 通过认证 recovery
  绑定。2026-07-24 冻结 code/test scope 为 29 paths，blob-manifest SHA-256 为
  `32e7c85620e6e88b407f2403715c52c5a9a5d30aa20d7fb800bdefabe8a1c858`；watch `12/12`、
  `remote_persistent_machines` `11/11`、完整 CLI package final run exit 0、release allocator `1/1`、relay-client
  `25/25` 与 protocol `244/244` 均通过，静态门禁全绿。`spec/security` 与 `quality` 终审均 Approved，
  P0/P1/P2=0。P4.7 automatic Task 与 P4 automatic Phase Exit 已完成；P5.1 又建立共享
  `AgentDeckSessionSource` facade、typed state/receipt 与显式 SwiftPM/iOS product 依赖图；P5.2 已建立
  typed Apple Keychain account、ADCS v1 sealed state、counter/state Pending recovery、4096 replay window 与
  marker-last paired store；P5.3 已建立 generation-scoped WSS、current/next DER-SPKI pin、bounded
  incoming/writer 与 per-connection transfer assembler；P5.4 automatic Task 已建立 shared
  transfer budget、authenticated MachineConnection/key-sync ingress、bounded broadcaster/reducers、scoped
  RelaySessionSource 与 typed command/pairing path，并补齐 unsubscribe single-flight retirement、满 update queue
  shutdown 解锁以及 staged→committed pairing visibility gate；P5.5 又把 iOS fixture/ViewModel 迁移到共享
  `SessionSource` 与 Core canonical reducer，并以 32-identity cap、snapshot mid-turn inference、event-seq retry
  fence、retired-operation 校验与 terminal-only turn advance 保留审批证据；P5.6 已把 iOS Release composition
  切到真实 Relay source，并接入完整邀请配对与前后台 generation lifecycle；P5.7 已建立 macOS 唯一本机 UDS
  source、按机器隔离的 remote source registry、typed local capability、scope generation 与 shutdown/join
  barrier，并用真实 P4 daemon RemoteLink + synthetic adapter 验证 local/remote 双 scope 不串线。P4–P6 按
  Task 进度上限为 7/7、7/9、0/4。`p4-auto`
  已 PASS；`p4` 仍不受支持，
  且 focused aggregate 本身不包含顶层
  Rust/Swift、最终 diff/status、冻结 hash 或双路 review。上述独立门禁与双路 review 已在
  pre-closeout candidate SHA-256
  `18654fa9c398383dafcefa1542c8e48f8c460f1f521806880c5dab083bdb29f5` 上补齐并通过。
  远端 cannot-confirm pairing 由独立 RuntimeCore principal gate 证明；real runner 仍只是不读参数/env、
  不探测或执行的静态 fail-closed sentinel，固定输出完整
  `missingInputs` 与 `BLOCKED/mutations=0/evidence=[]/summaryGenerated=false`。Linux 只用 ephemeral test
  keys，macOS production persistent Keychain 不降级；root-lost 流程以 `RELAY_RUNBOOK.md` 为准。P3.1 方案 b、production-signed
  LaunchAgent/Keychain、物理设备与公网证据继续作为 post-MVP BLOCKED。P5 MVP 只以 iOS Simulator
  自动 E2E 退出；原 course-correction 中的本机第二客户端/P6 synthetic DoD 已由 rescue 计划整体后置。P5.4 已在 Swift
  `42f47dc2eecfcd0ca312b9178583246aad48b9f59d6413fc9814052cb7e1cd1c` 与 Rust
  `4815d82628992281c3e1e032c91364080237ca34e6d94398d376b75ec1f7c30f` 候选上通过 `225/225` focused、
  RelayClient `429/4 SKIP`、完整 Swift `958/4 SKIP + 35`、iOS `26/26` 与完整 Rust/cross-language/static
  门禁；exact scope 为 34 Rust/fixture + 69 Swift + 6 docs = 109 paths。两笔提交按 `34 → 75` 有序依赖，
  第一笔只承诺 Rust scoped-green，完整绿色证据属于组合候选。P5.5 以 code/test/fixture content manifest
  `8dd8610966430a5cf640617da53e34d91bf379fe0ad495ea2ef719a6fec9d5ba` 冻结 52 + 10 docs = 62-path scope；
  除 SessionSource/receipt 迁移外，又在不升级 Runtime v5 的前提下删除 transient canonical Error producer，
  把 command-bound fixed Error 固定为唯一 Failed terminal，commandless Error 保持非终态 diagnostic。
  fresh automatic 证据含顶层 Swift `980 XCTest / 4 skipped + 35 Swift Testing`、warnings-as-errors focused
  `91/91` 与 iOS Simulator `91/91`；上一 command terminal 不消费下一 prompt receipt 的反例也已冻结；
  其余 Rust 精确结果见 `QUALITY.md`。该 Task 收口时 P5 为 5/9。P5.6 后续以 focused `42/42`、Relay
  shutdown `56/56`、RelayClient `445/4 SKIP`、顶层 Swift `985/4 SKIP + 35`、iOS `133/133` 与 Release
  fixture-surface 门禁独立完成；P5.7 exact scope 为 `40 prerequisite + 23 registry + 7 docs = 70 paths`，Genesis
  snapshot recovery、selected-scope reentrancy、`SessionModel` operation join 与 Preview/AppRuntime pump barrier
  均已闭环，fresh 门禁与双路终审见 `QUALITY.md`。rescue R3 的 P5.8-lite 本机 pending-device 控制面也已
  独立闭环，当前 P5 为 8/9；P5.9 与 P5 automatic Phase Exit 仍未完成。P5.1–P5.8-lite/P4 automatic 完成项
  都不表示 P5.9 fixed-topology Simulator
  Relay E2E、真实公网 WSS、production-signed Keychain、第二台 Mac、真实 vendor 或 destructive purge 已完成。

## 协议资料

- `../protocol/SPIKE_FINDINGS.md`：Codex app-server wire framing、方法和 schema 事实源。
- `../protocol/CODEX_VERSION.txt`：生成当前 schema 时使用的 Codex 版本。
- `../protocol/*.json`：官方 schema 快照。
- `../protocol/agentdeck/`：AgentDeck 自身四条独立协议轴的 schema 与说明。current Runtime v5 fixture 为
  `fixtures/runtime-v5-wire.jsonl`；冻结的 v1–v4 fixture 只作兼容证据。各 `*.schema.json` 均由 schemars 从 Rust 类型派生生成（非手写），
  `README.md` 说明生成与更新流程。

## 更新规则

- 代码行为变化时，同步更新对应产品、架构、诊断或计划文档。
- 文档不要重复大段实现细节；稳定事实放专门文档，临时决策放计划文档。
- 如果某条规则需要长期执行，优先补测试、脚本或 CI 检查，而不是只写自然语言。
- 每次阶段性收口前运行 `scripts/verify-agent-docs.sh`，确认文档入口没有漂移。
