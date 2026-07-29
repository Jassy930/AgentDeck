# AgentDeck Relay Companion MVP 救援实施计划

| 字段 | 值 |
|---|---|
| 状态 | In execution；R0–R3 complete，R4.1–R4.3 complete、R4.4 pending |
| 日期 | 2026-07-28 |
| 基线 | `codex/relay-companion-mvp` / `e400c1c` |
| 目标 | 保留已验证的 P0–P5.7 基础，只交付一条可重复、可读回、可收口的 Companion automatic MVP 纵向链路 |
| 产品边界事实源 | `2026-07-10-relay-companion-mvp-design.md` |
| 历史约束输入 | `2026-07-10-relay-companion-mvp-implementation.md`、`2026-07-18-relay-companion-mvp-course-correction.md` |
| 被取代范围 | 旧 implementation 中尚未完成的 P5.8、P5.9、P5 Phase Exit 与 P6 执行范围 |

## 1. Goal

在不推倒 singleton RuntimeCore、Relay v2、RemoteLink、持久 CLI 和 Swift SessionSource 的前提下，把当前
Relay 分支收敛为一个边界明确的 automatic MVP：

```text
fresh temp TLS Relay
+ 一台真实 agentdeckd / RemoteLink
+ synthetic Codex / Claude Code adapter
+ same-UID 本机配对确认
+ production Swift Relay client
+ iOS Simulator

pair → list/open → prompt → approval → relaunch/reconnect → revoke
```

本计划只证明上述自动链路。production-signed Keychain/LaunchAgent、物理 iPhone、公网 WSS、第二台 Mac、
真实 vendor login、干净 Linux systemd host 与 destructive purge 证据保持 post-MVP `BLOCKED`。

## 2. Architecture

- 保留每个 macOS 登录用户唯一常驻 `agentdeckd`；本机 UDS 与 RemoteLink 只做 transport/principal。
- `RuntimeCore` 继续唯一拥有 conversation、command、approval、event sequence 与 idempotency。
- Relay v2 继续只路由最小元数据、公开授权材料和密文；不增加业务字段或 plaintext 路径。
- Runtime 固定 v5、Relay 固定 v2、E2EE 固定 v1；rescue MVP 禁止新增协议或物理 schema 版本。
- macOS 只补被控机本地 pending-device approve/cancel 控制面，不交付远程 macOS machine picker。
- iOS Simulator 是 automatic MVP 唯一远程 UI；CLI 保留诊断和 deterministic harness 能力。
- P6 四 principal、完整故障注入、真实跨网/设备和运维矩阵全部后置。

## 3. 权威关系与硬停止线

1. P0–P4 automatic 与 P5.1–P5.7 已完成记录继续有效，不重写历史、不重复造证据。
2. 旧实施清单中未完成的 P5.8–P6 只作历史参考，不再直接执行。
3. 只允许修改能直接推进固定纵向链路的代码、测试、脚本和文档。
4. 以下事项转入 post-MVP：新协议/存储版本、新 crash matrix、remote macOS 完整控制面、多 principal
   压力矩阵、APNs/后台 WSS、Hosted/multi-tenant、production signing、物理设备、公网和真实 vendor。
5. 阶段失败只能回到本阶段或前一阶段修复；不得放宽断言、把 BLOCKED 改成 PASS 或跳过 cleanup。
6. 不 push。每个阶段由用户确认后进入下一阶段；每阶段形成一个独立、可验证的 scoped commit。

## 4. 统一闭环节奏

### 4.1 Task 闭环

1. **入口读回**：记录 `git status --short --branch`、HEAD、Task、允许路径 manifest、并行进程和外部输入。
2. **RED**：先增加最小失败测试或 deterministic assertion；保存真实命令、退出码和失败原因。历史 RED
   不存在时明确记录“未保留”，不得补写虚构 transcript。
3. **最小实现**：只修改 manifest 内路径；不升级版本、不新增旁路、不做无关重构。
4. **Focused GREEN**：运行直接相关测试、lint、format；失败后从对应 RED/GREEN 步骤重跑。
5. **Integration GREEN**：运行阶段集成门禁，检查 schema、network/no-net、fixture/secret 静态边界。
6. **双路复审**：同一冻结 candidate hash 上执行 `spec/security` 与 `quality` review；P0/P1/P2 清零。
   修改代码后 candidate hash 变化，旧门禁和 review 全部失效。
7. **读回与文档**：读回用户状态、receipt、terminal、cleanup 和 BLOCKED 槽位；只记录实际证据。
8. **工作区与提交**：`git diff --check`、`git status --short --branch`、精确暂存、staged diff 检查，
   一个 Task 一个 scoped commit，不 push。

### 4.2 Phase 闭环

- 本阶段所有 Task 完成 Task 闭环。
- Phase verifier 在已提交 candidate 上 exit 0。
- 自动 PASS 与外部 `BLOCKED` 分轴读回；absence 不得当 PASS。
- 至少一次真实运行态或 UI readback；编译/fixture 不代替运行态证据。
- 同一 candidate hash 的 `spec/security`、`quality` phase review P0/P1/P2=0。
- README/ARCHITECTURE/QUALITY/DIAGNOSTICS/runbook/计划与实际证据一致。
- 无生成工程、DB、Keychain 测试项、截图、日志或临时证书进入 git。
- 阶段提交后 `git status --short --branch` clean。

### 4.3 证据格式

每个 Task/Phase 在本计划状态表和 `docs/QUALITY.md` 记录：

```text
stage/task:
candidateCommit:
candidateTreeHash:
commands:              # 精确命令
results:               # exit code、passed/failed/skipped/ignored
runtimeReadback:       # PID/endpoint/generation/receipt/terminal/cleanup，全部脱敏
blockedSlots:          # versioned BLOCKED record
changedPathsHash:
review:                # spec/security、quality
gitStatus:
```

原始日志、DB、密钥、证书、截图和运行 artifact 只放私有临时目录；仓库只记录脱敏摘要、命令、hash 和
可复算 manifest。任何 `skipped/ignored` 必须单列原因，不能计入 PASS。

## 5. 阶段总览

| 阶段 | 目标 | 预计节奏 | 退出结果 |
|---|---|---:|---|
| R0 | 冻结事实、建立 rescue 入口 | 1 天 | 基线可重放，旧 P5.8–P6 停止扩张 |
| R1 | 同步 `master` 并恢复门禁 | 2–4 天 | rescue 包含主线，P4/P5.7 无回归 |
| R2 | 冻结协议所有权和版本 | 1–2 天 | v5/v2/v1 owner/漂移门禁可机器检查 |
| R3 | P5.8-lite 本机配对确认 UI | 3–5 天 | 被控 Mac 可读回 fingerprint 并 approve/cancel |
| R4 | 固定拓扑 Simulator E2E 与 `p5` verifier | 4–7 天 | 完整纵向链路连续三次 fresh PASS |
| R5 | 全量回归、复审和 candidate 收口 | 2–3 天 | `Implemented (MVP automatic scope)` candidate |

总计约 2–3 周，不包含 post-MVP 外部槽位解锁。

## 6. Phase R0：基线冻结与执行入口

### Scope

- 保留当前分支作为历史基线；后续在 `codex/relay-mvp-rescue` 继续。
- 冻结 protocol/runtime/storage 版本和 P4/P5.7 已验证能力。
- 把本计划登记为当前执行 SSOT，旧计划剩余项停止执行。

### Tasks

- [x] R0.1：记录 HEAD、tree hash、分支/上游、worktree、master divergence 与状态。
- [x] R0.2：未改生产代码的 candidate 上重跑既有自动基线。
- [x] R0.3：复核新旧计划权威关系、停止线、自动/外部证据两轴。
- [x] R0.4：精确提交 R0 文档，确认 clean；用户确认后进入 R1。

### Automatic gates

```bash
git status --short --branch
git rev-parse HEAD^{commit} HEAD^{tree}
git rev-list --left-right --count master...HEAD
git diff --check
bash scripts/verify-relay-companion-mvp.sh p4-auto
RUSTC_WRAPPER= swift test --filter \
  'AppDelegateTerminationTests|LocalDaemonSessionSourceTests|MachineScopeRealIntegrationTests|MachineScopeRoutingTests|SessionSourceRegistryTests'
scripts/verify-agent-docs.sh
```

### Manual/readback gates

- 旧计划未完成 P5.8–P6 已被本计划覆盖，不再是默认入口。
- 当前 P4=7/7、P5=7/9、P6=0/4 与 post-MVP BLOCKED 列表一致。
- 没有创建额外远端、tag、push 或运行数据。

### Exit

基线记录一致且可复核；文档 gate PASS；阶段提交后 clean。既有门禁失败则 R0 `BLOCKED`。

## 7. Phase R1：同步 master 并恢复门禁

### Scope

- 从冻结基线创建 `codex/relay-mvp-rescue`，以 merge 保留历史合入 `master`，不重写既有提交。
- 只解决集成冲突和主线漂移回归，不新增 Relay 功能。

### Expected conflict surface

- `Sources/AgentDeck/HistorySidebarViewController.swift`
- `Sources/AgentDeck/InputBarView.swift`
- `Sources/AgentDeck/SessionViewController.swift`
- `Sources/AgentDeck/SessionModel.swift`
- protocol schema/fixture、README/ARCHITECTURE/QUALITY/index

### Tasks

- [x] R1.1：只读生成 merge-base、冲突面和 path manifest。
- [x] R1.2：合入 `master`，逐文件解决冲突；禁止整侧覆盖。
- [x] R1.3：先跑 Swift/AppKit focused 和 P5.7 dual-scope，再跑 P4 automatic。
- [x] R1.4：完整 Rust/Swift/iOS/运行态门禁与双路 review。
- [x] R1.5：提交唯一 master-sync commit，读回 clean status。

### Focused gates

```bash
git merge-base --is-ancestor master HEAD
RUSTC_WRAPPER= swift test --filter \
  'AppDelegateTerminationTests|LocalDaemonSessionSourceTests|MachineScopeRealIntegrationTests|MachineScopeRoutingTests|SessionSourceRegistryTests|NoVendorBranchInUITests'
bash scripts/verify-relay-companion-mvp.sh p4-auto
```

### Phase gates

```bash
RUSTC_WRAPPER= cargo test --locked --no-fail-fast -- --test-threads=1
RUSTC_WRAPPER= swift test -Xswiftc -warnings-as-errors
(cd ios && xcodegen generate && \
  xcodebuild -project AgentDeckMobile.xcodeproj -scheme AgentDeckMobile \
    -destination 'platform=iOS Simulator,name=iPhone 17' test)
RUSTC_WRAPPER= bash scripts/run-local-runtime-smoke.sh
RUSTC_WRAPPER= swift run AgentDeck -- --selfcheck
RUSTC_WRAPPER= swift run AgentDeck -- --diagnostics-report --json
scripts/verify-agent-docs.sh
git diff --check
git status --short --branch
```

### Manual/readback gates

- 启动 App，读回本机历史、输入栏、会话切换和窗口交互无主线回归。
- local scope 只走 UDS；remote source 走真实 RemoteLink；事件不串线。
- App 关闭不终止 stable daemon；test/preview 不接触 production namespace。

### Pre-closeout readback（2026-07-28）

- merge-base 为 `81f4c27db519556b90c245ce83f6a308d453b0e3`；冻结 rescue HEAD 为
  `1950f939135e9acc1ed824456b66961041217015`，`master` / `MERGE_HEAD` 为
  `8f895eaecbf7ea22e27d66293917ee9c31c4a34e`。同步前 `HEAD...master` 为 `275/36`，master
  输入共 120 个路径；40 个文本冲突已逐文件解决，`git ls-files -u` 为空。
- 最终候选相对 rescue HEAD 为 116 个路径、`+15178/-4925`。其中 115 个为 master 同步与集成修复路径，
  另 1 个为本 rescue 实施计划；大部分体量来自 master 已提交的 AppKit 富渲染、
  Codex 0.145.0 官方 schema/`thread/list`/`thread/read` 兼容与打包脚本，不是 R1 新增 Relay 平台。
  冲突收敛继续保留 Runtime v5 canonical UDS、singleton stable daemon、`SessionSource`、exec/metadata gate 和
  canonical `conversationID`；普通 GUI 没有新增 daemon child。
- master 侧旧 `DaemonLaunchTests`、`SessionModelHistoryMutationTests` 与
  `SessionModelHistoryNavigationTests` 没有进入最终树：前者验证 App-owned daemon，后两者验证直接 history
  mutation/navigation，均与 rescue 冻结边界冲突。相同行为由 shared-daemon transport、Runtime metadata、
  canonical catalog/sidebar 与 composer integration 测试覆盖。
- 打包 Preview 首轮运行出现“窗口可交互但历史永远 loading、异步新会话不执行”。LLDB 读回
  `runtimeConnectionAvailable=false` 且 operation task 已创建未调度；根因是 `main.swift` 顶层 `await` 把入口变为
  async main，随后同一 MainActor task 阻塞在 `NSApplication.run()`。修复把 headless async selfcheck/smoke 收进
  `runBlockingAsync`，GUI 恢复同步入口；Preview fixture 的 register/select 延后到事件循环后的 `prepare()`，
  history 使用 completion barrier，不再 MainActor 轮询。
- focused warnings-as-errors 为 `35 passed / 0 failed`；`p4-auto`、local Runtime smoke、diagnostics 和 fresh iOS
  `133/133` 已通过。重新打包 `./script/build_and_run.sh --verify` PASS；真实 Preview 显示 3 条历史、可切换会话，
  新会话 `relay rescue ui qa` 收到 synthetic terminal，窗口从 `929x760` 缩放为 `859x760`，关闭后进程 exit 0。
  stable selfcheck 因当前账号没有 production-signed LaunchAgent/socket 继续 typed `BLOCKED`，不记为 PASS。
- 当前仍处于 `git merge --no-ff --no-commit master`。R1.4 最终全量门禁、候选 hash 和双路 review，以及 R1.5
  唯一 merge commit/clean status 尚未完成；不得把本段 pre-closeout 证据写成 R1 complete。

### Final automatic gate readback（2026-07-28）

- `RUSTC_WRAPPER= swift test -Xswiftc -warnings-as-errors`：`1152 XCTest passed / 4 Keychain entitlement skipped`
  与 `48 Swift Testing passed`，零失败。
- `RUSTC_WRAPPER= cargo test --locked --no-fail-fast -- --test-threads=1`：exit 0；daemon lib
  `1708 passed / 3 ignored`，其余 workspace integration/doc-test 零失败。额外 ignored 仅为交互式 P5.7 host、
  外部 fixture、production-signed Keychain 和显式慢/手动门禁，均未计入 PASS。
- `p4-auto`、隔离 local Runtime smoke 与 diagnostics 均 exit 0；smoke 读回双安装身份、双 owner command、
  owner-scoped receipt、共享 Runtime 收敛且 `fallbackSpawned=false`。四份 schema diff、daemon network/no-net、
  `cargo fmt --check`、agent docs 与 `git diff --check` 全部 exit 0。
- fresh DerivedData iPhone 17 Simulator `.xcresult` 读回 `133 passed / 0 failed / 0 skipped`。production-signed
  stable selfcheck 继续 typed `BLOCKED`，不计入 automatic PASS。
- 冻结 code/test/config manifest 为 96 个路径，按 `git blob-or-DELETED + path` 排序后的 SHA-256 为
  `43f172a6fed614883b8df9280337014473b4d3021818a12779e908d42d19cd8f`；完整 116-path
  `name-status` manifest SHA-256 为 `e491aef9260def4e1f2c0a15f31b26a97a74912b0cc43633030eb2ecb008524b`。
  最终双路复审在同一 code/test hash 上均为 Approved，`P0/P1/P2=0`；本节随唯一 master-sync merge commit
  原子收口，提交后读回 clean，R1 complete。
- `spec/security` 复审确认 Runtime v5 / Relay v2 / E2EE v1、唯一 local UDS、per-machine remote source、
  Runtime exec/metadata gate、vendor-token 边界和 canonical conversation identity 未被 master 同步改写。
  `quality/Git` 复审确认被删除的三份 master 测试只覆盖已拒绝的 App-owned/direct-history 模型，正式路径已有
  shared-daemon、Runtime metadata、sidebar/composer 与 Preview lifecycle 回归；冲突标记、二进制、DB、日志、
  secret 和构建产物均未进入 manifest。两路均无剩余 P0/P1/P2。

### Exit

`master` 是 HEAD ancestor；全部门禁 PASS；冲突修复无新协议/功能；阶段提交后 clean。

## 8. Phase R2：协议版本与所有权冻结

本阶段不迁移 Protobuf、不重写 DTO，只建立 rescue 期间的机器可检治理。

### Files

- Create: `protocol/agentdeck/protocol-ownership.json`
- Create: `scripts/verify-agentdeck-protocol-ownership.sh`
- Create: `scripts/tests/verify-agentdeck-protocol-ownership.sh`
- Modify: `protocol/agentdeck/README.md`、`docs/QUALITY.md`、`ARCHITECTURE.md`

### Contract

- 四条协议轴列出 Rust owner、Swift mirror、schema、fixture、版本常量。
- schema 是生成物；E2EE canonical bytes 由 Rust codec 定义，Swift 以互操作 vectors 证明一致。
- SessionSource 与登记的 UI 边界不 import 或直接引用 Relay/Runtime/E2EE wire 类型；既有 Runtime
  adapter/coordinator 不在 R2 迁移 DTO。
- 版本/schema/mirror 变化必须更新 ownership 并触发完整 parity gate。

### Tasks

- [x] R2.1：写 ownership verifier RED tests。
- [x] R2.2：生成 current manifest，不改变 wire bytes。
- [x] R2.3：增加唯一源目录库存、UI/domain 静态边界和四 schema parity 门禁。
- [x] R2.4：运行 protocol/crypto/Swift focused、schema diff 与双路 review。
- [x] R2.5：提交治理工件，读回无协议/DB版本变化。

### Automatic gates

```bash
bash scripts/tests/verify-agentdeck-protocol-ownership.sh
bash scripts/verify-agentdeck-protocol-ownership.sh
cargo test -p agentdeck-protocol --locked
cargo test -p agentdeck-crypto --locked
swift test --filter 'Runtime|Relay|Crypto|Wire|SessionSource'
cargo run -q -p agentdeck-cli --locked -- protocol schema | diff - protocol/agentdeck/agentdeck-protocol.schema.json
cargo run -q -p agentdeck-cli --locked -- protocol runtime-schema | diff - protocol/agentdeck/runtime-protocol.schema.json
cargo run -q -p agentdeck-cli --locked -- protocol relay-schema | diff - protocol/agentdeck/relay-v2.schema.json
cargo run -q -p agentdeck-cli --locked -- protocol e2ee-schema | diff - protocol/agentdeck/e2ee-v1.schema.json
git diff --check
scripts/verify-agent-docs.sh
```

### Final automatic gate readback（2026-07-28）

- ownership 仓库/隔离正例及 coordinated version、Swift mirror、未登记源、SessionSource 越层、UI wire、
  generated schema 六个反例全部按预期通过。
- Rust protocol 为 `251 tests + 4 doctests`，Rust crypto 为 `66 tests + 1 doctest`；Swift focused 为
  `817 executed / 4 entitlement skipped / 0 failed`，skip 不计入 PASS。
- local IPC v2、Runtime v5、Relay v2、E2EE v1 四份 schema 的 CLI 生成字节逐一 diff exit 0；相对 R1 HEAD
  `19d187a` 没有 protocol/crypto/Swift mirror/schema diff，也没有 Runtime DB physical schema 变化。
- 3-path governance content hash 为
  `14a0c95b0d9a0cd3e0a5ef102157ab60f4233a21c4328bdec1b8953be1d92588`；完整 7-path name manifest hash 为
  `d2c1d2adf9e769b57105d89edeb76e2e9cdcc1e519cb91d32f01154feedcdf2e`。
- `spec/security` 复审收紧未登记源、完整 E2EE owner、协调版本漂移、Package 依赖旁路与注释声明误判；
  重新冻结后 `spec/security`、`quality/Git` 均 Approved，`P0/P1/P2=0`。R2 没有用户运行/UI 行为变化，
  真实运行读回是 production ownership verifier 与四个 CLI schema generator。

### Exit

漏同步可确定性失败；版本和 schema bytes 与 R1 一致；无 UI wire import、第二 DTO family 或新版本。

## 9. Phase R3：P5.8-lite 本机配对确认 UI

### Scope

只实现被控 Mac 本机 pending-device 控制面：fingerprint、approve、cancel、AlreadyHandled 与 typed failure。
不做 remote macOS picker、控制另一台 machine、remote pairing sheet、fleet UI 或无关 AppKit 重构。

### Expected files

- Create: `Sources/AgentDeck/Machines/PendingDeviceApprovalController.swift`
- Create: `Tests/AgentDeckTests/PendingDeviceApprovalTests.swift`
- Modify: minimal AppKit composition/navigation entry、Preview fixture/spies、相关文档

### Tasks

- [x] R3.1：assembly/state tests 证明只有 local scope 有 `LocalPairingAdministration`。
- [x] R3.2：approve/cancel single-flight、AlreadyHandled、fingerprint 绑定和迟到结果反例。
- [x] R3.3：最小 UI；普通 controller 只依赖 protocol，不 downcast concrete source。
- [x] R3.4：focused/full Swift、selfcheck、NoVendorBranch/static 门禁。
- [x] R3.5：真实打开 fixture/local UI，读回所有状态。
- [x] R3.6：双路 review、文档、clean status 和 scoped commit。

### Automatic gates

```bash
RUSTC_WRAPPER= swift test --filter \
  'PendingDeviceApprovalTests|LocalDaemonSessionSourceTests|SessionSourceRegistryTests|NoVendorBranchInUITests'
RUSTC_WRAPPER= swift test -Xswiftc -warnings-as-errors
RUSTC_WRAPPER= swift run AgentDeck -- --selfcheck
scripts/verify-agent-docs.sh
git diff --check
```

### Manual/readback gates

- 展示完整脱敏 DeviceSign fingerprint，不显示 secret、grant 或 key material。
- 确认前远端不能自批；remote/fixture scope 没有批准入口。
- approve/cancel 只执行一次；竞态读回 `AlreadyHandled(winner,state)`。
- transport failure、expired、canceled、security failure 是不同 typed 状态。
- 关闭面板不关闭 stable daemon、其他 scope 或已运行 turn。

### Exit

被控 Mac 具备 iOS pairing 所需最小本地控制面；无 remote macOS/协议扩张；自动与可见读回 PASS。

### Final gate readback（2026-07-28）

- 5-path code/test content hash 为 `9c3bd63c9e56ef244d0d72da3192cfe3ade31b80c7a41675ee804355b56720ba`；
  未修改 local IPC v2、Runtime v5、Relay v2、E2EE v1、schema、daemon 或 Relay 实现。
- focused `46/46`；顶层 warnings-as-errors 为 `1161 XCTest / 4 skipped / 0 failed + 48 Swift Testing / 0 failed`；
  ownership、changed-file strict format 与 diff 门禁均 exit 0。
- stable `swift run AgentDeck -- --selfcheck` 真实读回 `daemon.client.socket_missing`，作为当前账号 canonical
  daemon 缺失的环境 `BLOCKED`，不计 PASS；hermetic local-runtime smoke 用真实 ephemeral daemon/UDS 完成
  Rust + Swift selfcheck、双 installation、receipt/replay/stream/cleanup，exit 0。
- `build_and_run.sh --verify` 读回 exact bundle/helper/resource/minos 后，用真实 AppKit 菜单打开“本机配对请求…”；
  stable daemon 缺失时面板显示 typed transport failure。fixture AppKit tests 读回完整 fingerprint、confirm/cancel、
  AlreadyHandled、expired/canceled/security failure，且 request hash/key material 不可见。
- 最终 `spec/security` 与 `quality/Git` 在同一冻结 code/test hash 上均 Approved，P0/P1/P2=0；R3 exact scoped
  commit 后 clean，未 push。remote picker/pairing sheet、P5.9、真实设备/公网/vendor 仍 pending/BLOCKED。

## 10. Phase R4：固定拓扑 Simulator E2E 与 P5 verifier

### Files

- Create: `ios/AgentDeckMobileUITests/RelayCompanionUITests.swift`
- Reuse: `agentdeckd/tests/relay_v2_machine_e2e.rs` 中既有
  `p57_real_dual_scope_ndjson_host`，禁止再建平行 host/runtime platform
- Create: `scripts/run-relay-companion-simulator-e2e.sh`
- Create: `scripts/tests/run-relay-companion-simulator-e2e.sh`
- Create: physical iPhone/second-Mac read-only BLOCKED runners
- Modify: `ios/project.yml`、`scripts/verify-relay-companion-mvp.sh`、相关文档

### Harness invariants

- fresh private temp root/DB/cert/pin/invite/installation IDs。
- 单一 orchestrator 持有 PID/generation；使用 readiness probe，不以固定 sleep 替代 ready。
- synthetic adapter 只替代 vendor，不替代 daemon、RuntimeCore、PairingCoordinator、RemoteLink、local approval
  或 production Swift client。
- 失败统一 trap：关闭 UI/transport/daemon/adapter/Relay，读回 PID absent，再删除 temp root。
- secret、prompt/output sentinel 不出现在 Relay DB/log/outer frames；仓库不保留运行 artifact。

### Tasks

- [x] R4.1：脚本 contract tests 和 UI E2E RED。
- [x] R4.2：复用 synthetic adapter host，完成 temp Relay/daemon/Simulator orchestrator 与 waiting/零授权/cleanup
  闭环。
- [x] R4.3：production Swift client + iOS UI 完成 pair/list/open/prompt/approval。
- [ ] R4.4：client/daemon relaunch、cursor/backfill reconnect 与 revoke terminal。
- [ ] R4.5：外部 runner 严格只读 BLOCKED preflight，固定以 exit 78 表示预期未解锁。
- [ ] R4.6：扩展 verifier `p5`；automatic 缺失/失败必须非零，外部 BLOCKED 不计入 PASS。
- [ ] R4.7：同步文档并提交 R4 implementation candidate。
- [ ] R4.8：同一 committed candidate 连续三次 fresh E2E。
- [ ] R4.9：同一 candidate 双路 review、cleanup 与 clean status；若修改代码，从 R4.7 重来。

### R4.1 RED readback（2026-07-28）

- 入口 HEAD 为 R3 scoped commit `216dbb3`，工作树 clean；本切片只新增独立
  `AgentDeckMobileUITests` target / `RelayCompanionE2E` scheme、首个 production pairing UI test 和 runner
  contract test，不修改 production app、Runtime、Relay、协议或 remote macOS UI。
- `bash scripts/tests/run-relay-companion-simulator-e2e.sh` 按预期 exit 1，唯一失败为缺少可执行
  `scripts/run-relay-companion-simulator-e2e.sh`；contract 已冻结单一六组件 topology、one-line JSON、零 mutation
  与 unknown argument exit 2。
- `xcodegen generate` 后，`xcodebuild -project AgentDeckMobile.xcodeproj -scheme RelayCompanionE2E
  -destination 'platform=iOS Simulator,name=iPhone 17'
  -only-testing:AgentDeckMobileUITests/RelayCompanionUITests/testPairingReachesLocalConfirmation test` 能发现、编译并
  启动 UI test；在没有 `AGENTDECK_RELAY_E2E_INVITE_PATH` 时于 0.55 秒 fail-close，test 1 failed、exit 65。
  App 未 launch，未触发网络、Keychain、pairing 或其他 mutation；没有 fixture fallback。
- 3-path test/config content hash 为 `0662ac6ed04e8cd672f8e1bb5d2dda10ed5b9bfd02fc3a612159af1390f82958`；
  原 `AgentDeckMobile` scheme 仍为 `133/133`、零失败，UI test strict four-space format、shell `bash -n`、
  docs 与 diff 均 PASS。expected RED 只存在于显式 R4 runner/UI E2E 入口，不污染既有 automatic gate。
- 下一步只允许 R4.2 提供 runner `--contract` 与 private invite/host orchestration；不得通过 skip、fixture、固定
  sleep、放宽 0600 文件校验或把 expected RED 写成 PASS 来消除失败。

### R4.2 host-smoke readback（2026-07-29）

- 没有创建 `synthetic_adapter_host.rs` 或第二套本地运行平台；runner 直接启动既有 ignored + env-gated
  `p57_real_dual_scope_ndjson_host`。该 host 已组合 temp Direct TLS Relay、单例 daemon/RuntimeCore、
  RemoteManager/RemoteLink、same-UID UDS、synthetic vendor adapter 和 mode 0600 PairInvite。
- `scripts/run-relay-companion-simulator-e2e.sh` 现有三个 fail-closed 入口：`--contract` 一行 `READY` JSON 且零
  mutation；`--host-smoke` 运行本切片闭环；默认完整入口固定 exit 1 + `INCOMPLETE`，在 R4.3/R4.4 前不能冒充
  完整 E2E PASS。未知参数固定 exit 2。
- 单一 Bash 3.2 orchestrator 通过 FIFO 持有 cargo wrapper PID、真实 host PID 与 fresh generation；严格解析
  `agentdeck-p57-host/v1` NDJSON；host 的 test-only parent seam 被限制到 orchestrator 的 0700 root，使 ready
  前失败也可精确回收。runner 校验 host root 0700、invite/Unix socket 0600、全部路径位于 owned root，并用
  `simctl bootstatus` 等待独占 iPhone 17 Simulator ready，不用固定 sleep 代替 readiness。
- 实测确认 xcodebuild shell env 不会透传 UI test，Simulator 进程也不能直接读取 Mac/Simulator 全局 tmp。
  最终只在 `AgentDeckMobileUITests` target 增加短生命周期桥接：build phase 从受限
  `/private/tmp/ar4.*/ad-p57-host-*/pair-invite.secret` 读取 mode 0600 文件，放入 fresh test bundle；UI test
  立即在自身 sandbox 建立 mode 0600 私有副本、读取后删除，再调用 production `--pair-invite`。runner
  只传路径，不把 invite 明文放入环境、脚本参数、stdout 或仓库；production App target 零改动。
- fresh `--host-smoke` 最终一行 JSON 为 `status=PASS`，本机 host 读回
  `pendingPairingCount=1 / relayGrantTotal=0 / relayGrantActive=0 / runtimeCommandCount=0`；graceful `shutdown`
  又读回 `inviteRemoved=true / socketExists=false`，随后证明 host PID/root/invite/socket 与 owned Simulator 全部
  absent。此前各失败轮次也走同一 trap，现场复核无 orphan PID、temp root 或 Simulator。
- 提交前 fresh gates：runner shell/contract、Rust fmt、仅忽略 3 个 untouched Codex adapter 既有 lint 的
  `relay_v2_machine_e2e` scoped Clippy、UI test strict format、docs 与 diff 均 exit 0；原 `AgentDeckMobile` scheme
  `133/133`、零失败。无 invite 的 `RelayCompanionE2E` 仍按预期 exit 65，精确失败为
  `missingPrivateInvitePath`，证明 bridge 不提供 stale/fallback 输入。未加豁免的 package Clippy 被
  `agentdeckd/src/codex/{app_server,translate}.rs` 的 3 个既有 Rust 1.96 lint 阻断，不计 PASS，也未在本切片
  扩张修复范围。
- 5-path code/test manifest SHA-256 为
  `f18609bb95fd9e4d267ea86c64867604c93703645773138ddd481b1f58cb252b`；文档不进入该 hash，避免证据自引用。
- 该 PASS 只关闭 R4.2 的真实 host + requester waiting + 零授权 + cleanup；list/open、prompt/approval、
  relaunch/reconnect、revoke terminal 仍属于 R4.3/R4.4，P5.9 与 P5 Phase 继续保持未完成。

### R4.3 business-smoke readback（2026-07-29）

- R4.3 没有新增协议、schema、Runtime/Relay 版本或第二套本地平台。既有 P5.7 host 只增加 env-gated
  `r43-business` test scenario：经真实 Runtime UDS 预建一条 Codex 会话、提供 same-UID
  `approvePendingPairing` 命令，并从 Runtime DB 只读汇总 command/approval terminal 计数。production iOS 改动仅为
  machine/session/event/input/approval 控件补稳定 accessibility identifier 和交互式键盘收起，不增加测试旁路。
- runner 新增 `--business-smoke`，编排顺序固定为：启动 production UI → host 精确读回
  `pendingPairingCount=1` 且零 grant/command → same-UID local approve → 等待 machine active、单一 catalog stream、
  transition 清零 → UI list/open/prompt/approval → host terminal readback。默认完整入口仍 exit 1 + `INCOMPLETE`，
  `remaining` 只收敛为 `relaunch-reconnect` 与 `revoke-terminal`，不能把本切片写成 P5.9 PASS。
- 首轮真实运行发现 cold Xcode build 超过原 30 秒 pending wait，runner 随即 fail-close 并完整清理；修复只把 host
  test protocol 的有界 wait cap 扩为 120 秒，没有加入固定 sleep。第二轮读回 pending/local grant 成功，但 UI 在
  host 批准后仍等待瞬态 status label，页面切换使 test 自身退出，daemon 因缺少客户端 ACK 正确保持
  `daemon.remote.transition.business_fenced`。R4.2 已独立验证该 UI waiting 标签；R4.3 改由 host 精确拥有中间态
  断言，UI 继续拥有批准后的业务断言。两轮失败均复核 owned Simulator、host PID 和 `/private/tmp/ar4.*` absent。
- fresh `--business-smoke` 最终一行 JSON 为 `mode=business-smoke / status=PASS`；host 读回
  `runtimeCommandCount=1 / runtimeCompletedCommandCount=1 / runtimeApprovalTotal=1 /
  runtimeApprovalApplied=1`。production Swift client 实际打开 `R4.3 synthetic Codex`，发送
  `R4.3 UI prompt sentinel`，显示 synthetic adapter 经 daemon/Relay 返回的 assistant item 与 canonical approval，
  并读回“已应用批准”。Relay SQLite、存在时的 WAL/SHM 均未发现 prompt、assistant 或 approval sentinel 明文。
- cleanup JSON 证明 host PID/root、invite、UDS 与 owned Simulator 全部 absent。回归门禁为 Rust focused
  `2 passed / 1 interactive host ignored`、scoped Clippy/format/runner contract/Swift strict format PASS；顶层 Swift
  `1161 XCTest / 4 entitlement skipped + 48 Swift Testing` 零失败；原 iOS scheme `133/133` 零失败；docs/diff
  同步门禁 PASS。
- 9-path code/test/runner content manifest 按 `git blob + path` 排序后的 SHA-256 为
  `5561551ea1a2678c8bc14cb950efa359c1728f86a6c4832e0f8f4f1de17f090d`；文档不进入该 hash。R4.4 的
  relaunch/reconnect/revoke terminal、R4.5–R4.9、完整 P5.9 与 P5 Phase Exit 仍未完成。

### Automatic gates

```bash
bash scripts/tests/run-relay-companion-simulator-e2e.sh
for run in 1 2 3; do bash scripts/run-relay-companion-simulator-e2e.sh; done
bash scripts/verify-relay-companion-mvp.sh p5
swift test --filter AgentDeckSessionSourceTests
swift test --filter AgentDeckRelayClientTests
scripts/verify-agent-docs.sh
git diff --check
git status --short --branch
```

### Post-MVP BLOCKED readback（不计入 automatic gates）

两个 runner 只能执行零写入 preflight，并以 exit 78 + versioned JSON 表示槽位仍为 `BLOCKED`。exit 0、其他
退出码、产生授权/配对/运行数据或缺少 cleanup readback 都是 R4 失败，不能转写为 PASS：

```bash
set +e
bash scripts/run-relay-companion-ios-device-smoke.sh; ios_rc=$?
bash scripts/run-relay-companion-macos-e2e.sh; macos_rc=$?
set -e
test "$ios_rc" -eq 78
test "$macos_rc" -eq 78
```

### Required readback

| 能力 | 必须证据 |
|---|---|
| Pair | requester waiting、本机 fingerprint、local approve、paired terminal、独立 route/request hash |
| List/Open | 真实 daemon 产生 catalog/snapshot，iOS production source 显示 |
| Prompt | daemon Accepted + canonical command/turn/event；RouteAccepted 不冒充成功 |
| Approval | daemon first-wins，Applied/AlreadyHandled canonical 收敛 |
| Reconnect | relaunch 后 durable cursor/backfill 恢复，无重复命令/审批 |
| Revoke | signed revoke、terminal close、材料删除且不可重连 |
| Security | Relay 可见面零业务明文，错误 key/pin/replay fail-closed |
| Cleanup | owned PID/temp DB/cert/invite/root absent，git clean |

### Exit

同一 candidate 三次 fresh E2E PASS；`p5` exit 0 只表示 automatic MVP；修复行为后必须重跑三次。

## 11. Phase R5：MVP candidate 收口

本阶段原则上不改生产行为。若需要改生产代码，回到 R3/R4，旧 candidate hash、review 和证据全部作废。

### Tasks

- [ ] R5.1：基于 R4 证据更新状态/文档，清理生成物并提交 closeout candidate。
- [ ] R5.2：冻结最终 commit/tree/path hashes，运行完整 Rust/Swift/iOS/P4/P5 门禁。
- [ ] R5.3：在同一最终 candidate 上执行 phase `spec/security`、`quality` review，清零 P0/P1/P2。
- [ ] R5.4：逐项读取 post-MVP BLOCKED，确认 exit 78、零 mutation 和 versioned summary。
- [ ] R5.5：读回文档、cleanup、diff/status；任何仓库修改都会使 candidate 失效并回到 R5.1。
- [ ] R5.6：仓库保持只读和 clean，向用户报告；由用户决定是否 push/PR/合入。

### Final gates

```bash
RUSTC_WRAPPER= cargo test --locked --no-fail-fast -- --test-threads=1
RUSTC_WRAPPER= swift test -Xswiftc -warnings-as-errors
(cd ios && xcodegen generate && \
  xcodebuild -project AgentDeckMobile.xcodeproj -scheme AgentDeckMobile \
    -destination 'platform=iOS Simulator,name=iPhone 17' test)
bash scripts/verify-relay-companion-mvp.sh p4-auto
bash scripts/verify-relay-companion-mvp.sh p5
bash scripts/run-local-runtime-smoke.sh
swift run AgentDeck -- --selfcheck
swift run AgentDeck -- --diagnostics-report --json
cargo fmt --all -- --check
bash scripts/check-daemon-network-boundary.sh
bash scripts/check-daemon-no-net.sh
scripts/verify-agent-docs.sh
git diff --check
git status --short --branch
```

### Final automatic MVP DoD

- [ ] singleton daemon/UDS/RemoteLink 只有一个 canonical Runtime owner。
- [ ] Relay v2 TLS/E2EE/pair/revoke/stream/ACK automatic PASS。
- [ ] 本机 pending-device UI 只能 local approve/cancel。
- [ ] iOS Simulator fresh 完成 pair/list/open/prompt/approval/reconnect/revoke。
- [ ] `p4-auto` 与 `p5` 在同一 committed candidate exit 0。
- [ ] 三次 fresh E2E 一致，cleanup absent。
- [ ] 四 schema、跨语言 parity、network/no-net、secret/plaintext、docs/diff/status PASS。
- [ ] 双路 phase review P0/P1/P2=0。
- [ ] 外部槽位保持 versioned BLOCKED。

全部完成后状态只能写为：

```text
Implemented (MVP automatic scope)
post-MVP external evidence: BLOCKED by explicit slots
```

## 12. Post-MVP backlog（本计划不执行）

- remote macOS picker/pairing/receipt UI；
- 第二本机客户端和四 principal 多写者/故障注入矩阵；
- production-signed Keychain/LaunchAgent；
- 物理 iPhone/FileProtection、公网 WSS/Linux systemd、真实 vendor、第二台 Mac；
- destructive purge evidence、APNs、后台连接、Hosted/team mode；
- Protobuf/IDL codegen 和手写 Swift mirror 渐进替换。

每项另建 design/implementation，不得重新并入本 rescue MVP。

## 13. 阶段状态表

| 阶段 | 状态 | Candidate | 自动门禁 | 运行/UI读回 | Review | Git 状态 |
|---|---|---|---|---|---|---|
| R0 基线冻结 | complete | code `e400c1c`；本阶段 docs commit | `p4-auto` PASS；Swift 50/50；docs/diff PASS | real daemon + local UDS/RemoteLink PASS | 双路 P0/P1/P2=0 | scoped commit 后 clean |
| R1 master 同步 | complete | merge parents `1950f93` + `8f895ea`；code/test hash `43f172a` | Swift 1152/4 skip + 48、Rust 1708/3 ignored、P4 automatic、local smoke、diagnostics、iOS 133/133 及全部静态门禁 PASS | 原生 Preview list/open/prompt/terminal/resize/cleanup PASS；stable signed selfcheck BLOCKED | spec/security 与 quality/Git Approved；P0/P1/P2=0 | 唯一 merge commit；提交后 clean；未 push |
| R2 协议治理 | complete | R1 `19d187a`；governance hash `14a0c95b` | ownership 正/反例、Rust protocol/crypto、Swift 817/4 skip、四 schema/docs/diff PASS | 治理阶段无 UI 行为变化；真实 verifier/CLI generator 读回 PASS | spec/security 与 quality/Git Approved；P0/P1/P2=0 | exact 7-path scoped commit；提交后 clean；未 push |
| R3 P5.8-lite | complete | code/test hash `9c3bd63c` | focused 46/46；Swift 1161/4 skip + 48；ownership/format/diff PASS | real bundle/menu/typed failure + fixture AppKit state matrix PASS；stable daemon BLOCKED | spec/security 与 quality/Git Approved；P0/P1/P2=0 | exact scoped commit 后 clean；未 push |
| R4 Simulator E2E | in progress | R4.1 hash `0662ac6e`；R4.2 hash `f18609bb`；R4.3 hash `5561551e` | business-smoke PASS；Rust 2/1 ignored；Swift 1161/4 skip + 48；iOS 133/133；contract/Clippy/format/docs/diff PASS | pair/local approve/list/open/prompt/approval terminal 与 plaintext-absence/cleanup PASS；reconnect/revoke pending | R4.1–R4.3 Task 证据已闭环；phase review 尚未开始 | R4.3 scoped commit 后 clean；未 push |
| R5 MVP 收口 | pending | — | — | — | — | — |

状态只能按实际证据更新。focused PASS 不得把 Phase 标为 complete；外部 BLOCKED 不得改写为 PASS。
