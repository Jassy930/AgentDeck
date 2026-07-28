# AgentDeck Relay Companion MVP 救援实施计划

| 字段 | 值 |
|---|---|
| 状态 | In execution；R0 complete，R1 pending |
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

- [ ] R1.1：只读生成 merge-base、冲突面和 path manifest。
- [ ] R1.2：合入 `master`，逐文件解决冲突；禁止整侧覆盖。
- [ ] R1.3：先跑 Swift/AppKit focused 和 P5.7 dual-scope，再跑 P4 automatic。
- [ ] R1.4：完整 Rust/Swift/iOS/运行态门禁与双路 review。
- [ ] R1.5：提交唯一 master-sync commit，读回 clean status。

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
- UI 只消费 SessionSource domain model，不 import wire 类型。
- 版本/schema/mirror 变化必须更新 ownership 并触发完整 parity gate。

### Tasks

- [ ] R2.1：写 ownership verifier RED tests。
- [ ] R2.2：生成 current manifest，不改变 wire bytes。
- [ ] R2.3：增加 UI/domain 静态边界和四 schema parity 门禁。
- [ ] R2.4：运行 protocol/crypto/Swift focused、schema diff 与双路 review。
- [ ] R2.5：提交治理工件，读回无协议/DB版本变化。

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

- [ ] R3.1：assembly/state tests 证明只有 local scope 有 `LocalPairingAdministration`。
- [ ] R3.2：approve/cancel single-flight、AlreadyHandled、fingerprint 绑定和迟到结果反例。
- [ ] R3.3：最小 UI；普通 controller 只依赖 protocol，不 downcast concrete source。
- [ ] R3.4：focused/full Swift、selfcheck、NoVendorBranch/static 门禁。
- [ ] R3.5：真实打开 fixture/local UI，读回所有状态。
- [ ] R3.6：双路 review、文档、clean status 和 scoped commit。

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

## 10. Phase R4：固定拓扑 Simulator E2E 与 P5 verifier

### Files

- Create: `ios/AgentDeckMobileUITests/RelayCompanionUITests.swift`
- Create: `agentdeck-cli/examples/synthetic_adapter_host.rs`
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

- [ ] R4.1：脚本 contract tests 和 UI E2E RED。
- [ ] R4.2：synthetic adapter host 与 temp Relay/daemon orchestrator。
- [ ] R4.3：production Swift client + iOS UI 完成 pair/list/open/prompt/approval。
- [ ] R4.4：client/daemon relaunch、cursor/backfill reconnect 与 revoke terminal。
- [ ] R4.5：外部 runner 严格只读 BLOCKED preflight，固定以 exit 78 表示预期未解锁。
- [ ] R4.6：扩展 verifier `p5`；automatic 缺失/失败必须非零，外部 BLOCKED 不计入 PASS。
- [ ] R4.7：同步文档并提交 R4 implementation candidate。
- [ ] R4.8：同一 committed candidate 连续三次 fresh E2E。
- [ ] R4.9：同一 candidate 双路 review、cleanup 与 clean status；若修改代码，从 R4.7 重来。

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
| R1 master 同步 | pending | — | — | — | — | — |
| R2 协议治理 | pending | — | — | — | — | — |
| R3 P5.8-lite | pending | — | — | — | — | — |
| R4 Simulator E2E | pending | — | — | — | — | — |
| R5 MVP 收口 | pending | — | — | — | — | — |

状态只能按实际证据更新。focused PASS 不得把 Phase 标为 complete；外部 BLOCKED 不得改写为 PASS。
