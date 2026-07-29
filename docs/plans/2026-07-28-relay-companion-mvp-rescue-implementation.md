# AgentDeck Relay Companion MVP 救援实施计划

| 字段 | 值 |
|---|---|
| 状态 | In execution；终审重开后第四次 replacement R4.7 已冻结，R4.8 pending；R5 暂停 |
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

### R4.4 lifecycle-smoke readback（2026-07-29）

- R4.4 沿用同一个 `p57_real_dual_scope_ndjson_host` 和 production Swift client，没有增加新的本地
  runtime/platform、协议、schema 或存储版本。host 增加的 `r44-lifecycle` 场景只负责持有并重启原
  daemon composition，并通过真实 Runtime DB 读回 conversation、command、approval 和 revocation terminal。
- Relay 的 machine generation 丢失现在只对确定的 disconnect/authorization invalidation/heartbeat timeout
  级联关闭所属 device；普通背压不再关闭 request origin，uncertain purge 保留原始 close reason。Swift
  reconnect 只在已有 `committedProjection` 时 warm-resume；首次订阅失败或无 baseline 必须轮换
  broadcaster generation 并 fresh snapshot。Runtime backfill 先于 Relay publication 时只补 durable outer
  cursor，不重复应用业务 item。
- fresh lifecycle 门禁读回 `daemonGeneration=2 / clientRelaunchHistoryRecovered=true`，重启前后
  `runtimeCommandCount=1 / runtimeCompletedCommandCount=1 / runtimeApprovalTotal=1 /
  runtimeApprovalApplied=1`；revoke terminal 后 `runtimeRevokedAuthorizationCount=1 / relayGrantTotal=1 /
  relayGrantActive=0`。production UI 重启后读回原 conversation 和 `R4.4 daemon restart marker`，没有
  重复 command 或 approval。
- Relay DB/WAL/SHM 未发现 prompt、assistant、approval 或 restart marker 明文；最终 JSON 读回
  `hostPidAbsent/hostRootAbsent/inviteAbsent/socketAbsent/simulatorAbsent=true`。首个 fresh 轮次暴露了
  R4.3 遗留的 30 秒 `businessReady` readiness 窗口：诊断轮在同一代码上完整 PASS，随后只将
  condition wait 收紧为与 lifecycle 总预算匹配的 90 秒，仍由 readiness 驱动且 xcode 提前退出会
  立即 fail-close；调整后 fresh 轮次 PASS。
- 提交前完整 Rust `cargo test --no-fail-fast -- --test-threads=1` exit 0：daemon unit
  `1711 passed / 3 ignored`，Relay route `15/15`、TLS `13/13`，全部 integration/doctest 零失败。
  fresh Swift warnings-as-errors 为 `1167 XCTest / 4 skipped + 48 Swift Testing`，原 iOS scheme `133/133`；
  scoped Clippy、Rust/Shell/Swift format、runner contract、network/no-net、protocol ownership、docs/diff 全部 PASS。
- 20-path code/test/runner manifest SHA-256 为
  `383fa35e4476db10f7016f8dbb92a9bb11cd34423f7e5d94be12f287a4ffc927`；文档不进入该 hash。
  该证据只关闭 R4.4；R4.5–R4.9、完整 P5.9 与 P5 Phase Exit 仍未完成。

### R4.5 external BLOCKED slot readback（2026-07-29）

- 新增物理 iPhone 与第二台 Mac 两个独立 runner；它们各自固定为四行 `/bin/sh` 静态 sentinel，唯一行为是
  输出一行 versioned JSON 并 `exit 78`。runner 不读取参数或环境变量，不探测设备、SSH、公网、真实
  PairInvite、签名、Keychain 或 vendor login，也不创建进程、文件、授权、配对或证据。
- 两条 JSON 都精确保持 `phase=post-MVP / status=BLOCKED / mutations=0 / evidence=[] /
  summaryGenerated=false`，列出各自完整 `missingInputs`；`cleanup.processesRemaining=0 /
  artifactsRemaining=0` 只读回静态 sentinel 的零残留，不冒充真实 preflight 或实机 evidence。
- 独立 contract test 先以缺少 runner 的 exit 1 取得 RED，再验证默认调用与 hostile env/参数调用均返回
  同一 record 和 exit 78。测试同时锁定四行 source、exact keys/数组、单行 stdout，并比较隔离
  HOME/TMPDIR/cwd 的路径+内容快照及仓库 status，全部无变化。
- `bash -n` 与 contract test 均 PASS。3-path code/test content manifest 按
  `blob <git hash-object> <path>` C-locale 排序后的 SHA-256 为
  `50f725a2c479f7b352bc33023d51a4ab6ea0c97d2cbe1365143a348a10bedbcd`；文档不进入该 hash。
  该证据只关闭 R4.5；物理 iPhone、第二台 Mac、公网、真实 vendor 仍是 post-MVP `BLOCKED`，R4.6–R4.9、
  完整 P5.9 与 P5 Phase Exit 仍未完成。

### R4.6 P5 verifier aggregate 收口（2026-07-29）

- `scripts/verify-relay-companion-mvp.sh` 新增唯一的 `p5` aggregate 入口，依次执行 Simulator runner contract、
  external BLOCKED contract、真实 lifecycle E2E、共享 SessionSource、RelayClient 与 agent docs。任一 automatic
  入口缺失或非零都会由 `set -e`/`run_gate` 立即使 verifier 非零，不能被外部槽位遮蔽。
- 两个实机 runner 必须精确返回 exit 78 和 versioned `BLOCKED` JSON；exit 0、其他退出码、额外输出、字段缺失、
  `PASS` 状态或非零 mutation 都使 verifier 失败。成功的 automatic 汇总只打印
  `verify-relay-companion-mvp p5: PASS (automatic scope; external slots remain BLOCKED)`，实机槽位单独打印
  `BLOCKED:`，不计为 PASS。
- 独立 verifier contract 使用隔离临时 fixture 覆盖 valid automatic + external BLOCKED、automatic runner 缺失、
  automatic runner 失败、外部错误 exit 0 与 malformed JSON；fresh 执行 exit 0，且 fixture trap 后无残留。
- UI 的 machine-online 与 catalog-title 条件等待已统一为 120 秒，并由 runner contract 锁定其长于 host 90 秒
  权威窗口；prompt 还必须等待 send button 明确 enabled，不能在首个 conversation snapshot/SyncComplete 前抢跑。
- focused RED 证明首个 Catalog `Subscribe` 可能在 daemon active ingress 建立前被静默丢弃。生产修复只对
  subscription 增加 generation-bound、可取消、有界的 exact retry：复用同一 request route、sender counter 与
  sealed bytes；typed completion、generation teardown 或 12.7 秒窗口结束即停止，普通 prompt/approval command
  不进入盲重试。另以 `canSubmitPrompt` 将 UI readiness 收紧到 connected + 首个 canonical conversation snapshot
  已提交 + nonterminal，关闭 transport connected 后的 prompt 抢跑。
- focused subscription retry/ingress/readiness、完整 RelayClient、fresh `lifecycle-smoke`、完整 `p5` aggregate、
  iOS `134/134`、Swift `1169 XCTest / 4 external entitlement skipped + 48 Swift Testing / 0 failure` 与完整
  `cargo test` 均 PASS。Rust daemon lib 为 `1711 passed / 3 ignored / 0 failed`，其余 workspace integration 与
  doctest 零失败；ignored 均为显式外部门禁，未计入 PASS。fresh lifecycle 在 daemon generation 2 完成
  prompt、approval、restart/history recovery 与 revoke，cleanup 读回全部 absent。
- 11-path code/test/runner content manifest 按 `blob <git hash-object> <path>` C-locale 排序后的 SHA-256 为
  `9c4b7f1a31c4057da00d8f0de9bd2d82947f742c40e94208f4a6e7b288fb4f27`；tracked docs 不进入 hash。旧
  `5bb1d1f69c363da81887055767be46e5478e2d3b6a70a9f8f5716cab5c88ca08` 已失效。
- R4.6 只关闭 automatic aggregate 与上述可靠性缺口。R4.7–R4.9、完整 P5.9/P5 Phase Exit，以及物理 iPhone、
  第二台 Mac、公网、production signing 与真实 vendor 仍未完成或保持 post-MVP `BLOCKED`。

### R4.7 implementation candidate 冻结（2026-07-29）

- R4.6 implementation commit 为 `9c15d72003e678c0ac7802bce03e076128da40a4`，tree 为
  `7855e052ab5f5a505f05774661af0ce775f2edf9`；提交后工作区 clean、未 push，相对本地 `master` 为
  `0 behind / 284 ahead`。
- implementation content 继续由 R4.6 的 11-path hash
  `9c4b7f1a31c4057da00d8f0de9bd2d82947f742c40e94208f4a6e7b288fb4f27` 约束。R4.7 不修改 production、
  test、runner、协议或 schema，只同步本计划与 `docs/QUALITY.md`，并以 docs-only scoped commit 生成 R4
  committed candidate。
- candidate commit/tree 必须在 R4.7 提交后读回，并作为 R4.8 三次 fresh E2E 和 R4.9 双路 review 的唯一输入；
  期间不得 amend、混入代码或切换 HEAD。任何实现修改都使三次计数失效并从 R4.7 重来。
- R4.7 只冻结 candidate，不提前声明三次 fresh E2E、双路 review、完整 P5.9 或 P5 Phase Exit 完成；两个外部
  槽位继续保持 versioned post-MVP `BLOCKED`。

### R4.8/R4.9 重复性与 review 收口（2026-07-29）

> 历史证据，已失效：后续 R5.2 首轮完整 `p5` 暴露 failure cleanup 遗留本轮 `agentdeckd --exec-gate`
> 后代。下列重复性与 review 结论只属于旧 candidate `3fb83e8`，不得继续作为当前 R4/R5 完成证据。

- committed candidate 为 `3fb83e83a34abd659e32b817cf1cabccf999ca79`，tree 为
  `d136544a47f64ffabe0e60a464cc7f8cd18f5f33`，相对本地 `master` 为 `0 behind / 285 ahead`。三次 fresh
  lifecycle E2E 全程保持同一 HEAD/tree，均在 daemon generation 2 完成 command `1/1`、approval `1/1`、
  revoke `1`，最终 active grant `0`。
- 三轮都读回 Relay plaintext absent，host PID/root/invite/UDS/owned Simulator cleanup 全部 absent；没有通过
  重用前一轮 DB、证书、邀请、installation ID 或 Simulator 状态取得假重复性。完整 `p5` 与 `p4-auto` 均 PASS，
  SessionSource `25/25`、RelayClient `457 executed / 4 external entitlement skipped / 0 failed`。
- 同一 candidate 的既有完整门禁继续有效：iOS `134/134`，Swift
  `1169 XCTest / 4 external entitlement skipped + 48 Swift Testing / 0 failed`，Rust daemon lib
  `1711 passed / 3 ignored / 0 failed` 且 workspace 全量零失败。四 schema parity、协议 ownership 正反例、
  daemon network/no-net、external BLOCKED contract、format、shell syntax、docs 和 diff 均通过；未新增协议、
  schema、版本或第二套 runtime platform。
- `spec/security` 与 `quality/Git` 在该 candidate 上均 Approved，`P0/P1/P2=0`。ignored/skipped 只对应显式
  外部门禁，不计入 PASS；物理 iPhone 与第二台 Mac runner 继续精确返回 exit 78、versioned `BLOCKED`、
  `mutations=0`、`evidence=[]`、`summaryGenerated=false`。
- cleanup 时先用 `git check-ignore -v` 确认 `ios/AgentDeckMobile.xcodeproj/` 是 `xcodegen` ignored 产物，再将其
  移出 worktree；`.build`/`target` 缓存未删除。最终无本 worktree Relay/daemon 残留、无 booted Simulator，
  candidate HEAD/tree 未漂移且 `git status --short --branch` clean。R4、P5.9 与 P5 automatic Phase Exit complete；
  最终 MVP candidate 仍必须继续通过 R5.2–R5.6，不能用本节提前宣布整体收口。

### R4.9 failure-path 重开与 replacement R4.7（2026-07-29）

- R5.2 在 closeout candidate `5966c9867848e4ea176d61eeeb296e0c2fb280c3` 上首轮完成 Rust 全量、Swift
  全量、iOS `134/134` 与 `p4-auto`；完整 `p5` 已通过配对、本机批准和 business-ready，但 UI 在 60 秒内未
  观察到 `synthetic Codex response`，`xcodebuild` exit 65。失败 trap 返回后仍存在本轮
  `agentdeckd --exec-gate` PID `54930`、PPID `1`，经精确命令/启动时间核对后 TERM→KILL 并读回 absent。
- 该残留证明旧 runner 未在父进程退出、TERM-resistant 后代 reparent 到 PID 1 时完成失败闭环，因此
  `3fb83e8` 的 R4.9/P5 Phase Exit 与 `5966c98` 的 R5.1 candidate 全部失效；R5.2 的其余首轮 PASS 只保留为
  诊断证据，不可拼接到 replacement candidate。
- replacement implementation commit 为 `5bd57ba33d03abbf7a4fcb7fa2e427a30d329bc2`，tree 为
  `37b7bbe240e601dcc7654349b97318c9e0bd28d5`，相对本地 `master` 为 `0 behind / 287 ahead`。runner 在停止
  cargo 或 host 前递归冻结本轮 PID + `ps lstart` 身份树，TERM 后只 KILL 身份仍精确匹配的已捕获后代，并
  等待其 absent/zombie；不按进程名全局扫描或杀进程。
- contract 真实创建父进程与忽略 TERM 的子进程，分别覆盖 cargo-root 与 host-root 两条 reparent 清理路径；
  `bash -n`、动态 contract、`git diff --check` 均 exit 0，测试后无 probe/Relay/daemon/exec-gate 残留。两路径
  content manifest SHA-256 为 `fd5a6c5e93c1391f4536d5fd9b4746e859c1ad7ca660dbbcb58f60026de9bd61`。
- 首版修复 WIP 的 fresh lifecycle 与完整 `p5` 已 PASS，但随后补齐 host-root fallback，因此这些运行结果不计作
  replacement candidate 的 R4.8 计数。本次 docs-only scoped commit 生成新的 R4.7 committed candidate；其后
  必须从零连续执行三次 fresh lifecycle、完整 `p5`、`p4-auto` 与双路 review，期间任何仓库修改都使证据失效。

### R4.8 revision rollover 重开与第二次 replacement R4.7（2026-07-29）

- 上述 failure cleanup 文档提交生成的 committed candidate 为
  `0f601aeb2e551ae95025e3ad09b99d3c8144a10d`。在它的首轮 fresh lifecycle 调试中，key directory revision
  前进后长期 subscription job 被拆除；因此该轮不计作 R4.8，`0f601ae` 及其后的重复性/全量/review 证据均不得
  继续使用。
- 根因是 RemoteLink 的 `DeviceConnectionKey` 错误包含 request-scoped `authorization_hash` 与
  `key_directory_revision`。subscription 准备推进 revision 后，下一条 prompt 会把同一授权身份误判为新连接，
  断开旧 Runtime connection，并连带销毁已建立的 catalog/conversation subscription job。
- replacement 将 connection identity 收敛为 trust domain、machine/device route、grant serial 与 device-sign
  fingerprint；每个 ingress 仍携带本次 Store-current principal。Core 只允许相同稳定 identity 且共享同一
  revoke lease 的 request principal 挂到连接，command binding、snapshot、catalog 与 subscription pump 均使用
  本次 request snapshot。grant/设备身份变化仍断开，单纯 revision rollover 不再拆连接。
- 新增 `remote_connection_identity_survives_key_directory_revision_rollover` 与
  `remote_envelope_uses_request_scoped_principal_after_revision_rollover`：后者证明 revision 42 prompt 不会回退到
  connection 上的 revision 41 binding，且 revision 41 建立的 live subscription/job 在请求后仍保持 `1/1`。
  P5.7 host evidence 同时把 `BusinessMutated` 收紧为 writers `2`、live subscriptions `2`、barriers `0`、
  snapshot senders `0`、jobs `2`，不再只凭 durable business count 假阳性通过。
- replacement implementation commit 为 `769a5992e1eeb55f719a56d55ac87abc5b03a486`，tree 为
  `2f285772922a1071c2cacceb0c191018d5ba0c40`，8-path code/test manifest SHA-256 为
  `606bfb9061291aa0bd2361277dd3004ccfb1e487a6b45d9c6536214fee9130e6`，相对本地 `master` 为
  `0 behind / 289 ahead`。focused regression `2/2`、RemoteLink `33/33`、machine E2E
  `2 passed / 1 interactive ignored`、daemon lib `1713 passed / 3 ignored / 0 failed`、两组 warnings-as-errors
  Clippy、integration compile、format、network/no-net 与 diff 均通过。
- 本次只更新本计划与 `docs/QUALITY.md`，以 docs-only scoped commit 再次生成 R4.7 committed candidate。提交后
  必须读回 commit/tree/clean status；R4.8 三次 fresh lifecycle、完整 `p5`、`p4-auto` 与 R4.9 双路 review
  全部从该新 candidate 的零状态重新计数。

### R4.8 transition COMMIT/readback 与 restart readiness 重开（2026-07-29）

- 上述 revision rollover 文档提交生成的 committed candidate 为
  `f7d2e681e247cd8098ad8941a7762c379abe5601`，tree 为
  `7b33ec2cf9c28d606868ff1f715cbaf32ab847dd`。其后完整 `p5` 先后暴露两处竞态，因此 `f7d2e68` 失效；
  旧三次 lifecycle、aggregate、全量与 review 证据，以及本轮任何局部 PASS 均不得拼接到新 candidate。
- 第一处失败为 transition 已进入 `Add:BarriersCommitted`，endpoint 在 Store
  `mark_key_barriers_committed_exact()` 返回后、coordinator reload 前合法提交 KeyUpdate ACK；旧 coordinator 将
  `BarriersFrozen` 内存快照与新 readback 做完整 equality，误报永久
  `daemon.remote.transition.readback_mismatch`。该窗口也允许已认证 stream-applied ACK 单调前进。
- 修复继续精确比较 operation/target/revision/recipient、cuts、canonical update bytes、snapshot flushes 与其他稳定
  轴，只放行 Store 已认证的 `Frozen → Acked` 和 stream-applied ACK 集合单调增长；readback 随后仍执行
  `validate_existing_updates` 与 `validate_frozen_barrier_set`。不可变 update bytes 或稳定轴漂移继续 fail-close。
- 第二处失败发生在 daemon restart 后：durable transition 已归零，但 host 在 production client 完成重连订阅前
  发布 marker，最后 evidence 为 writers `1`、live subscriptions `0`、jobs `0`，导致 UI 合理收不到 marker。
  `P57HostWaitCondition::BusinessReady` 现要求 writers `2`、live subscriptions `2`、barriers `0`、snapshot senders
  `0`、jobs `2`；超时会返回完整最后 evidence，避免只凭 control-plane/durable 状态假阳性通过。
- replacement implementation commit 为 `dc24c542806fff427b306edb9eaa667c6f4625ac`，tree 为
  `40365af59d250f9e2aa385f8205b07fd26dbc33f`，3-path code/test content manifest SHA-256 为
  `8031eef7ce3825addc8f86ef96edea3b2151c8353a61bdb5fb492d7b05b2f974`，相对本地 `master` 为
  `0 behind / 291 ahead`。新增三项 COMMIT/readback 回归均通过，最终 transition suite `33/33`、machine E2E
  `2 passed / 1 interactive ignored`、daemon lib `1716 passed / 3 ignored / 0 failed`；integration compile、两组
  warnings-as-errors Clippy、format、network/no-net 与 diff 全部 exit 0。
- 修复 WIP 的完整 `p5` 已 PASS，SessionSource `25/25`，RelayClient
  `457 executed / 4 external entitlement skipped / 0 failed`；该结果只证明 implementation 具备重新冻结资格，
  不计作新 committed candidate 的 R4.8/R4.9 证据。本次 docs-only scoped commit 第三次生成 replacement R4.7
  committed candidate；提交后必须从零连续执行三次 fresh lifecycle、完整 `p5`、`p4-auto`、双路 review 与
  cleanup，期间任何代码或文档修改都使计数再次失效。
- 物理 iPhone、第二台 Mac、公网 WSS、真实 vendor 与 production signing 继续保持 versioned post-MVP
  `BLOCKED`，不计入 automatic PASS，也不能用 Simulator 或本机结果替代。

### R4.9 Acked stream-applied ACK 终审重开（2026-07-30）

- 第三次 replacement docs candidate 为 `eaa1c5a1de6aaea0ba56643b42e8663925ea6b08`，tree 为
  `5b08d42a1d6d1a4efadc087c407f61b530865f59`。它的连续三次 fresh lifecycle、完整 `p5` 与 `p4-auto`
  虽然全部 PASS，但 spec/security 终审发现合法竞态未覆盖，因此这些结果只保留为诊断证据，不得计作
  R4.8/R4.9 或 P5 Phase Exit 完成。
- 漏洞位于 `same_or_monotonic_committed_update()` 的 `Acked → Acked` 分支：旧比较器要求
  `state_changed_at_ms` 完全一致，而真实 Store 的 `acknowledge_stream_applied()` 在新增已认证 stream ACK 后会把
  timestamp 推进到 `acknowledged_at_ms`。旧 Fake Store 未同步该行为，既有回归也只覆盖
  `Frozen → Acked + stream ACK`，因此会把“原快照已 Acked、mark 后新增 stream ACK”的合法 readback 误报为
  `daemon.remote.transition.readback_mismatch`。
- 修复后的边界为：canonical ACK 必须完全一致；旧 stream ACK 集合必须是新集合的子集；集合未增长时 timestamp
  必须完全一致，严格增长时才允许 timestamp 单调前进。operation/recipient/revision、canonical update bytes、
  snapshot flushes、created time 与其他稳定轴继续精确比较，timestamp-only 漂移仍 fail-close。Fake Store 同步在
  新增 stream ACK 时推进 `state_changed_at_ms`。
- replacement implementation commit 为 `33625506259d2ee46a1c8d0342d42ddce846208c`，tree 为
  `1cfef041438b76094b5a8e18cb0d31a629cb1d58`，相对本地 `master` 为 `0 behind / 293 ahead`；2-path
  code/test manifest SHA-256 为 `ce3158fca4eb68b7feac9bbf497ec5167b49471eb27184faa504541c0da7a7ee`。
  新增“already Acked 后合法增长”和“无增长 timestamp 漂移拒绝”两项回归。
- fresh implementation gates：COMMIT/readback focused `5/5`、transition `35/35`、machine E2E
  `2 passed / 1 interactive ignored`、daemon lib `1718 passed / 3 ignored / 0 failed`；integration compile、两组
  warnings-as-errors Clippy、format、network/no-net、agent docs 与 diff 全部 exit 0。完整 `p5` 也 PASS，daemon
  generation 2 完成 command/approval/revoke `1/1/1`、restart marker 与 history recovery，Relay plaintext 和全部
  owned cleanup 均 absent；SessionSource `25/25`、RelayClient `457 executed / 4 external skipped / 0 failed`。
  这些结果只证明 implementation 具备重新冻结资格，不计作新 committed candidate 的 R4.8/R4.9 证据。
- 本次只更新本计划与 `docs/QUALITY.md`，以 docs-only scoped commit 第四次生成 replacement R4.7 committed
  candidate。提交后必须读回 commit/tree/clean status，并从零连续执行三次 fresh lifecycle、完整 `p5`、
  `p4-auto`、双路 review 与 cleanup；期间任何仓库修改都会使计数再次失效。物理 iPhone、第二台 Mac、公网
  WSS、真实 vendor 与 production signing 继续保持 versioned post-MVP `BLOCKED`。

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
- [x] R4.4：client/daemon relaunch、cursor/backfill reconnect 与 revoke terminal。
- [x] R4.5：外部 runner 严格只读 BLOCKED preflight，固定以 exit 78 表示预期未解锁。
- [x] R4.6：扩展 verifier `p5`；automatic 缺失/失败必须非零，外部 BLOCKED 不计入 PASS。
- [x] R4.7：Acked stream-applied ACK 终审修复后重新同步文档并提交第四次 replacement
  implementation candidate。
- [ ] R4.8：在 replacement committed candidate 上从零连续执行三次 fresh E2E。
- [ ] R4.9：同一 replacement candidate 执行完整 `p5`/`p4-auto`、双路 review、cleanup 与 clean status；若修改
  代码，从 R4.7 重来。

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

- [ ] R5.1：replacement R4.9 完成后，重新更新状态/文档、清理生成物并提交 closeout candidate。
- [ ] R5.2：冻结最终 commit/tree/path hashes，运行完整 Rust/Swift/iOS/P4/P5 门禁。
- [ ] R5.3：在同一最终 candidate 上执行 phase `spec/security`、`quality` review，清零 P0/P1/P2。
- [ ] R5.4：逐项读取 post-MVP BLOCKED，确认 exit 78、零 mutation 和 versioned summary。
- [ ] R5.5：读回文档、cleanup、diff/status；任何仓库修改都会使 candidate 失效并回到 R5.1。
- [ ] R5.6：仓库保持只读和 clean，向用户报告；由用户决定是否 push/PR/合入。

### R5.1 closeout candidate（2026-07-29）

> 已失效：本节生成的 `5966c98` candidate 在 R5.2 首轮 `p5` 暴露 failure-path orphan；当前必须先完成
> replacement R4.8/R4.9，再重新执行 R5.1。

- 本 Task 只更新本计划与 `docs/QUALITY.md`，把 R4.8/R4.9 的同 candidate 重复性、双路 review 和 cleanup
  证据写回 SSOT；不修改 production、test、runner、协议、schema 或版本。
- R4 evidence candidate 固定为 `3fb83e83a34abd659e32b817cf1cabccf999ca79` / tree
  `d136544a47f64ffabe0e60a464cc7f8cd18f5f33`。R5.1 以包含本节的 docs-only scoped commit 生成最终 closeout
  candidate；R5.2 必须从提交后 clean 状态重新读回 commit/tree/path hashes，并把后续全部门禁绑定到新 candidate。
- `ios/AgentDeckMobile.xcodeproj/` 已按 ignored 生成物清理；R5.1 不删除 `.build`/`target` 缓存，不创建 tag、远端、
  push、运行数据库、证书或密钥。任何提交后的仓库修改都会使 R5 candidate 失效并回到 R5.1。

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
| R4 Simulator E2E | in progress（reopened） | replacement implementation `3362550` / tree `1cfef04`；2-path hash `ce3158f` | focused `5/5`、transition `35/35`、machine E2E `2/1 ignored`、daemon lib `1718/3 ignored`、完整 `p5`、Clippy/compile/format/network/docs/diff PASS | `eaa1c5a` 虽三轮 lifecycle、`p5`、`p4-auto` PASS，但终审发现 Acked→Acked stream ACK 合法竞态，全部不计数；新 candidate 尚须从零重跑 | 旧双路 review再次失效；replacement review 待 R4.9 | implementation 已 exact commit；本次 docs-only commit 生成第四次 replacement R4.7；未 push |
| R5 MVP 收口 | paused | `5966c98`、`0f601ae`、`f7d2e68`、`eaa1c5a` 均已失效 | 既有 R5.2、R4.8 与 implementation 全量结果只作诊断/实现门禁，不可拼接 | 旧 PID 54930 已精确清理；当前 implementation `p5` cleanup PASS | 必须等待第四次 replacement R4.9 | 回到 R4.8；R5.1–R5.6 全部重跑 |

状态只能按实际证据更新。focused PASS 不得把 Phase 标为 complete；外部 BLOCKED 不得改写为 PASS。
