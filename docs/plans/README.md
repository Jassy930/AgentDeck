# AgentDeck 计划文档规则

计划文档是一等工件，用来保存设计取舍、实施步骤和验证证据。不要把长期规则埋在一次性聊天记录里。

## 文件命名

- 设计文档：`YYYY-MM-DD-<topic>-design.md`
- 实施计划：`YYYY-MM-DD-<topic>-implementation.md`
- 小型协调记录：`YYYY-MM-DD-<topic>.md`

同一主题先写 design，再写 implementation。窄小修复可以只写 implementation，但必须包含目标、涉及文件和验证命令。

## 文档内容

设计文档应包含：

- 背景和用户问题。
- 目标与非目标。
- 架构方案和边界。
- 错误处理与可观测性。
- 测试和验收标准。

实施计划应包含：

- Goal、Architecture、Tech Stack。
- 按任务拆分的文件清单。
- 每步要运行的命令和预期结果。
- 文档更新和最终收口步骤。

## 更新规则

- 计划执行中出现重要偏差时，更新计划或追加决策记录。
- 代码落地后，如果 README、架构、诊断或质量规则变化，必须同步更新对应文档。
- 不把计划文档变成完整日志。只保留未来 agent 需要复用的事实、命令和决策。

## 当前目录状态

现有计划暂时保留在 `docs/plans/` 根目录，避免为了归档制造大规模文件移动。后续当计划数量继续增长时，再引入：

当前 active Relay 目标架构事实源是 `2026-07-10-relay-companion-mvp-design.md`；当前唯一执行事实源是
`2026-07-28-relay-companion-mvp-rescue-implementation.md`。旧
`2026-07-10-relay-companion-mvp-implementation.md` 与上位增量
`2026-07-18-relay-companion-mvp-course-correction.md` 保留历史清单、已验证证据、Task 粒度门禁和 Runtime
store 离线篡改边界；其中未完成的 P5.8–P6 已被 rescue 计划覆盖，不再直接执行。P3.6-A/P3.6-B/P3.6-C/P3.6-D 已分别提交为
`7731d1e`/`02cc640`/`694f2d9`/`b668d8f`，默认并发完整 daemon gate 已 exit 0。P3.7 已在
`819aa5e` / `1acf8b8` / `3f22cf0` 前置分片之上实现 current-binary exec-gate、typed driver/durable
ACK、cooperative-descendant PGID fencing、两遍 recovery 与 production bootstrap；边界已裁决排除显式
`setsid`/`setpgid`/launch service 自守护或逃逸。release 前唯一 reaper、typed clean/unknown prepare
failure 分类、fresh 完整门禁和独立终审已经完成，并由 `5568e93` 完成主体 scoped commit；
`c9d2146` / `5713be4` 又补齐真实 current-binary release 前取消、内部故障 bookkeeping 与 sentinel
leader 退出窗口门禁。P3.8-A 已由 `eb97f7f` 完成 accepted-stream UDS 原语；P3.8-B1 已由
`1e7f9ea` 完成 recovery 后 secure listener/permit/supervisor，并从 clean detached HEAD 独立复验；
P3.8-B2 production config/main、stdio exhaustive allowlist、真实 binary lifecycle 和 Rust/Swift
compatibility 参数已由 `459f32a` 完成。P3.9-C0-A0/A1 已由
`d4057f1` / `3b83391` / `c28a968` / `c36a4f9` / `ef830cd` 完成，Runtime v2 Rust contract 与
signed-material hard cutover 的 A1 complete；Swift A2 已由
`bea4c13` / `3e019ed` / `0dd58de` / `c2d2c28` / `e419d84` 完成 strict mirror、outer、JSON/compact
current codec、98-fixture 与真实 UDS Swift readback，A2 complete。
P3.9-C0-B3a 已由 `48594e8` / `09a14b0` 完成并通过 Task 完整门禁与双路终审：B3 current-open
最后一笔仍为 `974f9b1`，同 UID 在线攻击自此作为 residual risk，不再扩展；B3b exact execution 已由
`c0ed6cd` / `f4141f0` / `fb1629a` 收口，B4 managed metadata 已由 `5f1ca1c` / `347a0f0`
完成，B5 cross-layer closeout 已由 `aebc8d0` 以 test-only 增量完成并通过完整门禁与双路终审；C0-C native
history projection、P3.9-A/B Rust/Swift shared-daemon client component、P3.9-C3 App model cutover、
P3.9-D 默认入口/真实双客户端 smoke 与 P3.9-E App 会话可靠性也已分别完成 Task 门禁与双路终审；
D/E code/test 提交分别为 `b818f81` / `d68cc02`。P3.10 主体由 `19622ab` 完成 schema v7/admin ledger、
flush-ACK-gated upgrade 与 LaunchAgent lifecycle；P3 Phase review 又由 `773a2b3` 收口安装 verifier
资源上界、`0057824` 收口 legacy pre-migration authentication，并由 `81cc314` / `9efb28d` 稳定回收
verifier 进程组。以 `9efb28d` 为 code baseline 的完整 `p3` Phase verifier exit 0，双路 phase code
review 均为 P0/P1/P2=0，P3 automatic scope 6/6 complete。P3.1 继续采用方案 b：provisioned signed
Keychain/LaunchAgent roundtrip 保持 post-MVP ignored/BLOCKED，不阻塞主线，也不表示 stable production
signing 已完成。P4.1 已由 `3cd76d2`、`644712c`、`95090c1`、`85df3d2`、`f137112`、`46c6bb8`
完成 machine identity、schema v8/24 表、key-directory guard、通用 CounterGuard IO 与 bootstrap；完整
daemon package exit 0、两路终审 Approved。P4.2 code/test 由 `a6842bc` 收口 Runtime v3、
schema v9/25 表、link/data cert、durable enrollment/receipt、control-only authenticated MachineLink、
root-present/root-lost trust reset 与安全 uninstall purge。P4.3 由 `518380e`、`b28f995`、`55be98f`、
`ba3629f`、`4ec3d2f`、`fe3a9ad`、`3b4b977` 收口 Runtime v4、schema v10/30 表、PairInvite/DeviceGrant/
DeviceAuthorization/KeyDirectory、本机 auth ledger、revoke、control handoff 与 cancel-safe recovery。
最终实际范围为 130 个非 lock 代码/测试/协议路径（另含 `Cargo.lock`），最大 production 子片 Store pairing
为 1,792 additions。
P4.4 code/test `cd7d9fb` 已收口唯一 MachineLink business lane：Relay v2 outer、DeviceSign/AAD/replay
candidate/AEAD、Store exact-current auth-ledger recheck 后才把 `RuntimeRequest` 规范化为 `RemotePrincipal`
并交给 `RuntimeCore`；`RouteAccepted` 不等于 command success。recovery 完成前 RemoteLink 不启动：Active
可恢复、Inactive 在 actor install 前终止、Unprovable/legacy 只隔离对应 conversation。
`RemoteLink` 只持易失 generation/replay/connection/reply-route，不持 canonical 业务状态。最大 production
子片 `link.rs` 为 1,038 additions，低于 1,800 预拆线。
P4.5 code/test `c6ef387`、`88b3c42` 已收口 MachineDataSign signed publication、counter/replay/key
transition crash recovery 与 production sealer/publisher 接线；P4.5 收口时 Runtime wire 为 v4，physical schema
为 v14/35 表。完整 daemon lib `1579 passed / 3 gated ignored`、main `7/7`，integration/doc-test 零失败，
`runtime_store_boundaries` `5/5`（256 MiB，282.85 秒），Clippy/fmt/diff 全绿；双路终审在同一冻结 hash
`88ac6c486a7446b5fe4613388f66ee25561a7529a2fd0f8904844217730a896f` 上 P0/P1/P2=0。
P4.6 persistent remote CLI 已完成 automatic Task，current Runtime wire 为 v5；`pair`、
`machines`、`conversations`、`watch`、`prompt`、`approve`、`retry-approval`、`revoke-self` 均已接入。
watch 使用 fresh authenticated bootstrap、canonical NDJSON、SIGINT/SIGTERM 与有序 stopped/revoked terminal；
paired-state V6 durable transfer 的 TTL 不依赖下一帧，prepared ADST v2 mode/guard commitment 通过 AEAD
认证并覆盖 4095→4096 crash cut recovery。2026-07-24 冻结 code/test scope 为 29 paths，blob-manifest
SHA-256 为 `32e7c85620e6e88b407f2403715c52c5a9a5d30aa20d7fb800bdefabe8a1c858`；watch `12/12`、
`remote_persistent_machines` `11/11`、完整 CLI package final run exit 0、release allocator `1/1`、relay-client
`25/25` 与 protocol `244/244` 均通过，四 schema/三 crate Clippy/fmt/network/no-net/docs/diff 全绿。
`spec/security` 与 `quality` 终审均 Approved，P0/P1/P2=0。P4.7 automatic Task 与 P4 automatic
Phase Exit 已完成，P4 按 Task 进度为 7/7。verifier 接受 `p0|p2|p3|p4-auto`，但 `p4` 仍不受支持；
`p4-auto` focused aggregate 已 PASS，但它本身不含顶层 `cargo test`、`swift test`、最终 diff/status、
冻结 hash 或双路 phase review。fresh `cargo test --locked`、`swift test`（577/577）、三组 Clippy、fmt、
network/no-net、schema/docs/diff、local Runtime smoke、ephemeral selfcheck 与 diagnostics 已单独通过；
`spec/security`、`quality` 在 pre-closeout candidate SHA-256
`18654fa9c398383dafcefa1542c8e48f8c460f1f521806880c5dab083bdb29f5` 上均 Approved，P0/P1/P2=0。
远端 cannot-confirm pairing 由独立 RuntimeCore principal gate 证明；
real runner 当前只是不读参数/env、不探测或执行的静态 fail-closed sentinel，固定输出完整
`missingInputs` 与 `BLOCKED/mutations=0/evidence=[]/summaryGenerated=false`，真实 preflight/execution 留
post-MVP。Linux 仅 ephemeral test keys，macOS production persistent Keychain 不降级；root-lost 流程交叉
引用 `docs/RELAY_RUNBOOK.md`。真实 iOS Companion E2E 仍属于 P5、尚未完成；
P3.1 方案 b、production-signed
Keychain/LaunchAgent、真实 vendor、物理 iPhone/第二台 Mac、公网 WSS 与 destructive purge 证据继续作为
post-MVP BLOCKED 槽位。

`2026-07-30-relay-web-test-companion-design.md` 与配套 implementation 是 automatic MVP 收口后的已批准
post-MVP 开发计划，未替换上述 Relay 架构或 rescue 事实源。当前 W0/W1/W2a/W2b automatic complete：
Rust/WASM + 薄 Web host 已完成真实 Chrome 的直连、配对与同页最小业务闭环；W2c durable
promotion/reload/reconnect/revoke 仍未开始。浏览器本机证据不得写成物理设备、公网 WSS、production
signing、真实 vendor 或第二台 Mac PASS。

```text
docs/plans/
  active/
  completed/
  tech-debt-tracker.md
```

引入归档目录时，需要同步更新 `AGENTS.md`、`docs/index.md` 和 `scripts/verify-agent-docs.sh`。
