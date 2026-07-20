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

当前 active Relay 事实源是 `2026-07-10-relay-companion-mvp-design.md`、
`2026-07-10-relay-companion-mvp-implementation.md` 与上位增量
`2026-07-18-relay-companion-mvp-course-correction.md`；后者固定 Task 粒度门禁、Runtime store 离线
篡改边界和 P5/P6 MVP 外部验收范围。P3.6-A/P3.6-B/P3.6-C/P3.6-D 已分别提交为
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
daemon package exit 0、两路终审 Approved。P4 当前为 1/7，下一项是 P4.2；P4.1 严格零 cert、零
enrollment workflow、零 receipt IO、零 RemoteLink，link/data cert、enrollment 与首条 RemoteLink 首次归
P4.2。通用 CounterGuard IO 不代表 active symmetric key reservation、DB high-water 绑定或整库回滚闭环
已完成。P4 E2EE/Relay Publish、P5 Simulator 自动 E2E 与 P6 本机第二客户端 synthetic DoD 均未完成；
物理 iPhone/第二台 Mac 是 post-MVP BLOCKED 槽位。
transfer/publication 也尚无 production remote owner；不能因 fake publication、store tests 或 Simulator
fixture 改写尚未实现的自动链路状态。

```text
docs/plans/
  active/
  completed/
  tech-debt-tracker.md
```

引入归档目录时，需要同步更新 `AGENTS.md`、`docs/index.md` 和 `scripts/verify-agent-docs.sh`。
