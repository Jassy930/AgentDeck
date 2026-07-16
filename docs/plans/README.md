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

当前 active Relay 事实源是 `2026-07-10-relay-companion-mvp-design.md` 与
`2026-07-10-relay-companion-mvp-implementation.md`。P3.6-A/P3.6-B/P3.6-C/P3.6-D 已分别提交为
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
signed-material hard cutover 的 A1 complete；Swift A2a/A2b 与 A2c1 已由
`bea4c13` / `3e019ed` / `0dd58de` / `c2d2c28` 完成，A2c2 current/compact gate 与 shared-daemon client
cutover 尚未完成。
P3.1 的 provisioned signed Keychain 外部门禁仍有 1 项 ignored/BLOCKED，P3.9/P3.10、P4 E2EE/Relay Publish
和 P5 真实 Companion 均未完成；transfer/publication 也尚无 production remote owner。不能因 fake
publication、store tests 或 Simulator fixture 改写状态。

```text
docs/plans/
  active/
  completed/
  tech-debt-tracker.md
```

引入归档目录时，需要同步更新 `AGENTS.md`、`docs/index.md` 和 `scripts/verify-agent-docs.sh`。
