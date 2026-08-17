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

当前桌面实现的目标事实源：

- `2026-08-17-gpui-desktop-reset-design.md`
- `2026-08-17-gpui-desktop-reset-implementation.md`

此前 AppKit 统一壳计划保留为历史记录，不再定义当前 macOS 桌面实现或默认迭代顺序。

现有计划暂时保留在 `docs/plans/` 根目录，避免为了归档制造大规模文件移动。后续当计划数量继续增长时，再引入：

```text
docs/plans/
  active/
  completed/
  tech-debt-tracker.md
```

引入归档目录时，需要同步更新 `AGENTS.md`、`docs/index.md` 和 `scripts/verify-agent-docs.sh`。
