# AgentDeck 质量与验证

本页把可机械执行的质量入口集中起来。新增规则时优先补测试或脚本，让 agent 能在仓库内直接验证，而不是依赖口头记忆。

## 常用验证命令

```bash
cargo test
swift test
swift run AgentDeck -- --selfcheck
swift run AgentDeck -- --diagnostics-report --json
scripts/verify-agent-docs.sh
```

## 按变更范围选择验证

| 变更范围 | 最小验证 |
| --- | --- |
| Rust daemon、IPC、Codex adapter、run record、diagnostics | `cargo test`；涉及运行态再跑 `swift run AgentDeck -- --selfcheck` |
| Swift UI、会话模型、历史回放、富文本渲染、选择/滚动行为 | `swift test` |
| 诊断日志、自检、数据目录、密钥脱敏 | `cargo test`；`swift run AgentDeck -- --selfcheck`；`swift run AgentDeck -- --diagnostics-report --json` |
| 文档结构、AGENTS 入口、计划规则 | `scripts/verify-agent-docs.sh` |
| 协议 schema 或 app-server 方法 | `cargo test`；核对 `protocol/SPIKE_FINDINGS.md` 和 `protocol/CODEX_VERSION.txt` |

## 文档结构检查

`scripts/verify-agent-docs.sh` 是当前最小 doc-gardening 检查。它验证：

- 关键文档入口存在。
- `AGENTS.md` 链接到项目北极星、README、架构、诊断、质量、计划和协议事实源。
- `README.md` 链接到架构、文档索引和质量文档。
- 项目没有重新引入已剥离的外部 skill 强制绑定。
- `docs/plans/README.md` 存在，计划文档不再只是散落文件。

后续接入 CI 时，先把这个脚本作为独立 job，再逐步增加更严格的结构检查。

## 失败处理

- 验证失败时，不要只重跑。先读失败输出，定位是哪条不变量被破坏。
- 如果失败来自文档漂移，优先更新真实文档或检查脚本，不要绕过规则。
- 如果失败来自 flaky 外部条件，记录命令、错误和复验结果到对应计划文档。

## 收口清单

阶段性工作结束前至少完成：

1. 更新相关文档。
2. 运行与变更范围匹配的验证命令。
3. 运行 `git status --short --branch`。
4. 摘要说明哪些验证已跑、哪些未跑以及原因。
