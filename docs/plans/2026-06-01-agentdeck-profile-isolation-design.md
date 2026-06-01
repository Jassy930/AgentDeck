# AgentDeck Profile Isolation Design

## 背景

用户希望把 AgentDeck 拆成两个使用实例：一个用于快速迭代和调试，另一个用于稳定的日常工作。当前 AgentDeck 的 run record 和 diagnostic log 默认写入 `~/Library/Application Support/AgentDeck/`。如果开发态和稳定态共享该目录，调试数据、自检探针和真实工作记录会混在一起，降低诊断可信度。

本设计采用轻量 profile 隔离 AgentDeck 自己管理的数据，同时继续共享用户已有 Codex 登录状态和 Codex 历史。

## 目标

- 支持 `stable` 与 `dev` 两个 AgentDeck profile。
- 默认行为保持稳定：不传 profile 时等价于 `stable`。
- `dev` profile 使用独立数据目录：`~/Library/Application Support/AgentDeck-Dev/`。
- run record、diagnostic log、selfcheck、diagnostics report 都使用同一套 profile 数据目录规则。
- 保留 `AGENTDECK_DATA_DIR` 作为测试和诊断覆盖入口，并让它优先于 profile。
- 不读取、不保存、不复制、不转发 Codex token。

## 非目标

- 不隔离 Codex 登录状态。
- 不隔离 Codex app-server 自己管理的历史 thread。
- 不引入第二个 bundle id、签名流程或发布通道。
- 不新增数据库迁移或复杂配置系统。
- 不把 profile 做成通用多工作区账户体系。

## 方案

新增 Swift 启动参数：

```bash
swift run AgentDeck -- --profile stable
swift run AgentDeck -- --profile dev
swift run AgentDeck -- --selfcheck --profile dev
swift run AgentDeck -- --diagnostics-report --json --profile dev
```

未传 `--profile` 时使用 `stable`。非法 profile 应在 Swift 启动阶段给出明确错误，不启动 UI 或 daemon。

Swift 侧解析 profile 后，把它传给 daemon：

```text
AGENTDECK_PROFILE=dev
```

Rust daemon 统一决定最终数据目录。目录优先级：

```text
AGENTDECK_DATA_DIR 已设置
  -> 使用 AGENTDECK_DATA_DIR

否则 AGENTDECK_PROFILE=dev
  -> ~/Library/Application Support/AgentDeck-Dev/

否则 AGENTDECK_PROFILE=stable 或未设置
  -> ~/Library/Application Support/AgentDeck/
```

这样所有持久化入口继续通过 `record::app_data_dir()`、`record::record_dir()` 和 `diag::diagnostic_log_path()` 派生路径，避免 Swift 与 daemon 各自理解 profile。

## 架构边界

profile 只影响 AgentDeck 管理的数据目录，不改变 IPC schema、Codex adapter、RuntimeHub、history 读取或 approval 流程。

Swift 层职责：

- 解析 `--profile`。
- 校验 profile 值。
- 启动 daemon 时注入 `AGENTDECK_PROFILE`。
- 可选：在窗口标题或诊断输出中显示当前 profile，避免误用。

Rust daemon 职责：

- 在数据目录解析处读取 `AGENTDECK_DATA_DIR` 和 `AGENTDECK_PROFILE`。
- 让 run record、diagnostic log、selfcheck 和 diagnostics report 都自然落到 profile 目录。
- diagnostics report 返回实际 `dataDir`、`runsDir` 和 `diagnosticLog`，用于确认当前实例写到了预期目录。

## 错误处理与可观测性

- `--profile` 只接受 `stable` 和 `dev`。其他值直接失败，并输出可读错误。
- `AGENTDECK_PROFILE` 非法时 daemon 退回 `stable` 还是失败需要实现阶段定稿。推荐失败，因为静默回退会造成数据混写。
- `AGENTDECK_DATA_DIR` 继续保持最高优先级，主要用于测试、CI 和一次性诊断。
- `--selfcheck --profile dev` 必须验证 dev 目录下能写入 `runs/*.jsonl` 和 `diagnostic.log`。
- `--diagnostics-report --json --profile dev` 必须在 JSON 中返回 dev 数据路径。

## 测试与验收

最小验证命令：

```bash
cargo test
swift test
swift run AgentDeck -- --selfcheck --profile dev
swift run AgentDeck -- --diagnostics-report --json --profile dev
scripts/verify-agent-docs.sh
```

验收标准：

- 不带 `--profile` 的行为与当前 stable 行为一致。
- `--profile dev` 的 selfcheck 写入 `~/Library/Application Support/AgentDeck-Dev/`。
- diagnostics report 的 `dataDir`、`runsDir`、`diagnosticLog` 指向当前 profile 对应目录。
- 设置 `AGENTDECK_DATA_DIR` 时，它优先于 `AGENTDECK_PROFILE`。
- Swift 测试覆盖 profile 参数编码或 daemon 启动环境注入。
- Rust 测试覆盖 profile 到数据目录的映射和非法 profile 行为。

## 文档更新

实现时同步更新：

- `README.md`：记录 `--profile dev|stable` 的运行方式和数据目录规则。
- `ARCHITECTURE.md`：说明 profile 只影响 AgentDeck 数据目录，不影响 Codex token 或 Codex 历史。
- `docs/AGENT_DIAGNOSTICS.md`：补充带 `--profile dev` 的自检和诊断报告命令。
- `docs/QUALITY.md`：补充涉及 profile / 数据目录变更的验证命令。

