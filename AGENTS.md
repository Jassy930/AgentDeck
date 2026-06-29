# AgentDeck 代理工作入口

本文件只作为仓库地图和执行规则，不承载详细百科。更深的产品、架构、诊断和计划信息必须写入下游文档，并随代码同步更新。

## 必读顺序

1. `NORTH_STAR.md`：产品北极星和 v0.1 不做什么。
2. `README.md`：当前用户可见能力、架构摘要、构建与测试命令。
3. `ARCHITECTURE.md`：稳定架构、分层边界、依赖方向和不变量。
4. `docs/index.md`：文档记录系统导航。
5. `docs/AGENT_DIAGNOSTICS.md`：自检、诊断日志和 failure code。
6. `docs/QUALITY.md`：验证命令、质量门禁和文档结构检查。
7. `docs/plans/README.md` 与 `docs/plans/`：设计文档和实施计划规则。修改相关功能前先读最近的设计文档和实施计划。
8. `protocol/SPIKE_FINDINGS.md` 与 `protocol/`：Codex app-server 协议事实源。

## 项目边界

- AgentDeck 是 macOS 原生的本地 Coding Agent 工作台，不是 IDE、不是 Codex Desktop 替代品，也不是通用多 agent 聊天界面。
- v0.1 的核心是原生流式会话和 agent-中立适配器边界。
- 中立边界在 IPC 协议本身：Swift UI 只处理中立 `AgentItem`，不得解析 Codex vendor JSON。
- Codex 细节只能留在 Rust daemon adapter 层；新增 adapter 不能要求 Swift 侧知道具体 agent。
- `protocol/` 中 schema 必须来自官方 `codex app-server generate-json-schema`，不要手写或逆向猜测协议。
- AgentDeck 不读取、不保存、不转发 Codex token；沿用用户已有 `codex login` 状态。
- AgentDeck 管理的 run record 与 diagnostic log 写入 `~/Library/Application Support/AgentDeck/`，不得写入用户项目 git。

## 工作规则

- 永远使用中文回答用户；项目文档默认使用中文。
- Python 使用 `uv`；JS/TS 使用 `bun`。
- 代码变更必须同步更新相关文档。若行为、架构、协议、诊断或用户可见流程变化，更新 `README.md`、`docs/` 或对应计划文档。
- 每个阶段性工作结束后，整理工作区并查看 `git status --short --branch`。
- 不添加 co-author / Codex 合作者信息。
- 不把本地构建产物、运行记录、诊断日志、token、`.env` 或用户项目数据提交进仓库。

## 验证入口

按变更范围选择最小但足够的验证：

```bash
cargo test
swift test
swift run AgentDeck -- --selfcheck
swift run AgentDeck -- --diagnostics-report --json
scripts/verify-agent-docs.sh
```

涉及 daemon、IPC、记录、诊断、协议翻译时至少运行 `cargo test` 和自检。涉及 Swift UI、会话模型、历史回放、富文本渲染时至少运行 `swift test`。涉及诊断、日志或数据目录时同时运行 diagnostics report。

### 统一接口层补充验证

```bash
# 打印 IPC 协议 JSON Schema（可与快照核对）
cargo run -p agentdeck-cli -- protocol schema

# 核对快照与代码是否同步（漂移测试也随 cargo test 自动运行）
cargo run -q -p agentdeck-cli -- protocol schema \
  | diff - protocol/agentdeck/agentdeck-protocol.schema.json \
  && echo "schema in sync"

# 通过 CLI 执行 IPC + logging 自检
cargo run -p agentdeck-cli -- selfcheck

# 门控 E2E（本地执行，需要 codex login；默认 cargo test 跳过）
AGENTDECK_E2E=1 cargo test -p agentdeck-cli --test e2e
```

协议 schema 漂移测试随标准 `cargo test` 运行；改动 `agentdeck-protocol` 中的类型后须用以下命令重新生成快照：

```bash
UPDATE_SCHEMA=1 cargo test -p agentdeck-protocol schema_matches_committed_snapshot
```

## 浏览与外部资料

需要网页资料时优先使用当前环境可用的官方浏览工具和一手来源。不要引入项目级外部浏览 skill 依赖，也不要要求安装额外工具才能在本仓库工作。
