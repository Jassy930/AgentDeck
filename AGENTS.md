# AgentDeck 代理工作入口

本文件只作为仓库地图和执行规则，不承载详细百科。更深的产品、架构、诊断和计划信息必须写入下游文档，并随代码同步更新。

## 必读顺序

1. `NORTH_STAR.md`：产品北极星和当前必赢目标。
2. `README.md`：当前用户可见能力、架构摘要、构建与测试命令。
3. `ARCHITECTURE.md`：GPUI 重启基线、稳定分层边界和后端不变量。
4. `docs/index.md`：文档记录系统导航。
5. `docs/AGENT_DIAGNOSTICS.md`：自检、诊断日志和 failure code（含 CC adapter failure codes）。
6. `docs/AGENTDECKD_STATUS.md`：daemon 当前功能完整度、证据边界和关键缺口。
7. `docs/QUALITY.md`：GPUI P0、共享 Core、backend 和文档质量门禁。
8. `docs/plans/README.md` 与 `docs/plans/`：设计文档和实施计划规则。当前 macOS 实现只以 `docs/plans/2026-08-17-gpui-desktop-reset-design.md` / implementation 为事实源；desktop 接入前的 daemon 边界以 `docs/plans/2026-08-17-agentdeckd-minimum-stable-boundary-design.md` 和 Codex 生命周期 ADR 为事实源。旧 AppKit 计划是历史记录，不定义当前桌面迭代顺序。
9. `protocol/SPIKE_FINDINGS.md` 与 `protocol/`：Codex app-server 协议事实源。

## 项目边界

- AgentDeck 是 Coding Agent 的统一原生桌面客户端，把 Codex 和 Claude Code 作为绝对一等公民，不是 IDE、不是 Codex Desktop 替代品、不是通用多 agent 聊天界面。
- 当前 macOS 桌面端是 `agentdeck-desktop/` 下的 Rust/GPUI 最小壳；尚未连接 daemon 或 IPC，也不恢复旧 AppKit 兼容层。
- `agentdeckd` 的 Codex 本地链路固定为由 daemon 直接持有 session-scoped `codex app-server --listen stdio://` 子进程，不依赖 Codex managed daemon/proxy；该 M0 边界尚待代码验收，不能描述成已完成能力。
- 后续会话 UI 必须通过 Rust typed router 按 `SessionCapabilities` 路由，禁止硬编码 vendor 分支（N2）。
- IPC 主干类型严禁出现 vendor 字样；vendor 字段只能出现在 `capabilities.*` / `vendorControl.*` / `vendorPanel.*` 命名空间（N1）。
- Codex 细节只能留在 `agentdeckd/src/codex/` 子模块；CC 细节只能留在 `agentdeckd/src/claude_code/` 子模块；两者互不知晓（N3）。
- `protocol/` 中 Codex schema 必须来自官方 `codex app-server generate-json-schema`，不要手写或逆向猜测协议（K8）。
- AgentDeck 不读取、不保存、不转发任何 vendor token（Codex 或 Claude Code）；CC 历史走 CC 原生接口，不建 `cc-meta/` 目录（K9、N8）。
- AgentDeck 管理的 run record 与 diagnostic log 写入 `~/Library/Application Support/AgentDeck/`，不得写入用户项目 git（K5）。
- `Sources/AgentDeckMobileCore/` 是 iOS 使用的平台无关 Swift 层，禁止 import AppKit/UIKit；macOS GPUI target 不依赖它。`ios/` 是 fixture 驱动的 UIKit companion 前端，唯一数据入口是 `MobileSessionSource`，本期不含网络代码（设计见 `docs/plans/2026-07-03-ios-uikit-frontend-design.md`）。

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
cargo test -p agentdeck-desktop
cargo run -p agentdeck-desktop -- --selfcheck
./script/build_and_run.sh --verify
swift test
scripts/verify-agent-docs.sh
```

涉及 GPUI 桌面时至少运行 desktop test、desktop selfcheck 和真实 bundle verify。涉及 daemon、IPC、记录、诊断、协议翻译时至少运行对应 focused test、daemon lib test 和 CLI selfcheck。当前 daemon lib test 会执行本地 vendor `--version`，虽不创建 session 或发送 prompt，但不是零 vendor process；部分 adapter shape 测试还会直接启动真实 vendor CLI。统一补上严格 `AGENTDECK_E2E=1` 门控和可注入版本探测前，不得把裸 `cargo test` 当作完全离线门禁；需要真实模型调用时必须先取得用户确认。涉及 `AgentDeckMobileCore` 或 iOS 时运行 `swift test`；涉及诊断、日志或数据目录时同时运行 daemon diagnostics report。

### iOS 前端验证

```bash
# iOS 工程生成 + 构建 + 单测（fixture 驱动，无真实链路）
cd ios && xcodegen generate && \
  xcodebuild -project AgentDeckMobile.xcodeproj -scheme AgentDeckMobile \
    -destination 'platform=iOS Simulator,name=iPhone 17' test
```

涉及 `Sources/AgentDeckMobileCore/` 或 `ios/` 时至少运行 `swift test` 与上述 iOS 测试。

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
AGENTDECK_E2E=1 cargo test -p agentdeck-cli --test e2e_codex -- --nocapture
AGENTDECK_E2E=1 cargo test -p agentdeck-cli --test e2e_claude_code -- --nocapture
AGENTDECK_E2E=1 cargo test -p agentdeck-cli --test e2e_cross_agent_history -- --nocapture --test-threads=1
```

当前 `agentdeckd/tests/cc_adapter_shape.rs` 中仍有未统一门控的真实 Claude Code
prompt 测试，`codex_adapter_shape.rs` 也会在 PATH 命中时启动 app-server。修复该测试
基础设施缺口前，标准 `cargo test -p agentdeckd` / `cargo test` 不是离线安全命令；
现状与安全替代入口见 `docs/AGENTDECKD_STATUS.md` 和 `docs/QUALITY.md`。

协议 schema 漂移测试随标准 `cargo test` 运行；改动 `agentdeck-protocol` 中的类型后须用以下命令重新生成快照：

```bash
UPDATE_SCHEMA=1 cargo test -p agentdeck-protocol schema_matches_committed_snapshot
```

## 浏览与外部资料

需要网页资料时优先使用当前环境可用的官方浏览工具和一手来源。不要引入项目级外部浏览 skill 依赖，也不要要求安装额外工具才能在本仓库工作。
