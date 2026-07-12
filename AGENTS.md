# AgentDeck 代理工作入口

本文件只作为仓库地图和执行规则，不承载详细百科。更深的产品、架构、诊断和计划信息必须写入下游文档，并随代码同步更新。

## 必读顺序

1. `NORTH_STAR.md`：产品北极星和 v0.2 必赢目标。
2. `README.md`：当前用户可见能力、架构摘要、构建与测试命令。
3. `ARCHITECTURE.md`：稳定架构、分层边界、依赖方向和不变量（v0.2 含 N1–N8 新不变量）。
4. `docs/index.md`：文档记录系统导航。
5. `docs/AGENT_DIAGNOSTICS.md`：自检、诊断日志和 failure code（含 CC adapter failure codes）。
6. `docs/QUALITY.md`：验证命令、质量门禁和文档结构检查（含 v0.2 手动 QA 清单）。
7. `docs/plans/README.md` 与 `docs/plans/`：设计文档和实施计划规则。当前实现基线仍以 `docs/plans/2026-06-30-unified-shell-v02-design.md` / implementation 为准；Relay 以已批准的 `docs/plans/2026-07-10-relay-companion-mvp-design.md` 和 `docs/plans/2026-07-10-relay-companion-mvp-implementation.md` 为目标事实源与执行清单。P2.10 已完成；P3.1 代码已提交为 `835a7b3`，但真实 provisioned signed Keychain roundtrip 仍 gated BLOCKED，因此不得宣称 P3.1/P3 完成，继续按计划执行 P3–P6。
8. `protocol/SPIKE_FINDINGS.md` 与 `protocol/`：Codex app-server 协议事实源。

## 项目边界

- AgentDeck 是 Coding Agent 的统一原生桌面客户端，把 Codex 和 Claude Code 作为绝对一等公民，不是 IDE、不是 Codex Desktop 替代品、不是通用多 agent 聊天界面。
- v0.2 核心：IPC v2 双层协议 + ClaudeCodeAdapter MVP + CapabilityRouter + 跨 agent 历史聚合。
- UI 必须通过 `CapabilityRouter` 按 `SessionCapabilities` 路由渲染路径，禁止 `if agentKind == .codex` 硬编码分支（N2）。
- IPC 主干类型严禁出现 vendor 字样；vendor 字段只能出现在 `capabilities.*` / `vendorControl.*` / `vendorPanel.*` 命名空间（N1）。
- Codex 细节只能留在 `agentdeckd/src/codex/` 子模块；CC 细节只能留在 `agentdeckd/src/claude_code/` 子模块；两者互不知晓（N3）。
- `protocol/` 中 Codex schema 必须来自官方 `codex app-server generate-json-schema`，不要手写或逆向猜测协议（K8）。
- AgentDeck 不读取、不保存、不转发任何 vendor token（Codex 或 Claude Code）；CC 历史走 CC 原生接口，不建 `cc-meta/` 目录（K9、N8）。
- AgentDeck stable run record 与 diagnostic log 固定写入当前 EUID 的 OS account home 下 `Library/Application Support/AgentDeck/`；ephemeral 实例写入随机 0700 temp namespace，均不得写入用户项目 git（K5）。
- `Sources/AgentDeckCore/` 是 macOS/iOS 共享的平台无关层，禁止 import AppKit/UIKit；`ios/` 是 fixture 驱动的 UIKit companion 前端，唯一数据入口是 `MobileSessionSource`，本期不含网络代码（设计见 `docs/plans/2026-07-03-ios-uikit-frontend-design.md`）。

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

### iOS 前端验证

```bash
# iOS 工程生成 + 构建 + 单测（fixture 驱动，无真实链路）
cd ios && xcodegen generate && \
  xcodebuild -project AgentDeckMobile.xcodeproj -scheme AgentDeckMobile \
    -destination 'platform=iOS Simulator,name=iPhone 17' test
```

涉及 `Sources/AgentDeckCore/` 或 `ios/` 时至少运行 `swift test` 与上述 iOS 测试。

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

协议 schema 漂移测试随标准 `cargo test` 运行；改动 `agentdeck-protocol` 中的类型后须用以下命令重新生成快照：

```bash
UPDATE_SCHEMA=1 cargo test -p agentdeck-protocol schema_matches_committed_snapshot
```

### Relay Companion MVP P2.10

Relay R0/R1 计划与测试只保留为历史记录；v1 协议、server、client、daemon bridge
和兼容 feature 已物理删除，不得再使用 `--bootstrap-secret`、`ws://` v1 命令或
R1b 测试作为当前验证。production binary 只运行 Relay v2 Direct TLS/WSS；loopback
明文或 proxy 只能显式用于受控开发。`/v1/connect` 只是无状态 HTTP 426 tombstone。

```bash
# 当前统一 P2 门禁
bash scripts/verify-relay-companion-mvp.sh p2

# Relay v2 安全与故障专项
cargo test -p agentdeck-relay --features server,tls \
  --test relay_v2_hardening_e2e -- --test-threads=1
cargo test -p agentdeck-relay --features server,tls \
  --test relay_v2_security_e2e -- --test-threads=1
cargo test -p agentdeck-relay-client

# Relay v2 production config selfcheck：真实 TLS preflight + Store/Core 打开/关闭
relay_selfcheck_dir="$(mktemp -d)"
cargo run -p agentdeck-relay --features server,tls -- \
  --selfcheck \
  --config agentdeck-relay/tests/fixtures/relay-selfcheck.toml \
  --storage "$relay_selfcheck_dir/relay.db"
rm -rf "$relay_selfcheck_dir"

# daemon 仍无网络依赖
bash scripts/check-daemon-no-net.sh
```

真实外部 Direct TLS/SPKI synthetic 由本机 admin UDS 先生成一次性 bundle，再执行：

```bash
agentdeck remote synthetic --bundle /secure/path/machine-enrollment-bundle.json
```

该命令只使用临时 machine/device identity，不建立持久状态。P4 前其余
`remote pair/machines/sessions/watch/send/...` 必须返回
`remote.persistent.unsupported`。旧 v1 credential marker 只允许做 metadata
存在性探测；production CLI 不读取、不删除、不拨号。需要清理时只能显式运行
`scripts/reset-relay-v1-dev-state.sh`，成功后重新配对，不提供恢复。

改动任一协议轴后，使用对应的 `UPDATE_*_SCHEMA=1` 测试更新快照，并确认以下
四条导出都与仓库快照逐字节一致：本地 IPC、Runtime、Relay v2、E2EE。

### Relay Companion MVP P3.1（尚有 gated 签名门禁）

```bash
cargo test -p agentdeckd --test daemon_namespace --test storage_kek \
  --test daemon_startup -- --test-threads=1
cargo test -p agentdeckd
cargo test -p agentdeck-cli
swift test
cargo run -q -p agentdeck-cli -- selfcheck
bash scripts/check-daemon-no-net.sh
```

unsigned 开发实例必须显式使用 `--ephemeral --no-remote --profile dev`；stable daemon
不接受 `HOME`、`AGENTDECK_DATA_DIR`、`AGENTDECK_PROFILE` 或运行时 access-group override。
真实 Keychain `set → load → delete` ignored test 只有在编译值、codesign entitlement 与
provisioning profile 一致的 helper 上实际运行后才算通过；当前本机无匹配 provisioning
profile，已签名尝试均被 AMFI 以 exit 137 终止。ignored 不能计作 PASS，也不能据此完成 P3.1。

## 浏览与外部资料

需要网页资料时优先使用当前环境可用的官方浏览工具和一手来源。不要引入项目级外部浏览 skill 依赖，也不要要求安装额外工具才能在本仓库工作。
