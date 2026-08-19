# AgentDeck

AgentDeck 是 Coding Agent 的统一原生桌面客户端。产品目标仍是把 Codex 和
Claude Code 作为一等公民放进同一个工作台；当前实现处于桌面端重启阶段。

## 当前状态

macOS 旧 AppKit 客户端已经移除。新的 `agentdeck-desktop` 使用 Rust、
[GPUI](https://crates.io/crates/gpui) 和
[gpui-component](https://crates.io/crates/gpui-component) 从最小壳开始迭代。

当前桌面端只承诺：

- 创建真实 GPUI macOS 窗口。
- 初始化 `gpui-component` 并挂载 `Root`。
- 提供 `--selfcheck`，验证 GPUI、Metal renderer、隐藏窗口和组件树初始化。
- 通过统一脚本构建并启动 `dist/AgentDeck.app`。

当前明确不包含：

- daemon / IPC 连接。
- 会话、历史、composer、审批和富文本 transcript。
- 远程机器、网络数据源和配对流程。
- 对旧 AppKit 界面或行为的兼容层。

这些能力只按新的纵向切片逐步加入；当前仓库先收敛本地最小闭环。

后端 `agentdeckd` 已有 Codex / Claude Code adapter、history、approval、record 和
diagnostics 等较宽的代码表面。Codex 路径已经落地 protocol v4 的 session-scoped
生命周期与累计消息 streaming：规范握手、顺序多轮、原生 turn interrupt、显式
close/wait，以及带 `turnId`、稳定 `itemId` 和 `streaming|completed` state 的
`AgentItem`；同一 assistant message 的每次非空 delta 都作为完整文本快照发给客户端。
Unix 进程组消失与路由清除后才发 `SessionClosed`；stdin EOF 会有序关闭并等待 retained
session，无法确认 cleanup 时 daemon 会 poison 并退出。Codex 只声明已由确定性 fixture
覆盖的 `StreamingMessages`；Claude Code 仍丢弃 partial message/reasoning delta，因此
不声明 `StreamingMessages` 或 `StreamingReasoning`。这仍不是 desktop 可依赖的完整 M0：持久连接 CLI/真实 vendor 验收和生产
RunRecord/diagnostics 分别留在 #5、#6，且本轮没有运行真实 Codex session/prompt。
当前完整度和证据边界见
[docs/AGENTDECKD_STATUS.md](docs/AGENTDECKD_STATUS.md)。

## 仓库结构

```text
agentdeck-desktop/       最小 Rust/GPUI macOS 客户端
agentdeck-protocol/      AgentDeck 中立 IPC 类型与 schema 事实源
agentdeckd/              Codex / Claude Code adapter daemon
agentdeck-cli/           参考客户端与 E2E 驱动
Sources/AgentDeckMobileCore/  iOS 使用的平台无关 Swift 模型
ios/                     UIKit companion
protocol/                Codex 官方 schema 与 AgentDeck schema 快照
docs/                    架构、诊断、质量规则与计划
```

`agentdeck-desktop` 当前不依赖 daemon 或 protocol crate。下一阶段若接入
本地能力，只允许增加 `desktop → typed client → agentdeckd` 的单向依赖；UI 不直接
解析 vendor JSON，也不把 daemon 嵌入 GUI 进程。

## 依赖版本

桌面 P0 固定使用：

```toml
gpui = { version = "=0.2.2", features = ["runtime_shaders"] }
gpui-component = "=0.5.1"
```

`runtime_shaders` 用于避免本地额外安装 Metal Toolchain。依赖通过仓库根目录的
`Cargo.lock` 锁定；不要在没有验证的情况下追 Git main。

## 构建与运行

前置环境：

- macOS 15+
- Rust 1.96+
- Xcode 26 或相应 Command Line Tools

最小开发循环：

```bash
cargo check -p agentdeck-desktop
cargo test -p agentdeck-desktop
cargo run -p agentdeck-desktop -- --selfcheck
./script/build_and_run.sh
./script/build_and_run.sh --verify
```

`script/build_and_run.sh` 是唯一桌面 build/run 入口。它构建
`agentdeck-desktop`、装配 `dist/AgentDeck.app`、写入 macOS 15 最低版本并启动
最新产物。当前最小 bundle 不携带或启动 `agentdeckd`。

Codex 桌面应用里的 Run action 已指向该脚本：

```text
.codex/environments/environment.toml
```

## 测试

```bash
# 新 GPUI 桌面壳
cargo test -p agentdeck-desktop
cargo run -p agentdeck-desktop -- --selfcheck

# iOS 共用 Swift Core
swift test

# 默认离线的 Rust workspace 门禁（含 vendor marker tripwire）
scripts/verify-offline-tests.sh

# 直接运行同一套标准 workspace 测试
env -u AGENTDECK_E2E cargo test --workspace --locked

# 用当前 checkout 构建的 daemon 执行 CLI selfcheck
cargo build --locked \
  -p agentdeckd --bin agentdeckd \
  -p agentdeck-cli --bin agentdeck
AGENTDECK_DAEMON_BIN="$PWD/target/debug/agentdeckd" \
  ./target/debug/agentdeck \
  --data-dir /tmp/agentdeck-selfcheck selfcheck

# 协议 schema 漂移
AGENTDECK_DAEMON_BIN="$PWD/target/debug/agentdeckd" \
  ./target/debug/agentdeck \
  --data-dir /tmp/agentdeck-schema protocol schema \
  | diff - protocol/agentdeck/agentdeck-protocol.schema.json

# 文档结构
scripts/verify-agent-docs.sh
```

只有改动对应层时才运行其门禁。

标准 `cargo test --workspace --locked` 默认不启动 `codex` / `claude`，也不读取用户
vendor history；所有真实 vendor process、session、prompt、history 和 auth 路径只在
`AGENTDECK_E2E` 的值严格等于 `1` 时启用。`scripts/verify-offline-tests.sh` 会把 marker
shim 放到 PATH 首位，并使用临时 HOME 隔离用户 vendor history 与默认 AgentDeck data dir：unset 和 `0` 各跑完整
workspace，空值、`false` 和其他值跑全部 gated integration targets，每次都断言 marker
不存在。普通 Cargo 测试中的 E2E 提前跳过仍会显示 passed，因此该结果不等于真实
Codex / Claude Code E2E 证据；完整边界见 [docs/QUALITY.md](docs/QUALITY.md)。

## 下一条纵向切片

下一目标是先稳定 daemon，再开始 desktop 的真实连接，而不是恢复旧客户端的全部功能：

1. 以已落地的 Issue #3 生命周期和 #4 累计 streaming 切片为底座，在 #5 增加持有同一
   daemon 连接的 CLI/test driver，并用连续两轮、cancel 后续轮和
   `SessionClose` 的真实 Codex E2E 验收同 PID/threadId 复用。
2. 在 #6 把 RunRecord、lifecycle diagnostics 和可定位的 `diagnosticRef` 接入生产路径，
   完成 M0 可观测闭环。
3. M0 全部门禁通过后，再抽出 typed local client 并连接本机 `agentdeckd`；desktop 首
   切片仍只消费首轮。
4. 在该闭环稳定后再增加历史、审批、Markdown、Claude Code 和多 agent 能力。

设计和实施边界见：

- `docs/plans/2026-08-17-gpui-desktop-reset-design.md`
- `docs/plans/2026-08-17-gpui-desktop-reset-implementation.md`
- `docs/plans/2026-08-17-codex-app-server-lifecycle-adr.md`
- `docs/plans/2026-08-17-agentdeckd-minimum-stable-boundary-design.md`

## 文档入口

- [ARCHITECTURE.md](ARCHITECTURE.md)：稳定边界与依赖方向。
- [docs/index.md](docs/index.md)：文档导航和历史计划。
- [docs/AGENTDECKD_STATUS.md](docs/AGENTDECKD_STATUS.md)：daemon 能力完整度与缺口。
- [docs/QUALITY.md](docs/QUALITY.md)：按变更范围选择验证。
