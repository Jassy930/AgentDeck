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

## 仓库结构

```text
agentdeck-desktop/       最小 Rust/GPUI macOS 客户端
agentdeck-protocol/      AgentDeck 中立 IPC 类型与 schema 事实源
agentdeckd/              Codex / Claude Code adapter daemon
agentdeck-cli/           参考客户端与 E2E 驱动
Sources/AgentDeckCore/   iOS 使用的平台无关 Swift 模型
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

# 现有 Rust backend / protocol
cargo test

# 协议 schema 漂移
cargo run -q -p agentdeck-cli -- protocol schema \
  | diff - protocol/agentdeck/agentdeck-protocol.schema.json

# 文档结构
scripts/verify-agent-docs.sh
```

只有改动对应层时才运行其门禁。

## 下一条纵向切片

桌面端的下一目标是本机最小闭环，而不是恢复旧客户端的全部功能：

1. 抽出一个 typed local client。
2. 连接本机 `agentdeckd`。
3. 只完成一个会话的启动、prompt、流式文本和结束状态。
4. 在该闭环稳定后再增加历史、审批、Markdown 和多 agent 能力。

设计和实施边界见：

- `docs/plans/2026-08-17-gpui-desktop-reset-design.md`
- `docs/plans/2026-08-17-gpui-desktop-reset-implementation.md`

## 文档入口

- [ARCHITECTURE.md](ARCHITECTURE.md)：稳定边界与依赖方向。
- [docs/index.md](docs/index.md)：文档导航和历史计划。
- [docs/QUALITY.md](docs/QUALITY.md)：按变更范围选择验证。
