# AgentDeck

**Codex 写代码，AgentDeck 组织工作。**

AgentDeck 是一个 macOS 原生的本地 Coding Agent 工作台，通过官方
[Codex app-server](https://developers.openai.com/codex/app-server) 协议连接
OpenAI Codex，让你在原生界面里实时看到 agent 在做什么、并掌控它。

> 状态：v0.1 开发中。这是一个开源 / 学习项目。

## 这是什么

每次你让 Codex 干活，AgentDeck 在一个 macOS 原生窗口里流式展示它的
工作过程 —— 它在想什么（reasoning）、跑了什么命令（shell）、改了哪些
文件（file-edit）—— 并在它要执行有风险的操作前让你 approve / deny。

AgentDeck **不是** IDE，**不是** Codex Desktop 替代品，**不是**通用多
agent 聊天界面。它是本地代码项目的 agent 工作台。

## v0.1 范围

v0.1 验收两件事（"双拍"）：

1. **原生流式会话**：macOS 原生界面，流式渲染 Codex 的
   reasoning / shell / file-edit item，带交互式 approve / deny。这是
   "为什么必须 macOS 原生"的证明。
2. **agent-中立的适配器边界**：daemon 内翻译，IPC 协议本身就是中立的
   `AgentItem`。Swift 永远不知道 Codex 存在。这是社区能平行贡献
   Claude Code / SSH / 云端 adapter 的地基 —— 官方产品结构上做不了
   agent 中立。

完整设计与三层评审记录见设计文档（office-hours → CEO → Eng → Design
review，七层可追溯）。

## 架构

```
AgentDeck.app  (macOS, SwiftUI + AppKit)
      │  stdio JSONL IPC（中立 AgentItem，无 Codex 字样）
      ▼
agentdeckd  (Rust daemon)
      │  ├── CodexAdapter（Codex item → 中立 AgentItem 翻译）
      │  ├── Session 状态机（唯一状态源）
      │  └── 进程组拥有 app-server，退出连带 kill
      ▼
codex app-server  (子进程, JSON-RPC over stdio)
```

中立边界的物理位置 = IPC 协议本身。可验证事实：IPC schema 里不出现
任何 Codex 字样。

## 构建

前置：Rust（`cargo`）、Swift 6 / Xcode（macOS 14+）、`codex` CLI 已
`codex login`（AgentDeck 不碰 / 不存 / 不转发任何 token —— 沿用 codex
已有认证）。

```bash
# Rust daemon
cargo build --release            # 产出 target/release/agentdeckd

# Swift app
swift build -c release           # 产出 .build/release/AgentDeck
```

运行（Swift app 会自动 spawn 同目录或 PATH 上的 agentdeckd）：

```bash
swift run AgentDeck               # 打开原生窗口
swift run AgentDeck -- --selfcheck  # 无窗口自检(CI: IPC+生命周期)
```

测试：

```bash
cargo test        # daemon: ipc/codex/record/diag(含 fixture 回放)
swift test        # app: 中立协议 + 分行成帧
```

### 协议

`protocol/` 是从官方 `codex app-server generate-json-schema` 生成的
协议 schema（非逆向）。`protocol/SPIKE_FINDINGS.md` 记录实测的 wire
framing（逐行 JSONL）。codex 版本固定在 `protocol/CODEX_VERSION.txt`。

### 本地数据（AgentDeck 管理，绝不进你的 git）

- run 记录：`~/Library/Application Support/AgentDeck/runs/*.jsonl`
- 诊断日志：`~/Library/Application Support/AgentDeck/diagnostic.log`

写入前做 best-effort 密钥脱敏。写失败不阻塞会话，但会在界面可见
警告（绝不静默）。

### 回滚

未签名 `.app`：删除应用即可。GitHub Releases 保留旧版本 zip。无
数据库迁移、无 feature flag。首次打开需在系统设置允许（Gatekeeper）。

## 贡献

AgentDeck 的核心是那条 agent-中立适配器接口。今天它只有一个
`CodexAdapter`；社区可以平行贡献新 adapter（Claude Code、SSH 远程、
云端 agent）。贡献指南待补（adapter 接口稳定后）。

## License

MIT — 见 [LICENSE](LICENSE)。
