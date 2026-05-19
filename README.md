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

> 待补：Xcode 工程 + Cargo 工程就位后填写。

```
# Swift app
xcodebuild ...

# Rust daemon
cargo build --release -p agentdeckd
```

## 贡献

AgentDeck 的核心是那条 agent-中立适配器接口。今天它只有一个
`CodexAdapter`；社区可以平行贡献新 adapter（Claude Code、SSH 远程、
云端 agent）。贡献指南待补（adapter 接口稳定后）。

## License

MIT — 见 [LICENSE](LICENSE)。
