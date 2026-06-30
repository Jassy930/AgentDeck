# AgentDeck North Star

AgentDeck 是 Coding Agent 的统一原生桌面客户端。

它把 OpenAI Codex 和 Anthropic Claude Code 作为绝对一等公民，
两家的功能、概念和原始语义都被完整保留——AgentDeck 不强行
统一它们，而是为它们提供同一个工作台。

AgentDeck 不是 IDE。
AgentDeck 不是 Codex Desktop 替代品（它的对标对象是 Codex Desktop
的体验，但服务范围远大于单一 vendor）。
AgentDeck 不是通用多 agent 聊天界面。

Codex 写代码，Claude Code 写代码。
AgentDeck 是工作台、控制台、管理面。

## 一等公民承诺

- Codex 和 Claude Code 在 AgentDeck 里能用到的功能都是 100%，
  不为对方阉割、不为统一打折。
- Vendor 的原始概念语义（如 Codex 的 approval policy、CC 的
  permission mode）在 UI 上保留原词，不强译为中立词。
- 未来社区贡献的 adapter 同样按"一等公民"标准接入。

## 多端形态

AgentDeck 的"原生体验"意思是每个平台都用平台原生 UI 框架：
- macOS：AppKit
- iOS：UIKit
- Windows / Linux / Web：Rust 壳 + Web UI（Tauri 风格）

共享层是一个 Rust daemon `agentdeckd` + 中立 IPC 协议
`agentdeck-protocol`。所有客户端通过统一协议消费同一个 daemon。

## AgentDeck 自带能力（跨 agent）

- 跨项目的 Project / Task / Run 工作台
- Skill 管理
- 插件系统
- SSH 远程执行
- 移动端伴侣

这些能力按版本路线图分阶段交付，不在 v0.2 范围内。

## v0.2 必赢

在 macOS AppKit 上端到端验证「统一壳」架构：
1. IPC 协议 v2 引入 agent capabilities，支持两层（控件 + 事件）。
2. ClaudeCodeAdapter MVP 上线，CC 的特色能力（permission 模式、
   hooks、output-style 等）完整可用。
3. UI 整体范式统一，vendor-specific 控件保留原始语义。
4. Codex Desktop 对标点：Approval + Sandbox + Persistence 完整
   控件、Reasoning Effort + Token/Auth 小面板。
