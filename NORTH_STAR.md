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

AgentDeck 的桌面端使用 Rust + GPUI，优先把 macOS 做扎实，再评估 GPUI 支持的
其他桌面平台；iOS companion 继续使用 UIKit。桌面端不再维护 AppKit 实现，也不
增加迁移兼容层。

共享层是一个 Rust daemon `agentdeckd` + 中立 IPC 协议
`agentdeck-protocol`。所有客户端通过统一协议消费同一个 daemon。

## AgentDeck 自带能力（跨 agent）

- 跨项目的 Project / Task / Run 工作台
- Skill 管理
- 插件系统
- SSH 远程执行
- 移动端伴侣

这些能力按版本路线图分阶段交付，不在 v0.2 范围内。

## 当前必赢

先建立可快速迭代的 macOS 最小闭环：

1. GPUI + gpui-component 的真实 `.app` 能稳定构建、启动和自检。
2. 桌面端只通过 typed local client 连接本机 `agentdeckd`，不嵌入 daemon。
3. 先完成单会话 prompt → streaming → complete，再扩展历史和审批。
4. 远程能力不在当前桌面切片中，也不作为本地开发门禁。
5. 不恢复旧 AppKit 的实现细节，只保留仍有效的产品和协议不变量。
