# AgentDeck Claude 入口

本仓库不绑定项目级外部 skill。仓库自有 skill 放在 `.agents/skills/` 入库，`.claude/skills/` 下用符号链接指向同一份（目前只有发版流程 `agentdeck-release`）；外部 skill 不入库。Claude Code 在本项目中工作时，先读取并遵守 `AGENTS.md`。

项目级约束、文档入口、架构边界和验证命令以 `AGENTS.md` 为准；不要通过项目 hook 强制安装或使用额外工具。
