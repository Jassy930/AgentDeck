# AgentDeck v0.1 产品定义：Local Coding Agent Workbench

## 一句话定义

**AgentDeck 是一个 macOS 原生的本地 Coding Agent 工作台，用来连接 Codex，并统一管理多个本地项目中的任务、运行、变更、状态与复盘。**

更短一点：

> **Codex writes code. AgentDeck organizes the work.**

中文：

> **Codex 负责写代码，AgentDeck 负责组织、管理和推进这些工作。**

---

## 核心定位

AgentDeck 不是：

- 不是 IDE
- 不是 Codex Desktop 替代品
- 不是通用多 agent 聊天界面
- 不是自动化办公助手
- 不是简单的 Codex GUI 壳

AgentDeck 是：

> **本地代码项目的 Agent Workbench。**

也就是：

```text
Project
  → Task
    → Codex Thread
      → Run
        → Diff / Log / Test / Summary / Decision
```

---

## 唯一必须赢的点

# Local Agent Workbench

每个本地项目都有一个面向 agent 工作流的统一工作台。

它统一呈现并管理：

- 这个项目当前有哪些 agent 任务
- Codex 本身已有的历史 thread 分布在哪些项目里
- 哪些任务正在推进、等待 review 或被 blocked
- 每次运行改了哪些文件
- 测试有没有通过
- 哪些失败需要处理
- 下一步应该继续什么
- 哪些项目上下文需要更新

这是 AgentDeck 相比 Codex Desktop 最核心的差异：

| 产品 | 核心 |
|---|---|
| Codex Desktop | 当前 Codex thread 的执行体验 |
| AgentDeck | 跨项目、跨任务、跨 run 的本地 agent 工作台 |

一句话：

> **Codex Desktop 管当前会话，AgentDeck 管本地项目的 agent 工作流。**

---

## MVP 只做一个闭环

# 从 Task 到 Timeline

第一版只做这个闭环：

```text
导入本地项目
→ 扫描 / 导入 Codex 已有历史 Thread
→ 创建 AgentDeck Task 或选择历史 Thread
→ 通过 Codex app-server 启动 / 绑定 / 恢复 Codex Thread
→ 观察本次 Run
→ 结束后抓取 Diff / Log / Test Result
→ 生成 Run Summary
→ 写入 Project Workbench / Timeline
```

不要一开始做多 agent，不要做复杂编排，不要做完整 chat，不要做大而全 dashboard。

---

## MVP 核心页面

只保留 4 个页面。

### 1. Projects

本地项目列表。

每个项目显示：

- 项目名
- 路径
- Git 分支
- 是否有未提交改动
- 最近一次 agent run
- 当前未完成 task 数
- 是否有 AGENTS.md
- 最近失败原因

目标：

> 一眼知道本机哪些项目被 agent 改过、哪些还没收尾。

---

### 2. Project Workbench

这是主页面，也是杀手功能。

展示某个项目的 agent 工作状态、任务进展和历史记录：

```text
Today
- AD-012: 修复 Settings 面板
  Codex Run 完成
  8 files changed
  tests failed
  reason: missing xcodebuild scheme
  next: 补充 AGENTS.md 里的 test command

Imported Codex History
- thread_abc: 改善原生流式会话反馈
  cwd: /Users/jassy/Documents/glm/AgentDeck
  source: cli
  next: 可通过 thread/resume 继续上下文

Yesterday
- AD-011: 重构 Rust daemon config loader
  Codex Run 完成
  4 files changed
  tests passed
  decision: 保留 TOML 作为用户配置格式
```

目标：

> 把 agent 正在做、已经做过、还需要继续推进的工作放到同一个可管理界面里。

---

### 3. Tasks

结构化任务列表。

每个 Task 有：

```markdown
# AD-0001: Implement project scanner

## Goal

## Context

## Constraints

## Acceptance Criteria

## Linked Codex Thread

## Runs

## Current Status
```

状态只需要：

```text
Backlog
In Progress
Review
Done
Blocked
```

目标：

> 不再用散乱 prompt 驱动 agent，而是用可追踪的任务契约驱动 agent。

---

### 4. Runs

每一次 agent 执行的详情页。

记录：

- agent：Codex
- project
- task
- thread id
- thread 来源：AgentDeck 新建 / Codex 历史导入
- prompt
- start / end time
- event log
- changed files
- diff stat
- test result
- summary
- next action

目标：

> 每次 Codex 干了什么，都能被回看和审计。

---

## 技术定义

### 架构

```text
AgentDeck.app
macOS Native App
SwiftUI + AppKit
        │
        ▼
agentdeckd
Rust daemon
        │
        ├── Codex App Server Adapter
        ├── Project Scanner
        ├── Git Inspector
        ├── Task Store
        ├── Run Recorder
        └── Timeline Indexer
```

---

### 首要协议

```text
Codex app-server
```

不用 CLI wrapper 作为主路径。

CLI 可以作为 fallback，但产品定义上必须是：

> **Codex app-server native client.**

---

### 本地数据

v0.1 当前实现采用 AgentDeck 管理的数据目录，绝不写入用户项目 git：

#### 1. Run Records

```text
~/Library/Application Support/AgentDeck/runs/*.jsonl
```

每次 turn 写入中立 item 留痕，用 `runId` 与诊断日志关联。

#### 2. Diagnostic Log

```text
~/Library/Application Support/AgentDeck/diagnostic.log
```

记录进程、IPC、adapter 和持久化异常；每行是结构化 JSONL，带 `runId` / `eventSeq` 等关联字段。

`AGENTDECK_DATA_DIR` 只用于测试和诊断覆盖目录。早期草案里的 repo-native
`.agentdeck/runs` bridge 不再是当前实现路径。

---

## macOS 原生价值

只保留最关键的 4 个。

### 1. Menu Bar Agent Radar

菜单栏常驻显示：

- 正在运行的 agent
- 等待 approval 的任务
- 失败的 run
- 有未提交改动的项目

---

### 2. Native Notifications

当这些事件发生时通知用户：

- run 完成
- tests failed
- 等待 approval
- 修改文件过多
- 任务 blocked

---

### 3. Global Quick Capture

全局快捷键创建任务：

```text
⌥ Space → New AgentDeck Task
```

从任何地方快速捕获一个 agent 任务。

---

### 4. Local Project Watcher

后台 watch 本地项目：

- 新增 repo
- Git dirty
- AGENTS.md 缺失
- 最近被 agent 修改
- 任务状态变化

---

## 和竞品的边界

### 对 Codex Desktop

不抢：

- Chat
- Diff review
- Worktree execution
- 官方 Codex 体验

只赢：

> **跨项目 agent 工作台、任务治理与复盘。**

---

### 对 AionUi

不抢：

- 多 agent 数量
- 跨平台
- 通用 AI cowork

只赢：

> **Codex-first 深度、本地代码项目治理、macOS 原生体验。**

---

## 产品北极星

建议写成项目根目录的 `NORTH_STAR.md`：

```markdown
# AgentDeck North Star

AgentDeck is a native macOS workbench and control console for local coding agents.

It uses Codex app-server as the first-class protocol.

AgentDeck does not replace Codex Desktop.
AgentDeck does not try to be an IDE.
AgentDeck does not try to be a generic multi-agent chat app.

Codex writes code.
AgentDeck organizes the work.

The core product is Local Coding Agent Workbench:

For every local project, AgentDeck records tasks, Codex threads, runs, diffs, logs, test results, decisions, failures, and next actions.

Its goal is to make agent work across local projects visible, controllable, reviewable, recoverable, and continuously improvable.
```

---

## 最小版本名称

## AgentDeck v0.1 — Local Coding Agent Workbench

v0.1 只验收一件事：

> 我能在一个本地工作台里看到某个项目的 Codex 任务、运行、变更、结果和下一步，并能持续推进它。

这就是最小可成立版本。
