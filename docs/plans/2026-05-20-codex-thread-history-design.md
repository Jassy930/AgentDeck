# Codex 历史 Thread 管理设计

## 背景

AgentDeck 的定位是本地 Coding Agent 工作台，不只展示当前一次运行，还要组织跨项目、跨任务、跨 run 的 agent 工作流。现有 v0.1 已经能通过 Codex app-server 启动新 thread、流式展示 turn，并把 run 记录写入 AgentDeck 自己的数据目录。

新的目标是让 AgentDeck 能扫描、导入并管理 Codex 本身已有的历史 thread：用户可以看到不同项目的历史会话，打开历史内容，并恢复到之前的上下文继续工作。

## 目标

- 扫描 Codex app-server 已持久化的历史 thread。
- 按项目 `cwd` 聚合历史会话，支持跨项目浏览。
- 读取历史 thread 的 turns/items，用 AgentDeck 的中立 UI 模型回放。
- 通过 `thread/resume(threadId)` 恢复真实 Codex 上下文，再继续 `turn/start`。
- 保持 Swift 客户端对 Codex 零感知；Codex 细节仍只存在于 Rust adapter。

## 非目标

- 第一版不做完整 SQLite 数据库迁移。
- 第一版不全量复制 Codex 历史为 AgentDeck 的唯一真相源。
- 第一版不做 `rollback`、`fork` 等会改变上下文语义或影响本地文件状态的高级管理动作。
- 第一版不导入非 Codex adapter 的历史。

## 推荐方案

采用“Codex 原生索引优先，AgentDeck 轻量镜像”的方案。

AgentDeck 通过 app-server 的 `thread/list` 获取历史列表，并按需调用 `thread/read(includeTurns: true)` 读取详情。用户选择继续某个历史会话时，daemon 调用 `thread/resume`，保存当前 active thread id，之后的 prompt 不再创建新 thread，而是在已恢复 thread 上执行 `turn/start`。

这个方案让 Codex 历史仍是上下文真相源，AgentDeck 只承担索引、组织、回放和管理入口。它同时满足“管理 Codex 本身已有历史 thread”和“AgentDeck 不中断官方 app-server 语义”的要求。

## 架构

```text
AgentDeck.app
  SessionModel / History UI
      │ neutral IPC
      ▼
agentdeckd
  ipc history requests/responses
  CodexAdapter
      ├── thread/list
      ├── thread/read
      ├── thread/resume
      └── turn/start(existing thread)
      ▼
codex app-server
```

Swift 侧新增的是中立历史模型，例如 `HistoryThread`、`HistoryTurn`、`HistoryProjectGroup`。这些类型不得暴露 Codex 字样，也不得要求 Swift 解析 vendor JSON。

Rust 侧在 `codex.rs` 中新增 Codex app-server 方法，在 `ipc.rs` 中定义中立 wire shape，在 `main.rs` 中新增请求分发。

## 数据流

1. 用户打开历史入口。
2. Swift 发送 `history/listThreads`，可带 `cwd`、`searchTerm`、`cursor`、`limit`。
3. daemon 调用 Codex `thread/list`，返回中立 thread 摘要：`id`、`name`、`preview`、`cwd`、`createdAt`、`updatedAt`、`status`、`modelProvider`、`source`。
4. Swift 按 `cwd` 分组展示。
5. 用户点开 thread，Swift 立即标记该行正在打开，不阻塞主线程。
6. Swift 在后台发送 `history/readThread { threadId, includeTurns: true }`。
7. daemon 调用 Codex `thread/read`，把 turns/items 翻译成可回放的中立结构。
8. Swift 记录 read / apply timing，并在主线程应用详情。
9. 大段 shell output 和 diff 先只保留原文与摘要，展开时再填充 TextKit buffer。
10. 用户点击继续。
11. Swift 发送 `history/resumeThread { threadId }`。
12. daemon 调用 `thread/resume`，保存 active thread id 并返回恢复后的 thread 摘要。
13. 后续输入 prompt 时，Swift 发送现有 `startSession` 或新增 `startTurn`，daemon 对 active thread 执行 `turn/start`。

## UI 设计

第一版采用低复杂度布局：

- 顶部状态栏保留当前项目与状态。
- 当前空状态增加“打开历史会话”入口。
- 有项目时增加历史侧栏或历史面板，按项目路径分组。
- Thread 行展示项目名、标题或 preview、更新时间、状态。
- Thread 行必须是整行块级点击目标；hover、正在打开和已选中状态要有可见反馈，
  不能只让标题文字成为有效热区。
- Thread 打开时行内显示进度，状态栏显示最近一次历史打开的 read / apply 耗时。
- Thread 详情复用现有单列 stream 样式，不做聊天气泡化。
- 长 output / diff 保持折叠；未展开前不创建大 TextKit storage。
- 已恢复的 thread 在输入框附近显示“继续历史会话”的短状态。

管理动作第一版只做：

- 刷新历史。
- 按项目过滤。
- 搜索标题或 preview。
- 归档 / 取消归档。
- 重命名 thread。

## 错误处理

- `thread/list` 失败：显示可见错误，不清空已有 UI。
- `thread/read` 失败：保留列表，详情区域显示失败原因。
- `thread/resume` 失败：不切换 active thread，提示用户仍在当前会话状态。
- Codex 返回空 turns：仍显示 thread metadata 和 preview。
- Codex 历史 items 是 lossy 的事实必须在代码注释和文档里明确，不能暗示可完整还原每一次 shell/file-edit。

## 测试策略

- 行为测试：点击历史 thread 后立即进入 opening 状态，详情返回后再回放。
- Timing 测试：成功打开后记录 thread id、item count、read/apply/total ms。
- Lazy 内容测试：大 output / diff 在回放时不填充 buffer，展开请求后再 materialize。

## 后续 TODO

- 支持分页 / 部分读取：优先只读取最近 N 个 turns，滚动到更早位置时再请求旧 turns。
- 如果 Codex app-server 增加 `thread/read` 的 range/cursor 参数，优先用服务端分页，避免客户端拿完整历史后再截断。
- 为 timing 增加 daemon 分段日志：spawn、initialize、thread/read、neutral mapping、IPC write。

- Rust adapter fixture 测试：覆盖 `thread/list`、`thread/read`、`thread/resume` 返回结构解析。
- Rust IPC 测试：中立历史响应不能包含 vendor vocabulary。
- Swift 模型测试：历史列表按 cwd 分组、搜索过滤、选择 thread 后加载详情。
- Swift 会话测试：恢复 thread 后继续 prompt 不创建新 thread。
- 端到端手动验证：使用真实 Codex app-server 扫描本机历史，读取一个旧 thread，继续发送一条低风险 prompt。

## 文档同步

- README 增加“历史会话”能力说明。
- 产品定义文档补充 Codex 原生历史 thread 的管理边界。
- 如果后续引入 SQLite，再新增单独的存储迁移计划。
