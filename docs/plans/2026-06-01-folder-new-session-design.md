# Folder New Session Design

## 背景

左侧 History 面板按项目 `cwd` 分组展示历史会话。用户看到某个文件夹后，想直接在该文件夹下开启一个新会话；当前入口只有状态栏中的 `New session`，它只针对当前项目上下文，不方便从历史分组快速切换项目。

## 目标

- 在左侧文件夹名称行右侧增加加号按钮。
- 点击加号后，把当前工作目录切换为该文件夹，并清空当前历史选择与会话流。
- 保持现有 live session 创建语义：不立即创建空 thread，等用户输入第一条 prompt 后再通过现有 `submit()` 路径创建 runtime。

## 非目标

- 不改变 daemon、IPC、Codex app-server 协议或历史读取语义。
- 不新增空历史记录或预创建 Codex thread。
- 不改变历史会话行的打开、重命名、归档行为。

## 设计

`SessionView.historyGroup(_:)` 将文件夹标题行从纯文本改为 `HStack`：左侧显示现有 `group.projectName`，右侧显示 `plus` 图标按钮。按钮使用无边框样式和 help 文案，点击后调用 `SessionModel.startNewSession(inProjectCwd:)`。

`SessionModel.startNewSession(inProjectCwd:)` 先把 `cwd` 设置为传入路径，再复用现有新会话重置逻辑：清空 `selectedHistoryThreadId`、取消正在打开的历史 thread、清空 legacy stream 和错误状态，并把 phase 置为 `.ready`。后续用户提交 prompt 时，现有 `submit()` 会用这个 `cwd` 创建新的 live runtime。

## 错误处理与可观测性

该按钮只基于已经从历史列表返回的 `cwd` 工作，不访问文件系统，也不启动 daemon。如果目录后续不存在或不可读，daemon 侧仍会在真正启动 turn 时给出权威错误；Swift 层不在点击按钮时做额外阻塞检查。

## 测试和验收

- Swift 单元测试覆盖：从历史详情状态点击某个分组的新会话后，`cwd` 切换到该分组路径，历史选择被清空，conversation viewport identity 重置为 live，phase 为 ready。
- 手工验收：左侧每个文件夹标题右侧出现加号；点击后右侧进入空的新会话输入状态，状态栏项目名切到对应文件夹。
