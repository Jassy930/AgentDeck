# History Runtime Indicators Design

## 背景

左侧 History 面板曾在搜索框下方单独显示 compact runtime selector。该区域会随着
用户打开多个历史 thread 而增长，占用 History 列表空间；同时标题多来自项目目录名，
多个 thread 的 `cwd.lastPathComponent` 相同时会显示成重复项目，难以表达真实含义。

## 目标

- 移除独立 Runtime 区块，把 runtime 状态压回对应历史会话行。
- 已缓存历史 thread 在历史行内可见，但不抢占列表主空间。
- 未读事件只用一个小彩色点提示，不显示数字徽标。
- 保留底层 `WorkbenchModel` / `ThreadRuntimeModel`，继续支持后台运行、队列、
  审批和未读计数。

## 设计

History 行根据 `thread.id` 查询 `workbench.runtime(sessionId:)`。如果存在匹配
runtime，行内在 agent 图标之后显示一个小圆点：

- `ready` / 普通缓存态：低调灰色小点。
- `starting` / `running`：系统 accent 小点。
- `waitingApproval`：橙色小点。
- `failed`：红色小点。
- `unreadEventCount > 0`：使用更醒目的 accent 小点，尺寸略大；不显示数字。

副标题保留原有 `status / source / updatedAt`，并在有匹配 runtime 时附加 runtime
phase。当前选中历史 thread 仍由整行背景和左侧 accent bar 表示。

## 非目标

- 不把尚未进入历史列表的 live runtime 塞入 History 列表。
- 不改变 daemon runtime hub 或 IPC 协议。
- 不改变历史 thread 的读取、回放和续写语义。
