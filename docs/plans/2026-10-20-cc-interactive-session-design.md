# Claude Code 交互会话（stream-json 双向协议）设计

## 背景

AgentDeck 目前只能只读浏览历史。要支持"发送消息交互"，并以 Claude Code 为主体，daemon
原有的 CC adapter 存在以下问题：

- 每次发消息都起一个 one-shot `claude --print` 进程；
- 结束时发 legacy `TurnComplete`，hub 会把它当成会话终态；
- partial delta 被丢弃；
- 审批写回格式是猜的（`permission_response`）。

用户要求以 Claude Code 功能最完整的方式交互，并且用 stream-json。

## 目标与非目标

目标（P1，daemon 侧，本次已实施）：

- 每个 AgentDeck session 对应一个常驻的 `claude` 子进程，同一进程里跑多轮。
- 用 CC 原生 stream-json 双向 control 协议实现审批、中断和会话内权限模式切换。
- partial delta 以累计快照形式流式下发。
- 走 hub 现有的 session owner 契约：`TurnStarted` / `TurnFinished` / exit 信号 → `SessionClosed`。

非目标（后续阶段）：

- P2 桌面端：daemon client 事件订阅、会话页输入框、发送/停止、审批条。v1 只续聊侧栏里已有的会话。
- hooks / SDK MCP server 回调（CC 发来的这类 control_request 一律回 error）。
- 图片输入、slash command 列表展示（`initialize` 回包里已有 `commands`，暂未使用）。

## 架构

全部改动限定在 `agentdeckd/src/claude_code/` 内（N3）：

- `adapter.rs`：负责 preflight、拼命令行、发出 `SessionStarted` + `SessionCapabilities`（N7），
  再把子进程交给 owner。adapter 只保存每个会话的命令邮箱。
- `session.rs`：owner actor。它独占 stdin/stdout，在一个 `select!` 里串行处理客户端命令和 CC 输出。
- `translate.rs`：纯翻译。`stream_event` 翻成累计 Streaming 快照，`result` 翻成
  `TurnFinished(nextState=ready)`，`control_request(can_use_tool)` 翻成 `ActionRequest`。

命令行：

```
claude --print --input-format stream-json --output-format stream-json \
  --permission-prompt-tool stdio --include-partial-messages --include-hook-events \
  --verbose --permission-mode <mode> [--resume <id> | --session-id <uuid>] ...
```

新会话由 daemon 生成 `--session-id`，因此 `threadId` 在 `SessionStarted` 里就确定了，后续所有事件都带上它。

## 协议事实（claude 2.1.304 实测，2026-10-20）

| 动作 | stdin → CC | CC → stdout |
| --- | --- | --- |
| 握手 | `{"type":"control_request","request_id":X,"request":{"subtype":"initialize"}}` | `control_response{subtype:success, response:{commands,...}}` |
| 发消息 | `{"type":"user","message":{"role":"user","content":"..."}}` | `system.init`、`stream_event`、`assistant`、`user(tool_result)`，最后 `result` |
| 审批请求 | — | `control_request{request_id, request:{subtype:"can_use_tool", tool_name, input, description, permission_suggestions, tool_use_id}}` |
| 允许 | `control_response{subtype:success, request_id, response:{behavior:"allow", updatedInput, [updatedPermissions]}}` | 工具执行 |
| 拒绝 | `control_response{..., response:{behavior:"deny", message}}` | `tool_result is_error`，并记入 `result.permission_denials` |
| 中断 | `control_request{subtype:"interrupt"}` | `control_response success`，随后 `result{subtype:"error_during_execution", is_error:true}`，进程存活 |
| 切权限模式 | `control_request{subtype:"set_permission_mode", mode}` | `control_response{response:{mode}}` |
| 关闭 | 关闭 stdin | 进程以 0 退出 |

- `persist=true` 的 approve 会把 `permission_suggestions` 原样作为 `updatedPermissions` 回传。
  CC 按 suggestion 的 destination 落盘，实测会写到项目 `.claude/settings.local.json`。
  这是 CC 原生语义，AgentDeck 不额外保存任何东西。
- 用户 `settings.json` 里 allow 的工具（`source: config`）不会触发 `can_use_tool`。

## 生命周期与错误

- `TurnStart` 时如果已有 turn 在跑，返回 `turn-already-running`；`TurnCancel` 指向非活动 turn，返回 `turn-not-active`。
- owner 自己发出 interrupt 之后收到的 `result`，一律映射为 `canceled`。其余非 success 的 `result` 映射为
  `failed`，错误码为 `cc-turn-failed`。
- `SessionClose` 的处理顺序：
  1. 有 turn 在跑就先 interrupt；
  2. 关闭 stdin；
  3. 在 10 秒内继续排空 stdout；
  4. wait 子进程，超时则 kill 进程组，最后再清扫一次进程组；
  5. 发 exit 信号，由 hub 发出唯一一个 `SessionClosed`。
- 子进程意外退出时：正在跑的 turn 报 `TurnFinished(failed, closing, cc-process-exited)`，错误信息里附 stderr 尾部；
  会话以 `failed` 收口。
- 未知的 inbound control_request 回 `control_response{subtype:error}`，避免 CC 一直挂起等待。

## 已知边界

- CLI 的 one-shot `agentdeck run` 在 `default` 权限模式下如果遇到需要审批的工具，会一直停在等待决定。
  需要交互审批时请用 `session live`，或者显式指定 `--permission acceptEdits` / bypass。
- `continue_thread`（旧 CLI 入口）仍然硬编码 `bypassPermissions`。
- 累计快照每个 delta 都下发全文，和 Codex 的语义对齐；超长回复的带宽开销是 O(n²)。

## 验证

- 离线：`cargo test -p agentdeckd --lib claude_code::session` 用 fake `claude` 覆盖两轮、审批路由、
  并发 turn 拒绝、interrupt 转 canceled、close 回收，以及子进程意外退出。
  `--test cc_translate` 覆盖流式快照、`TurnFinished` 和 `can_use_tool` 翻译。
  `scripts/verify-offline-tests.sh` 全绿。
- 真实（2026-10-20，claude 2.1.304，经 `agentdeckd` stdio）：
  - 新会话 + 审批 allow 写文件 → succeeded；
  - 第二轮中断 → canceled/ready；
  - 会话内切 acceptEdits 后第三轮写文件无需审批 → succeeded；
  - `SessionClosed(closed)`，共 56 个 streaming 快照；
  - 另起 daemon 用 `resumeThreadId` 续聊，模型记得前文，`persist=true` 后同类 Bash 不再询问。
