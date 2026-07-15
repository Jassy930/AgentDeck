# Adapter 录制 fixture 来源

## Claude Code 筛选脱敏录制

`claude_code/{simple_turn,bash_tool_use}.jsonl` 源自 2026-06-30 以 Claude Code 2.1.191
在 `/private/tmp` 录制、随 `68b6cfd` 首次提交的真实 `--output-format stream-json`
输出。本次只保留 typed RuntimeTranslator 门禁所需的 assistant/result 与 Bash tool_use/tool_result
帧，并把 session/message/tool/event ID 和绝对时间替换为固定 fixture 值；用户环境、hook、
插件/skill 清单、思考签名和录制机绝对路径均不再进入当前候选。`bash_tool_use` 仍保留通用
`echo hi` 命令及输出，用于验证 Shell 映射，以及 tool start/result 复用同一
`AdapterItemKey → (ItemId, EntityId)`。

当前筛选片段验证的生命周期顺序是：简单 turn 的 `assistant(text) -> result(success)`，
Bash turn 的 `assistant(tool_use) -> user(tool_result) -> assistant(text) -> result(success)`。
筛选 fixture 未保留任何 `stream_event` partial frame，因此不能作为孤立
`content_block_delta` 可被安全忽略的真实证据。

`claude_code/control_request_can_use_tool.jsonl` 源自 2026-07-15 使用 Claude Code
2.1.207、`--permission-prompt-tool stdio` 取得的真实 `can_use_tool` 请求，并与官方
`@anthropic-ai/claude-agent-sdk` 0.3.210 的 control protocol 类型交叉核对。本轮 live
验证向该请求回写 `control_response/deny` 后，CLI 的 terminal result 包含对应
`permission_denials`，目标命令没有执行。提交片段保留 top-level/request 字段结构；
session/request/tool-use identity、命令、说明、suggestion rule 和 blocked path 均替换为
固定 fixture sentinel。typed translator 测试会证明这些 raw 字段不会进入 durable
`ActionRequest`，只有有界 identity、工具名、ActionKind 和按工具类型选取、脱敏且可判别的
动作 summary 被建模。

`claude_code/lifecycle_frames.jsonl` 源自 2026-07-15 本机 Claude Code 2.1.207 的两次受限真实
`--output-format stream-json` 运行。第一轮禁用工具、禁用会话持久化并启用 hook event，只取到
`hook_started/hook_response/status(requesting)` 后因 0.05 美元预算上限以明确 error result 结束；
第二轮使用 `--safe-mode`、只允许一条无文件副作用的 Bash `sleep/printf`、禁用会话持久化并以
0.20 美元为上限，取得 `task_started/task_notification` 与
`result(success,is_error=false,terminal_reason=completed)`。提交 fixture 只保留 canonical translator
需要忽略的五条非权威生命周期 frame；session/uuid/hook/task/tool identity、hook 名、命令说明、摘要和
output path 均替换为固定 sentinel。`hook_progress/task_progress/task_updated/`
`background_tasks_changed/tool_progress` 当前只有 2.1.207 binary 与
`@anthropic-ai/claude-agent-sdk` 0.3.210 type contract 行为测试，没有真实录制片段，文档和测试不得把
它们写成 live fixture 证据。

原 `plan_mode.jsonl` 不被现有 fixture suite 消费，且原始录制含不适合入库的短期授权码与
用户环境清单，本次已删除。对当前 adapter fixture 的 credential/用户绝对路径扫描为空；
这些筛选片段仍不代表 exec-gate 已接管 Claude Code spawn。

`simple_turn` / `bash_tool_use` 由 crate unit gate
`runtime::conversation::runtime_execution_fixture_tests` 直接送入两家的私有 typed
RuntimeTranslator，再经 production `append_adapter_event` 做 daemon identity 包装并写入真实
Runtime Store。门禁会在关闭前和 reopen 后分别 backfill，逐字节比较 canonical event、modeled
item、command/item/entity identity 与唯一 terminal；测试不再逐事件手工 mint identity，也不扩大
translator 的 production/public API。`control_request_can_use_tool` 由 CC translator/driver unit gate
消费，验证 durable registration ACK 与 decision response；没有 decision 的通用 execution fixture
helper 遇到 Approval 会返回 typed error，禁止静默忽略。

删除只修复当前候选树：祖先提交 `68b6cfd` 仍可通过 Git history 读到原
`plan_mode.jsonl`。本 task 未获得改写已共享历史的授权，也没有该 OAuth flow 的撤销/过期读回证据，
因此不能宣称完整仓库历史已经清除 token/用户环境数据。分发完整 Git 历史前必须另行协调
credential 处置与 history rewrite；不要把当前树 sentinel scan 当作历史扫描。

提交片段 SHA-256：

- `simple_turn.jsonl`：`2c4438598bd25a653987aae034f893da79cf4d8b425d0cb7c56f42e5eb30682b`
- `bash_tool_use.jsonl`：`92d973335697759d2e8e4024988303d73188755be0105520739426ec2300c84a`
- `control_request_can_use_tool.jsonl`：`a63a5b85b37839817d87ad68bf4178c1528b9fdbae9c518eedb3fbec95f075d5`
- `lifecycle_frames.jsonl`：`5e1b95e27d957ff00a9cc6b1d4cd7e3fe10691c69b28a1ae2f7e6a33126844f5`

## Codex `simple_turn.jsonl`

该文件是 2026-07-15 通过本机已登录、由 `PATH` 解析的 `codex app-server` 在操作系统
创建的独立临时目录中执行
`initialize -> thread/start -> turn/start` 获得的真实录制筛选脱敏片段。录制请求使用
`sandbox=read-only`、`approvalPolicy=never`，prompt 固定为
`Reply exactly fixture-ok. Do not use tools or modify files.`。本次输出的目标 turn 只包含
assistant message，未保留 handshake、用户消息、token usage 等与 translator 门禁无关的帧。

提交文件只保留 translator 所需的 6 帧：完整 turn started/completed、
assistant message delta，以及 `agentMessage` 的 item started/completed。thread/turn/item/client/session ID、
路径和绝对时间均替换为固定 fixture 值；非空 `durationMs=3213`、事件结构与 assistant 文本来自
真实输出。
这 6 帧同时验证严格的
`turn/started -> item/started -> item/agentMessage/delta -> item/agentMessage/delta -> item/completed -> turn/completed`
顺序；当前没有真实 fixture 支持无 start 的 delta/completion，或 item 尚未完成时的成功 terminal。
原始 JSONL、脱敏中间文件和临时 cwd 已在读回验证后删除，因此本文件只能称为“真实录制的筛选
脱敏 fixture”，不能称为完整原始抓包，也不能替代 P3.7 私有 FD exec-gate 的 live vendor 门禁。

提交片段 SHA-256：
`78a40e4cce9952818021cf1626f02619eb6a19cdcfd5c62e938d016e86029f05`。
