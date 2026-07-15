# Adapter 录制 fixture 来源

## Claude Code 筛选脱敏录制

`claude_code/{simple_turn,bash_tool_use}.jsonl` 源自 2026-06-30 以 Claude Code 2.1.191
在 `/private/tmp` 录制、随 `68b6cfd` 首次提交的真实 `--output-format stream-json`
输出。本次只保留 translator 门禁所需的 assistant/result 与 Bash tool_use/tool_result
帧，并把 session/message/tool/event ID 和绝对时间替换为固定 fixture 值；用户环境、hook、
插件/skill 清单、思考签名和录制机绝对路径均不再进入当前候选。`bash_tool_use` 仍保留通用
`echo hi` 命令及输出，用于验证 Shell 映射。

原 `plan_mode.jsonl` 不被现有 fixture suite 消费，且原始录制含不适合入库的短期授权码与
用户环境清单，本次已删除。对当前三份 adapter fixture 的 credential/用户绝对路径扫描为空；
这些筛选片段仍不代表 exec-gate 已接管 Claude Code spawn。

删除只修复当前候选树：祖先提交 `68b6cfd` 仍可通过 Git history 读到原
`plan_mode.jsonl`。本 task 未获得改写已共享历史的授权，也没有该 OAuth flow 的撤销/过期读回证据，
因此不能宣称完整仓库历史已经清除 token/用户环境数据。分发完整 Git 历史前必须另行协调
credential 处置与 history rewrite；不要把当前树 sentinel scan 当作历史扫描。

提交片段 SHA-256：

- `simple_turn.jsonl`：`2c4438598bd25a653987aae034f893da79cf4d8b425d0cb7c56f42e5eb30682b`
- `bash_tool_use.jsonl`：`92d973335697759d2e8e4024988303d73188755be0105520739426ec2300c84a`

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
原始 JSONL、脱敏中间文件和临时 cwd 已在读回验证后删除，因此本文件只能称为“真实录制的筛选
脱敏 fixture”，不能称为完整原始抓包，也不能替代 P3.7 私有 FD exec-gate 的 live vendor 门禁。

提交片段 SHA-256：
`78a40e4cce9952818021cf1626f02619eb6a19cdcfd5c62e938d016e86029f05`。
