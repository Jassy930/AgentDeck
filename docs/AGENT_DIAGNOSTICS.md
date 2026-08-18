# AgentDeck Agent Diagnostics

本页给没有历史上下文的 agent 使用。目标是在 5 分钟内判断 AgentDeck 当前是否能记录、诊断和复验问题。

## 快速入口

```bash
# GPUI 桌面壳：只验证 UI/Metal/隐藏窗口/Root 初始化
cargo run -p agentdeck-desktop -- --selfcheck

# backend：独立验证 daemon 与 adapter
cargo build --locked \
  -p agentdeckd --bin agentdeckd \
  -p agentdeck-cli --bin agentdeck
AGENTDECK_DAEMON_BIN="$PWD/target/debug/agentdeckd" \
  ./target/debug/agentdeck \
  --data-dir /tmp/agentdeck-selfcheck selfcheck
cargo run -p agentdeckd -- --diagnostics-report
```

当前 GPUI 桌面端没有连接 daemon，也没有 profile、run record 或 diagnostics report
入口。桌面 selfcheck 成功不能证明 backend 或 vendor CLI 健康。

## 日志位置

- run record: `~/Library/Application Support/AgentDeck/runs/*.jsonl`
- diagnostic log: `~/Library/Application Support/AgentDeck/diagnostic.log`
- dev profile: `~/Library/Application Support/AgentDeck-Dev/`
- 测试覆盖目录: 设置 `AGENTDECK_DATA_DIR=/tmp/agentdeck-diag`

## 关联规则

优先用 `runId` 关联 `diagnostic.log` 与 `runs/*.jsonl`。
同一个 `runId` 内用 `eventSeq` 排序。
没有 `runId` 的诊断只作为进程级问题处理。

## 标准自查流程

1. 跑 `cargo run -p agentdeck-desktop -- --selfcheck`，确认桌面基础是否可启动。
2. 构建当前 checkout 的 daemon 与 CLI，再按上面的 `AGENTDECK_DAEMON_BIN` 绝对路径运行
   selfcheck，独立确认 backend，避免命中旧 sibling 或系统安装。
3. 如果 backend 失败，跑 `cargo run -p agentdeckd -- --diagnostics-report`。
4. 查看 `byLevel` / `byEvent` 和 `tail` 中最近的错误或告警。
5. 按 `tail` 里的事件上下文继续执行只读检查。

backend 的 profile 与 `AGENTDECK_DATA_DIR` 规则保持不变；它们不影响当前 GPUI
桌面壳。

## Failure Codes

| code | 含义 | 下一步 |
| --- | --- | --- |
| `record_write_failed` | run record 写入失败 | 检查 data dir 路径和权限 |
| `diagnostic_write_failed` | diagnostic log 写入失败 | 检查 data dir 路径和权限 |
| `redaction_failed` | 测试 secret 明文落盘 | 停止分享日志，修 redaction |
| `adapter_unhandled_method` | app-server 协议出现未识别事件 | 查看 raw record 和 schema |
| `ipc_malformed_jsonl` | client/daemon IPC 收到坏 JSONL | 查看上一条 IPC line |
| `daemon_spawn_failed` | backend client 无法启动 daemon | 检查 `agentdeckd` 路径 |
| `app_server_handshake_failed` | app-server 握手失败 | 检查 agent 登录、版本和 GUI 启动环境里的 `PATH` / `node` |
| `turn_failed` | turn 执行失败 | 按 runId 查看 run record |
| `approval_wait_stalled` | turn 正在等待用户审批 | 查看当前 runtime 的 `actionRequest`，确认 UI 是否已回写 `actionDecision` |

## Codex app-server stderr

daemon 会持续 drain Codex app-server 子进程 stderr，避免管道回压卡死子进程，
但 K9 token 边界禁止保存或转发这段自由文本。错误最多附带
`stderr ... content withheld` 标记，stderr 正文不会进入 IPC、UI、
`diagnostic.log` 或 run record。排障以结构化 failure code、Codex 版本与可复现
命令为准，不要求用户把可能含凭据的 vendor stderr 交给 AgentDeck。

Claude Code 历史 archive / rename 子进程遵守同一 K9 边界：daemon 将其
stdout / stderr 直接丢弃，非零退出只返回结构化 failure code、exit status 和
`vendor stderr content withheld` 标记。完整历史请求超时或被取消时，daemon
同时终止该命令的独立进程组，禁止 CLI helper 在超时回复后继续产生晚到副作用。

## 真实 Codex / Claude Code 历史刷新

GPUI 桌面端当前没有历史界面。历史能力只通过 CLI/daemon 独立排查：

```bash
agentdeck history list
agentdeck history list --agent codex --limit 20
agentdeck history list --agent claude-code --limit 20
```

排查“全部历史为空”时不要加 `--cwd-filter`，否则结果会被缩小到指定项目。Codex
列表和读取分别调用官方 `thread/list`、`thread/read(includeTurns=true)`，不是扫描
当前 AgentDeck 会话或猜测本地记录格式。

CLI 会为每次历史请求生成唯一 `requestId`；未来桌面接入时必须遵守同一契约。daemon 无论成功还是失败
都在对应的 history admin 终态回复中原样回显。客户端只消费严格匹配当前
`requestId` 的回复，忽略其他请求或已超时请求的迟到回复。wire 字段保持可选仅用于
兼容旧客户端；当前客户端的请求或回复缺少该字段，应按关联链路回归排查。

| code | 含义 | 下一步 |
| --- | --- | --- |
| `codex-not-found` | daemon 在继承的 `PATH` 和常见安装位置中都找不到 `codex` | 运行 `/usr/bin/which codex` 和 `codex --version`；修复 GUI 启动环境的安装或路径后重启 App |
| `codex-spawn-failed` | 已定位 `codex`，但无法启动 `codex app-server`，或子进程标准管道不可用 | 运行 `codex app-server --help`；结合错误中的系统原因检查可执行权限、隔离属性和启动环境 |
| `codex-rpc-timeout` | 单次 `initialize` / `thread/list` / `thread/read` RPC 超过 20 秒 | 分别执行 Codex list/read 定位卡住的方法；核对 Codex 版本，并暂时禁用异常 MCP 配置后复测 |
| `codex-history-timeout` | Codex 历史 list/read 的 30 秒总预算内会为进程清理预留 2 秒；工作阶段超时后 daemon 清理短生命周期 app-server 进程组 | 分别执行 Codex list/read 定位卡住的操作；优先排查 app-server 或 MCP helper 卡住 |
| `codex-history-decode-failed` | 官方 `thread/list` 或 `thread/read` 返回值无法按当前协议结构解码；错误只带固定 withheld 标记，不包含 serde 文本或 vendor 响应值 | 记录 `codex --version`，与 `protocol/CODEX_VERSION.txt` 对照；按官方 schema 刷新流程确认是否发生版本漂移，不要把它当作合法空历史 |
| `history-no-sources` | router 中没有注册任何历史来源 | 运行 `agentdeck selfcheck` 和 `agentdeck agent list`，确认 App 使用的是当前打包 daemon 且 adapter 已注册 |
| `history-source-timeout` | 跨 agent list 中单一来源超过 router 的 30 秒独立 deadline；若另一来源成功，router 会保留其结果并完成 best-effort 回复 | 用带 `--agent` 的 list 命令单独探测慢来源；检查对应 vendor CLI 或 app-server 是否挂起 |
| `history-all-sources-failed` | 已注册的所有来源都失败；错误消息会列出各来源及其底层 failure code | 分别运行两条带 `--agent` 的 list 命令，按各自底层 code 修复；该错误不能按“历史为空”处理 |
| `history-request-timeout` | 包含双来源合并在内的完整历史请求超过 daemon 的总 deadline | 分别运行两条带 `--agent` 的 list 命令定位慢来源；该请求已被 daemon 终止，不会在下一次刷新中产生迟到 reply |

跨 agent list 是 best-effort：每个来源有独立的 30 秒 deadline；只要至少一个来源
成功，router 就合并并返回成功来源的数据，另一来源失败或超时不会阻断结果；成功
来源合法返回空列表时，合并结果也可能为空。
因此“看到一些会话”或“没有收到聚合错误”都不代表两家来源同时健康，必须用上述
两条带 `--agent` 的命令分别确认。只有没有来源或所有来源失败时，才分别返回
`history-no-sources` / `history-all-sources-failed`，不再伪装成成功空列表。

## Raw / Warning 可见性

未知 adapter item 必须在 daemon 侧中立化为 `raw`，并继续进入 run record。
`rawKind` 只保留最长 64 字节的安全方法/类型标识，`rawPayload` 固定为
`[vendor payload withheld]`，不携带 vendor 原始 JSON。GPUI 尚未接入 runtime，
当前通过 CLI、测试和 record 排查。

daemon 写入失败等非致命问题会发出 `warning` 事件。当前选中的 runtime 应显示
自己的 warning；没有选中 runtime 时才回退显示 legacy session warning。

## Claude Code System Events

CC `stream-json` 中 `system.subtype=init` 只用于抓取原生 `session_id`。
`hook_started` / `hook_response` 仍映射为 `VendorPanelEvent::hookFired`；
其他 `system` 诊断事件（例如 `api_retry`、`status`、`thinking_tokens`）
映射为 `VendorPanelEvent::systemStatus`，保留 `subtype`、可读 `message`、
`attempt`、`error`、`errorStatus`、`maxRetries` 和 `retryDelayMs`，不进入
中立 `AgentItem` 主干，也不透传原始 vendor JSON。

## Approval 卡住排查

Codex 的命令执行、文件变更和额外权限审批会先在 daemon adapter 层映射为中立
`actionRequest`。GPUI 当前没有审批 UI；涉及审批的 turn 只允许通过 backend 测试或
CLI harness 验证，不能把桌面壳当成可用审批客户端。

## Claude Code Adapter Failure Codes（v0.2 新增）

| code | 含义 | 下一步 |
| --- | --- | --- |
| `cc-not-installed` | `claude` 二进制不存在 | 运行 `npm install -g @anthropic-ai/claude-code` 安装 Claude Code CLI |
| `cc-version-too-old` | `claude` 版本过老，不支持 `--output-format stream-json` | 运行 `npm update -g @anthropic-ai/claude-code` 升级到最低支持版本 |
| `cc-not-authenticated` | 用户未 `claude auth login` | 运行 `claude auth login` 完成登录 |
| `cc-spawn-failed` | `claude` CLI 进程 spawn 失败（权限或路径问题） | 检查 `PATH` 和 `claude` 可执行权限；确认 GUI 启动环境里 `node` 可找到 |
| `cc-history-not-found` | 指定 session_id 在 `~/.claude/projects/` 下找不到对应 `.jsonl` | 确认 session_id 正确；历史可能已被 `claude rm` 彻底删除 |
| `cc-history-parse-failed` | 读取 CC `.jsonl` 历史文件时解析失败 | 检查 `~/.claude/projects/<encoded_cwd>/<id>.jsonl` 文件格式；可能是 CC 版本升级导致格式变更 |
| `cc-archive-not-supported` | 对普通 CC session 调用 `claude rm`（仅 background-agent 支持） | 普通 session 不支持 archive；历史会保留在原路径，可用 `--resume` 继续 |
| `cc-archive-failed` | `claude rm` 执行失败（非 0 退出） | 按结构化 code 与 exit status 复现 `claude rm`；AgentDeck 不保留 vendor stderr 正文 |
| `cc-rename-failed` | `claude --resume <id> --name <title>` 执行失败 | 确认 session_id 存在且 `claude` 版本支持 `--name` 参数；AgentDeck 不保留 vendor stderr 正文 |
| `cc-vendor-control-requires-new-turn` | CC 的 permission mode 等 vendor 控件变更需通过新 turn 生效，不支持会话内即时切换 | 下次启动新 session 或新 turn 时携带更新后的 `ClaudeCodeSessionOptions` |
| `cc-vendor-control-not-supported` | 收到不支持的 ClaudeCodeVendorControl variant | 检查 client 与 daemon 协议版本是否匹配（v2）；升级 client 到最新版 |

## v0.2 双 adapter 探测

daemon 注册了 Codex 和 ClaudeCode 两个 adapter。`agentdeck selfcheck` 会在响应中
报告已注册的 adapter 列表；GPUI desktop selfcheck 不报告 adapter：

```bash
# CLI 探测（输出 JSON，含 adapters 数组）
agentdeck selfcheck

# 查看可用 adapter 列表
agentdeck agent list

# 查看各 adapter 的 capabilities
agentdeck agent capabilities --agent codex
agentdeck agent capabilities --agent claude-code
```

若 selfcheck 只报告一个 adapter，说明另一个 adapter 的 preflight 探测失败
（对应 `cc-not-installed` / `cc-not-authenticated` 等错误码）。先修复对应
failure，再重跑 selfcheck 验证。

两家 adapter 互不影响：Codex 不可用时 CC 仍可正常工作，反之亦然。
