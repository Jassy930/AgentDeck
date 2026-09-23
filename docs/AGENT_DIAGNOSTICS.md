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

当前 GPUI 桌面端通过 daemon 读取 agent 列表与会话历史，尚无 profile、run record 或
diagnostics report 的 UI 入口。桌面 selfcheck 不连接 daemon，成功不能证明 backend
或 vendor CLI 健康。

## 日志位置

- run record: `~/Library/Application Support/AgentDeck/runs/*.jsonl`
- diagnostic log: `~/Library/Application Support/AgentDeck/diagnostic.log`
- dev profile: `~/Library/Application Support/AgentDeck-Dev/`
- 测试覆盖目录: 设置 `AGENTDECK_DATA_DIR=/tmp/agentdeck-diag`

## 关联规则

优先用 `runId` 关联 `diagnostic.log` 与 `runs/*.jsonl`。
同一个 `runId` 内用 `eventSeq` 排序。
没有 `runId` 的诊断只作为进程级问题处理。

生产会话使用 `runId=sessionId`；Codex 的同一个 run record 包含多轮事件、
`SessionClosed` 和一个 footer。CC 仍使用 one-shot `TurnComplete` 收尾；启动失败或
legacy EOF/cancel 缺少终态时，writer 排空全部事件后补 footer，连接保持期间暂不关闭记录。`diagnosticRef` 为 `runId:eventSeq`，按这两个字段可在 `diagnostic.log`
定位实际条目；report 默认只返回最近 20 条，较早引用需读取日志文件。
`codex_child_spawned` / `codex_turn_started` 的 detail JSON 包含 `childPid`，
`codex_cleanup_completed` 包含 child wait 与进程组清理结果。自由文本 prompt、vendor
frame 和 stderr 不写入生命周期诊断。

记录 open/append/close 失败会发非 terminal `record_write_failed`，CLI 显示告警并继续
等待真实 turn/session terminal；连续 append 失败仅首次告警，终态写入仍失败时再告警。
iOS fixture 消费方同样保留 warning 后的 streaming 和会话状态。诊断写入失败使用
stderr fallback，省略 `diagnosticRef`，不返回无法定位的引用，也不改变会话结果。

## 标准自查流程

1. 跑 `cargo run -p agentdeck-desktop -- --selfcheck`，确认桌面基础是否可启动。
2. 构建当前 checkout 的 daemon 与 CLI，再按上面的 `AGENTDECK_DAEMON_BIN` 绝对路径运行
   selfcheck，独立确认 backend，避免命中旧 sibling 或系统安装。
3. 如果 backend 失败，跑 `cargo run -p agentdeckd -- --diagnostics-report`。
4. 查看 `byLevel` / `byEvent` 和 `tail` 中最近的错误或告警。
5. 按 `tail` 里的事件上下文继续执行只读检查。

桌面启动的 daemon 继承 `AGENTDECK_PROFILE` 与 `AGENTDECK_DATA_DIR`，遵循相同的
backend 数据目录规则；这些变量不改变 vendor 历史来源。

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
| `daemon-shutdown-failed` | CLI 已收到成功 terminal，但 daemon 随后非零退出、超时或未能确认回收 | 将本次命令视为失败；检查 daemon exit status、cleanup failure 与残留进程，不要只采信先到的 turn terminal |
| `approval_wait_stalled` | turn 正在等待用户审批 | 查看当前 runtime 的 `actionRequest`，确认 UI 是否已回写 `actionDecision` |

## Codex app-server stderr

daemon 会持续 drain Codex app-server 子进程 stderr，避免管道回压卡死子进程，
但 K9 token 边界禁止保存或转发这段自由文本。错误最多附带
`stderr ... content withheld` 标记，stderr 正文不会进入 IPC、UI、
`diagnostic.log` 或 run record。排障以结构化 failure code、Codex 版本与可复现
命令为准，不要求用户把可能含凭据的 vendor stderr 交给 AgentDeck。

### Codex live session failure codes

| code | 含义 | 下一步 |
| --- | --- | --- |
| `codex-handshake-timeout` | `initialize` 或 `thread/start|resume` 未在握手 deadline 内完成 | 核对固定 Codex 版本与登录状态；暂时禁用异常 MCP 配置后复测 |
| `codex-rpc-timeout` | live session 的 turn/interrupt RPC 未在 deadline 内返回 | 按当前 session/turn 定位卡住的方法；连接会进入不可恢复关闭，不要重放 prompt |
| `codex-interrupt-timeout` | `turn/interrupt` 后未在 grace period 内收到权威 terminal | 等待 failed `SessionClosed` 与 daemon 退出；从保留的 threadId 显式恢复，不要自动重放 |
| `codex-close-timeout` | close 已开始，但 active turn 未在 close deadline 内收口 | 等待 daemon 执行强制 cleanup；若随后是 failed close，按 cleanup failure 排查 |
| `codex-disconnected` / `codex-stdout-read-failed` / `codex-stdin-write-failed` | app-server transport 在 terminal 前断开或读写失败 | 将当前 session 视为不可继续；核对 Codex 版本、进程退出原因与对应 diagnosticRef |
| `codex-malformed-json` / `codex-unmatched-response` / `codex-protocol-error` | vendor frame 无法按固定 schema 解码、response 无对应 request，或 JSON-RPC error | 与 `protocol/` 中 0.155.0-alpha.16 官方 schema 对照；不要把该 session 恢复为 Ready |
| `codex-unsupported-server-request` / `codex-terminal-status-invalid` | app-server 发出 M0 不支持的 server request，或 terminal status 仍是 `inProgress` | 记录可复现方法与固定版本；该 turn/session 会按 protocol failure 收口 |
| `codex-cleanup-failed` | 无法确认 direct child 已 wait、Unix 进程组已消失或 stderr pump 已停止 | 不再向该 daemon 发新 session；等待 failed `SessionClosed` 后 daemon 退出，检查残留 app-server/helper 进程 |
| `turn-id-already-used` | client 在同一 session 内复用了已接受的 caller-owned `turnId` | 生成新的 `turnId` 后重试；该拒绝不会写入 vendor 或改变 Ready session |

`initialize` 成功仍可能在 `thread/start` 因用户配置类型不兼容而返回 `codex-protocol-error`；2026-09-21 的 0.145.0 验收曾遇到 `features.context_management` 的 table/bool 冲突，仅用进程级 `-c features.context_management=false` 覆盖完成真实验收，未修改全局配置。当前 0.155.0-alpha.16 尚未重跑 lifecycle E2E，详见 [当前验收边界](AGENTDECKD_STATUS.md#当前验收边界)。

Claude Code 历史 archive / rename 子进程遵守同一 K9 边界：daemon 将其
stdout / stderr 直接丢弃，非零退出只返回结构化 failure code、exit status 和
`vendor stderr content withheld` 标记。完整历史请求超时或被取消时，daemon
同时终止该命令的独立进程组，禁止 CLI helper 在超时回复后继续产生晚到副作用。

## 真实 Codex / Claude Code 历史刷新

GPUI 桌面端已接入只读历史；来源加载失败会在侧栏显示错误。可通过 CLI/daemon
独立排查对应来源：

```bash
agentdeck history list
agentdeck history list --agent codex --limit 20
agentdeck history list --agent claude-code --limit 20
```

排查“全部历史为空”时不要加 `--cwd-filter`，否则结果会被缩小到指定项目。Codex
列表调用官方 `thread/list(modelProviders=[])`，避免按当前 provider 过滤掉其他来源的
历史。正文先调用 `thread/read(includeTurns=false)` 核对会话，再用
`thread/turns/list(itemsView=full, sortDirection=asc)` 跟随游标读取全部轮次；不扫描
当前 AgentDeck 会话或猜测本地记录格式。任意页面失败会使整次读取失败，不返回残缺正文。
当前固定版本的分页接口属于稳定 API，不需要 `experimentalApi`。

若列表正常而读取返回 `codex-protocol-error`，需区分分页接口与 vendor 数据兼容性：
调查中旧 0.145.0 曾拒绝解析部分新版客户端保存的子代理 `completed` 记录（上游
`-32603`）。当前已将协议与版本升级至 0.155.0-alpha.16；仍须核对实际运行版本和
逐页读回结果，不能改用摘要或空列表掩盖失败。桌面 selfcheck 和 fake bundle 验证
均不能证明真实正文可读。

daemon 会依次异步探测 PATH 与常见安装位置，只跳过成功读出但不匹配的版本，选择完整版本精确
匹配 `protocol/CODEX_VERSION.txt` 的首个 executable。macOS 候选包含
`/Applications/ChatGPT.app/Contents/Resources/codex`，因此 shell 中的 `codex --version`
可能仍显示 Homebrew 的 0.145.0，不能据此认定 daemon 选错版本。probe 与 spawn 使用
同一规范化绝对路径。执行失败、非法输出、超时或清理失败立即返回，不再尝试其他候选。
所有候选共享 5 秒探测预算，历史请求的候选查找与 RPC 共享 28 秒工作预算，另预留
2 秒清理。App 更新后若不再提供固定版本，需要安装匹配版本或同步升级协议。

CLI 与桌面 client 都为每次历史请求生成唯一 `requestId`。daemon 无论成功还是失败
都在对应的 history admin 终态回复中原样回显。客户端只消费严格匹配当前
`requestId` 的回复，忽略其他请求或已超时请求的迟到回复。wire 字段保持可选仅用于
兼容旧客户端；当前客户端的请求或回复缺少该字段，应按关联链路回归排查。

| code | 含义 | 下一步 |
| --- | --- | --- |
| `codex-version-unsupported` | daemon 探测候选后没有找到完整版本精确匹配 `protocol/CODEX_VERSION.txt` 的 executable | 核对 PATH 和常见安装位置中各 executable 的 `--version`，包括 macOS App 自带路径；修复安装/路径，或安装固定版本后重启 App |
| `codex-version-probe-failed` | 已存在的候选无法执行、`--version` 非零退出或输出不是合法版本 | 检查该 executable 或 launcher 的权限、退出码及版本输出；修复此候选后重试，不会回退到其他系统安装 |
| `codex-version-timeout` | 所有候选共享的 5 秒探测预算耗尽；探测会终止并回收独立进程组，清理预算另为 2 秒 | 检查所定位 executable 或 launcher 是否挂起；不能将它视为版本不匹配或合法空历史 |
| `codex-spawn-failed` | 已定位 `codex`，但无法启动 `codex app-server`，或子进程标准管道不可用 | 使用实际匹配版本的 executable 运行 `app-server --help`；结合错误中的系统原因检查可执行权限、隔离属性和启动环境 |
| `codex-rpc-timeout` | 单次 `initialize` / `thread/list` / `thread/read` / `thread/turns/list` RPC 超过 20 秒 | 分别执行 Codex list/read 定位卡住的方法；核对 Codex 版本，并暂时禁用异常 MCP 配置后复测 |
| `codex-history-timeout` | Codex 历史 list/read 的候选查找与 RPC 共用 28 秒工作预算，另预留 2 秒清理；工作阶段超时后 daemon 清理短生命周期 app-server 进程组 | 分别执行 Codex list/read 定位卡住的操作；优先排查 app-server 或 MCP helper 卡住 |
| `codex-history-decode-failed` | 官方 history 返回值无法按当前协议结构解码；错误只带固定 withheld 标记，不包含 serde 文本或 vendor 响应值 | 记录实际使用的 executable 路径及 `--version`，与 `protocol/CODEX_VERSION.txt` 对照；按官方 schema 刷新流程确认是否发生版本漂移，不要把它当作合法空历史 |
| `codex-history-pagination-stalled` | 列表或正文分页返回了未推进的游标 | 本次读取失败；核对固定版本的分页接口，不能把已读页面当完整结果 |
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
| `cc-vendor-control-not-supported` | 收到不支持的 ClaudeCodeVendorControl variant | 检查 client 与 daemon 协议版本是否匹配（v4）；升级 client 到最新版 |

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
