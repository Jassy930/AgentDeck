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
| 撤回审批 | — | interrupt 时若有待决 `can_use_tool`，CC 发 `control_cancel_request{request_id}`；owner 丢弃路由 |

- `persist=true` 的 approve 会把 `permission_suggestions` 原样作为 `updatedPermissions` 回传。
  CC 按 suggestion 的 destination 落盘；实测在项目 `.claude/settings.local.json` 写入
  `permissions.allow`（如 `Bash(touch <path>)`）。
  这是 CC 原生语义，AgentDeck 不额外保存任何东西。
- 审批待决时直接 `SessionClose`：实测 0.4 秒收口，该 turn 记为 canceled，会话 `closed`。
- 用户 `settings.json` 里 allow 的工具（`source: config`）不会触发 `can_use_tool`。

## 生命周期与错误

- `TurnStart` 时如果已有 turn 在跑，返回 `turn-already-running`；`TurnCancel` 指向非活动 turn，返回 `turn-not-active`。
- owner 自己发出 interrupt 之后收到的 `result`，一律映射为 `canceled`。其余非 success 的 `result` 映射为
  `failed`，错误码为 `cc-turn-failed`。
- `SessionClose` 的处理顺序：
  1. 有 turn 在跑就先 interrupt；
  2. 关闭 stdin；
  3. 在 10 秒内继续排空 stdout；
  4. 使用 owner 启动时保存的 PGID 回收进程组；即使 direct child 已被 wait，也清扫其残留工具进程并确认组已消失，无法确认则报 `cc-cleanup-failed`；
  5. 发 exit 信号，由 hub 发出唯一一个 `SessionClosed`。
- 子进程意外退出时：正在跑的 turn 报 `TurnFinished(failed, closing, cc-process-exited)`，错误信息里附 stderr 尾部；
  会话以 `failed` 收口。
- 未知的 inbound control_request 回 `control_response{subtype:error}`，避免 CC 一直挂起等待。

## P2 桌面续聊（2026-10-20 已实施）

- `daemon.rs`：每个 `Client` 一条 `async-channel` 事件通道。读线程把非回复行解析成
  `ServerEvent` 推入通道；每条连接记录经它启动的 sessionId，连接结束时逐会话推送
  `Error{sessionId, code:daemon-disconnected}`，已关闭会话不再通知。旧连接的迟到 EOF 不影响新连接上的会话。
  `send()` 只写不等回复；`AgentCapabilities` 同次读取并缓存 CLI 版本与完整 typed 能力。
- `live.rs`：纯状态机 `LiveSession`。首次发送生成 `SessionStart(resumeThreadId, initialTurn)`，
  之后发 `TurnStart`。按 itemId upsert 流式条目；终止性 `Error` 清掉运行状态，会话没起来或
  daemon 不认识时，下次发送重新 SessionStart。审批按 requestId 保存在 `VecDeque`，依到达顺序逐项处理，
  同 requestId 更新原请求；断线、写失败或本轮结束时清空待决审批。重新打开会话时丢弃已完成的轮次，因为它们已写进 vendor 历史。
- `shell.rs`：每台机器一个事件监听任务，按 machine id 定位，不按 host，避免重新添加同名机器时串线。
  会话页底部有审批条、错误行、输入框和发送/停止按钮，记录区 = 历史块 + live 块。
- `transcript.rs`：`append` 平移 live 块的组下标；`render` 发现 blocks 换了一份时，
  保留已展开的组重算可见行，并跟随到底部。
- N2：`SessionRouter` 按 typed `VendorCapabilities` 构造 `VendorSessionOptions`，确认 advertised 能力支持默认配置；
  CC 保持 default 权限模式，Codex 保持 daemon 固定的 M0 选项（未从桌面验证），缺失支持时不回退放宽权限。
  首轮使用缓存的 agent 能力，`SessionCapabilities` 握手后改以会话能力为准：`StreamingMessages` 启用续聊，
  `Approval` 启用审批；停止要求已收到会话能力且有运行中的 turn，协议没有单独的取消 capability。
  UI 按钮与键盘处理使用同一能力判定。
- 初始实窗验证：在临时目录新建一次性 CC 会话，用临时环境变量开关自动打开会话并发送消息，截图确认
  历史、续聊气泡、流式"变更"条目、审批条和"停止"按钮都已渲染。点击"允许 / 拒绝 / 停止"
  当时未验证；下述 PR #43 修复验证补齐了 fake daemon 下的实际按钮操作。

## P3 权限功能（2026-10-20，协议 v8）

实测（claude 2.1.304）：
- default 启动的会话 `set_permission_mode` 到 bypassPermissions 会被拒（"session was not launched with
  --dangerously-skip-permissions"）。启动带隐藏参数 `--allow-dangerously-skip-permissions` 后可切换；该参数
  不改变启动模式。plan / acceptEdits / auto / dontAsk 都可以直接切换。
- `system.init` 和 `system.status` 带 `permissionMode`。计划批准后推送 `status{permissionMode:<原模式>}`；
  persist 的 `setMode` 建议生效后推送 `status{permissionMode:"acceptEdits"}`。
- `ExitPlanMode` 的 `can_use_tool` 中，`input.plan` 是计划 markdown，另带 `planFilePath`，没有 suggestions。
  deny 加 message 后，CC 会留在 plan 模式按反馈修改计划，并再次请求审批。

实现：
- 协议 v8：`ActionRequest.detail`、`ActionKind::ApprovePlan`、`ActionDecision.message`、CC `canPersist`、
  `ClaudeCodeVendorPanelEvent::PermissionModeChanged`。新字段可缺省，v7 形状仍能解码；Swift 镜像已同步。
- owner 写出 `set_permission_mode` 后立即回复 hub（不等待 CC 回包，以免阻塞后续生命周期命令），并登记 request_id；
  CC 回 success 时发 `PermissionModeChanged`，回 error 时发 `Error(cc-permission-mode-rejected)`。
  translator 跟踪 system 行里的模式，相同模式不重复发。
- hub 把 VendorControl 放进有序 lifecycle 队列：之前紧跟 SessionStart 发出的模式切换会先于会话注册执行，
  报 session-not-found。
- 桌面：模式选择器与命令都通过 `SessionRouter` 路由，启动前用完整 `AgentCapabilities`，
  启动后只用 `SessionCapabilities` 的 feature 与模式列表。开始前改本地选择，开始后发 VendorControl，显示只认事件。
  下拉选择“跳过权限”只展开确认条，必须点击“确认开启”才发命令。审批卡保留 detail 全文并滚动显示；
  审批按 requestId 排队，persist 与拒绝反馈 message 都交给当前请求。
  daemon 协议未知或非 v8 时禁用交互；Client 在实际发送连接上检查 ProtocolVersion，旧 daemon 不会收到 v8 审批字段，历史仍可读取。
  本轮还没有任何输出时显示"等待 agent 响应…"（GUI 环境下用户插件的 hook 可能让 CC 首个输出等上几分钟，实测约 2 分钟）。

验证：离线 owner 测试（切模式成功/被拒）、translator 测试（模式事件去重、计划审批、Edit patch）、
desktop live 测试（开始前本地、开始后事件驱动）；经 daemon 的真实链路：
- 中途切 bypass 后写文件不询问；
- 计划被拒并反馈后修改计划、批准后回到 default；
- 总是允许后切到 acceptEdits。

初始实窗截图确认计划审批卡、跳过权限确认条和模式按钮渲染正常；本轮 fake daemon 点击与长正文滚动验收见下方 PR #44 记录。

## P4 AskUserQuestion（2026-10-20，仍属协议 v8）

实测（claude 2.1.304）：
- 任何权限模式下（包括 bypassPermissions），AskUserQuestion 都会走 `can_use_tool`，并带
  `requires_user_interaction: true`。`input.questions[]` 每题有 `question`、`header`、
  `options[{label, description}]` 和 `multiSelect`。
- 回答方式：allow，`updatedInput` = 原 input 加上 `answers: {问题原文: 选中的 label}`，多选用 `", "` 连接。
  模型收到的 tool_result 是 `"Your questions have been answered: "Q"="A", ..."`。

实现：
- 协议新增中立的 `ActionKind::AnswerQuestions`、`ActionRequest.questions`（`UserQuestion` / `UserQuestionOption`）
  和 `ActionDecision.answers`，都可缺省。
- translator 按字段取值，忽略 CC 选项里多出的字段（如 preview）；问题解析失败时退化为普通审批。
- owner 在 approve 时把 answers 写进 updatedInput；"跳过"即 deny。
- 桌面问题卡与 Claude Code TUI 一致，一题一页：
  - 顶部每题一个 tab（标签用 header，已答的打勾）。多题时最后一页是"提交"汇总，未答的标红，点击跳回该题；
    只有一题时没有 tab 和汇总页。
  - 选项一行一个，带序号和说明，末尾是"其他"。单选选中即进下一页，只有一题时直接提交；多选用"下一题"。
  - 键盘：←→ / Tab 切页、↑↓ 移动、Enter / 空格选中（汇总页为提交）、数字键直选。焦点在"其他"输入框里时按键交给输入框，
    在里面按 Enter 回到卡片并前进。方向键与数字键按选项实际布局滚动，保持选项名称可见；切题回到顶部，选“其他”时输入框滚入视口。
  - "其他"在单选题里替换已选选项，在多选题里与选项并存，填的文字接在选项后面，用 ", " 连接；草稿随会话保留。
  - 有题没答或"其他"留空时，提交被拦下，停到那题并在错误行提示。
  题目区限高并可滚动，提交与跳过按钮固定在题目区外；自由文本草稿随会话中的待决请求保留，切换会话或机器页不会丢失，提交、跳过或请求结束后清除。
  提问与普通审批共用 FIFO 队列，新请求入队不重置当前选择和草稿；处理当前请求后初始化下一条。同一 requestId 的题目变化或断线时清除旧答案。
  实测 CC 接受选项之外的自由文本（答"墨绿色""苹果, 芒果"后，模型如实复述）。
- Swift 镜像与 Rust 协议一致，省略 `multiSelect` 的题目按单选解码。

验证：translator（真实形状、忽略多余字段）、owner（answers 写进 updatedInput）、桌面 live（每题必答、多选按选项顺序拼接）；
经 daemon 的真实链路：模型复述"你喜欢蓝色，想要苹果和橙子"；实窗截图确认问题卡、选中态和提交按钮禁用态。

## 已知边界


- 桌面不发 `SessionClose`，CC 子进程随 daemon（应用退出或连接重置）回收。
- 显式断开机器或装完 daemon 后的 `reset()` 会在 2 秒后 SIGKILL daemon；若此时 CC 正在收尾（宽限 10 秒），
  `claude` 子进程可能成为孤儿。应用正常退出走 stdin EOF，不受影响。
- live 内容更新时总是跟随到底部，用户上翻查看时会被拉回。


- CLI one-shot `agentdeck run` 的 CC 默认权限改为 `acceptEdits`（2026-10-20），文件编辑不再等审批；
  Bash 等其他工具仍会等待决定，交互审批请改用 `session live`，或显式指定 `--permission bypass-permissions`。
- `continue_thread`（旧 CLI 入口）仍然硬编码 `bypassPermissions`。
- CC 历史 cwd 原先从 `~/.claude/projects` 的编码目录名还原，路径含 `-` 时会还原错；已改为读取 JSONL 行内
  记录的 `cwd`，读不到才回退目录名（2026-10-20）。
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
  - `AGENTDECK_E2E=1 cargo test -p agentdeck-cli --test e2e_claude_code`：修复 cwd 后 9/9 通过。

### PR #43 审查修复验证（2026-10-20）

- 离线回归通过：desktop 83 项功能测试与新增的 1 项会话 UI vendor 边界测试、CC session 4 项测试，
  以及完整 `scripts/verify-offline-tests.sh`。覆盖审批队列、断线与写失败状态清理、旧连接 EOF 隔离、
  能力握手路由，以及 direct child 已 wait 后的进程组回收。
- 当前 checkout 构建的 daemon/CLI selfcheck 与 diagnostics report 通过，desktop selfcheck 通过；
  `swift test` 的 XCTest 76 项、Swift Testing 31 项通过。
- `/bin/bash script/build_and_run.sh --verify` 验证真实 bundle 初始化、内置 daemon 和 macOS 15.0 最低版本。
  交互阶段使用独立 bundle 标识和临时 fake daemon：能力读取首次失败后点击重试，确认恢复发送；
  两条待决审批依次点击允许、拒绝；下一轮点击停止，界面恢复发送。
  fake daemon 命令记录确认两个不同 requestId 分别收到 approve/deny，并收到对应 turn 的 `TurnCancel`。
- 本轮未运行真实 vendor E2E，以上实窗按钮结果只证明离线 IPC/UI 路径；Codex 桌面发送、远端续聊仍待实测。
  上述 2 秒 reset 与 10 秒 CC 收尾窗口仍是已知限制。

### PR #44 整合回归（2026-10-20）

- 桌面 87 项离线测试通过，覆盖旧协议拒绝交互但保留只读请求、同连接协议检查、
  会话握手覆盖预查询权限模式、模式拒绝后状态不变、审批队列中 persist 与反馈的请求关联。
- PR #43 的能力重试、多个审批、旧连接 EOF 隔离与进程组清理实现均保留。
- 完整离线门禁、当前 checkout 的 daemon/CLI selfcheck 与 diagnostics report、desktop selfcheck、真实 bundle verify 均通过。
  Swift XCTest 76 项与 Swift Testing 31 项、iPhone 17 / iOS 26.5 fixture 测试 21 项通过。
- 临时 fake daemon 的实窗验证通过：握手后模式列表采用会话能力；重复选择 bypass 仍只展开确认条，
  专用确认按钮才发命令；计划拒绝反馈与后续持久允许分别写入正确 requestId。
  160 行计划可滚到末尾标记，审批 Markdown 使用自动高度，外层保留 240px 滚动视口。
- 本轮未重跑真实 vendor E2E；以上实窗结果只证明离线 IPC/UI 路径，此前真实链路记录不替代本轮验证。


### PR #45 问答整合回归（2026-10-20）

- 完整离线门禁通过，桌面 90 项测试覆盖问题作答、FIFO 排队、草稿保留、同 requestId 改题及断线清理。
  Swift XCTest 77 项与 Swift Testing 31 项、iPhone 17 / iOS 26.5 fixture 测试 21 项通过。
- 当前 checkout 的 daemon/CLI 构建、CLI selfcheck 与 diagnostics report、desktop selfcheck 和真实 bundle verify 均通过。
- 临时 fake daemon 实窗验证四题单选、多选、自由文本与问题区滚动，决定按钮保持可见。
  切换机器页再返回后选择与自由文本草稿仍在；提交命令中的四条 answers 与界面逐项一致，
  多选按选项顺序拼接，随后显示排队的普通审批。下一轮选择已清空，点击跳过发送 deny 且不携答案，后续审批仍可处理。
- 本轮未重跑真实 vendor E2E；上述实窗只验证本地 IPC/UI，不替代远端或真实 vendor 验收。

### PR #46 分页问答回归（2026-10-20）

- 桌面 90 项测试、desktop selfcheck、真实 bundle verify 均通过；Swift XCTest 77 项与 Swift Testing 31 项通过。
- 临时 fake daemon 实窗验证长单选、多选的方向键滚动、“其他”自动聚焦与 Enter 前进、Tab / Shift-Tab 切题、数字键作答和汇总提交；输入框内 Tab 保留正常焦点导航。
  三题实际 IPC 答案精确匹配 `scroll-draft`、`选项 A, 选项 D`、`确认`，随后普通审批正常处理。
  单题无 tab，方向键移动到 D 后名称与说明可见，Enter 直接提交的唯一答案为 `选项 D`。
- 本轮未运行真实 vendor E2E 或 iOS simulator 测试；实窗使用隔离数据目录与 fake daemon，只证明本地 IPC/UI 路径。

## P4 桌面新建会话（2026-10-20）

- 入口：主页每张 agent 卡片右上角的“+”（卡片本身仍是筛选），daemon 协议不支持交互时禁用。
- 复用会话页：`Stage::Session { draft: true }`，记录为空，thread id 是 `draft-<n>` 占位，不发 history read。
  输入栏上方显示工作目录输入框，默认取该机器该 agent 最近一次会话的 cwd，本机无历史时取 `$HOME`，远端无历史时留空必填。
- 首发时 `LiveSession.draft` 带上侧栏条目，`SessionStart.resumeThreadId = None`；会话没起来时下次发送仍按新会话启动。
- `SessionStarted.threadId` 到达后 `adopt_thread` 把 live key 换成真实 id，Shell 同步替换当前会话页、侧栏游标，并把条目插到侧栏顶部。
  刷新该来源时，`replace_source_sessions` 保留历史尚未返回但仍有 `session_id` 的活动侧栏会话，按完整 `SessionKey`（机器、agent、threadId）去重，历史返回的元数据优先。
  会话关闭或断线后不再保留本地补充项；下次刷新若历史仍无此项即移除，其他机器与 agent 的会话不受影响。
- 协议无改动：Codex 与 CC 的 `SessionStarted` 都带 thread id。工作目录不做客户端校验，不存在时由 daemon 启动失败报错并显示在错误行。
- 验证：desktop 93 项测试（含 draft 不带 resume、adopt 换 key、慢历史快照保留活动会话与去重）、desktop selfcheck、真实 bundle verify、Swift XCTest 77 项与 Swift Testing 31 项均通过。
  隔离 fake daemon 的实窗验证覆盖 Codex 与 CC 从空历史新建、工作目录编辑与空值禁用、真实 threadId 入侧栏、重开后同 session 第二轮、启动失败后重试，以及刷新不重复；命令记录确认新建不带 resumeThreadId，重试使用新 sessionId。
  作者已记录本机 CC 新会话的真实回复、侧栏条目与选中态；本轮未运行真实 vendor，fake daemon 验证不能替代真实链路。Codex 与远端新会话仍待真实链路验收。
