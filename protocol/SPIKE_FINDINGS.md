# 协议 Spike 发现（Step 0,Eng D7）

首次 framing 实测日期：2026-05-19
schema 最近刷新日期：2026-08-18
codex 版本：codex-cli 0.145.0（已固定在 `CODEX_VERSION.txt`）

## D7 核心问题：wire framing 是什么？

**结论：逐行 JSONL。不是 Content-Length 分帧（非 LSP 风格）。**

实测证据（`codex app-server` 启动后发 initialize，xxd 看原始字节）：
- 每个 JSON-RPC 消息以**单个 `\n`（0x0a）结尾**
- 消息间无分隔符，下一条紧接上一条 `\n` 之后
- **无 `Content-Length:` header，无 `\r\n`**
- wire 上**省略 `"jsonrpc":"2.0"` 字段**（响应是 `{"id":1,"result":{...}}`）

→ daemon 的 CodexAdapter 用按行读 `BufReader` 即可，**无需 LSP 风格
header 解析**。Eng review 前提 7（IPC=stdio JSONL）对 daemon↔Codex
这一段成立。D7 标记的"三 token 最底层风险"已消除，且落在最简单的分支。

fixture：`../spike/initialize-response.jsonl`（initialize 真实响应）。

## 零逆向：官方 schema 可直接生成

`codex app-server generate-json-schema --out DIR` 生成完整官方协议
schema；`generate-ts --out DIR` 可生成 TypeScript binding。**不需要逆向
协议。**根目录文件数会随 Codex 版本变化，不作长期合约。

固化进项目的关键 schema（`protocol/`）：
- `JSONRPCMessage.json` — 消息信封（Request/Notification/Response/Error）
- `ClientRequest.json` — 客户端可发的请求（方法名见 client-methods.txt）
- `ClientNotification.json` — 客户端通知；0.145.0 当前定义 `initialized`。该官方生成
  快照已提交，live session 与 short-lived history path 均实现该 notification。
- `ServerNotification.json` — 服务端通知（item 事件流在这里）
- `ServerRequest.json` — 服务端发起的请求（approval 在这里）
- `codex_app_server_protocol.v2.schemas.json` — v2 完整 schema

`client-methods.txt` 从 `ClientRequest.json` 的
`oneOf[*].properties.method.enum[0]` 确定性派生，不手写。0.145.0 共
89 个方法；派生命令见 `docs/QUALITY.md`。

## 关键方法确认

- `initialize` — 握手（实测：传 clientInfo，返 userAgent/codexHome/platform）
- `initialized` — 收到 initialize response 后必须发送的 client notification，再进入 thread 请求
- `thread/start` — 启动会话
- `turn/start` — 启动一轮
- `turn/interrupt` / `turn/steer` — 打断/引导当前 turn（D9 状态机 cancel 用）
- **`thread/fork`** — 确实存在（D8 fork 能力的协议依据，v0.2）
- `thread/resume` — 恢复会话（对应研究里的 resume 痛点）
- `thread/list` / `thread/read` — 列出本机会话并读取持久化 turns/items
- `thread/shellCommand`、`thread/compact/start`、`thread/rollback` 等

## approval 协议（D8 验证）

ServerRequest 里有具体 approval 类型，**带结构化元数据**（非字符串猜命令）：
- `CommandExecutionRequestApprovalParams`（信息丰富）
- `ExecCommandApprovalParams`、`ApplyPatchApprovalParams`、
  `FileChangeRequestApprovalParams`、`PermissionsRequestApprovalParams`

→ D8 的"危险分类优先用 Codex 请求自带元数据"**成立**：approval 请求
是带类型的结构化对象，daemon 可据此映射中立 `AgentActionRequest` 并
判定危险等级，无需字符串猜命令。

0.145.0 的默认官方生成物已包含对应 response schema：
- `CommandExecutionRequestApprovalResponse`：`{"decision":"accept|decline|cancel|acceptForSession|..."}`
- `FileChangeRequestApprovalResponse`：`{"decision":"accept|decline|cancel|acceptForSession"}`
- `PermissionsRequestApprovalResponse`：`{"permissions": GrantedPermissionProfile, "scope": "turn|session", "strictAutoReview": ...}`

AgentDeck v0.1 只暴露一次性 approve / deny：命令和文件请求映射为
`accept` / `decline`；额外权限 approve 回写请求里的 `permissions`，deny 回写空
权限 profile。持久化策略类 decision 暂不进入 Swift UI。

## 对设计文档前提的影响

- **D7 → 已验证**：framing = 逐行 JSONL，最简单分支。BufReader 按行读。
- **C-protocol 待补 → 已解决**：request/notification 方法名、版本和关键 schema 已锁定。
- **M0 握手实现 → 已落地、待真实验收**：Issue #3 的 live session owner 与
  `ShortLivedAppServer` 都在 initialize response 后、thread request 前发送
  `initialized`，fake executable/duplex 测试守护顺序，官方 `ClientNotification.json`
  同步固定该 wire。desktop 接入前仍须由 #5 的持久真实 Codex E2E 证明握手、多轮和
  close 没有随 vendor 漂移。
- **D8 → 强化**：approval 元数据结构化，中立 action 抽象有可靠数据源。
- **D2 → 实现路径清晰**：daemon 用官方 schema 反序列化 Codex 消息，
  翻译成中立 AgentItem，IPC 传中立 JSON。
