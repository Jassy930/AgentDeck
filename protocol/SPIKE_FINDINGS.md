# 协议 Spike 发现（Step 0,Eng D7）

首次实测日期：2026-05-19；schema 最近刷新：2026-07-15
codex 版本：codex-cli 0.144.1（已固定在 `CODEX_VERSION.txt`）

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
schema（35 个 JSON + v1/v2 目录）。`generate-ts --out DIR` 生成
TypeScript binding。**不需要逆向协议。**

2026-07-15 使用本机实际执行的 `codex-cli 0.144.1` 重新生成以下固化
schema，并以一次真实、只含 `initialize` 的 stdio JSONL probe 复核 framing：
响应仍为单行 JSON、带 `id/result` 且不含 `method`，4 秒观察窗内未收到额外
notification。该 probe 只证明当前本机 initialize 形状；可选通知仍以官方 schema
和 `optOutNotificationMethods` 为边界，不能把“本次未观察到”解释为永不发送。

固化进项目的关键 schema（`protocol/`）：
- `JSONRPCMessage.json` — 消息信封（Request/Notification/Response/Error）
- `ClientRequest.json` — 客户端可发的请求（方法名见 client-methods.txt）
- `ServerNotification.json` — 服务端通知（item 事件流在这里）
- `ServerRequest.json` — 服务端发起的请求（approval 在这里）
- `codex_app_server_protocol.v2.schemas.json` — v2 完整 schema

## 关键方法确认（client-methods.txt 完整）

- `initialize` — 握手（实测：传 clientInfo，返 userAgent/codexHome/platform）
- `thread/start` — 启动会话
- `turn/start` — 启动一轮
- `turn/interrupt` / `turn/steer` — 打断/引导当前 turn（D9 状态机 cancel 用）
- **`thread/fork`** — 确实存在（D8 fork 能力的协议依据，v0.2）
- `thread/resume` — 恢复会话（对应研究里的 resume 痛点）
- `thread/shellCommand`、`thread/compact/start`、`thread/rollback` 等

## approval 协议（D8 验证）

ServerRequest 里有具体 approval 类型，**带结构化元数据**（非字符串猜命令）：
- `CommandExecutionRequestApprovalParams`（14933 bytes — 信息丰富）
- `ExecCommandApprovalParams`、`ApplyPatchApprovalParams`、
  `FileChangeRequestApprovalParams`、`PermissionsRequestApprovalParams`

→ D8 的"危险分类优先用 Codex 请求自带元数据"**成立**：approval 请求
是带类型的结构化对象，daemon 可据此映射中立 `AgentActionRequest` 并
判定危险等级，无需字符串猜命令。

`codex app-server generate-json-schema --experimental` 也生成了对应 response
schema：
- `CommandExecutionRequestApprovalResponse`：`{"decision":"accept|decline|cancel|acceptForSession|..."}`
- `FileChangeRequestApprovalResponse`：`{"decision":"accept|decline|cancel|acceptForSession"}`
- `PermissionsRequestApprovalResponse`：`{"permissions": GrantedPermissionProfile, "scope": "turn|session", "strictAutoReview": ...}`

AgentDeck v0.1 只暴露一次性 approve / deny：命令和文件请求映射为
`accept` / `decline`；额外权限 approve 回写请求里的 `permissions`，deny 回写空
权限 profile。持久化策略类 decision 暂不进入 Swift UI。

## 对设计文档前提的影响

- **D7 → 已验证**：framing = 逐行 JSONL，最简单分支。BufReader 按行读。
- **C-protocol 待补 → 已解决**：方法名、版本、schema 全部锁定并固化。
- **D8 → 强化**：approval 元数据结构化，中立 action 抽象有可靠数据源。
- **D2 → 实现路径清晰**：daemon 用官方 schema 反序列化 Codex 消息，
  翻译成中立 AgentItem，IPC 传中立 JSON。
