# AgentDeck 手机端前置设计：自托管 Relay 与远程 daemon

| 字段 | 值 |
|---|---|
| 状态 | Design - 方向已确认 |
| 日期 | 2026-07-01 |
| 主题 | 参考 Happier 的跨设备 agent 工作流，为 AgentDeck 手机端先补最小服务端能力 |
| 关联 | `NORTH_STAR.md`、`ARCHITECTURE.md`、`docs/plans/2026-06-30-unified-shell-v02-design.md` |

## 1. 背景

AgentDeck 的北极星已经把 iOS 写成未来原生端形态：macOS 用 AppKit，iOS 用 UIKit，共享层是 Rust `agentdeckd` 与中立 `agentdeck-protocol`。但当前 v0.2 只在 macOS AppKit 上验证统一壳；如果直接开始做 iOS 客户端，手机只能在同一机器或同一网络里连本地 daemon，无法解决真实移动场景里的离线、跨网络、通知、配对和多设备状态同步。

Happier 的公开资料提供了一个有参考价值的模式：

- Happier 是跨设备、端到端加密的 AI coding agent companion，目标是让本机 coding session 可以从手机、Web 或桌面继续控制。
- Happier 支持自托管 Relay，强调 Relay 无法读取端到端加密内容。
- Happier 的 onboarding 文档把 Relay、daemon、手机/桌面 app 分成可组合部署形态，并支持 self-host Relay only 与 devbox 形态。

AgentDeck 不应照搬 Happier 的完整产品面。AgentDeck 的核心仍是 Codex 与 Claude Code 的统一原生工作台；手机端第一阶段应围绕“远程观察、审批、继续会话”服务主线。

参考资料：

- https://github.com/happier-dev/happier
- https://happier.dev/
- https://happy.engineering/docs/how-it-works/
- https://happy.engineering/docs/guides/self-hosting/
- https://docs.happier.dev/getting-started/onboarding

## 2. 结论

AgentDeck 需要先构建服务端能力，但第一阶段应是 **自托管优先的薄 Relay**，不是完整 SaaS 云平台。

服务端不运行 Codex 或 Claude Code，不保存 vendor token，不直接读取用户项目文件。它只负责设备配对、机器在线状态、加密事件转发、实时连接、离线队列和通知触发。真正的 agent 生命周期、文件系统访问、权限决策和 vendor 认证仍由用户机器上的 `agentdeckd` 负责。

## 3. 目标

- 手机离开 Mac 所在网络后，仍能看到机器和活跃会话。
- 手机能接收 session stream、任务完成、失败和等待 approval 通知。
- 手机能执行低风险控制：approve / deny、继续当前 thread、发送下一条 prompt、刷新历史。
- Relay 默认可自托管，未来可演进到团队托管或公开托管，但不把多租户 SaaS 作为第一阶段目标。
- 继续遵守 AgentDeck 现有边界：`agentdeck-protocol` 是契约事实源；Codex / Claude Code token 不进入 AgentDeck 服务端；vendor 语义不被强行统一。

## 4. 非目标

- 不做服务端执行 agent。
- 不做服务端托管 Codex / Claude Code 凭证。
- 不做完整 iOS 端编辑器、文件浏览器、Git 面板或 IDE 功能。
- 不做多人实时协作、公共分享链接或组织权限系统。
- 不把 Relay 作为用户项目数据仓库。
- 不在第一阶段承诺 Hosted SaaS、计费、团队管理、审计合规后台。

## 5. 推荐架构

```text
┌──────────────────────────────┐
│ AgentDeck Mobile (iOS UIKit) │
│ - 会话列表 / 流式查看          │
│ - approve / deny              │
│ - prompt queue                │
└───────────────┬──────────────┘
                │ WebSocket / HTTPS
                │ E2EE envelope
                ▼
┌──────────────────────────────┐
│ AgentDeck Relay (self-host)  │
│ - device pairing             │
│ - machine registry           │
│ - encrypted event relay      │
│ - offline queue / push hook   │
│ - minimal metadata            │
└───────────────┬──────────────┘
                │ outbound connection
                │ E2EE envelope
                ▼
┌──────────────────────────────┐
│ agentdeckd Remote Mode       │
│ - CodexAdapter               │
│ - ClaudeCodeAdapter          │
│ - history / approval / runs  │
│ - local filesystem access    │
└───────────────┬──────────────┘
                │ local process stdio
                ▼
        codex app-server / claude CLI
```

### 5.1 AgentDeck Relay

Relay 是新的服务端能力，第一版建议作为 Rust crate / binary 进入 workspace，例如 `agentdeck-relay`。理由是它可以复用 `agentdeck-protocol`、Tokio、serde、schemars 与现有 Rust 测试栈。若后续需要 Web 管理面，再用 Bun/TypeScript 做独立前端。

Relay 第一版职责：

- 设备配对：签发 device credential，支持撤销。
- 机器注册：维护 `machine_id`、在线状态、最后心跳、协议版本。
- 实时通道：手机端与 daemon 端通过 WebSocket 连接 Relay。
- RPC 转发：把移动端控制请求转成 daemon 可处理的 remote command。
- 事件转发：把 daemon 的 `ServerEvent` / session delta 转发给已授权设备。
- 离线队列：短期保存加密 envelope，支持移动端重连后补拉。
- 通知触发：第一阶段只定义 hook；APNs 可后置。
- 诊断：输出机器可读 structured error 和 relay trace id。

Relay 第一版不解析 session 内容。它可以看到必要元数据，例如 account/profile、device、machine、session id、sequence、事件类型、时间戳和大小，但不读取 prompt、shell output、diff 或 approval detail 明文。

### 5.2 agentdeckd Remote Mode

`agentdeckd` 增加 remote mode，主动连 Relay。它仍然是唯一接触本机文件系统、vendor CLI 和 vendor login 状态的进程。

Remote mode 职责：

- 用本机 device/machine credential 连接 Relay。
- 上报 machine online/offline、daemon version、protocol version、capabilities。
- 把本地 `ServerEvent` 包进加密 remote envelope 后发送给 Relay。
- 接收移动端控制请求，解密后转换为本地 `ClientCommand`。
- 按现有 session lock / approval / history 规则执行，不为移动端开旁路。
- 对 destructive 或状态改变动作保留 confirmation gate。

### 5.3 iOS Mobile Companion

第一版手机端是 companion，不是完整桌面替代品。

必须能力：

- 机器列表：在线、离线、最近连接时间。
- 会话列表：活跃、等待审批、最近历史。
- 会话详情：用户消息、assistant stream、reasoning、shell、diff 摘要、错误状态。
- 审批卡片：approve / deny，并显示 vendor 原词和当前风险上下文。
- Prompt 输入：只发到已选中的 thread/runtime；排队规则沿用 daemon。
- 通知入口：等待审批、turn 完成、失败。
- 配对与注销：扫码配对，手机端可登出，桌面端可撤销。

## 6. 协议与数据模型

Relay 不应替代 `agentdeck-protocol`。推荐新增一层 remote envelope：

```text
RemoteEnvelope {
  relay_protocol_version,
  agentdeck_protocol_version,
  account_or_profile_id,
  device_id,
  machine_id,
  session_id?,
  stream_seq,
  kind,
  created_at,
  ciphertext,
  signature
}
```

`ciphertext` 内部才是 `agentdeck-protocol` 的 `ClientCommand` / `ServerEvent` / history response。Relay 只按外层元数据路由、排序和补发。

第一版需要的对象：

- `Device`：手机、桌面、daemon endpoint。
- `Machine`：一台运行 `agentdeckd` 的主机。
- `Connection`：某 device 或 machine 的当前 websocket 连接。
- `Subscription`：设备订阅哪些 machine/session 的事件。
- `EncryptedEvent`：短期离线补发队列。
- `Revocation`：被撤销的 device credential。

## 7. 安全边界

- Relay 不读取、不保存、不转发 Codex / Claude Code token。
- Relay 默认不保存明文 session 内容。
- 端到端密钥由用户设备生成和配对；服务端只保存不可逆标识和公钥材料。
- 所有 mobile control request 必须经 daemon 再执行，不能在 Relay 直接变成本机动作。
- approve / deny 之外的高风险动作需要显式 confirmation gate，例如 adopt/create、终止 session、修改持久权限。
- Device credential 可撤销；daemon 下次心跳必须同步撤销列表。
- Relay 日志禁止输出 prompt、shell output、diff、路径片段和 token-like 字符串。

## 8. 错误处理与可观测性

建议新增 failure code 命名空间：

- `relay.auth.invalid_device`
- `relay.auth.revoked_device`
- `relay.machine.offline`
- `relay.machine.version_mismatch`
- `relay.queue.expired`
- `relay.envelope.bad_signature`
- `relay.envelope.decrypt_failed`
- `remote.daemon.not_connected`
- `remote.daemon.busy`
- `remote.session.not_found`
- `remote.approval.expired`

诊断要求：

- 每条 remote request 都有 `trace_id`，Relay、daemon、mobile 三端能关联。
- Relay 只记录外层 envelope 元数据和错误码。
- daemon 诊断继续写入 `~/Library/Application Support/AgentDeck/` 或 dev profile 数据目录。
- mobile 端保存最近错误和连接状态，便于用户复制诊断报告。

## 9. 分阶段路线

### R0：契约 spike

目标是证明 remote envelope 与现有 `agentdeck-protocol` 能组合。

交付：

- remote envelope 类型草案。
- 本地 fake relay 集成测试。
- CLI 级 smoke：daemon 连接 fake relay，另一个 client 订阅事件。

### R1：Relay MVP

目标是自托管 Relay 能跑通机器注册、设备配对和加密事件转发。

交付：

- `agentdeck-relay` binary。
- SQLite 存储或内存存储加文件快照；公开托管前不引入复杂数据库。
- WebSocket endpoints：machine connect、device connect、subscribe、send command、ack。
- structured error 与基础诊断。

### R2：agentdeckd Remote Mode

目标是本机 daemon 能作为 machine endpoint 接入 Relay。

交付：

- `agentdeckd --remote --relay-url ...` 或 profile 配置。
- outbound reconnect、heartbeat、capabilities 上报。
- session stream 与 approval request 转发。
- mobile command 进入现有 session lock / approval 流程。

### R3：Mobile Companion MVP

目标是 iOS UIKit 端完成伴侣功能。

交付：

- 扫码配对。
- 机器 / 会话列表。
- 会话流式查看。
- approve / deny。
- 继续当前 thread 的 prompt 输入。
- 等待审批和完成通知入口。

### R4：Hosted / team mode 评估

只有 R1-R3 的自托管链路稳定后，再设计公开托管、多租户、团队权限、审计、计费和 SLA。

## 10. 测试与验收标准

Relay / daemon 第一阶段验收：

- 启动 self-host Relay 后，`agentdeckd` 能注册为 online machine。
- 第二个 client 能通过 Relay 看到 machine online 和 capabilities。
- 本地 session 的 streaming `ServerEvent` 能通过 Relay 到达订阅 client。
- 移动端等价 client 能发送 approve / deny，daemon 按现有 approval 流程执行。
- daemon 断线重连后，client 能补拉未 ack 的加密事件。
- Relay 日志中不存在 prompt、shell output、diff 明文或 token-like 字符串。
- 撤销 device credential 后，该设备无法继续订阅或发送 command。
- `scripts/verify-agent-docs.sh` 通过；涉及协议变更时 `cargo test` 与 schema 漂移测试通过。

手机端第一阶段验收：

- 真机经公网或跨网络访问 self-host Relay，不依赖和 Mac 在同一局域网。
- 能看到至少一个活跃 Codex 或 Claude Code session。
- 能完成一次真实 approval。
- 能发送一条继续 prompt 并收到后续流式输出。
- 后台切出再回来后连接状态和未读事件正确恢复。

## 11. 开放问题

- 第一版是否需要 APNs，还是先用 app 内在线通知完成闭环。
- self-host Relay 的默认存储用 SQLite 还是 Postgres。推荐先 SQLite，公开托管前再引入 Postgres。
- 端到端加密采用现成 Noise / age / libsodium 方案中的哪一个。设计时必须优先选择成熟库，不手写密码学。
- 是否需要让 macOS AppKit 客户端也通过 Relay 接远端 machine。推荐后置；第一版 AppKit 仍优先本地 daemon。
- 是否需要把 `agentdeck-cli` 扩成 remote 调试客户端。推荐需要，因为它能在 iOS 之前验证 Relay 链路。

## 12. 当前决策

- 第一阶段按自托管优先设计，不直接做公开 SaaS。
- 先做服务端能力，再做正式 iOS UIKit 客户端。
- 服务端能力只做薄 Relay，agent 生命周期仍归 `agentdeckd`。
- Relay 不接触 vendor token，不解析明文 session 内容。
- 手机端第一版定位为 companion：观察、审批、继续会话和通知。
