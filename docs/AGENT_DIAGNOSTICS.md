# AgentDeck Agent Diagnostics

本页给没有历史上下文的 agent 使用。目标是在 5 分钟内判断 AgentDeck 当前是否能记录、诊断和复验问题。

## 快速入口

```bash
swift run AgentDeck -- --selfcheck
swift run AgentDeck -- --diagnostics-report --json
swift run AgentDeck -- --selfcheck --profile dev
swift run AgentDeck -- --diagnostics-report --json --profile dev
```

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

1. 跑 `swift run AgentDeck -- --selfcheck`。
2. 如果失败，先看 stderr 的 failure code。
3. 跑 `swift run AgentDeck -- --diagnostics-report --json`。
4. 查看 `byLevel` / `byEvent` 和 `tail` 中最近的错误或告警。
5. 按 `tail` 里的事件上下文继续执行只读检查。

排查开发调试实例时，在 selfcheck 和 diagnostics report 后加 `--profile dev`。
SwiftPM/debug 构建未显式传 `--profile` 时也会默认使用 dev profile。
`AGENTDECK_DATA_DIR` 仍优先于 profile，主要用于一次性测试覆盖目录。

## Relay v1 开发状态 reset

Relay v1 状态与后续 Companion MVP 版本不兼容时，没有开发恢复或自动迁移路径。
先停止 Relay，确认 DB 与 bearer credential 的 canonical absolute 路径，再执行：

```bash
bash scripts/reset-relay-v1-dev-state.sh \
  --storage /absolute/path/to/relay.db \
  --credentials /absolute/path/to/relay/dev.credentials.json \
  --confirm DELETE-RELAY-V1-DEV-STATE
```

脚本拒绝相对路径、目录、symlink、非 v1 schema/credential shape、非 canonical
Base64 或解码长度不是 32 bytes 的 credential，以及 `account_id` / `device_id` /
`role` / credential hash 与 DB 行不一致的输入；unlink preflight 还会检查父目录
权限与 macOS immutable/system flags。任一 validation/preflight 拒绝都发生在首次
unlink 前，因此应保留全部四个目标。若报告文件在校验期间变化，说明 Relay 可能
仍在运行：停止它后重新检查路径，不要手工 `rm` 绕过。preflight 之后 OS unlink
仍因 race/I/O 失败时可能部分删除：脚本非零退出、逐个列出仍存在的 exact path、
不打印成功、不承诺 rollback；按列出的路径人工清理后重新配对。
成功只删除 DB、精确 `-wal` / `-shm` 与指定 credential；同前缀和其他文件保留，
之后必须重新配对。

## Relay v2 Store 诊断（Companion MVP P2.1）

P2.1 只建立与 v1 并列的 v2 Store library；生产 Relay binary 要到 P2.9 才原子
切换，当前不能把 Store 测试通过解释为公网 v2 listener 已上线。v2 Store 由一个
blocking worker 独占 SQLite connection，async 调用通过有界队列串行进入；启动
成功必须同时读回 `journal_mode=WAL`、`synchronous=FULL`、`foreign_keys=ON` 与
`busy_timeout=5000`。

生产存储路径必须是 lexical-canonical absolute regular-file path，拒绝 `.` / `..`
alias、文件或任一父级
symlink；新建目录和 DB 权限分别为 0700/0600，已有路径权限更宽时 fail-closed。
schema marker 同时绑定 family、version、精确 DDL SHA-256 signature 与
relay server ID。高版本、精确 v1 legacy、未知或损坏 schema 都在写入前拒绝，
检查路径不会改写 DB/WAL/SHM。没有原地恢复或自动降级：停止对应 Relay，保留
原文件用于取证；开发状态按受控 reset 后重新配对，不能手改 `user_version`、
marker 或 DDL 冒充兼容。

Store 默认 retention 为每 stream 2,000 frames / 64 MiB / 24 小时、每 machine
512 MiB、全局 4 GiB；replay 每页最多 64 frames / 8 MiB。磁盘安全余量取
512 MiB 与总容量 5% 的较大值。`relay.disk.low` 只拒绝新的 Publish，replay、
revoke 与 purge 等读/控制路径仍可用；配额淘汰优先于 ACK，随后重放旧 cursor
会明确返回 `relay.replay.gap`，不得静默跳过。

Store 启动和显式 full maintenance 用 keyset 逐项收敛全部配额；每次 replay 只对
目标 stream 做有过期行才写入的 age maintenance，避免单页重放扫描全库，同时确保
超过 age cap 的 ciphertext 不会等到下一次 Publish 才失效。P2.6 的 lifecycle
sweeper 只负责周期触发 full maintenance。full maintenance 同时删除严格早于当前
时间的 enrollment code，exact
expiry 仍允许相同请求取回冻结 response，超过 1 ms 后不提供恢复。code 表最多
4,096 行，可按部署下调但不能调高。hot-WAL schema 快照若需要物理复制，必须先按
预计复制 bytes 加磁盘 reserve 做 fail-closed preflight。每个 snapshot 在复制前
fsync 与 source path hash 绑定的 marker 并持有排他锁；重启只逐文件清理同 owner、
0700/0600、marker 精确匹配、无额外 child 且锁已释放的 artifact，绝不按前缀递归删。

P2.1 的 v2 配置面是独立 `RelayV2StoreSettings`，没有复用或改变 v1
`RelayConfig`。它显式承载 storage path、stream count/bytes/age、machine/global
bytes、replay page count/bytes 与磁盘 reserve bytes/percent；转换为
`RelayV2StoreConfig` 时还带入 enrollment code count，并先拒绝相对路径和
无效/越界配额。CLI、env 与 config file
优先级要到 P2.6 接入，当前不要把 v1 `--storage` 当成已启用的 v2 配置入口。

| v2 Store diagnostic code | 含义 | 下一步 |
| --- | --- | --- |
| `relay.store.path_invalid` | 路径非规范绝对路径、含 symlink、owner 不符、不是 regular file 或权限过宽 | 停止 Relay，核对 exact path、owner、父目录和 0700/0600 权限 |
| `relay.store.schema_too_new` | DB schema 高于当前 binary | 使用匹配版本；禁止降级打开或改 marker |
| `relay.store.legacy_reset_required` | exact v1 DB 被交给 v2 Store | 使用上节受控 v1 reset，随后重新配对 |
| `relay.store.schema_corrupt` | marker、DDL、字段类型或 signature 不匹配 | 保留文件取证；受控重建 Store 并重新配对 |
| `relay.store.pragma_mismatch` | WAL/FULL/FK/5s 任一启动读回不一致 | 检查 SQLite build、文件系统和进程占用，不能带病启动 |
| `relay.store.unavailable` | SQLite/I/O/worker 不可用 | 检查磁盘、权限和同路径进程；不要把 frame 视为已持久化 |
| `relay.store.busy` | bounded Store command queue 已满 | 对当前连接施加背压或返回可重试失败；请求未被 Store 接管，禁止当作已提交 |
| `relay.store.invalid_value` | 持久值或 retention 配置超出约束 | 修正配置/调用方；禁止截断或整数 wrap |
| `relay.store.not_found` | machine、grant 或 stream 不存在 | 重新同步授权/stream；不要隐式创建跨 route 绑定 |
| `relay.store.enrollment_not_found` | enrollment code hash 不存在 | 核对 bundle 是否来自当前 Relay；重新创建短期 enrollment bundle |
| `relay.store.enrollment_expired` | enrollment code 已超过 absolute expiry | 重新创建 bundle；禁止延长或复活旧 code |
| `relay.store.conflict` / `relay.store.stale` | 幂等 bytes 冲突或单调值回退 | 终止该请求并检查 generation、serial 与 canonical bytes |
| `relay.stream.out_of_order` | stream sequence 不是期望的下一值 | 以当前 generation/HWM 重连；到 `u64::MAX` 前创建新 generation |
| `relay.auth.revoked` | grant 已撤销 | 终止设备链路并走重新配对 |
| `relay.quota.exceeded` / `relay.disk.low` | 单帧/stream/machine/global 或磁盘安全门禁拒绝 Publish | 先释放容量或调整经批准的配额，再重试同一 canonical frame |
| `relay.frame.too_large` | canonical outer frame 超过 4 MiB | 按 transfer part 规则拆分，不能截断 |
| `relay.replay.gap` / `relay.replay.cursor_invalid` | cursor 已被淘汰或 continuation 不属于本次 replay | 暂停 live，执行 bounded backfill/snapshot 后重新订阅 |

## Relay v2 鉴权诊断（Companion MVP P2.2）

P2.2 只建立 challenge/auth/access library，生产 listener 仍未切到 v2。每次普通
machine/device 连接都必须取得 Relay 新生成的 32-byte challenge；challenge 仅内存保存、
30 秒起过期、单次消费、全局最多 4,096。source/route token bucket 或任一内存 hard
bound 拒绝不会访问 SQLite，也不会产生半个授权状态；bucket idle TTL 只允许配置在
30 秒到 5 分钟之间，不能用超大值关闭回收。

MachineLink 必须同时通过 MachineRoot-signed Link cert、absolute cert expiry、持久化
trust epoch/link generation gate 和 MachineLinkSign challenge signature。DeviceLink 必须
同时通过 MachineRoot-signed RelayGrant、当前持久化 serial/hash/pubkey/fingerprint、
tombstone 与 DeviceSign challenge signature。验签通过后仍需 Store CAS/confirm 成功，才会
原子替换 active connection。`AuthorizationCoordinator` 在 Store mutation 前把 route 标为
`Transitioning`，这时所有数据面 `is_current` 检查都必须失败；Store 失败只恢复仍在线的旧
entry，COMMIT 成功后在同一 actor poll 中提交 replacement/invalidation。COMMIT fault、旧
generation、未安装的 higher grant 或错误签名都不能踢掉旧连接。

每个 Store 只能有一个 coordinator owner；owner 存活时 raw trust mutator 被拒绝。active
变更同时写入独立 bounded lifecycle channel，P2.3 Core 必须持续读取并关闭返回的旧 writer。
caller future 取消不取消转换；普通 lifecycle channel 满时独立 emergency slot 会把 backlog
与当前受影响 connection IDs 合并为 terminal `FailClosedAll`。收到 terminal 后必须关闭 Core
拥有的全部列出 writer 且不再处理旧 lifecycle backlog。receiver Drop 会立即 poison/清空
active；coordinator shutdown 先投递失效并释放 owner，随后才允许 Store shutdown。相同
platform-normalized DB path 的第二个进程内 Store worker 会被拒绝；跨进程 lock 留给 P2.6
server lifecycle。

对外错误故意不报告“哪一段签名/哪个字段错误”，避免把 Relay 变成 trust inventory
oracle。诊断日志同样只能记录 failure code、脱敏 route 短标识和阶段，不得格式化完整
`Authenticate`、credential、challenge 或 access context。

| v2 auth/route code | 含义 | 下一步 |
| --- | --- | --- |
| `relay.auth.invalid_grant` | cert/grant、root/trust、route、generation/serial、hash 或任一签名不满足同一 trust domain | 停止自动重试；核对本地持久 grant/cert。状态不一致或 key 丢失时按机器重新配对 |
| `relay.auth.revoked` | 当前 device route/serial 已有 terminal tombstone | 立即关闭旧链路并重新配对；禁止提高 serial 复活同 route |
| `relay.auth.challenge_expired` | consume 时已达到 30 秒 TTL | 建立新连接并取得全新 challenge；不得复用旧签名 |
| `relay.auth.replay` | challenge 不存在、source 不匹配、connection collision 或已消费 | 丢弃当前握手并重新连接；若持续出现，检查重复 writer/重放 |
| `relay.quota.exceeded` | challenge pending、source/route token bucket、bucket map 或 active connection hard bound 已满 | 对该 source 退避；检查异常握手洪泛，不能调成无界 |
| `relay.store.unavailable` | trust snapshot、单调 CAS/confirm、coordinator ownership/lifecycle 或 challenge 内部状态不可用 | 不激活新连接并关闭该 Core 的现存 writer；恢复唯一 coordinator/Store 后用新 challenge 重试 |
| `relay.route.not_found` | PairRoute 不存在、server/route 不匹配或已过 absolute expiry | 关闭 pairing connection，重新生成并带外传递 PairInvite |
| `relay.route.forbidden` | PairingAccess 发送了 PairData/Close 之外的 frame，或 route 不匹配 | 立即拒绝该 frame；重复越权应关闭连接 |
| `relay.version.unsupported` | pairing/普通握手不是 Relay v2 | 升级 client/Relay；禁止自动降级到 v1 |

## Failure Codes

| code | 含义 | 下一步 |
| --- | --- | --- |
| `record_write_failed` | run record 写入失败 | 检查 data dir 路径和权限 |
| `diagnostic_write_failed` | diagnostic log 写入失败 | 检查 data dir 路径和权限 |
| `redaction_failed` | 测试 secret 明文落盘 | 停止分享日志，修 redaction |
| `adapter_unhandled_method` | app-server 协议出现未识别事件 | 查看 raw record 和 schema |
| `ipc_malformed_jsonl` | Swift/Rust IPC 收到坏 JSONL | 查看上一条 IPC line |
| `daemon_spawn_failed` | Swift 无法启动 daemon | 检查 `agentdeckd` 路径 |
| `app_server_handshake_failed` | app-server 握手失败 | 检查 agent 登录、版本和 GUI 启动环境里的 `PATH` / `node` |
| `turn_failed` | turn 执行失败 | 按 runId 查看 run record |
| `approval_wait_stalled` | turn 正在等待用户审批 | 查看当前 runtime 的 `actionRequest`，确认 UI 是否已回写 `actionDecision` |

## Codex app-server stderr

daemon 会捕获 Codex app-server 子进程 stderr 的有限尾部摘要。若 app-server
启动后立刻 EOF、握手失败或 turn 期间断连，错误详情会带上 `recent stderr`
片段，并写入 `diagnostic.log` 的 `detail` 字段。该片段会经过 best-effort
脱敏；它只用于诊断，不是长期原始日志。

## Raw / Warning 可见性

未知 adapter item 必须在 daemon 侧中立化为 `raw`，并继续进入 run record 与
runtime UI。`raw` 只显示中立描述，不携带 vendor 原始 JSON；如果 UI 看不到
`raw`，优先检查 `ThreadRuntimeModel` 的 agent item ingest 路径。

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
`actionRequest`，再由 Swift 回写 `actionDecision`。如果 turn 停在
`waitingApproval`：

1. 先看当前 runtime 是否显示 approve / deny 控件。
2. 如果没有控件，检查 `session/event` 中是否有 `kind=actionRequest`。
3. 如果控件点击后没有继续，检查 Swift 是否发送 `kind=actionDecision` 且带
   `sessionId`、`requestId` 和 `decision`。
4. 如果 daemon 返回 error，按同一 `requestId` 查看 diagnostic log 和 run record。

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
| `cc-archive-failed` | `claude rm` 执行失败（非 0 退出） | 查看 daemon diagnostic log 中的 stderr 摘要 |
| `cc-rename-failed` | `claude --resume <id> --name <title>` 执行失败 | 确认 session_id 存在且 `claude` 版本支持 `--name` 参数 |
| `cc-vendor-control-requires-new-turn` | CC 的 permission mode 等 vendor 控件变更需通过新 turn 生效，不支持会话内即时切换 | 下次启动新 session 或新 turn 时携带更新后的 `ClaudeCodeSessionOptions` |
| `cc-vendor-control-not-supported` | 收到不支持的 ClaudeCodeVendorControl variant | 检查 client 与 daemon 协议版本是否匹配（v2）；升级 client 到最新版 |

## v0.2 双 adapter 探测

v0.2 起 daemon 注册了 Codex 和 ClaudeCode 两个 adapter。`agentdeck selfcheck` 和
`swift run AgentDeck -- --selfcheck` 会在响应中报告已注册的 adapter 列表：

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
