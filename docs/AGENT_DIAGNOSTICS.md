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

## Relay v1 历史 marker 与显式 reset

当前 production binary 没有 v1 协议、兼容 feature 或自动迁移路径。CLI 只用
`symlink_metadata` 探测旧 credential marker 是否存在；它不打开、不解析、不删除，
也不据此拨号。marker 存在、悬空 symlink 或 metadata 无法安全判定时均返回
`remote.v1.reset_required`。先停止旧 Relay，确认 DB 与 bearer credential 的
canonical absolute 路径，再显式执行：

```bash
bash scripts/reset-relay-v1-dev-state.sh \
  --storage /absolute/path/to/relay.db \
  --credentials /absolute/path/to/relay/dev.credentials.json \
  --confirm DELETE-RELAY-V1-DEV-STATE
```

只有该 reset 脚本拥有删除权限。脚本拒绝相对路径、目录、symlink、非 v1
schema/credential shape、非 canonical Base64 或解码长度不是 32 bytes 的 credential，以及 `account_id` / `device_id` /
`role` / credential hash 与 DB 行不一致的输入；unlink preflight 还会检查父目录
权限与 macOS immutable/system flags。任一 validation/preflight 拒绝都发生在首次
unlink 前，因此应保留全部四个目标。若报告文件在校验期间变化，说明 Relay 可能
仍在运行：停止它后重新检查路径，不要手工 `rm` 绕过。preflight 之后 OS unlink
仍因 race/I/O 失败时可能部分删除：脚本非零退出、逐个列出仍存在的 exact path、
不打印成功、不承诺 rollback；按列出的路径人工清理后重新配对。
成功只删除 DB、精确 `-wal` / `-shm` 与指定 credential；同前缀和其他文件保留，
之后必须重新配对。

## Relay v2 Store 诊断（Companion MVP P2.1）

P2.1 最初以隔离 library 建立 v2 Store；P2.9 后它已成为 production Relay 的唯一
Store。单独 Store 测试仍不能解释为某个公网部署已上线。v2 Store 由一个
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
512 MiB 与总容量 5% 的较大值。`relay.disk.low` 拒绝新的 Publish，也拒绝新增空 stream
或 durable subscription metadata（metadata growth 另预留 64 KiB）；完全相同的幂等 retry、
replay、revoke 与 purge 等不增长数据的路径仍可用。配额淘汰优先于 ACK，随后重放旧 cursor
会明确返回 `relay.replay.gap`，不得静默跳过。

空 stream / subscription row 也有 count hard bound：默认每 machine 4,096 streams、全局
65,536 streams、每 device 4,096 subscriptions、全局 262,144 subscriptions，只能下调不能
调高。每次新 INSERT 在 transaction 内同时检查 principal/global count；Store 启动还会在
ready 前读回现有计数，配置下调或旧 DB 超限时返回 typed `relay.quota.exceeded`，不静默删
durable state。

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

当前 v2 配置面使用 `RelayV2StoreSettings`。它显式承载 storage path、stream count/bytes/age、machine/global
bytes、replay page count/bytes 与磁盘 reserve bytes/percent；转换为
`RelayV2StoreConfig` 时还带入 enrollment code count，并先拒绝相对路径和
无效/越界配额。server config 按 CLI > env > TOML > defaults 接入全部字段；
已删除的 v1 参数不是 v2 配置入口。

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
| `relay.quota.exceeded` / `relay.disk.low` | frame retention、stream/subscription metadata principal/global count 或磁盘增长安全门禁拒绝写入；也可能是启动读回已超当前上限 | 先释放容量或恢复经批准且不超过代码 hard max 的配置；Publish 只重试同一 canonical frame，现有 metadata 不得手改或静默删除 |
| `relay.frame.too_large` | canonical outer frame 超过 4 MiB | 按 transfer part 规则拆分，不能截断 |
| `relay.replay.gap` / `relay.replay.cursor_invalid` | cursor 已被淘汰或 continuation 不属于本次 replay | 暂停 live，执行 bounded backfill/snapshot 后重新订阅 |

## Relay v2 鉴权诊断（Companion MVP P2.2）

P2.2 最初建立 challenge/auth/access library；P2.9 后 production listener 已只使用 v2。每次普通
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
entry；这里只包括明确发生在 COMMIT 前的 rollback。MachineLink COMMIT 或其结果未知时先以
同 cert hash/generation 精确重试，恢复仍失败则失效旧 entry，绝不能恢复已经低于 SQLite
最高 generation 的连接。COMMIT 成功后在同一 actor poll 中提交 replacement/invalidation。
COMMIT 前 fault、旧 generation、未安装的 higher grant 或错误签名都不能踢掉旧连接。

每个 Store 只能有一个 coordinator owner；owner 存活时 raw trust mutator 被拒绝。active
变更同时写入独立 bounded lifecycle channel，P2.3 Core 必须持续读取并关闭返回的旧 writer。
caller future 取消不取消转换；普通 lifecycle channel 满时独立 emergency slot 会把 backlog
与当前受影响 connection IDs 合并为 terminal `FailClosedAll`。收到 terminal 后必须关闭 Core
拥有的全部列出 writer 且不再处理旧 lifecycle backlog。receiver Drop 会立即 poison/清空
active；coordinator shutdown 先投递失效并释放 owner，随后才允许 Store shutdown。相同
platform-normalized DB path 的第二个进程内 Store worker 会被拒绝；P2.6 server lifecycle
已在 DB 同目录增加 `<db>.agentdeck.lock` 的 OS 排他锁，覆盖不同进程；production
binary 当前默认使用这条路径。

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

## Relay v2 Stream Core 诊断（Companion MVP P2.3）

P2.3 最初建立 v2 stream routing library；P2.9 后 production listener 已只走 v2。
`RelayCore` 是唯一 stream mutation 裁决者：命令队列、ingress bytes、连接数和每连接订阅数都有 hard bound；
Core 可以等待单一 Store worker，但任何 socket write 都必须由 per-connection writer task
完成。看到 stream 测试通过，只能说明 contract 成立，不能解释为某个公网 WSS 已部署。

Publish 的可见屏障是 SQLite COMMIT。Store 返回前没有 fan-out，也没有
`RouteAccepted`；如果 COMMIT 后 reply 丢失，publisher 必须用完全相同的 canonical frame
重试，Core 会补做尚未发生的 fan-out。`RouteAccepted` 只表示 Relay 已持久化并接纳路由，
不表示 Companion 已 flush 或 daemon 已处理业务命令。

每个连接同一时刻只物化一个 replay page，其他 stream replay 在连接内 FIFO 排队；hot stream
每完成一个 catch-up quantum 都轮转到队尾。initial terminal 来自 Subscribe transaction 冻结的
high-water；每页实际大小取 writer 可用预算、Store 配置和 64 frames / 8 MiB 协议 hard max
三者最小值。最后一页入 writer 后异步等待 control reserve，再发送一次 `ReplayComplete`，
随后追赶 terminal 之后的并发 Publish；超过 16 个同时排队的空 replay 也不能因 control reserve
暂满而误断。

Writer normal 上限为 512 frames / 16 MiB，control reserve 为 16 frames / 1 MiB；全 Core 默认
另受 normal 16,384 frames / 256 MiB、control 4,096 frames / 16 MiB 聚合预算约束，所有预算
直到 socket flush 才释放。Publish COMMIT 后先给 origin `RouteAccepted` 占 normal permit，再
fan-out readers。单个慢 writer 会以 Lagged/CriticalBackpressure 关闭，不应阻塞其他 reader、
publisher 或 Store。Store command queue 瞬时满时 replay 会先释放整页预算，最多三次可取消
退避；持续 busy 则关闭该连接并要求重连，绝不无界等待或堆积 ciphertext。

authorization 的 `Transitioning` 是数据面即时 fence：live/replay Publish、Gap 与
`ReplayComplete` 都必须把 current-generation 检查和 writer enqueue 放在同一个
`with_current` 临界区。若 fence 已建立，Core 以 AuthorizationInvalidated 关闭旧 writer；
不能依赖先 `is_current`、稍后 enqueue 的两步检查，也不能让 terminal 作为例外跨过 fence。

`Gap` 表示 cursor 已无法连续重放或 live sequence 出现缺口。收到后该 stream 进入暂停态，
更高 sequence 不再交付；客户端完成 backfill/snapshot 后，必须使用同 generation 与合法
cursor 显式重新 Subscribe。disconnect 只清 runtime subscription；durable lease/ACK 保留，
只有显式 Unsubscribe 删除。ACK 只允许单调推进，grant serial 更新不会继承旧 serial lease。

heartbeat 每 20 秒生成一个 server Ping；只有 exact outstanding nonce 的 Pong 才刷新连接，
60 秒边界关闭。authorization replacement、revoke、lifecycle overflow terminal、writer/receiver
退出都会取消该连接 replay 并清理 active generation；Core task panic 会优先于 command backlog
回收，Core future 意外被 runtime 取消时 registry Drop guard 仍会取消 replay 并关闭 transport
writer clone。重复出现应先检查唯一 coordinator、Store 健康与客户端是否及时 flush，而不是
调大为无界队列。

| v2 stream/core code | 含义 | 下一步 |
| --- | --- | --- |
| `relay.route.not_found` | stream 不存在、owner 不匹配或不可见 | 核对当前 machine trust domain 与已注册随机 route；不要枚举 route |
| `relay.route.forbidden` | 当前 access role 发送了不允许的 frame | 修正端点 dispatch；endpoint 不能发送 server-only Ping/ReplayComplete/Gap |
| `relay.stream.generation_stale` | route generation 不匹配或 generation 已耗尽 | 从 machine 建立全新随机 generation；禁止 wrap 或重绑旧 route |
| `relay.stream.out_of_order` | sequence 跳号、same-seq different bytes 或 ACK 超过 HWM | 读取当前 cursor/HWM，按相同 canonical frame 重试或新建 generation |
| `relay.replay.cursor_invalid` | cursor/continuation 非法、越过冻结边界或已耗尽 | 停止自动推进，按当前 generation 重新取得合法 cursor |
| `relay.replay.gap` | retention 已删除需要的 frame，或 live 连续性丢失 | 暂停该 stream，完成 backfill/snapshot 后显式 re-Subscribe |
| `relay.quota.exceeded` | Core command/ingress/connection/subscription、per-writer 或 global normal/control hard bound 已满 | 对当前端退避；慢 writer 应重连，禁止把任一上限改成无界 |
| `relay.store.unavailable` | Store 持续 busy、停止、replay 校验失败或 Core 内部状态不可用 | 当前连接 fail-closed；检查 DB/worker 后用新 challenge 重连 |
| `relay.auth.invalid_grant` / `relay.auth.revoked` | command/replay 时 access 已被 replacement 或撤销 | 立即停止旧 connection；按机器重新配对或使用当前 active grant |

## Relay v2 PairRoute / 在线请求诊断（Companion MVP P2.4）

P2.4 的 PairRoute/在线请求 contract 当前已由 production v2 listener 使用。PairRoute 只存在于当前 `RelayCore`
内存：Core/Relay 重启后 view 为空是预期行为，daemon 必须从 durable outbox 以完全相同的
machine/route/absolute expiry 重开；不能生成第二个邀请或把该现象误判为 SQLite 丢数据。

PairRoute 默认 hard bound 为每 machine 8、全局 1,024、每 route lifetime 32 frames / 1 MiB、
TTL 300 秒，另有每 route burst 8、refill 2 frames/s。Close 后 tombstone 在 absolute expiry
前继续占容量。`RouteAccepted` 只说明目标 frame 已进入 bounded writer；目标尚未 flush 时
断线，PairData/Send/Reply 都可以丢失，不能据此推进 pairing delivered 或业务执行状态。

`Send/Reply` 不进 SQLite，也没有 `req_origin`。目标离线立即 not-found；目标 writer 满时只
关闭目标并向 origin 返回 quota；目标已入队但 origin ACK writer 满时只关闭 origin，目标
事实不回滚。origin 与 target 的 generation 在同一 authorization 临界区核对；replacement
或 revoke fence 后看到旧连接继续发送，属于安全回归，不能靠重试旧 access 绕过。

| v2 route code | 含义 | 下一步 |
| --- | --- | --- |
| `relay.route.conflict` | Open 的 owner/expiry 与已有 active/tombstone 冲突，或同 route 已有 pairing writer | 使用原 durable route/absolute expiry 做完全相同的 retry；不要延长 TTL 或复用随机 ID |
| `relay.route.not_found` | PairRoute 不存在/已过期、pairing 未绑定、或在线 Send/Reply 目标离线 | Pairing 重新生成邀请；已配对端重新认证目标并用业务 idempotency key 查询状态 |
| `relay.route.forbidden` | role、self device route、trust domain 或 pairing allowlist 不匹配 | 修正 endpoint dispatch；Pairing 只允许同 route PairData/Close 与 exact Pong |
| `relay.quota.exceeded` | PairRoute 数量/lifetime/rate 或目标 writer 容量耗尽 | 对当前 route 有界退避；writer 已关闭时用新 connection 重连，禁止调成无界 |
| `relay.auth.invalid_grant` | origin/target 在路由时已被 replacement/revoke fence | 丢弃旧 connection 上的排队操作，只使用当前 active generation |

Pairing 发出 Close 后若 ACK 不确定，可在同一已激活 connection、同 machine/route/expiry 且
tombstone 未过期时重试，Relay 返回 `AlreadyAbsent`；PairData/Pong 不享受该 terminal 例外，
route close 后立即不可用。

## Relay v2 Grant / Revoke / Retire 诊断（Companion MVP P2.5）

P2.5 的撤销/退役路径当前已由 production v2 listener 使用。看到 revocation E2E 通过只证明
本地真实签名、事务和 writer 生命周期成立，不能解释为某个公网部署已经支持撤销。production control frame必须来自
current、同 machine 的 MachineAccess；Device/Pairing 直接发送 InstallGrant、RevokeDevice 或
RetireMachine 均是 `relay.route.forbidden`。

撤销以 SQLite COMMIT 为计时边界。目标 writer 尚未出队的普通 Data/Control 会被丢弃，唯一
`RevocationCommitted` 使用独立 terminal slot；flush 后立即关闭，未 flush 最多 2 秒关闭。
连接先关闭但没有 signed terminal 不能让 endpoint 删除 key；用原 grant + DeviceSign 建立新
challenge，合法 proof 会只读回同一 terminal，不会出现 `Authenticated`。伪造 proof 只能得到
`relay.auth.invalid_grant`，不能据 route 探测是否已撤销。

若 COMMIT 已成功但 Store 回执丢失，authorization actor 会用完全相同的 canonical grant、
revocation 或 retirement 做一次精确幂等恢复；恢复读回的 duplicate 仍按原 mutation 失效旧
generation。再次失败时 target 不会恢复为 active，整机 retirement 会触发 Core 全局
fail-close，避免内存 PairRoute 与 SQLite retired tombstone 分叉。排查时不要调用或重新暴露
coordinator raw mutator；生产只允许 `*_from(current MachineAccess, signed object)`。

RetireMachine 成功后 origin 收到 `RetirementCommitted(machineRoute, trustEpoch, retireHash)`
terminal，其他同 machine writer与 PairRoute关闭。readback必须是
`0/1/0/0/0/0/0`；daemon 在收到 matching retireHash 前不得删除本地 MachineRoot/Link材料。
ACK 丢失时旧 exact MachineLink proof只会重放 terminal；更高 generation、普通 command或重新
enroll 旧 route 都不能复活。root-lost admin purge 已由 P2.7 的本机 admin UDS 承载，
不能从公网 frame 伪造。

| v2 revoke code / state | 含义 | 下一步 |
| --- | --- | --- |
| `relay.route.forbidden` | role 或 machine trust domain 不匹配 | 拒绝 endpoint 自行改授权；由被控机 daemon 的 current MachineAccess 重发 |
| `relay.auth.invalid_grant` | root signature、rootKeyId、trustEpoch、serial/hash 或 possession proof 不匹配 | 丢弃 frame；重新读取本机冻结对象，不能修改字段后复用 signature |
| `relay.store.unavailable` | Store fault/busy、COMMIT 精确恢复仍失败或 purge readback不完整 | 保留本地 key与 frozen request；恢复 Store 后 exact retry，不能假设未提交；旧 access 已 fail-closed |
| `relay.quota.exceeded` | device metadata或 terminal aggregate hard bound已满 | 先完成受控撤销/整机 purge；禁止调成无界或删除单行绕过 tombstone |
| writer close=`Revoked` / `Retired` | terminal 已 flush或达到2秒硬 deadline | 只有已验证 terminal/hash才推进本地删 key；单纯 socket close继续重连读取终态 |

若排查 retired tombstone，可只读确认 `status`、root fingerprint、retirement hash与各表计数；
禁止打印 root pubkey、link hash、terminal bytes或完整 route。P2.5 schema signature因新增最小
retirement tombstone列而更新；旧的未发布 v2 开发 DB会被严格 schema signature拒绝，应按开发
环境 reset流程清理并重新配对，不能手改 SQLite schema。

## Relay v2 TLS / readiness / shutdown 诊断（Companion MVP P2.6）

P2.6 server 已在 P2.9 成为 `agentdeck-relay` production binary 的唯一 listener。
不要把本地 TLS E2E 或 selfcheck 通过描述为某个现网 WSS 已部署。public listener
只应暴露固定 `/v2/connect` 与 `/v2/pair`，`/healthz`、`/readyz` 只能从单独 loopback health
listener读取；public 上这些 path、未知 path 与旧 query pairing 都不应 redirect 到其他 host/scheme。

启动顺序是 config validate → TLS identity validate → Store open → bind。direct TLS 的证书或
私钥缺失、超过 1 MiB、PEM 无效、keypair 不匹配或 binary 没有 `tls` feature 时，必须在公开
listener bind 前失败，不能观察到临时明文端口。配置失败使用 `RelayV2ConfigError::code()`，TLS
identity失败使用 `TlsIdentityError::code()`；这些 code 不包含 path 或 PEM 内容：

| code | 含义 | 下一步 |
| --- | --- | --- |
| `relay.transport.tls_feature_missing` | 配置了 direct TLS，但 binary 未编译 TLS | 用带 `server,tls` features 的受控构建，禁止改成明文绕过 |
| `relay.config.tls_partial` | cert/key 只配置一项，或高优先级层只覆盖一半 | 在同一 CLI/env/TOML 层提供完整 pair |
| `relay.transport.tls_required` | 非 loopback 未配置 direct TLS | 配置有效 cert/key；不能启用 insecure loopback |
| `relay.transport.insecure_loopback_opt_in_required` | loopback 明文未显式 opt-in | 只在本机开发明确启用；production 使用 Direct TLS |
| `relay.transport.proxy_requires_loopback` | proxy backend 尝试监听非 loopback | 将 backend 收回 loopback，由可信反代终止 TLS |
| `relay.proxy.source_required` | proxy 请求缺少可信来源 header | 配置反代始终覆写单个 `x-agentdeck-client-ip` |
| `relay.proxy.source_invalid` | proxy 来源 header 重复、列表化或不是 canonical IP | 删除外部同名 header，并以实际 TCP peer IP 覆写单值 |
| `relay.transport.mode_conflict` | direct/insecure/proxy 模式冲突 | 只保留一种 transport mode |
| `relay.config.health_non_loopback` | health listener 不是 loopback | 改为 loopback；不要向公网暴露 readiness |
| `relay.tls.certificate_read` / `relay.tls.private_key_read` | identity 文件不可读 | 检查 owner、0600/目录权限与部署路径，不打印文件内容 |
| `relay.tls.certificate_too_large` / `relay.tls.private_key_too_large` | PEM 超过启动硬上界 | 修复证书链或私钥文件，禁止调大到无界 |
| `relay.tls.identity_invalid` | PEM 解析失败或 cert/key 不匹配 | 在离线安全环境校验 keypair并原子替换两文件 |

公开 listener 还在 accept 前执行三层 pre-upgrade 边界：最多 1,024 个物理连接；从 TCP accept
到 TLS handshake、完整 HTTP/1 header 与成功 101 upgrade 共用 5 秒 deadline；解密后的
request line + headers 最多 64 KiB。只有确认返回 101 才解除 deadline，permit 随 WebSocket
持有到关闭；所有 400/404/405、extractor rejection 与其他非 101 响应都必须带
`Connection: close` 并立即释放 permit。超过期限或大小的连接应直接关闭且不产生 protocol
frame；1,024 个完整普通 HTTP keep-alive 也不能阻塞下一个合法 WS upgrade。

`ProxyLoopback` 把 loopback backend 与反代作为同一个部署信任边界。反代必须先删除互联网
客户端携带的全部 `x-agentdeck-client-ip`，再用它实际看到的 TCP peer IP 覆写为恰好一个纯
IPv4/IPv6 值；不能追加、传逗号列表或转发未经清洗的 header。Relay backend 只能绑定 loopback，
同主机进程因此属于受信/DoS 边界。direct TLS 与 insecure loopback 模式会忽略此 header，始终
使用直接 TCP peer，避免远端自行伪造来源 bucket。

`/healthz` 返回 `200 {"status":"ok"}` 只表示进程存活；`/readyz` 的 200 才表示最新缓存探针
通过。`relay.disk.low`、`relay.store.unavailable`、`relay.quota.exceeded` 或
`relay.server.draining` 时 readyz 返回 503。HTTP handler 不直接请求 Store；若高频 readyz 导致
Store busy，属于回归。磁盘恢复后等待至多一个 5 秒 readiness 周期；不要通过删除 WAL/lock
文件制造假恢复。

Store 会在 DB 同目录保留 `<db>.agentdeck.lock`。文件存在本身不是“另一个 Relay 正在运行”；
判断依据是 OS 排他锁。第二进程得到 `StoreAlreadyOpen` 时先确认原进程和配置路径，不能删除仍被
持有的 lock/DB/WAL。正常 SIGTERM 应先停止 accept、发送 `ServerRestarting`，网络最多 drain
5 秒；进程退出后立即可重新打开 DB。超过网络 deadline 可返回 typed `DrainTimeout`，但若随后
仍不能取得 DB lock，说明 Core/Auth/Store 未真正 quiesce，必须作为 lifecycle bug 处理。
Store shutdown 成功回执只允许在 SQLite connection、OS 排他锁与进程内 path lease 均已释放后
发送；即使 Core shutdown 已报错，server 也必须继续等待 Store shutdown，不能提前返回漏锁。

日志排查只搜索 `event`、`failure_code` 与计数。完整 URL query、route、source IP、证书路径、
public key/signature、terminal/sealed bytes或输入 sentinel 出现在日志中均是安全回归。P2.6 的
真实 SIGTERM 子进程测试和 positive-event sentinel scan 命令见 `docs/QUALITY.md`。

## Relay v2 Admin / machine enrollment 诊断（Companion MVP P2.7）

admin、inventory、readback 与 purge 只存在于 Relay host 本机 UDS；公网只允许
`POST /v2/machine-enroll`。操作步骤见 `RELAY_RUNBOOK.md`。production listener 已在 P2.9
切换为仅 v2，但本地 E2E 通过仍不能描述为某个现网 enrollment endpoint 已部署。

| code | 含义 | 下一步 |
| --- | --- | --- |
| `relay.admin.config_partial` | socket、WSS origin、SPKI pins 最终配置不完整 | 按 CLI > env > TOML 逐字段核对三项 |
| `relay.admin.secure_transport_required` | insecure loopback 尝试启用 admin | 改为 direct TLS 或可信 proxy loopback；禁止降级 |
| `relay.admin.config_invalid` | socket非绝对路径、WSS origin或pin集合无效 | 修正绝对路径、纯 `wss://` origin和1–2个32-byte base64url pin |
| `relay.tls.spki_pin_mismatch` | 配置第一 pin 与当前 leaf DER SPKI 不同 | 停止启动并核对证书轮换，不要跳过 pin |
| `relay.admin.socket_parent_insecure` | socket父目录owner/mode不安全 | 使用Relay用户持有的0700目录 |
| `relay.admin.socket_in_use` | socket活跃或无法安全证明stale | 查原进程；不得删除活跃pathname |
| `relay.admin.peer_forbidden` | UDS peer不是Relay运行UID | 切到配置owner执行 |
| `relay.admin.request_too_large` | JSONL超过64 KiB | 修复调用方；不要调大无界 |
| `relay.store.confirmation_mismatch` | route的root fingerprint与确认值不一致 | 从可信receipt/inventory重新人工核对 |
| `relay.enrollment.request_invalid` | JSON结构或body无效 | 生成严格V1请求，body必须≤64 KiB |
| `relay.enrollment.rejected` | code、证书、公钥、签名或幂等请求不合法 | 修复未消费的请求；code失效/冲突时重新创建bundle |

MachineRoot 丢失不进入恢复模式：daemon保持remote blocked，本机管理员执行带旧fingerprint的
purge，再以同fingerprint readback确认active/grant/revocation/stream/frame/subscription全为0、
只剩一个retired tombstone，之后重新enroll与重新配对。COMMIT结果不确定会让整个Core
fail-closed；若仍观察到旧writer或PairRoute，这是P0级安全回归。

## Relay v2 Rust client 诊断（Companion MVP P2.8）

| code | 含义 | 下一步 |
| --- | --- | --- |
| `remote.transport.tls_pin_mismatch` | leaf DER SPKI不在current/next pinset | 核对证书轮换；错过窗口重新取得bundle/invite，禁止忽略pin |
| `relay.client.tls_verification_failed` | CA、证书时间或hostname验证失败 | 修证书链/SAN/系统时间，不降级到pin-only或明文 |
| `relay.client.server_identity_mismatch` | Challenge/PairingHello的Relay server ID与冻结配置不同 | 停止签名和重试，重新核对可信bundle |
| `relay.client.authentication_terminal` | 收到逐字节保留的signed revoke/retire terminal | 交给P4状态机验签、持久化并进入撤销/退役终态 |
| `relay.client.send_outcome_unknown` | frame进入sink后失败或flush超时，是否到达对端未知 | 当前generation已fail-close；只按上层幂等/outbox语义决定重试 |
| `relay.client.lagged` | 有界入站frame/byte预算耗尽 | 关闭并从cursor/snapshot恢复；不要扩大成无界队列 |
| `relay.client.pair_event_pending` | 兼容data helper前存在close/error/restart等control event | 改用`next_event()`先处理并持久化control结果 |
| `relay.client.enrollment_response_invalid` | server/route/epoch/receipt回显不匹配 | 视为安全错误，保留原请求，不生成新key/route后盲重试 |

P2.8 client 已接入 P2.9/P2.10 的 production v2 与 synthetic 路径；v1 client/compat
feature 已物理删除。normal client 依赖树出现 server/store，或 pairing 调用方能发送
Subscribe/Publish/Send，都属于边界回归。

## Relay v2 production cutover / synthetic 诊断（P2.9–P2.10）

production `agentdeck-relay` 只加载 v2 config、Store/Auth/Core/Admin 与 server。
`/v1/connect` 的唯一允许结果是无状态 HTTP 426；若出现 101、challenge、DB 访问或
任何 v1 frame，属于 P0 安全回归。旧 `--bootstrap-secret` 等 v1 参数必须在 admin、
config、TLS、Store 或网络 I/O 前本地拒绝，且不得因非 UTF-8 参数 panic。

真实链路诊断使用本机 admin 生成的一次性 bundle：

```bash
agentdeck remote synthetic --bundle /secure/path/machine-enrollment-bundle.json
bash scripts/verify-relay-companion-mvp.sh p2
```

bundle 必须是当前用户持有的 0600 regular file；读取使用 `O_NOFOLLOW`、同一 fd 并受
64 KiB 上界约束。synthetic 会通过真实 Direct TLS/CA/hostname/SPKI 完成临时 machine/
device 全流，但不会保存身份。测试会在 SQLite 和 Relay 可见 outer bytes 中扫描多个
sentinel；出现应用明文、key、签名或 enrollment code 均是安全回归。

| code / 现象 | 含义 | 下一步 |
| --- | --- | --- |
| `remote.v1.reset_required` | 发现旧 marker、悬空 symlink，或 metadata 状态无法安全判断 | 不读取 marker；停止旧 Relay，按上节显式 reset 后重新配对 |
| `remote.persistent.unsupported` | P4 前调用了持久 remote 命令 | 只运行 synthetic 门禁；等待 P4 Keychain/持久状态机，不要自行落 secret 文件 |
| `/v1/connect` 返回 426 | 预期的无状态 migration tombstone | 升级到 v2；禁止自动降级或重试 v1 |
| synthetic 在 SPKI/CA/hostname 前失败 | server identity 未通过完整验证 | 核对证书、DNS、bundle 与 pin 轮换；不得改成明文或 pin-only |
| synthetic 返回 authentication terminal | signed revoke/retire 已成为当前终态 | 验 canonical terminal；临时身份直接丢弃，持久身份由 P4 状态机处理 |

P2.10 hardening suite 还必须证明 restart byte-identical replay、retention gap、quota、
disk-low、Store fault 与 deterministic shutdown；`agentdeckd` 同时继续通过
`scripts/check-daemon-no-net.sh`。这些证据只收口 Relay，不代表 daemon/iOS Companion
持久链路已经完成。

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
