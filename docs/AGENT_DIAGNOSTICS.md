# AgentDeck Agent Diagnostics

本页给没有历史上下文的 agent 使用。目标是在 5 分钟内判断 AgentDeck 当前是否能记录、诊断和复验问题。

## 快速入口

```bash
swift run AgentDeck -- --selfcheck
swift run AgentDeck -- --diagnostics-report --json
swift run AgentDeck -- --selfcheck --profile dev
swift run AgentDeck -- --diagnostics-report --json --profile dev
cargo run -p agentdeckd -- --ephemeral --no-remote --profile dev --selfcheck
```

## 日志位置

- stable run record: `<OS account home>/Library/Application Support/AgentDeck/runs/*.jsonl`
- stable diagnostic log: `<OS account home>/Library/Application Support/AgentDeck/diagnostic.log`
- P3.1 stdio 开发实例: OS temp root 下随机的 0700 `ad-<instance-id>/`
- 旧 dev profile / 测试覆盖目录: 只允许 diagnostics one-shot 通过
  `--profile dev` 或 `--data-dir /absolute/path` 读取；不能覆盖 daemon startup namespace

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

排查 P3.1 过渡 stdio 实例时，Swift/Rust transport 已固定把 child 启动为
`--ephemeral --no-remote --profile dev`，并删除继承的 `AGENTDECK_DATA_DIR` /
`AGENTDECK_PROFILE`；每次 spawn 都是新的 temp namespace。diagnostics report 不启动
daemon，仍可用 `--profile dev` 或 `--data-dir` 读取旧日志。不要把 diagnostics override
当成 stable ownership 配置。

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

## Daemon namespace / singleton / StorageKEK 诊断（Companion MVP P3.1）

daemon 正常启动顺序固定为 `config → private namespace/singleton → keystore →
StorageKEK → record namespace → selfcheck/stdio loop`。前一步失败时不得继续打开下一层。
stable data root 来自当前 EUID 的 `getpwuid_r`，不读取 `HOME`；stable access group 只接受
编译时注入且与签名 entitlement 一致的展开值，运行时同名环境变量不能补齐 unsigned
helper。unsigned 开发构建应使用：

```bash
cargo run -p agentdeckd -- --ephemeral --no-remote --profile dev --selfcheck
```

看到 singleton/namespace 错误时，先只读检查 data root 与 lock 的 type、UID、mode、nlink、
dev/ino。不要先 `rm` lock：guard 锁的是保持打开的 fd，删除 pathname 可能让第二个进程
锁住另一个 inode。固定 stable 旧目录若由当前 UID 拥有且是实体目录，daemon 只迁移历史
精确 0755，并在 `O_NOFOLLOW` directory fd 上收紧为 0700；0775、0777、01755 等其他宽权限
一律拒绝。ephemeral 权限不精确为 0700 时也直接拒绝，不会自动修复。

StorageKEK 缺失时先检查 `runtime.db`、`runtime.db-wal`、`runtime.db-shm` 是否存在或不是
普通空文件。任一既有 state 都意味着不能生成替代 key；不要删除 DB 以绕过错误，也不要
把 key 写入文件。stable Keychain backend 不可用时只修复 signing/provisioning/entitlement，
禁止切换到 memory store。P3.1 真实签名 roundtrip 当前仍 gated/BLOCKED：本机无匹配
provisioning profile，两个已通过 `codesign --verify` 的尝试均被 AMFI 以 exit 137 终止；
ignored 测试不是通过证据。

| P3.1 code | 含义 | 下一步 |
| --- | --- | --- |
| `daemon.cli.missing_value` | `--profile` 或 `--data-dir` 缺值 | 补齐参数值，不要用环境变量替代 stable ownership |
| `daemon.cli.invalid_profile` | profile 不是 `stable` / `dev` | 使用受支持值，并同时满足下面的 mode matrix |
| `daemon.cli.unknown_argument` | daemon 收到未知参数 | 核对调用方版本；不要把 Relay/client 参数传给 daemon |
| `daemon.cli.data_dir_forbidden` | daemon serve/selfcheck 尝试使用 `--data-dir` | 移除 override；它只允许 diagnostics one-shot |
| `daemon.cli.conflicting_one_shot_modes` | 同时传 selfcheck 与 diagnostics-report | 每次只运行一个 one-shot |
| `daemon.cli.diagnostics_startup_flags_forbidden` | diagnostics-report 带了 ephemeral/no-remote startup flag | diagnostics 不启动 daemon，移除 startup flags |
| `daemon.config.ephemeral_requires_no_remote` | 只启用了 ephemeral | 同时显式加 `--no-remote` |
| `daemon.config.no_remote_requires_ephemeral` | stable 尝试单独关闭 remote | 开发实例同时加 `--ephemeral`；stable 不允许半隔离 |
| `daemon.config.ephemeral_access_group_forbidden` | ephemeral config 携带 stable access group | 移除 access group；ephemeral 只能用独立 memory store |
| `daemon.config.dev_requires_ephemeral` | `--profile dev` 没有完整 ephemeral pair | 加 `--ephemeral --no-remote` |
| `daemon.config.stable_forbids_ephemeral` | stable profile 与 ephemeral 混用 | 二选一；不得把 stable 信任域当测试夹具 |
| `daemon.config.home_unavailable` | 当前 OS account home 缺失、为空或非绝对路径 | 修复系统账号记录；不要设置 `HOME` 绕过 |
| `daemon.config.home_lookup_failed` | `getpwuid_r` 查询 OS account 失败 | 记录系统 status，检查账号目录服务后重试 |
| `daemon.namespace.root_not_absolute` | hermetic/ephemeral root 不是绝对路径 | 使用 canonical absolute root |
| `daemon.namespace.invalid_instance` | instance ID 为空、过长或含非法字符 | 只用 1–64 位 ASCII 字母、数字、`-`、`_` |
| `daemon.namespace.socket_path_too_long` | UDS 路径超过平台 `sun_path` 上限 | 缩短 temp root；不要把 socket 移到 0700 namespace 外 |
| `daemon.namespace.socket_path_invalid` | UDS 路径含 NUL | 修复路径来源，禁止 lossy 转换后继续 |
| `daemon.namespace.unsafe_data_directory` | data root 不是当前 UID 的实体目录，ephemeral 不是 0700，或 stable 旧权限不是精确 0755 | 核对 type/UID/mode；不要自动跟随 symlink 或放宽迁移范围 |
| `daemon.namespace.io_failed` | 建立或检查 data root 的文件系统操作失败 | 检查父目录、权限、磁盘与具体 operation/path |
| `daemon.singleton.already_running` | 同一 namespace 的 lock 已被其他进程持有 | 连接既有 daemon；若怀疑僵尸，先核对 owner 进程，不要删 lock pathname |
| `daemon.singleton.unsafe_lock` | directory fd/path 或 lock fd/entry 的 type、UID、mode、nlink、dev/ino 不一致 | 视为路径替换/权限安全错误；停止并人工检查，不要自动修复 lock |
| `daemon.singleton.unsupported_platform` | 平台不支持 Unix singleton lock | stable daemon 仅在受支持 Unix/macOS helper 上运行 |
| `daemon.singleton.io_failed` | `open/openat/fstatat/flock/fchmod` 等失败 | 按 operation/path 检查 errno、文件系统与并发进程 |
| `daemon.keystore.access_group_unconfigured` | stable build 没有编译进真实 access group，或 Keychain adapter 未获得配置 | 使用匹配 provisioning/entitlement 的 release-signed helper；运行时 env 无效 |
| `daemon.keystore.access_group_invalid` | access group 格式错误、文档占位符、前后空白或与编译值不一致 | 注入实际 TeamIdentifier 展开值并保证 codesign entitlement 完全一致 |
| `daemon.keystore.unsupported_platform` | stable Keychain backend 在当前平台不可用 | 不得回退明文/memory；改在受支持的 macOS helper 运行 |
| `daemon.keystore.unavailable` | Keychain backend set/get/delete 或 memory test lock 失败 | stable 检查 entitlement、Keychain status 与签名；保留原 Runtime state |
| `daemon.storage.key_missing` | Keychain 无 `storage-kek.v1`，但 DB/WAL/SHM 已有 state | fail-close；恢复同一 Keychain item/签名环境，禁止生成替代 key 或删库绕过 |
| `daemon.storage.key_invalid` | 读出的 StorageKEK 不是 32 bytes | 视为损坏/错误 entitlement domain；停止打开 Runtime DB |
| `daemon.storage.state_check_failed` | 检查 DB/WAL/SHM metadata 失败 | 修复路径/权限/I/O 后重试；检查完成前不能 mint key |
| `daemon.storage.entropy_unavailable` | OS CSPRNG 无法生成 fresh 32-byte key | 停止启动，修复系统 entropy source；禁止弱随机替代 |
| `daemon.storage.key_persistence_failed` | Keychain store 成功返回后无法读回，或读回 bytes 改变 | 视为 backend/并发安全故障；不要打开 DB，检查 Keychain domain |
| `daemon.record.namespace_not_absolute` | record/diagnostics 绑定到非绝对路径 | 只绑定已验证的 absolute daemon data root |
| `daemon.record.namespace_already_configured` | 同进程尝试把 record namespace 改到另一目录 | 视为 ownership bug；进程退出后按正确 config 重启 |
| `daemon.selfcheck.namespace_mismatch` | record namespace 与 resolved daemon namespace 不一致 | 检查 startup 顺序和调用方是否绕过 config |
| `daemon.selfcheck.namespace_unavailable` | selfcheck 未取得 data root 或目录消失 | 检查 singleton guard 与 namespace 生命周期 |
| `daemon.selfcheck.diagnostics_unavailable` | 已验证 namespace 中无法解析 diagnostic path | 检查 record/diag namespace 绑定 |
| `daemon.selfcheck.record_failed` | selfcheck run record 写入失败 | 检查 0700 data root、runs 目录、磁盘与权限 |
| `daemon.diagnostics.path_unavailable` | diagnostics one-shot 无可用日志路径 | 提供合法 profile/absolute data-dir，或先创建一次诊断日志 |
| `daemon.runtime.main_loop_failed` | security bootstrap 已完成，但 stdio RuntimeHub 主循环失败 | 按同一 diagnostic log 检查 IPC I/O；guard/KEK 会随进程退出释放/清零 |

## Runtime SQLite / journal / adapter 私表 / Core 诊断（Companion MVP P3.2–P3.6）

P3.2/P3.3 error code 是 store 内部精确错误的稳定诊断归类；P3.4–P3.6 已把接入 RuntimeCore 的
路径映射成 wire `RuntimeFailure`，并增加 Core/principal/connection/read overload、approval
authorization、delivery 与 stream/snapshot 分类。transfer reducer 仍只有 component-local typed
error，没有 production wire owner。排查时保留 DB/WAL/SHM 原件，先运行 diagnostics/read-only
inspection，
不要用删除 sidecar、生成新 KEK 或直接改 high-water 的方式“修复”。

### Store shutdown deadline 语义

Store shutdown 的等待上界固定为 `busy_timeout_ms + 5000 ms`。`ShutdownTimedOut` 只表示
调用方在 deadline 前没有观察到 worker 静默，**不表示** SQLite connection、row keys 或进程内
path lease 已释放。worker lifecycle 会继续保持 `ShuttingDown`；重复 shutdown 返回
`ShutdownInProgress`，普通、安全与读取请求也不再接收。取消 shutdown future 或丢弃全部
handle 同样不会释放这些资源，更不会启动第二个 worker。

只有 worker 真正退出时，才会依次关闭队列、释放 SQLite state/keys 与 path lease、切换到
`Stopped`；成功 shutdown 回执在这些步骤之后发送。遇到 `ShutdownTimedOut` 时必须保持 daemon
fail-closed shutdown，不得在同一进程中循环 reopen、删除 DB sidecar 或绕过 singleton；保留诊断
证据后由 supervisor 在旧进程退出后再重启。

### Paged recovery 语义

daemon 启动恢复必须调用 `begin_recovery_scan`：先做全库 streaming integrity validation，再在
冻结 catalog barrier 前完成一次 24h expiry sweep。随后只使用 store 返回的 opaque keyset
cursor，每页读取一个 conversation；单页 retained 上限 80 MiB。RuntimeCore 必须消费并释放
当前页后再取下一页，不能聚合全库，也不能在终页 `finish_recovery_scan` 成功前启动任何
Accepted command。begin/page/finish 回执丢失都只重试原 token。
finish 会在开放 mutation 前重新执行完整 integrity readback；若 begin 后有同 UID 外部工具改写
DB/WAL，finish 必须失败并保持 Recovering。

scan active 时 inspect 与 shutdown 仍可用；create/accept/start、fence/release/terminal/rescue
全部返回 `daemon.runtime.recovering`。这不是“读永远可用”：业务 recovery read 也受 exact
cursor/单 outstanding scan 限制。若 scan 无法结束，保留 DB/WAL/SHM 与 Keychain 原件后让
daemon fail-closed 退出，不要跳页、伪造 cursor 或删除 sidecar。

worker 初始化或 migration 通过 ready channel 返回错误前，必须先释放 Runtime DB path lease；caller
收到错误后可直接 exact reopen。若此时仍得到 `daemon.runtime.store_unavailable`/`StoreAlreadyOpen`，
保留进程与 path-owner 证据，不要用轮询掩盖 lease ownership 错误。

测试进程里的 `failed to initialize runtime read-only WAL pool` 还要先区分 harness FD 耗尽：macOS
默认 soft FD limit 256，而每份真实 RuntimeStore fixture 固定打开 1 个 writer 与 8 个 WAL readers。
当前 unit `cfg(test)` worker 与 integration fixture admission 都把单个测试进程同时存活的 Store 限为
4，permit 一直持有到 ReadPool 关闭/path lease 释放。该机制防御的是默认并行 `libtest` 在业务断言前
耗尽 FD，并非 production 限流；不要据此把 production ReadPool 从 8 降低、提高系统 FD 上限来掩盖
fixture 泄漏，或把 test-only admission 暴露为运行时配置。

| P3.2/P3.3 code | 常见内部原因 | 下一步 |
| --- | --- | --- |
| `daemon.runtime.store_invalid` | path/type/owner/mode/nlink、busy/count/byte config 或 operation input 不合法 | 核对 0700 namespace、0600 artifacts 和固定 config；拒绝 symlink/hardlink，不自动放宽 |
| `daemon.runtime.schema_incompatible` | schema family/version/signature/live manifest、typed canonical descriptor/row linkage、逐 conversation HWM、authenticated metadata、command/execution/event/approval/stream/snapshot/publication totals 或两类 adapter-state total 不一致 | 停止写入并保留 main/WAL/SHM/journal；v1/v2/v3→v4 只能走内置原子 migration，不能原地猜测/手改 schema |
| `daemon.runtime.store_unavailable` | worker/shutdown/commit outcome、clock/capacity probe、SQLite/I/O、sequence coordination，或 bounded checkpoint 被 reader pin 住 | 对 unknown outcome 用完全相同 stable ID/idempotency input 重试；checkpoint blocked 时停止新副作用、释放 reader 并保留 WAL，其他错误保留 evidence 后重启/修复底层 I/O |
| `daemon.runtime.store_busy` | normal/safety/read lane 的 count 或 retained-allocation byte permit 已满 | 客户端退避并保持同一 idempotency key；不要并发重发新 key |
| `daemon.runtime.recovering` | 已冻结 paged recovery barrier，终页尚未核账并 finish | 继续使用上一页返回的 exact cursor；RuntimeCore 逐页消费，终页 finish 后再开放请求，不得并行 mutation |
| `daemon.runtime.safety_only` | 非 disk capacity violation 已在本进程 latch，普通副作用关闭 | read/diagnostics 可继续；fence/release/terminal/rescue 仍会逐次校验预留尾，失败时不得绕过；释放空间并按 runbook 重启 |
| `daemon.runtime.disk_low` | projected transaction 后无法保留 `max(512 MiB, filesystem 5%)` | 释放同一文件系统空间后以相同请求重试；该错误本身不永久 latch |
| `daemon.runtime.store_full` | main+WAL+SHM projected footprint、SQLite page budget，或剩余 safety obligation 接近/超过 2 GiB | 停止普通写；仅在安全写自身复核通过时完成终态并导出诊断，不要手工删除 WAL |
| `daemon.runtime.crypto_failed` | StorageKEK unwrap、row AEAD、blind token 或 generation 校验失败 | 视为 key/domain/tamper 故障；恢复原 Keychain item 和正确签名环境，禁止新建 KEK |
| `daemon.runtime.invalid_state` | stable ID/kind、clock monotonicity、queue head、fence/release、terminal/sequence 状态冲突，或 adapterStateKey 已绑定另一 namespace/不同 resume ref | 读取 canonical command/recovery/private-state 状态；错误 turn/nonce/fence 或 vendor ref 不能强制覆盖；CC 映射只能从明确 native history entry 重建，不按 title/cwd 猜测 |
| `daemon.runtime.execution_failed` | 已获 durable release 的 turn 在 adapter/vendor 执行期失败；event journal 只保存固定 `agent execution failed`，不持久化 vendor stderr、token、路径或 diagnostic reference | 以原 commandId/eventId 查询 durable Error 并按同 eventId exact replay；详细原因只查本机脱敏 diagnostic log，不把原始 vendor 错误补写进 Runtime event |
| `daemon.command.idempotency_conflict` | 同 conversation + stable owner + key 被不同 payload 重用 | 使用原 payload 查询原 command；新意图必须换新 key |
| `daemon.command.queue_full` | conversation 32、全机 1,024 或 queued payload 256 MiB 任一先到 | 等待/取消已有 Accepted 后以同一请求重试；满载时 exact replay 仍应成功 |
| `daemon.payload.item_too_large` | prompt、descriptor、intent/event/fence/result 超过各自硬上界 | 在进入 store 前缩小对应 item；不能切片成多个同 key 请求规避 |
| `daemon.runtime.recovery_too_large` | 单个 conversation recovery page 的 retained projection 超过固定 80 MiB | 视为 schema/cap 漂移或损坏并 fail-close；不能改用全库物化或复用 async lane budget，保留证据后核对 item hard limits |
| `daemon.command.queue_expired` | Accepted 到达 24 小时边界，已事务化为 Expired 并写 canonical event | 不自动重放旧 vendor 副作用；用新 idempotency key 发起新命令 |

P3.4 RuntimeCore 的 transport-neutral failure：

| code | 含义 | 下一步 |
| --- | --- | --- |
| `daemon.runtime.not_ready` | Core 尚未完成 paged recovery，或正在 draining/stopped | 等待 daemon readiness；若 recovery 无法完成，按上节保留 DB/Keychain 证据并 fail-close |
| `daemon.runtime.protocol_mismatch` | Runtime v1 版本不兼容 | 升级客户端/daemon 到同一 Runtime protocol；不能回退 Relay/IPC 业务字段 |
| `daemon.runtime.invalid_request` | ID 非 canonical UUID、Start key/cwd 或其他规范化输入非法 | 修正原请求；不得由 daemon 猜 ID/path 或替客户端补目标 |
| `daemon.runtime.feature_unavailable` | 请求属于尚未接线的后续 phase（P3.8–P4，例如 local transport/pairing/revoke/trust reset） | 读取 capabilities/实施状态后等待对应 phase；production execution 已进入 P3.7，Catalog/Subscribe/Backfill 已进入 P3.6，不应再用该 code 代替其真实错误；不得用 compatibility path 或 fake coordinator 假成功 |
| `daemon.authorization.revoked` | opaque principal lease 已 Revoking/Revoked 或 issuer registry 不可用 | 停止该 connection；remote 设备按 durable revocation/re-pair 流程处理，本地重新认证 peer credential |
| `daemon.runtime.identity_unavailable` | machine trust/ID derivation domain 非法或 OS entropy 不可用 | 停止启动并检查 machine identity/系统熵；不得生成零 ID 或使用时间/PID 回退 |
| `daemon.runtime.actor_unavailable` | conversation actor/execution control 已损坏或 recovery-blocked | 不自动重放 Started；保留 command/fence 证据，P3.7 按 orphan fencing 处理 |
| `daemon.runtime.connection_unavailable` | connection 不存在、writer lagged、transport 未 ACK flush 或编码失败 | 仅重连当前客户端，并按 commandId/idempotency 查询 durable receipt；不得假定未执行 |
| `daemon.runtime.read_unavailable` | 独立 ReadPool 已满或关闭 | 有界退避后重试读取；不要创建更多等待 task，副作用请求仍以 durable receipt 为准 |
| `daemon.runtime.recovery_blocked` | Started 的已知 PGID 内 cooperative descendants 无法在 TERM→KILL/reap 后证明退出，binding/fence readback 不一致，或 P4 前存在 remote Accepted | 只隔离对应 damaged conversation；保留 DB/fence/process 证据并人工清理。remote Accepted 属全局启动拒绝，P4 durable auth readback 前不得安装任何 actor。该 code 不表示 daemon 已检测到流程外自守护/逃逸进程 |
| `daemon.turn.stale` | CancelQueued 已输给 Started，或 CancelActive 的 turnId 不是当前 turn | 查询精确 CommandStatus；对 Started 只使用返回的当前 turnId 明确 cancel |
| `daemon.runtime.legacy_execution_disabled` | production stdio 收到旧 `SessionStart`/`SessionContinue`，该路径会绕开 typed RuntimeCore/exec-gate | 改用 P3.8 RuntimeEnvelope v1；P3.7 过渡期 production stdio 只保留 admin/read compatibility |
| `daemon.runtime.legacy_history_mutation_disabled` | production stdio 收到旧 rename/archive/history write | 等待对应操作迁入 typed RuntimeEnvelope；不得回退 legacy adapter spawn 或私有 vendor history mutation |

P3.7 exec-gate 的以下 code 是内部 typed 分类码。`--exec-gate` one-shot 自身失败时会把 code 写到
stderr，私有 ADGX abort frame 也可携带 code；但当前 parent/runtime 不保证把每个子码写入
`diagnostic.log`，部分路径只对上层暴露 `daemon.exec_gate.rejected` 或统一的
`daemon.runtime.execution_failed`。因此不能把下表描述成“结构化本机日志已完整覆盖”。Runtime event
不得写入 program/path/token/原始 stderr：

| code | 含义 | 下一步 |
| --- | --- | --- |
| `daemon.exec_gate.control_unavailable` | 固定私有 FD 不存在、读写/flush 失败 | 停止 execution；核对 current-binary spawner 的 FD3 dup/close-on-exec，不回退 argv/env 传 secret |
| `daemon.exec_gate.invalid_frame` / `daemon.exec_gate.version_mismatch` | ADGX magic/version/tag/长度/trailing 或字段上界非法 | 视为 binary/version mismatch 或内部篡改；升级为同一 daemon candidate，不尝试宽松 JSON/stdio fallback |
| `daemon.exec_gate.invalid_binding` / `daemon.exec_gate.release_mismatch` | command/boot/nonce、PID/start-time、PGID、release token/commitment 或时间不精确匹配 | 不发送第二次 release；关闭 control FD、清理 exact group，并按 Interrupted/RecoveryBlocked 收口 |
| `daemon.exec_gate.process_group_failed` / `daemon.exec_gate.process_group_not_exited` | 无法建立独立 PGID，或 TERM→KILL/reap 后仍不能证明已知 PGID 内进程退出 | 禁止恢复同 conversation 的 Accepted queue；保留 PID/start-time/PGID 证据，人工清理后再恢复 |
| `daemon.exec_gate.entropy_unavailable` | release token 随机源不可用 | 停止启动 vendor；检查系统熵，禁止常量/时间/PID 回退 |
| `daemon.exec_gate.spawn_failed` / `daemon.exec_gate.handshake_timeout` / `daemon.exec_gate.rejected` | current daemon binary 无法 spawn，5 秒 handshake 超时，或 child 明确拒绝 prepare | 核对当前签名 binary、固定 vendor 安装目录、daemon version 与资源上限；不要调用 legacy adapter spawn。typed disposition 确认未创建 child 时直接 Interrupted，不能误标 RecoveryBlocked；只有 identity/清理不确定时才 fail-close |
| `daemon.exec_gate.exec_failed` | release 后最终 `execve` vendor 失败 | 该 turn 按已越过 release 的 unknown outcome 处理；查询本机诊断并修复固定目录中的 vendor binary，不自动重放 prompt |
| `daemon.exec_gate.wait_failed` | child wait/reap 失败 | 先按 exact PID/start-time 复核已知进程组；无法证明同组进程退出则 RecoveryBlocked，不把 terminal event 当作已 fenced。release 前也必须由 prepare 起唯一 reaper 消费 child，不能把 zombie sentinel 当成存活进程 |
| `daemon.cli.exec_gate_mode_conflict` | `--exec-gate` 与 profile/data-dir/ephemeral/diagnostics/probe/help/version 等普通 CLI flag 混用 | 只允许 current-binary spawner 以独占 `--exec-gate` + 私有 FD 启动；不要手工拼普通 daemon 参数 |

vendor program 只从 `/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin`，以及 macOS
由 `getpwuid_r(geteuid())` 取得的当前 OS account `~/.local/bin` 解析 basename；不读取继承 HOME/PATH。
该集合及其中预期 binary 是流程外信任根；同一 OS account 主动替换被信任 binary 超出 exec-gate 的
证明边界。`claude` 只装在其他目录时，production typed prepare 会返回 `cc-binary-not-found`；应把
发行所需 binary 安装/链接到受信目录，不能临时把项目目录加回 PATH。

PGID 诊断只覆盖不主动 `setsid`/`setpgid`、不通过 `launchd`/launch service 或其他 supervisor 脱离
继承 PGID 的 cooperative vendor/tool descendants；此边界内仍保证 release 前零 vendor/tool 副作用与
同组 TERM→KILL/reap。显式自守护/逃逸是流程外不支持行为，当前机制不声称检测、枚举、收割或以
`RecoveryBlocked` 报告它。若工具必须采用这类执行模型，应停用当前执行路径并另行使用真正执行域隔离。

### P3.5 approval / authorization / delivery 诊断

P3.5 的正常状态转换以 `ApprovalReceipt` 为主，不应把业务回执误报成 transport 失败：
`Claimed` 表示本决定赢得 first-wins CAS；`Applied` 表示 adapter 已完整 write+newline+flush；
`DeliveryFailed` 表示赢家仍被密封保存、自动投递已停止，可由有 retry 权限的 client 显式重试同一
决定。`AlreadyHandled` 必须携带原赢家和当前精确 Claimed/Applying/Applied/DeliveryFailed/Expired
状态。没有赢家的 Pending expiry 单独返回 `Expired`；已经 claim 的 expiry 返回
`AlreadyHandled(winner, Expired)`，两者不能混写。

| failure code / 状态 | 常见原因 | 下一步 |
| --- | --- | --- |
| `daemon.authorization.permission_denied` | principal 仍 Active，但没有本次 Resolve 或 Retry 的显式 approval permission；本地 transport 也不自动获得权限 | 保持原 approval 不变；核对 issuer capability/grant，不要用 `is_local`、connection 类型或 owner 绕过 |
| `daemon.approval.already_handled` / `AlreadyHandled` | 另一个 writer 已先 COMMIT winner，或同一 winner 的 exact retry 读到后续状态 | 以回执中的 winner+state 为准；不要换 idempotency key 或提交对立 decision 争抢第二次 |
| `daemon.approval.delivery_failed` / `DeliveryFailed` | 8 次/60 秒预算耗尽、明确永久拒绝，或 write/flush/route 结果为 `OutcomeUnknown` | 不自动重投；查询 durable receipt 后，只能调用 `RetryApproval` 重用 sealed winner 开新 round |
| `daemon.approval.expired` / `Expired` | 默认 30 分钟或更短 capability deadline 到达，或 turn terminal 原子关闭 active approval | Pending 无 winner；已 claim 必须读回原 winner+Expired。deadline 不会向 vendor 合成 Deny；matching active turn 经 exact fence 后以 Interrupted 收口。重新执行用户意图需要新 ActionRequest，不能复活旧 approval |
| `daemon.runtime.store_unavailable`（approval/terminal COMMIT unknown） | Register/Claim/Retry/Begin/Applied/DeliveryFailed/Expired 或 terminal+expiry 的 after-COMMIT 回执丢失、SQLite outcome 不明 | 只在回报的 operation 与当前 mutation 匹配时，用完全相同的 approval/attempt/decision/completion stable input 精确重试；不匹配或其他错误直接 fail-close。AppliedAck 后禁止再次调用 adapter；已提交 terminal 必须重放为 Completed/Replayed 后再清 route 与启动 successor |
| `daemon.runtime.recovery_blocked` | 重启读到 Started turn 及 Applying/DeliveryFailed approval，但 process group 尚未被 P3.7 exec fence 证明退出；当前 delivery generation 在 adapter 已返回后无法 durable 写入唯一终态，产生 `FatalClosure`；或 approval expiry 已 fence 但 10 秒内 daemon terminal pipeline 仍未收口 | 停止并清理全部进程内 delivery/deadline/execution task，但保留 durable Started/approval 原状；不得自动恢复投递、写伪造的 Interrupted 或启动后续 Accepted。`FatalClosure` 也不得把仍为 Applying 的 row 当作可重投 route |

schema v3 的 `approval_ledger`、row AEAD/metadata MAC、`approval_count` 与
`active_approval_count` ledger MAC 会在 open/recovery/readback 时一起验证。deadline、attempt、
decision token、last event linkage 或 count 任一被改写，都按 corrupt state fail-close；不要直接
编辑 SQLite 纠正数字。每个 active approval 已预留 1 MiB Safety obligation，因此普通注册可能因
DiskLow/SafetyOnly 被拒，而既有 approval 的 Applied/Expired/terminal+expiry 仍应尝试安全收口。
若 safety 写也失败，保留 main/WAL/SHM 和诊断，不要删 WAL 腾空间。

open/recovery 的 approval 审计按全部 conversation 分批，单批 compact projection 上限 16 MiB；
完整 request 只留 32-byte keyed digest，event chain 按 `eventSeq` 常量空间归约。若启动期内存随
历史 approval payload 或 manual-retry 次数线性暴涨，应视为完整性扫描回归；不要通过调高进程
内存限制掩盖。零 approval row conversation 中出现认证的 ActionRequest/ApprovalResolved 也必须
作为 orphan fail-close。

BeginApprovalAttempt COMMIT 成功或 exact replay 并不自动授权 adapter 调用：worker 随后还会刷新
单调时钟，并以持久化的 deadline、round start 与 last attempt 坐标重新判定。刷新后已经到达或
越过 deadline 时只写 Expired；越过 round budget 时只写 DeliveryFailed，adapter 调用数必须保持
不变。store 自身还会在 preflight 与事务内 authenticated reload 后各校验一次持久化时间线；任一
读取早于 `max(stateChanged, roundStarted, lastAttempt)` 都返回 ClockRegressed，row/event 不变且不
签发 permit。排查“deadline 附近仍执行一次”的问题时，优先保留 Begin event 与这些时间坐标，
不要只看 COMMIT 前的内存时钟。

Codex route 只有完整 flush 后才算 Applied，失败时保留精确 route。P3.7 canonical Claude Code driver
使用 `--permission-prompt-tool stdio`，只接受已录制验证的 stdio
`control_request/control_response`，并只通过 canonical capability builder
广告 Approval；legacy compatibility builder 对 speculative permission wire 仍隐藏该能力。P3.5 的
private fake 与 P3.7 筛选 fixture 都不是 live vendor 证据；未经 exec-gate 或不符合 recorded control
shape 的 CC approval 必须 fail-close。

approval 卡必须显示可判别的最小动作摘要，而不是只显示“请求执行命令/编辑文件”。摘要只允许来自
translator 已验证的动作字段，并经过固定 source pre-cap、secret redaction 与 UTF-8 限长。Codex 自由
文本必须显示为保留换行/控制符边界的 JSON 字符串，无法完整显示时拒绝；CC 才折叠控制字符并截断。
若看到 permission suggestion、blocked path、未选中的 CC input 或完整 vendor JSON，立即按 durable data
boundary 泄漏处理。Codex file approval 必须能用 `itemId` 关联同一 in-flight fileChange 的非空 proposed
changes；`grantRoot/reason` 只是可选上下文。Codex `codex-item-kind-mismatch` 表示 completed frame 与
started kind 漂移，
`codex-shell-terminal-status-invalid` 表示 `inProgress`、未知或缺失 terminal status；两者都必须保留
in-flight state，不能降级为 Completed。Claude Code Shell 的 `exitCode=null` 是“wire 未提供权威退出码”，
不是成功码 0；成功/失败只看 typed `ShellStatus`。

`codex-approval-action-missing`、`codex-approval-summary-too-large`、`cc-control-action-invalid` 与
`cc-control-tool-unmodeled` 都表示 daemon 无法向用户完整展示将被批准的具体动作；这类请求不会注册
durable approval，也不能退回泛化 summary。Codex permission profile 必须先通过与 response builder
相同的官方字段 validator，再以完整 compact profile 进入脱敏 summary；只含 scan depth、空对象、未知
字段或超过 1 KiB 都拒绝。排查时不要把 raw params 打进日志；route/output Debug 已固定脱敏。

### P3.6 stream / snapshot / transfer 诊断

Catalog、Subscribe、Backfill 与 Unsubscribe 已由 P3.6-C 提交 `694f2d9` 接入 transport-neutral
RuntimeCore，不再返回 P3.6 `FeatureUnavailable`。正常 barrier 顺序固定为
`snapshot/backfill → SyncComplete → catchup/live`；若已经 flush 任一 snapshot/backfill/TransferPart
后发生错误，daemon 会 fail-close 当前 connection，绝不再发送可能与客户端已见前缀矛盾的 terminal
Failure。客户端必须重连，并用 durable inner cursor/新的 snapshot 重新建立 generation，不能在原
connection 猜测续传成功。

| failure code / 状态 | 常见原因 | 下一步 |
| --- | --- | --- |
| `daemon.runtime.read_unavailable` | subscription/barrier/snapshot sender、pending capture（4/connection、128/global）或 one-shot Catalog quota 已满；absolute 5 分钟 barrier/cursor TTL 到达；catalog cursor 无效/跨 principal/跨进程；cursor ahead、snapshot-required、stale generation；read-only WAL pool 或 snapshot build 128 MiB 不可用；authenticated snapshot/backfill decode 失败 | 对 overload 有界退避；expired/invalid cursor 重新发 fresh Catalog/Subscribe；reply message 为 `retained range requires a new snapshot` 时重新取 fresh snapshot，不能要求 partial backfill，也不要虚构独立 `daemon.stream.*` code；保留同一 durable inner cursor，不增加无界 waiter。若相同 frozen reference 持续失败，保留 DB/WAL/SHM 并按 schema/crypto corruption 处理 |
| `daemon.runtime.connection_unavailable` | paced writer reserve/commit/flush 失败，或 TransferPart 已部分交付、客户端未 ACK | 只关闭并重连当前 connection；从最后已完整应用并持久化的 inner cursor/snapshot 恢复。不得把 transport close 当作 command 未执行或 transfer 已完整应用 |
| `daemon.runtime.store_unavailable` | StoreCommitHub authenticated readback、snapshot store、backfill pin completion、publication freeze/COMMIT/ACK 或 cleanup 的 SQLite outcome 不可确认 | 对带 stable input 的 store mutation只重试原输入；subscription 重新建 barrier。不要手工删除 TEMP/stream/snapshot/publication row，也不要把 frozen-but-uncommitted outer cut 当成 Relay-committed |
| `daemon.runtime.invalid_state` / `daemon.runtime.invalid_request` | Runtime request 的 ID/target/shape 非法，或 authenticated store state 与请求绑定不一致 | 修正原 request；不得由 daemon 猜 target/ID，也不能手工改 store state 强行接受。snapshot-required/cursor/stale generation 属于上面的 read failure，不要合并成通用 invalid request |

Catalog page cursor 使用进程内随机 HMAC key，绑定 snapshot、principal、下一 keyset position 与 absolute
5 分钟 expiry；daemon 重启后旧 cursor 必然失效，这是恢复语义，不是 durable cursor 损坏。每个 frozen
catalog cache 只保留一个可替换 expiry task；反复读取不会为同一 snapshot 累积 sleeper。若 cache/budget
在失败后没有释放，优先核对 disconnect/expiry job 与全局 128 MiB shared snapshot budget，不要延长 TTL
或改成无界缓存。

conversation snapshot 的 exact TEMP build pin 与 shared build permit 会跨已入队 Store command 保存。
caller disconnect/cancel 只停止观察，不会让 worker 尚持大 payload 时提前归还预算；store failure 进入
无 deadline terminal flush wait 前必须先丢弃 retry payload、pin 与 permit。看到 barrier 卡住时，应区分
“worker 仍在完成已接管 store”与“terminal frame 未 ACK”；不要并行启动第二个大 snapshot 绕过全局
128 MiB 上界。barrier TTL/前置错误进入 terminal wait 前还会 exact release live/barrier/
snapshot-sender registry quota；若 terminal Failure 一直未 ACK，保留的只能是 terminal writer job，
不能继续占用上述 registry quota。若出现 `runtime_subscription_quota_release_failed`，说明 exact lease
release 的 registry mutex/状态异常，daemon 会 fail-close 当前 connection；保留该诊断与同进程 DB/WAL/
SHM，不要绕过 registry 手工释放计数。quota 已释放后，resubscribe/Unsubscribe/disconnect 取消旧
terminal wait 是正常 generation handoff，不应产生 `daemon.runtime.connection_unavailable` 或误杀新
generation；若仍出现，保留 subscription generation 与 writer flush 诊断按 race 处理。
pre-delivery error 的 terminal Failure 在 flush ACK/cancel 前继续持有 per-connection egress gate；若
同 connection 的 sibling 在 terminal 未 ACK 时出现 paced reservation slot conflict，说明 gate
ownership 提前释放，应按并发 race 保留 writer/flush 证据，不能简单扩大 writer slot。
subscription `commit` 应在登记可取消后台 job 后立即返回；激活锁序是 `egress → coordination`，
teardown 只在 coordination 内 detach/cancel，释放锁后再等待 handle。若 disconnect、Unsubscribe 或
shutdown 卡在未 ACK terminal 上，或 Core operation 自身等 socket gate，应按 job registration/锁序
回归处理，不能用 terminal flush deadline 或 detached task 规避。

同 target replacement 只给最新 generation 发 receipt/snapshot/sync；被 supersede 的 pending request
不会收到 stale receipt。未来 P3.8/P4 客户端发出 replacement 时必须同步取消旧 request waiter，否则
旧 waiter 会永久等待一个按 contract 不再发送的回执。若日志出现旧 messageId 的迟到 receipt，或
disconnect 已胜出后 pending-slot map 被 stale prepare 重建，应保留 generation/messageId 与
coordination gate 时序；不要提高 4/connection、128/global 上界来掩盖 race。
StoreCommitHub 同样在 oneshot reply 前把 backfill/snapshot pin 交给 cleanup owner；receiver/caller
在 reply 交接窗口取消时，pin 应由该 owner 自动释放。出现 pin 长期占用时不要手工删 row，先核对
`pin created -> cleanup bound -> oneshot send` 的顺序与对应 worker diagnostic。

P3.6 publication 只接受测试注入的 opaque/fake sealed blob，验证 freeze/COMMIT/ACK/restart 算法。
当前 daemon 没有真实 MachineDataSign/E2EE seal、CounterGuard 或 Relay Publish；任何日志/报告把
fake blob、Runtime TransferPart 或 Simulator fixture 写成远程密文已发布，都属于阶段状态错误。
transfer reassembly 当前仍是 bounded component API，duplicate/metadata/hash/length/TTL/配额冲突返回
typed `TransferError`；`TransferStateMachine` 与 publication dispatcher 都没有 production remote owner。
在 P4/P5 把它们接入真实远程收发前，不要虚构新的 production wire failure code 或 WSS 诊断。

P3.3 canonical adapter 边界的错误不会携带 raw resume reference：

| code | 含义 | 下一步 |
| --- | --- | --- |
| `adapter-state-not-configured` / `adapter-state-invalid-key` / `adapter-state-not-found` | canonical adapter 未注入 singleton store、key kind 错误或私有映射不存在 | 核对 daemon composition 与 catalog；禁止退回客户端提供 ThreadId |
| `adapter-state-vendor-id-forbidden` | canonical CC start 收到客户端指定 native session id | 删除该字段，让 daemon 生成并先持久化随机 UUID |
| `adapter-state-native-not-materialized` | CC 私有映射存在，但本机没有唯一、可 `O_NOFOLLOW` 打开并有界读回的 regular/non-memory 有效 JSONL | fresh home 缺少 projects root 时继续复用原 `--session-id`；歧义、打不开、空或 malformed JSONL 均 fail-close，不按 title/cwd/mtime 猜测，必要时走显式 native import 或新 conversation |
| `codex-thread-id-mismatch` | Codex resume response 或后续 frame 缺失/携带与私有映射不同的 thread id | kill 当前 child 并保留原映射；不得接受缺 ID response，也不得用观察到的新值覆盖 |
| `adapter-state-initial-prompt-required` | canonical CC 新建没有首个 prompt，无法形成 authoritative native init | 只创建 catalog；首个 prompt 到达后再启动 adapter |
| `adapter-raw-event-blocked` / `adapter-raw-history-blocked` | vendor translator/history 产生未建模 Raw frame | 不向 Runtime/Relay 透传；先补 typed translator/schema 与脱敏测试 |

`machine_enrollment_receipts` 仅用于 root-lost 时定位 old route/root fingerprint；它是刻意保持
非秘密、未加 MAC 的 rescue locator，不是授权凭据。P4 trust-reset/purge 必须另验
Relay/admin-signed receipt；该表被改写时不得据此直接删除远端状态。行 MAC/ledger 能检测局部
篡改，但整套 main+WAL 回滚到更早且内部自洽的快照，要等 P4 Keychain CounterGuard 绑定后才
能检测；P3.2/P3.3 诊断不能声称覆盖该攻击。

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

上段描述的是 legacy compatibility translator。P3.7 typed production driver 的 durable Runtime 路径更
严格：`init`、hook 生命周期，以及 2.1.207 已核实的 `status`、`task_started/task_progress/`
`task_notification/task_updated`、`background_tasks_changed` 和 top-level `tool_progress` 先校验当前
shape，再作为非持久化控制/进度帧消费；未知 subtype 或已知 method 的 shape 漂移仍 fail-close。它不产出
Raw、VendorPanel 或原始 stderr event。typed CC Bash `tool_result` 没有权威工具耗时，因此 canonical Shell
固定 `duration_ms=None`；本机解析间隔和 turn-level `result.duration_ms` 都不能冒充单个工具 duration。
`result` 只有在 `subtype=success`、`is_error=false`、`duration_ms` 为有效非负整数、
`terminal_reason=completed` 且没有非空 `deferred_tool_use` 时才产生 TurnComplete；`tool_deferred` 等结果
不会被伪造成 Completed。

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
| `cc-session-id-mismatch` / `cc-session-id-missing` | startup/init 的 native session 与私有映射不同，或 authoritative init 缺 ID | daemon 会 kill child 并 fail-close；保留本机诊断，检查 CC CLI 版本/参数语义，不覆盖私表 |
| `cc-session-identity-eof` / `cc-session-identity-timeout` / `cc-session-identity-read` / `cc-session-identity-too-large` | CC 在 authoritative init 前退出、超时、I/O 失败或超过 256 lines/2 MiB handshake 上界 | 不接受该 turn；检查 hooks/CLI stderr/资源状态，再以原 idempotency input 由 RuntimeCore 裁决是否可重试 |
| `cc-session-startup-status` | daemon 无法读取 CC child 的早期退出状态 | 按本机进程/权限故障处理，不发布 canonical started/capabilities |
| `cc-binary-not-found` | typed prepare 在固定系统目录和当前 OS account `~/.local/bin` 都找不到 `claude` | 把官方 CLI 安装/链接到上述受信目录；不要修改 daemon 继承 PATH 或从项目目录执行同名文件 |
| `cc-system-frame-unmodeled` | typed Runtime 收到当前封闭 allowlist 之外的 system subtype | 保留筛选后的本机诊断并核对 CC 版本；在 typed schema/持久化建模前不得回退 Raw/VendorPanel 透传 |
| `cc-system-frame-invalid` / `cc-tool-progress-invalid` | 已知 lifecycle/progress method 缺少 2.1.207 必需字段、类型或使用未知 task patch 字段 | 视为 vendor wire 漂移并终止该 turn；先用脱敏真实样本和当前 SDK contract 更新封闭 validator，不能直接静默忽略 |
| `cc-turn-terminal-invalid` / `cc-turn-not-completed` | success result 缺精确布尔/耗时/terminal reason，或仍带 deferred tool work | 不写 Completed；保留本机脱敏 shape 诊断，确认 CLI 是否仍有后台工作或协议已升级 |

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
