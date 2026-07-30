# AgentDeck Agent Diagnostics

本页给没有历史上下文的 agent 使用。目标是在 5 分钟内判断 AgentDeck 当前是否能记录、诊断和复验问题。

## 快速入口

```bash
swift run AgentDeck -- --selfcheck
swift run AgentDeck -- --diagnostics-report --json
swift run AgentDeck -- --diagnostics-report --json --profile dev
cargo run -p agentdeckd -- --ephemeral --no-remote --profile dev --selfcheck
agentdeck remote machine status
agentdeck remote machine enroll --bundle-file /secure/path/machine-enrollment-bundle.json
agentdeck remote trust-reset
agentdeck remote trust-reset --admin-purge-receipt-file /secure/path/admin-purge-receipt.json
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

排查 P3.1 历史 compatibility/test-only stdio 实例时，显式 legacy harness 固定把 child 启动为
`--stdio-compat --ephemeral --no-remote --profile dev`，并删除继承的 `AGENTDECK_DATA_DIR` /
`AGENTDECK_PROFILE`；每次 spawn 都是新的 temp namespace。当前 Rust CLI 与 Swift `--selfcheck` 默认入口
不再启动该 child，也不能用 `--profile dev` 把 Runtime 自检切回开发 namespace，而是始终连接 current-EUID
stable UDS。diagnostics report 不启动 daemon，仍可用 `--profile dev` 或 `--data-dir` 读取旧日志；不要把
diagnostics override 当成 stable ownership 配置。

## Relay Web Test Companion W0–W3.7 failure codes

W0 页面与 Playwright harness 只验证 browser storage/locking 可行性，尚未连接 Relay。以下 code 只在本地
测试 host 中出现；它们不进入 daemon diagnostic log，也不能解释为远端业务失败：

| code | 含义 | 下一步 |
| --- | --- | --- |
| `web.remote.storage.invalidProfileId` | 测试 profile 不是 1–64 位小写字母、数字或连字符 | 修正测试隔离 ID；不要把用户输入或路径直接当 DB 名 |
| `web.remote.storage.invalidActualRevision` | IndexedDB 中的 revision 不是非负 safe integer | 删除本轮隔离测试 profile 后重跑；真实实现进入 W2 前必须 fail-close 并保留取证 |
| `web.remote.storage.revisionConflict` | current revision 与 expected 不同，出现 stale/sibling writer | 当前 transaction abort；重新读取唯一 current state，禁止 blind overwrite |
| `web.remote.storage.nonExactNextRevision` | next 不是 `expected + 1` | 修正 state owner；不能跳号、回退或提交 sibling revision |
| `web.remote.storage.stateMissing` | CAS 前没有初始化 state record | 重新执行本轮 fresh profile 初始化；不能在 CAS 中隐式创建 paired state |
| `web.remote.storage.kekCloneFailed` | non-extractable `CryptoKey` 未能从 IndexedDB structured clone 读回 | 当前 Chromium 不满足 W0；停止 W1/W2，不得回退 extractable key 或明文 secret |
| `web.remote.cleanup.unexpectedArtifacts` | PASS 后 Playwright output 除 `.last-run.json` 外仍有 trace/screenshot 等 artifact | 保留目录排查为何成功用例仍产出 artifact；不要让 cleanup 按目录递归删除证据 |

W1 额外使用以下本地 test-host code；它们同样不进入 daemon diagnostic log：

| code | 含义 | 下一步 |
| --- | --- | --- |
| `web.remote.origin_invalid` | WASM core 拒绝非 root WSS、带 credential/path/query/fragment 或非法端口的 origin | 只传固定 `wss://host:port/`；`/v2/connect` 必须由 WASM 选择 |
| `web.remote.server_identity_mismatch` | Challenge 中的 Relay server identity 与预期不一致 | 立即终止本 generation；核对 fresh Relay 的只读 server id，不发送 Authenticate |
| `web.remote.handshake_rejected` | Challenge/signature 篡改或 Relay 拒绝 Authenticate | 保留 typed stage/code；不得自动降级、重放或继续发布 |
| `web.remote.single_flight` / `web.remote.generation_stale` | 同页已有 active connection，或旧 generation 回调到达 | 关闭并 join 旧 socket 后再建新 generation；旧回调不得推进状态 |
| `web.remote.connect_failed` / `web.remote.connect_timeout` | TLS/WSS endpoint 不可达或 connect deadline 到期 | 核对本轮 Relay PID、端口、证书/SPKI；不要改用 `ws://` 绕过 |
| `web.remote.text_frame_rejected` / `web.remote.frame_too_large` | Relay 收到非 binary 或超过 4 MiB 的 frame 并关闭连接 | 修正 host 发送边界；确认 SQLite frame count 未增加 |
| `web.remote.replay_rejected` | 已完成鉴权后重放 Authenticate，被 Relay 拒绝 | 这是预期负例；确认连接未产生 sealed business frame |
| `web.remote.sentinel_not_accepted` | 有界接收窗口内未见精确 stream receipt | 检查 Relay route/store 日志与 generation；不得仅凭 Authenticated 宣布 W1 PASS |
| `web.remote.cleanup.unexpectedArtifacts` | PASS 后仍有 trace/screenshot/test result | 保留失败证据定位；成功收口必须让 `test-results/` absent |

W2a 的 pairing core 使用以下 code。它们只证明 automatic 浏览器配对切片，不代表 paired state 已经可跨 reload
恢复：

| code | 含义 | 下一步 |
| --- | --- | --- |
| `web.remote.pairing.invite_invalid` | PairInvite 非 canonical、过期、TTL/URL/identity 绑定非法 | 停止在本地 inspect；重新从被控 Mac 生成邀请，不建立 WebSocket |
| `web.remote.pairing.root_fingerprint_mismatch` | 用户确认值与完整 MachineRoot fingerprint 不逐字相同 | 保持确认前零网络；重新核对带外 fingerprint，禁止短码或模糊匹配 |
| `web.remote.pairing.state_invalid` | Hello/PairingHello/frame 在错误 phase 调用或发生重放 | 关闭当前 generation；不得跳阶段、补发或用 transport 状态伪造 paired |
| `web.remote.pairing.handshake_rejected` / `relay_rejected` | `/v2/pair` 未返回有效 Authenticated，或 Relay 拒绝 route | 保留本轮邀请与 host 证据；核对 Relay identity、route expiry 和唯一 pairing writer |
| `web.remote.pairing.frame_invalid` / `route_mismatch` | PairData carrier、request hash、route 或 terminal 不匹配 | 视为安全失败并关闭 generation；不产生 grant promotion 或业务连接 |
| `web.remote.pairing.crypto_failed` | PairPending/PairResponse 的 HPKE、签名、证书、grant/authorization/key directory 任一验证失败 | 丢弃本轮内存材料；不得把裸 response 或部分字段降级为 paired state |
| `web.remote.pairing.entropy_unavailable` | browser WASM 无法取得三组独立随机 seed | 确认后仍停止在网络前；不得使用固定 seed、Math.random 或 TypeScript 私钥生成 |
| `web.remote.pairing.outcome_unknown` / `web.remote.pairing.timeout` | restart、AlreadyAbsent、EOF 或 deadline 前没有 matching Closed | W2a 不宣称成功；W2c durable recovery 接入前只能重新执行 fresh automatic run |
| `web.remote.pairing.serialization_failed` | 脱敏 preview/evidence 无法序列化 | 关闭测试页并调查 Rust view model；不得把 raw wire/crypto bytes交给 UI 兜底 |

W2b paired principal 使用以下 code；它们仍只属于本地 automatic test companion，不进入 daemon diagnostic log：

| code | 含义 | 下一步 |
| --- | --- | --- |
| `web.remote.business.state_invalid` | principal 尚未 promoted、已有 pending request，或 list/open/prompt/approval 调用顺序非法 | 关闭当前 generation，从 fresh W2a 配对重跑；不得跳过 subscription/barrier 或并发发送业务 request |
| `web.remote.business.handshake_rejected` / `relay_rejected` | `/v2/connect` challenge/auth 或 Relay route 被拒绝 | 核对同一 verified grant、Relay identity 与 active grant；不得改用新身份掩盖失败 |
| `web.remote.business.crypto_failed` | directed reply、stream publish、key/binding、nonce/counter、签名或 AEAD 验证失败 | 立即终止本 generation；保留脱敏 stage，禁止把 raw key/wire 导出给 TypeScript |
| `web.remote.business.frame_invalid` | Runtime reply、subscription snapshot/sync、bootstrap barrier、cursor、event identity 或 approval receipt 不符合当前状态 | 对照 Catalog/Conversation 两条流的 binding→barrier→semantic ACK→outer ACK 顺序；approval 首次 `Claimed` 是合法中间态，不能要求其直接 Applied |
| `web.remote.business.authorization_denied` | verified authorization 不含请求需要的 capability/permission | 停止业务 mutation，重新核对 W2a 请求与本机批准范围；不能由 UI 绕过权限 |
| `web.remote.business.outcome_unknown` | server restarting 或业务 outcome 无法在内存态 session 内确定 | W2c durable recovery 完成前，本轮不能算 PASS；fresh 配对重跑并核对 daemon ledger 是否已有副作用 |
| `web.remote.business.counter_exhausted` | request/counter/evidence 计数溢出 | 视为安全终态并停止发送；不得回卷、复用 nonce 或清零后续跑 |
| `web.remote.business.timeout` / `fence_retry_exhausted` / `fence_stage_invalid` | 有界窗口内业务未收敛，或 transition fence 超过 8 次/出现在非法阶段 | 读取脱敏 business evidence 定位 Catalog、Conversation、Prompt 或 Approval；不得用固定 sleep 或无限重试绕过 fence |

W2c durable recovery 继续使用以下本地 test-host code。它们描述浏览器 durable state 与恢复编排，不进入
daemon diagnostic log：

| code | 含义 | 下一步 |
| --- | --- | --- |
| `web.remote.durable.state_invalid` | Rust/WASM durable bytes 非 canonical、身份/授权/cursor/evidence 不一致，或恢复投影非法 | 停止联网并保留本轮隔离 profile；不能丢弃旧状态后静默重配对 |
| `web.remote.durable.commit_required` | promotion、counter reservation 或 state mutation 尚未由 host exact CAS 提交 | 先完成 IndexedDB transaction 和 revision readback；提交前禁止发送任何 frame |
| `web.remote.durable.not_prepared` | host 尝试激活尚未 prepare/export 的 durable state | 修正 promotion 顺序；不能把内存态 paired session 直接当作可恢复身份 |
| `web.remote.storage.kekInvalid` / `pairedStateSizeInvalid` | KEK 不是不可导出的 AES-GCM key，或 opaque paired state 尺寸越界 | fail-close 并保留取证；禁止 extractable key、明文 state 或无界 payload |
| `web.remote.storage.pairedPromotionConflict` / `pairedRevisionConflict` / `revocationConflict` | promotion、普通提交或 revoke cleanup 的 expected revision/terminal 条件不精确 | transaction 必须 abort；重新读取唯一 current record，禁止 blind overwrite 或 sibling 合并 |
| `web.remote.storage.revisionInvalid` / `pairedStateIncomplete` | revision 非 safe integer，或 paired record/KEK 缺一部分 | 视为损坏状态；停止自动恢复，不得猜测缺失材料 |
| `web.remote.storage.revokedMaterialPresent` | revoked tombstone 与 paired material/KEK 同时存在 | 视为安全失败并停止；不得选择任意一边继续连接 |
| `web.remote.storage.counterGuardInvalid` / `pairedStateInvalid` / `revokedStateInvalid` | counter guard、encrypted paired record 或 revoked tombstone 的 phase、revision、commitment、时间、IV/密文形状非法，或密文超过 256 KiB plaintext 上界加 AEAD tag | 保留隔离 profile，停止联网；不得无界解密、修补字段、伪造 revoked 完成或绕过 commitment/AAD 校验 |
| `web.remote.storage.counterGuardConflict` / `counterGuardFork` | durable stage 的 exact guard 已变化，或 paired state 既不是 pending previous 也不是 exact next | fail-close 且零 frame；对照 raw phase/revision/commitment，禁止自动合并 sibling/fork |
| `web.remote.storage.state_fork_quarantined` | `statePending` 观察到既非 previous、也非 staged exact next 的同 scope sibling/fork；已原子写入 `quarantined(stateFork)` | 预期为零 frame；保留隔离 profile 取证，不得用 revision +1 猜测、合并 sibling 或静默重配对 |
| `web.remote.storage.state_quarantined` | 冷启动读到已持久化的 state fork quarantine | 这是持续 fail-close 终态；只有显式撤销/清理流程可移除材料，普通恢复不得重新激活 |
| `web.remote.writer_locked` | 同 profile 的 Web Lock 已由另一 tab/worker generation 持有 | 保持零 load/mutation/send；等待显式交接或 owner 页面终止，禁止轮询写入或绕开锁 |
| `web.remote.writer_generation_missing` | 当前 tab 从未取得 profile writer generation，却触发 durable mutation/send | 视为编排错误并保持零 frame；先取得 Web Lock，不能仅凭 IndexedDB 可读就写入 |
| `web.remote.generation_stale` | generation 已 relinquish、关闭或收到新 owner 的 BroadcastChannel activation | 丢弃迟到 callback/frame；不得提交 state、推进 cursor/counter 或发送响应 |
| `web.remote.durable.writer_contention_probe_failed` | W3.3 探针未在锁拒绝/旧 generation 上保持 revision/guard 不变和零 frame | 保留隔离 profile 与 Playwright 证据；停止 W3，不能把单写者测试写成 PASS |
| `web.remote.test.chrome_pid_missing` / `chrome_cdp_timeout` / `chrome_exited` | W3.4 runner-owned Chrome 未取得主 PID、CDP 未就绪或在连接前退出 | 核对系统 Chrome executable、独立 user-data-dir 和端口；不能退回 Playwright 普通 close 模拟 crash |
| `web.remote.test.chrome_kill_timeout` / `chrome_already_terminal` | 精确 process-group `SIGKILL` 未在窗口内读回，或同一 managed process 被重复终止 | 保留 PID/PGID 证据并停止本轮；禁止按全局进程名杀浏览器或把 TERM/close 写成 crash PASS |
| `web.remote.durable.pending_business_checkpoint_incomplete` | prompt cut 冷启动未在 daemon restart 前完成原 pending approval 与 command | 保留 encrypted profile 和 host ledger；不能先重启 daemon 后把合法 `Expired` 改写或伪报为 Applied |
| `web.remote.test.fault_proxy_config_invalid` | W3.5 代理 listen/target/control/mode 不完整或越界 | 停止本轮；只允许 runner 生成的 loopback 端口、0700 control dir 与 disconnect/delay/relayRestart 三种 mode |
| `web.remote.connection_closed` / `connection_failed` | 透明代理切断 TCP，或真实 Relay restart 关闭当前恢复连接 | 查看 proxy byte/connection evidence 与 durable revision；disconnect 可由 bounded reconnect 收敛，Relay restart 的首轮必须保留 active material 后再恢复 |
| `web.remote.storage.counterGuardRecoveryFailed` / `pairedCommitmentMismatch` | Pending 收口后未读回 Stable exact state，或解密 plaintext 的 SHA-256 与 sealed commitment 不一致 | 停止旧 identity；保留 profile 取证，不能回退旧 revision 或重新配对掩盖 |
| `web.remote.durable.reconnect_timeout` / `recovery_timeout` | reload 后认证或 Catalog/Conversation recovery 未在有界窗口完成 | 读取 `recoveryStage` 与 host generation；不要用固定 sleep、无限重试或重新配对掩盖 cursor/gap 错误 |
| `web.remote.durable.revocation_terminal_missing` | self-revoke 后未验证 MachineRoot-signed terminal | 保留材料，不执行删除；directed receipt 或 socket close 都不能单独充当权威 terminal |
| `web.remote.durable.cleanup_readback_failed` | revoke cleanup 后没有读回 material/KEK absent + tombstone present + exact revision | 停止旧身份的任何重连并保留 profile 取证；不能只清内存或只删一层记录 |
| `web.remote.durable.revoked` | reload 读到 revoked tombstone，旧 identity 被本地拒绝 | 这是 revoke 后重连负例的预期终态；必须同时确认零 binary frame 与 Relay active grant `0` |

W2.7 不新增 wire failure code，而是用 `W2NegativeSnapshot` 对既有生产准入规则做 typed readback。运行
`scripts/run-relay-web-companion-e2e.sh --negative` 时，任一 snapshot 字段为 false 都表示相应拒绝路径发生了
mutation 或 admission 漂移：

| snapshot 轴 | false 时的含义 | 下一步 |
| --- | --- | --- |
| `approvalLoserRecognizedApplied` / `approvalLoserZeroClaimMutation` | 后到 `AlreadyHandled(Approve, Applied)` 未按 loser readback，或被误计为第二 claim | 运行 daemon machine E2E，比较 resolve/Retry 前后的 approval total/applied；禁止重写 idempotency key 再抢一次 |
| `stalePublishRejected` / `skippedPublishRejected` / `rejectedPublishCursorUnchanged` | outer sequence 接受了 stale/gap，或拒绝后 cursor 被推进 | 停止 generation；核对 binding cursor 的 exact-next admission，不补 ACK、不跳过缺帧 |
| `replyNonceReplayRejected` / `replyCounterSetUnchanged` | directed reply replay 被接受，或拒绝时消费了 replay slot | 检查 counter 是否只在验签、解密、Runtime 语义接纳全部成功后提交；不清空 set 重试 |
| `streamNonceReuseRejected` / `streamCounterSetUnchanged` | stream nonce reuse 被接受，或拒绝时污染 counter set | 同时核对 stream route + counter 复合键与 semantic admission；禁止仅凭 nonce prefix 推进状态 |
| `uncommittedReservationRejected` / `reservationOverflowRejected` / `rejectedReservationCounterUnchanged` | 未 durable COMMIT 或越过 high-water 仍可 seal/send，或拒绝后 command counter 改变 | 保持零发送，先读回 exact IndexedDB revision/reservation；不得回卷或临时扩大 high-water |

`W2BusinessEvidence.recoveryStage` 只记录脱敏阶段，不包含 wire、key、业务正文或 vendor 文本。典型值从
`recovery.state.restored`、`recovery.catalog.requested` / `recovery.conversation.requested` 推进到各流的
`subscription_receipt`、`backfill`、`sync_complete`、`stream_binding`、`epoch_barrier`、
`stream_applied_ack`、`replay_complete` 与 `subscription.active`；`recovery.frame.*` 用于指出最后收到的 outer
frame。它是定位线索，不是 PASS 证明；PASS 仍须读回两条 active subscription、exact counter/revision、host
计数、signed revoke terminal 与 cleanup。

W0 失败先运行 `bun run check` 和 `bun run test:browser -- --grep W0`。W1 失败用
`scripts/run-relay-web-companion-e2e.sh --contract` 区分 contract/ownership，再用 `--transport` 复现真实
Chrome→Relay 路径。W2a 失败用 `--pairing` 重放 fresh fixed-topology host，并以 runner 输出和 host NDJSON
区分 pre-confirm、pending、local approve、receipt/Closed 或 cleanup 阶段；W2b 失败用 `--business` 查看脱敏
Catalog/Conversation/Prompt/Approval evidence 和 host 精确计数；W2c 失败用 `--durable` 查看 exact
revision/counter、`recoveryStage`、daemon generation 与 revoked readback；W2.7 失败用 `--negative` 对照 typed
snapshot 与 daemon SQLite frozen counts；W3.1 失败用 `--crash-cuts` 确认具体 cut、
`reservationRecovery`、revision `4`、`512→768` 与注入后
零 frame。`pendingPreviousFinalized` 表示从 previous 完成 exact-next state 后 finalize，
`pendingNextFinalized` 表示只补 Stable，`stableExact` 表示无需写入恢复；任何其他状态都不能联网。
W3.2 失败用 `--state-cuts` 定位 state cut，或用 `--recovery` 同时回归两类 durable cut；
`statePendingPreviousRetried` 表示先回滚 guard 后重试同一 staged candidate，
`statePendingNextFinalized` 表示 paired state 已是 exact next、只补 Stable。sibling 负例必须读回
`quarantined(stateFork)` 与零 frame，不能把 quarantine 当作可恢复成功。
W3.3 失败用 `--contention`，同时核对第二 tab acquire、主 tab relinquish、peer invalidation、两次 late probe
和 paired revision/guard before/after；BroadcastChannel 只允许通知 generation，不得携带 canonical state。
W3.4 失败用 `--browser-kills`，核对 prompt/approval/reconnect cut、主 PID、`SIGKILL` readback、同一 profile、
revision/reservation 与 host exactly-once 计数。若第二次 recovery 停在 marker 之后，确认 durable
`restartMarkerObserved` 随 catalog cursor 单调保留，不能倒退 cursor 重放旧 marker。
W3.5 失败用 `--network-faults`，核对 proxy `parsedProtocol=false`、armed connection/byte count、delay 次数、
Relay generation 与 machine-link readiness。真实 Relay restart 后必须等 lifecycle active、catalog stream `1`、
transition `0`，不能用固定 sleep；proxy 关闭时不得丢弃尚在延迟队列中的 signed terminal。
W3.6 失败用 `--repeatability`；任一子轮失败后旧计数作废，必须从第一轮重跑。逐轮核对 candidate commit/tree、
W2b terminal、三种 crash cut、三种 state cut、两份 aggregate、plaintext 与 cleanup，不能用 3+3 数量替代 exact
cut覆盖。
测试结束必须停止静态 server、关闭 tab/profile、Relay/daemon 并删除本轮精确临时 root；cleanup 不使用
全局浏览器数据或全局进程名删除。

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

P3.9 Runtime v2 hard cutover 后，Runtime v1 TBS 签发的 persisted cert/grant、control
grant/revocation/retirement 都统一表现为 `relay.auth.invalid_grant`；旧 Link/Data cert 经公网
enrollment 统一表现为 `relay.enrollment.rejected`。不要根据通用 code 猜具体失败字段，也不要自动降级。
P4.2 曾 additive 升为 Runtime v3，P4.3 又升为 Runtime v4；P4.6 automatic Task complete的
current contract 已升为 Runtime v5，production 只接受 current v5。开发环境发现旧凭据时，
先用可信 Relay admin inventory 定位 realm：存在时执行 purge 并取得 portable signed receipt，不存在时记录
可信 absent 结果；随后只用本页 P4.2 本地 trust-reset 命令重新 enroll。不得手改 SQLite/Keychain 代替。

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
| `remote.persistent.unsupported` | 当前平台或 production identity/composition 不支持持久 remote；非受支持平台、unsigned/ad-hoc 或缺 entitlement/access-group 都可能触发 | 先区分签名、平台与 composition 前置；不要落 secret 文件、绕过签名或把 automatic injected PASS 当 production PASS。`watch` 已属于支持命令面，不得再以“命令未实现”解释该错误 |
| `/v1/connect` 返回 426 | 预期的无状态 migration tombstone | 升级到 v2；禁止自动降级或重试 v1 |
| synthetic 在 SPKI/CA/hostname 前失败 | server identity 未通过完整验证 | 核对证书、DNS、bundle 与 pin 轮换；不得改成明文或 pin-only |
| synthetic 返回 authentication terminal | signed revoke/retire 已成为当前终态 | 验 canonical terminal；临时身份直接丢弃，持久身份由 P4 状态机处理 |

P2.10 hardening suite 还必须证明 restart byte-identical replay、retention gap、quota、
disk-low、Store fault 与 deterministic shutdown；`agentdeckd` 同时继续通过
`scripts/check-daemon-network-boundary.sh`。这些证据只收口 Relay，不代表 daemon/iOS Companion
持久链路已经完成。

## Daemon namespace / singleton / StorageKEK 诊断（Companion MVP P3.1）

daemon 正常启动顺序固定为 `config → private namespace/singleton → keystore →
StorageKEK → record namespace → RuntimeCore → recovery permit → secure UDS`；只有完整显式 stdio
compatibility 三 flag 才以 admin/read loop 替代 UDS。前一步失败时不得继续打开下一层。
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
禁止把既有 stable state 偷换到 memory store。2026-07-18 已采用方案 b：MVP 接受完整
`--ephemeral --no-remote --profile dev` 与 dev/ephemeral Keychain 路径；这不等于 stable production
signing 已完成。P3.1 provisioned signed roundtrip 已移入 post-MVP BLOCKED 证据槽位：本机无匹配
provisioning profile，两个已通过 `codesign --verify` 的尝试均被 AMFI 以 exit 137 终止，ignored 测试
不是通过证据。P3 Phase automatic scope 已在该槽位精确保持
`BLOCKED/mutations=0/evidence=[]/summaryGenerated=false` 时完成；该槽位不阻塞后续 P4 主线，也不再尝试
本地绕过 AMFI，但不得因此把 stable production signing 记为 PASS。

| P3.1 code | 含义 | 下一步 |
| --- | --- | --- |
| `daemon.cli.missing_value` | `--profile` 或 `--data-dir` 缺值 | 补齐参数值，不要用环境变量替代 stable ownership |
| `daemon.cli.invalid_profile` | profile 不是 `stable` / `dev` | 使用受支持值，并同时满足下面的 mode matrix |
| `daemon.cli.unknown_argument` | daemon 收到未知参数；production `--socket` 也固定走此拒绝 | 核对调用方版本；不要把 Relay/client 参数或 socket path 注入 daemon |
| `daemon.cli.data_dir_forbidden` | daemon serve/selfcheck 尝试使用 `--data-dir` | 移除 override；它只允许 diagnostics one-shot |
| `daemon.cli.conflicting_one_shot_modes` | 同时传 selfcheck 与 diagnostics-report | 每次只运行一个 one-shot |
| `daemon.cli.diagnostics_startup_flags_forbidden` | diagnostics-report 带了 ephemeral/no-remote/stdio startup flag | diagnostics 不启动 daemon，移除 startup flags |
| `daemon.config.ephemeral_requires_no_remote` | 只启用了 ephemeral | 同时显式加 `--no-remote` |
| `daemon.config.no_remote_requires_ephemeral` | stable 尝试单独关闭 remote | 开发实例同时加 `--ephemeral`；stable 不允许半隔离 |
| `daemon.config.ephemeral_access_group_forbidden` | ephemeral config 携带 stable access group | 移除 access group；ephemeral 只能用独立 memory store |
| `daemon.config.stdio_compat_requires_ephemeral_no_remote` | `--stdio-compat` 没有同时显式携带完整 ephemeral/no-remote pair | 只允许 `--stdio-compat --ephemeral --no-remote`；默认 ephemeral 入口仍是 UDS |
| `daemon.config.dev_requires_ephemeral` | `--profile dev` 没有完整 ephemeral pair | 加 `--ephemeral --no-remote` |
| `daemon.config.stable_forbids_ephemeral` | stable profile 与 ephemeral 混用 | 二选一；不得把 stable 信任域当测试夹具 |
| `daemon.config.home_unavailable` | 当前 OS account home 缺失、为空或非绝对路径 | 修复系统账号记录；不要设置 `HOME` 绕过 |
| `daemon.config.home_lookup_failed` | `getpwuid_r` 查询 OS account 失败 | 记录系统 status，检查账号目录服务后重试 |
| `daemon.namespace.root_not_absolute` | hermetic/ephemeral root 不是绝对路径 | 使用 canonical absolute root |
| `daemon.namespace.invalid_instance` | instance ID 为空、过长或含非法字符 | 只用 1–64 位 ASCII 字母、数字、`-`、`_` |
| `daemon.namespace.socket_path_too_long` | UDS 路径超过平台 `sun_path` 上限 | 缩短 temp root；不要把 socket 移到 0700 namespace 外 |
| `daemon.namespace.socket_path_invalid` | UDS 路径含 NUL | 修复路径来源，禁止 lossy 转换后继续 |
| `daemon.namespace.unsafe_temp_root` | ephemeral `TMPDIR` final entry 不是实体目录、不是当前 UID、权限不是精确 0700，或 canonical identity 改变 | 创建并 canonicalize 当前用户独占的 0700 temp root；不要用 symlink、普通文件或共享 `/tmp` 直接启动 |
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
| `daemon.runtime.main_loop_failed` | security bootstrap 已完成，但 UDS listener 或显式 stdio compatibility 主循环失败 | 先按下方 `daemon.local.*` 子码检查入口/信号/I/O；guard/KEK 会随进程退出释放/清零 |

## Runtime SQLite / journal / adapter 私表 / Core 与本地客户端诊断（Companion MVP P3.2–P3.9-E）

P3.2/P3.3 error code 是 store 内部精确错误的稳定诊断归类；P3.4–P3.6 已把接入 RuntimeCore 的
路径映射成 wire `RuntimeFailure`，并增加 Core/principal/connection/read overload、approval
authorization、delivery 与 stream/snapshot 分类；P3.9-C0-B2 又接通 DescribeAgents、configuration CAS、
cursor-consistent snapshot 与 Core typed receipt，B3a 再接通 configuration-aware SendPrompt admission、
nonzero command pin 与 pinned revision receipt；B3b 再把 command-pinned exact configuration 送入
Store Start、Runtime execution context、两家 adapter argv/control 与 approval at-decision metadata；B4
再接通 managed rename/archive/unarchive 的 durable mutation ledger、entry/catalog revision 与
CatalogDelta 原子收敛。
B5 再通过真实 UDS 双 principal 与 shutdown/reopen 锁定 configuration/event 和 metadata/catalog 两条
revision 轴的独立收敛、owner-scoped idempotency、receipt/snapshot/backfill 一致性，以及 revoke、caller
cancellation、after-COMMIT unknown 下 authorization guard 与单次通知语义；B5 没有新增 production writer。
transfer reducer 仍只有 component-local typed
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
finish 会在开放 mutation 前重新执行完整 integrity readback；若 begin 后 artifact 已无法通过当前
KEK/database/domain 认证，finish 必须失败并保持 Recovering。该检查属于离线篡改 fail-close，不扩张为
对可 ptrace、替换二进制或读取进程内密钥的同 UID 在线攻击者的安全承诺。P3.10 Task 收口已删除同 UID
在线换路径测试；后续不要为该 residual risk 新增测试或诊断分支。

scan active 时 inspect 与 shutdown 仍可用；create/accept/start、fence/release/terminal/rescue
全部返回 `daemon.runtime.recovering`。这不是“读永远可用”：业务 recovery read 也受 exact
cursor/单 outstanding scan 限制。若 scan 无法结束，保留 DB/WAL/SHM 与 Keychain 原件后让
daemon fail-closed 退出，不要跳页、伪造 cursor 或删除 sidecar。

### Exact execution configuration 语义

Started command 的执行配置以 Accepted 时的 authenticated pin 为准，不以排队、重启或 recovery 时的
current configuration head 为准。Store 必须在同一 SQLite transaction 读取 command/pin，认证该
conversation 完整 `1...head` configuration chain，再选择 pinned historical revision；目标行存在但链的
中间行、tail、event anchor、agent kind 或 vendor variant 无法认证时，都要在 adapter spawn 前
fail-close。排查“receipt 是 rev1、argv/control 却像 rev2”时，应保留 DB/WAL/SHM 与 StorageKEK 原件，
核对 command、pin、configuration chain 和 startup provenance；禁止改 pin、回退 current head 或用当前
defaults 重跑原 command。

rev0 只解释真实 v4→v5 migration cutoff 内、由 authenticated startup reconciliation 安装的 Accepted
command，并使用 daemon 冻结的 P3.7 defaults。普通 live queue、exact replay、同进程恢复或 cutoff 外
command 都没有该资格；出现 rev0 时应保持 `RecoveryBlocked`，不能手工改成 nonzero pin。Codex 的
approval policy/sandbox、reasoning effort 和 Claude Code 的 permission mode/model/effort/output style
都来自同一冻结配置；Runtime/UI 的 Claude Code `Default` 在当前 vendor argv 上对应 `manual`，日志里出现
`--permission-mode default` 是 mapping regression。Codex approval 的 policy/sandbox 与 CC approval 的
permission mode at-decision metadata 也必须与执行配置一致。

production restart probe 使用 synthetic `ProbeAgent` 与无副作用 `/bin/sh` helper；recorded
argv/control/translator fixture 只用于字段形状和映射回归。它们不是 live vendor login、真实 approval、
RemoteLink 或 Companion E2E，排障报告不得把这些自动证据升级成真实链路结论。

### Managed metadata mutation 语义

managed rename/archive/unarchive 以 conversation + canonical owner + raw idempotency key 形成稳定 namespace。
Applied 必须在同一 SQLite transaction 写 terminal ledger outcome、descriptor/lifecycle、conversation-local
entry revision、全局 catalog revision 与唯一 `CatalogDelta`；conversation event high-water 和 last-active
时间保持不变。完全相同的重试只读回 Replayed；同 namespace 不同 request 返回 durable Conflict，不得换
key 覆盖旧意图。RecoveryBlocked conversation 只允许 rename，archive/unarchive 应零写失败。

`daemon.conversation.metadata_mutation_pending` 表示 authenticated ledger 已存在 active native claim，
startup recovery 或已释放副作用只能按原 claim/fence 做 authenticated readback，不能再次调用 vendor。
C0-C 已实现完整 claim/fence/release/readback substrate，但 MVP production native Rename 在 claim 前返回
`daemon.conversation.metadata_unsupported`，因此 ledger/fence/spawn 都保持零；harmless synthetic
current-binary roundtrip 不是 live Claude 证据。旧 history compatibility 的 Rename/Archive/Unarchive 返回
`cc-history-mutation-requires-runtime-gate`，不能绕过 Runtime authorization/idempotency。遇到 metadata
corruption、CatalogDelta/revision 不一致或 totals 漂移时，保留 DB/WAL/SHM/KEK，禁止删除 ledger row、
回退 revision、重封 request/outcome 或手工补 CatalogDelta。

### C0-C native projector 与 dynamic history 排障

projector 只有在同一 generation 真实到达 EOF、全部已交付 candidate 获得 ACK，并按值消费 completed
witness 后才能 reconciliation。partial/incomplete generation、crash、busy actor 或 read failure 都不能写
Removed。`runtime_native_projection_refresh` 表示 source unavailable、generation/source/read 错误或不完整
见证进入固定 30 秒 refresh；不要把它改成 250 ms 快速重试。`runtime_native_projection_truncated` 表示
live/nonlive/physical/private-reference 任一 Store hard cap 命中；当前 candidate 必须保持 pending 且零 ACK，
释放容量后由后续 refresh exact retry，禁止跳过、驱逐或伪造 acknowledgement。

NativeProjected Snapshot 每次重新验证原生 JSONL，正文不会写入 Runtime snapshot/event 表。相同
turn/item key 应派生稳定 identity；成功读回后，本次 bounded command set 才可由 `QueryReceipt` 返回
`daemon.command.history_only`。原生读取失败要保留最近一次成功 receipt set；Removed 才清除，重现仅恢复
identity，必须再次成功动态读取后才能恢复 receipt。排障时不得把 history-only ID 手工插入 command journal，
也不得输出 raw project component、transcript filename、native session ID 或正文。

### B5 跨层一致性排障

configuration revision 与 conversation event cursor 是一条轴；entry revision 与 catalog revision/
`CatalogDelta` 是另一条轴。并发 Configure 与 Rename/SetArchived 后，如果 receipt 已 Applied，但 snapshot、
backfill 或 Catalog 只看到其中一半，先按同一 installation owner + idempotency key 查询 exact durable outcome，
再核对订阅 ACK/flush 与重连 frozen cursor；不得把两条 revision 强行对齐、手工补 delta，或换 owner/key 重放。
after-COMMIT unknown 可能已经提交并广播一次，exact retry 应返回 Replayed 且不能产生第二次通知。

若 revoke 或 caller cancellation 与 metadata COMMIT 同时发生，authorization guard 必须继续持有到 Store
outcome、通知和 reply 收口；revoke 只能在此前置工作完成后返回。排障时不要用固定 sleep 判断先后，应读回
principal Revoking 状态、Store completion 与最终 exact replay。该规则只覆盖 authenticated Runtime 操作，
不把同 UID 在线进程竞态重新纳入威胁模型。

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
| `daemon.runtime.schema_incompatible` | schema family/version/signature/live manifest、typed canonical descriptor/row linkage、逐 conversation HWM、authenticated metadata、command/execution/event/approval/stream/snapshot/publication/configuration/projection/effect-fence/admin-command/machine-identity totals 或两类 adapter-state total 不一致 | 停止写入并保留 main/WAL/SHM/journal；legacy v1–v14 必须先在 rescue committed-state 上完成对应 ledger token 与既有行全量认证，再打开原库 RW 并在任何 DDL 前二次认证，最后原子 migration 到 current v15（35 张表）；不能原地猜测/手改 schema |
| `daemon.runtime.store_unavailable` | worker/shutdown/commit outcome、clock/capacity probe、SQLite/I/O、sequence coordination，或 bounded checkpoint 被 reader pin 住 | 对 unknown outcome 用完全相同 stable ID/idempotency/full request 重试；Configure after-COMMIT unknown 可能已产生唯一 `ConfigurationChanged`，exact retry 应读回 Replayed 而不是换 key；checkpoint blocked 时停止新副作用、释放 reader 并保留 WAL，其他错误保留 evidence 后重启/修复底层 I/O |
| `daemon.runtime.store_busy` | normal/safety/read lane 的 count 或 retained-allocation byte permit 已满 | 客户端退避并保持同一 idempotency key；不要并发重发新 key |
| `daemon.runtime.recovering` | 已冻结 paged recovery barrier，终页尚未核账并 finish | 继续使用上一页返回的 exact cursor；RuntimeCore 逐页消费，终页 finish 后再开放请求，不得并行 mutation |
| `daemon.runtime.safety_only` | 非 disk capacity violation 已在本进程 latch，普通副作用关闭 | read/diagnostics 可继续；fence/release/terminal/rescue 仍会逐次校验预留尾，失败时不得绕过；释放空间并按 runbook 重启 |
| `daemon.runtime.disk_low` | projected transaction 后无法保留 `max(512 MiB, filesystem 5%)` | 释放同一文件系统空间后以相同请求重试；该错误本身不永久 latch |
| `daemon.runtime.store_full` | main+WAL+SHM projected footprint、SQLite page budget、configuration/pin/metadata count/charged-bytes/active cap、native live/nonlive/physical identity/private-reference cap，或剩余 safety obligation 接近/超过 2 GiB | 停止普通写；exact replay 仍应保持只读；projector candidate 保持 pending、零 ACK并等待 30 秒 refresh；仅在安全写自身复核通过时完成终态，禁止手工删除 WAL/ledger/projection row |
| `daemon.runtime.crypto_failed` | StorageKEK unwrap、row AEAD、blind token 或 generation 校验失败 | 视为 key/domain/tamper 故障；恢复原 Keychain item 和正确签名环境，禁止新建 KEK |
| `daemon.runtime.invalid_state` | stable ID/kind、clock monotonicity、queue head、fence/release、terminal/sequence 状态冲突，或 adapterStateKey 已绑定另一 namespace/不同 resume ref | 读取 canonical command/recovery/private-state 状态；错误 turn/nonce/fence 或 vendor ref 不能强制覆盖；CC 映射只能从明确 native history entry 重建，不按 title/cwd 猜测 |
| `daemon.runtime.execution_failed` | 已获 durable release 的 turn 在 adapter/vendor 执行期失败；唯一 canonical 形态是带 commandID 的 Failed terminal，message 固定为 `agent execution failed` 且 diagnosticRef 为空。execution lane 不再保存 transient Error | 以原 commandId/eventId 查询 command terminal 并按同 eventId exact replay；详细原因只查本机脱敏 diagnostic log。若历史 command-bound Error 没有被 `terminal_event_id` 指向，保留 DB/WAL/SHM 并按 schema corruption 处理，禁止猜测迁移或把它当普通 warning |
| `daemon.conversation.not_found` | Configure 或其他 conversation-scoped 请求引用不存在的 canonical conversation | 先用 Catalog/Start receipt 核对 conversationId；不要创建同 ID 占位记录或把缺失降级为 rev0 |
| `daemon.conversation.configuration_required` | production `SendPrompt` 指向 fresh/unconfigured conversation，当前 authenticated configuration revision 为 rev0/NULL；即使 caller 传 0 或非零 expected revision 也不能准入 | 先用 `DescribeAgents` 取得该 agent 的 default configuration，再对同一 conversation 执行 `ConfigureConversation(expectedRevision=0)`；收到 Applied/Replayed rev1 后用该 revision 重发 prompt，不能把 rev0 当可执行默认值 |
| `daemon.conversation.configuration_conflict` | production `SendPrompt.expectedConfigurationRevision` 与当前 authenticated configuration head 不一致；常见于另一个 writer 已推进配置 | 读取最新 configuration state，确认新配置后以新的 idempotency key 发起新 prompt；若是在重试既有 Accepted command，应按原 key/commandId 查询 receipt，不能把 expected revision 改写后复用旧 key |
| `daemon.conversation.metadata_mutation_pending` | authenticated native mutation 已处于 claimed/applying/outcomeUnknown，exact retry 不能安全判定 vendor outcome | 保持同一 owner/key/request，由 startup recovery/已释放路径做 authenticated readback；不得重调 vendor、改 key、删 ledger row 或把 pending 猜成 failed。MVP production 新请求在 claim 前 gated，不应新建该状态 |
| `daemon.conversation.metadata_unsupported` | native metadata mutation 不受支持，或 live vendor mutation 仍属于 post-MVP gate | 保持 ledger/fence/spawn 零写；不要改走 legacy history mutation、managed-only metadata 或 synthetic runner。当前 MVP 只接受 typed failure |
| `daemon.conversation.native_metadata_prepare_failed` / `daemon.conversation.native_metadata_gate_failed` / `daemon.conversation.native_metadata_unreleased` / `daemon.conversation.native_metadata_recovered_unreleased` / `daemon.conversation.native_metadata_readback_failed` | synthetic/post-MVP substrate 在 adapter prepare、current-binary gate、release 前清理、startup recovery 或 authenticated readback 阶段失败 | 保留 exact claim/fence/process identity 与 DB/WAL/SHM/KEK；released 状态只 readback、不 respawn，unreleased 必须先证明 exact group 已退出再终态化 |
| `cc-history-mutation-requires-runtime-gate` | legacy CC Rename/Archive/Unarchive 尝试绕过 Runtime authorization/idempotency | 改用 Runtime `UpdateConversationMetadata`；当前 native production 会返回 `metadata_unsupported`，不能恢复旧 direct vendor/no-op 行为 |
| `daemon.command.history_only` | command ID 来自本次已验证 NativeProjected dynamic Snapshot，不属于 durable command journal | 将它解释为只读原生历史 identity；不能查询为 Accepted/terminal、补写 journal 或据此重放 vendor。重启后须先成功动态读取才能重新建立该 volatile receipt |
| `daemon.command.idempotency_conflict` | 同 conversation + stable owner + key 被不同 command payload 或 configuration full request 重用 | 使用原完整请求查询/重试；新意图必须换新 key，不能覆盖既有 ledger row |
| `daemon.command.queue_full` | conversation 32、全机 1,024 或 queued payload 256 MiB 任一先到 | 等待/取消已有 Accepted 后以同一请求重试；满载时 exact replay 仍应成功 |
| `daemon.payload.item_too_large` | prompt、descriptor、intent/event/fence/result 超过各自硬上界，或已认证 Runtime v1 snapshot 加入 v2 必填字段后超过 64 MiB | 新输入须在进入 store 前缩小，不能切片成多个同 key 请求规避；旧 snapshot 保留原 ciphertext 证据并走显式恢复，禁止截断、重建或 reseal |
| `daemon.runtime.recovery_too_large` | 单个 conversation recovery page 的 retained projection 超过固定 80 MiB | 视为 schema/cap 漂移或损坏并 fail-close；不能改用全库物化或复用 async lane budget，保留证据后核对 item hard limits |
| `daemon.command.queue_expired` | Accepted 到达 24 小时边界，已事务化为 Expired 并写 canonical event | 不自动重放旧 vendor 副作用；用新 idempotency key 发起新命令 |

P3.4 RuntimeCore 的 transport-neutral failure：

| code | 含义 | 下一步 |
| --- | --- | --- |
| `daemon.runtime.not_ready` | Core 尚未完成 paged recovery，或正在 draining/stopped | 等待 daemon readiness；若 recovery 无法完成，按上节保留 DB/Keychain 证据并 fail-close |
| `daemon.runtime.protocol_mismatch` | Runtime protocol 版本不兼容 | 升级客户端/daemon 到同一 Runtime protocol；不能回退 Relay/IPC 业务字段 |
| `daemon.runtime.invalid_request` | ID 非 canonical UUID、Start key/cwd、Configure key 或 configuration agent kind 与 conversation 不匹配等规范化输入非法 | 修正原请求；不得由 daemon 猜 ID/path/agent kind 或替客户端补目标 |
| `daemon.runtime.feature_unavailable` | 请求属于尚未接线的后续 phase（当前主要是业务 RemoteLink），或当前 capability/构建不支持该请求 | 读取 capabilities/实施状态后等待对应 phase；`StageUpgrade` 已由 P3.10 接入，machine enroll/status/trust-reset 已由 P4.2 接入，pairing/device revoke 已由 P4.3 接入，正常失败必须保留各自更精确的 `daemon.upgrade.*` / `daemon.install.*` / `daemon.remote.*` / `daemon.pairing.*` / `daemon.purge.*` code。native metadata 使用 `daemon.conversation.metadata_unsupported`；不得用 compatibility path 或 fake coordinator 假成功 |
| `daemon.authorization.revoked` | opaque principal lease 已 Revoking/Revoked 或 issuer registry 不可用 | 停止该 connection；remote 设备按 durable revocation/re-pair 流程处理，本地重新认证 peer credential |
| `daemon.runtime.identity_unavailable` | machine trust/ID derivation domain 非法或 OS entropy 不可用 | 停止启动并检查 machine identity/系统熵；不得生成零 ID 或使用时间/PID 回退 |
| `daemon.runtime.actor_unavailable` | conversation actor/execution control 已损坏或 recovery-blocked | 不自动重放 Started；保留 command/fence 证据，P3.7 按 orphan fencing 处理 |
| `daemon.runtime.connection_unavailable` | connection 不存在、writer lagged、transport 未 ACK flush 或编码失败 | 仅重连当前客户端，并按 commandId/idempotency 查询 durable receipt；不得假定未执行 |
| `daemon.runtime.read_unavailable` | 独立 ReadPool 已满或关闭 | 有界退避后重试读取；不要创建更多等待 task，副作用请求仍以 durable receipt 为准 |
| `daemon.runtime.recovery_blocked` | Started 的已知 PGID 内 cooperative descendants 无法在 TERM→KILL/reap 后证明退出，binding/fence readback 不一致，exact command pin/configuration chain 无法认证，live/replay command 出现 rev0，或 P4 前存在 remote Accepted | 只隔离对应 damaged conversation；保留 DB/WAL/SHM/KEK、pin/configuration、fence/process 证据，禁止补 pin或改 current head。remote Accepted 属全局启动拒绝，P4 durable auth readback 前不得安装任何 actor。该 code 不表示 daemon 已检测到流程外自守护/逃逸进程 |
| `daemon.turn.stale` | CancelQueued 已输给 Started，或 CancelActive 的 turnId 不是当前 turn | 查询精确 CommandStatus；对 Started 只使用返回的当前 turnId 明确 cancel |
| `daemon.runtime.stdio_command_forbidden` | 显式 compatibility stdio 收到 allowlist 外的 execution/control/history mutation 命令 | 改用 RuntimeEnvelope UDS；stdio 只保留 Ping/Selfcheck/schema/version、agent list/capabilities 与 history list/read |

P3.8 production 本地入口在 recovery 后才建立。若 socket 尚未完成 retained-dirfd/pathname
readback，或 recovery permit 不属于同一 `RuntimeCore`，不得通过改路径、降级 stdio 或重启循环
绕过：

| code | 含义 | 下一步 |
| --- | --- | --- |
| `daemon.local.recovery_permit_mismatch` | UDS/stdio 拿到另一 `RuntimeCore` 的 recovery capability | 视为 bootstrap ownership bug；停止进程，不能创建 socket 或启动 remote transport |
| `daemon.local.stdio_selected` / `daemon.local.stdio_config_invalid` | UDS 与 stdio mode 混用，或 stdio 缺少完整隔离配置 | 按 config 只选一个入口；stdio 必须完整显式三 flag |
| `daemon.local.socket_unsafe` | canonical pathname 的 type、UID、mode、nlink、dirfd/path identity 或 listener address readback 不符合不变量 | 保留现场并检查 0700 parent 与 stale/replacement entry；不要自动 unlink 非精确匹配对象 |
| `daemon.local.socket_in_use` | endpoint 已有 active listener，或 stale probe/二次 inode readback不能证明可安全清理 | 连接既有 daemon；若怀疑 stale，先核对 PID、lock 和 pathname identity |
| `daemon.local.socket_io_failed` | bind/chmod/fstatat/unlinkat/accept 等本地 socket 操作失败 | 按 operation/path/errno 检查权限、路径长度和文件系统状态 |
| `daemon.local.connection_task_failed` | accepted connection actor panic/异常 join | 保留 diagnostic log；listener 会停止并 graceful join 其余连接后再关闭 Core |
| `daemon.local.signal_failed` | SIGINT/SIGTERM handler 无法建立或读取 | 停止启动并检查平台 signal 支持，不回退 stdin EOF 生命周期 |
| `daemon.local.peer_credential_failed` / `daemon.local.peer_uid_mismatch` | 无法在读帧前验证 peer EUID，或 peer 不是 daemon 当前 UID | 拒绝该连接；修复本机调用身份，不跳过 credential gate |
| `daemon.local.preface_missing` / `daemon.local.preface_invalid` | 连接未先发 strict bounded preface，或 client installation ID/version 非法 | 客户端先发送 canonical LocalClientPrefaceV1，再发送 Hello |
| `daemon.local.frame_read_failed` / `daemon.local.runtime_rejected` | JSONL malformed/oversize，或 RuntimeCore 拒绝 envelope | 只重连该客户端并修正 frame/version；sibling 与 Core 不应被停止 |
| `daemon.local.write_failed` / `daemon.local.writer_failed` / `daemon.local.writer_cancelled` / `daemon.local.hello_not_flushed` | 当前连接写/flush/ACK 或 cancellation 失败 | 只关闭当前连接；用原 messageId/commandId 查询 durable receipt，不假定未执行 |
| `daemon.local.stdio_io_failed` | 显式 compatibility stdio read/write 失败 | 仅重启隔离的 compatibility 子进程；不得影响 stable singleton daemon |

P3.9-A Rust 与 P3.9-B Swift shared-daemon client component 定义以下本地 client failure families；
P3.9-C3（`b4e9565`）已把**普通 GUI** 的 SessionModel/composition 切到惰性 OS-account shared UDS。
P3.9-D（`b818f81`）又把 `agentdeck` Rust binary 默认入口与
`Sources/AgentDeck/main.swift --selfcheck` 切到同一 canonical UDS。三者遇到 socket/Hello/stream failure
都只返回 typed code 并关闭当前 fd，不 spawn daemon，也不 fallback stdio/`ProcessDaemonTransport`：

| code family | 含义 | 下一步 |
| --- | --- | --- |
| `daemon.client.installation_home_failed` / `installation_parent_unsafe` / `installation_record_unsafe` / `installation_record_corrupt` / `installation_publish_unsupported` / `installation_io_failed` | passwd home 不可用，installation parent/record 的 type、owner、mode、nlink 不安全，record 非 canonical，或 no-replace/fsync I/O 失败 | 保留原 record 与目录；修复 OS account home/权限/文件系统，不删除或自动轮换 identity，不改用 `HOME` 覆盖 |
| `daemon.client.socket_path_invalid` / `socket_missing` / `socket_parent_unsafe` / `socket_unsafe` / `connect_failed` / `socket_option_failed` | canonical UDS 路径非法或不存在，parent/socket 的 type、owner、mode、nlink 不满足，connect 或 socket option 失败 | GUI、Rust CLI 与 Swift selfcheck 都直接暴露该失败且零 fallback；核对 stable daemon/LaunchAgent、current-EUID installation 与 canonical path，不用 diagnostics/legacy stdio 成功覆盖 Runtime socket failure |
| `daemon.client.preface_failed` / `encode_failed` / `hello_invalid` / `hello_order_invalid` / `sequence_required` / `message_id_duplicate` / `server_request_forbidden` / `reply_uncorrelated` | preface/Hello/首帧/messageId/reply sequence 编码或协议被破坏 | 关闭当前 fd，升级为同一 Runtime v5 candidate；若 daemon 返回 `daemon.runtime.protocol_mismatch`，client 会保留该精确 code，不包成通用错误 |
| `daemon.client.connection_closed` / `read_failed` / `frame_invalid` / `frame_unterminated` / `frame_too_large` / `write_failed` / `write_timeout` / `write_handoff_incomplete` / `close_failed` | EOF、JSONL/1 MiB framing、read/write/flush/cancellation 或 close 失败 | 未见 terminal 的 sender close 必须按 failure 处理；App 先等待共享 close barrier，不能在 fault callback 内热重连。下一次用户操作才建新 wire；有副作用请求保守复用 exact Runtime request payload、stable idempotency key 与冻结 revision，让新 wire 自行分配 outer messageId 并由 daemon 裁决 durable outcome，不能把 EOF 当正常完成 |
| `daemon.client.reply_backpressure` / `reply_sequence_backpressure` / `reply_timeout` / `reply_drain_expired` / `stream_backpressure` | pending/reply/stream 的 frame、retained-byte budget、absolute deadline 或 TTL 到界；Rust CLI 完整 reply sequence 共用一个 30 秒 deadline，中间帧不续期；Swift 普通 event/catalogDelta 与 transfer complete 都计入 stream byte budget | 关闭当前连接并有界重连；有副作用请求用原 idempotency key 重发 exact request，让 daemon 裁决 replay/conflict，或由同 owner 显式查询 durable receipt。先消费/取消旧 sequence，不扩大 channel 或并发生成新 messageId |
| `daemon.client.transfer_backpressure` / `transfer_binding_mismatch` / `transfer_expired` / `transfer_incomplete` / `transfer_invalid` / `transfer_tombstone_desync` | transfer part 数量、byte/hash/binding/TTL/completed tombstone 不一致 | 丢弃当前重组状态并关闭连接；从 daemon cursor 重新同步，不接受 partial payload 或复用 transferId |

### P3.9-C3 GUI canonical projection 诊断

C3 focused `46/46`、完整 Swift `435 XCTest + 35 Swift Testing`、普通与 warnings-as-errors build、iOS
Simulator `20/20`、production source purge/format/diff 均通过，两路终审无 P0/P1/P2。排查 GUI 时以以下
canonical 行为为准：

- Subscribe 可合法返回 `Snapshot → Backfill* → SyncComplete`；projection 只在 terminal 完整验证后原子
  提交。`Backfill → Snapshot`、重复 Snapshot、target/generation/cursor gap 必须 fail-close 当前 client，
  不能部分展示或改 cursor；
- SendPrompt 的 `Replayed` 不是 terminal 证明。只有 App 已归约的同 conversation、exact command terminal
  identity 匹配时才把 outcome-unknown 队首恢复为 `ready`；`Accepted`、不同 command 或 active turn 继续
  等 canonical event。若后续引入 snapshot-only reconnect，应以 owner-scoped `QueryReceipt` 的精确
  CommandStatus 补证，不能仅凭 replay 标签；
- `--preview` 使用独立 synthetic stream，按同 command/turn 和连续 sequence 发出 started/user/assistant/
  completed；普通 GUI composition 不引用 Preview wire。Preview PASS 不能证明 UDS、daemon 或 vendor login；
- `SyncComplete` 之后 live event 可先到达。`completeConversationStart` 接受 runtime cursor 等于或晚于
  terminal；若落后则 `draftConversationNotSynchronized`，不得倒退或覆盖已经归约的 running/terminal phase。

GUI 的 `daemon.client.socket_missing` 或 `connect_failed` 应直接提示 shared daemon/LaunchAgent 状态；现场
若出现新的 `agentdeckd` child、legacy stdio 成功遮蔽该错误，属于 composition 回归而不是恢复策略。

### P3.9-D 诊断与组合 smoke

D 的 canonical CLI 只接受/输出 `conversationId`；continue 路径的旧 `threadId/agent/cwd`，以及
`persistApproval/worktree/sessionName` 等无 Runtime v2 映射的 vendor 参数，会在连接前返回稳定 `usage` JSON
envelope。`session run` 的 canonical `agent/cwd` 仍是必填配置。Rust CLI 默认 dispatcher 与
`main.swift --selfcheck` 已走
stable UDS；显式 diagnostics one-shot 可保留 spawn，但 UDS 任一失败后不会调用它作为 fallback。

`QueryReceipt` 绑定 installation owner。Rust installation 只能查询 Rust 自己的 command/idempotency receipt，
Swift installation 只能查询 Swift 自己的 receipt；cross-owner 拒绝是 PASS 条件。组合 smoke 应以一个真实
`agentdeckd --ephemeral --no-remote`、private TMPDIR 中验证过的唯一 `ad-*/s`，证明两个客户端各自稳定
installation、各自 receipt、共同 catalog/conversation/event/command queue、daemon PID 不变、任一客户端
close-only 且零 fallback。真实 vendor login 缺失时保持 gated；共享 binary/receipt 证据可与现有
listener/actor 的 active-turn sibling-close 自动测试组合，但不得新增 debug-only synthetic coordinator，
也不得把组合证据写成真实 vendor E2E。`scripts/run-local-runtime-smoke.sh` 已 PASS；排障时可直接重跑该脚本。
若它在 `RUN:` 某阶段失败，先检查输出的 daemon stderr、唯一 `ad-*/s`、两个 installation 是否不同、各自
receipt selector 是否 owner-scoped，以及 cleanup 后 daemon PID 是否消失。P3.9-D code/test 提交为 `b818f81`。

### P3.9-E retry、composer 与有界重连诊断

P3.9-E code/test 提交为 `d68cc02`。GUI 状态栏中的 `sending` 只表示本地请求正在等待 daemon admission；
只有收到 Accepted/Replayed receipt 后才进入 daemon `queued`。失败后出现 `retry required` 时必须由用户
显式重试，不得在后台自动换 key 或悄悄重发：

- 只有 allowlist 明确证明 durable outcome 已知的 definitive reject，才允许按失败 stage 建立 fresh
  idempotency key；transport、EOF、closed、未知 failure 与 `daemon.runtime.store_unavailable` 都按
  outcome unknown 处理，复用 exact UTF-8 payload、
  configuration revision 与原 key。用户改变 prompt 是新意图，不能复用旧 outcome-unknown key；
- composer draft 绑定 bootstrap/conversation logical owner。切换目标会保存/恢复对应 draft；bootstrap 成功
  转正只允许同一 lineage 携带。缓存最多 32 owners、单 draft 256 KiB、总 1 MiB；出现 draft drop warning
  表示超限或 LRU eviction，不应扩大上界或跨 owner 拼接文本；
- history 快速 A→B→C 只允许 A 完成后直接处理最新 C。若 UI 最终回到 B 或出现多个并行 open，检查
  latest-intent generation 与单 drain ownership，不要用 sleep 延长来掩盖；
- stream fault 会关闭旧 wire并等待 close barrier；旧 generation 的 wire reply/inbound item 都必须拒绝。
  barrier 完成后仍不会主动热重连，下一次 history/submit/retry 等用户操作才创建新 wire；
- catalog 与 conversation 合计最多 64 个 live subscriptions。普通历史会话按 LRU 腾槽，只有收到 exact
  Unsubscribe ACK 才能从账本删除；selected/required/active-prompt conversation 被 pin。全部 pinned 时 Start
  必须零副作用并提示 `all local Runtime subscription slots are pinned by active conversations`。并发
  History/Start 若选中重复 victim、超过 64 或本地账先于 ACK 漂移，检查 FIFO admission 中
  “腾槽→Subscribe→记账”的单飞边界，不要增大 daemon quota。

Task 门禁中真实 AF_UNIX EOF、新 wire 首操作、subscription admission 各有确定性覆盖；真实 vendor login、
RemoteLink、provisioned signed Keychain 仍是 post-MVP/后续阶段证据，不能由本节的本地 synthetic 结果替代。

### P3.10 install/upgrade 与 P3 Phase 排障

P3.10 code/test commit 为 `19622ab`；Phase review hardening 依次为 `773a2b3`、`0057824`、
`81cc314`、`9efb28d`。基于 `9efb28d` 的独立 `p3` verifier 已 exit 0，P3 Phase complete（MVP
automatic scope）。安装 verifier 的所有外部命令都在独立 PGID 中运行，使用 10 秒绝对 deadline、
stdout+stderr 合计 256 KiB 上限；leader 在同组清理前保持 wait identity，避免 PGID 在 SIGKILL 前被无关
进程复用。该收口只覆盖同 PGID 成员，不声称发现或清理主动 `setsid`/`setpgid` 的逃逸进程。

| code | 含义 | 下一步 |
| --- | --- | --- |
| `daemon.install.verifier_timeout` | `codesign`、`plutil` 或候选 `agentdeckd --version` 超过 10 秒绝对 deadline，或 leader 退出后同 PGID 仍不能在 deadline 内连续读回静默 | 停止安装并保留当前 artifact/current；检查签名环境、候选 `--version` 与同 PGID 后代，不扩大 deadline、不降级 verifier，也不把该错误改写为 `signature_invalid` |
| `daemon.install.verifier_output_too_large` | verifier stdout+stderr 聚合超过固定 256 KiB | 拒绝候选并清理未发布 temp；检查异常输出或错误 packaging，禁止截断后继续发布或切换 `bin/current` |

production-signed LaunchAgent/Keychain slot 继续精确返回 post-MVP
`BLOCKED/mutations=0/evidence=[]/summaryGenerated=false`；`p3` verifier exit 0 表示该 BLOCKED contract 与
automatic gate 正确，不表示 production signing PASS。P3.1 继续采用方案 b。P4.1 已由
`3cd76d2`、`644712c`、`95090c1`、`85df3d2`、`f137112`、`46c6bb8` 完成 automatic Task 收口，
P4.2 又由 `a6842bc` 完成 Link/Data cert、enrollment workflow、receipt IO、control-only
RemoteTransport 与 trust reset；P4.3 又完成 PairInvite/DeviceGrant/auth ledger/revoke/control handoff；
P4.4 由 `cd7d9fb` 完成 MachineLink ingress/RuntimeCore dispatch；P4.5 由 `c6ef387`、`88b3c42`
完成 signed publication、key/counter/replay crash recovery。P4.6 persistent remote CLI automatic Task
已完成，current Runtime wire 为 v5；P4.7 automatic Task 与 P4 automatic Phase Exit 也已完成，P4 按
Task 进度为 7/7。focused `p4-auto`、独立顶层门禁、pre-closeout hash
`18654fa9c398383dafcefa1542c8e48f8c460f1f521806880c5dab083bdb29f5` 与双路 phase review 均通过；
`p4` 仍不受支持。

### P4.1 machine identity / Keychain guard 排障

P4.1 current Runtime schema 是 **v8 / 24 张表**：在历史 v7 的 23 张表上新增
`machine_identity_state`，并用 `runtime_meta.machine_identity_count` 与 v8 ledger token 认证 singleton
count。v7→v8 migration 不轮换 crypto context/key generation，不重封既有 ciphertext/wrapped key，也不改写
`machine_enrollment_receipts`。P4.1 bootstrap 固定顺序为“四组 key exact load/create/readback → DB
Preparing → key-directory guard exact install/readback → DB Active”；普通重启只 exact load，不生成第二 root。

诊断时先区分 failure stage：identity/guard/key reconcile 产生的
`RemoteBootstrapOutcome::Blocked` 只关闭 remote，本地 Runtime recovery 与 canonical UDS 继续；
`RuntimeStoreHandle::open`、identity Store command/worker/SQLite 或 StorageKEK 的失败仍是全局 fatal，不能改写成
remote-only warning。日志只记录 `status=disabled|active|blocked` 与稳定 code，不得打印原始 key、完整 public
key/fingerprint 或 guard bytes。

| P4.1 code / 状态 | 含义 | 下一步 |
| --- | --- | --- |
| `status=disabled` | 显式 ephemeral/no-remote 模式在任何 stable machine account IO 前退出 | 仅用于隔离开发 harness；不得把它当 stable identity 通过证据 |
| `daemon.remote.identity.database_rollback` | DB 没有 identity row，但 Keychain key-directory guard 已存在 | remote 保持 blocked；保留 DB/WAL/SHM 与 guard，禁止补行、删 guard、重建 root 或生成新 KEK |
| `daemon.remote.identity.state_fork` | DB binding、四组 public material、guard database/root/revision 或 Preparing/Active lifecycle 不精确一致 | remote 保持 blocked并核对同一 authenticated DB/Keychain domain；禁止选择一侧覆盖另一侧 |
| `daemon.remote.identity.key_missing` / `daemon.remote.identity.key_invalid` | Preparing/Active 的四组既有 key 任一缺失，或长度/public derivation 非法 | 不补 key、不重建 root；保留其余 item 与 DB state。只有 authenticated `Active` 经 manager 读回四轴并转成 `admin_receipt_required` 后才走 portable root-lost purge；其他 lifecycle 人工恢复原状态且不展示 purge 模板 |
| `daemon.remote.identity.key_persistence_failed` | fresh item store 后缺失或 exact readback bytes 改变 | 停止 remote bootstrap；检查 Keychain backend/entitlement，不得假定写入成功或继续 Preparing |
| `daemon.remote.identity.guard_missing` / `daemon.remote.identity.guard_invalid` / `daemon.remote.identity.guard_conflict` | Active guard 缺失、canonical encoding 非法，或 existing guard 与 authenticated identity 冲突 | remote fail-close；不得删除、覆盖或按 DB 猜测重建 guard |
| `daemon.remote.identity.entropy_unavailable` | 生成 fresh key material 或非零 RootKeyId 的 OS CSPRNG 不可用/连续全零 | 停止 remote bootstrap并修复系统熵；禁止时间、PID、常量或弱随机回退 |
| `daemon.remote.identity.counter_regression` | 通用 CounterGuard high-water 请求低于既有值 | 拒绝回退并保留原 guard；核对 key purpose/epoch。P4.1 Task 收口时尚无 active reservation/full rollback 检测；当前由 P4.5 的 authenticated reservation/reconciliation 接管，不能只凭该 code 宣称整库回滚已闭环 |
| `daemon.remote.identity.fingerprint_mismatch` / `daemon.remote.identity.delete_failed` | 删除请求的 expected root fingerprint 不匹配，或 delete 后 item 仍可读 | 零容忍停止 destructive flow；保留 identity/guard并复核目标，禁止无 expected fingerprint 的批量删除 |
| `daemon.remote.identity.start_permit_missing` | Active identity 未与 recovery 后 canonical stable UDS 产生的一次性 `RemoteStartPermit` 配对 | 只阻断 remote，检查 startup ownership/order；不得在 recovery/UDS readiness 前直接启动网络 |

`daemon.keystore.*` 继续按 P3.1 表排障：同一 code 若发生在 StorageKEK/bootstrap 前属于全局 fatal；Store 已
安全打开后的 machine identity Keychain reconcile failure 才映射为 remote-only blocked。P4.1 的 CounterGuard
当时只是按 key purpose/epoch 的通用单调 IO；当前 P4.5 已建立 active reservation、DB rollback
reconciliation、retire/rekey/fail-close。P4.1 production source 自身仍是零 Link/Data cert、零 enrollment/code、零
`machine_enrollment_receipts` IO、零 RemoteLink；后续 P4.2 通过独立 authenticated state machine 接管，不能
通过手改 DB/Keychain 或 synthetic Relay 路径“修复”。P3.1 provisioned signed roundtrip 仍是 post-MVP
BLOCKED，不是 P4.1/P4.2 automatic PASS 证据。

### P4.2 machine enrollment / control-only transport / trust reset / purge 排障

P4.2 收口时 Runtime protocol 是 v3、physical schema 是 **v9 / 25 张表**；P4.3 收口时升级为
Runtime v4、schema v10/30 表，current P4.6 contract 已使用 Runtime v5。本节以下 enrollment/trust-reset lifecycle 仍保持兼容。P4.2 新增 authenticated
`machine_remote_state` 与以下可公开的最小 lifecycle；status 只允许 Relay server ID、machine route、root
fingerprint、trust epoch 和 bounded failure code，不得回显 code、origin/pin、cert、receipt、terminal 或 proof：

| lifecycle | 含义 | 下一步 |
| --- | --- | --- |
| `unenrolled` | 尚无 durable machine remote state；四个 trust binding 字段必须全空 | 使用当前 Relay 生成的私有 bundle 显式 enroll |
| `enrollmentPrepared` / `enrollmentResponseValidated` | exact request/response 已冻结，可能处于 COMMIT/response-loss 恢复窗口 | 只以完全相同 bundle 重试；不得换 code/origin/pin/Relay/receipt anchor/expiry |
| `active` | enrollment receipt、locator、Link/Data cert 与 control-only MachineLink 已建立 | 可读 status或执行普通 trust reset；不能据此宣称 pairing/业务 RemoteLink 已完成 |
| `retirePending` / `relayCommitted` / `purgeReadbackAbsent` | root-present retirement 已冻结、Relay terminal 已提交，或 absent proof 已持久 | 保留 exact state并重试同一 trust-reset；不得新建 route/cert或跳过本地 CAS |
| `localDeleted` | 旧 machine trust 已删除并留下 authenticated tombstone | 可用新 bundle显式 re-enroll；普通 restart 不得自动生成第二 root |
| `blocked` | failure code 阻断 remote；绑定字段只能全空或完整四轴 | 按 failure code 处理；本地 Runtime/UDS 可继续时不得把 remote-only failure升级为全局数据修复 |

`agentdeck remote machine status` 与 trust-reset 输出还包含 `operation`、`requestFailureCode` 和可选
`relayAdminPurge`。只有 manager 已从 authenticated `Active` 状态收敛到
`daemon.remote.trust_reset.admin_receipt_required`，且 route/root/epoch 四轴完整时，才允许生成严格的 Relay
admin purge NDJSON/命令模板；`daemon.remote.identity.key_missing` 本身以及其他 blocked code 下模板必须为空。
特别是 `EnrollmentPrepared`、`EnrollmentResponseValidated` 或 `RetirePending` 的 root-lost 状态只能返回
state conflict，由人工恢复原状态，不能获得一个 Store 无法消费的 destructive purge 提示。root-lost 的无
receipt trust-reset 不做网络或删除，只返回该安全操作提示。

#### 本机输入与管理面

| code | 含义 | 下一步 |
| --- | --- | --- |
| `remote.local_input.unsafe` | bundle/receipt 不是 current-UID、single-link、no-follow、group/other 权限为零的 regular file | 修正可信原文件 owner/mode/nlink；禁止 symlink、hardlink、目录、FIFO 或宽权限副本 |
| `remote.local_input.too_large` | 输入超过固定 64 KiB | 从可信 Relay 重新导出严格 DTO；禁止提高上界或截断 JSON |
| `remote.local_input.invalid_json` | deny-unknown JSON、版本或 portable receipt shape/签名字段编码非法 | 不猜字段、不做宽松 decode；重新取得 current bundle/receipt |
| `daemon.client.machine_status_invalid` | daemon 返回的 lifecycle/binding/failure-code 组合不满足 current Runtime v5 contract | 关闭 fd并升级 client/daemon到同一 candidate；不要展示部分 binding 或生成 purge 模板 |
| `daemon.remote.administration.unavailable` | remote 显式禁用或未安装 production manager | 使用 stable remote-enabled daemon；ephemeral/no-remote 不得开启网络 |
| `daemon.remote.start_not_armed` | recovery/UDS 尚未产生或 transport 已消费 `RemoteStartPermit` | 检查 startup ownership/order；不得绕过 permit直接连接 Relay |
| `daemon.remote.shutting_down` | manager 正在停止 | 等待同一 daemon 完成 shutdown；不要并发 enroll/reset |
| `daemon.remote.clock_invalid` | 系统时间早于 epoch或无法表示为 u64 ms | 修复系统时钟；禁止用饱和/固定时间继续创建 expiry |

#### Enrollment、certificate 与 control-only transport

| code | 含义 | 下一步 |
| --- | --- | --- |
| `daemon.remote.enrollment.version_unsupported` / `expired` | bundle 版本不是 current 或已到 absolute expiry | 在 Relay 本机重新创建 bundle；不得延长或复活旧 code |
| `daemon.remote.enrollment.relay_id_invalid` / `code_invalid` / `pinset_invalid` | Relay ID/code/pinset 零值、长度、数量或 canonical encoding 非法 | 停止网络前修复 bundle；不要发送任何 root/public material |
| `daemon.remote.enrollment.receipt_key_invalid` / `receipt_relay_mismatch` | portable receipt verify key 非法或不属于 bundle Relay | 重新从同一可信 Relay 生成 bundle；禁止拼接另一 Relay 的 key |
| `daemon.remote.enrollment.origin_invalid` | URL 不是严格无 user/query/fragment/path 的 `wss://` origin | 修复 Relay production config；禁止 redirect、host/scheme downgrade |
| `daemon.remote.enrollment.route_unavailable` | OS CSPRNG 无法生成非零 route | 停止 enroll并修复系统熵；禁止时间/PID/常量回退 |
| `daemon.remote.enrollment.state_missing` / `state_conflict` | durable lifecycle 缺失，或同一状态收到不同 frozen input | 读 status并以原 bundle exact retry；不得覆盖 singleton或跳状态 |
| `daemon.remote.enrollment.response_invalid` | response 的 Relay/route/epoch/receipt hash或严格 shape不匹配 | 保留 request/response用于本机诊断；不得激活、生成新 route或猜测字段 |
| `daemon.remote.certificate.binding_mismatch` / `root_key_invalid` / `relay_id_invalid` / `route_id_invalid` | cert 与 active identity/Relay/route/root domain 不一致 | 停止 enroll；核对同一 authenticated identity，禁止选一侧覆盖另一侧 |
| `daemon.remote.certificate.role_mismatch` / `subject_mismatch` / `root_id_mismatch` / `epoch_mismatch` / `generation_mismatch` | Link/Data role、subject、root、epoch或generation错绑 | 丢弃本次构造，保留原 keys/state；不得把 Link cert当Data cert或推进 generation |
| `daemon.remote.certificate.expiry_unexpected` / `tbs_mismatch` / `signature_invalid` | MVP cert携带expiry、TBS domain/context漂移或root签名无效 | 视为安全错误；修复 current binary/protocol，禁止宽松验签 |
| `remote.transport.frame_forbidden` | control-only MachineLink 收到业务 frame | 立即关闭该 transport并调查 Relay/client；P4.2不得向 RuntimeCore dispatch |
| `remote.transport.route_mismatch` / `closed` | retirement route错绑或 transport已关闭 | 保留 frozen retirement，以同一 durable state在新认证连接上恢复 |
| `remote.transport.start_permit_unavailable` / `authenticator_still_shared` | permit被重复消费，或 authenticator尚未唯一归还 | fail-close manager；检查 owner/lifetime，禁止 Clone/共享 key owner |
| `remote.transport.pairing_entropy_contract_violation` | 版本锁定的 HPKE consumer 没有恰好请求一次 32-byte IKM，而是请求错误长度、word API 或重复取值 | 丢弃本次 artifact 并 fail-close；核对 `hpke` 锁定版本与 `OneShotHpkeSeedRng` contract tests，禁止回退到可复制或通用 RNG owner |

底层 `relay.client.*` / `relay.tls.*` code 继续按本页 Relay client/TLS 表处理。初次 connect 失败只保留一个不可
Clone 的 exact retry state，重拨必须复用相同 authenticator、cert与 start permit；不得生成新 route/cert。

#### P4.3 Pairing、grant 与 revoke

Pairing 只允许 same-UID canonical Runtime v5 UDS 管理。invite absolute TTL 为 298 秒；RouteAccepted 不是
grant/delivery 成功，只有 exact DeviceSign-signed `PairResponseReceived` 才能推进 delivered。错误后必须保留
durable frozen state并用同一 idempotency key/pairing ID/grant serial 重试，不能重建 secret/grant：

| code | 含义 | 下一步 |
| --- | --- | --- |
| `daemon.pairing.administration.unavailable` / `sink_unavailable` | production pairing coordinator 或 local pending sink 未安装 | 使用 stable remote-enabled daemon；不得用 diagnostics/fake coordinator 假成功 |
| `daemon.pairing.actor_busy` / `actor_stopped` / `draining` | 有界 actor lane 已满、已停或正在 drain | 保留原请求，等待同一 actor/transport恢复后 exact retry；不要创建第二 coordinator |
| `daemon.pairing.drain_pending` / `active` | pairing lane 未在 10 秒绝对 deadline 内收口，或 trust reset 与 active pairing 冲突 | 不 resume、不推进 retirement/cleanup；重试同一 Running drain，或先完成/取消 active pairing |
| `daemon.pairing.invite_invalid` / `clock_invalid` / `entropy_unavailable` | invite binding、系统时钟或 CSPRNG 不满足 current contract | 网络前 fail-close；修复时钟/熵或重新生成新 invite，禁止延长旧 expiry |
| `daemon.pairing.transport_unavailable` / `grant_recovery_unavailable` | 唯一 control transport 或 durable grant recovery row 暂不可用 | 保留 open/grant outbox并在同一 route/expiry/frozen bytes 上恢复；不要把 RouteAccepted 当成功 |
| `daemon.pairing.request_invalid` / `pending.invalid` / `pending.identity_unavailable` / `pending.connection_unavailable` | PairRequest possession proof、local pending identity 或 directed local connection 无法验证 | 不产生 grant；重新建立 current local-control connection并让设备重发同一 canonical request |
| `daemon.pairing.grant_request_invalid` / `grant_authority_mismatch` / `grant_allocation_invalid` / `key_state_conflict` | frozen request、machine authority、device route/serial 分配或 bootstrap KeyDirectory 不一致 | 保留 authenticated Store；不得任选一侧覆盖、换 route或重签部分对象 |
| `daemon.pairing.grant_route_revoked` / `grant_serial_trust_reset_required` | 该 device route 已撤销，或 serial 到达不可安全递增边界 | 旧 route 不得复活；执行 machine trust reset/重新 enrollment 与重新 pairing |
| `daemon.pairing.frozen_response_invalid` / `receipt_encoding_invalid` / `receipt_binding_mismatch` / `receipt_signature_invalid` | PairResponse 或 PairResponseReceived 的 canonical bytes/hash/TBS/signature 任一错绑 | 不推进 delivered、不擦除 secret；从 durable frozen artifact exact retry，禁止修改 receipt 字段 |
| `daemon.pairing.terminal_invalid` / `already_completed` / `canceled` / `expired` | terminal 与 durable winner 不一致，或 pairing 已有 confirm/cancel/expiry 赢家 | 读取 canonical receipt；同动作只读 replay，输家不得逆转 first-valid CAS |
| `daemon.pairing.revocation_authority_unavailable` / `revocation_authority_mismatch` / `revocation_grant_invalid` / `revocation_signing_failed` | revoke 所需 authority、exact grant/serial 或签名失败 | 保留 active/revoking ledger并 exact retry；不得跳到 revoked 或删除 device key |

##### Pairing bootstrap install proof / ADKT 恢复

exact DeviceSign `PairResponseReceived` 同时证明目标设备已安装 PairResponse 的 bootstrap KeyDirectory。它只把
matching Add/Renew transition 的 exact device route/grant serial/revision target 视为已 ACK；其他 recipient 仍须
普通 `KeyUpdateAckV1`。first-device zero-cut Add 因而可直接到达 `BusinessReady`，观察不到第二条 KeyUpdateAck
不是故障，也不能靠注入 unsolicited ACK“修复”。

proof 的 stable slot digest 不比较随机 HPKE `enc`/`wrapped_key`，但必须同时匹配 pairing confirm 同事务冻结的
完整 `global_key_state_hash` 与 stable key-lineage digest。digest 覆盖同 revision 内不可变的 active roster、
current epoch 和真实 key material，不覆盖 retention owner、tombstone 或 revoked-secret GC；因此这些合法
storage-lifecycle mutation 不会被误报为 fork，真实 roster/key-material 分叉仍 fail-closed。普通 ACK 先到时
保留真实 ACK，fresh receipt 不能早于该 durable 时间；receipt 先到后普通 ACK 可升级 evidence，但不会移动
Completed transition 的 terminal causal time。

| code / 状态 | 常见原因 | 下一步 |
| --- | --- | --- |
| `daemon.runtime.invalid_state` 出现在 receipt/transition reconcile | fresh receipt 时钟早于 durable ACK；Add/Renew target、revision、slot/global lineage 不一致；proof 后尝试 cancel；fresh delivery 缺 matching transition | 停止 remote drive，保留 exact receipt、pairing、transition 与 DB/WAL/SHM；修复系统时钟或调查 state fork 后只重试原 input，禁止重签 receipt、手工 ACK 或重建 transition |
| `daemon.runtime.schema_incompatible` 出现在 full-open/Close | authenticated ADKT proof/lineage 被篡改，或 transition 已无但 matching update 仍在 | remote 保持 fail-closed；保留 Runtime DB/WAL/SHM、Keychain 与日志做离线审计，不执行写迁移、删孤立 row 或用 close-only compatibility 掩盖损坏 |
| Delivered + ADKT v1/v2 proofless transition | 旧 candidate 在 proof 字段引入前已经 delivered，matching transition/update 仍完整，且当前 global revision/hash 仍能精确证明 receipt 时的目录状态 | 仅当 current revision 等于 binding revision、完整 global-state hash 精确一致时，exact receipt replay 才可原子回填 stable lineage 与 v3 proof；revision 已前进则零写 fail-close。Close 前 GC 必须 pin matching Completed transition |
| ADKT v3 Add/Renew 缺 global/stable lineage | 当前 row 缺失 confirm-time commitment，或 v3 被错误当作 legacy | 按 authenticated corruption 停止 remote drive并保留 DB/WAL/SHM；不得 backfill、手工补 hash 或继续 Close |
| Delivered 且 transition/update 都已被旧版本收集 | 升级前旧 GC 已完成，authenticated v12 audit 证明两者均 absent | 只允许 exact receipt replay 与 Close scrub；不伪造 proof、不恢复 transition，也不能把该路径用于 fresh delivery |

fresh Close ACK 在 scrub pairing/outbox 的同一事务内保留原 receipt `created_at_ms`，把 `retain_until_ms`
延长为 ACK 后完整 30 天并重签 MAC。exact Close replay 在读取 wall clock 前只读返回，不再次续期；
AfterCommit-unknown 重开时 startup purge 必须先看到已延长 tombstone。若出现 clock regression，整个 fresh
Close 零写拒绝；不要通过重复 Close 人为续期。

pairing startup/retention 遇到 `daemon.runtime.store_busy` / `store_unavailable` 等本地 Store code 时进入
`LocalBlocked`：不得重拨 WSS，每轮只执行完整 `purge_expired_receipts → recover_generation`。status 以 actor
health 为准，自愈后回到 Active；进入 block 前已排队的旧 admission epoch 命令必须有界失败，恢复后不得执行。

P4.3 本身不处理业务 Runtime request/event；后续 P4.4 已接入严格验证后的 ingress。
pairing/grant receipt 仍不得改写成 prompt/approval/command success。

#### P4.4 MachineLink ingress / RuntimeCore dispatch

P4.4 的唯一 ingress 顺序为 Relay v2 outer → DeviceSign/AAD/replay candidate/AEAD → Store
exact-current auth-ledger recheck → `RemotePrincipal` → `RuntimeCore`。任一前置校验失败都不得
调用 Core；local revoke 后网络中残留的旧 frame 必须在 Core 前拒绝。`RouteAccepted` 只是
Relay transport 状态，不是 daemon acceptance、Store commit 或 command success。

恢复分类保持 conversation-scoped：Active ADC2 exact binding 可继续恢复；Inactive ADC2 在
actor install/start 前转为 `revokedBeforeStart`；Unprovable binding 或 legacy ADC1 只把对应
conversation 置为 `RecoveryBlocked` 只读，其他安全 conversation 继续服务。RemoteLink 只持有
易失 generation/replay/connection/reply-route，canonical conversation/command/receipt 仍只属于
RuntimeCore/Store。

| code | 含义 | 下一步 |
| --- | --- | --- |
| `daemon.remote.ingress.invalid_outer` / `invalid_sealed_blob` / `invalid_key_binding` | Relay route/context、canonical sealed blob 或 DeviceCommandTx key epoch/revision 不匹配 | 在 Core 前拒绝；核对 current Relay v2 / E2EE v1 wire 与 key directory，禁止宽松 decode |
| `daemon.remote.ingress.invalid_signature` / `replay_rejected` / `invalid_ciphertext` | DeviceSign、counter+signed-frame+ciphertext replay tuple 或 AEAD 验证失败 | 丢弃 frame 并保留 current replay window；不调用 Core、不返回业务成功；legacy 零 signed-frame sentinel 只用于 exact readback，不视为 current duplicate |
| `daemon.remote.ingress.authorization_denied` | device/grant 不是 Active，或 crypto 后 exact-current auth-ledger recheck 因 revoke/renew/key revision 变化失败 | 保持 fail-close；读取本机 auth ledger，禁止缓存旧 grant 绕过 recheck |
| `daemon.remote.ingress.invalid_runtime_request` | 解密 payload 不是 current Runtime v5 request | 拒绝且不猜测版本/类型；四个协议版本轴不得联动升级 |
| `daemon.remote.link.generation_replaced` / `transport_failed` / `closed` | active business generation 被新连接替换，或 transport/actor 结束 | 丢弃 stale generation 的 reply route并由唯一 supervisor 有界恢复；不创建第二 owner |
| `daemon.remote.link.core_unavailable` / `core_rejected` / `core_dispatch_capacity` | Core 不可用、拒绝 request 或有界 dispatch lane 已满 | 不把 RouteAccepted 提升为 command success；返回 typed failure 并保持有界背压 |
| `daemon.remote.link.reply_route_unknown` / `reply_route_capacity` / `reply_authorization_mismatch` / `reply_seal_invalid` / `invalid_core_egress` | directed reply route 过期/满载、授权错绑、sealer 返回错绑 wire，或 Core 输出不是 Reply/Stream | drop write 且不 ACK；不换 route、不宽松校验 |
| `daemon.remote.link.connection_capacity` / `replay_capacity` | 易失 connection/replay key 容量达到硬上限 | 拒绝新 admission，先收口旧 generation/connection；不扩展为无界缓存 |
| `daemon.remote.link.reply_seal_unavailable` / `daemon.remote.link.stream_publisher_unavailable` | test fallback、缺失 composition 或 production 启动组合失败 | 当前 production 已安装 sealer/publisher；若仍出现必须关闭 business admission 并 fail-close，不得伪造 sealed reply/publish 或继续执行 |
| `daemon.remote.link.shutdown_timed_out` | actor 未在绝对 shutdown deadline 内 quiesce | abort + join 并保留安全 durable state；禁止 detached task |

#### P4.5 signed publication / counter recovery

P4.5 production publication 固定执行 `CounterGuard reserve → seal 一次 → Runtime DB 冻结 exact
blob/streamSeq/counter/event range → Relay Publish COMMIT → local ACK`。outcome unknown、Store busy、Relay
offline 或进程重启都只能由唯一 transition owner/dispatcher 复用冻结 artifact 恢复；不得 reseal、换
counter、创建第二 driver，或让普通 drive 绕过 remote fence。

若上一条 publication 仍是 DB 中的 exact `Frozen` predecessor，而 CounterGuard 已为下一次 reservation
进入 `Pending`，恢复只能在 `previous_high_water == Frozen.reserved_end` 且
`previous_db_anchor == Frozen.db_anchor` 同时成立时，把下一整块记为 gap 后收敛为新的 Stable guard；旧
Frozen blob 仍按原 publication identity 恢复，绝不能被当成当前 Pending 的 retry。任一 high-water、anchor、
scope、reservation 或 publication 轴分叉都必须退休 sender key 并保持 admission fail-close。

current physical schema 为 v15/35 表。v15 只放宽带 authenticated rotation provenance 的
Relay COMMIT→local ACK 合法 crash window：此时 acknowledged inner cursor 可落后于 committed
inner cursor，但不得超前。重启后应恢复同一 frozen publication 并继续 local ACK，不得手改
`publication_streams`、伪造 ACK 或回退 schema。P4.5 收口时 v14/35 表的历史基线保持不变；
v15 已随 P4.7 automatic Task 与 P4 automatic Phase Exit 收口；这不改变 P4.5 的历史 schema 基线，
也不表示真实公网、production-signed 或 iOS 链路已经完成。

| code | 含义 | 下一步 |
| --- | --- | --- |
| `daemon.remote.transition.recovery_timed_out` | durable transition 或其 required ACK 未在绝对 deadline 内完成 | 保持 remote fence 与冻结 state；修复 Store/transport 后只让唯一 owner 继续，不得绕过 owner 开放 admission |
| `daemon.remote.transition.progress_pending` | publication outcome unknown、commit pending 或 typed Store busy，尚不能证明 durable progress | 唯一 owner 按 250 ms→30 s 有界退避复用 exact request/blob；不得 reseal、换 idempotency binding 或创建第二 driver |
| `daemon.remote.transition.reconnect_pending` | Relay offline，transition 只能等待 authenticated generation replacement | 等待认证 transport generation 变化后由同一 owner 恢复；不做 timer retry，普通 drive 不得绕过 |
| `remote.transport.publication_offline` | activation/generation 仍有效，但当前 authenticated session reader offline | dispatcher 停放冻结 exact blob；authenticated reconnect 后重发同一 artifact，不 ACK、不重封 |
| diagnostic event `remote_stream_publisher_failure` | shared publisher 在 canonicalization、transaction axes/key、CounterGuard、subscription registration、exact COMMIT/ACK 或 bounded drive 阶段 fail-close；日志只带 typed `daemon.remote.publisher.*` code | 先按该 typed code 区分 invalid input、snapshot/rotation、retired counter、offline/unknown outcome 或 drive failure；保留 remote fence 与 frozen artifact，不伪造 Runtime success、不重封或另建 publisher |
| diagnostic event `remote_publication_drive_failure` | 唯一 publication drive owner 的 notify/drive/reconnect recovery 返回 typed error，并统一降级为 `daemon.remote.publisher.drive_unavailable` | 保留 outbox、CounterGuard 与同一 owner 的恢复权；修复 Store/transport 后 exact retry。不得删除 frozen row、切换 counter、手工 ACK 或启动第二 drive owner |

#### P4.6 persistent CLI durable transfer / watch（automatic Task complete）

current Runtime wire 为 v5。persistent CLI 已接入 `pair`、`machines`、`conversations`、`watch`、`prompt`、
`approve`、`retry-approval`、`revoke-self`。`watch` 从 fresh authenticated bootstrap 开始，以 canonical
NDJSON 输出 `bootstrap|synchronized|live|control|terminal`；paired-state V6 把 durable stream binding 与
live-transfer records 放入同一 sealed CAS；V1–V5 冷读映射为空 transfer collection，不做隐式写迁移。
下列 `remote.transfer.*` 是要求废弃
exact binding 并重新 bootstrap 的稳定 marker，不是放宽校验后继续组包的许可：

| code | 含义 | 下一步 |
| --- | --- | --- |
| `remote.transfer.identity_invalid` / `metadata_mismatch` / `target_mismatch` / `stale_binding` | transfer identity、authenticated metadata、stream target 或 exact binding 不一致 | 原子保留 NeedsBootstrap marker并丢弃该 exact binding 的 active partial；completed tombstone 只用于 exact duplicate 去重，随受控 binding replacement、TTL 清理或 256 条硬上界下的 oldest eviction 回收。越过已驱逐 tombstone 的旧 source 仍由 inner cut fail-close 并要求重新 bootstrap，不猜 source/cursor |
| `remote.transfer.duplicate_conflict` | 同一 part index 的 durable bytes 与重放 bytes 冲突 | fail-close 当前 binding；不得任选一份、覆盖 durable bytes 或继续 hash assembly |
| `remote.transfer.expired` / `active_limit` | sealed absolute TTL 或 active transfer 数到界 | 停止接收当前 binding 并重新 bootstrap；idle TTL 由 runtime 自己唤醒并 durable commit，不等待下一 Relay frame，也不得通过重连续期 |
| `remote.transfer.reassembly_full` | 通用 reassembly logical budget，或 paired-state V6 normal plaintext budget 到界；128 MiB hard cap 顶部按 4,096 个 binding 聚合预留 replay+marker emergency 空间，这不是 RSS 断言 | replay admission 自身超限时与 marker 同一 exact CAS 落盘；replacement candidate 超限也从 current exact state 持久化 compact marker。两者均保留 replay admission，但 ACK/outer applied/reducer/inner cursor 不推进并清空 exact binding 的 active/buffered records；冷重开后 Publish/Gap/ReplayComplete 均保持原 marker fence。不得驱逐其他 binding state、扩大容量或让超 normal 的 legacy state 先写后失败 |
| `remote.transfer.length_mismatch` / `hash_mismatch` / `payload_rejected` | 完整 payload 与 authenticated length/hash 不符，或上层 reducer 拒绝已认证 payload | 不发布 partial/complete 结果；保留稳定 marker，换新 binding 后从 snapshot/cut 重新同步 |
| `remote.runtime.reducer_capacity` | subscription reducer 声明的 inline + transitive retained 上界无效或超过 64 MiB | 在 transport IO 与 durable mutation 前拒绝；修正 reducer 的真实静态资源契约，不得调高全局上限或把声明值当作 RSS 证据 |
| `remote.runtime.state_invalid` | 持久 Runtime 状态不可信；例如 cold restart 后 wall clock 早于 paired-state V6 sealed transfer watermark，scheduler 无法可信计算 absolute TTL | 立即 fail-close 并修复系统时钟或损坏状态；回拨路径不得等待放大的 timer、伪造 expired marker或发送 transport frame，且 paired-state records byte-exact 零写、ACK/reducer/cursor 不推进 |

prepared ADST v2 的 Normal/EmergencyBootstrapMarker mode 位于 AEAD 认证内容，CounterGuard sealed
commitment 绑定完整 sidecar；legacy ADST v1 只解释为 Normal。4095→4096 marker 的 guard-first 与
active-first crash cut 都必须恢复到 exact next state/stable guard 并清理 sidecar。cleanup 仅由 exact owner
unlink 并可安全 retry；sidecar 缺失后的 reseal、commitment conflict 或 legacy over-normal CounterPending
active-next 都必须 fail-close，state/guard/sidecar 保持 byte-exact 零写。

| watch code / terminal | 含义 | 下一步 |
| --- | --- | --- |
| `remote.runtime.outcome_unknown` | EOF 或普通断线发生在 authenticated terminal 前 | 非成功退出；保留 durable state 并从 fresh bootstrap 重试，不得合成 stopped/revoked |
| `remote.watch.output_failed` | canonical NDJSON 编码、写入或 flush 失败 | 关闭 transport 并失败退出；不要把未 flush record 当作消费者已观察 |
| `remote.watch.signal_failed` | SIGINT/SIGTERM listener 无法建立或异常关闭 | shutdown 后失败退出；修复本机 signal 环境，不改写 durable cursor |
| `remote.runtime.handshake_revoked` / terminal `revoked` | 握手期已取得 verified root-signed revoked terminal；或 active connection 收到相同终态 | revoked 优先于 ready signal；只有 transport shutdown/drop 与 crash-safe paired cleanup 完成后才公开 terminal `status=revoked` |
| terminal `stopped` | SIGINT/SIGTERM 已 latch | 当前 exact frame 必须先 durable apply + ACK terminal；marker/control 先输出。Connected+ready signal 时零 Subscribe，shutdown 后才输出 `status=stopped` |

这些 code 与 paired-state V6 focused tests 属于 P4.6 automatic Task 证据。2026-07-24 冻结 code/test
scope 为 29 paths，blob-manifest SHA-256 为
`32e7c85620e6e88b407f2403715c52c5a9a5d30aa20d7fb800bdefabe8a1c858`；watch `12/12`、
`remote_persistent_machines` `11/11`、release allocator `1/1`、relay-client `25/25`、protocol
`244/244` 与完整 CLI package final run 均通过，四 schema、三 crate Clippy、fmt、network/no-net、docs、diff
全绿。`spec/security` 与 `quality` 终审均 Approved，P0/P1/P2=0。
这些 P4.6 证据本身不等于 P4.7 Phase PASS；后续 focused `p4-auto`、独立顶层门禁、冻结 hash 与双路
phase review 已通过，P4.7 automatic Task 与 P4 automatic Phase Exit complete。production-signed Keychain
仍未闭合，不能把 marker 行为写成 production-signed 或真实公网 watch PASS。真实
entitlement/access-group roundtrip 继续保持 post-MVP BLOCKED。
8 MiB lowered-cap 只在 `debug_assertions` automatic test build 中存在，release artifact 不编译该入口，
production CLI/env/config 也不能选择该值。

#### P4.7 automatic complete 与真实槽位诊断边界（post-MVP BLOCKED）

`p4-auto` 只是 machine/CLI/state-machine/protocol/schema/network/docs 的 focused aggregate，不包含顶层
`cargo test`、`swift test`、最终 diff/status、冻结 candidate hash 或独立 `spec/security`、`quality`
phase review。remote principal 不能确认 pairing 由单独的 RuntimeCore principal gate 证明，不应在 machine
E2E 内寻找或伪造同一证据。

P4.7 收口时 `p4-auto`、fresh `cargo test --locked`、`swift test` 577/577、三组 Clippy、fmt、
network/no-net、四 schema、agent docs、diff、local Runtime smoke、ephemeral selfcheck 与 diagnostics 均通过。
pre-closeout review candidate SHA-256 为
`18654fa9c398383dafcefa1542c8e48f8c460f1f521806880c5dab083bdb29f5`；`spec/security` 与 `quality`
均 Approved，P0/P1/P2=0。verifier 仍不支持 `p4`；上述独立证据不能从单独一次 `p4-auto` 反推。

`scripts/run-relay-companion-p4-real-e2e.sh` 目前只是一条静态 fail-closed slot sentinel。它不读取参数或
环境变量，不探测签名、entitlement、WSS、vendor login 或 disposable profile，也不执行真实链路；输出始终
包含固定完整 `missingInputs`，并保持 `BLOCKED/mutations=0/evidence=[]/summaryGenerated=false`。因此
“missingInputs 已列出”不等于真实 prerequisite preflight 已执行；真实 preflight/execution 留给 post-MVP。
Linux synthetic client 只允许 ephemeral test keys，macOS production persistent pairing 必须使用 Data
Protection Keychain 且没有 file/dev keystore 降级。MachineRoot 丢失按
[`RELAY_RUNBOOK.md` 的 portable purge receipt 流程](RELAY_RUNBOOK.md#machineroot-丢失后的-portable-purge-receipt)
处理；static sentinel 不生成 receipt，也不提供删除授权。
production-signed Keychain/LaunchAgent、真实 vendor、公网 WSS、物理真机/真实 iOS、第二台 Mac 与
destructive purge 继续 post-MVP BLOCKED；P5.1 shared facade、P5.2 crash-safe client storage、P5.3
WSS/pin/per-connection transfer primitive、P5.4 MachineConnection/bounded source、P5.5 canonical
fixture/receipt UI、P5.6 iOS production composition/pairing lifecycle 与 P5.7 macOS SessionSource registry
automatic Task 已收口，rescue R3 又完成 P5.8-lite 本机 AppKit pending-device 控制面，P5/P6 当前进度为
8/9、0/4。P5.8-lite automatic 证据不替代 P5.9 fixed-topology Relay E2E 或任何外部门禁。

#### P5.2 client storage / counter / replay failure

| code | 含义 | 下一步 |
| --- | --- | --- |
| `remote.keystore.invalid_account` / `invalid_length` | 调用方没有使用 typed pending/paired account，或 invite/root/route 长度不合法 | 停止持久化并重建 typed identity；不得传任意 service/account |
| `remote.keystore.immutable_conflict` | immutable item 已存在但 bytes 不同 | 保留原 item，核对 installation/root/route/purpose；不得覆盖 |
| `remote.keystore.compare_and_replace_missing` / `compare_and_replace_mismatch` | CounterGuard 等可变 item 缺失或 expected bytes 已漂移 | 退休当前 epoch 或重新审计 paired state；不得 blind update |
| `remote.keystore.persistence_readback_failed` / `delete_readback_failed` | Keychain mutation 后 exact readback 不一致 | 视为 commit unknown，停止发送/删除并读回；不得假定成功 |
| `remote.keystore.unavailable.*` | Security.framework 返回 OSStatus；SwiftPM 的 `-34018` 是缺 Data Protection Keychain entitlement | production 必须使用匹配签名/entitlement；automatic runner 明确 SKIP，不回退 memory/file secret |
| `remote.crypto_state.missing_storage_key` | sealed state 已存在但对应 DeviceStorageKEK 不在 Keychain | fail-close 并走重新配对/trust reset；禁止生成替代 KEK |
| `remote.crypto_state.authentication_failed` / `invalid_format` | AAD identity、KEK、header/version/length 或 AEAD tag 不匹配 | 不修复、不覆盖原文件；核对 client/installation/machine/root/route 后进入 security error |
| `remote.crypto_state.input_too_large` | plaintext 超过 128 MiB，或 sealed file 超过 128 MiB + 40-byte ADCS overhead | 停止订阅并先做 snapshot/GC；不得截断或静默丢 replay guard |
| `remote.crypto_state.unsafe_file` / `backup_exclusion_missing` / `file_protection_missing` | state 不是当前 UID 的单链接 0600 regular file，或保护属性缺失 | 停止加载；修复可信目录/签名环境后重试，不在原路径自动降级 |
| `remote.crypto_state.compare_and_replace_mismatch` / `persistence_readback_failed` | sealed state exact CAS 或 durable readback 失败 | 按 commit unknown 处理并重新读 guard/state；不得继续消费 counter |
| `remote.counter.epoch_retirement_required` | guard/state high-water、state commitment、Pending reservation 分叉或 UInt64 overflow | 退休当前 key epoch 并由上层协调 rekey；绝不猜测 counter |
| `remote.crypto.nonce_reuse` | replay window 内同 counter 出现不同 ciphertext hash | 持久化 quarantine/retirement 后隔离连接；不要只重试当前 frame |

重启读到 counter `Pending` 时只能按 exact reservation commitment 补写/确认并整块跳号；读到
non-counter `statePending` 时，只能在 state 仍等于 previous 时回滚 guard，或在 state commitment exact
等于 next 时 finalize。第三种 state（即使 scope 相同且 revision 正好 +1）都是 authenticated fork，必须
durable quarantine + retired guard，不能手改 guard/state 让它继续 active。

Simulator 可验证 CryptoState roundtrip、backup exclusion、tamper fail-close 和 production protection policy
配置，但 CoreSimulator 当前把 protection readback 固定显示为 `CompleteUntilFirstUserAuthentication`；只有物理
iPhone 的锁屏/解锁 readback 能关闭真实 `Complete` 证据槽位。

#### P5.3 WSS / TLS pin / transfer failure

P5.3 transport 只拥有一个 physical WSS generation。`connect()` 的 generation 不能复用；普通 owner 必须把
`send`、`incomingFrames` 与 `close` 都绑定该 generation。close 只有依次读回 task `didComplete` 与 session
`didBecomeInvalid` 才解除旧 generation，WebSocket `didClose` 单独不算完成；connect/write/cleanup 任一绝对
deadline 到界都 fail-close，禁止新旧 socket 重叠或让
半开 write 永久占用 in-flight continuation。`shutdown()` 只用于 composition root teardown，不是普通重连入口。

| code | 含义 | 下一步 |
| --- | --- | --- |
| `remote.transport.endpoint_invalid` | origin 不是 canonical `wss://` root，或带 userinfo/path/query/fragment/非法 port | 修正 Relay origin；不要拼接 `/v2/connect`、允许 redirect 或降级 `ws/http` |
| `remote.transport.tls_pinset_invalid` / `tls_challenge_invalid` / `tls_hostname_mismatch` / `tls_trust_failed` / `tls_pin_mismatch` / `tls_certificate_invalid` | TLS policy/pin、challenge host、public trust 或 leaf DER-SPKI 校验失败 | fail-close；从可信 PairInvite/key directory 更新 current+next pin。不得点“忽略证书”或回退 public CA/pin-only |
| `remote.transport.connection_timed_out` | connection attempt 的 30 秒绝对 deadline 到界 | 关闭 exact attempt；由 P5.4 supervisor 按 typed reconnect policy 重试，不复用 generation |
| `remote.transport.connection_cleanup_stalled` | canceled attempt 或 physical close 未在 5 秒内读回 terminal cleanup | 当前 transport 已 poison；销毁 composition owner 后重建，保留 socket/delegate 时序诊断，不在同实例继续 connect |
| `remote.transport.outcome_unknown` | application write 进入 socket 后失败、取消、restart 或绝对 write deadline 到界 | 不把它当作“命令未执行”；按原 idempotency key/Runtime receipt 恢复，只关闭 exact generation |
| `remote.transport.stale_generation` / `canceled` | caller 使用旧 generation，或自己的 connect/incoming/send waiter 被取消 | 丢弃旧 owner token；等待当前 close/cleanup 完成后由 supervisor 新建 generation，不重放 Hello |
| `remote.transport.frame_too_large` / `frame_invalid` / `text_message` / `peer_closed` | 数据超过 4 MiB（含 local/peer 1009）、outer frame 非 canonical binary、收到 text，或 peer 以 typed code 关闭 | 关闭 exact generation；不要把 text/oversize 当成 Runtime payload。1000/1001/1002/1008/1009/1011/1012/1013 保留稳定诊断语义 |
| `remote.transport.incoming_backpressure` / `outgoing_backpressure` | regular/urgent 或 application/control 的 frame/byte 任一预算耗尽 | 当前 generation fail-close；修复慢消费者/生产者，不调高为无界缓存 |
| `remote.transport.server_restarting` | 已验证 `ServerRestarting`，携带 drain deadline | 交付 urgent terminal，清空普通 incoming/queued application；in-flight application 视为 outcome unknown，deadline 后叠加 jittered backoff |
| `remote.transfer.too_large` / `hash_mismatch` / `expired` / `reassembly_full` / `stale_scope` | per-connection transfer 的结构/长度/hash/duplicate/TTL/budget 或 connection+generation scope 不合法 | 释放 offending partial 并从完整 snapshot/cut 重建；不得续接旧 partial、驱逐 TTL 内 tombstone或返回未验完整 payload |

incoming regular 固定 512 frames/16 MiB，urgent reserve 4 frames/8 MiB；application writer 固定
512 frames/16 MiB，control reserve 8 frames/1 MiB。aggregate 分别是 516/24 MiB 与 520/17 MiB；这两轴
同时是 hard cap。`TransferAssembler` 只证明每 connection 64 active、parts+assembly 峰值 128 MiB、
256 completed tombstone 与 absolute TTL 5 分钟；process-global 512 MiB/8,192 必须由 P5.4 shared
coordinator 在 allocation 前 reserve。看到多个 connection 总占用越界时，不要把 P5.3 component gate 当作
global 证据。

pinned self-signed 的准确含义是：先匹配 exact leaf DER-SPKI，再把该 leaf 作为显式 anchor 运行
hostname/time/EKU/结构验证，并由 TLS CertificateVerify 证明 pinned private-key possession；它不验证 anchor
的自签 signature。真实公网 WSS 与物理设备仍是 post-MVP BLOCKED，P5.3 automatic tests 不替代这些证据。

#### P5.4 MachineConnection / RelaySessionSource typed failure

P5.4 Swift client 当前用 facade state、stable transfer code 与 module-internal typed error 分层表达故障；不要把
内部 enum 名称写成 daemon/Relay wire failure code。排查时先确认 exact connection + transport generation，
再读 durable CryptoState/key-sync episode、request correlation 与 source observation，禁止通过清 state、复用
route/counter 或扩大 buffer 来“恢复”。

| typed state / failure | 含义 | 下一步 |
| --- | --- | --- |
| `SessionConnectionState.relayUnavailable` / `.machineOffline` / `.reconnecting` | 暂态 transport、Relay 或 machine 可达性变化 | 保持外层 observation；等待 supervisor 在旧 generation 完整 teardown 后以 fresh challenge/resume 重连，不手工重放 Hello |
| `SessionConnectionState.lagged(.bufferDropped)` | conversation 慢消费者填满 512 队列，旧内部 generation 已失效 | 等待同一外层 observation 收到 lag marker、fresh snapshot 与 `SyncComplete` barrier；不要继续消费旧排队 event |
| `SessionConnectionState.lagged(.cursorGap)` / `.lagged(.snapshotRequired)` | outer/inner cursor 不连续，或 key barrier 要求该 target 重建 | 只重订阅受影响 catalog/conversation；从 fresh snapshot/barrier 恢复，禁止用 alias 打开普通 rollback payload |
| `ProductionMachineConnectionVerifiedIngressError.keySyncTimedOut` / `.keySyncMismatch` | 30 秒 absolute deadline 到界，或 update/barrier/revision/route 不属于 exact active episode | 关闭 exact generation并从 durable episode恢复；不得重置 deadline、合成完整 directory 或跳过 barrier |
| `ProductionMachineConnectionVerifiedIngressError.outboundCapacity` | transport action/control request route 的 512 hard cap 或 reservation 不可满足 | 让已发 control route取得 matching RouteAccepted，或结束 generation；不得复用业务 route、取消 reservation 后继续签名或调高 cap |
| `MachineRequestCorrelationError.preparedMutationPending` / `.capacityExceeded` / `.routeCollision` | request/subscription 已有待 durable commit mutation，或 pending/live/historical namespace 已满/碰撞 | cancel 必须 fail-close exact generation；不能吞掉 unregister 失败后让旧 StreamBinding 继续 commit/Subscribe |
| `TransferAssemblerError.reassemblyFull` | per-connection 或 process-global 512 MiB/8,192 budget 在 allocation 前拒绝 | 丢弃 offending transfer/completion并确认 exact reservation release；不得临时超配或驱逐 5 分钟 TTL 内 tombstone |
| `SessionConnectionState.revoked` / `.incompatible` / `.securityError` | root-signed terminal、协议不兼容或验证/crypto 安全失败 | 这是 fatal observation terminal；完成 connection shutdown/paired cleanup readback后重新配对或升级，不进入普通 reconnect loop |
| `SessionSourceFailureCode.transportUnavailable` / `.machineOffline` | command 在 source shutdown、离线或无 active generation 时发起 | 返回 typed failure，不离线排队；恢复 observation 后由调用方按原 idempotency key重新发起 |

若 pre-MVP developer Keychain 中仍有 `ADPR`/`ADPM` version 1 paired marker，P5.4 cold open 会返回
`PairedMachineStoreError.invalidRecord` 并保持零迁移、零自动删除。version 1 没有 MachineRoot public key 与
Data certificate，无法从 fingerprint/grant 安全重建；因此不要手改 marker 或降级验证。P5.6 Release composition
发布前已复核并继续冻结 version 2 hard cutover：v1 developer artifact 不是受支持的 migration input，当前恢复
方式只能是在明确授权后清理对应 developer state 并重新配对。

resource observation 只保留 newest-one；conversation observer cap 为 64、每 observer queue 为 512。第 65 个
observer 只拒绝 offending admission，不能重启已有 observation。process-shared transfer budget 必须在
complete、validation/hash/length failure、TTL、disconnect/reset 与 owner teardown 后读回 exact release。
key-sync semantic ACK 先于 Relay outer ACK；签名失败、generation teardown 或 reconnect 后只能恢复同一
barrier hash 的 durable proof。

最后一个 conversation observer 退出后，该 conversation 会进入 single-flight retirement：先等待 Runtime
`Unsubscribe` receipt，再退休 correlation binding并发送 exact Relay outer unsubscribe。retirement 返回前同一
conversation 的 replacement 必须被拒绝，且该条目继续占用全局/per-machine observer cap；不要把这段时间误判为
泄漏后清 state。unsubscribe 任一步失败会 fail-close 对应 machine/generation，不能跳过旧 retirement 建新 binding。
若 shutdown 在 update queue 已满时停住，核对顺序必须是 cancel supervisor → finish update channel → teardown
generation → join；消费者可读完已排队的 512 条前缀，第 513 个 pending send 必须由 finish 解锁且不得越界交付。

pairing 恢复时看到完整 `staged` marker 并不表示 machine 已配对可见。只有 matching `PairRouteClosed` 才能把它
CAS 为 `committed`；在此之前 `list/load/openConnectionMaterial` 都必须隐藏。`relay.route.not_found` 即使带有
精确关联的 receipt frame hash，也可能只是 daemon 离线，必须按 transport unavailable 处理并保留
responsePrepared + staged marker。完整 promotion 可跨 invite expiry 继续 reconciliation，因为远端 Delivered
grant 不会被 TTL sweep 自动撤销；无 exact Close proof 时，既不能开放连接，也不能删除可能仍绑定 active grant
的 credential。marker 缺失的 partial rollback 若已存在 CounterGuard，必须先验证其 promotion ID、state 与
bootstrap commitment 绑定；malformed 或 foreign guard 必须零 mutation fail-close。requestPrepared 仍按绝对
expiry 清理，合法 partial promotion 仍精确回滚。

2026-07-27 的非门控 Instruments Allocations smoke 启动 `dist/AgentDeck.app --selfcheck`，exit 0、duration
2.639832 秒；trace 只在 `/tmp/agentdeck-p54-instruments.rt5Mo5/p54-agentdeck-selfcheck.trace`，不得提交。
它不是 RelaySessionSource 长跑、真实公网 WSS、production-signed Keychain、物理 iPhone、第二台 Mac 或真实
vendor 证据。P5.4 收口后，P5.5–P5.8-lite 已分别独立完成；当前只剩 P5.9 与 P5 Phase Exit 未完成。

#### P5.5 iOS canonical / receipt 乱序诊断

P5.5 后，iOS ViewModel 不再消费私有 `MobileSessionSource` 事件，而是把共享 `SessionSource` 的 canonical
snapshot/event、command status、typed connection state 与异步 receipt 视为不同到达轴。排障时必须同时保留
conversationID、turnID、commandID、approvalID、requestID、idempotency key、canonical event sequence 与 receipt
到达顺序；只截一张最终 UI 图无法判断是正常追平、transport outcome unknown 还是安全错绑。

| typed state / 现象 | 含义 | 下一步 |
| --- | --- | --- |
| 收到 `commandID=null` 的 canonical Error，但当前 turn 仍在 streaming | conversation diagnostic，不是 Failed terminal | 保留 failure 文本用于诊断，但不得清 active turn、派发下一 prompt、生成 failed inbox 或停止 streaming；后续 Item/Completed 仍按 exact-next 接受 |
| command-bound Error 的 code/message/diagnosticRef 不是固定 tuple，或同 command 已有 terminal | Runtime v5 authenticated event 违反唯一 Failed terminal 契约 | ingress/reducer 立即 security fail-close，保持 cursor/approval/queue 零漂移；不要把 vendor 文本改写后重试，也不要升级 Runtime 版本掩盖同 candidate 漂移 |
| `PromptSubmissionState.failed` 且源错误为 `.transportUnavailable` | 请求是否到达 daemon 未知；同文本仍绑定原 idempotency key | 只让用户重试同一文本并复用原 key；收到 Accepted/Replayed 后按 commandID 等待 canonical user item，禁止换 key 猜测未执行 |
| 下一 prompt 收到 Accepted/Replayed 后 queued row 消失，但 canonical 只有上一 command 的 terminal | receipt reconcile 错把旧 Completed/Interrupted/Failed 当成当前 prompt 证据 | 对照 receipt 与 terminal 的 commandID；只有逐字一致才可收口 pending prompt。保留新 queued row 并等待其 canonical user/terminal，禁止按“最近 terminal”跨 command 消费 |
| receipt 已 Applied，但 UI 随后看到旧 Claimed/Applying | canonical stream 仍在追赶同一 operation epoch，receipt 是临时 UI floor | 保留两轴证据并等待 canonical Applied；不得把 UI 回退为 submitting，也不要人为补发审批 |
| receipt 为 DeliveryFailed，但旧 canonical Applying 仍在 | delivery failure 尚未在 canonical 轴出现，当前不能证明新 retry round 已开始 | 等待同 approvalID/winner 的 canonical DeliveryFailed；只有随后 DeliveryFailed → Applying 才是合法 retry，禁止把旧 Applying 当作 retry 成功 |
| canonical DeliveryFailed 后重试仍被旧 Applying 满足，或新 round 状态倒退 | retry operation 没有绑定 event-seq fence，或把 fence 前旧前缀当成新证据 | 对照 retry 发起时的 canonical event sequence；只有严格大于 fence 的 Applying/Applied 才属于新 round。保留原 idempotency key，不补发第二次决定 |
| `.lagged` 后 fresh snapshot 已到，但审批卡回退或同步横幅不消失 | recovery snapshot 被错误当成审批账本 reset，或 UI 未完成 generation barrier | 保留同 observation 的 context/receipt/retry/operation 与 terminal floor；核对 backfill 的 turn/command/approval/request identity。snapshot 成功后应恢复 connected，任何错绑必须 security fail-close |
| 新 `turnStarted` 或 snapshot 后 direct turn terminal 到达，但旧状态仍是 Pending/Submitting/DeliveryFailed | 非终态 approval 被错误退休或继续保持可点击，canonical journal 存在分叉或缺帧 | 必须进入 `.securityError`。只有 Applied、Expired 或等价 terminal AlreadyHandled 可以跨 turn；direct Failed 没有 turnID 时只可用全库唯一 commandID 绑定，matching terminal event 本身不能替代 approval terminal 证据 |
| canonical 已终态但异步 receipt 更晚到达 | 正常的双轴乱序；ViewModel 会在最多 32 条 retired-operation 证据内继续校验 | 核对 receipt approvalID 与 canonical winner；完全一致则保持终态，不一致立即 security fail-close。队列满不是可恢复网络错误 |
| bare `.expired` receipt 显示 `.expired(nil)` | Pending 在 claim 前过期，没有 winner；已 claim 的过期会返回 `.alreadyHandled(winner, .expired)` | 不填本地提交决定；若后续同 identity 的 canonical 带 winner，视为 authenticated state fork 并 security fail-close |
| `.alreadyHandled(approvalID, decision, state)` | first-valid winner 已由 daemon 决定，可能来自另一客户端 | 显示 receipt winner/state；只在 state 为 DeliveryFailed 时按同 winner 请求 delivery retry，不允许反向决定 |
| receipt approvalID 与当前 context 不同，或 receipt/canonical 都有 winner 且不一致 | 身份错绑、迟到跨 operation response 或 authenticated state fork | 立即进入 `.securityError` terminal，取消 observation/prompt/approval task，保留原序列用于审计；不得清 state 后继续 |
| `.revoked` / `.incompatible` / `.securityError` 从 observation 或 command/approval failure 到达 | 不可恢复 terminal，而非普通网络波动 | 禁止后续 prompt/approval；完成 source/credential cleanup readback后再按升级或重新配对流程处理，不进入 reconnect loop |
| fixture subscriber 收到 `.lagged(.bufferDropped)` 后结束 | preview/test consumer 填满 512 buffer，旧 generation 已终止 | 新建 observation，并确认首帧为更新后的 fresh snapshot、sequence 连续；不得继续使用旧 stream |
| Machine/Session/Inbox 收到 retryable `.failed` 后仍显示旧 ready 行 | ViewModel 没有把错误态与旧缓存投影分离，用户可能误判资源仍可用 | `.failed` 必须清空旧列表/分组并触发一次 `onUpdate`；retryable 只控制重试入口，不能保留旧 ready 数据遮蔽错误 |

如果 fixture 解码或 canonical reducer 失败，`FixtureSessionSource`/ViewModel 会发出或进入
`SessionConnectionState.securityError`，而不是跳过坏 event。先检查 fixture 是否以
`ConversationSnapshotV2` 起始、capabilities 是否为 snapshot 第一项、后续 `RuntimeEventV2.eventSeq` 是否
exact-next，以及 approval 的 turn/command/approval/request identity 与赢家是否连续。fixture 的
`inspectPairInvite`/`pair`/`revokeSelf` 明确返回 typed refusal，因为它只用于 preview/test。
Core 与 Relay reducer 对每个 turn 的 pending + resolved approval identity 总量都限制为 32；若第 33 个
identity 被接受、overflow 后 cursor/ledger 变化，或 `.at(H)` snapshot 的一次 mid-turn inference 被第二个 turn
复用，都应按 reducer/security bug 处理，而不是扩大上限或跳过事件。
Runtime v5 没有为本次收紧升级 wire version：commandless Error 保留 diagnostic 兼容面，command-bound Error 则
只允许 Store-owned fixed Failed terminal。若 fixture、Relay 或 macOS 把前者投影为 failed inbox/turn terminal，
或把后者留在 active turn 后继续接收下一 `TurnStarted`，都属于同 candidate 的 reducer bug。

#### P5.6 iOS production composition / pairing lifecycle 诊断

P5.5 candidate 当时的 `SceneDelegate` 仍注入 `FixtureSessionSource`；因此该 Task 的 connected、prompt、
approval 或 reconnect UI 只证明 presentation/fixture 语义。P5.6 已把 Release composition 切到真实
`RelaySessionSource`，fixture 只在 Debug preview/test 可达；若普通 Release 启动仍出现 fixture machine，或
Release binary 命中 fixture launch/install 字符串，应按 packaging/security regression 处理。P5.6 收口时
P5.7–P5.9 与 P5 Phase Exit 当时尚未完成；后续 P5.7 与 rescue P5.8-lite 已独立收口。当前只剩 P5.9 与
P5 Phase Exit 未完成；
其中 P5.9 必须跑 fixed-topology Simulator Relay E2E，不能
标成 post-MVP BLOCKED。真实公网 WSS、物理 iPhone、production-signed Keychain、第二台 Mac、真实 vendor 与
destructive purge 才继续属于 post-MVP `BLOCKED`。

若扫码页离开、scene deactivation 或重新激活后仍被旧权限回调、start completion、metadata 或 stop 改写，应按
capture generation 隔离回归处理：配置/start/stop 必须只在专用串行队列执行，只有 view visible + scene active
才持有 exact UUID；metadata proxy 要保留到 metadata queue barrier 后，MainActor 仅在 UUID 仍属于当前
generation 时更新 UI 或提交邀请。Simulator 自动门禁不替代物理 iPhone 的相机权限、交互式返回与锁屏
data-protection readback。

#### P5.7 macOS local/remote SessionSource registry 诊断

| typed state / 现象 | 含义 | 下一步 |
| --- | --- | --- |
| local scope 返回 `.transportUnavailable`，diagnostic 为 `daemon.client.socket_missing` | 当前 OS account 没有运行中的 canonical daemon；stable `swift run AgentDeck -- --selfcheck` 不能据此记为产品 PASS | 先核对 LaunchAgent/UDS owner；开发门禁使用 hermetic local-runtime smoke 与 ephemeral daemon selfcheck，禁止为通过测试临时改 stable socket |
| 切换 machine 后旧 catalog/conversation 又覆盖当前 UI | selected-scope generation 没有在 replacement 前取消并 join 旧 observation/model | 核对 generation、scope key 与 shutdown/join 顺序；旧 generation 的任何 update 必须被丢弃，不要只清可见列表 |
| remote/fixture scope 出现本机 pending-device approve/cancel 能力 | registry 泄漏了 local-only capability，或 UI 对 concrete source 做 downcast | 只从 registry 读取 typed optional `LocalPairingAdministration`；remote/fixture 必须为 `nil`，按 security regression 处理 |
| remote source 已 transport connected，但 Catalog/Conversation 提前订阅或串到另一台机器 | business-ready 未同时绑定 exact connection ID + transport generation，或复用了 `.allPairedMachines` owner | 每台 remote machine 固定独立 `.machine(id)` source；只有 exact current ready scope 能开始订阅，generation 变化必须先退休旧 correlation |
| Genesis barrier 重启后反复 ACK、缺 ACK 或出现 phantom activation | replay admission、activation、CounterGuard stable 与 ACK permit 的 crash cut 恢复不完整 | 分别检查 `stateGuardPendingDurable`、`stateDurable`、`guardStableDurable`；只有 exact durable proof 可恢复 permit，stale tuple 必须零 mutation/零 action |
| confirm 反复返回 `daemon.runtime.snapshot_required` | RuntimeCore snapshot materialization 未覆盖当前 H，或 retry 超出三轮恢复上界 | 只为 typed snapshot prerequisite materialize Catalog 与缺失 conversation snapshot并重新采样 H；其他错误不得触发 snapshot 写入，第四次 prerequisite 必须原样返回 |
| observation handler 内重入 `select`/`shutdown` 卡死 | selected-scope owner 正在等待或取消自身 observation task | 识别 current task，禁止 self-join；将旧 task 移入 retired 集合，最终只由外部 shutdown barrier 完整 join |
| 退出 App 后 blocked prompt/inbound handler 仍存活，或 termination 过早回复 | `SessionModel` operation registry 漏记业务 task，或 coordinator 把 wire close 当成 pump terminal | 停止 admission 后 cancel/join 全 registry；Preview 必须显式注册 fixture scope，外部 `close()` 捕获并 join exact pump，handler 派生 close 不得跳过 join |

P5.7 的真实 dual-scope integration 使用本机 UDS 与由真实 P4 daemon RemoteLink 支撑的 remote source；synthetic
adapter 只替代 vendor，不替代 daemon/PairingCoordinator/RemoteLink。后续 rescue R3 只补齐本机
pending-device approval；可见 picker、remote pair sheet/receipt UI 仍属 post-MVP，P5.9 Simulator UI E2E
仍未完成。

#### Rescue R3 本机 pending-device 面板诊断

| typed state / 现象 | 含义 | 下一步 |
| --- | --- | --- |
| 面板显示“本机 Runtime 暂不可用” | local UDS 当前不可达；没有发生授权，也不能把失败误当空列表 | 核对 stable LaunchAgent/UDS owner；开发验证用 hermetic local-runtime smoke，不临时占用 canonical socket |
| 同一 pairing 行在处理中仍可再次点击，或 terminal 后立即恢复按钮 | UI 未保持 per-ID single-flight/terminal 锁存 | 保留当前 identity 的 in-flight/terminal gate，直到 pending stream 真正删行；不得靠重复请求碰运气 |
| 同一 pairing ID 的 fingerprint/request hash/expiry 变化后旧结果覆盖新行 | mutation 未绑定完整 pending identity，存在 ABA | 立即锁为 security failure；迟到结果和不同 receipt ID 都必须 fail-close，不授予权限 |
| 面板或日志出现 request hash、secret、grant、私钥 | UI/诊断越过最小披露边界 | 只显示完整 DeviceSign fingerprint；按安全回归处理并清理 artifact，禁止提交截图/日志 |
| Preview/fixture 或 remote scope 出现“本机配对请求…” | composition 泄漏 local-only administration capability | 菜单只由 production local composition 安装；禁止 downcast concrete source 或按 vendor/machine kind 分支 |

#### Trust reset 与本地 cleanup

| code | 含义 | 下一步 |
| --- | --- | --- |
| `daemon.remote.trust_reset.admin_receipt_required` | MachineRoot 丢失，不能在线签 retirement | 按 runbook 在 Relay 本机 purge并取得 portable signed receipt，再以私有文件重试 |
| `daemon.remote.trust_reset.root_present_receipt_forbidden` | MachineRoot/transport仍可用却提供 admin receipt | 删除 receipt 参数，执行普通 root-present retirement |
| `daemon.remote.trust_reset.binding_mismatch` / `relay_id_invalid` / `route_id_invalid` / `authenticated_relay_mismatch` / `epoch_mismatch` | retirement或proof不属于当前 authenticated trust domain | 保留旧状态并人工核对；禁止试错 purge、改 locator或生成新 route |
| `daemon.remote.trust_reset.root_key_invalid` / `signature_invalid` | root public key或 retirement签名无效 | remote保持blocked；root确实丢失时走portable proof，不伪造在线签名 |
| `daemon.remote.trust_reset.state_conflict` / `terminal_invalid` | lifecycle不允许该转换，或 RetirementCommitted bytes/hash/binding无效 | 以原 frozen input读取/retry；不得跳到LocalDeleted |
| `daemon.remote.trust_reset.terminal_timeout` | Relay 未在 10 秒绝对 deadline 内返回 RetirementCommitted | 保留同一 RetirePending frozen bytes，确认 Relay/链路恢复后 exact retry；shutdown/upgrade 会在 manager mutex 外取消等待，禁止改 route/cert |
| `daemon.remote.trust_reset.proof_invalid` | portable receipt的verify key/signature/server/route/root/epoch/readback任一不匹配 | 零本地删除；从可信Relay重新取得同realm receipt，禁止修改JSON字段 |
| `daemon.remote.trust_reset.transport_missing` / `relay_restarting` | root-present路径缺authenticated transport，或Relay正在drain | 保留RetirePending并在同一Relay恢复；不要切到root-lost或新route |
| `daemon.remote.identity.cleanup_binding_mismatch` / `cleanup_partial_state` / `cleanup_counter_axis_duplicate` | 本地key/guard/counter axis与authenticated tombstone不一致，或删除只完成一部分 | 停止cleanup，保留全部残余并按同一 expected fingerprint恢复；不得任选一侧当权威 |
| `daemon.remote.identity.delete_failed` / `fingerprint_mismatch` | expected fingerprint错或delete后item仍可读 | 零容忍停止 destructive flow，重新读status/target；禁止无expected fingerprint批量删除 |

#### `daemon uninstall --purge` 与 stopped finalizer

marker 一旦 reserve并 exact readback，即代表 durable purge intent，manager 必须 fence enroll。root-lost 必须先用
portable receipt完成普通 trust-reset；`daemon uninstall --purge` 本身不接收 receipt。错误处理按阶段分组：

| code | 含义 | 下一步 |
| --- | --- | --- |
| `daemon.purge.finalizer_unavailable` / `authorization_invalid` / `identity_unavailable` | production finalizer identity不可建立，或当前 authenticated Store状态不能授权plan | 零删除；核对签名helper、stable namespace与当前 lifecycle，禁止因DB absent推断授权 |
| `daemon.purge.recovery_required` | durable marker/intention存在但尚未安全完成 | 所有 enroll保持fenced；用同一安装helper和exact plan重试purge |
| `daemon.purge.plan_mismatch` / `marker_missing` / `marker_invalid` / `marker_conflict` / `marker_unauthorized` / `marker_persistence_failed` | plan ID、marker shape/state或exact readback不一致 | 保留marker与安装artifact；不要创建第二plan、删除marker或手改Keychain |
| `daemon.purge.daemon_not_running` / `pid_missing` / `pid_changed` / `daemon_still_running` / `socket_unsafe` | live daemon/PID/UDS无法建立稳定停止边界 | 停止操作并核对launchd、PID与socket identity；不得在进程仍可能运行时调用finalizer |
| `daemon.purge.helper_missing` / `helper_unsafe` / `helper_mismatch` / `attestation_mismatch` / `attestation_changed` | retained helper不存在，或owner/mode/nlink/version/hash/signature发生变化 | 零删除；恢复同一已签名安装artifact，禁止换helper续做原plan |
| `daemon.purge.namespace_invalid` / `install_layout_invalid` / `filesystem_unsafe` / `stopped_recovery_unsafe` / `stopped_permit_mismatch` | stable namespace、bin/current/plist/parent或stopped permit不满足exact安全布局 | 保留残余并修复真实安装布局；禁止symlink/hardlink/递归rm绕过 |
| `daemon.purge.runtime_request_invalid` / `runtime_reply_invalid` / `runtime_readback_mismatch` | current Runtime v5 purge request/reply不是exact plan或未读回`PurgeReadbackAbsent`+marker | 不bootout、不删文件；升级同一candidate并用原plan重试 |
| `daemon.purge.key_item_conflict` / `storage_kek_missing` / `storage_kek_conflict` | machine key/guard/StorageKEK与frozen binding冲突或KEK在marker前已缺失 | 停止finalizer；DB absent或部分key absent不能补充授权 |
| `daemon.purge.delete_readback_failed` / `cleanup_readback_failed` / `terminal_proof_failed` / `synchronization_failed` | 删除后仍可读、retained helper/bin仍存在、marker-missing终态证明或fsync失败 | 保留剩余artifact并exact retry；不得打印成功或假定最终一致 |
| `daemon.purge.helper_failed` / `io_failed` | finalizer子进程或文件系统操作失败 | 读取稳定code与剩余exact paths，保持plan/marker；不要无计划续删 |

`daemon.purge.injected_crash` 只属于 automatic fault harness，不是 production 操作者可恢复码。生产日志与错误不得
包含 helper path、完整 route/fingerprint、key bytes、receipt、terminal、plan或marker内容；只记录阶段与稳定 code。

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

P3.6 publication 只接受测试注入的 opaque/fake sealed blob，验证 freeze/COMMIT/ACK/restart 算法；这是
P3.6 历史 component gate 的边界。P4.5 已安装真实 MachineDataSign/E2EE sealing、CounterGuard 与
Relay publication，但 P3.6 的 fake blob、Runtime TransferPart 或 Simulator fixture 仍不能冒充 P4.5
证据。P4.6 automatic Task 已把 bounded transfer reassembly 接入 paired-state V6 durable
records，duplicate/metadata/hash/length/TTL/配额冲突映射为上表 `remote.transfer.*` bootstrap marker，并接入
authenticated watch。冻结范围与门禁证据见上节；这些 automatic 证据仍不得据此宣称
production-signed、真实公网持续 watch/WSS、iOS 真链路或 P4 Phase PASS。

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
非秘密、未加 MAC 的 rescue locator，不是授权凭据。P4.2 用 authenticated `machine_remote_state` 交叉审计
该 locator，并要求 enrollment 时锚定的 Relay verify key 验证 portable admin-signed purge receipt；该表被
改写时 open/recovery fail-close，但不得据此直接删除远端或本地状态。P4.1 当时只有通用 CounterGuard IO；
当前 P4.5 已建立 active reservation、DB rollback reconciliation 与 retire/rekey/fail-close，并在
open/recovery 中交叉审计 authenticated Store/Keychain 状态。P3.2/P3.3/P4.1/P4.2 的历史证据仍不能冒充
P4.5 覆盖。

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

侧栏默认发起不带 agent 和 cwd 过滤的跨 agent 历史查询。界面没有会话或只出现
一家来源时，先用同样的全局查询复现，再分别探测两个来源：

```bash
agentdeck history list
agentdeck history list --agent codex --limit 20
agentdeck history list --agent claude-code --limit 20
```

排查“全部历史为空”时不要加 `--cwd-filter`，否则结果会被缩小到指定项目。Codex
列表和读取分别调用官方 `thread/list`、`thread/read(includeTurns=true)`，不是扫描
当前 AgentDeck 会话或猜测本地记录格式。

当前 Swift 与 CLI 会为每次历史请求生成唯一 `requestId`；daemon 无论成功还是失败
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
| `history-request-timeout` | 包含双来源合并在内的完整历史请求超过 daemon 的 32 秒总 deadline；Swift 等待 35 秒，为终态回复穿过 stdout、完成 `requestId` 匹配与投递保留 3 秒余量 | 分别运行两条带 `--agent` 的 list 命令定位慢来源；该请求已被 daemon 终止，不会在下一次刷新中产生迟到 reply |

跨 agent list 是 best-effort：每个来源有独立的 30 秒 deadline；只要至少一个来源
成功，router 就合并并返回成功来源的数据，另一来源失败或超时不会阻断结果；成功
来源合法返回空列表时，合并结果也可能为空。
因此“看到一些会话”或“没有收到聚合错误”都不代表两家来源同时健康，必须用上述
两条带 `--agent` 的命令分别确认。只有没有来源或所有来源失败时，才分别返回
`history-no-sources` / `history-all-sources-failed`，不再伪装成成功空列表。

## Raw / Warning 可见性

未知 adapter item 必须在 daemon 侧中立化为 `raw`，并继续进入 run record 与
runtime UI。`rawKind` 只保留最长 64 字节的安全方法/类型标识，`rawPayload` 固定为
`[vendor payload withheld]`，不携带 vendor 原始 JSON；如果 UI 看不到 `raw`，
优先检查 `ThreadRuntimeModel` 的 agent item ingest 路径。

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
| `cc-history-mutation-requires-runtime-gate` | legacy history compatibility 尝试直接 Rename/Archive/Unarchive | 改走 Runtime `UpdateConversationMetadata`；MVP native production 会在 claim 前返回 typed `metadata_unsupported`，不得恢复旧 direct vendor/no-op 路径 |
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
