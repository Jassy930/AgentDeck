# AgentDeck Relay v2 运维手册

本页只记录已经由自动化测试真实跑通的 Relay v2 管理命令与安全边界。production
binary 已在 P2.9 原子切换为仅 Relay v2；P2.10 又以真实 Direct TLS/SPKI synthetic、
安全扫描与故障注入门禁收口。P4.1 已完成 daemon machine identity/guard；P4.2 又以
`a6842bc` 完成 Runtime v3、schema v9、certificate、durable enrollment/receipt、
control-only RemoteTransport、两条 trust reset 与安全 uninstall purge；P4.3 又由 `518380e`、`b28f995`、
`55be98f`、`ba3629f`、`4ec3d2f`、`fe3a9ad`、`3b4b977` 完成 Runtime v4、schema v10、本机确认 pairing、DeviceGrant/
DeviceAuthorization/KeyDirectory、auth ledger 与 revoke；P4.4 `cd7d9fb` 接通业务 ingress/Core，P4.5
`c6ef387`、`88b3c42` 又完成 signed publication/counter recovery，并把 current physical schema 推进到
v14/35 表。P4.6 persistent remote CLI 已完成 automatic Task，current Runtime wire 为 v5；
P4 按 Task 进度为 6/7，P4.7、P4 Phase Exit 与 iOS 真实链路仍未完成。因此本页不是“公网 Companion 已上线”或
production-signed LaunchAgent/Keychain 已 PASS 的证明。

## 部署不变量

- production 公网只允许 Direct TLS/WSS。明文 loopback 与可信反代后的 loopback
  backend 都必须显式选择，只用于受控开发；明文 loopback 不能启用 admin/enrollment。
- v1 协议与兼容路径已经物理删除。`/v1/connect` 只返回无状态 HTTP 426，不升级
  WebSocket，也不触发 Auth/Core/Store；禁止自动降级。
- `admin_socket` 必须是绝对路径，父目录由 Relay 运行用户持有且不得向 group/other 开放；
  socket 固定为 `0600`，server 逐连接核对 peer UID。
- `public_wss_url` 必须是无用户名、query、fragment 和额外 path 的 `wss://` origin。
- `spki_pins` 只能有一或两个 base64url-no-padding SHA-256 pin。direct TLS 下第一项必须等于
  当前 leaf certificate 的 DER SPKI SHA-256；第二项只用于下一张证书的受控轮换。
- 管理命令只有本机 JSONL UDS。公网 `/v2/machine-enroll` 只处理首次登记；网络 listener
  不存在 inventory、readback 或 purge API。

配置项可来自 CLI、`AGENTDECK_RELAY_*` 环境变量或 TOML，优先级逐字段为
CLI > env > TOML > defaults：

production Direct TLS 配置示例：

```toml
bind = "0.0.0.0:8443"
health_bind = "127.0.0.1:8444"
storage = "/var/lib/agentdeck-relay/relay-v2.db"
tls_cert = "/etc/agentdeck-relay/tls/fullchain.pem"
tls_key = "/etc/agentdeck-relay/tls/private-key.pem"
admin_socket = "/var/run/agentdeck-relay/admin.sock"
public_wss_url = "wss://relay.example.com/"
spki_pins = ["BASE64URL_SHA256_CURRENT", "BASE64URL_SHA256_NEXT"]
```

对应环境变量是 `AGENTDECK_RELAY_ADMIN_SOCKET`、
`AGENTDECK_RELAY_PUBLIC_WSS_URL` 与逗号分隔的 `AGENTDECK_RELAY_SPKI_PINS`。

部署前先以同一配置执行完整 preflight；selfcheck 会验证 TLS identity/SPKI、打开并
重开 SQLite Store、构造 Core/Auth，再在不绑定 listener 的情况下退出：

```bash
agentdeck-relay --selfcheck --config /etc/agentdeck-relay/relay.toml
agentdeck-relay --config /etc/agentdeck-relay/relay.toml
```

## 创建 machine enrollment bundle

先确保输出文件所在目录只有当前用户可读。命令的 stdout 是唯一包含 256-bit 一次性 code
的输出面；不要把 stdout 接入普通日志：

```bash
umask 077
agentdeck-relay machine-enroll create \
  --admin-socket /var/run/agentdeck-relay/admin.sock \
  > machine-enrollment-bundle.json
```

bundle 包含 Relay server ID、公开 WSS origin、当前/下一 SPKI pin、5 分钟到期时间和一次性
code。Relay SQLite 只保存 code 的 SHA-256。daemon 在发送 code、MachineRoot 或 link/data
public material 前，必须先完成公开 CA 或 bundle SPKI pin 验证；redirect 一律拒绝。

同 code + 同 canonical request 在 TTL 内会逐字节重放首次冻结响应；同 code + 不同请求
拒绝。两个并发请求只有一个能建立 route。签名、公钥或证书角色校验失败发生在 code 消费前。

需要验证当前 Relay 全链路而不建立持久配对时，用该 bundle 驱动真实外部
Direct TLS listener：

```bash
agentdeck remote synthetic --bundle machine-enrollment-bundle.json
```

该命令使用临时 machine/device key，真实完成 enrollment、fresh challenge 鉴权、
InstallGrant、register/publish/subscribe replay、Send/Reply、signed revoke 与终态重连。
不得把 synthetic 临时结果当作已保存设备配对。

## 让 stable daemon 持久登记本机

P4.2/P4.3 的本机管理只走 same-UID canonical current Runtime v5 UDS，不创建第二个 admin socket。bundle 必须是
current-UID、single-link、no-follow regular file，group/other 权限为零且不超过 64 KiB；推荐保持 `0600`：

```bash
chmod 0600 machine-enrollment-bundle.json
agentdeck remote machine enroll \
  --bundle-file "$PWD/machine-enrollment-bundle.json"
agentdeck remote machine status
```

enroll 在发送 code、MachineRoot 或 Link/Data public material 前完成 CA/hostname/SPKI 校验。P4.2 收口时
只建立 authenticated **control-only** MachineLink；后续 P4.4 在同一 supervisor/session 上增加了唯一
business ingress lane。完全相同的 bundle 可用于 exact retry；不同 code/origin/pin/Relay/receipt
anchor/expiry 会在网络前 conflict。

P4.3 已提供下节 `remote pairing ...` 与 exact `remote revoke` 本机管理面；P4.6 已接入
`remote pair|machines|conversations|watch|prompt|approve|retry-approval|revoke-self`；旧
`sessions/send/deny/ping` 命令面已删除。P4.6 automatic Task 已完成，计为 P4 的第 6/7 项。
automatic gate 使用 injected dev/ephemeral keystore 与 hermetic namespace；真实 production 命令仍要求
provisioned、release-signed daemon/CLI 与正确 entitlement，当前槽位保持 post-MVP BLOCKED，不能由
automatic PASS 代替。

## Persistent CLI 配对、查询与 watch

PairInvite bearer 不得放入 argv。使用 current-UID、exact-0600、no-follow regular file，或重定向的
non-interactive stdin；同时人工核对带外 MachineRoot fingerprint：

```bash
agentdeck remote pair \
  --invite-file /secure/path/pair-invite.txt \
  --confirm-root-fingerprint <root-fingerprint>
agentdeck remote machines
```

`machines` 只读本机 PairedMachineStore，不拨 Relay。其余命令必须同时使用 canonical padded STANDARD
base64 的 32-byte root fingerprint 与 16-byte machine route，不能用 display name、device route 或 URL
回退选择：

```bash
agentdeck remote conversations \
  --machine-root-fingerprint <standard-base64-32> \
  --machine-route <standard-base64-16>

agentdeck remote watch \
  --machine-root-fingerprint <standard-base64-32> \
  --machine-route <standard-base64-16> \
  --conversation-id <conversation-id>
```

prompt、approval 与 self-revoke 使用同一 exact machine selector；前两者只有取得 authenticated daemon
receipt 才能成功退出，`RouteAccepted` 不能替代 receipt：

```bash
agentdeck remote prompt \
  --machine-root-fingerprint <standard-base64-32> \
  --machine-route <standard-base64-16> \
  --conversation-id <conversation-id> \
  --text "continue safely" \
  --idempotency-key <stable-key> \
  --expected-configuration-revision <revision>

agentdeck remote approve \
  --machine-root-fingerprint <standard-base64-32> \
  --machine-route <standard-base64-16> \
  --conversation-id <conversation-id> \
  --turn-id <turn-id> \
  --approval-id <approval-id> \
  --decision approve \
  --request-id <stable-request-id>

agentdeck remote retry-approval \
  --machine-root-fingerprint <standard-base64-32> \
  --machine-route <standard-base64-16> \
  --conversation-id <conversation-id> \
  --approval-id <approval-id>

agentdeck remote revoke-self \
  --machine-root-fingerprint <standard-base64-32> \
  --machine-route <standard-base64-16>
```

`watch` stdout 是逐行 flush 的 canonical NDJSON，阶段只包括
`bootstrap|synchronized|live|control|terminal`。bootstrap payload 使用 canonical raw JSON；
synchronized 保留 transport `routeAccepted` 与 requested cursor/subscription/sync-complete，但
`RouteAccepted` 仍不是业务成功。SIGINT/SIGTERM 会 latch：当前 exact frame 必须先 durable apply 并完成
ACK terminal；`TransferBootstrapRequired`/subscription control 必须先输出，再输出 terminal
`status=stopped`。Connected 与 ready signal 同时出现时零 Subscribe、shutdown 后 stopped；verified revoked
terminal 优先，且只有 transport shutdown/drop 与 crash-safe cleanup 完成后才输出 `status=revoked`。
EOF 或普通断线固定为 `remote.runtime.outcome_unknown`，不能伪造 stopped/revoked。

P4.6 的 live-stream partial 已写入 paired-state V6 sealed CAS，disconnect/crash/restart 不会重置其
absolute TTL。Relay 即使在最后一个 part 前永久静默，CLI runtime 也会按 sealed deadline 主动写入 durable
`remote.transfer.expired` marker，不等待下一帧。128 MiB 是 paired-state plaintext 编码的 logical budget，
不是 RSS 上限；candidate 超限会持久化 `remote.transfer.reassembly_full`，保留已认证 replay admission，但
不发送 ACK、不推进 reducer/outer applied/inner cursor，并清空该 binding 的 active/buffered records。不要通过
扩大容量或重启来绕过 bootstrap。8 MiB lowered-cap 只存在于 `debug_assertions` automatic test build，release
artifact 不含该入口，也不能由 CLI/env/config 设置。prepared ADST v2 的 Normal/EmergencyBootstrapMarker
mode 位于 AEAD 认证内容，guard commitment 绑定完整 sealed sidecar；legacy v1 只解释为 Normal。4095→4096
marker 的 guard-first/active-first crash cut 均可恢复，cleanup 只允许 exact owner unlink+retry，缺失后 reseal
或 commitment conflict 必须 fail-close。P4.7 与 P4 Phase Exit 尚未完成。

P4.4 完成 ingress/Core dispatch：Relay v2 outer、DeviceSign/AAD/replay/AEAD 和本机 auth-ledger
exact recheck 全部通过后，才把 `RemotePrincipal` 交给 RuntimeCore。invalid grant/signature/AAD/
replay 或 local revoke 后的旧 frame 会在 Core 前拒绝；`RouteAccepted` 仍不是 command success。
P4.5 已安装 `DirectedReplySealer` / `RemoteStreamPublisher`：顺序固定为 CounterGuard reserve→seal once→
Runtime DB 冻结 exact blob→Relay Publish COMMIT→local ACK；retry、outcome unknown 与 restart 都只能复用
同一 frozen blob。离线时 publication park，authenticated reconnect 后再继续；counter/publication/transition
recovery 未全部通过前 admission 保持关闭。P4.5 本身当时不含 persistent remote CLI 或 iOS 真链路；
上节命令面属于 P4.6 automatic Task，不能倒算为 P4.5 证据。不得为了调试绕过 admission，也不得把内部
publication PASS 当作远程 E2E；iOS 真链路仍未完成。

## 创建并本机确认 PairInvite

stable daemon 已 Active 后，invite 必须先持久化 open outbox，并在 Relay 对同 route/absolute expiry 返回
Open ACK 后才打印。daemon 使用 298 秒 TTL，为 Relay 300 秒硬上限保留 2 秒调度余量；不得延长、复活或
复用旧 invite。显示名只进入带外 PairInvite，不进入 Relay durable store：

```bash
agentdeck remote pairing invite \
  --display-name workstation \
  --idempotency-key invite-001
```

设备提交 byte-stable PairRequest 后，本机只展示 canonical pairing ID 与 DeviceSign fingerprint。仅当前
same-UID local principal 可以列出、确认或取消；远程 principal、PairingAccess 与 Relay 管理员都不能代办：

```bash
agentdeck remote pairing pending
agentdeck remote pairing approve 11111111-1111-1111-1111-111111111111
agentdeck remote pairing cancel 11111111-1111-1111-1111-111111111111
```

confirm/cancel/expiry 是 first-valid durable CAS；同动作重试只读回同一 canonical receipt。RouteAccepted 只
表示 Relay transport 接受，不能当作 grant 或业务成功；只有验证 exact DeviceSign-signed
`PairResponseReceived` 后才进入 delivered。GrantCommitted ACK 暂态失败会重发相同 InstallGrant；不要重建
grant、修改 PairResponse 或手改 Store。撤销必须绑定 exact device route 与 grant serial：

```bash
agentdeck remote revoke --device <device-route-id> --grant-serial <serial>
```

pairing drain 与 retirement 共用唯一 control owner：drain 绝对 deadline 为 10 秒，可被 shutdown 取消；
失败时保留 durable state并 exact retry。P4.3 本身不提供业务 Runtime dispatch；后续 P4.4 已接入
严格 ingress/Core；后续 P4.5 已完成 signed publication/counter recovery。P4.6 persistent remote CLI 已形成
automatic Task complete，但 P4.7、P4 Phase Exit、production-signed 与 iOS 真链路仍未完成。

### Pairing receipt 与 key-transition 恢复

不要为了“补齐”配对而手工发送 KeyUpdateAck。经过 DeviceSign 验证的 exact `PairResponseReceived` 会把
matching Add/Renew transition 的 target 作为已 ACK；其他设备仍保持 Frozen，等待各自普通 KeyUpdateAck。
因此 first-device zero-cut Add 可以不经过第二条 ACK 直接收敛到 `BusinessReady`。PairResponse 与后续
KeyUpdateSet 使用独立随机 HPKE ciphertext 是正常现象；系统比较稳定 slot identity、confirm-time 完整
global-state hash 与同 revision 稳定 key-lineage digest，不比较 `enc`/`wrapped_key` 字节。digest 只覆盖
active roster/current epoch/真实 key material；retention owner、retired tombstone 与 revoked-secret GC 可在
不推进 revision 时合法变化，不应据此诊断为 state fork。

receipt 与普通 KeyUpdateAck 的两种到达顺序都支持：ACK 先到时保留真实 ACK，fresh receipt 不能早于该
durable 时间；receipt 先到时后续 ACK 可升级 evidence，但不会移动 Completed transition 的 terminal 时间。
出现 clock regression、target/revision/slot/global-state mismatch 或 proof 后 cancel 时，保留原 pairing、transition、
DB/WAL/SHM 与 Keychain，修复时钟或调查状态分叉后只重试 exact input；禁止手改 SQLite、伪造 proof 或放宽 ACK。

从旧 candidate 升级时，ADKT v1/v2 Delivered row 若仍有 matching Add/Renew transition，只有当前 global
revision 仍等于 receipt binding revision、且完整 global-state hash 精确一致时，第一次 exact receipt replay
才可能原子回填 stable lineage 与 v3 proof，之后 replay 为只读；matching Completed transition 在 Close scrub
前会被 GC pin。若 global revision 已经前进，旧 row 无法证明历史 key material lineage，必须零写拒绝，不能
以 `stable_key_lineage_hash=None` 继续 Close。当前 ADKT v3 Add/Renew 缺失 global/stable lineage 一律按损坏
拒绝，不能进入 legacy backfill。
若升级前旧版本已经完整 GC transition/update，authenticated audit 只允许 exact receipt replay 与 Close scrub，
不会重建 transition 或 proof。若 transition 不在但 matching update 仍在，按损坏停用 remote，不做自动修复。

fresh Close ACK 会在 scrub pairing/outbox 的同一事务内把 receipt tombstone 延长到 ACK 后完整 30 天；原
`created_at_ms` 仍是 receipt 的审计时间。AfterCommit-unknown 后重开会读到已延长的 tombstone；exact Close retry
只读且不再次续期。不要通过重复 Close 延长保留期。

## 本机 inventory 与 readback

inventory 分页上限固定为 128，输出 route、root fingerprint、trust epoch 和 retired 状态：

```bash
agentdeck-relay machine inventory \
  --admin-socket /var/run/agentdeck-relay/admin.sock
```

`machineRoute` 使用协议 ID 的标准 Base64（含 padding），`rootFingerprint` 使用
base64url、无 padding；两者都可直接从 inventory JSON 复制。readback 必须同时提交旧 root
fingerprint，防止只凭 route 误确认另一个 trust domain：

```bash
agentdeck-relay machine readback MACHINE_ROUTE \
  --confirm ROOT_FINGERPRINT \
  --admin-socket /var/run/agentdeck-relay/admin.sock
```

完成 purge 后，readback 的期望值是 `activeMachineRoutes=0`、grant/revocation/stream/frame/
subscription 全为 0，并保留 `retiredTombstones=1` 的最小不可复活 tombstone。

## MachineRoot 尚在时的 trust reset

普通 reset 不接受 admin purge receipt：

```bash
agentdeck remote trust-reset
agentdeck remote machine status
```

daemon 复用当前 authenticated MachineLink，冻结一次 root-signed `RetireMachine` 并只重试同一 canonical
bytes。Relay 的 `RetirementCommitted` 只会在 purge COMMIT 且 active/data absent readback 已完成后产生；daemon
先持久化 exact terminal，再独立 CAS 到 `PurgeReadbackAbsent`，因此不另发明第二个网络 readback API。最后删除
旧 machine keys/guard 并保留 authenticated `LocalDeleted` tombstone；下一次显式 enroll 才建立新 trust domain。
在 root 仍可用时传 `--admin-purge-receipt-file` 必须返回
`daemon.remote.trust_reset.root_present_receipt_forbidden`，不得借 admin proof 绕过在线 retirement。

## MachineRoot 丢失后的 portable purge receipt

本项目不提供 root 恢复。daemon 保持 `Blocked`；先读最小状态。缺 receipt 的 trust-reset 会返回
`requestFailureCode=daemon.remote.trust_reset.admin_receipt_required`，并只在该安全状态输出严格的 Relay admin
purge NDJSON/命令模板：

```bash
agentdeck remote machine status
agentdeck remote trust-reset
```

操作者人工核对输出中的旧 route/fingerprint 后，在 Relay 主机的本机 admin UDS 执行 purge。CLI 返回完整
JSON response；把其中 portable signed receipt 提取为 current-UID 私有文件：

```bash
umask 077
agentdeck-relay machine purge MACHINE_ROUTE \
  --confirm ROOT_FINGERPRINT \
  --admin-socket /var/run/agentdeck-relay/admin.sock \
  > machine-purge-response.json
jq -e '.status == "ok" and .result.kind == "machine_purged"' \
  machine-purge-response.json >/dev/null
jq -e '.result.receipt' machine-purge-response.json \
  > machine-purge-receipt.json
chmod 0600 machine-purge-receipt.json
```

错误 fingerprint 在 SQLite transaction 内、任何删除之前拒绝。正确 purge 通过同一个 Core actor 与
连接/PairRoute 操作线性化；COMMIT 后只保留不可复活 tombstone，并返回由专用 Relay receipt key 签名、绑定
server/route/root/epoch/readback 的 proof。把 receipt 带回被控机器：

```bash
agentdeck remote trust-reset \
  --admin-purge-receipt-file "$PWD/machine-purge-receipt.json"
agentdeck remote machine status
```

daemon 只使用 enrollment 时持久化的 authenticated receipt verify anchor 验证 proof；route、root、epoch、
readback 或 signature 任一不匹配都零本地删除。`machine_enrollment_receipts` 的三字段 locator 只用于定位，
不是授权。成功后状态为 `LocalDeleted`，才允许显式重新 enroll；无法访问 Relay 管理面时不能安全重建 route。

## LaunchAgent 卸载与全量 purge

普通卸载删除 LaunchAgent/plist 和已安装 binary，但保留 Runtime DB 与 Keychain：

```bash
agentdeck daemon uninstall
```

显式 `--purge` 是 destructive 操作。root-present 时它可在同一流程完成 trust reset；root-lost 时必须先按
上节用 portable receipt 把本机状态推进到 `LocalDeleted`，因为 `daemon uninstall --purge` 不接受 receipt 参数：

```bash
agentdeck daemon uninstall --purge
```

CLI 先校验已安装 helper 的签名、entitlement、version、hash、TeamIdentifier/access group，向运行中 daemon
reserve 并 exact-readback 一次性 purge plan；marker 一旦存在就 fence 后续 enroll。daemon 完成/读回 trust
reset 后，CLI 才 bootout 并确认 PID/UDS absent，再由 retained helper finalizer 删除版本目录/plist、Runtime
DB/main/WAL/SHM、machine Keychain items，最后删除 StorageKEK。每一步都复核 namespace/helper/marker identity
并可在 crash 后 exact retry；“DB 已不存在”本身从来不是删除 Keychain 的授权。任一前置失败必须 fail-close，
不得手工拆开顺序或以 `rm`/`security delete-*` 冒充完成。

## Runtime v5 hard-cutover 开发凭据

Runtime version 已绑定 MachineRoot TBS。P3.9 的 Runtime v1→v2 与 P4.2 的 v2→v3 hard cutover 证据继续
保留；P4.3 收口时 contract 为 Runtime v4，P4.6 已将 current wire 升至 v5；production 只接受 current v5。
旧签名材料不会通过 current verifier：对外只返回
通用 `relay.auth.invalid_grant` / `relay.enrollment.rejected`，不暴露失败字段。这是预期 hard cutover，不是可
自动迁移的数据。

P4.3 pairing trust realm 使用前，任何曾生成 Runtime v1 签名材料的开发 trust realm 都必须按以下顺序处理：

1. 先用可信 Relay admin inventory 查询旧 route/root fingerprint。
2. realm 存在时执行 admin purge，并用同一 fingerprint readback，确认 active、grant、revocation、stream、
   frame、subscription 全为 0 且只剩 retired tombstone。若 inventory 可信确认 absent（例如从未 enrollment
   或开发 Store 已受控重建），记录 absent 结果；不得为了满足流程伪造 tombstone。
3. 只有完成 present realm 的 purge/readback，或得到可信 absent 结果后，才删除对应本地开发 trust state。
4. 生成新的 route/key，使用 current Runtime v5 重新 enroll，再让每台设备重新 pair；禁止恢复旧
   cert/grant 或自动降级 verifier。

`scripts/reset-relay-v1-dev-state.sh` 只处理早期 Relay v1 DB/bearer credential，不处理 Relay v2 Store 中的
历史 Runtime TBS 开发凭据。当前本地 trust-reset 必须走上述 Runtime v5 命令与 signed proof；不得手改
SQLite、Keychain 或签名版本来伪造完成。

## 常见 failure code

| code | 含义 | 处理 |
| --- | --- | --- |
| `relay.tls.spki_pin_mismatch` | 当前 leaf SPKI 与配置第一 pin 不同 | 停止启动，核对证书部署与受控轮换顺序 |
| `relay.admin.socket_parent_insecure` | UDS 父目录 owner/mode 不安全 | 改为 Relay 用户持有的 0700 目录 |
| `relay.admin.socket_in_use` | 同路径已有活跃 daemon，或无法安全判定为 stale | 查进程；不要手工删除仍被监听的 socket |
| `relay.admin.peer_forbidden` | UDS peer UID 与 Relay 运行用户不同 | 用配置 owner 执行管理命令 |
| `relay.store.confirmation_mismatch` | root fingerprint 与 route 不匹配 | 重新从可信 receipt/inventory 人工核对，禁止试错 purge |
| `relay.enrollment.rejected` | code、签名、证书或幂等请求不合法 | 修复请求；code 到期或已被不同请求消费时重新创建 bundle |
| `remote.local_input.unsafe` / `too_large` / `invalid_json` | bundle/receipt 不是 current-UID 私有 single-link regular file、超过 64 KiB 或不是严格 DTO | 修复 owner/mode/nlink/大小或重新从可信 Relay 输出；禁止 symlink/hardlink/宽权限输入 |
| `daemon.remote.enrollment.*` | bundle、certificate、response 或 durable lifecycle 不满足 exact binding | 保留原 bundle/state；按具体 code 修复 expiry/origin/pin/Relay/receipt anchor，异输入不得覆盖原事务 |
| `daemon.remote.trust_reset.admin_receipt_required` | MachineRoot 已丢失，不能在线签 retirement | 按 root-lost 流程取得 portable signed purge receipt；不得删除本地 locator/key 绕过 |
| `daemon.remote.trust_reset.root_present_receipt_forbidden` | MachineRoot 尚在却提供 admin receipt | 删除该参数，执行普通 authenticated retirement |
| `daemon.remote.trust_reset.terminal_timeout` | Relay 未在 10 秒绝对 deadline 内返回 retirement terminal | 保留 exact RetirePending frozen bytes；确认 Relay/链路恢复后重试，shutdown/upgrade 在 manager mutex 外取消等待 |
| `daemon.remote.transition.progress_pending` | transition 已有唯一 owner，仍在安全推进或等待可重试 Store 结果 | 保留 frozen transition 与 admission fence；不得另起 owner 或服务 ordinary publication |
| `daemon.remote.transition.reconnect_pending` | transition 需要 authenticated reconnect 才能继续 | 保留 exact frozen blob；恢复认证链路后由同一 owner 继续，禁止 timer 重封 |
| `remote.transport.publication_offline` | publication 在 Register/Publish 前确认链路离线 | park exact frozen publication；等待 authenticated reconnect，不生成新 blob/counter |
| `daemon.runtime.invalid_state`（pairing bootstrap/Close） | receipt、Add/Renew target、revision、slot/global lineage 或 durable 时间不一致；也可能尝试取消已有 proof 的 transition | 立即停止 remote drive并保留 exact pairing/transition 与 DB/WAL/SHM；修复时钟或调查 state fork 后只重试原 input，禁止手工 ACK、重建 proof或改表 |
| `daemon.runtime.schema_incompatible`（ADKT/transition） | authenticated proof/row 被篡改，或 transition 已不存在但 matching update 仍残留 | 保留 Runtime DB、WAL/SHM、Keychain 与诊断日志做离线审计；不得启动写迁移、删除孤立 row 或用 close-only legacy 兼容掩盖损坏 |
| `remote.runtime.outcome_unknown` | persistent command/watch 在 authenticated terminal 前 EOF 或普通断线 | 保留 durable state，从 fresh bootstrap exact retry；不得当作 stopped/revoked 或 daemon receipt |
| `remote.watch.output_failed` / `remote.watch.signal_failed` | NDJSON write/flush 或 SIGINT/SIGTERM listener 失败 | shutdown 后失败退出；修复 stdout consumer/signal 环境，不手改 cursor、sidecar 或 paired state |
| terminal `stopped` / `revoked` | stopped 已完成当前 frame/ACK 与 shutdown；revoked 已完成 verified terminal、transport drop 与 crash-safe cleanup | 只接受 canonical terminal NDJSON；若前置顺序缺失，按安全回归处理，不继续使用本地 key |
| 其他 `daemon.remote.trust_reset.*` / `remote.transport.*` | terminal/proof/binding/transport 不一致或 Relay 正在重启 | 保留 exact frozen state并重试同一输入；禁止生成新 route/cert 或猜测 terminal |
| `daemon.purge.recovery_required` | durable purge intent/marker 存在但尚未安全完成 | 停止 enroll，按同一 install/helper/plan exact retry `daemon uninstall --purge` |
| `daemon.purge.*` | marker/plan/helper/attestation、PID/UDS、Keychain/KEK 或删除读回失败 | 不手动续删；保留 marker与残余，按 `docs/AGENT_DIAGNOSTICS.md` 的具体 code 恢复同一 plan |

日志只允许记录稳定 event/failure code 和计数；一次性 code、完整 route/fingerprint、public key、
signature、receipt、terminal 或 request/response bytes 出现在日志中均为安全回归。

## 验证入口

```bash
bash scripts/verify-relay-companion-mvp.sh p2

# P4.6 automatic Task（P4 聚合 verifier 到 P4.7 才建立）
cargo test -p agentdeck-cli --locked --no-fail-fast -- --test-threads=1
cargo test -p agentdeck-relay-client --locked -- --test-threads=1
cargo test -p agentdeck-protocol --locked
cargo test --release -p agentdeck-cli --test remote_transfer_memory --locked \
  production_transfer_peak_is_bounded_across_capacity_completion_and_duplicate -- \
  --ignored --exact --nocapture --test-threads=1
cargo clippy -p agentdeck-cli -p agentdeck-protocol --locked --all-targets -- -D warnings
cargo clippy -p agentdeck-relay-client --locked --all-targets --no-deps -- -D warnings
cargo fmt --all -- --check
bash scripts/check-daemon-network-boundary.sh
bash scripts/check-daemon-no-net.sh
scripts/verify-agent-docs.sh
git diff --check
```

P2 聚合门禁包含 workspace Rust 回归、Relay v2 hardening/security E2E、client、Direct TLS selfcheck、
daemon network-boundary、四份 schema 快照、文档与运行数据 git-status guard。P4.6 使用上面的直接 Task
矩阵。2026-07-24 冻结 code/test scope 为 29 paths，blob-manifest SHA-256 为
`32e7c85620e6e88b407f2403715c52c5a9a5d30aa20d7fb800bdefabe8a1c858`；watch `12/12`、
`remote_persistent_machines` `11/11`、完整 CLI package final run exit 0、release allocator `1/1`、relay-client
`25/25` 与 protocol `244/244` 均通过，四 schema、三 crate Clippy、fmt、network/no-net、docs 与 diff
全绿。`spec/security` 与 `quality` 终审均 Approved，P0/P1/P2=0。当前 verifier
不支持 `p4`/`p4-auto`，不得虚构尚未由 P4.7
建立的 aggregate PASS。R0/R1 命令和
`--bootstrap-secret` 只属于历史记录，不得用于当前部署或验收。
