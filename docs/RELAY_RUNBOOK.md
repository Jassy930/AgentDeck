# AgentDeck Relay v2 运维手册

本页只记录已经由自动化测试真实跑通的 Relay v2 管理命令与安全边界。production
binary 已在 P2.9 原子切换为仅 Relay v2；P2.10 又以真实 Direct TLS/SPKI synthetic、
安全扫描与故障注入门禁收口。P4.1 已完成 daemon machine identity/guard；P4.2 又以
`a6842bc` 完成 Runtime v3、schema v9、certificate、durable enrollment/receipt、
control-only RemoteTransport、两条 trust reset 与安全 uninstall purge 的 automatic scope。Pairing、业务
RemoteLink、E2EE、持久远程 CLI 和 iOS 自动链路仍属于后续 Task。因此本页不是“公网 Companion 已上线”
或 production-signed LaunchAgent/Keychain 已 PASS 的证明。

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

P4.2 的本机管理只走 same-UID canonical Runtime v3 UDS，不创建第二个 admin socket。bundle 必须是
current-UID、single-link、no-follow regular file，group/other 权限为零且不超过 64 KiB；推荐保持 `0600`：

```bash
chmod 0600 machine-enrollment-bundle.json
agentdeck remote machine enroll \
  --bundle-file "$PWD/machine-enrollment-bundle.json"
agentdeck remote machine status
```

enroll 在发送 code、MachineRoot 或 Link/Data public material 前完成 CA/hostname/SPKI 校验。成功后只建立
authenticated **control-only** MachineLink；它处理 auth、server restart 与 retirement control，任何业务 frame
都必须关闭连接且不会进入 RuntimeCore。完全相同的 bundle 可用于 exact retry；不同 code/origin/pin/Relay/
receipt anchor/expiry 会在网络前 conflict。

除上述 `remote machine enroll|status` 与下文 `remote trust-reset` 外，P4.3–P4.6 尚未完成的持久
`remote pair/machines/sessions/watch/send/...` 仍返回 `remote.persistent.unsupported`。automatic gate 使用
injected dev/ephemeral keystore 与 hermetic namespace；真实 production 命令仍要求 provisioned、release-signed
daemon/CLI 与正确 entitlement，当前槽位保持 post-MVP BLOCKED，不能由 automatic PASS 代替。

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

## Runtime v3 hard-cutover 开发凭据

Runtime version 已绑定 MachineRoot TBS。P3.9 的 Runtime v1→v2 hard cutover 证据继续保留；P4.2 current
contract 为 Runtime v3，不提供 production v2/v3 双栈。旧签名材料不会通过 current verifier：对外只返回
通用 `relay.auth.invalid_grant` / `relay.enrollment.rejected`，不暴露失败字段。这是预期 hard cutover，不是可
自动迁移的数据。

P4 production pairing 投产前，任何曾生成 Runtime v1 签名材料的开发 trust realm 都必须按以下顺序处理：

1. 先用可信 Relay admin inventory 查询旧 route/root fingerprint。
2. realm 存在时执行 admin purge，并用同一 fingerprint readback，确认 active、grant、revocation、stream、
   frame、subscription 全为 0 且只剩 retired tombstone。若 inventory 可信确认 absent（例如从未 enrollment
   或开发 Store 已受控重建），记录 absent 结果；不得为了满足流程伪造 tombstone。
3. 只有完成 present realm 的 purge/readback，或得到可信 absent 结果后，才删除对应本地开发 trust state。
4. 生成新的 route/key，使用 current Runtime v3 重新 enroll，再让每台设备重新 pair；禁止恢复旧
   cert/grant 或自动降级 verifier。

`scripts/reset-relay-v1-dev-state.sh` 只处理早期 Relay v1 DB/bearer credential，不处理 Relay v2 Store 中的
历史 Runtime TBS 开发凭据。当前本地 trust-reset 必须走上述 Runtime v3 命令与 signed proof；不得手改
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
| 其他 `daemon.remote.trust_reset.*` / `remote.transport.*` | terminal/proof/binding/transport 不一致或 Relay 正在重启 | 保留 exact frozen state并重试同一输入；禁止生成新 route/cert 或猜测 terminal |
| `daemon.purge.recovery_required` | durable purge intent/marker 存在但尚未安全完成 | 停止 enroll，按同一 install/helper/plan exact retry `daemon uninstall --purge` |
| `daemon.purge.*` | marker/plan/helper/attestation、PID/UDS、Keychain/KEK 或删除读回失败 | 不手动续删；保留 marker与残余，按 `docs/AGENT_DIAGNOSTICS.md` 的具体 code 恢复同一 plan |

日志只允许记录稳定 event/failure code 和计数；一次性 code、完整 route/fingerprint、public key、
signature、receipt、terminal 或 request/response bytes 出现在日志中均为安全回归。

## 验证入口

```bash
bash scripts/verify-relay-companion-mvp.sh p2

# P4.2 Task automatic scope（P4 聚合 verifier 到 P4.7 才建立）
cargo test -p agentdeckd --locked -- --test-threads=1
cargo test -p agentdeck-cli --locked
cargo test -p agentdeck-relay-client --locked
cargo test -p agentdeck-protocol --locked
cargo test -p agentdeck-relay --features server,tls --locked
cargo test -p agentdeck-crypto --locked
swift test
cd ios && xcodegen generate && \
  xcodebuild -project AgentDeckMobile.xcodeproj -scheme AgentDeckMobile \
    -destination 'platform=iOS Simulator,name=iPhone 17' test
bash scripts/check-daemon-network-boundary.sh
```

P2 聚合门禁包含 workspace Rust 回归、Relay v2 hardening/security E2E、client、Direct TLS selfcheck、
daemon network-boundary、四份 schema 快照、文档与运行数据 git-status guard。P4.2 目前使用上面的直接 Task
矩阵；不得虚构尚未由 P4.7 建立的 `verify-relay-companion-mvp.sh p4`。R0/R1 命令和
`--bootstrap-secret` 只属于历史记录，不得用于当前部署或验收。
