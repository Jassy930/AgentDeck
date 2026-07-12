# AgentDeck Relay v2 运维手册

本页只记录已经由自动化测试真实跑通的 Relay v2 管理命令与安全边界。P2.8 仍是与旧
Relay listener 并列的 library server；production listener 要到 P2.9 才原子切换，因此本页
不能作为“公网 Companion 已上线”的证明。

## 部署不变量

- 公网只允许 direct TLS，或由可信反向代理终止 TLS 后连接 loopback backend。开发明文
  loopback 不能启用 admin/enrollment。
- `admin_socket` 必须是绝对路径，父目录由 Relay 运行用户持有且不得向 group/other 开放；
  socket 固定为 `0600`，server 逐连接核对 peer UID。
- `public_wss_url` 必须是无用户名、query、fragment 和额外 path 的 `wss://` origin。
- `spki_pins` 只能有一或两个 base64url-no-padding SHA-256 pin。direct TLS 下第一项必须等于
  当前 leaf certificate 的 DER SPKI SHA-256；第二项只用于下一张证书的受控轮换。
- 管理命令只有本机 JSONL UDS。公网 `/v2/machine-enroll` 只处理首次登记；网络 listener
  不存在 inventory、readback 或 purge API。

配置项可来自 CLI、`AGENTDECK_RELAY_*` 环境变量或 TOML，优先级逐字段为
CLI > env > TOML > defaults：

```toml
admin_socket = "/var/run/agentdeck-relay/admin.sock"
public_wss_url = "wss://relay.example.com/"
spki_pins = ["BASE64URL_SHA256_CURRENT", "BASE64URL_SHA256_NEXT"]
```

对应环境变量是 `AGENTDECK_RELAY_ADMIN_SOCKET`、
`AGENTDECK_RELAY_PUBLIC_WSS_URL` 与逗号分隔的 `AGENTDECK_RELAY_SPKI_PINS`。

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
public material前，必须先完成公开 CA 或 bundle SPKI pin 验证；redirect 一律拒绝。

同 code + 同 canonical request 在 TTL 内会逐字节重放首次冻结响应；同 code + 不同请求
拒绝。两个并发请求只有一个能建立 route。签名、公钥或证书角色校验失败发生在 code 消费前。

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

## MachineRoot 丢失后的 purge

本项目不提供 root 恢复。daemon 必须保持 remote blocked；操作者从本机 receipt 或 inventory
取得旧 route/fingerprint，人工核对后执行：

```bash
agentdeck-relay machine purge MACHINE_ROUTE \
  --confirm ROOT_FINGERPRINT \
  --admin-socket /var/run/agentdeck-relay/admin.sock
```

错误 fingerprint 在 SQLite transaction 内、任何删除之前拒绝。正确 purge 通过同一个 Core
actor 与连接/PairRoute 操作线性化：COMMIT 后目标 machine、device 和 pairing writer 关闭，
内存 PairRoute 清除；其他 machine realm 不受影响。若 COMMIT 结果无法判定，整个 Core
fail-closed，绝不恢复旧 generation。只有再次执行带相同 fingerprint 的 readback 并确认上述
计数后，daemon 才能删除旧本地 trust state，再重新 enroll 和重新配对。

## 常见 failure code

| code | 含义 | 处理 |
| --- | --- | --- |
| `relay.tls.spki_pin_mismatch` | 当前 leaf SPKI 与配置第一 pin 不同 | 停止启动，核对证书部署与受控轮换顺序 |
| `relay.admin.socket_parent_insecure` | UDS 父目录 owner/mode 不安全 | 改为 Relay 用户持有的 0700 目录 |
| `relay.admin.socket_in_use` | 同路径已有活跃 daemon，或无法安全判定为 stale | 查进程；不要手工删除仍被监听的 socket |
| `relay.admin.peer_forbidden` | UDS peer UID 与 Relay 运行用户不同 | 用配置 owner 执行管理命令 |
| `relay.store.confirmation_mismatch` | root fingerprint 与 route 不匹配 | 重新从可信 receipt/inventory 人工核对，禁止试错 purge |
| `relay.enrollment.rejected` | code、签名、证书或幂等请求不合法 | 修复请求；code 到期或已被不同请求消费时重新创建 bundle |

日志只允许记录稳定 event/failure code 和计数；一次性 code、完整 route/fingerprint、public key、
signature、receipt、terminal 或 request/response bytes 出现在日志中均为安全回归。
