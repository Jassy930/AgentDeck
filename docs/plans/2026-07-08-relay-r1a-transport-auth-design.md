# AgentDeck Relay R1a 设计：传输 + 鉴权骨架

| 字段 | 值 |
|---|---|
| 状态 | Design - 待用户评审 |
| 日期 | 2026-07-08 |
| 主题 | Relay R1 第一子片（R1a）：把 R0 的进程内 FakeRelay 连接换成真 WebSocket 服务端 + 客户端层，并落地连接鉴权（Bearer + 服务端派生角色 + account scope）与运营者 bootstrap 的 challenge-response 设备 enroll |
| 关联 | `docs/plans/2026-07-08-relay-r1-design-review.md`（R1 评审 + §8 决策记录，本设计的依据）、`docs/plans/2026-07-07-relay-r0-contract-spike-design.md`（R0，已实现）、`docs/plans/2026-07-01-agentdeck-mobile-relay-design.md`（母设计）、`ARCHITECTURE.md`（N1/N6/K5/K9/N8） |

## 1. 背景和用户问题

R0 已落地：控制面/数据面分层协议（`agentdeck-protocol::remote`）、内存 `FakeRelay`（Core actor）、`StdioMachineBridge`（外部把真实 daemon 当 machine 接入）、CLI `remote` 命令面 + 单进程 smoke。但 R0 全在**进程内**（`FakeRelay::connect` 直接返回内存 `RelayClient`），无网络、无鉴权。

R1 评审（`2026-07-08-relay-r1-design-review.md`）把 R1 切成 R1a/R1b/R1c，并锁定关键决策。R1a 是第一子片，目标：**让 relay 真正联网且从第一版起就可安全联网**——用 WebSocket 承载 R0 已有的协议与路由逻辑，并在握手处引入鉴权。持久化（SQLite）、router 健壮化的其余部分、E2EE 真加解密分别是 R1b/R1c。

R1a 经头脑风暴确认的子决策（在 R1 评审 §8 决策之上）：① 传输与鉴权**合成一片**（握手与鉴权一体，不做联网无鉴权的中间态）；②-a 配对**一次登记 sign+box 双公钥**（box 休眠至 R1c，配对做一次到位）；②-b machine(bridge) 与 device(CLI) **两侧都 enroll**；③ HOL 防阻（Core 改 `try_send` + 最小溢出策略）**落 R1a**。

## 2. 目标与非目标

### 目标

- 交付可运行的 `agentdeck-relay` binary（axum WebSocket 服务端 + 配置 + `--selfcheck`）。
- `RelayLink` trait（RemoteFrame 类型的客户端连接抽象）**定义在 `agentdeck-relay`**——因为 `bridge` 与 `FakeRelay` 的 `RelayClient` 都要实现/使用它，放 client crate 会与之成环。新建 `agentdeck-relay-client` crate 提供 `WsRelayClient`（tungstenite 客户端，实现 `RelayLink`）+ `InProcRelayClient`（包 R0 `FakeRelay`，供确定性测试）；下层 `WsTransport: Transport`（N6 trait，字节层，**不改 trait 形状**）。依赖方向：`agentdeck-relay-client → agentdeck-relay`（单向，无环）。
- 服务端：每 WS 连接 per-conn reader/writer task 喂**原样复用的 R0 Core**；Core 的 fan-out 从 `send().await` 改 **`try_send` + 最小溢出策略**（HOL 防阻）。
- 鉴权：Ed25519 账户身份 + 运营者 bootstrap secret + challenge-response（CSPRNG nonce+TTL+单次消费）enroll，签发不透明 device credential（存哈希）；WS 握手 Bearer → **服务端派生 `ClientRole`**（忽略/校验 `from`）；account scope 检查点；**RegisterMachine 身份绑定** + **AdminReply 回复者身份绑定**；device 可撤销（relay 侧关连接 + 拒连）。
- 配对**一次登记 sign(身份)+box(E2EE) 双公钥**（box 休眠至 R1c）；machine 与 device 两侧都 enroll。
- 线格式：`DataEnvelope` 字节 base64；一条 RemoteFrame = 一条 WS text 帧 + `max_message_size`；`RELAY_PROTOCOL_VERSION` 0→1 + 握手版本协商；`trace_id` 边缘生成、relay 不覆写。
- 可观测性：tracing + `DataEnvelope`/`AuthContext` 脱敏 Debug + 类型化失败码注册表 + 哨兵-token 日志脱敏测试。
- 引入 tokio `net` **仅限** `agentdeck-relay`(server) 与 `agentdeck-relay-client`(client)；**daemon 保持无 net**；补 CI guard 断言 `agentdeckd` 依赖树无 tokio net。

### 非目标（明确后置）

- **不做 SQLite 持久化**（R1b）：R1a 用 `RelayStore` trait + **仅内存实现**；relay 重启丢设备登记（R1a 可接受）。
- **不做 router 健壮化的其余部分**（R1b）：conv_buffer 上界/RetireSession 级联清/Ack-trim/AnnounceSession 去重/req_origin 超时清理/seq 高水位持久化。R1a 只做 HOL 的 `try_send`+最小溢出（丢帧标 lagged / 控制满断连），**不做**重连重放补齐（依赖 R1b 的 buffer/Ack）。
- **不做 E2EE 真加解密**（R1c）：R1a 数据面保持 `DataEnvelope::Plaintext`，机密性靠**传输层 TLS**（非 loopback 强制，见 §4.5 门禁），配对已登记 box 公钥。
- 不做 QR 扫码配对（R3）、daemon remote-mode（R2）、APNs（R3+）、多账户/团队（R4）。

## 3. 已确认决策（R1 评审 §8 + R1a 头脑风暴）

- 传输栈：axum(server) + tokio-tungstenite(client)（D1）；net 拆 `agentdeck-relay-client` crate（D5）；服务端另立 accept+per-conn actor 抽象 + RelayLink 层，不碰 Transport trait（D3）。
- 鉴权=最小但完整骨架（D6）；bootstrap=运营者 secret（R1a Q2）；存储=RelayStore trait + 仅内存（R1a Q1，SQLite 留 R1b）。
- E2EE=真 E2EE 目标（D7=B），但 R1a 只**登记 box 公钥**、真加解密留 R1c；canonical 密码学（IETF ChaCha20-Poly1305 + X25519/HKDF）在 R1c 定向量。
- TLS=可选 rustls 进程内 wss，dev 默认 ws loopback（D2）。
- 切片=合成一片（①）；双公钥一次登记（②-a）；两侧都 enroll（②-b）；HOL 落 R1a（③）。

## 4. 架构方案和边界

### 4.1 拓扑与 crate 布局

```text
agentdeck-cli remote (device role) ─┐
                                    ├─(wss, Bearer)→ agentdeck-relay (axum WS server)
StdioMachineBridge (machine role)  ─┘                     │ per-conn reader/writer task
                                                           ▼
                                                R0 Core actor（原样复用）
```

```text
agentdeck-relay/                 # 从 lib 升级为 lib + binary
  Cargo.toml                     # 加 axum + tokio(net) + tracing/tracing-subscriber + rustls(可选 feature) + dotenvy
  src/
    lib.rs
    router.rs                    # R0 Core：fan-out 改 try_send+溢出（HOL）+ 连接身份 + handle_frame 授权检查
    relay_link.rs                # 新：RelayLink trait（客户端连接抽象）；FakeRelay 的 RelayClient 实现它
    bridge.rs                    # spawn(...) 收 impl RelayLink（不再收 &FakeRelay 具体类型）
    server/                      # 新：axum WS 服务端 + per-conn 任务 + 握手鉴权（server feature 后）
    auth/                        # 新：账户/设备/challenge 模型 + RelayStore trait + 内存 impl + credential 校验
    config.rs                    # 新：--bind/--bootstrap-secret/--tls-*/--log-level + AGENTDECK_RELAY_* + dotenvy
    main.rs / [[bin]]            # 新：relay 二进制入口 + --selfcheck

agentdeck-relay-client/          # 新 crate（net 客户端侧）；依赖 agentdeck-relay 取 RelayLink trait
  src/
    lib.rs                       # 导出；WsRelayClient/InProcRelayClient 均实现 agentdeck-relay::RelayLink
    ws.rs                        # WsRelayClient（tungstenite）+ WsTransport: Transport
    inproc.rs                    # InProcRelayClient（包 agentdeck-relay::FakeRelay，供测试）

agentdeck-protocol/src/remote/   # 扩：DataEnvelope 字节 base64；握手/enroll 帧或 REST DTO；类型化失败码注册表；RELAY_PROTOCOL_VERSION→1
agentdeck-cli/                   # remote pair 子命令 + baseline_stub 接线 --relay ws://（依赖 agentdeck-relay-client）
```

**crate 依赖图与 net/axum 隔离（精化 D5，避免把 axum 拉进 CLI/daemon）**：

- `agentdeck-relay`：`router.rs`(FakeRelay/Core)、`bridge.rs`、`RelayLink` trait、`auth/`、`RelayStore` trait+内存 impl **始终可用**；axum WS **服务端 + tokio net 放在 `server` feature 后**；`[[bin]]`（relay 二进制）启用 `server`。
- `agentdeck-relay-client`：`WsRelayClient`(实现 `RelayLink`) + `WsTransport`(tokio-tungstenite client + net)；依赖 `agentdeck-relay`（**不启用 `server` feature**，只取 `RelayLink`/类型）。
- `agentdeck-cli`：依赖 `agentdeck-relay`（**默认无 `server`**，取 FakeRelay/bridge 供 in-proc 快路径 smoke）+ `agentdeck-relay-client`（device `WsRelayClient` 走 `--relay ws://`）。**CLI 不含 axum**。
- `agentdeckd`：**不依赖 relay 任何 crate**，保持无 net（至 R2）。CI guard 断言其依赖树无 tokio net。
- **自包含端到端**（relay server + bridge + device 同进程）放 `agentdeck-relay` 的**集成测试**（启用 `server` feature），不放 CLI 二进制——CLI 的 `remote smoke --relay ws://` 连**外部已启动的 relay**（CLI 仅客户端）。

net feature 因此严格限定在：`agentdeck-relay` 的 `server` feature + `agentdeck-relay-client`。CLI 只在用 `agentdeck-relay-client` 时带 net（客户端连接必需），不带 axum server。

### 4.2 传输：服务端 accept + per-conn actor（D3）

- axum 单 WS 路由 `/v1/connect`（角色**从凭据派生**，非 `frame.from`）+ REST `/v1/pair/challenge`、`/v1/pair/complete`（enroll）。
- 每 WS 连接：握手鉴权通过后，`CoreMsg::Connect{conn_id, identity}` 注入 Core；spawn **reader task**（WS text → 解码 `RemoteFrame` → `CoreMsg::Frame{conn_id, frame}`）+ **writer task**（排空 per-conn **有界** `mpsc<RemoteFrame>` → WS send）。
- **Core 改动一（HOL 防阻）**：`send_to` 从 `conn.out.send(frame).await` 改 `conn.out.try_send(frame)` + 最小溢出——事件类满→丢帧并标该连接 lagged（R1b 加重放补齐）；控制/回执类（AdminReply/CommandDelivered/Error/MachineList/SessionList）满→断该连接（`relay.conn.overflow`）。单 actor 永不被慢连接 await 阻塞。
- **Core 改动二（连接身份 + 授权不变量）**：Core **不是「逻辑原样」**。`CoreMsg::Connect` 携带 server 层已验证的**连接身份**（account/device/role），Core 按 `conn_id` 记住它；`handle_frame` 新增授权检查（见 §4.3）——`Subscribe`/`SendCommand` 过 account scope；`RegisterMachine` 校验身份绑定（**取代 `router.rs:128` 现有的无条件 `machines.insert`**）；`AdminReply` 校验回复者==请求的目标 machine；新增 `Revoke` 主动断连。这些都要改 Core 状态与 `handle_frame`。
- **分层职责（防「只做传输鉴权、绕过控制面授权」）**：**server 层**只做连接**认证**（验 Bearer → 解析并派生**权威** `ClientRole`/account → 注入 `CoreMsg::Connect`）；**Core 层**做控制面**授权**（scope + 身份绑定 + revoke），依据 server 注入的身份、**不信 `frame.from`**。两层缺一不可。
- 客户端侧 `RelayLink`（RemoteFrame 类型）：`WsRelayClient` reconnect 后自动重放已记录 `Subscribe`（Ack 游标补拉留 R1b）；`WsTransport: Transport` 承字节层，N6 守护测试与 trait 形状不动。
- `bridge.rs::spawn(...)` 从收 `&FakeRelay` 改收 `impl RelayLink`，逻辑零改；R1a 传 `WsRelayClient(machine)`，测试传 `InProcRelayClient`。

### 4.3 鉴权与 enroll

**身份模型**（`auth/`）：

- **R1a = 单账户（singleton）**：一个自托管 relay 实例对应**一个 root account**；`account_id` 在**首次 enroll** 时由账户 owner 公钥派生（如 pubkey 哈希前缀）并固定，之后**所有设备（device 与 machine）都挂在这一个 `account_id` 下**——这样 account scope 才能让 device 看到 machine（二者同账户）。这正是 P1-2 要害：bootstrap secret 是「**加入本实例账户**」的授权，不是「新建账户」。
- `Account { account_id, owner_sign_pubkey(Ed25519) }`（R1a 只有一个；owner keypair 供 R3 无-bootstrap 授权新设备用，R1a 由首个客户端持有、不作 R1a 的授权源）
- `Device { device_id, account_id, role: Machine|Device, credential_hash, sign_pubkey(Ed25519), box_pubkey(X25519), revoked }`
- `Challenge { device_sign_pubkey, nonce, expires_at, used }`
- `RelayStore` trait（增删查账户/设备/challenge/revocation）；R1a 唯一实现 `InMemoryRelayStore`。

**enroll（challenge-response，D6 + Q2；建/加入同一 singleton account）**：

1. 客户端生成**本设备** sign/box 密钥对（首个客户端另生成 account owner keypair）；`POST /v1/pair/challenge {device_sign_pubkey}` → relay 存 `Challenge{nonce=CSPRNG, expires_at=now+TTL, used=false}` → 返回 nonce。
2. `POST /v1/pair/complete {bootstrap_secret, sig=Ed25519_by_device(nonce), device:{device_id, role, sign_pubkey, box_pubkey}, owner_pubkey?}` → relay：校 `bootstrap_secret`（`relay.pair.bad_secret`）→ 用 `device.sign_pubkey` 验 `sig`（证明持有所登记设备私钥）→ **原子单次消费 nonce**（check-and-set used，失败 `relay.pair.challenge_expired`）→ **首次**（无 account）：用 `owner_pubkey` 派生 `account_id` 建 root account；**后续**（已有 singleton account）：**直接把设备挂到既有 `account_id`，不新建 account**（`owner_pubkey` 忽略）→ 登记 `Device`（sign+box 双公钥、role）→ 生成 256-bit 不透明 credential、**存哈希**、明文一次性返回。
3. 客户端把 `{relay_url, account_id, device_id, device_credential, device_sign_privkey, device_box_privkey}`（首个客户端另存 `owner_sign_privkey`）存本地凭据文件（见 §4.6，`0600`、gitignore）。**R1a 每次入账户靠 `bootstrap_secret` 授权，设备各持自己的密钥、无需共享 account 私钥**（规避密钥分发）；`box_privkey` R1c 才用。R3 QR 用 owner keypair 替换 bootstrap secret 作为「授权新设备入账户」的输入，wire/数据模型不返工。

**连接鉴权**：WS 握手 `Authorization: Bearer <credential>` → relay 查 credential 哈希 → 解析 `account+device+role` → 绑定连接身份、**服务端派生 `ClientRole`**（`frame.from` 仅校验一致性，不作信任源）；未知/撤销 → 关连接（`relay.auth.invalid_device`/`relay.auth.revoked_device`）；版本不符 → `relay.version.unsupported`。

**授权与身份绑定**：

- account scope：每个 `Subscribe`/`SendCommand` 校验目标（machine/conversation）属于连接的 account（R1a 单账户，检查点建好、默认放行同账户，跨账户 `relay.auth.forbidden`）。
- **RegisterMachine 身份绑定**：校验连接凭据授权该 `machine_id`，拒绝跨身份覆盖既有机器（`relay.machine.identity_conflict`）。
- **AdminReply 回复者绑定**：relay 的 pending 表记 `request_id → {origin_device_conn, target_machine}`；`AdminReply` 校验发送连接 == `target_machine`，否则 `relay.reply.unauthorized`；`request_id` 用随机不可猜值。
- 撤销：`RelayStore` 标 `revoked` → Core 收到 `Revoke` 消息按 device 主动断其活连接；后续连接被拒。

### 4.4 线格式与版本

- `DataEnvelope` 的 `bytes`（及 R1c 的 Encrypted 字段）加 base64 serde（serde_with/base64），消除 `Vec<u8>`→JSON 数字数组膨胀；控制面明文可读、数据面 relay 不解码不变。
- 一条 `RemoteFrame` = 一条 WS **text** 帧；设 `max_message_size`，超限（大 `HistoryResponse`）回 `relay.frame.too_large`（分块后置）。
- `RELAY_PROTOCOL_VERSION` 0→1；握手期客户端报支持版本，relay 只接受 1，不匹配 `relay.version.unsupported`。
- `trace_id` 由边缘（CLI/bridge）生成、全程透传，relay **不覆写**（修 R0 `created_at_ms`/trace 恒 0 的僵尸行为）。

### 4.5 传输安全门禁（硬规则，兑现「从第一版可安全联网」）

- 默认 `--bind 127.0.0.1`：允许明文 `ws`/`http`（仅本机回环，凭据/明文不出机）。
- **绑定到任何非 loopback 地址时，必须配置 TLS（rustls，`wss`/`https`），否则 relay 拒绝启动**（`relay.config.plaintext_non_loopback`）。仅当显式传 `--allow-plaintext`（dev-only，启动时打印响亮告警）才允许非 loopback 明文。
- pair 的 REST（携 `bootstrap_secret`）与 WS（携 Bearer credential）**走同一 scheme**——非 loopback 即 `https` + `wss`，二者不得混用明文/密文。
- 这条硬规则直接兑现 §1「从第一版可安全联网」：杜绝 `--bind 0.0.0.0` 未配 TLS 时 `bootstrap_secret`/Bearer credential/prompt 在网络上明文裸奔。（内容层 E2EE 是 R1c；R1a 的机密性由此传输门禁承担。）

### 4.6 CLI 命令面（R1a）

R0 的 `remote` 子命令组从「baseline_stub 占位」升级为真实实现（`agentdeck-cli/src/remote.rs` + `main.rs` 的 `RemoteOp`）：

- **旗标**：各 `remote` 子命令加 `--relay <ws://|wss://url>`（目标 relay endpoint）；沿用现有全局 `--profile`/`--data_dir`（决定凭据文件所在数据目录）。
- **`remote pair --relay <url> --bootstrap-secret <s> [--role device|machine]`**（新）：生成设备 sign/box 密钥（首个客户端另生成 account owner 密钥）→ challenge-response enroll → 写凭据文件。默认 `--role device`；bridge 侧用 `--role machine`。
- **`remote machines` / `sessions <machine_id>` / `watch <conversation_id>` / `send <conversation_id> <text>` / `approve|deny <turn_session_id> <request_id>` / `ping <machine_id>`**：加 `--relay <url>`，读凭据文件（device 角色）连 relay 执行——**取代 R0 的 `baseline_stub`**。
- **`remote smoke`**（in-proc、无网络，**保留**为确定性快路径）/ **`remote smoke --relay <url>`**（新，CLI 作纯 device 连**外部**已启动 relay）。
- **凭据文件**：`<data_dir>/relay/credentials.json`（`<data_dir>` 由 `AGENTDECK_DATA_DIR`/`--profile` 决定，默认 `~/Library/Application Support/AgentDeck/`），`0600` 权限、gitignore；内含 `{relay_url, account_id, device_id, device_credential, device_sign_privkey, device_box_privkey}`（首个客户端另含 `owner_sign_privkey`）。多设备/角色各自一份（如 `credentials-machine.json`）。
- CLI 只依赖 `agentdeck-relay-client`（device `WsRelayClient`）+ `agentdeck-relay`（无 `server` feature，取 in-proc smoke 的 FakeRelay/bridge），**不含 axum**。

## 5. 错误处理与可观测性

- **tracing + tracing-subscriber(EnvFilter)**；为 `DataEnvelope` 与 `agentdeck-protocol::transport::AuthContext` 实现**脱敏 Debug/Display**（token/明文绝不入日志——修 R0 已核实的 `AuthContext` derive(Debug,Serialize) 泄漏与其「Must not leak」注释矛盾）。relay 只记控制面元数据（trace_id、from-role、msg 变体、conversation_id/machine_id/request_id/seq、seal-tag、byte-len、失败码）。
- **失败码类型化注册表**：把 R0 散落的裸字符串码提升为 `agentdeck-protocol` 里的枚举/常量，纳入 schema 快照。R1a 新增：`relay.auth.invalid_device`、`relay.auth.revoked_device`、`relay.auth.forbidden`、`relay.pair.bad_secret`、`relay.pair.challenge_expired`、`relay.version.unsupported`、`relay.machine.identity_conflict`、`relay.reply.unauthorized`、`relay.conn.overflow`、`relay.frame.too_large`、`relay.config.plaintext_non_loopback`（复用 R0 的 `remote.session.not_found` 等）。
- **哨兵-token 日志脱敏测试**：把哨兵串塞进 payload 与 credential，断言绝不出现在捕获日志里——把「日志禁明文/token」从空话变可执行门。
- `agentdeck-relay --selfcheck`：启动配置校验 + store/路由自检，对齐 daemon 现有 `--selfcheck`。

## 6. 测试和验收标准

### 测试分层（D11）

- **逻辑测留内存确定性**：R0 Core + `InProcRelayClient` 跑 T1/T2/T3 与 router 单测**不回归**；HOL 的 try_send/溢出加确定性单测（合成慢连接→事件丢+标 lagged、控制满→断连，Core 不阻塞其它连接）。
- **WS 适配器 / 自包含端到端测（`agentdeck-relay` 集成测试，启用 `server` feature，loopback + ephemeral :0）**：进程内起 relay server（bind 127.0.0.1:0 读回实际端口）+ bridge(machine) + device client 三者经真 ws，`oneshot` 就绪同步、沿用 5s bounded-timeout；断言握手鉴权 + machines 订阅 + admin ping 往返经真 WS。这是「真 WS 端到端」的权威测试所在（不放 CLI 二进制）。
- **鉴权测**：challenge-response（nonce 单次消费、TTL 过期用 tokio test-util paused time、错 bootstrap secret 拒、撤销设备拒、未知 credential 拒）；服务端角色派生（伪造 `from` 被忽略/校验）；account scope；RegisterMachine 跨身份覆盖被拒；AdminReply 非目标 machine 抢答被拒。
- **CLI smoke**：R0 的 in-proc `remote smoke`（FakeRelay + bridge 同进程、无网络）保留为确定性快路径；新增 `remote smoke --relay ws://<url>`——CLI 作为**纯 device 客户端**连**外部已启动的 relay**（enroll → 订阅 machines → admin ping），验证 CLI↔relay 客户端链路（不在 CLI 内起 server，保持 CLI 无 axum）。
- **guard**：`cargo tree -p agentdeckd` 断言无 tokio net（脚本/测试）。

### 验收标准（R1a）

- `cargo test` 全绿（含新 WS 适配器测、鉴权测、HOL 溢出测、schema 快照同步）；`agentdeck-relay --selfcheck` 通过。
- relay binary 启动（默认 bind 127.0.0.1）；device 与 machine 各经 bootstrap secret + challenge-response enroll 成功、拿到 credential，且二者挂在**同一 singleton account** 下（device 能看到 machine）。
- **非 loopback 绑定未配 TLS 时 relay 拒绝启动**（`relay.config.plaintext_non_loopback`），除非显式 `--allow-plaintext`（打印告警）。
- CLI 用 credential 经 ws 连上，看到 bridge(machine) 注册 + 一个会话，admin ping 经真 WS 往返；prompt/审批命令路由正确（复用 R0 语义）。
- 错 bootstrap secret / 过期或重用 nonce / 撤销设备 / 无 credential / 版本不符 连接均被正确拒并回对应失败码。
- 伪造 `from`、跨身份 RegisterMachine、非目标 machine 抢答 AdminReply 均被拒。
- 慢连接不冻住整个 relay（HOL 溢出生效）。
- 日志中无 credential/token/prompt/shell/diff 明文（哨兵测试通过）。
- `agentdeckd` 依赖树无 tokio net（guard 通过）；`scripts/verify-agent-docs.sh` 通过；AGENTS.md 补 R1a 验证入口。

## 7. 范围与后续衔接

- **R1b**（持久化 + router 健壮化）：`RelayStore` 的 SQLite(WAL) 实现（accounts/devices/revocation/seq 高水位/加密离线事件队列）；conv_buffer 上界 + RetireSession 级联清 + Ack-trim + 重连重放补拉；AnnounceSession 去重；req_origin 超时清理。
- **R1c**（E2EE 真加解密）：`DataEnvelope::Encrypted`（IETF ChaCha20-Poly1305 + X25519/HKDF）+ 跨语言测试向量；用 R1a 已登记的 box 公钥封装 per-session DEK；seal 策略（required_e2ee/optional/plaintext_only）+ loopback 默认/非 loopback 拒 Plaintext 门禁；机器侧 box 私钥托管（R1a bridge keyfile 临时 → R2 daemon）。
- **R2**：agentdeckd remote-mode（daemon 作为有凭据 machine 直连 relay，取代外部 bridge；outbound reconnect/backoff）。
- **R3**：iOS `RelaySessionSource` + QR 扫码配对（替换 R1a 的 bootstrap secret 输入；challenge-response 骨架复用）；跨平台密码学互操作验证。

## 8. 落地后文档更新

- `AGENTS.md`：补 R1a 验证入口（relay 构建/测试/selfcheck、WS smoke、daemon-no-net guard、RELAY_PROTOCOL_VERSION 变更后 UPDATE_SCHEMA）。
- `ARCHITECTURE.md`：补 relay 存储/网络边界不变量（relay 独立数据目录、只存不透明数据 + 公钥材料 + credential 哈希；net feature 仅限 relay/relay-client；daemon 无 net 至 R2）。
- `docs/index.md`：登记本 spec。
- R1 评审文档 §6 范围切分标注 R1a 已落地。
