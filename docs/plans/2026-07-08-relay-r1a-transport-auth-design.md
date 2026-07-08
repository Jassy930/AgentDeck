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
- 新建 `agentdeck-relay-client` crate：`RelayLink` trait（RemoteFrame 类型）+ `WsRelayClient`（tungstenite 客户端）+ `InProcRelayClient`（包 R0 `FakeRelay`，供确定性测试）；下层 `WsTransport: Transport`（N6 trait，字节层，**不改 trait 形状**）。
- 服务端：每 WS 连接 per-conn reader/writer task 喂**原样复用的 R0 Core**；Core 的 fan-out 从 `send().await` 改 **`try_send` + 最小溢出策略**（HOL 防阻）。
- 鉴权：Ed25519 账户身份 + 运营者 bootstrap secret + challenge-response（CSPRNG nonce+TTL+单次消费）enroll，签发不透明 device credential（存哈希）；WS 握手 Bearer → **服务端派生 `ClientRole`**（忽略/校验 `from`）；account scope 检查点；**RegisterMachine 身份绑定** + **AdminReply 回复者身份绑定**；device 可撤销（relay 侧关连接 + 拒连）。
- 配对**一次登记 sign(身份)+box(E2EE) 双公钥**（box 休眠至 R1c）；machine 与 device 两侧都 enroll。
- 线格式：`DataEnvelope` 字节 base64；一条 RemoteFrame = 一条 WS text 帧 + `max_message_size`；`RELAY_PROTOCOL_VERSION` 0→1 + 握手版本协商；`trace_id` 边缘生成、relay 不覆写。
- 可观测性：tracing + `DataEnvelope`/`AuthContext` 脱敏 Debug + 类型化失败码注册表 + 哨兵-token 日志脱敏测试。
- 引入 tokio `net` **仅限** `agentdeck-relay`(server) 与 `agentdeck-relay-client`(client)；**daemon 保持无 net**；补 CI guard 断言 `agentdeckd` 依赖树无 tokio net。

### 非目标（明确后置）

- **不做 SQLite 持久化**（R1b）：R1a 用 `RelayStore` trait + **仅内存实现**；relay 重启丢设备登记（R1a 可接受）。
- **不做 router 健壮化的其余部分**（R1b）：conv_buffer 上界/RetireSession 级联清/Ack-trim/AnnounceSession 去重/req_origin 超时清理/seq 高水位持久化。R1a 只做 HOL 的 `try_send`+最小溢出（丢帧标 lagged / 控制满断连），**不做**重连重放补齐（依赖 R1b 的 buffer/Ack）。
- **不做 E2EE 真加解密**（R1c）：R1a 数据面保持 `DataEnvelope::Plaintext`（经 TLS 传输保护），但配对已登记 box 公钥。
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
    router.rs                    # R0 Core：fan-out 改 try_send + 最小溢出（HOL）
    bridge.rs                    # spawn(...) 收 impl RelayLink（不再收 &FakeRelay）
    server/                      # 新：axum WS 服务端 + per-conn 任务 + 握手鉴权
    auth/                        # 新：账户/设备/challenge 模型 + RelayStore trait + 内存 impl + credential 校验
    config.rs                    # 新：--bind/--bootstrap-secret/--tls-*/--log-level + AGENTDECK_RELAY_* + dotenvy
    main.rs / [[bin]]            # 新：relay 二进制入口 + --selfcheck

agentdeck-relay-client/          # 新 crate（net 客户端侧）
  src/
    lib.rs                       # RelayLink trait
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
- Core（`router.rs`）**逻辑原样**，唯一改动：`send_to` 从 `conn.out.send(frame).await` 改 `conn.out.try_send(frame)` + 最小溢出：事件类满→丢帧并标该连接 lagged（R1b 加重放补齐）；控制/回执类（AdminReply/CommandDelivered/Error/MachineList/SessionList）满→断该连接（`relay.conn.overflow`）。→ 单 actor 永不被慢连接 await 阻塞。
- 客户端侧 `RelayLink`（RemoteFrame 类型）：`WsRelayClient` reconnect 后自动重放已记录 `Subscribe`（Ack 游标补拉留 R1b）；`WsTransport: Transport` 承字节层，N6 守护测试与 trait 形状不动。
- `bridge.rs::spawn(...)` 从收 `&FakeRelay` 改收 `impl RelayLink`，逻辑零改；R1a 传 `WsRelayClient(machine)`，测试传 `InProcRelayClient`。

### 4.3 鉴权与 enroll

**身份模型**（`auth/`，R1a 单账户）：

- `Account { account_id, sign_pubkey(Ed25519) }`
- `Device { device_id, account_id, role: Machine|Device, credential_hash, sign_pubkey, box_pubkey(X25519), revoked }`
- `Challenge { account_pubkey, nonce, expires_at, used }`
- `RelayStore` trait（增删查账户/设备/challenge/revocation）；R1a 唯一实现 `InMemoryRelayStore`。

**enroll（challenge-response，D6 + Q2）**：

1. 客户端生成账户 Ed25519 密钥对（首次）+ 设备 sign/box 密钥对；`POST /v1/pair/challenge {account_pubkey}` → relay 存 `Challenge{nonce=CSPRNG, expires_at=now+TTL, used=false}` → 返回 nonce。
2. `POST /v1/pair/complete {account_pubkey, sig=Ed25519(nonce), bootstrap_secret, device:{device_id, role, sign_pubkey, box_pubkey}}` → relay：校 `bootstrap_secret` → 验 `sig` → **原子单次消费 nonce**（内存 store：check-and-set used，失败即 `relay.pair.challenge_expired`）→ 登记 Account(首次)+Device（sign+box 双公钥）→ 生成 256-bit 不透明 credential、**存哈希**、明文一次性返回。
3. 客户端把 `{account_id, account_sign_privkey, device_id, device_credential, device_box_privkey}` 存到本地凭据文件（CLI/bridge 侧，config 目录，0600 权限，gitignore）。box 私钥 R1c 才用。

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

## 5. 错误处理与可观测性

- **tracing + tracing-subscriber(EnvFilter)**；为 `DataEnvelope` 与 `agentdeck-protocol::transport::AuthContext` 实现**脱敏 Debug/Display**（token/明文绝不入日志——修 R0 已核实的 `AuthContext` derive(Debug,Serialize) 泄漏与其「Must not leak」注释矛盾）。relay 只记控制面元数据（trace_id、from-role、msg 变体、conversation_id/machine_id/request_id/seq、seal-tag、byte-len、失败码）。
- **失败码类型化注册表**：把 R0 散落的裸字符串码提升为 `agentdeck-protocol` 里的枚举/常量，纳入 schema 快照。R1a 新增：`relay.auth.invalid_device`、`relay.auth.revoked_device`、`relay.auth.forbidden`、`relay.pair.bad_secret`、`relay.pair.challenge_expired`、`relay.version.unsupported`、`relay.machine.identity_conflict`、`relay.reply.unauthorized`、`relay.conn.overflow`、`relay.frame.too_large`（复用 R0 的 `remote.session.not_found` 等）。
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
- relay binary 启动（默认 bind 127.0.0.1）；device 与 machine 各经 bootstrap secret + challenge-response enroll 成功、拿到 credential。
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
