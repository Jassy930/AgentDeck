# AgentDeck Relay R1 设计评审（就绪度评估）

| 字段 | 值 |
|---|---|
| 状态 | Review - 正式 R1 设计前的批判性评审，待用户确认决策 |
| 日期 | 2026-07-08 |
| 主题 | 基于 R0 实际落地产出 + 母设计 + happier，对 Relay R1（Relay MVP）方向做 6 维度批判性评审，产出待决策项 / 风险 / 母设计订正清单 / 就绪度结论 |
| 关联 | `docs/plans/2026-07-01-agentdeck-mobile-relay-design.md`（母设计，§9 R1 定义）、`docs/plans/2026-07-07-relay-r0-contract-spike-{design,implementation}.md`（R0，已落地）、`ARCHITECTURE.md`（N1/N6/K5/K9/N8） |

## 0. 本文定位

这是**评审文档，不是 R1 设计文档**。它在正式进入 R1 设计（头脑风暴 → 设计 → 计划）之前，基于 R0 的真实代码产出，批判性检视母设计 §9 对 R1（Relay MVP）的方向，挖出必须拍板的决策、真实风险、以及母设计/R0 规划里**对 R1 已不成立或自相矛盾**的地方。评审由 6 个维度并行完成（传输/存储/E2EE/鉴权/router 健壮化/测试运维），所有结论均对 R0 实际代码做了 grounding（带文件/行号）。

母设计对 R1 的定义（§9）：agentdeck-relay binary；SQLite 或内存+文件快照；WebSocket endpoints（machine/device connect、subscribe、send command、ack）；structured error + 基础诊断。

## 1. 就绪度结论（先给判断）

**R1 的总体方向成立**（自托管薄 relay + WS + 持久化），R0 也把 Core 路由器与传输解耦（`router.rs` 的 `mpsc<RemoteFrame>` 缝）为 R1 网络化铺好了路。**但 R1 尚不能直接进入实现**——评审发现 R0 现状与母设计在若干处对 R1 不成立，其中有 **3 个必须在正式设计前拍板的重决策**和 **一批母设计/R0 内部矛盾须先订正**：

- **鉴权归属矛盾（最重要）**：R1 首次开放网络端点，但母设计 §9 把配对/凭据推到 R2/R3，而 §7/§8 又把「可撤销 device credential + relay.auth.\* 失败码」当 relay 职责。R0 的 `RemoteFrame.from`、`connect(role)`、`RegisterMachine` **全部自述且从不校验**（已核实：`router.rs` `connect(&self, role)` 直接采信、`role` 字段还挂着 `#[allow(dead_code)]`）。**结论：无鉴权的网络 relay = 完全授权绕过**（任意端可冒充任意 machine/device、订阅他人会话、注入 AdminReply、操控任意 machine）。R1 **必须**落地最小连接鉴权，不能推给 R2/R3。
- **E2EE 分期与「零知识」承诺**：母设计把 E2EE 列为 R1(v0.5) 硬交付，但 R1 两端（bridge 侧本地 daemon、CLI device）同信任域，E2EE 零收益；真实威胁边界在 R2/R3 才出现，且密钥要 R2/R3 才有。同时母设计 §7「relay 默认不保存明文/无法读取」对 R0/R1-plaintext **过度承诺**（relay 在内存与无界 `conv_buffer` 里完整持有 `DataEnvelope::Plaintext{bytes}`，T3 只证明「不 decode」非「读不到」）。
- **HOL 阻塞是 R1 头号正确性阻塞项**：R0 单 Core actor 的 `send_to` 内联 `out.send().await`（`router.rs:114-119`），网络下一个慢连接阻塞整个 relay。

一句话：**R1 可以做，但它的真实工作量远大于母设计 §9 的字面描述**——鉴权、seq 持久化、背压、Encrypted 帧格式冻结这些「隐性但硬」的项，母设计要么没写、要么排错了阶段。

## 2. 关键待决策清单（建议方案）

> 以下是进入 R1 设计前需要确认的决策。每条给出评审推荐；标 ★ 的是必须先拍板的重决策。

| # | 决策 | 推荐 | 理由摘要 |
|---|---|---|---|
| D1 | Relay WS 栈 | 服务端 **axum**（WebSocketUpgrade + 路由 + auth extractor，为 §5.1 预告的配对/注册/通知/未来 web 面留位）；客户端 **tokio-tungstenite** | axum 底层即 tungstenite，线兼容；客户端更瘦、适合 R2 放进 daemon；避免两套 WS 实现 |
| D2 | TLS/wss | dev 默认 `ws://` loopback；生产**可选 rustls feature 进程内 `wss://`**（用户给 cert/key），并文档化反代终止作为备选；不用 OpenSSL | 母设计 §10 要求公网真机访问、iOS ATS 拒明文——wss 必须在 R3 前就绪；rustls 无 OpenSSL 依赖、交叉编译友好，契合薄单二进制 |
| ★D3 | 服务端抽象 vs N6 Transport trait | **relay 服务端不实现 Transport trait**（它是客户端出站单连接抽象）；服务端 = accept 循环 + per-conn actor 新抽象；在 Transport 之上加 **RemoteFrame-typed 的 `RelayLink`/`WsRelayClient`** 层，R0 内存 `RelayClient` 与 R1 `WsRelayClient` 共用之，bridge/CLI 零改切换 | Transport 语义（send/recv 单 String 行、reconnect、单连接）是客户端出站；relay accept N 连接、从不自 reconnect、需 per-conn 身份——强套是概念错配。N6 守护测试与 trait 形状**无需改动、保持绿** |
| D4 | DataEnvelope 线编码 | `bytes`（及 R1 Encrypted 的 ciphertext/nonce/tag）加 **base64 serde**；一条 RemoteFrame = 一条 WS **text** 帧、无 length-prefix；设 `max_message_size` + 超限失败码 | 现状 `Vec<u8>` 经 serde_json 序列化为数字数组（已核实 `data.rs:15`），流式 agent+密文下 3-4x 膨胀；WS 自带消息分帧，length-prefix 是 stdio 遗留 |
| ★D5 | net feature 拓扑 | `agentdeck-relay`=server(axum+net)；**新建 `agentdeck-relay-client` crate**=WsTransport+WsRelayClient(tungstenite client+net)；CLI(R1)/daemon-remote(R2) 只依赖 client crate；**daemon 保持 no-net 至 R2**；补 CI/脚本 guard 断言 agentdeckd 依赖树无 tokio net | daemon 至 R2 前必须无 net；R0「编译期无网络」实为「没人加 net」无任何 guard（已核实），R1 引 net 后必须补自动守护否则边界必漂 |
| ★D6 | R1 鉴权/配对最小集 | **R1 落地**：WS 握手 `Authorization: Bearer` header → 服务端派生并强制 `ClientRole`（忽略/仅校验 `from`）；device credential = 256-bit 不透明 token **存哈希**、可撤销（删行即时生效）；账户身份 = **Ed25519 sign 密钥对 + 服务端只存公钥**；配对 = REST challenge-response（服务端 CSPRNG nonce + 短 TTL + 单次原子消费，焊死 happy #669）；引入 **account_id scope**（单账户也要，每个 Subscribe/SendCommand 过 scope 校验）。**推 R3**：QR 扫码 UX。**推 R2**：daemon 作为有凭据 machine 接入 | 数据模型（accounts/devices/challenge/公钥登记）是最贵的一次性成本，R3 QR 只替换「谁授权入网」；裸预共享 token 无 per-device 撤销、无前向路径、被抓即全账户沦陷 |
| ★D7 | E2EE 分期 | **R1 = TLS-only + 冻结 `DataEnvelope::Encrypted` 布局 + seal 策略（required_e2ee/optional/plaintext_only）+ loopback 默认/非 loopback 拒 Plaintext 门禁**；真加解密 R2（daemon 持凭据）、跨平台互操作 R3（iOS）。canonical 密码学：内容层 **IETF ChaCha20-Poly1305(12B nonce)**（Rust `chacha20poly1305` 与 iOS `CryptoKit.ChaChaPoly` 唯一共同 AEAD），密钥封装 **X25519 ECDH + HKDF 手工 box**（**不要** crypto_box 的 NaCl 布局）；布局 + 跨语言测试向量由 agentdeck-protocol(Rust) 在 R1 先定入库，R3 iOS 校验；配对同时登记 sign(身份)+box(E2EE) 双公钥 | E2EE 收益在跨信任边界才出现（R2/R3），但格式/策略必须 R1 冻结否则 R2/R3 破坏契约；R0§8/§11 的 crypto_box+CryptoKit **不可互操作**（nonce 长度/原语不同），必须 R1 由 Rust 侧定 canonical 而非等 R3 反向发现 |
| ★D8 | 存储模型 | **纯 SQLite(WAL)** 存小而关键的持久事实：机器身份、会话目录(SessionDescriptor)、**per-conversation seq 高水位**、device 凭证、revocation；**事件负载只留内存**（有界 + ack trim），不落盘；连接态（conns/subs_\*/req_origin/is_online/turn_conv/conv_machine 索引）**绝不落盘**。rusqlite + 专用 Store 任务 + HiLo seq 预留区间（把同步写移出 Core 热路径）；schema 预留 nullable owner_id | 母设计「内存+文件快照」的崩溃窗口会破坏 seq 单调（正确性硬伤）；事件不落盘规避 §7「明文写盘」违规、解耦 E2EE 时序、避开写压；会话内容权威源在 daemon 历史而非 relay（§5「不作数据仓库」） |
| ★D9 | Router 健壮化（清 R0 六债 + 网络正确性） | ①**per-conn 写任务 + 有界队列 + `try_send` 溢出策略**（事件可丢+标 lagged，靠 seq/buffer/Ack 重放；控制/回执满则断连；Core 绝不 await per-conn 发送）；②**Ack 驱动 conv_buffer trim + 上界 + RetireSession 级联清 + persist-before-deliver 的 seq 高水位**；③AnnounceSession **upsert 去重**；④req_origin **TTL + disconnect 清理**；⑤AdminReply **校验回复者=目标 machine 连接** + RegisterMachine **校验凭证与 machine_id 一致**（拒跨身份覆盖）；⑥bridge 写失败**不置 inflight、回错误码、下线**。不引入 expectedVersion；**CommandDelivered 语义定义为 enqueued-to-machine**（不承诺已处理） | 多条 R0 债在「网络+持久+多连接+弱信任」下升级为正确性/安全关键；④实为「每 prompt/approval 必漏」（Conversation/Turn 命令回执走 Event 流、永不触发 AdminReply 清理路径） |
| D10 | 协议版本 | RELAY_PROTOCOL_VERSION **0→1**（首个联网 wire-stable 版本，v0=从未联网草案直接拒）；握手期做**版本 + seal 能力协商**（client 报支持集，server 取交集）；保留 deny_unknown_fields 但用协商避免跨版本硬拒 | deny_unknown_fields + 无协商 → App Store iOS(R3) 与自托管 relay 升级步调不一致时新字段被硬拒；R3 上架前必须就绪，R1 预留握手协商位 |
| D11 | 测试分层 | 逻辑测（T1/T2/T3 + router 单测）**继续跑确定性内存 mpsc**；WS 编解码/连接生命周期写**独立 loopback+ephemeral(:0) 测**（oneshot 就绪同步、沿用 5s bounded-timeout）；时间逻辑（心跳/TTL/退避）用 **tokio test-util paused time**；新增 **T5「WS 传输冒烟」**（gated loopback，合成 machine + 真实 daemon admin over 真 WS）；**T4 真实会话穿透仍推 R2**（需 daemon remote mode + 身份 bootstrap）；CLI smoke 支持 `--relay ws://`；补 daemon-no-net guard | R0 已把 Core 做成 transport-agnostic，把易 flaky 的真网络面压到最小、其余保持确定性是唯一低成本路径 |
| D12 | 交付/运维 | `agentdeck-relay` 加 **binary**（`src/main.rs`+`[[bin]]`）+ 配置（`--bind` **默认 127.0.0.1**、`--storage`/`--in-memory`、`--log-level`、可选 `--tls-cert/--tls-key`；`AGENTDECK_RELAY_*` env + **dotenvy**，因 Swift 的 DotEnv 不覆盖 Rust binary）+ `relay --selfcheck`；**tracing + tracing-subscriber** + **脱敏 Debug（DataEnvelope/AuthContext）** + 哨兵-token 日志脱敏测试；Docker（多阶段 + compose，TLS 交反代或 rustls）；AGENTS.md 补 R1 验证入口 | R0 relay 是 lib-only、无任何 logging/配置层；「日志禁明文/token」目前是空话（`AuthContext` derive Debug+Serialize 会打印 token，与其注释矛盾——已核实），必须落地脱敏 + 可执行测试才成立 |

## 3. 母设计 / R0 需订正的内部矛盾与文档漂移

> 这些是评审发现的**规划缺口**——进入 R1 设计前应先订正对应文档，否则会误导实现。

1. **G1 鉴权阶段归属自相矛盾**（母设计 §5.1/§9 把配对/凭据/撤销列为 R1，§8 又列 relay.auth.\* 码；R0 §8 却把 device credential/撤销/challenge nonce 推到 R2/R3）→ 和解为：**凭据签发+撤销+challenge 骨架 = R1；QR UX = R3；daemon 有凭据接入 = R2**。
2. **G2 §10 R1 验收越界**（混入「daemon 断线重连补拉未 ack 的加密事件」「撤销 device credential 后禁订阅」等 R2/R3 概念）→ 重写为 §9 scope 可达项，越界项显式标 R2/R3。
3. **G3 §7 零知识过度承诺**（对 R0/R1-plaintext，relay 内存+conv_buffer 完整持明文）→ 改写为区分**结构化零知识(Encrypted，跨信任边界)** vs **按策略不检视(Plaintext，自托管单运营者)**，并说明零知识仅在 Encrypted 下结构成立。
4. **G4 §6 stream_seq（全局）vs R0 per-conversation conv_seq** → 订正为 **per-conversation seq**；`Ack.conversation_id: Option` 的 None 语义未定义 → **收紧为必填**。
5. **G5 §6 `signature` 字段 R0 已丢弃** → 明确 **R1 不做逐帧签名**（传输鉴权=握手 Bearer，内容完整性=Encrypted 的 AEAD tag），把 signature 定性为对 happier 的误读并删除。
6. **G6 §5.1「5 个 WS endpoints」过时**（R0 已把 subscribe/send/ack 折进单连接的 RelayControlMsg 变体）→ R1 实际只需 **1-2 条 WS 路由**（/machine、/device 或单路由+握手角色），不要误建 5 条 REST 端点。
7. **G7 §11 加密库选型不可互操作**（crypto_box NaCl 24B nonce ≠ CryptoKit ChaChaPoly IETF 12B nonce；Noise/age/libsodium 三条互斥路线未收敛）→ 收敛为 D7 的 canonical。
8. **G8 §6 Connection/Subscription 与持久对象并列无分层** → 明确二者是**连接态、R1 不建表**。
9. **G9 R0 §4.1 声称 relay 依赖 tracing，实际 Cargo.toml 无**（已核实）→ R1 落地 tracing。
10. **G10 R0「编译期强制无网络」无任何 guard**（已核实仅靠没人加 net）→ R1 引 net 后补自动化守护。
11. **G11 类型漂移**：`agentdeck_protocol_version` 代码是 **u32**（`data.rs`/`fleet.rs`），R0 设计文档写 u16；`RELAY_PROTOCOL_VERSION` 是 u16 而 `PROTOCOL_VERSION` 是 u32 → R1 冻结契约前统一并让 schema 快照守护。
12. **G12 `transport.rs` `AuthContext` derive(Debug,Serialize) 与「Must not leak token material in display」注释矛盾**（已核实 line 8 vs 47）→ R1 接线前落脱敏 Debug/Display 实现兑现注释。
13. **G13 R0 §8/§11「CLI 是否扩成 remote 客户端」实际已隐性拍板为做**（remote.rs 已冻结 `--relay ws://` 语义并留桩）→ 勾销该开放问题，R1 直接落地。
14. **G14 `created_at_ms` 全调用点传 0、Heartbeat/last_heartbeat_ms no-op** → R1 明确**边缘 ingest 点 stamp**（保持「外部传入不取内部时钟」的确定性约定）+ **心跳超时判 online**。
15. **G15 `PublishEvent.seq` 是 machine→relay 僵尸字段**（relay `router.rs:158 seq:_` 忽略、自行 re-stamp）→ 移除或注明忽略，避免误导实现者以为 machine 设权威 seq。
16. **G16 relay 存储边界不变量缺失**（ARCHITECTURE.md 只有 daemon 的 K5/K6）→ R1 补：relay 独立 `--data-dir`（与 daemon 目录隔离，relay 常在异机/容器）、只存不透明数据。
17. **G17 `account_or_profile_id` 在 R0 被丢弃** → R1 重引 account scope（fleet 类型/relay 索引/授权检查点）。

## 4. 风险登记册

**High（R1 前必须有对策）**

- **HOL 阻塞**：单 Core actor `send_to` 内联 await，慢连接停摆全 relay（网络下常态触发，非边缘）。对策见 D9①。
- **开放 relay / 身份欺骗**：`from`/`connect(role)`/`RegisterMachine`/`AdminReply` 全未认证 → 冒充、越权订阅、响应注入、机器身份劫持覆盖。对策见 D6 + D9⑤。
- **seq 回退**：conv_seq 内存 HashMap，重启归零 → seq 碰撞 → 设备去重丢真事件/补拉崩。对策见 D8（持久高水位 + persist-before-deliver）。
- **req_origin 每 prompt/approval 必漏** → 长驻 OOM。对策见 D9④。
- **conv_buffer 无界 + Ack no-op + RetireSession 不清** → 长驻 OOM。对策见 D9② / D8。
- **加密库互操作返工**：拖到 R3 才发现两端 AEAD/nonce 不兼容需返工整个数据面。对策见 D7（R1 定 canonical + 向量）。
- **tracing 明文/token 泄漏**：`DataEnvelope`/`AuthContext` derive Debug/Serialize，任一 `debug!(?frame)` 即泄漏 prompt/shell/diff/token。对策见 D12（脱敏 + 日志捕获测试）。
- **零知识结构性缺口**：见 G3；R1 loopback 默认 + 非 loopback 拒 Plaintext 门禁兜底。

**Medium**

- 线格式膨胀（Vec<u8> 数字数组，D4）；无版本协商跨版本硬拒（D10）；订阅/命令无 ACL（D6 account scope + ACL 钩子）；reconnect 订阅态丢失（RelayLink 层重放 Subscribe+Ack 游标）；bridge 写失败卡 single-flight 死锁（D9⑥）；配置源 .env 不覆盖 Rust binary（D12 dotenvy）；is_online 序列化落盘把离线广告成 online（D8 只存身份列、online 实时算）；WS 大消息（HistoryResponse）无上限（D4 max_message_size）。

## 5. 分维度评审摘要（R1 必须交付）

- **传输/网络**：axum server + tungstenite client；服务端 accept+per-conn actor（不碰 Transport trait）；RelayLink/WsRelayClient RemoteFrame 层；DataEnvelope base64 + 单 WS text 帧；per-conn 写任务 + try_send（清 HOL）；net 拆 client crate + daemon-no-net guard；握手 Bearer 鉴权派生角色。
- **状态/存储**：持久/易失分层；纯 SQLite(WAL) 存身份/目录/seq 高水位/凭证/revocation；事件负载只内存（有界+ack trim）；rusqlite + Store 任务 + HiLo seq；schema 预留 owner_id；relay 存储边界不变量。
- **E2EE/安全**：TLS-only 先行 + 冻结 Encrypted 布局 + seal 策略 + loopback 门禁；canonical IETF ChaCha20-Poly1305 + X25519/HKDF + 跨语言向量；连接身份握手期绑定根除 from/RegisterMachine/AdminReply 伪造；脱敏日志。
- **鉴权/配对**：Authorization header Bearer；256-bit 不透明 token 存哈希、可撤销；Ed25519 账户密钥对 + 只存公钥；REST challenge-response（CSPRNG nonce+TTL+单次消费）；account scope + ACL 钩子（默认 permissive）；配对登记 sign+box 双公钥；撤销 R1 做连接级（关连接+拒连），E2EE per-device 密钥撤销留 R2/R3。
- **Router 健壮化**：D9 六条 + CommandDelivered 语义 + 不引 expectedVersion（单 actor 串行已足，会话 metadata 权威写者是 machine）。
- **测试/运维**：逻辑测留内存确定性 + WS 适配器 loopback 测 + paused time；T5 WS 冒烟 / T4 留 R2；relay binary+config+dotenvy+selfcheck+Docker；tracing+脱敏+日志捕获测试；RELAY_PROTOCOL_VERSION 1 + 握手协商；错误码集中化为类型注册表（当前是散落裸字符串）+ 进 schema；AGENTS.md 验证入口。

## 6. 建议的 R1 范围切分（和解矛盾后）

**在 R1（Relay MVP）内**：WS server(axum) + 可选 TLS(rustls) + 最小 Bearer 鉴权 + account scope + device credential 签发/撤销 + REST challenge-response 骨架 + SQLite 持久化(身份/目录/seq/凭证/revocation) + router 健壮化(D9①-⑥) + DataEnvelope base64 + **Encrypted 布局冻结(不含真加解密)** + seal 策略 + 版本/能力协商 + tracing/脱敏 + relay binary/config/Docker + CLI `--relay ws://` + T5 WS 冒烟 + daemon-no-net guard + 错误码类型化。

**推到 R2**：真实 encrypt/decrypt（daemon remote-mode 持密钥）、agentdeckd remote mode 本身、真实会话穿透 T4、outbound reconnect/backoff。

**推到 R3**：QR 扫码配对 UX、iOS `RelaySessionSource`、跨平台密码学互操作验证、APNs。

**推到 R4**：hosted/多租户/团队 ACL、scoped 凭据、JWT 规模化。

> 注意：这个切分把母设计 §9「R1 = 单纯 relay MVP」实质**扩展**为「R1 = 可安全联网的 relay MVP」——因为「开放网络端点但不鉴权」不可接受。R1 的真实工作量因此显著大于母设计字面，需在正式设计/计划时按此认知排期。

## 7. 进入正式 R1 设计的前置条件与下一步

**进入 R1 头脑风暴/设计前需确认（用户拍板）**：
1. ★D6 R1 鉴权范围（是否接受「R1 落最小 Bearer + 凭据/撤销/challenge 骨架 + account scope」这一比母设计更大的 R1 边界）。
2. ★D7 E2EE 分期（是否接受「R1 TLS-only + 冻结 Encrypted 格式 + 定 canonical crypto，真加解密留 R2/R3」）。
3. ★D8 存储模型（纯 SQLite + 事件不落盘 vs 母设计的内存+快照）。
4. ★D5 net 拓扑（是否新建 `agentdeck-relay-client` crate）。

**建议下一步**：
- 若用户认可本评审的方向 → 先按 §3 订正母设计 + R0 文档的漂移/矛盾项（G3/G4/G5/G6/G9/G11/G13/G15 等，低成本消歧），再以本文的决策表为输入，走 R0 同款「头脑风暴 → 设计文档（含代码评审修订）→ 实现计划 → subagent 驱动执行」流程做 R1。
- R1 体量明显大于 R0，建议正式设计时进一步把 R1 切成可独立验收的子切片（如 R1a 传输+鉴权骨架、R1b 持久化+router 健壮化、R1c Encrypted 格式冻结+seal 策略），每片一份 spec+plan。
