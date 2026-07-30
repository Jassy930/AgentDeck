# Relay Web Test Companion 设计

| 字段 | 值 |
|---|---|
| 状态 | W0/W1 automatic complete；W2 尚未开始 |
| 日期 | 2026-07-30 |
| 基线 | `codex/relay-mvp-rescue` / `2aec190` / tree `27c8fbb` |
| 目标 | 用浏览器直接复用 Relay v2 + E2EE v1，增加一条低成本、可重复的远程业务闭环 |
| 非目标 | 交付正式 Web 产品、替代物理 iPhone/第二台 Mac或证明 production 公网 TLS |

## 1. 背景与结论

Relay Companion automatic MVP 已能在一台 Mac 上通过真实 temp TLS Relay、唯一 `agentdeckd`、
synthetic Codex/Claude Code 和 iOS Simulator 完成：

```text
pair → list/open → prompt → approval → relaunch/reconnect → revoke
```

剩余外部槽位是物理 iPhone、第二台 Mac、公网 WSS、production signing 和真实 vendor。它们不能由更多
本机 fixture 变成 PASS，但开发阶段仍需要一条启动更快、可由 Playwright 控制、能独立于 Swift/iOS UI
定位 Relay/Runtime 问题的第二远程客户端路径。

本设计选择“测试型 Web Companion”，不选择完整网页版产品：

- 浏览器直接连接既有 `/v2/pair` 与 `/v2/connect`，不经新业务后端或本机 UDS 代理。
- Relay outer codec、Runtime v5 DTO、canonical bytes 与 E2EE 由 Rust 共享代码编译为 WASM；TypeScript
  不手写第二份协议或密码学。
- 浏览器只拥有远程 device principal 和本地可恢复状态；`RuntimeCore` 仍是唯一业务事实源，
  `agentdeckd` 仍是唯一运行平台。
- 本阶段只形成 automatic/test evidence。浏览器结果不能替代物理设备、公网、Keychain/FileProtection、
  第二台 Mac或 production-signed 证据。

2026-07-30 已完成 W0：同一 Rust protocol/crypto 实现可原样编译为 browser WASM；Chrome 自动用例已关闭
golden-vector parity、strict Relay/Runtime 负例、non-extractable WebCrypto KEK 的 IndexedDB structured clone、
transaction abort rollback、exact revision CAS 与 Web Locks 第二 tab 拒绝。W0 没有新增业务 bridge、daemon、
Relay/Runtime/E2EE 版本或 TypeScript wire/crypto owner。

W1 已用真实 Chrome、每轮 fresh `localhost` 证书和临时 TLS Relay 关闭 `/v2/connect` 的
Hello→Challenge→Authenticate→Authenticated 与 sealed sentinel route。Relay restart 后重复发布保持一条
SQLite frame，wrong identity、challenge/signature 篡改、Authenticate replay、text/oversize、disconnect 和
unavailable 均为零新增 frame；DB/WAL/SHM、浏览器输出和临时 root 未发现 sentinel 明文。该证据使用隔离
Chrome 精确 SPKI 参数与 `w1-test-fixture` 固定 identity，只是 automatic test policy；`/v2/pair` 和完整业务
链路仍属于 W2，不能外推为 production pin 或完整网页版。

## 2. 目标与非目标

### 2.1 目标

1. 一条命令启动 fresh Relay、daemon、synthetic adapter、隔离浏览器 profile 和 Web UI。
2. 浏览器使用独立 installation/key/grant，经真实 Relay v2/E2EE 控制现有 daemon。
3. 自动读回 pair/list/open/prompt/approval/reload/reconnect/revoke，以及 exactly-once、明文隔离和 cleanup。
4. 每阶段都有正例、反例、运行态读回、残留检查和 clean Git 状态。
5. Web 实现不新增 Runtime/Relay/E2EE 版本，不把 vendor token 或本机 UDS 暴露给浏览器。

### 2.2 非目标

- 不做完整 Web 产品、账号系统、托管 Relay、多租户、离线 transcript、附件或后台推送。
- 不让浏览器读取项目文件、本机 Runtime UDS、Codex/Claude Code token 或 daemon 私有数据库。
- 不在 TypeScript 中复制 Relay binary codec、Runtime wire、签名 TBS、HPKE/AEAD 或 replay/counter 规则。
- 不把本机 loopback/Playwright 结果称为跨网、物理设备、Safari 或 production TLS PASS。
- 不修改 Relay 为通用 HTTP 静态站点；测试页面由独立的短生命周期静态 server 提供。

## 3. 方案比较

| 方案 | 收敛价值 | 主要问题 | 决策 |
|---|---|---|---|
| 继续只用 iOS Simulator | 已有完整 automatic 业务闭环，生产 Swift 路径覆盖最好 | 启动慢；不能提供第二语言/第二 UI 的独立定位面 | 保留为权威回归门禁 |
| Web UI + 本地 Rust/Swift bridge | 最快出现页面，可复用 native client | 浏览器不是远程 principal；bridge 容易变成第二运行平台和协议代理 | 不作为主线 |
| TypeScript 直接重写 Relay/E2EE | 浏览器部署简单 | 产生第三份协议、crypto 和 durable-state 实现，规模重新失控 | 拒绝 |
| Rust/WASM core + 薄 Web host | 直接连真实 Relay；协议/crypto 复用；Playwright 易编排 | 需要证明 WASM 可移植性、IndexedDB 原子状态与浏览器 TLS 边界 | 推荐 |
| 直接上公网/物理设备 | 最接近最终事实 | 依赖签名、证书、设备、网络和安全运维，失败定位成本高 | W4 外部门禁 |

## 4. 架构

```text
Browser / Playwright isolated profile
  ├─ Web UI (Bun + TypeScript)
  │    └─ 只处理渲染、用户意图、WebSocket/IndexedDB host adapter
  └─ agentdeck-web-core.wasm
       ├─ 复用 agentdeck-protocol：Relay v2 codec + Runtime v5 DTO/canonical bytes
       ├─ 复用 agentdeck-crypto：Ed25519 / HPKE / ChaCha20-Poly1305
       └─ 拥有 browser remote state machine、counter/replay/cursor/outbox
                    │ opaque binary WebSocket
                    ▼
              existing agentdeck-relay
                    │ opaque routes / sealed bytes
                    ▼
              existing RemoteLink
                    │ RemotePrincipal
                    ▼
            singleton RuntimeCore / agentdeckd
                    │
             synthetic vendor adapter
```

禁止新增 `web-daemon`、`browser-runtime-server` 或 UDS→HTTP bridge。短生命周期静态 server 只提供测试页面，
没有身份、协议、crypto、会话或命令 authority。

### 4.1 模块所有权

- `agentdeck-protocol`：继续是 Relay/Runtime 类型、binary codec 和 canonical bytes 的事实源。
- `agentdeck-crypto`：继续是 E2EE 实现和 KAT 的事实源；WASM 只增加受控导出，不复制算法。
- `agentdeck-web-core`：新的 transport-neutral remote client owner；接收 host event，输出 opaque send action、
  typed view state 和 durable mutation intent。
- `web/relay-test-companion`：Bun 管理的薄 UI/host adapter；不能构造或解释 wire/crypto bytes。
- `agentdeck-relay`、`agentdeckd`：保持现有生产边界，不因网页增加业务字段、HTTP API 或 vendor 分支。

### 4.2 浏览器 host contract

WASM 与 TypeScript 之间只允许以下高层边界：

- 输入：用户意图、WebSocket binary frame、timer、visibility/reload、已提交的 storage revision。
- 输出：待发送 binary frame、原子 storage transaction、typed view state、typed failure、cleanup request。
- 禁止：把 private key、DEK、raw grant、canonical TBS 或解密后的 Runtime wire交给 UI 层。

所有 binary frame 在进入 UI 前保持 opaque。用于断言的业务状态来自 WASM 输出的中立 view model，不由
TypeScript 二次解释 Runtime wire。

## 5. 协议与多语言策略

网页不引入新的物理协议版本。共享策略固定为：

1. Rust 类型与 codec 是唯一编码事实源。
2. WASM 直接调用同一 Rust `encode/decode`、canonicalization 和 crypto。
3. JSON Schema 只用于文档、view model 校验和漂移检测，不用 schema generator 重写 binary codec。
4. 现有 Rust/Swift golden vectors 增加 browser consumer；同一输入必须产生 byte-identical 输出。
5. TypeScript 只允许生成 view model 类型，不允许生成或手写 Relay/Runtime wire owner。

如果 W0 证明现有 crate 无法在不复制协议/crypto 的前提下形成 WASM core，计划必须停止并重新评审，不能
退化为 TypeScript 重写。

## 6. 浏览器持久状态

测试型 Web Companion 仍需证明 reload/reconnect，不允许只把密钥和 counter 放在内存中。

- 每个 fresh Playwright profile 生成独立 installation identity。
- IndexedDB 保存 versioned paired marker、encrypted crypto state、counter guard、replay window、cursor、
  outbox 和 exact revision。
- 设备私钥与 state plaintext 由 IndexedDB 中不可导出的 WebCrypto KEK 加密；WASM 活跃时只在受控内存中
  短暂解密，Debug/log/DOM/截图均不得出现秘密。
- 每次发送先用单个 IndexedDB transaction durable 提交 counter reservation，再产生 wire；状态更新同样以
  previous revision + exact next commitment 做 CAS，禁止 blind overwrite。
- 使用 Web Locks API 对 installation 取得单写者 lease；第二 tab、worker 或旧 generation 只能只读失败或
  typed fail-close，不能同时消费 counter。
- `BroadcastChannel` 只做 generation invalidation 通知，不承载 canonical state。
- revoke 后先持久化 terminal/cleanup journal，再删除 grant/private material；页面刷新不能恢复已撤销 identity。

W0 必须先验证当前目标 Chromium 对 non-extractable `CryptoKey` 的 IndexedDB structured clone、transaction
rollback 和 Web Locks 行为。上述能力任一不可靠，W2 前停止。

## 7. TLS 与浏览器硬边界

当前 native client 支持 public CA、public CA + current/next SPKI pin、以及 pinned self-signed。浏览器
WebSocket API 不暴露 peer certificate，也不允许应用执行等价的 SPKI pin 回调。因此：

- automatic W1–W3 使用每轮 fresh 证书，并由隔离 Chromium 测试配置只信任该轮测试 SPKI/CA；该配置是
  test harness policy，不冒充应用层 pin。
- 浏览器仍验证 Relay v2 Challenge 中的 `relayServerId` 和 signed authentication transcript。
- Web UI 必须使用固定 HTTPS origin、CSP `default-src 'self'` 与收紧的 `connect-src`，不加载第三方脚本。
- 正式公网 Web 若继续推进，只能先要求 public CA；PairInvite 的 current/next SPKI pin 在普通浏览器中无法
  获得 native 等价保证，必须单列产品安全决策。

所以 Web automatic PASS 不能关闭 `public-wss-ca-and-spki-pin`、物理设备或 production signing 槽位。

## 8. 错误、诊断与隐私

- failure code 使用 `web.remote.*` host 前缀或复用既有 `relay.client.*` / `remote.*` typed code；UI 不显示
  raw crypto、wire 或 vendor 文本作为协议错误。
- 日志只允许 stage、generation、opaque correlation hash、计数和脱敏 failure code。
- 页面、Playwright trace、screenshot、console、Relay DB/log/metrics 必须扫描 secret、prompt、assistant、
  approval sentinel 明文。
- transport error、storage conflict、replay/nonce reuse、revoked、incompatible、securityError 分开终态化；
  fatal security state 不自动重连。
- runner trap 必须回收 browser、static server、Relay、daemon/host、临时证书/DB/profile/root；只按本轮
  exact PID/path/启动身份清理，不做全局进程名 kill。

## 9. 分阶段闭环

| 阶段 | 关闭的问题 | 自动证据 | 明确不能证明 |
|---|---|---|---|
| W0 可行性 | Rust codec/crypto 能否原样复用到 WASM；浏览器 storage 能否安全提交 | golden vector byte parity、WASM build、IndexedDB/Web Locks 正反例 | 真实 Relay 业务 |
| W1 直连 | 浏览器能否直接完成真实 Relay v2 TLS/Hello/auth/E2EE 传输 | temp TLS Relay、binary WSS、challenge/auth、tamper/replay、明文扫描 | pairing/业务 UI、production pin |
| W2 纵向业务 | 网页能否完成完整远程用户流 | pair/list/open/prompt/approval/reload/reconnect/revoke 与 exactly-once | 物理/公网/真实 vendor |
| W3 恢复隔离 | 浏览器 crash/tab contention/Relay restart 是否可重复收敛 | 三个 durable cut、旧 generation、第二 tab、网络中断、三次 fresh run、cleanup | 跨物理网络和系统 Keychain |
| W4 外部槽位 | 公网和独立设备是否真实可用 | 独立 runner 的真实输入、证据与 readback | automatic 本机结果不能代替 |

W0–W3 每阶段必须独立 scoped commit、focused gate、integration gate、运行读回、负例、cleanup、文档更新和
`git status --short --branch` clean。代码候选变化会使本阶段旧证据失效。

## 10. 验收边界

Web Test Companion 只有满足下列条件才可写为 `Implemented (automatic test scope)`：

- 浏览器直连真实 Relay，不经过业务 bridge。
- Relay/Runtime/E2EE 版本未变，TypeScript 中没有第二份 wire/crypto owner。
- W0–W3 automatic gates 全绿，同一 candidate 三次 fresh W2/W3 E2E 一致。
- prompt/approval/command exactly-once，reload/reconnect 不重复副作用，revoke 后不可重连。
- Relay/浏览器日志、DB、trace 与 screenshot 中业务/秘密明文缺失。
- 所有本轮进程、profile、证书、数据库和临时 root 已清理，Git clean。
- iOS Simulator 权威回归仍通过；Web 不能以替代方式删除或降级它。
- W4 继续保持独立 `BLOCKED` 或由真实外部证据关闭，不把 W0–W3 结果写入外部 PASS。
