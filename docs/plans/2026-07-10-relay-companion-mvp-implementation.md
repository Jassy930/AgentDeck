# AgentDeck Relay Companion MVP 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 交付一个真实可用的端到端 Companion MVP：每个被控 macOS 登录用户只有一个 `launchd` 常驻 `agentdeckd`，本地 App/CLI 与多个远程 macOS/iOS/CLI 客户端共享同一 RuntimeCore；Relay 严格最小可见，Codex 与 Claude Code 均通过真实链路完成浏览、prompt、审批、重连与多写者裁决。

**Architecture:** 以 `RuntimeEnvelope v1` 作为 UDS 与解密后远程链路的共同业务契约；`agentdeckd` 持有唯一 RuntimeCore、稳定 conversation 身份、SQLite journals、per-conversation actor、approval CAS 与两阶段 exec gate；Relay v2 只持有随机 route/stream/request 元数据、公开授权材料和 opaque sealed blob；Swift 的 `AgentDeckSessionSource` 统一本地与远程数据源，`AgentDeckRelayClient` 实现 WSS、CryptoKit、Keychain、replay 和 bounded stream。

**Tech Stack:** Rust 2024、Tokio、rusqlite/SQLite WAL、rustls、`hpke 0.14`、ChaCha20-Poly1305、Ed25519；Swift 6、Foundation/CryptoKit/URLSessionWebSocketTask、AppKit、UIKit、XCTest；macOS 15+、iOS 17+、XcodeGen、launchd、Linux systemd Relay。

**批准的设计事实源:** `docs/plans/2026-07-10-relay-companion-mvp-design.md`。实施中若发现设计无法落地，先更新设计决策与本计划，再继续代码；不得在实现里静默改变信任边界。

## Global Constraints

- 版本轴彼此独立：现有 local IPC `PROTOCOL_VERSION = 2`；新增 `RUNTIME_PROTOCOL_VERSION = 1`；Relay 目标 `RELAY_PROTOCOL_VERSION = 2`；`E2EE_FORMAT_VERSION = 1`。四者不得联动 bump。
- P1 只并列加入 Runtime/Relay v2/E2EE contract；P2 最后一个 cutover task 才删除 Relay v1 生产路径。生产 listener 不提供 v1/v2 双栈。
- Relay v2 wire、schema、SQLite、日志和 metrics，以及 P2.9 cutover 后的全部生产路径，禁止出现机器名、session title、cwd、agent kind、conversation/thread/turn/approval/vendor 真实业务字段或业务 payload。P0冻结当前Relay v1 schema/行为基线；P1继续编译v1 namespace并运行历史行为测试，但P1.3会按计划从local IPC aggregate schema移除v1 entries，不另建或冒充目标v1 schema。P0–P1均不扩展v1产品能力，也不提供v1/v2双栈生产listener。
- 生产 Relay v2 没有 plaintext data envelope；`ws://` 仅允许 loopback 且必须显式 `--allow-insecure-loopback`；非 loopback、TLS feature 缺失、证书不匹配、pin 不匹配都 fail-closed。
- 固定密码套件：HPKE Base mode X25519 + HKDF-SHA256 + ChaCha20-Poly1305；Ed25519；高频 AEAD 为 ChaCha20-Poly1305。禁止手写 X25519/HKDF box。
- CryptoKit HPKE Sender 无固定 RNG 注入口：确定性 byte-for-byte vector 只覆盖 canonical TBS/AAD、ChaChaPoly、签名和 Rust 固定 HPKE KAT；互操作覆盖 Rust 固定 KAT→Swift open、Swift 随机 seal→Rust open。
- 一台逻辑被控机器是一个 macOS 登录用户 profile；stable remote-enabled daemon 只能有一个。开发实例必须同时使用 `--ephemeral --no-remote`，并隔离 DB、UDS、lock、Keychain service。
- local UDS 与 RemoteLink 只做认证、编解码、收发；进入 RuntimeCore 后平权。每 conversation prompt FIFO、最多一个 active turn；control lane 优先处理 approval/cancel；不同 conversation 可并行。
- 所有有副作用命令先持久化再返回 `Accepted`；Relay `RouteAccepted` 绝不代表 daemon 接受或业务成功。审批只认 daemon SQLite CAS 的第一个有效决定。
- `conversationId` 必须在 adapter 启动前由 daemon 生成；vendor resume reference 只能存在于各 adapter 私有 namespace，不能进入 common catalog、Relay 或客户端 wire。继续遵守 N1/N2/N3/N7/N8/K9。
- MachineDataSign 必须签 daemon→device catalog/event/snapshot/key update；DeviceSign 必须签 device→daemon RuntimeRequest。共享 AEAD key 不能替代发送方身份签名。
- Keychain/DB counter 顺序固定为“先提升 CounterGuard high-water，再提交可消费 block”；检测 DB rollback、nonce reuse、key revision rollback 时 remote fail-closed。
- 资源硬上界：Relay frame 4 MiB；part 3.5 MiB；transfer 64 parts/64 MiB/5 分钟；每连接 reassembly 128 MiB；prompt 256 KiB；RuntimeRequest 1 MiB；每 conversation 32 个 queued prompt；全机 1,024 个/256 MiB/24 小时；Runtime DB 2 GiB。
- writer 默认 512 frames/16 MiB；Relay retention 默认每 stream 2,000 frames/64 MiB/24h、每 machine 512 MiB、全局 4 GiB；receive replay window 每 key 4,096 个 counter。
- Machine enrollment code与PairInvite secret均为256-bit随机值、5分钟单次；challenge nonce为32 bytes、30秒单次；approval自动投递每轮最多8次且60秒，默认deadline 30分钟；revoke terminal flush上限2秒。
- `AgentDeckCore` 继续只依赖平台无关 Foundation/Observation，不 import AppKit/UIKit/CryptoKit/网络。Swift 网络与 crypto 只在 `AgentDeckRelayClient`；UI 不拼 wire/crypto bytes。
- MVP 明确不引入 APNs、后台常驻 WSS、离线 transcript 数据库、附件、多租户/团队 ACL、托管 Relay 或账户级密钥恢复；iOS 后台主动断开，回前台从 cursor/snapshot 恢复。
- 不读取、不保存、不转发 Codex 或 Claude Code token；不创建 `cc-meta/`；不把 Runtime DB、Relay DB、日志、invite、证书私钥、Keychain 导出或用户项目数据提交进 git。
- 每个 task 都执行“新增失败测试→确认预期失败→最小实现→确认通过→文档/工作区检查→scoped commit”。不带 co-author，不执行 `git push`。
- 每个commit前先用`git status --short`和`git diff --name-only`核对当前task的Files；文中的目录级`git add`必须在执行时展开为本task实际变更的精确pathspec，任何用户既有/并行无关改动保持unstaged；禁止`git add -A`。

## Phase 依赖与交付

| Phase | 主题 | 退出门禁 |
|---|---|---|
| P0 | 基线、显式 Relay v1 reset、统一验证入口 | 当前 Rust/Swift/iOS/docs 基线全绿；reset 脚本只删除显式指定的 v1 开发状态 |
| P1 | Runtime/Relay v2/E2EE contract 与 Rust/Swift crypto | IPC/Runtime/Relay/E2EE 四套独立 schema、neutrality、Rust↔CryptoKit 互操作全绿 |
| P2 | Relay v2 原子 cutover | restart/revoke/quota/TLS/forgery/replay/slow-client/sentinel 全绿，v1 生产代码删除 |
| P3 | Singleton RuntimeCore、UDS、exec fence、LaunchAgent | 两个本地客户端共享真实会话；crash boundary、install/upgrade/uninstall 通过 |
| P4 | Machine identity、pairing、RemoteLink、远程 CLI | 真实远程 CLI 分别穿透 Codex/CC；Keychain restart 与 trust reset 闭环 |
| P5 | 共享 Swift client、iOS Companion、远程 macOS | Simulator 自动 E2E；物理 iPhone和第二台 Mac gated E2E 通过 |
| P6 | 四端竞态、故障注入、运维与 DoD | 设计 §17 十三项全部有可读证据 |

**设计覆盖索引:** §6 enrollment/pair/revoke/reset→P1.2、P2.2/P2.4/P2.7/P2.8、P4.1–P4.3、P5.6；§7 crypto/key/counter→P1.4–P1.7、P4.1/P4.5、P5.2/P5.4；§8 RuntimeCore→P3.1–P3.7；§9 stream/snapshot/transfer→P1.1、P2.3、P3.6、P4.5、P5.3/P5.4；§10–§12 Relay/TLS/ops→P2.1–P2.10、P6.2；§13 Companion→P5.1–P5.9；§14 failures→各phase contract/store/UI tests与DIAGNOSTICS同步；§17 DoD→P6.1–P6.4证据矩阵。

---

## Phase P0：基线与显式 reset

### Task P0.1：冻结基线、显式清理 Relay v1 开发状态、建立统一 verifier

**Files:**
- Create: `scripts/verify-relay-companion-mvp.sh`
- Create: `scripts/reset-relay-v1-dev-state.sh`
- Create: `scripts/tests/reset-relay-v1-dev-state.sh`
- Modify: `.gitignore`
- Modify: `ARCHITECTURE.md`
- Modify: `AGENTS.md`
- Modify: `docs/QUALITY.md`
- Modify: `docs/AGENT_DIAGNOSTICS.md`
- Modify: `docs/index.md`
- Modify: `docs/plans/2026-07-10-relay-companion-mvp-implementation.md`
- Modify: `README.md`

**Interfaces:** `verify-relay-companion-mvp.sh p0` 只编排当前已存在门禁；reset 脚本只接受 `--storage ABSOLUTE_FILE --credentials ABSOLUTE_FILE --confirm DELETE-RELAY-V1-DEV-STATE`，拒绝目录、根路径、symlink 与非 v1 schema/credential shape。开始第一次 unlink 前必须完成全部验证与 unlink preflight（含父目录权限、macOS immutable/system flags），并证明 credential 是解码恰好 32 bytes 的 canonical Base64、credential JSON 的 `account_id/device_id/role` 与 DB 行一致、`Base64(SHA256(credential原字符串))` 等于该行 `credential_hash`；删除前任一 validation/preflight 失败都零删除。preflight 之后 OS unlink 仍因 race/I/O 失败时允许部分删除，但必须非零退出、逐个列出仍存在的 exact path、不打印成功、不承诺 rollback，并指引人工清理后重新配对；SQLite 校验必须使用不触碰 WAL/SHM 的 immutable read。

- [x] Step 1: 先写 destructive-boundary shell test。测试在 tempdir 创建 v1 DB/WAL/SHM、旧 bearer JSON、无关文件和 symlink；断言缺确认串、目录、任一路径组件/sidecar symlink、v2 marker、未知/额外表、错误user_version、DB与JSON account/device/role/credential hash不匹配均退出非零且零删除。只有精确匹配的v1输入会删除DB、精确`-wal`/`-shm`与bearer JSON，并保留同前缀及其他无关文件。
- [x] Step 2: 运行 `bash scripts/tests/reset-relay-v1-dev-state.sh`。 Expected: FAIL，原因是 `scripts/reset-relay-v1-dev-state.sh` 尚不存在。
- [x] Step 3: 实现 reset 与 P0 verifier。reset 使用 `set -euo pipefail`、`realpath`/`stat` 校验、`sqlite3` 只读精确schema/user_version判断和DB↔credential关联校验；先收集并验证全部四个允许删除的精确path，再开始unlink，禁止宽泛glob。verifier顺序运行设计§16.5的P0命令，并确保`agentdeck-relay-data/`未出现在git状态。
- [x] Step 4: 运行 `bash scripts/tests/reset-relay-v1-dev-state.sh` 与 `bash scripts/verify-relay-companion-mvp.sh p0`。 Expected: 两者 exit 0；每个子门禁打印 `PASS`；最终 `git status --short` 不含构建/DB 产物。
- [x] Step 5: 更新README、ARCHITECTURE、QUALITY、DIAGNOSTICS、docs index、AGENTS与本计划进度，只记录已经存在的reset/verifier命令和“先停Relay、显式路径、无dev恢复”边界；运行`scripts/verify-agent-docs.sh`。Expected: `verify-agent-docs: ok`。
- [x] Step 6: 核对精确pathspec并提交。 `git add .gitignore scripts/verify-relay-companion-mvp.sh scripts/reset-relay-v1-dev-state.sh scripts/tests/reset-relay-v1-dev-state.sh README.md ARCHITECTURE.md AGENTS.md docs/QUALITY.md docs/AGENT_DIAGNOSTICS.md docs/index.md docs/plans/2026-07-10-relay-companion-mvp-implementation.md && git commit -m "chore(relay): 建立 Companion MVP 基线与显式 v1 reset"`

---

## Phase P1：Protocol + Crypto

### Task P1.1：定义 RuntimeEnvelope v1 中立 contract

**Files:**
- Create: `agentdeck-protocol/src/runtime/{mod,identity,envelope,catalog,command,event,receipt,sync,transfer,failure,schema}.rs`
- Create: `agentdeck-protocol/tests/{runtime_v1_contract,runtime_neutrality,transfer_envelope}.rs`
- Create: `protocol/agentdeck/runtime-protocol.schema.json`
- Modify: `agentdeck-protocol/src/lib.rs`

**Core interface:**
```rust
pub const RUNTIME_PROTOCOL_VERSION: u16 = 1;
pub struct RuntimeEnvelope { pub version: u16, pub message_id: MessageId, pub body: RuntimeMessage }
pub enum RuntimeMessage { Request(RuntimeRequest), Reply(RuntimeReply), Stream(RuntimeStreamItem) }
pub enum StreamCursor { BeforeFirst, At(u64) }
pub struct RuntimeEvent { pub conversation_id: ConversationId, pub event_id: EventId, pub event_seq: u64, pub item_id: Option<ItemId>, pub entity_id: Option<EntityId>, pub body: RuntimeEventBody }
```

- [ ] Step 1: 写 contract/neutrality/limits tests。 覆盖 stable ID newtypes、deny-unknown、`BeforeFirst/At`、`next()`、RuntimeRequest 1 MiB、prompt 256 KiB、TransferEnvelope 的 1/64/65 parts、3.5 MiB/64 MiB、duplicate-same/duplicate-conflict、TTL/hash/reassembly cap，以及 `SessionCapabilities` 必须在 snapshot items 前；pending pairing 的 list/confirm/cancel DTO必须标为local-only administration。
- [ ] Step 2: 运行 `cargo test -p agentdeck-protocol --test runtime_v1_contract`。 Expected: FAIL，缺少 `agentdeck_protocol::runtime`。
- [ ] Step 3: 实现完整 DTO、构造校验和 `runtime_schema()`。 `RuntimeRequest` 必须覆盖 hello/catalog/subscribe/start/sendPrompt/resolveApproval/retryApproval/cancel/queryReceipt/createPairInvite/listPendingPairings/confirmPairing/cancelPairing/revoke/trust-reset；pending pairing admin请求只允许same-UID UDS `LocalPrincipal`，receipt 明确 `Accepted/Replayed/Failed` 与 approval 五种 delivery state。
- [ ] Step 4: 运行 `UPDATE_RUNTIME_SCHEMA=1 cargo test -p agentdeck-protocol runtime_schema_matches_committed_snapshot`，再分别运行 `cargo test -p agentdeck-protocol --test runtime_v1_contract` 与 `cargo test -p agentdeck-protocol --test transfer_envelope`。 Expected: 全部PASS且生成独立Runtime schema。
- [ ] Step 5: 运行 `cargo fmt --all --check` 与 `git diff --check`。
- [ ] Step 6: 提交。 `git add agentdeck-protocol protocol/agentdeck/runtime-protocol.schema.json && git commit -m "feat(protocol): 定义 RuntimeEnvelope v1 中立契约"`

### Task P1.2：定义 Relay v2 opaque contract、公开授权对象与 E2EE context

**Files:**
- Create: `agentdeck-protocol/src/relay_v2/{mod,id,cursor,frame,auth,enrollment,codec,failure,schema}.rs`
- Create: `agentdeck-protocol/src/e2ee/{mod,context,tbs,pairing,keys,payload,schema}.rs`
- Create: `agentdeck-protocol/tests/{relay_v2_contract,relay_v2_neutrality,e2ee_canonical_contract}.rs`
- Create: `protocol/agentdeck/relay-v2.schema.json`
- Create: `protocol/agentdeck/e2ee-v1.schema.json`
- Modify: `agentdeck-protocol/src/lib.rs`

**Core interface:**
```rust
pub const RELAY_PROTOCOL_VERSION: u16 = 2;
pub const E2EE_FORMAT_VERSION: u16 = 1;
pub struct OpaqueRouteFrame { pub version: u16, pub body: RelayFrameBody }
pub enum RelayFrameBody { Hello(Hello), Challenge(Challenge), Authenticate(Authenticate), Authenticated(Authenticated), OpenPairRoute(OpenPairRoute), PairRouteOpened(PairRouteOpened), PairData(PairData), ClosePairRoute(ClosePairRoute), PairRouteClosed(PairRouteClosed), RegisterStream(RegisterStream), Publish(Publish), Subscribe(Subscribe), Unsubscribe(Unsubscribe), Ack(Ack), Gap(Gap), ReplayComplete(ReplayComplete), Send(Send), Reply(Reply), InstallGrant(InstallGrant), GrantCommitted(GrantCommitted), RevokeDevice(RevokeDevice), RevocationCommitted(RevocationCommitted), RetireMachine(RetireMachine), Ping(Ping), Pong(Pong), RouteAccepted(RouteAccepted), Error(RelayFailure), ServerRestarting(ServerRestarting), RetirementCommitted(RetirementCommitted), PairingHello(PairingHello) }
pub struct MachineEnrollmentRequestV1 { pub code: EnrollmentCode, pub machine_route: MachineRouteId, pub root_pubkey: PublicKeyBytes, pub link_cert: SignedCertificate, pub data_cert: SignedCertificate }
pub struct MachineEnrollmentResponseV1 { pub relay_server_id: RelayServerId, pub machine_route: MachineRouteId, pub trust_epoch: u64, pub receipt_hash: [u8; 32] }
```

- [ ] Step 1: 写v2 schema、bad-frame corpus、binary codec与neutrality tests。 route/generation ID必须恰为128-bit随机值且不可比较/复用；trust epoch/link generation/grant serial/key revision是u64单调值，到MAX必须reset/rekey且禁止wrap；grant/cert/revocation/enrollment DTO有确定字段；production WS codec固定`ADRV2` magic + big-endian version/kind + length-prefixed字段，Rust↔Swift逐字节fixture覆盖每个family；3.5MiB part完整frame≤4MiB，4MiB+1解析前拒绝；schema扫描禁止业务字段与createdAt。
- [ ] Step 2: 运行 `cargo test -p agentdeck-protocol --test relay_v2_contract`。 Expected: FAIL，缺少 `relay_v2` 与 `e2ee` module。
- [ ] Step 3: 实现所有§10.1 family、受限pairing handshake role、TLS machine enrollment request/response、binary codec、TBS/OuterContext/三种HPKE info、公开grant/cert/revocation，以及版本化`PairInviteV1/PairRequestV1/PairPendingV1/PairResponseV1/PairResponseReceivedV1/DeviceAuthorizationV1/KeyDirectoryV1/KeyUpdateV1/EpochBarrierV1/SealedPayloadV1`。`PairResponseReceivedV1`由DeviceSign签名并绑定request/grant/response hash。E2EE type-state固定`UnsignedSealedBlobV1 → SignedSealedBlobV1 → VerifiedSealedBlobV1`，Publish/outbound只接收Signed，AEAD open只接收Verified；P1保留旧Relay v1 namespace。
- [ ] Step 4: 运行 `UPDATE_RELAY_SCHEMA=1 UPDATE_E2EE_SCHEMA=1 cargo test -p agentdeck-protocol schema_matches_committed_snapshot`，再分别运行 `cargo test -p agentdeck-protocol --test relay_v2_contract`、`cargo test -p agentdeck-protocol --test relay_v2_neutrality`、`cargo test -p agentdeck-protocol --test e2ee_canonical_contract`。 Expected: Relay outer与endpoint E2EE snapshot彼此独立且PASS；旧IPC/Relay v1测试仍绿。
- [ ] Step 5: 运行 `cargo fmt --all --check`、`git diff --check`。
- [ ] Step 6: 提交。 `git add agentdeck-protocol protocol/agentdeck/relay-v2.schema.json protocol/agentdeck/e2ee-v1.schema.json && git commit -m "feat(protocol): 定义 Relay v2 与 E2EE 契约"`

### Task P1.3：拆分 IPC/Runtime/Relay/E2EE schema CLI

**Files:**
- Create: `agentdeck-cli/tests/protocol_schema_exports.rs`
- Modify: `agentdeck-cli/src/{main,commands}.rs`
- Modify: `agentdeck-protocol/src/lib.rs`
- Modify: `protocol/agentdeck/agentdeck-protocol.schema.json`
- Modify: `protocol/agentdeck/README.md`

- [ ] Step 1: 写CLI integration test。 分别执行`agentdeck protocol schema|runtime-schema|relay-schema|e2ee-schema`，断言stdout与四份snapshot byte-identical，并断言命令不尝试spawn daemon。
- [ ] Step 2: 运行 `cargo test -p agentdeck-cli --test protocol_schema_exports`。 Expected: FAIL，三个新subcommand尚不存在。
- [ ] Step 3: 把protocol command dispatch移到构造`Client`之前；四个subcommand直接调用各自schema函数。 从aggregate IPC schema删除Relay v1 entries但`PROTOCOL_VERSION`保持2；运行`UPDATE_SCHEMA=1 cargo test -p agentdeck-protocol schema_matches_committed_snapshot`更新IPC快照。
- [ ] Step 4: 分别运行 `cargo run -q -p agentdeck-cli -- protocol schema | diff - protocol/agentdeck/agentdeck-protocol.schema.json`、`cargo run -q -p agentdeck-cli -- protocol runtime-schema | diff - protocol/agentdeck/runtime-protocol.schema.json`、`cargo run -q -p agentdeck-cli -- protocol relay-schema | diff - protocol/agentdeck/relay-v2.schema.json`、`cargo run -q -p agentdeck-cli -- protocol e2ee-schema | diff - protocol/agentdeck/e2ee-v1.schema.json`，再运行integration test。 Expected: 全部exit 0。
- [ ] Step 5: 更新 `protocol/agentdeck/README.md` 的版本轴和 regeneration 命令；运行 docs gate。
- [ ] Step 6: 提交。 `git add agentdeck-cli agentdeck-protocol protocol/agentdeck && git commit -m "feat(cli): 拆分四层协议 schema 导出"`

### Task P1.4：建立 Rust canonical/signature/HPKE/AEAD crate

**Files:**
- Create: `agentdeck-crypto/Cargo.toml`
- Create: `agentdeck-crypto/src/{lib,error,canonical,signature,hpke,aead,sealed_blob}.rs`
- Create: `agentdeck-crypto/tests/golden_vectors.rs`
- Create: `protocol/agentdeck/crypto-vectors-v1.json`
- Modify: `Cargo.toml`, `Cargo.lock`

**Core interface:**
```rust
pub fn sign_tbs(key: &SigningKey, tbs: &ToBeSignedV1) -> SignatureBytes;
pub fn verify_tbs(key: &VerifyingKey, tbs: &ToBeSignedV1, signature: &SignatureBytes) -> Result<(), CryptoError>;
pub fn hpke_seal_base<R: hpke::rand_core::CryptoRng>(recipient: &HpkePublicKey, info: &[u8], aad: &[u8], plaintext: &[u8], rng: &mut R) -> Result<HpkeEnvelopeV1, CryptoError>;
pub fn hpke_open_base(recipient: &HpkePrivateKey, info: &[u8], aad: &[u8], envelope: &HpkeEnvelopeV1) -> Result<Vec<u8>, CryptoError>;
pub struct AeadSendingKey { pub key_id: KeyId, pub epoch: u64, pub nonce_prefix: [u8; 4], key: SecretAeadKey }
pub fn seal_symmetric(key: &AeadSendingKey, context: &OuterContextV1, plaintext: &[u8], counter: SenderCounter) -> Result<UnsignedSealedBlobV1, CryptoError>;
pub fn sign_sealed(blob: UnsignedSealedBlobV1, key: &SigningKey, context: &OuterContextV1) -> SignedSealedBlobV1;
pub fn verify_sealed(blob: SignedSealedBlobV1, key: &VerifyingKey, context: &OuterContextV1) -> Result<VerifiedSealedBlobV1, CryptoError>;
pub fn open_symmetric(key: &AeadReceivingKey, context: &OuterContextV1, blob: VerifiedSealedBlobV1) -> Result<Vec<u8>, CryptoError>;
```

- [ ] Step 1: 写fixed-seed golden tests。 固化长度前缀canonical bytes、SHA-256结果、Ed25519、HPKE Base、AEAD ciphertext/tag；nonce逐字节固定为`32-bit prefix || 64-bit big-endian counter`；复用prefix+counter、tamper任一路由/version/epoch/counter/hash/AAD或sender signature必须失败。
- [ ] Step 2: 运行 `cargo test -p agentdeck-crypto --test golden_vectors`。 Expected: FAIL，workspace member 不存在。
- [ ] Step 3: 新建crate，依赖方向固定为`agentdeck-crypto -> agentdeck-protocol`；HPKE固定为`hpke = { version = "0.14", default-features = false, features = ["alloc", "getrandom", "x25519", "chacha"] }`，测试RNG实现该crate重导出的`rand_core` trait；允许HPKE与Ed25519依赖各自兼容的sha2底层版本，但禁止第二套HPKE/AEAD高层实现；所有secret wrapper zeroize-on-drop且Debug不输出材料。
- [ ] Step 4: 运行 golden test 与 `cargo tree -p agentdeck-crypto`。 Expected: vectors PASS；不存在第二套 HPKE/AEAD 实现。
- [ ] Step 5: 运行 `cargo fmt --all --check`、`cargo clippy -p agentdeck-crypto --all-targets -- -D warnings`。
- [ ] Step 6: 提交。 `git add Cargo.toml Cargo.lock agentdeck-crypto protocol/agentdeck/crypto-vectors-v1.json && git commit -m "feat(crypto): 固化 Relay E2EE canonical 与密码套件"`

### Task P1.5：实现 crash-safe counter 与 replay window 纯状态机

**Files:**
- Create: `agentdeck-crypto/src/{counter,replay}.rs`
- Create: `agentdeck-crypto/tests/{counter_recovery,replay_window}.rs`
- Modify: `agentdeck-crypto/src/lib.rs`

**Core interface:**
```rust
pub struct CounterReservation { pub start: u64, pub end_exclusive: u64 }
pub enum CounterReconcile { Usable(CounterReservation), DbRollback, EpochRetirementRequired }
pub enum ReplayDisposition { Fresh, ExactDuplicate, Stale }
pub struct ReplayWindow { high_water: Option<u64>, floor: u64, hashes: BTreeMap<u64, [u8; 32]> }
impl ReplayWindow { pub fn observe(&mut self, counter: u64, ciphertext_hash: [u8; 32]) -> Result<ReplayDisposition, CryptoError>; }
```

- [ ] Step 1: 写 block=1,024、near-u64-max、Keychain ahead/behind、window=4,096、exact duplicate、same counter/different hash、below-floor tests。
- [ ] Step 2: 运行 `cargo test -p agentdeck-crypto --test counter_recovery --test replay_window`。 Expected: FAIL，module 不存在。
- [ ] Step 3: 实现无 IO 的 deterministic state machines。 `NonceReuse` 只对窗口内同 counter 不同 hash；低于 floor 返回 `Stale`；DB 小于 guard 返回 `DbRollback`，不能产生可用 counter。
- [ ] Step 4: 重跑两套 tests。 Expected: 全部 PASS，proptest/边界循环不 panic。
- [ ] Step 5: 运行 crypto crate clippy 与 fmt。
- [ ] Step 6: 提交。 `git add agentdeck-crypto && git commit -m "feat(crypto): 加入 counter guard 与 replay window 状态机"`

### Task P1.6：建立 CryptoKit mirror 与 Rust↔Swift 互操作门禁

**Files:**
- Modify: `Package.swift`
- Create: `Sources/AgentDeckRelayClient/Crypto/{CanonicalCodec,RelayCrypto}.swift`
- Create: `Tests/AgentDeckRelayClientTests/RelayCryptoVectorTests.swift`
- Create: `agentdeck-crypto/examples/hpke_probe.rs`
- Create: `scripts/verify-cross-language-crypto.sh`

**Swift interface:**
```swift
public enum RelayCrypto {
    public static func openHPKE(_ envelope: HPKEEnvelopeV1, recipient: Curve25519.KeyAgreement.PrivateKey, info: Data, aad: Data) throws -> Data
    public static func sealHPKE(_ plaintext: Data, recipient: Curve25519.KeyAgreement.PublicKey, info: Data, aad: Data) throws -> HPKEEnvelopeV1
    public static func sealSymmetric(_ plaintext: Data, key: AeadSendingKey, context: OuterContextV1, counter: UInt64) throws -> UnsignedSealedBlobV1
    public static func signSealed(_ blob: UnsignedSealedBlobV1, key: Curve25519.Signing.PrivateKey, context: OuterContextV1) throws -> SignedSealedBlobV1
    public static func verifySealed(_ blob: SignedSealedBlobV1, key: Curve25519.Signing.PublicKey, context: OuterContextV1) throws -> VerifiedSealedBlobV1
    public static func openSymmetric(_ blob: VerifiedSealedBlobV1, key: AeadReceivingKey, context: OuterContextV1) throws -> Data
    public static func sign(_ tbs: ToBeSignedV1, key: Curve25519.Signing.PrivateKey) throws -> Data
    public static func verify(_ signature: Data, tbs: ToBeSignedV1, key: Curve25519.Signing.PublicKey) -> Bool
}
```

- [ ] Step 1: 写 Swift tests 读取同一 `crypto-vectors-v1.json`。 固定向量覆盖 canonical/TBS/AAD/signature/ChaChaPoly 与 Rust fixed HPKE→Swift open；动态 test 启动 `hpke_probe`，由 Rust 生成 recipient，Swift seal，Rust open 回显 plaintext。
- [ ] Step 2: 运行 `swift test --filter RelayCryptoVectorTests`。 Expected: FAIL，target 与类型不存在。
- [ ] Step 3: 在 Package 增加 `AgentDeckRelayClient` library/test target的最小 Crypto 部分；使用 `HPKE.Ciphersuite.Curve25519_SHA256_ChachaPoly`，不伪造可注入 RNG 的 Swift API。
- [ ] Step 4: 运行 `bash scripts/verify-cross-language-crypto.sh`、`swift test --filter RelayCryptoVectorTests`、`cargo test -p agentdeck-crypto`。 Expected: 固定与动态双向门禁全部 PASS。
- [ ] Step 5: 运行完整 `swift test` 与 `cargo test`，确认旧 v1 默认路径无回归。
- [ ] Step 6: 提交。 `git add Package.swift Sources/AgentDeckRelayClient Tests/AgentDeckRelayClientTests agentdeck-crypto scripts/verify-cross-language-crypto.sh && git commit -m "feat(swift): 建立 CryptoKit 与 Rust E2EE 互操作门禁"`

### Task P1.7：建立 Swift Runtime v1 与 Relay v2 wire mirror

**Files:**
- Create: `Sources/AgentDeckCore/Protocol/RuntimeV1Types.swift`
- Create: `Sources/AgentDeckRelayClient/Wire/RelayV2Types.swift`
- Create: `Tests/AgentDeckTests/RuntimeV1ProtocolTests.swift`
- Create: `Tests/AgentDeckRelayClientTests/RelayV2WireTests.swift`
- Create: `protocol/agentdeck/fixtures/runtime-v1-wire.jsonl`
- Create: `protocol/agentdeck/fixtures/relay-v2-wire-vectors.json`
- Modify: `agentdeck-protocol/tests/{runtime_v1_contract,relay_v2_contract}.rs`

- [ ] Step 1: 让Rust tests在`UPDATE_WIRE_FIXTURES=1`时生成fixture，默认只比较已提交内容；Runtime JSONL覆盖stable IDs/receipts/snapshot/transfer，Relay vector JSON记录每个outer family的input字段与`RelayWireCodecV2`期望hex bytes，并逐变体覆盖PairInvite/PairRequest/PairResponse/DeviceAuthorization/KeyDirectory/KeyUpdate/EpochBarrier/SealedPayload；Swift mirror扫描禁止业务字段和vendor resume reference。
- [ ] Step 2: 运行 `swift test --filter RuntimeV1ProtocolTests` 与 `swift test --filter RelayV2WireTests`。 Expected: FAIL，Swift mirror不存在。
- [ ] Step 3: 在AgentDeckCore手写中立Runtime Codable/Sendable mirror，在AgentDeckRelayClient手写opaque Relay mirror；字段名与deny-unknown行为以Rust fixtures为准。 不在Swift定义vendor resume reference，不把CryptoKit类型放进AgentDeckCore。
- [ ] Step 4: 运行Rust fixture producers和两套Swift tests，再用`git diff --exit-code protocol/agentdeck/fixtures`检查稳定性。 Expected: Runtime decode→normalized JSON语义等价，Relay binary codec与canonical TBS/AAD逐字节一致，fixture无漂移。
- [ ] Step 5: 运行 `swift test`、`cargo test -p agentdeck-protocol`。
- [ ] Step 6: 提交。 `git add Sources Tests agentdeck-protocol protocol/agentdeck/fixtures && git commit -m "feat(protocol): 对齐 Swift Runtime 与 Relay v2 wire"`

---

## Phase P2：Relay v2 原子 cutover

### Task P2.1：实现 Relay v2 SQLite store actor、migration 与配额事务

**Files:**
- Create: `agentdeck-relay/src/v2/mod.rs`
- Create: `agentdeck-relay/src/v2/store/{mod,migrations,model,sqlite,worker}.rs`
- Create: `agentdeck-relay/tests/relay_v2_store.rs`
- Modify: `agentdeck-relay/src/{lib,config}.rs`
- Modify: `agentdeck-relay/Cargo.toml`

**Core interface:**
```rust
pub struct RelayStoreHandle { tx: mpsc::Sender<StoreCommand> }
impl RelayStoreHandle {
    pub async fn register_machine(&self, request: RegisterMachine) -> Result<MachineRecord, StoreError>;
    pub async fn install_grant(&self, request: InstallGrantRecord) -> Result<GrantCommit, StoreError>;
    pub async fn register_stream(&self, request: StreamRegistration) -> Result<StreamRecord, StoreError>;
    pub async fn publish(&self, request: PersistPublish) -> Result<PublishCommit, StoreError>;
    pub async fn subscribe(&self, request: PersistSubscription) -> Result<SubscriptionLease, StoreError>;
    pub async fn replay_page(&self, request: ReplayPageRequest) -> Result<ReplayPage, StoreError>;
    pub async fn ack(&self, request: PersistAck) -> Result<(), StoreError>;
    pub async fn revoke(&self, request: PersistRevocation) -> Result<RevocationCommit, StoreError>;
    pub async fn purge_machine(&self, request: PurgeMachine) -> Result<PurgeReadback, StoreError>;
}
```

**SQLite schema:** `relay_meta`、`machine_routes`、`device_grants`、`revocations`、`streams`、`frames`、`subscriptions`、`enrollment_codes`；后者除code hash/expiry/consumed外还保存首次成功请求的`request_hash`与冻结`response_blob/receipt_hash`，用于COMMIT后响应丢失的同请求幂等取回。字段逐项采用设计§11.1，`received_at`/`size`只由Relay计算，`sealed_blob`原样保存，challenge/PairRoute/active writer不落盘。

- [ ] Step 1: 写store integration tests。 覆盖fresh migration、higher schema reject、legacy schema签名触发reset、0700/0600、WAL/FULL/FK/5s、stream HWM=-1、第一帧0、duplicate-same/conflict、COMMIT fault、restart byte-identical sealedBlob、count/bytes/time/machine/global/disk-low cap；`replay_page`每页最多64 frames/8MiB并用opaque cursor继续，禁止一次物化64MiB retention。
- [ ] Step 2: 运行 `cargo test -p agentdeck-relay --features server --test relay_v2_store -- --test-threads=1`。 Expected: FAIL，`v2::store` 不存在。
- [ ] Step 3: 实现单 blocking worker 独占 `rusqlite::Connection`。 `publish` 在一个 `BEGIN IMMEDIATE` 中完成 generation/seq/hash 校验、insert、HWM/bytes、retention；所有方法返回 Result，禁止 `expect`/panic/eprintln-then-continue。
- [ ] Step 4: 重跑 store test并用 `rg -n 'expect\(|unwrap\(' agentdeck-relay/src/v2/store` 人工复核。 Expected: tests PASS；生产 store 不含无解释的 panic path。
- [ ] Step 5: 更新 `docs/AGENT_DIAGNOSTICS.md` 的 v2 store failure codes；运行 docs gate。
- [ ] Step 6: 提交。 `git add agentdeck-relay docs/AGENT_DIAGNOSTICS.md && git commit -m "feat(relay): 建立 v2 SQLite store actor"`

### Task P2.2：实现 challenge、MachineLink/DeviceLink 鉴权与单调防回退

**Files:**
- Create: `agentdeck-relay/src/v2/auth/{mod,challenge,access,verify}.rs`
- Create: `agentdeck-relay/tests/relay_v2_auth_e2e.rs`
- Modify: `agentdeck-relay/src/v2/mod.rs`

**Core interface:**
```rust
pub enum AccessContext { Machine(MachineAccess), Device(DeviceAccess), Pairing(PairingAccess) }
pub struct ChallengeRegistry { /* 30s TTL, 4,096 global, one-shot */ }
pub fn verify_authentication(frame: Authenticate, challenge: ConsumedChallenge, store: &MachineTrustView) -> Result<AccessContext, RelayFailure>;
pub fn authorize_pairing_route(hello: PairingHello, routes: &PairRouteView) -> Result<PairingAccess, RelayFailure>;
```

- [ ] Step 1: 写challenge/auth tests。 覆盖replay、30s expiry、并发双消费、capacity/token bucket、connection/server/version/route/serial/cert hash transcript binding、同serial同hash幂等、同serial异hash、较低generation、cross-machine grant、revoked tombstone；未配对设备只能凭active pairRoute建立受TTL/rate限制的`PairingAccess`，且只能发送PairData/ClosePairRoute。
- [ ] Step 2: 运行 auth e2e。 Expected: FAIL，auth v2 module 不存在。
- [ ] Step 3: 实现内存 challenge registry、root/link/device 验签、持久最高 generation/serial gate和单 active generation CAS。 active connection replacement 只在新鉴权完全通过后发生。
- [ ] Step 4: 重跑 auth e2e。 Expected: 所有恶意输入返回固定 `relay.auth.*`/`relay.route.*` code，不泄漏验签细节。
- [ ] Step 5: 运行 `cargo clippy -p agentdeck-relay --features server --all-targets -- -D warnings`。
- [ ] Step 6: 提交。 `git add agentdeck-relay && git commit -m "feat(relay): 加入 v2 challenge 与单调授权校验"`

### Task P2.3：实现 stream router、replay、ACK/gap 与慢 writer 隔离

**Files:**
- Create: `agentdeck-relay/src/v2/core/{mod,router,connection,writer,lifecycle,replay}.rs`
- Create: `agentdeck-relay/tests/relay_v2_stream_e2e.rs`
- Modify: `agentdeck-relay/src/v2/{mod,store/{model,sqlite}}.rs`
- Modify: `agentdeck-protocol/src/relay_v2/failure.rs`

**Core interface:**
```rust
impl RelayCore { pub async fn handle(&self, access: &AccessContext, frame: OpaqueRouteFrame) -> Result<RouteOutcome, RelayFailure>; }
pub enum RouteOutcome { Applied, Queued(RouteAccepted), Replay(ReplayTicket), Gap(Gap), Closed }
pub struct ReplayTicket { pub stream: StreamRouteId, pub generation: StreamGenerationId, pub next: StreamCursor, pub terminal: StreamCursor }
```

- [x] Step 1: 写stream tests。 覆盖random route/generation ownership、BeforeFirst→0、独立streamSeq、接近u64上界必须新generation且禁止wrap、out-of-order、persist-before-fanout、Subscribe/Unsubscribe幂等且Unsubscribe不阻塞trim、monotonic ACK、grant renewal不继承旧serial ACK lease、gap pauses live、reconnect resume、512 frames/16MiB writer、slow writer只断自己、heartbeat20s/60s与disconnect cleanup；补充tiny writer、Store page clamp、WorkerBusy、hot-stream公平轮转、聚合normal/control预算、origin acceptance优先、replay transition-fence race、metadata count/disk/startup preflight与actor Drop guard。
- [x] Step 2: 运行 stream e2e。 Expected: FAIL，core module 不存在。已保留红测阶段证据，并逐项转绿。
- [x] Step 3: 实现actor core与bounded writer。 Core只能`try_send`且不得await socket；replay由connection actor按writer/Store/协议三重上限从Store游标分页拉取，每批最多64 frames/8MiB，最后一批成功入队后异步取得control reserve再发ReplayComplete；Store COMMIT后先origin RouteAccepted再fan-out；gap后禁止投递更高seq，直到客户端完成backfill/snapshot并以同generation/cursor幂等re-Subscribe。所有连接共享有界normal/control预算，stream/subscription metadata同时受principal/global count与disk growth gate约束。
- [x] Step 4: 重跑 stream e2e与 store COMMIT fault test。 Expected: PASS，fault 时没有观察到 frame。已覆盖全量Store/Auth/Protocol回归与stream E2E重复运行。
- [x] Step 5: 运行 fmt/clippy。focused production clippy、rustdoc、panic scan、docs gate与diff check均纳入P2.3门禁。
- [x] Step 6: 提交。 `git add agentdeck-relay && git commit -m "feat(relay): 实现 v2 stream replay 与慢连接隔离"`

### Task P2.4：实现 PairRoute 与在线 Send/Reply

**Files:**
- Create: `agentdeck-relay/src/v2/core/{pair_route,request_route}.rs`
- Create: `agentdeck-relay/tests/relay_v2_route_e2e.rs`
- Modify: `agentdeck-relay/src/v2/{auth/{access,coordinator},core/{connection,mod,router},store/worker}.rs`
- Modify: `agentdeck-relay/tests/relay_v2_store.rs`

- [x] Step 1: 写routing tests。只有MachineAccess能OpenPairRoute；Open固定absolute expiry，同machine/route/expiry逐字相同幂等ACK，owner或expiry不同冲突；Close对同owner及已不存在route幂等返回Closed/AlreadyAbsent，不同active owner拒绝。PairingAccess只能访问邀请中的active route并发送PairData/ClosePairRoute，越权Subscribe/Send/Publish全部拒绝；PairRoute覆盖每machine8、全局1,024、32 frames/1MiB/5m、token bucket、Relay重启丢内存态后重开、daemon重启但Relay未重启时重复Open、未知route、过期与两端close；Send/Reply覆盖active writer、machine/device trust-domain binding、offline、disconnect reply loss、requestRoute伪造和RouteAccepted不持久化/不代表端侧收到。补充 target/origin writer 背压、pairing Close ACK 丢失重试、biased actor-order close/expiry race、stale replacement 与双主体 transition fence。
- [x] Step 2: 运行 route e2e。 Expected: FAIL，frame family 尚未 dispatch。已保留 `pair_route_view` 缺失与 terminal Close retry 被 active validator 拦截的红测证据，并逐项转绿。
- [x] Step 3: 实现内存有界且Open/Close幂等的 PairRoute，以及显式 deviceRoute/requestRoute 在线路由。PairRoute record固定owner与absolute expiry；重复Open不延长TTL，Close unknown返回AlreadyAbsent。删除 v2 中 `req_origin` 概念；Send/Reply 不进入 frames 表，不改变 stream HWM。所有 machine mutation/enqueue 与 current generation 同锁线性化；Send/Reply 同时验证 origin+target，PairData 使用 canonical bytes 两阶段预算。
- [x] Step 4: 重跑 route e2e并查询 test DB。 Expected: PASS；`frames`/`subscriptions` 不含 request/reply payload。已用非空 stream/HWM sentinel、同一 read-only connection 的 `PRAGMA data_version` 与八表语义快照证明 PairRoute/PairData/Send/Reply 零 SQLite commit；route E2E 10/10 case 全绿。
- [x] Step 5: 运行 fmt/clippy。focused production clippy、rustdoc、panic scan、全量 Relay/Auth/Store/Protocol 回归、route E2E 10 轮、docs gate 与 diff check 纳入 P2.4 门禁。
- [x] Step 6: 提交。 `git add agentdeck-relay README.md ARCHITECTURE.md docs && git commit -m "feat(relay): 实现 PairRoute 与在线 request reply"`

### Task P2.5：实现 grant install、revoke terminal、RetireMachine 与 purge readback

**Files:**
- Create: `agentdeck-relay/src/v2/core/revocation.rs`
- Create: `agentdeck-relay/tests/relay_v2_revocation_e2e.rs`
- Create: `agentdeck-protocol/tests/relay_v2_revocation_canonical_contract.rs`
- Modify: `agentdeck-protocol/src/relay_v2/{auth,frame,codec}.rs` 与 Relay v2 schema/golden
- Modify: `Sources/AgentDeckRelayClient/Wire/RelayV2Types.swift` 与 Swift wire tests
- Modify: `agentdeck-relay/src/v2/{auth/{access,coordinator,verify},core/{mod,router,connection,writer},store/{migrations,model,sqlite,worker}}.rs`

- [x] Step 1: 写 revocation tests。覆盖真实 root-signed InstallGrant/Revoke/Retire、COMMIT fault、same hash retry/serial rollback、普通/control queue 丢弃、独立 terminal、2s close、SQLite reopen后 terminal-only鉴权、target-only purge/readback与 PairRoute清理；另补 canonical/TBS、29种wire与Swift mirror。
- [x] Step 2: 运行 revocation e2e。红态先固定在缺少 `RelayCore::activate_authentication`/revoke dispatch；实现前 protocol canonical测试也精确红在缺 API/variant。
- [x] Step 3: 实现事务顺序与 terminal slot。origin current检查和 target/整机 transition同锁；COMMIT 后才失效 generation。terminal使用每writer单槽与全局4,096 frames/16MiB独立预算，普通Invalidated跳过，flush或2s关闭。
- [x] Step 4: 重跑测试并重开 SQLite。合法旧 DeviceSign/MachineLink proof分别逐字节重放 `RevocationCommitted`/`RetirementCommitted` 且不建立 active generation；purge 在 COMMIT 前按冻结 stream keys、foreign-key check与 exact terminal完成事务内 `0/1/0/0/0/0/0` 读回，COMMIT 后回执丢失用同 canonical request幂等恢复，SQLite reopen再次验证。
- [x] Step 5: 运行 store/core clippy。`agentdeck-relay --features server` 全量、Revocation E2E 11 cases连续10轮、Protocol全量、Swift RelayV2Wire 14/14、focused clippy/rustdoc/fmt/schema/docs/daemon-no-net/diff均通过；独立 security/core/test复审发现的 raw bypass、COMMIT-unknown、purge假读回、terminal伪造/ABA/双份内存与metadata测试缺口已全部闭环。
- [x] Step 6: 提交。按完整 scoped path stage protocol、Swift mirror、Relay、fixtures/schema 与 docs，并以 `feat(relay): 闭环 v2 revoke 与 machine purge` 收口；未包含构建产物、运行数据或本地 SDD ledger。

### Task P2.6：实现 TLS fail-closed、server lifecycle、health/readiness 与 redacted telemetry

**Files:**
- Create: `agentdeck-relay/src/v2/server/{mod,tls,health,connection,preupgrade}.rs`
- Create: `agentdeck-relay/tests/{relay_v2_config,relay_v2_tls_e2e,relay_v2_lifecycle_e2e}.rs`
- Create: `agentdeck-relay/tests/fixtures/relay-selfcheck.toml`
- Modify: `agentdeck-relay/src/{config,v2/mod}.rs`
- Modify: `agentdeck-relay/src/v2/{auth/coordinator,core/{router,writer},store/{sqlite,worker}}.rs`
- Modify: `agentdeck-relay/Cargo.toml`
- Modify: `agentdeck-protocol/src/relay_v2/{frame,codec,mod}.rs`、Relay v2 schema/golden/contract
- Modify: `Sources/AgentDeckRelayClient/Wire/RelayV2Types.swift` 与 Swift wire tests
- Modify: `README.md`、`ARCHITECTURE.md`、`docs/{QUALITY,AGENT_DIAGNOSTICS,index}.md`

- [x] Step 1: 写config/TLS/lifecycle tests。覆盖 CLI>env>TOML>defaults、全部 Store tunable、非loopback无TLS、TLS feature缺失、cert/key不匹配、相对storage、明文显式opt-in、proxy loopback、固定public path无redirect/query carrier、真实SIGTERM子进程、pre-upgrade deadline/header/物理连接上界、1,024普通HTTP keep-alive饱和恢复、slow partial HTTP drain、真实proxy source header、loopback health/readiness、disk-low、handle Drop与日志sentinel；另补 Auth/Core drain fence、Store shutdown回执顺序和真实OS子进程Store lock。
- [x] Step 2: 运行红测。旧实现精确失败于 `/v2/pair` 404/query pairing carrier、TLS feature fallback/配置门禁、缺少readiness/lifecycle与进程锁；PairingHello contract先红在缺variant/kind，auth/core测试先红在缺drain API；最终资源回归在1,024个完整非升级keep-alive后精确红于第1,025个合法WS超时。保留先红后绿证据。
- [x] Step 3: 实现并列的v2 WS server library。WS只接受canonical binary v2，listener/codec前4MiB拒绝oversize/text；direct TLS在bind/DB前校验且不fallback，明文/代理仅显式loopback；公开TCP受1,024物理连接、5s accept→成功101 deadline和64KiB header上界约束，只有101解除deadline并让permit穿过upgrade，非101强制close；可信proxy必须覆写单个canonical source IP。用`CancellationToken + JoinSet`管理tasks。固定 `/v2/connect` 与 `/v2/pair`，PairRoute只由TLS后kind29 `PairingHello`携带；Auth/Core FIFO drain、cached readiness、60s maintenance、zero-copy writer和OS process lock均闭环。此task不切换binary默认listener。
- [x] Step 4: TLS E2E 10/10、lifecycle 5/5、pre-upgrade 3/3、config三feature矩阵、Store 101/101、Auth 25/25、Route 12/12及 `server`/`server,tls` 全量通过。selfcheck直接消费fixture相对cert/key，真实打开绝对临时DB、迁移/readiness/Core，并用同一套Store配置shutdown/reopen；真实SIGTERM、正常运行慢header deadline、完整普通HTTP饱和恢复与5s forced drain后DB均可立即重开。binary默认切换仍留到P2.9。
- [x] Step 5: 日志positive-event sentinel零敏感命中；TLS E2E串行10轮+默认并行10轮（共200 case）全绿。P0总门禁、Protocol全量、Swift RelayV2Wire 15/15与client 23/23、full Rust两套feature、focused clippy/rustdoc/rustfmt、四份schema diff、docs gate、daemon-no-net与diff check全部通过。独立复审发现的Store锁回执顺序、Core错误清理、proxy来源隔离、pre-upgrade Slowloris、普通HTTP keep-alive占满permit与selfcheck配置漂移均已逐项red→green闭环；最终质量复审无P0/P1。
- [x] Step 6: 已精确暂存本task的 Relay、protocol/schema、Swift wire、依赖锁和文档改动并提交为 `4764f8c feat(relay): 强制 v2 TLS 与可控服务生命周期`；未包含构建产物、运行数据或本地 SDD ledger。

### Task P2.7：实现本机 admin UDS、enrollment bundle 与 purge CLI

**Files:**
- Create: `agentdeck-relay/src/v2/admin/{mod,protocol,server,client,command}.rs`
- Create: `agentdeck-relay/src/v2/server/enrollment.rs`
- Create: `agentdeck-relay/tests/relay_v2_admin_e2e.rs`
- Create: `docs/RELAY_RUNBOOK.md`
- Modify: `agentdeck-relay/src/{main,config}.rs`
- Modify: `agentdeck-relay/src/v2/store/{model,sqlite}.rs`

**Admin commands:** `machine-enroll create`、`machine inventory`、`machine purge --confirm ROOT_FINGERPRINT`、`machine readback`；admin socket只允许 Relay host 本地 0600，同 UID/配置 owner。

- [x] Step 1: 已写admin/enrollment tests。覆盖0600 socket/同UID gate、256-bit code hash-only/5m bundle/one-shot race、current leaf SPKI；真实TLS `POST /v2/machine-enroll` 的64KiB/no redirect、签名与endpoint key先验、同请求exact replay/不同请求冲突；错误fingerprint同时拒readback/purge，另有persistent COMMIT-unknown整Core fail-closed。
- [x] Step 2: 已保留RED证据：canonical request、inventory/readback/purge API与admin模块缺失时分别编译失败；真实E2E在实现前不存在target。
- [x] Step 3: 已实现bounded admin JSONL、同binary四组client subcommand和TLS enrollment endpoint。code只在CLI stdout响应；公网不提供inventory/readback/purge，DirectTLS第一pin在DB/bind前与leaf DER SPKI比对。
- [x] Step 4: admin TLS E2E 2/2与Core uncertain purge focused case通过；坏签名/公钥不消费code、并发双消费1胜1拒、SQLite只读hash、逐字节响应与网络admin path 404均有断言。Store/admin DTO自定义Debug脱敏，日志路径只记录typed code/计数。
- [x] Step 5: 已新增 `docs/RELAY_RUNBOOK.md`，并同步README、文档索引、诊断和质量门禁；只记录实际通过的本机命令与P2.9尚未cutover边界。
- [ ] Step 6: 提交。 `git add agentdeck-relay docs/RELAY_RUNBOOK.md && git commit -m "feat(relay): 加入本机管理面与 machine enrollment"`

### Task P2.8：重写 Rust Relay client 为 v2 WSS/pin client

**Files:**
- Create: `agentdeck-relay-client/src/v2/{mod,transport,connection,tls}.rs`
- Create: `agentdeck-relay-client/tests/relay_v2_client.rs`
- Modify: `agentdeck-relay-client/src/lib.rs`
- Modify: `agentdeck-relay-client/Cargo.toml`

**Core interface:**
```rust
impl RelayClient {
    pub async fn connect(config: RelayClientConfig, auth: Arc<dyn LinkAuthenticator>) -> Result<Self, RelayClientError>;
    pub async fn send(&self, frame: OpaqueRouteFrame) -> Result<(), RelayClientError>;
    pub async fn recv(&mut self) -> Result<Option<OpaqueRouteFrame>, RelayClientError>;
    pub async fn reconnect_and_authenticate(&mut self) -> Result<(), RelayClientError>;
}
impl RelayEnrollmentClient { pub async fn enroll_machine(config: EnrollmentClientConfig, request: MachineEnrollmentRequestV1) -> Result<MachineEnrollmentResponseV1, RelayClientError>; }
impl RelayPairingClient {
    pub async fn connect_pairing(config: RelayClientConfig, hello: PairingHello) -> Result<Self, RelayClientError>;
    pub async fn send_pair_data(&self, frame: PairData) -> Result<(), RelayClientError>;
    pub async fn recv_pair_data(&mut self) -> Result<Option<PairData>, RelayClientError>;
    pub async fn close_pair_route(&self, frame: ClosePairRoute) -> Result<(), RelayClientError>;
}
```

- [ ] Step 1: 写client tests。 覆盖WSS CA/pin/fixed-host、binary frame、reconnect/auth与errors；enrollment client在发送code/root material前完成TLS验证。 未配对设备的RelayPairingClient只暴露指定pair route的PairData/ClosePairRoute typed API，尝试Subscribe/Send/Publish在编译接口上不可表达且恶意raw frame在server端拒绝。
- [ ] Step 2: 运行 `cargo test -p agentdeck-relay-client --test relay_v2_client`。 Expected: FAIL，client仍是 bearer v1。
- [ ] Step 3: 实现纯client crate并移除对`agentdeck-relay`的生产依赖。 WS只发送/接收binary codec；已授权RelayClient、one-shot EnrollmentClient和受限RelayPairingClient共享同一rustls verifier/fixed-host policy，但API与connection state互不冒充。
- [ ] Step 4: 重跑 client与 Relay TLS tests。 Expected: PASS，`cargo tree -p agentdeck-relay-client` 不含 axum/rusqlite/agentdeck-relay。
- [ ] Step 5: fmt/clippy。
- [ ] Step 6: 提交。 `git add agentdeck-relay-client Cargo.lock && git commit -m "feat(relay-client): 切换 v2 WSS 与 SPKI pin"`

### Task P2.9：原子切换 binary/CLI synthetic tests 并删除 Relay v1 生产代码

**Files:**
- Modify: `agentdeck-cli/src/{main,remote}.rs`, `agentdeck-cli/Cargo.toml`
- Modify: `agentdeck-protocol/src/lib.rs`, `agentdeck-protocol/src/neutrality_tests.rs`, `agentdeck-protocol/Cargo.toml`
- Modify: `agentdeck-relay/src/{lib,main,config}.rs`, `agentdeck-relay/Cargo.toml`
- Modify: `agentdeck-relay-client/src/lib.rs`, `agentdeck-relay-client/Cargo.toml`
- Modify: `agentdeckd/Cargo.toml`
- Modify: `Cargo.lock`
- Delete: `agentdeck-protocol/src/remote/`
- Delete: `agentdeck-relay/src/{bridge,relay_link,router,store}.rs`
- Delete: `agentdeck-relay/src/auth/`
- Delete: `agentdeck-relay/src/server/`
- Delete: `agentdeck-relay-client/src/{ws,inproc}.rs`
- Delete: `agentdeck-relay/tests/{r0_composition,r1a_ws_e2e,r1b_hardening_e2e}.rs`
- Delete: `agentdeckd/tests/{relay_r0_bridge,relay_r0_e2e}.rs`
- Create: `agentdeck-cli/tests/remote_v2_synthetic.rs`

- [ ] Step 1: 先写 synthetic v2 CLI smoke。 用 ephemeral keys 完成 machine/device auth、register/publish/subscribe/send/reply/revoke；断言旧 bearer credential JSON、`--bootstrap-secret` 与 v1 wire都返回 typed unsupported/reset-required。
- [ ] Step 2: 运行 synthetic test。 Expected: FAIL，CLI仍调用 v1 API。
- [ ] Step 3: 切CLI与Relay binary/config/dependencies默认dispatch到v2，清除bootstrap/bearer/plaintext/req_origin配置并删除上述v1代码和测试。 P2 CLI只支持ephemeral synthetic device、受限pairing smoke与admin；persistent remote pair在P4前typed unsupported。
- [ ] Step 4: 运行 `cargo test`、四份schema diff和 `rg -n 'DataEnvelope::Plaintext|bootstrap_secret|RelayCredentials|FakeRelay|req_origin' --glob '*.rs'`。 Expected: tests PASS；生产Rust源无命中，允许历史docs/plan命中。
- [ ] Step 5: 运行 `bash scripts/check-daemon-no-net.sh`，确认 daemon尚未引入网络。
- [ ] Step 6: 精确stage并提交。 stage上述modified files与Cargo.lock；删除项只用精确pathspec：三个old protocol/relay/client source目录、`r0_composition.rs`、`r1a_ws_e2e.rs`、`r1b_hardening_e2e.rs`、`relay_r0_bridge.rs`、`relay_r0_e2e.rs`。 核对`git diff --cached --name-status`与task Files完全相同后执行`git commit -m "feat(relay): 原子切换 Relay v2 并移除 v1 生产路径"`，不得stage整个tests目录。

### Task P2.10：Relay v2 hardening E2E、sentinel 与阶段文档收口

**Files:**
- Create: `agentdeck-relay/tests/{relay_v2_hardening_e2e,relay_v2_security_e2e}.rs`
- Modify: `scripts/verify-relay-companion-mvp.sh`
- Modify: `README.md`, `ARCHITECTURE.md`, `docs/QUALITY.md`, `docs/AGENT_DIAGNOSTICS.md`, `docs/index.md`, `AGENTS.md`
- Modify: `docs/RELAY_RUNBOOK.md`, `protocol/agentdeck/README.md`

- [ ] Step 1: 写阶段级故障/安全 tests。 覆盖 restart byte-identical replay、COMMIT前后 crash、gap/quota/disk-low、challenge race、generation/serial rollback、forged grant、cross-machine takeover、revoke terminal、slow client、SIGTERM、TLS pin；sentinel 同时作为 machine/session/prompt/output/approval/vendor ref输入，扫描 DB/log/metrics/outer frame。
- [ ] Step 2: 在文档更新前运行 `bash scripts/verify-relay-companion-mvp.sh p2`。 Expected: FAIL，脚本尚未编排新 suite或入口文档仍描述 R1b。
- [ ] Step 3: 扩展 verifier并同步所有入口文档为已落地 P2 事实；旧 R0/R1文档保留为历史，不改写成当前行为。
- [ ] Step 4: 运行：
  ```bash
  cargo test
  cargo test -p agentdeck-relay --features server,tls --test relay_v2_hardening_e2e -- --test-threads=1
  cargo test -p agentdeck-relay --features server,tls --test relay_v2_security_e2e -- --test-threads=1
  cargo test -p agentdeck-relay-client
  cargo run -p agentdeck-relay --features server,tls -- --selfcheck --config agentdeck-relay/tests/fixtures/relay-selfcheck.toml
  bash scripts/check-daemon-no-net.sh
  bash scripts/verify-relay-companion-mvp.sh p2
  scripts/verify-agent-docs.sh
  ```
  Expected: 全部 exit 0；sentinel scan 输出 `0 plaintext matches`。
- [ ] Step 5: 执行 `git status --short --branch`，移除测试 DB、证书私钥副本与日志产物。
- [ ] Step 6: 提交。 `git add README.md ARCHITECTURE.md AGENTS.md docs protocol scripts agentdeck-relay/tests && git commit -m "test(relay): 收口 v2 安全与故障门禁"`

---

## Phase P3：Singleton RuntimeCore、UDS 与 LaunchAgent

### Task P3.1：建立 stable/ephemeral namespace、singleton lock 与 StorageKEK Keychain

**Files:**
- Create: `agentdeckd/src/{config,security/mod,security/key_store,security/macos_keychain}.rs`
- Create: `agentdeckd/src/runtime/{namespace,singleton}.rs`
- Create: `agentdeckd/tests/{daemon_namespace,storage_kek}.rs`
- Modify: `agentdeckd/src/{lib,main,record}.rs`
- Modify: `agentdeckd/Cargo.toml`

**Core interface:**
```rust
pub enum DaemonMode { Stable, Ephemeral { instance_id: String } }
pub struct DaemonPaths { pub data_dir: PathBuf, pub runtime_db: PathBuf, pub socket: PathBuf, pub lock: PathBuf, pub keychain_service: String, pub keychain_access_group: Option<String> }
pub trait KeyStore: Send + Sync { fn load(&self, account: &str) -> Result<Option<SecretBytes>, KeyStoreError>; fn store(&self, account: &str, value: &SecretBytes) -> Result<(), KeyStoreError>; fn delete(&self, account: &str) -> Result<(), KeyStoreError>; }
```

**Stable paths:** data root=`~/Library/Application Support/AgentDeck`，DB=`runtime.db`，UDS=`agentdeckd.sock`，lock=`agentdeckd.lock`，Keychain service=`com.agentdeck.agentdeckd.stable`；release helper的daemon-only access group固定为签名entitlement中的`TEAMID.com.agentdeck.agentdeckd.stable`，主App/CLI不持有该entitlement；ephemeral四类路径/service都包含同一随机instance ID且位于temp namespace。

- [ ] Step 1: 写namespace/lock/Keychain tests。 固定stable路径与service；第二stable lock失败；dev未带`--ephemeral --no-remote`失败；ephemeral的DB/socket/lock/service四项全隔离；fresh namespace可生成一次`storage-kek.v1`，但已有非空Runtime DB而StorageKEK缺失时必须`StorageKeyMissing`并拒绝生成替代key；secret Debug redacted。
- [ ] Step 2: 运行 `cargo test -p agentdeckd --test daemon_namespace`。 Expected: FAIL，配置与security module不存在；实现后再单独运行`--test storage_kek`。
- [ ] Step 3: 实现路径解析、原子进程锁、memory keystore与macOS generic-password adapter。 target-specific依赖固定`security-framework = { version = "3.7", features = ["OSX_10_15"] }`；release set/get/delete调用`use_protected_keychain()`、`set_access_synchronized(Some(false))`、`set_access_group(TEAMID.com.agentdeck.agentdeckd.stable)`并使用`AccessibleAfterFirstUnlockThisDeviceOnly`且无user-presence，保证LaunchAgent无交互；ephemeral测试使用独立memory/test group，stable非macOStyped unsupported且不回退明文key file。
- [ ] Step 4: 重跑 tests并确认 Keychain测试用唯一 service/account后清理。 Expected: PASS且输出不含 key bytes。
- [ ] Step 5: 运行 `cargo fmt/clippy` 与 `git status --short`。
- [ ] Step 6: 提交。 `git add agentdeckd Cargo.lock && git commit -m "feat(daemon): 建立 singleton namespace 与 StorageKEK"`

### Task P3.2：实现 Runtime SQLite journal、稳定身份与存储上界

**Files:**
- Create: `agentdeckd/src/runtime/{model,store}.rs`
- Create: `agentdeckd/tests/runtime_store.rs`
- Modify: `agentdeckd/src/runtime/mod.rs`
- Modify: `agentdeckd/Cargo.toml`

**Core interface:**
```rust
impl RuntimeStoreHandle {
    pub async fn create_conversation(&self, input: NewConversation) -> Result<ConversationRecord, RuntimeFailure>;
    pub async fn accept_command(&self, input: AcceptCommand) -> Result<CommandReceipt, RuntimeFailure>;
    pub async fn mark_started_with_event(&self, input: StartCommand) -> Result<ExecutionIntent, RuntimeFailure>;
    pub async fn persist_execution_fence(&self, fence: ExecutionFence) -> Result<(), RuntimeFailure>;
    pub async fn complete_command_with_event(&self, input: CompleteCommand) -> Result<CommandReceipt, RuntimeFailure>;
    pub async fn load_recovery_state(&self) -> Result<RecoveryState, RuntimeFailure>;
}
```

**Runtime DB schema:** `runtime_meta`、`conversations`、`commands`、`execution_intents`、`execution_fences`、`approval_ledger`、`event_journal`、`snapshots`、`adapter_state_index`、`auth_ledger`、`stream_generations`、`publication_outbox`、`publication_acks`、`revocation_outbox`、`machine_lifecycle`、`retirement_outbox`、`key_directory`、`counter_reservations`、`receive_replay`、`pair_invites`、不经StorageKEK包装的非秘密rescue index `machine_enrollment_receipts(relay_server_id, machine_route, root_fingerprint)`；P3.3把`adapter_state_index`拆成两个adapter私有访问namespace。

- [ ] Step 1: 写store tests。 覆盖daemon先生成stable IDs，commandSeq/eventSeq/catalogRevision跨重启单调，Accepted COMMIT，conversation/admin idempotency ledger各保留30天，2GiB按main DB+WAL+SHM总和计算、512MiB或文件系统5% reserve、1,024 prompts/256MiB/24h；disk-low拒绝新副作用但继续read/ACK/revoke/diagnostics；敏感row非明文；删除全部Keychain item后仍从非秘密receipt index读old route/fingerprint且不生成新root/KEK。
- [ ] Step 2: 运行 `cargo test -p agentdeckd --test runtime_store -- --test-threads=1`。 Expected: FAIL，RuntimeStore不存在。
- [ ] Step 3: 实现专用 blocking store worker、WAL/FULL/FK/busy timeout与 StorageKEK row cipher。 `Started + ExecutionIntent + CommandStarted event` 在同一事务；所有 store failure返回 typed error。
- [ ] Step 4: 重跑 store test，并把 DB复制/重开验证 recovery。 Expected: Accepted queue/HWM/idempotency恢复；wrapped field扫描不含 sentinel。
- [ ] Step 5: fmt/clippy。
- [ ] Step 6: 提交。 `git add agentdeckd && git commit -m "feat(daemon): 建立 Runtime 持久化 journal"`

### Task P3.3：建立 adapterStateKey 私有映射并收窄 N8

**Files:**
- Create: `agentdeckd/src/runtime/adapter_state.rs`
- Create: `agentdeckd/src/codex/state.rs`
- Create: `agentdeckd/src/claude_code/state.rs`
- Create: `agentdeckd/tests/adapter_state_boundary.rs`
- Modify: `agentdeckd/src/{agent,runtime/router}.rs`
- Modify: `agentdeckd/src/codex/{mod,adapter,history}.rs`
- Modify: `agentdeckd/src/claude_code/{mod,adapter,history}.rs`
- Modify: `ARCHITECTURE.md`, `AGENTS.md`, `README.md`

- [ ] Step 1: 写 boundary tests。 common catalog序列化只含随机 AdapterStateKey；Codex模块只能读 `codex_adapter_state` namespace，CC只能读 `claude_code_adapter_state`；跨模块读取失败；CC index可从原生 history重建；任何路径不创建 `cc-meta/`。
- [ ] Step 2: 运行 adapter boundary test。 Expected: FAIL，当前 router仍以 SessionId/ThreadId为 canonical map。
- [ ] Step 3: 实现 typed private state repositories并迁移 history/continue lookup。 旧 `ThreadId` 只留 stdio compatibility；vendor resume ref先用 StorageKEK包装，再写对应私有表；common层拿不到明文API。
- [ ] Step 4: 重跑测试与 `rg -n 'thread_id|session_id' agentdeckd/src/runtime`。 Expected: 仅 compatibility/迁移注释允许命中，RuntimeCore key不含 vendor identity。
- [ ] Step 5: 同步 N8：允许 adapter私有、派生、可重建映射，仍禁止新 CC 元数据事实源；运行 docs gate。
- [ ] Step 6: 提交。 `git add agentdeckd README.md ARCHITECTURE.md AGENTS.md && git commit -m "refactor(daemon): 隔离 adapter 私有 resume 映射"`

### Task P3.4：实现 transport-neutral RuntimeCore、principal 与 prompt actors

**Files:**
- Create: `agentdeckd/src/runtime/{core,connection,conversation,read_pool}.rs`
- Create: `agentdeckd/tests/runtime_core.rs`
- Modify: `agentdeckd/src/runtime/{mod,router}.rs`
- Modify: `agentdeckd/src/agent.rs`

**Core interface:**
```rust
pub struct RuntimeCore { store: RuntimeStoreHandle, router: Arc<AgentRouter>, connections: ConnectionRegistry, conversations: ConversationRegistry }
impl RuntimeCore {
    pub async fn connect(&self, principal: Principal, sink: ConnectionSink) -> Result<ConnectionId, RuntimeFailure>;
    pub async fn handle(&self, connection_id: ConnectionId, request: RuntimeRequest) -> RuntimeReply;
    pub async fn disconnect(&self, connection_id: ConnectionId);
    pub async fn recover(&self) -> Result<RecoveryReport, RuntimeFailure>;
}
pub enum Principal { Local(LocalPrincipal), Remote(RemotePrincipal) }
```

- [ ] Step 1: 写FakeAgent core tests。 两principal并发同conversation prompt按journal commandSeq FIFO；不同conversation并行；control lane不被prompt堵塞；queued prompt在Started前可取消、Started后只走明确cancel；每conversation32、全局1,024/256MiB；principal撤销后Accepted未Started终止为`RevokedBeforeStart`；512/16MiB慢writer只断自己；同idempotency key replay；remote grant serial renewal后同deviceRoute+DeviceSign owner仍重放原command。
- [ ] Step 2: 运行 runtime_core test。 Expected: FAIL，当前 RuntimeHub绑死单 stdin/stdout。
- [ ] Step 3: 实现 RuntimeCore与per-conversation actor；保留 RuntimeHub未接线作为 compatibility。 actor不await writer；ReadPool有独立 semaphore；local/remote排序不含transport优先级。
- [ ] Step 4: 重跑 test 100 次竞态循环。 Expected: commandSeq稳定，恰好一个 active turn，无任务泄漏。
- [ ] Step 5: fmt/clippy。
- [ ] Step 6: 提交。 `git add agentdeckd && git commit -m "feat(daemon): 建立持久化 RuntimeCore 与会话 actor"`

### Task P3.5：实现 approval first-wins、delivery retry 与精确 receipt

**Files:**
- Create: `agentdeckd/src/runtime/approval.rs`
- Create: `agentdeckd/tests/runtime_approval.rs`
- Modify: `agentdeckd/src/runtime/{core,conversation,store,model}.rs`

- [ ] Step 1: 写 approval tests。 覆盖 principal权限、conversation+turn+approval匹配、100路并发CAS仅一赢家、Pending→Claimed→Applying→Applied、DeliveryFailed保留决定、每轮8次/60s退避、RetryApprovalDelivery只重试同决定、默认30m deadline、turn中断→Expired、AlreadyHandled返回精确state。
- [ ] Step 2: 运行 `cargo test -p agentdeckd --test runtime_approval -- --test-threads=1`。 Expected: FAIL，approval ledger未实现。
- [ ] Step 3: 实现 SQLite CAS、可注入Clock/Backoff与 daemon-owned delivery worker。 winner先持久化再调用 adapter；客户端断线不取消delivery；后到决定永不能覆盖。
- [ ] Step 4: 重跑 tests并启用 paused Tokio time。 Expected: 无真实60秒等待；每条状态转换与canonical event一致。
- [ ] Step 5: 更新 diagnostics failure code与运行 docs gate。
- [ ] Step 6: 提交。 `git add agentdeckd docs/AGENT_DIAGNOSTICS.md && git commit -m "feat(daemon): 实现 approval first-wins 与投递恢复"`

### Task P3.6：实现 canonical event/catalog、SubscriptionBarrier、backfill/snapshot

**Files:**
- Create: `agentdeckd/src/runtime/{events,snapshot,backfill,publication}.rs`
- Create: `agentdeckd/tests/{runtime_stream,runtime_transfer}.rs`
- Modify: `agentdeckd/src/runtime/{core,conversation,store}.rs`

- [ ] Step 1: 写stream tests。 eventSeq/catalogRevision独立单调；eventId/itemId/entityId/commandId稳定；首次订阅锁H/C、注册H+1 watcher、先snapshot后sync/live；空流BeforeFirst→0；journal完整走backfill、裁剪走snapshot；per-conversation journal硬上界为10,000 events或64MiB先到者、全局512MiB；SessionCapabilities在任何AgentItem前；transfer完整hash后才推进inner HWM；publication store可冻结stream generation/seq/counter/exact blob/event range并跨重启逐字节读回。
- [ ] Step 2: 运行两套 tests。 Expected: FAIL，canonical journal/barrier接口缺失。
- [ ] Step 3: 实现event journal、catalog reducer、barrier、bounded transfer assembler和transport-neutral publication outbox API。 P3测试用fake sealed blob验证冻结/ACK/重试；真实seal/counter/Relay publish留P4.5。 Backfill/Snapshot作为定向reply，不写Relay frames、不改变outer stream HWM。
- [ ] Step 4: 重跑 tests并注入 duplicate/out-of-order/65 parts/hash mismatch。 Expected: 正常路径PASS，非法输入typed failure且state不推进。
- [ ] Step 5: fmt/clippy。
- [ ] Step 6: 提交。 `git add agentdeckd && git commit -m "feat(daemon): 加入 canonical stream 与 snapshot barrier"`

### Task P3.7：实现两阶段 exec gate、ExecutionFence 与 orphan recovery

**Files:**
- Create: `agentdeckd/src/{exec_gate,runtime/recovery}.rs`
- Create: `agentdeckd/src/runtime/process_identity.rs`
- Create: `agentdeckd/tests/{exec_gate,runtime_crash_recovery}.rs`
- Modify: `agentdeckd/src/{main,agent}.rs`
- Modify: `agentdeckd/src/codex/{adapter,translate}.rs`
- Modify: `agentdeckd/src/claude_code/{adapter,translate}.rs`
- Modify: `agentdeckd/Cargo.toml`

**Adapter interface:**
```rust
#[async_trait]
pub trait Agent: Send + Sync + 'static {
    async fn prepare_turn(&self, request: AgentTurnRequest, state: AdapterStateHandle) -> Result<Box<dyn PreparedAgentTurn>, ProtocolError>;
    async fn resolve_approval(&self, execution_id: &ExecutionId, decision: ActionDecision) -> Result<(), ProtocolError>;
    async fn cancel(&self, execution_id: &ExecutionId) -> Result<(), ProtocolError>;
}
#[async_trait]
pub trait PreparedAgentTurn: Send { fn exec_spec(&self) -> &ExecSpec; async fn attach(self: Box<Self>, child: GatedChild, events: AdapterEventSender) -> Result<RunningAgentTurn, ProtocolError>; }
```

- [ ] Step 1: 写五个crash-boundary tests。 Started COMMIT后未spawn、gate ready/Fence前、Fence后/release前、release后、父死但vendor group存活；`releaseAuthorizedAt`只表示允许release而不证明token送达/exec；PID复用/start-time不匹配；TERM→KILL失败→RecoveryBlocked；Accepted queue不得在旧group未证实退出时恢复。
- [ ] Step 2: 运行 gate/recovery tests。 Expected: FAIL，两个adapter当前直接spawn vendor。
- [ ] Step 3: 实现当前运行binary的`--exec-gate`子模式、继承私有FD handshake、独立process group、nonce/release token与Fence事务。 gate control/spec、prompt和secret不放`agentdeckd --exec-gate` argv/env；gate通过私有FD取得ExecSpec后，vendor必需的非敏感flags才进入最终exec argv；不经`bin/current`，所有adapter spawn ownership移入gate。 adapter translator只产中立AdapterEvent/approval，不再mint SessionId/RuntimeEvent，conversation/turn/event IDs统一由RuntimeCore包装。
- [ ] Step 4: 重跑tests并用真实无副作用helper验证PGID清理与启动顺序。 Expected: P3固定`singleton lock → Keychain/DB reconcile → fence classification/RecoveryBlocked → bind UDS → emit RemoteStartPermit`；P4.2只能在该permit后启动RemoteTransport。 recovery未完成时不接受新Started，crash前无越过gate副作用，release后crash标Interrupted且不自动重放。
- [ ] Step 5: 运行两个现有adapter fixture suites与clippy。
- [ ] Step 6: 提交。 `git add agentdeckd && git commit -m "feat(daemon): 用两阶段 exec gate 封住副作用边界"`

### Task P3.8：接入 RuntimeEnvelope v1 UDS 与 stdio compatibility

**Files:**
- Create: `agentdeckd/src/local/{mod,framing,peer,unix,stdio_compat}.rs`
- Create: `agentdeckd/tests/local_uds.rs`
- Create: `scripts/check-daemon-network-boundary.sh`
- Modify: `agentdeckd/src/{lib,main}.rs`
- Modify: `agentdeckd/src/runtime/hub.rs`
- Modify: `agentdeckd/Cargo.toml`
- Modify: `ARCHITECTURE.md`, `docs/QUALITY.md`, `AGENTS.md`
- Delete: `scripts/check-daemon-no-net.sh`

- [ ] Step 1: 写UDS tests。 0600、same effective UID、1MiB frame、malformed/oversize close、两个connection独立writer、typed version mismatch、disconnect不终止core；recovery人为阻塞时listener尚未bind，完成分类后Recovering/RecoveryBlocked conversation只读且不能Started，其他已确认安全conversation可恢复；stdio compatibility只支持旧子集并声明不支持multi-client/remote admin/full receipt replay。
- [ ] Step 2: 运行 local_uds test与新 guard。 Expected: FAIL，tokio net未启用且guard/script不存在。
- [ ] Step 3: 实现 JSONL RuntimeEnvelope listener与peer UID校验。 macOS用 `getpeereid`/安全等价API，不把clientInstallationId当认证；stable默认UDS，stdio仅显式 compatibility/ephemeral。
- [ ] Step 4: 重跑 tests和 `bash scripts/check-daemon-network-boundary.sh`。 Expected: P3 guard只允许 `agentdeckd/src/local/` 使用 UnixListener/UnixStream；全daemon无TCP/WSS/reqwest/axum。
- [ ] Step 5: 更新 ARCHITECTURE/QUALITY/AGENTS 的网络边界，运行 docs gate。
- [ ] Step 6: 提交。 运行`git add -- agentdeckd scripts/check-daemon-network-boundary.sh ARCHITECTURE.md docs/QUALITY.md AGENTS.md`和`git add -u -- scripts/check-daemon-no-net.sh`，核对staged diff后执行`git commit -m "feat(daemon): 以 UDS 暴露 RuntimeEnvelope v1"`。

### Task P3.9：macOS App 与 CLI 默认连接同一 UDS

**Files:**
- Create: `agentdeck-cli/src/unix_transport.rs`
- Create: `agentdeck-cli/tests/shared_daemon.rs`
- Create: `Sources/AgentDeck/{UnixSocketDaemonTransport,RuntimeEnvelopeClient}.swift`
- Create: `Tests/AgentDeckTests/{UnixSocketDaemonTransportTests,RuntimeEnvelopeClientTests}.swift`
- Create: `scripts/run-local-runtime-smoke.sh`
- Modify: `agentdeck-cli/src/{transport,client,main}.rs`
- Modify: `Sources/AgentDeck/{DaemonTransport,ProcessDaemonTransport,DaemonClient,SessionModel,WorkbenchModel,ThreadRuntimeModel,AppDelegate,main}.swift`

- [ ] Step 1: 写 shared-daemon tests。 Rust CLI与Swift transport连接同一temp UDS，看到同conversation/queue；关闭App连接后daemon PID/turn不变；protocol mismatch可见；默认代码路径不spawn；ProcessDaemonTransport只允许`--ephemeral --no-remote`。
- [ ] Step 2: 运行 `cargo test -p agentdeck-cli --test shared_daemon` 与 `swift test --filter RuntimeEnvelopeClientTests`。 Expected: FAIL，默认仍spawn私有daemon/讲IPC v2。
- [ ] Step 3: 实现 Rust/Swift Runtime v1 UDS client并迁移模型主键到conversationId/eventId/itemId/entityId/commandId。 删除synthetic agentItem序号；本地进程退出只close socket。
- [ ] Step 4: 重跑tests与`swift test`，再运行`bash scripts/run-local-runtime-smoke.sh`。 脚本必须在tempdir启动`agentdeckd --ephemeral --no-remote --socket "$AGENTDECK_TEST_SOCKET"`、等待socket ready、把同一`AGENTDECK_DAEMON_SOCKET`传给Rust CLI与`swift run AgentDeck -- --selfcheck`，最后trap清理进程/socket/DB。 Expected: 全部PASS，两个本地writer FIFO/approval结果一致。
- [ ] Step 5: 运行 network guard与git状态清理。
- [ ] Step 6: 提交。 `git add agentdeck-cli Sources Tests scripts/run-local-runtime-smoke.sh && git commit -m "feat(local): App 与 CLI 共用 singleton daemon UDS"`

### Task P3.10：实现 LaunchAgent 安装、versioned upgrade 与保留数据的 uninstall

**Files:**
- Create: `agentdeck-cli/src/daemon.rs`
- Create: `agentdeckd/src/runtime/upgrade.rs`
- Create: `packaging/com.agentdeck.agentdeckd.plist`
- Create: `agentdeck-cli/tests/daemon_install.rs`
- Create: `agentdeckd/tests/upgrade_idle.rs`
- Create: `scripts/verify-daemon-install.sh`
- Modify: `agentdeck-cli/src/main.rs`
- Modify: `agentdeckd/src/runtime/core.rs`
- Modify: `script/build_and_run.sh`
- Modify: `README.md`, `docs/QUALITY.md`, `docs/AGENT_DIAGNOSTICS.md`, `docs/index.md`, `AGENTS.md`

- [ ] Step 1: 写installer/upgrade tests。 固定`~/Library/Application Support/AgentDeck/bin/$VERSION/agentdeckd`、原子`bin/current`、plist label、首次bootstrap、active turn只stage、idle切symlink+优雅exit、launchd restart、mismatch、不卸载运行中错误版本、uninstall保留全部DB/Keychain；P3的`uninstall --purge`必须返回`daemon.purge.remote_not_ready`且不删除任何数据，完整purge到P4.2；ephemeral拒安装。
- [ ] Step 2: 运行 unit tests。 Expected: FAIL，daemon subcommand与upgrade coordinator不存在。
- [ ] Step 3: 实现`agentdeck daemon install|status|uninstall`并解析但拒绝P3的`--purge`。 App bundle helper固定`AgentDeck.app/Contents/Helpers/agentdeckd`；生产SignatureVerifier固定designated requirement、TeamIdentifier和daemon-only Keychain access-group entitlement，source使用O_NOFOLLOW读取，copy到同目录temp后fsync、对temp做第二次签名/version/hash/entitlement校验再atomic rename，覆盖TOCTOU；active daemon通过UDS接收StageUpgrade。 ad-hoc只存在test-only injected verifier，生产路径明确拒绝。
- [ ] Step 4: 运行unit tests与 `AGENTDECK_INSTALL_E2E=1 bash scripts/verify-daemon-install.sh`。 Expected: unit tests使用注入的launchctl/signature verifier；gated脚本只在明确指定的可丢弃macOS测试用户profile中验证`launchctl print`、PID、UDS、stage/idle switch与uninstall readback，并始终清理test label。
- [ ] Step 5: 扩展 `verify-relay-companion-mvp.sh p3`，运行 cargo/swift/network/docs gates并清理临时LaunchAgent。
- [ ] Step 6: 提交。 `git add agentdeck-cli agentdeckd packaging script scripts README.md docs AGENTS.md && git commit -m "feat(daemon): 完成 LaunchAgent 安装与空闲升级"`

---

## Phase P4：Machine identity、Pairing 与 RemoteLink

### Task P4.1：扩展 macOS Keychain 为 Machine identity、CounterGuard 与 enrollment receipt

**Files:**
- Create: `agentdeckd/src/remote/{mod,identity}.rs`
- Create: `agentdeckd/tests/machine_identity.rs`
- Modify: `agentdeckd/src/security/{key_store,macos_keychain}.rs`
- Modify: `agentdeckd/src/runtime/store.rs`
- Modify: `agentdeckd/src/{lib,main}.rs`
- Modify: `agentdeckd/Cargo.toml`

**Key accounts:** `machine-root-sign.v1`、`machine-hpke.v1`、`machine-link-sign.v1`、`machine-data-sign.v1`、既有`storage-kek.v1`、`key-directory-guard.v1`、每个active key的`counter-guard/{keyId}`；Runtime DB的`machine_enrollment_receipts`是唯一故意不经StorageKEK包装的非秘密rescue index。

- [ ] Step 1: 写identity tests。 首启生成一次、普通重启指纹不变；root只签固定对象family；link/data cert由root签；private key不进DB/日志；ephemeral不读stable；删除全部Keychain items后仍先读出old route/root fingerprint并进入`BlockedRootMissing`，绝不生成新root/KEK覆盖旧状态；DB key-directory revision低于guard、guard缺失/回退均fail-closed。
- [ ] Step 2: 运行 machine_identity test。 Expected: FAIL，remote identity不存在。
- [ ] Step 3: 实现typed MachineIdentityStore、generation/trustEpoch上界、counter与key-directory guard IO。 复用P3.1的protected/non-synchronizable/AfterFirstUnlockThisDeviceOnly与daemon-only stable access group；删除操作必须传expected fingerprint防错删。
- [ ] Step 4: 重跑test、扫描temp DB/log，并用versioned同TeamIdentifier helper读旧items且禁用交互。 Expected: 无Keychain弹窗；只有public fingerprint/cert/receipt，无secret bytes。
- [ ] Step 5: fmt/clippy。
- [ ] Step 6: 提交。 `git add agentdeckd && git commit -m "feat(remote): 建立机器根身份与 Keychain guard"`

### Task P4.2：先建立 RemoteTransport，再实现 machine enrollment 与两条 trust-reset 路径

**Files:**
- Create: `agentdeckd/src/remote/{config,transport,enrollment,trust_reset}.rs`
- Create: `agentdeckd/tests/{machine_transport,machine_enrollment}.rs`
- Modify: `agentdeckd/src/runtime/store.rs`
- Modify: `agentdeck-cli/src/{main,remote,daemon}.rs`
- Modify: `agentdeckd/Cargo.toml`
- Modify: `scripts/check-daemon-network-boundary.sh`

**Local commands:** `agentdeck remote machine enroll --bundle-file FILE`、`agentdeck remote machine status`、`agentdeck remote trust-reset`；本task把`agentdeck daemon uninstall --purge`接到同一trust-reset状态机，不能直接删除本地目录。root丢失时输出必须包含old route/root fingerprint与Relay admin purge命令，但不含恢复选项。

- [ ] Step 1: 写transport/enrollment/reset tests。 RemoteTransport必须等待P3的RemoteStartPermit，再以RelayEnrollmentClient消费code，成功后只建立一条authenticated MachineLink WSS；CA/SPKI验证必须发生在发送code/root pub前；redirect/host/scheme拒绝；code race只有一次成功；普通重启不重配。有root reset固定`Active→RetirePending(frozenSignedBytes)→RelayCommitted→PurgeReadbackAbsent→LocalDeleted`；无root保持blocked，admin purge/readback后才删receipt。覆盖recovery阻塞、Relay离线、每个COMMIT前后crash、daemon restart与错误fingerprint；P3的`daemon uninstall --purge`在本task接入同一状态机，并强制`trust reset/readback absent → launchctl bootout且确认进程/UDS消失 → 删除版本目录/plist → 删除Runtime DB/Keychain/receipt`，任何前置失败零删除。
- [ ] Step 2: 运行machine_transport/machine_enrollment tests。 Expected: FAIL，daemon没有outbound transport/config/command。
- [ ] Step 3: 依赖纯`agentdeck-relay-client`实现一次性TLS enrollment与persistent MachineLink transport；实现machine lifecycle/retirement durable outbox和本地RuntimeRequest入口，并把CLI `daemon uninstall --purge`替换为完整两阶段卸载：先由运行中daemon完成/读回trust reset，再bootout并读回PID/UDS消失，最后删除签名binary/plist与本地DB/Keychain/receipt。RemoteTransport此时只处理enrollment/auth/control，不向RuntimeCore派发业务frame；任何失败都保留旧root/receipt/frozen signed bytes，禁止启动时自动删除或注册新route。
- [ ] Step 4: 重跑tests和network guard。 Expected: 只允许`agentdeckd/src/remote/`及client crate outbound WSS/HTTPS；reset跨重启续做同一RetireMachine，读回active route/data absent前绝不删本地key/data。
- [ ] Step 5: 更新 Relay runbook的两条reset流程与diagnostic codes；运行docs gate。
- [ ] Step 6: 提交。 `git add agentdeckd agentdeck-cli scripts docs Cargo.lock && git commit -m "feat(remote): 建立 RemoteTransport 与 machine trust reset"`

### Task P4.3：实现 PairInvite、本机指纹确认、byte-stable PairRequest、DeviceGrant 与本机 auth ledger

**Files:**
- Create: `agentdeckd/src/remote/{pairing,grants,access,key_directory}.rs`
- Create: `agentdeckd/tests/pairing_state_machine.rs`
- Modify: `agentdeckd/src/runtime/{core,store}.rs`
- Modify: `agentdeck-cli/src/{main,remote}.rs`

**Core interface:**
```rust
impl RuntimeCore {
    pub async fn create_pair_invite(&self, principal: &LocalPrincipal) -> Result<PairInviteV1, RuntimeFailure>;
    pub async fn list_pending_pairings(&self, principal: &LocalPrincipal) -> Result<Vec<PendingPairing>, RuntimeFailure>;
    pub async fn confirm_pairing(&self, principal: &LocalPrincipal, pairing: PairingId) -> Result<PairingReceipt, RuntimeFailure>;
    pub async fn cancel_pairing(&self, principal: &LocalPrincipal, pairing: PairingId) -> Result<PairingReceipt, RuntimeFailure>;
    pub async fn revoke_device(&self, device: DeviceRouteId, serial: u64) -> Result<RevocationReceipt, RuntimeFailure>;
}
impl PairingCoordinator { pub async fn handle_pair_data(&self, context: PairRouteContext, outer: PairData) -> Result<PairResponseFrame, PairingFailure>; }
pub struct VerifiedPairRequest { pub request_hash: [u8; 32], pub device_sign_key: PublicKeyBytes, pub device_hpke_key: PublicKeyBytes, pub authorization_request: AuthorizationRequest }
```

- [ ] Step 1: 写pairing tests。create invite必须先持久化open outbox，再`OpenPairRoute`并等待Relay ACK，打开失败不返回invite；daemon/Relay重启用相同route/absolute expiry幂等重开。delivered/expired/canceled先持久化terminal close outbox，只有Closed/AlreadyAbsent ACK后擦除临时材料；逐个注入Open/Close ACK前后crash。覆盖5m/单次/最多8 invites及完整`routeOpening→unused→preparing(requestHash,frozenRequest)→awaitingLocalConfirmation→grantPreparing(frozenGrantArtifacts)→grantCommitted(encryptedResponse)→delivered|expired|canceled`；只有same-UID UDS LocalPrincipal能list/confirm/cancel，RemotePrincipal/PairingAccess/admin全部拒绝。本地看到DeviceSign fingerprint，确认前远端只有同requestHash的signed/encrypted PairPending且Relay无grant；两个LocalPrincipal的confirm-vs-cancel、confirm-vs-expiry做first-valid CAS，赢家canonical receipt、同动作retry replay、输家AlreadyHandled，grantPreparing后cancel不能逆转。另覆盖同requestHash byte-identical response、不同request拒、每个状态crash/restart；RouteAccepted不推进delivered，只有验过DeviceSign且匹配request/grant/response hash的PairResponseReceived才推进，回执丢失逐字节重发，TTL无回执撤销orphan grant；并覆盖RelayGrant最小字段、密文DeviceAuthorization、bootstrap KeyDirectory、serial renewal及撤销恢复。
- [ ] Step 2: 运行 pairing state-machine test。 Expected: FAIL，pairing module不存在。
- [ ] Step 3: 在remote::PairingCoordinator中解outer、绑定pair route/request context、验证DeviceSign possession proof后产生VerifiedPairRequest；RuntimeCore和adapter不得import`relay_v2::*`。create invite先持久化open outbox并经RemoteTransport open+ACK，恢复时以相同absolute expiry重开；PairRequest先持久化并发local-only pending事件，confirm/cancel/expiry由Runtime DB单事务CAS裁决，只有confirm赢家才冻结并签root-signed grant/auth。grantCommitted持续重发同一response，直到验证DeviceSign-signed PairResponseReceived；所有terminal先持久化close outbox、等Close ACK才擦除。实现invite secret/临时HPKE私钥包装、bootstrap key directory、InstallGrant commit handshake、本机auth ledger、durable revocation/route outbox；CLI增加`remote pairing pending|approve PAIRING_ID|cancel PAIRING_ID`且只走UDS，PairInvite机器名仅在带外编码。
- [ ] Step 4: 重跑 tests并对PairRequest/Response做tamper corpus。 Expected: PASS；相同请求的frame bytes完全一致。
- [ ] Step 5: fmt/clippy。
- [ ] Step 6: 提交。 `git add agentdeckd agentdeck-cli && git commit -m "feat(remote): 实现本机确认的独立配对与授权账本"`

### Task P4.4：把唯一 MachineLink transport 接入 RuntimeCore

**Files:**
- Create: `agentdeckd/src/remote/{link,dispatch}.rs`
- Create: `agentdeckd/tests/machine_remote_link.rs`
- Modify: `agentdeckd/src/{main,lib}.rs`
- Modify: `agentdeckd/src/runtime/core.rs`
- Modify: `agentdeckd/Cargo.toml`
- Modify: `scripts/check-daemon-network-boundary.sh`

**Boundary:**
```text
sealed frame -> Relay v2 outer validation -> DeviceSign/AAD/replay/AEAD verification
             -> local grantSerial auth-ledger check -> RemotePrincipal
             -> RuntimeCore::handle -> RuntimeReply/Event
             -> MachineDataSign + AEAD -> opaque Relay frame
```

- [ ] Step 1: 写RemoteLink tests。 复用P4.2唯一machine WSS；重连challenge与active generation replacement；invalid grant/signature/AAD/replay在core前拒；local revoke后网络中旧frame不执行；RouteAccepted不产生command success；多个device进入同core。 recovery完成前RemoteLink不启动；RecoveryBlocked conversation只读，其他安全conversation可服务。
- [ ] Step 2: 运行machine_remote_link test与boundary guard。 Expected: FAIL，transport已能鉴权但尚未派发Runtime业务。
- [ ] Step 3: 依赖existing RemoteTransport与agentdeck-crypto实现RemoteLink supervisor/dispatch。 adapter目录不得importrelay/remote类型；RemoteLink不持有canonical业务state，只把已验证的RuntimeRequest规范化为RemotePrincipal后交RuntimeCore。
- [ ] Step 4: 重跑tests和guard。 Expected: P4 guard只允许`agentdeckd/src/remote/`及client crate出现outbound WSS/HTTPS；仍禁止daemon axum、TCP listener、reqwest/server feature。
- [ ] Step 5: 运行完整agentdeckd tests与clippy。
- [ ] Step 6: 提交。 `git add agentdeckd scripts Cargo.lock && git commit -m "feat(remote): 接入唯一 outbound Machine RemoteLink"`

### Task P4.5：实现 key directory、MachineDataSign、publish/replay 与 counter crash recovery

**Files:**
- Create: `agentdeckd/src/remote/{counter,publisher,replay}.rs`
- Modify: `agentdeckd/src/remote/key_directory.rs`
- Create: `agentdeckd/tests/{remote_crypto_recovery,remote_replay}.rs`
- Modify: `agentdeckd/src/runtime/{core,connection,store}.rs`
- Modify: `agentdeckd/src/remote/{dispatch,link}.rs`

- [ ] Step 1: 写crypto/replay/publication tests。 CatalogKey/ConversationDEK/DeviceCommandTxKey/DeviceReplyTxKey方向；MachineDataSign来源；新增/撤销设备轮换catalog与active conversation epoch，新设备拿不到旧epoch且从barrier定向snapshot接续；EpochBarrier绑定generation/cursor/H/revision；unknown higher revision 3次/30s KeySync；lower revision隔离；CounterGuard先于DB、DB备份rollback、nonce reuse、4,096 window、retired key 24h+1h。 对catalog/event/barrier分别注入四个publish边界，重启只允许逐字节重发冻结blob。
- [ ] Step 2: 运行两套 tests。 Expected: FAIL，publisher/key directory不存在。
- [ ] Step 3: 实现wrapped key directory、counter allocator、signed sealed publisher、durable publication outbox/ACK与receive replay。 固定顺序为`Keychain guard reserve → seal一次 → Runtime DB冻结exact blob/streamSeq/counter/event range → Relay Publish COMMIT → local ACK`；第一步后失败只跳号，第二步后所有retry复用同一blob。 Backfill/Snapshot用DeviceReplyTxKey定向reply且不进outbox/Relay frames；shared ConversationDEK只用于barrier后publish。
- [ ] Step 4: 重跑tests并替换Runtime DB为旧备份。 Expected: publication crash gap无事件永久缺口、无同seq不同blob；自动退休旧epoch并rekey，无法协调时remote fail-closed，绝不发送旧counter。
- [ ] Step 5: 运行security sentinel与clippy。
- [ ] Step 6: 提交。 `git add agentdeckd && git commit -m "feat(remote): 加入签名事件流与 crash-safe counter"`

### Task P4.6：实现 macOS persistent remote CLI Keychain 与真实 daemon receipts

**Files:**
- Replace: `agentdeck-cli/src/remote.rs` → `agentdeck-cli/src/remote/{mod,keychain,pending,paired_machine,crypto_state,device_lock,runtime}.rs`
- Create: `agentdeck-cli/tests/{remote_keystore,remote_device_lock,remote_runtime_receipts}.rs`
- Create: `packaging/agentdeck-cli.entitlements`
- Modify: `agentdeck-cli/src/main.rs`
- Modify: `agentdeck-cli/Cargo.toml`
- Modify: `script/build_and_run.sh`
- Modify: `Cargo.lock`

**Keychain naming contract:** service固定`com.agentdeck.remote.v1`；发送前pending account语法为`pending/cli/{installationId}/{inviteHash}/{purpose}`，paired语法为`cli/{installationId}/{rootFingerprint}/{machineRoute}/{purpose}`。Swift P5使用同一编码文档但以`macos-app`或`ios-app` client-kind和独立installationId存储，默认不共享device private key。

**macOS persistence contract:** 仅发行签名CLI启用persistent mode；二进制带CLI-only Keychain access group entitlement并固定`kSecUseDataProtectionKeychain=true`、`kSecAttrSynchronizable=false`、`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`与non-interactive access，不能读取App或daemon access group。DeviceSign/DeviceHPKE、grant、StorageKEK与CounterGuard只进Data Protection Keychain。wrapped key directory、cursor、counter reservation和receive replay进入`~/Library/Application Support/AgentDeck/remote/cli/$INSTALLATION_ID/`下0700目录、0600 sealed file；所有open使用`O_NOFOLLOW`，写入执行temp+fsync+rename+parent fsync并排除备份。unsigned/ad-hoc CLI、无法验证entitlement或旧签名版本读回失败时返回typed unsupported/security error，绝不降级文件私钥。

- [ ] Step 1: 写CLI tests。 首次发送前持久化immutable`enc+ciphertext+proof`并exact retry；多Keychain item+StorageKEK sealed CryptoState使用单一paired commit marker两阶段提升，逐写点crash恢复；restart后读DeviceSign/DeviceHPKE/grant/counter/replay；128MiB cap；revokeSelf只有signed terminal才删key。 用签名test fixture读回升级前versioned items；断言Data Protection Keychain、ThisDeviceOnly/non-sync/无交互、CLI-only access group、0700/0600/O_NOFOLLOW/backup exclusion与fsync顺序，扫描sealed file无私钥/明文sentinel；unsigned/ad-hoc persistent mode typed unsupported。两个真实CLI进程同时打开同installation/device时，跨进程`flock`覆盖整个active connection/counter allocator生命周期，第二进程返回`remote.device.already_in_use`且所有counter唯一。另覆盖每machine独立keys、旧bearer JSON不读写、Linux persistent pair typed unsupported。
- [ ] Step 2: 运行 remote keystore/receipt tests。 Expected: FAIL，当前CLI仍是旧credential或synthetic-only。
- [ ] Step 3: 使用`security-framework`的protected Keychain API实现上述CLI-only签名/entitlement/accessibility contract，提交最小entitlements并让release/build脚本以指定TeamIdentifier签名；CLI启动persistent mode前读回自身designated requirement、TeamIdentifier和access group。再实现StorageKEK加密、0700/0600/O_NOFOLLOW、backup-excluded且fsync+rename的CryptoStateStore、paired commit marker、跨进程device lock和`remote pair|machines|conversations|watch|prompt|approve|retry-approval|revoke-self`。 `machines`只列本地PairedMachineStore；prompt/approval只在daemon receipt后exit 0；RouteAccepted只打印transport state。
- [ ] Step 4: 重跑tests并并发启动两个CLI进程竞争同installation record。 Expected: 只有持锁进程能连接/预留counter，另一个typed fail；进程崩溃释放lock后可恢复；不同installation不误用同key。
- [ ] Step 5: fmt/clippy并扫描home tempdir无private credential JSON。
- [ ] Step 6: 提交。 `git add agentdeck-cli packaging/agentdeck-cli.entitlements script/build_and_run.sh Cargo.lock && git commit -m "feat(cli): 用 Keychain 持久化远程设备身份"`

### Task P4.7：远程 CLI 合成/真实双 agent E2E 与阶段文档收口

**Files:**
- Create: `agentdeckd/tests/relay_v2_machine_e2e.rs`
- Create: `agentdeck-cli/tests/{e2e_remote_codex,e2e_remote_claude_code}.rs`
- Modify: `scripts/verify-relay-companion-mvp.sh`
- Modify: `README.md`, `ARCHITECTURE.md`, `docs/QUALITY.md`, `docs/AGENT_DIAGNOSTICS.md`, `docs/index.md`, `AGENTS.md`, `docs/RELAY_RUNBOOK.md`

- [ ] Step 1: 写默认合成E2E与gated真实E2E。 合成链路不需vendor login，完成enroll→invite→PairRequest→本地pending fingerprint读回/approve→grant→catalog→open→prompt→approval→reconnect/replay→revoke，并证明远端confirm被拒；真实suite分别验证Codex/CC start/continue/approval/history且receipt来自daemon。
- [ ] Step 2: 运行 `bash scripts/verify-relay-companion-mvp.sh p4`。 Expected: FAIL，脚本尚未编排新RemoteLink/CLI suites或文档仍称remote skeleton。
- [ ] Step 3: 扩展verifier和入口文档；记录Linux仅支持ephemeral test client、macOS persistent Keychain、root lost reset步骤。
- [ ] Step 4: 运行：
  ```bash
  cargo test
  swift test
  bash scripts/check-daemon-network-boundary.sh
  bash scripts/verify-relay-companion-mvp.sh p4
  scripts/verify-agent-docs.sh
  AGENTDECK_E2E=1 cargo test -p agentdeck-cli --test e2e_remote_codex -- --nocapture
  AGENTDECK_E2E=1 cargo test -p agentdeck-cli --test e2e_remote_claude_code -- --nocapture
  ```
  Expected: 默认门禁全部exit 0；gated tests在具备login的环境各输出真实conversation/command evidence reference。
- [ ] Step 5: `git status --short --branch`，清理临时Keychain accounts、DB、invite与logs。
- [ ] Step 6: 提交。 `git add agentdeckd agentdeck-cli scripts README.md ARCHITECTURE.md AGENTS.md docs && git commit -m "test(remote): 收口双 agent 真实远程 CLI 链路"`

---

## Phase P5：共享 Swift client、iOS Companion 与远程 macOS

### Task P5.1：建立 AgentDeckSessionSource target 与强类型 facade

**Files:**
- Create: `Sources/AgentDeckSessionSource/{SessionSource,LocalPairingAdministration,SessionSourceModels,SessionSourceReceipts,SessionSourceCompatibility}.swift`
- Create: `Tests/AgentDeckSessionSourceTests/{SessionSourceContractTests,LocalPairingAdministrationTests,ResourceStateTests}.swift`
- Modify: `Package.swift`
- Modify: `ios/project.yml`
- Delete after migration: `ios/AgentDeckMobile/DataSource/{MobileSessionSource,MobileSessionModels}.swift`

**Facade:**
```swift
public protocol SessionSource: Sendable {
    func machines() async -> AsyncStream<ResourceState<[MachineSummary]>>
    func conversations(machineID: String) async -> AsyncStream<ResourceState<[ConversationSummary]>>
    func conversation(conversationID: String) async -> AsyncStream<ConversationUpdate>
    func inbox() async -> AsyncStream<ResourceState<[InboxItem]>>
    func inspectPairInvite(_ encoded: String) async throws -> PairingPreview
    func pair(_ encodedInvite: String) async throws -> AsyncThrowingStream<PairingProgress, Error>
    func revokeSelf(machineID: String) async throws -> RevocationReceipt
    func sendPrompt(conversationID: String, text: String, idempotencyKey: UUID) async throws -> CommandReceipt
    func resolveApproval(conversationID: String, turnID: String, approvalID: String, decision: ActionDecisionKind, idempotencyKey: UUID) async throws -> ApprovalReceipt
    func retryApprovalDelivery(conversationID: String, approvalID: String) async throws -> ApprovalReceipt
}
public protocol LocalPairingAdministration: Sendable {
    func pendingPairings() async -> AsyncStream<ResourceState<[PendingPairing]>>
    func confirmPairing(id: String) async throws -> PairingAdministrationReceipt
    func cancelPairing(id: String) async throws -> PairingAdministrationReceipt
}
```

**Target edges:** `AgentDeckSessionSource -> AgentDeckCore`；`AgentDeckRelayClient -> AgentDeckCore + AgentDeckSessionSource`；macOS `AgentDeck` executable 与iOS `AgentDeckMobile` app均显式依赖`AgentDeckCore + AgentDeckSessionSource + AgentDeckRelayClient`；tests依赖各自被测target。

- [ ] Step 1: 写 compile-time/behavior tests。protocol无`@MainActor`，所有cross-actor types Sendable；观察方法必须async；`ResourceState`精确四态；`ConversationUpdate`精确snapshot/event/commandState/connectionState；`PairingProgress`精确preparing/waitingForLocalConfirmation/paired/canceled/expired；`LocalPairingAdministration`与普通SessionSource分离且confirm/cancel receipt支持AlreadyHandled；共享模型不含fixture的`streamResource`。
- [ ] Step 2: 运行 `swift test --filter AgentDeckSessionSourceTests`。 Expected: FAIL，target不存在。
- [ ] Step 3: 按上述target edges修改Package与`ios/project.yml`，增加`AgentDeckSessionSource` library/test target并更新P1.6已存在的RelayClient；为迁移提供typealias但不复制wire类型。 XcodeGen App target必须列出三个SPM product，不编辑生成的xcodeproj/Info.plist。
- [ ] Step 4: 重跑SessionSource tests与 `swift test`。 Expected: PASS，AgentDeckCore仍无CryptoKit/UIKit/AppKit/network import。
- [ ] Step 5: 运行 `rg -n 'import (CryptoKit|UIKit|AppKit|Network)' Sources/AgentDeckCore Sources/AgentDeckSessionSource`。 Expected: 0 matches。
- [ ] Step 6: 提交。 `git add Package.swift Sources/AgentDeckSessionSource Tests/AgentDeckSessionSourceTests ios/project.yml ios/AgentDeckMobile/DataSource && git commit -m "feat(swift): 建立共享 SessionSource facade"`

### Task P5.2：实现 Apple Keychain、CryptoStateStore 与 Swift counter/replay IO

**Files:**
- Create: `Sources/AgentDeckRelayClient/Storage/{KeyStore,AppleKeychainStore,CryptoStateStore,FileCryptoStateStore,PairedMachineStore}.swift`
- Create: `Sources/AgentDeckRelayClient/Crypto/{CounterAllocator,ReplayWindow}.swift`
- Create: `Tests/AgentDeckRelayClientTests/{AppleKeychainStoreTests,CryptoStateStoreTests,CounterAllocatorTests,ReplayWindowTests}.swift`
- Create: `ios/AgentDeckMobileTests/RelayClientStorageIntegrationTests.swift`

**Core interface:**
```swift
public protocol KeyStore: Sendable { func load(_ key: KeyStoreKey) async throws -> Data?; func store(_ data: Data, for key: KeyStoreKey) async throws; func delete(_ key: KeyStoreKey) async throws }
public protocol CryptoStateStore: Sendable { func load(machineID: String) async throws -> CryptoStateSnapshot?; func commit(_ snapshot: CryptoStateSnapshot, machineID: String) async throws; func delete(machineID: String) async throws }
```

- [ ] Step 1: 写storage tests。 Keychain固定`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`、service=`com.agentdeck.remote.v1`、每machine的`device-storage-kek.v1`和counter guard accounts；`CryptoStateFileV1`用DeviceStorageKEK AEAD包装key directory/replay/cursor且AAD绑定root fingerprint/route/version，文件exclude-from-backup、complete file protection、128MiB。 原子提交固定`temp write → fsync(file) → rename → fsync(parent dir)`；CounterGuard high-water先于sealed file reservation，逐边界crash只允许跳号；rollback退休epoch；state文件扫描不得出现prompt/output transcript sentinel。
- [ ] Step 2: 运行 `swift test --filter CounterAllocatorTests` 等四套tests。 Expected: FAIL，storage types不存在。
- [ ] Step 3: 实现actor-isolated stores、DeviceStorageKEK、sealed file codec、原子fsync/rename与Keychain OSStatus映射；private key只经CryptoKit rawRepresentation转换后进入Keychain。 App/CLI默认不同client-kind/installation-id，不要求跨签名进程共享同一private item。
- [ ] Step 4: 重跑SwiftPM tests并确认测试Keychain account清理。 Expected: PASS；logs/error description不含secret。
- [ ] Step 5: 运行 `cd ios && xcodegen generate && xcodebuild -project AgentDeckMobile.xcodeproj -scheme AgentDeckMobile -destination 'platform=iOS Simulator,name=iPhone 17' -only-testing:AgentDeckMobileTests/RelayClientStorageIntegrationTests test`，真实验证iOS ThisDeviceOnly/FileProtection/backup exclusion/crash恢复，再运行AgentDeckRelayClient完整tests。
- [ ] Step 6: 提交。 `git add Sources/AgentDeckRelayClient Tests/AgentDeckRelayClientTests ios/AgentDeckMobileTests/RelayClientStorageIntegrationTests.swift && git commit -m "feat(swift): 加入 Keychain 与 crash-safe crypto state"`

### Task P5.3：实现 Swift RelayWebSocketTransport、SPKI pin 与 transfer assembler

**Files:**
- Create: `Sources/AgentDeckRelayClient/Transport/{RelayWebSocketTransport,PinnedURLSessionDelegate,ReconnectPolicy}.swift`
- Create: `Sources/AgentDeckRelayClient/Transfer/TransferAssembler.swift`
- Create: `Tests/AgentDeckRelayClientTests/{RelayWebSocketTransportTests,TLSPinningTests,TransferAssemblerTests}.swift`

**Core interface:**
```swift
public actor RelayWebSocketTransport {
    public func connect() async throws
    public func incomingFrames() async -> AsyncThrowingStream<OpaqueRouteFrame, Error>
    public func send(_ frame: OpaqueRouteFrame) async throws
    public func close() async
}
```

- [ ] Step 1: 写注入式transport tests。 注入WebSocket task factory/clock/jitter；覆盖仅wss、public CA、current/next DER SPKI、pin mismatch、redirect/host/scheme、4MiB frame、exponential backoff、server restart；transfer覆盖1/64/65 parts、3.5/64MiB、乱序、duplicate-same/conflict、5m/hash/128MiB。
- [ ] Step 2: 运行三套tests。 Expected: FAIL，transport/assembler不存在。
- [ ] Step 3: 实现URLSessionWebSocketTask actor与pinned delegate。 transport只解析Relay outer wire，不解Runtime payload；incoming/writer各受512 frames/16MiB上界约束，drop/overflow关闭当前generation而非无界缓存；pin失败没有绕过回调；assembler在完整hash前不返回payload。
- [ ] Step 4: 重跑tests与 P1 cross-language crypto gate。 Expected: PASS，网络tests不依赖公网。
- [ ] Step 5: 运行Swift concurrency warnings as errors构建。
- [ ] Step 6: 提交。 `git add Sources/AgentDeckRelayClient Tests/AgentDeckRelayClientTests && git commit -m "feat(swift): 实现 WSS pin 与有界分片传输"`

### Task P5.4：实现 MachineConnection、bounded broadcaster 与 RelaySessionSource

**Files:**
- Create: `Sources/AgentDeckRelayClient/Connection/{MachineConnection,MachineConnectionStateMachine}.swift`
- Create: `Sources/AgentDeckRelayClient/Crypto/{MachineDataVerifier,DeviceRequestSigner}.swift`
- Create: `Sources/AgentDeckRelayClient/Streaming/BoundedBroadcaster.swift`
- Create: `Sources/AgentDeckRelayClient/Source/{RelaySessionSource,CatalogReducer,ConversationReducer,InboxReducer}.swift`
- Create: `Tests/AgentDeckRelayClientTests/{MachineDataVerifierTests,DeviceRequestSignerTests,BoundedBroadcasterTests,MachineConnectionTests,RelaySessionSourceTests,RelayResumeTests}.swift`

**Source scope:**
```swift
public enum RelaySourceScope: Sendable { case allPairedMachines; case machine(String) }
public actor RelaySessionSource: SessionSource { /* one MachineConnection per paired machine */ }
```

- [ ] Step 1: 写source/auth tests。入站固定顺序`outer bounds/domain/trust/serial/revision → MachineDataSign TBS verify → replay tuple → AEAD open → Runtime decode → reducer`；出站DeviceRequestSigner固定`Runtime encode → AEAD → outer-bound TBS → DeviceSign`。forged event、lower revision、unknown higher revision/key-sync exhaustion、bad AAD/tag均不得推进cursor/reducer；PairPending映射waitingForLocalConfirmation，signed canceled/expired为terminal，PairResponseReceived必须在本地paired record原子提升后发送且exact retry。resource stream`.bufferingNewest(1)`，conversation 512；drop通过`ConversationUpdate.connectionState(.lagged(reason: .bufferDropped))`轮换内部generation并snapshot/barrier，但用户observation stream保持存活；cold process launch因不存transcript必须先daemon snapshot/barrier，再增量resume。revoked/incompatible/securityError才fatal。
- [ ] Step 2: 运行四套tests。 Expected: FAIL，MachineConnection/RelaySessionSource不存在。
- [ ] Step 3: 实现MachineDataVerifier、DeviceRequestSigner、connection supervisor、bounded broadcaster、reducers与source。MachineDataVerifier必须把SignedSealedBlobV1验成VerifiedSealedBlobV1后才允许AEAD open；DeviceRequestSigner只能发送SignedSealedBlobV1。pair返回PairingProgress stream，持久化paired record后以DeviceSign发送/重试PairResponseReceived。只有签名/AEAD/inner验证完成后才能持久化cursor/revision；exact duplicate再按eventId去重；offline send立即typed failure。
- [ ] Step 4: 重跑tests并做10,000 events慢消费者压力、前后台与kill/relaunch恢复。 Expected: 无静默丢失/无无界内存；lag只重建内部generation，外层observation继续；冷启动不会从非零cursor拼出不完整transcript；伪造frame不改变任何state。
- [ ] Step 5: 运行Swift tests和Instruments非门控内存上限smoke。
- [ ] Step 6: 提交。 `git add Sources/AgentDeckRelayClient Tests/AgentDeckRelayClientTests && git commit -m "feat(swift): 建立 RelaySessionSource 与有界状态流"`

### Task P5.5：迁移 Fixture 与 iOS ViewModel 到真实 receipt 语义

**Files:**
- Modify: `ios/AgentDeckMobile/DataSource/{FixtureSessionSource,FixtureFormat}.swift`
- Modify: `ios/Fixtures/*.json`
- Modify: `ios/AgentDeckMobile/Screens/MachineList/MachineListViewModel.swift`
- Modify: `ios/AgentDeckMobile/Screens/SessionList/SessionListViewModel.swift`
- Modify: `ios/AgentDeckMobile/Screens/SessionDetail/{SessionDetailViewModel,MobileInputBarView}.swift`
- Modify: `ios/AgentDeckMobile/Screens/SessionDetail/Cells/ApprovalCardCell.swift`
- Modify: `ios/AgentDeckMobile/Screens/Inbox/InboxViewModel.swift`
- Modify: `ios/AgentDeckMobileTests/{FixtureSessionSourceTests,SessionDetailViewModelTests,MachineListViewModelTests,SessionListViewModelTests,InboxViewModelTests}.swift`

- [ ] Step 1: 先改tests为async SessionSource契约。 断言`start()`幂等且恰好一个subscription task；sendPrompt不调用start；sending→accepted/queued→canonical UserMessage commandId替换；offline保留draft；approval submitting→Applied；AlreadyHandled显示赢家+state；DeliveryFailed只能retry同决定；machine row分别呈现Relay不可达、machine offline、reconnecting、revoked、incompatible、securityError。
- [ ] Step 2: 运行iOS tests。 Expected: FAIL，现有source同步/无界/void receipt且viewmodel乐观更新。
- [ ] Step 3: 把FixtureSessionSource改为actor/Sendable facade实现，fixture返回确定receipt并使用bounded stream；迁移四组ViewModel和cell/input状态机。 fixture仍只用于preview/test。
- [ ] Step 4: 运行 `cd ios && xcodegen generate && xcodebuild -project AgentDeckMobile.xcodeproj -scheme AgentDeckMobile -destination 'platform=iOS Simulator,name=iPhone 17' test`。 Expected: 全部PASS；sendPrompt不会产生第二subscription。
- [ ] Step 5: 运行 `swift test`，确认shared targets无回归。
- [ ] Step 6: 提交。 `git add ios Package.swift Sources Tests && git commit -m "refactor(ios): 切换 SessionSource 与 daemon receipt 语义"`

### Task P5.6：实现 iOS 真配对、扫码/粘贴与前后台恢复

**Files:**
- Create: `ios/AgentDeckMobile/App/CompositionRoot.swift`
- Create: `ios/AgentDeckMobile/Screens/Pairing/{PairingViewModel,QRCodeScannerViewController}.swift`
- Create: `ios/AgentDeckMobileTests/{PairingViewModelTests,AppLifecycleTests}.swift`
- Modify: `ios/project.yml`
- Modify: `ios/AgentDeckMobile/App/SceneDelegate.swift`
- Modify: `ios/AgentDeckMobile/Screens/Pairing/PairingViewController.swift`
- Modify: `ios/AgentDeckMobile/Screens/MachineList/MachineListViewController.swift`

- [ ] Step 1: 写pair/lifecycle tests。invite version/expiry/wssURL/serverID/pins/root fingerprint；用户确认机器前零网络；pending keys+invite hash/requestHash+byte-identical PairRequest先落ThisDeviceOnly；PairPending显示waitingForLocalConfirmation，daemon canceled/expired显示明确terminal并擦除pending；retry完全相同；成功原子paired后发送DeviceSign-signed PairResponseReceived，回执重试不重复提升；revoke等signed terminal才删key；socket close不删；offline local-forget必须二次警告并提示回被控机撤销残留grant；background close WSS、foreground outer+inner resume。
- [ ] Step 2: 运行iOS Pairing/AppLifecycle tests。 Expected: FAIL，发行composition仍固定Fixture且Pairing是静态UI。
- [ ] Step 3: 实现真实Relay composition root、扫码和完整文本粘贴。 只提供完整QR/invite，不提供短PIN；`project.yml`增加相机说明和测试注入launch argument；不编辑生成文件。
- [ ] Step 4: 运行 `cd ios && xcodegen generate && xcodebuild -project AgentDeckMobile.xcodeproj -scheme AgentDeckMobile -destination 'platform=iOS Simulator,name=iPhone 17' test`，用注入的fake transport验证pair与lifecycle状态机。 Expected: PASS，重新前台不重配、不复用counter；真实synthetic Relay编排在P5.9单独验收。
- [ ] Step 5: 运行Keychain/crypto tests并清理Simulator paired state。
- [ ] Step 6: 提交。 `git add ios && git commit -m "feat(ios): 接入真实配对与前台 Companion 生命周期"`

### Task P5.7：建立 macOS LocalDaemonSessionSource 与 SessionSourceRegistry

**Files:**
- Create: `Sources/AgentDeck/SessionSources/{LocalDaemonSessionSource,SessionSourceRegistry,AppSessionSourceComposition}.swift`
- Create: `Tests/AgentDeckTests/{LocalDaemonSessionSourceTests,SessionSourceRegistryTests,MachineScopeRoutingTests}.swift`
- Modify: `Sources/AgentDeck/{SessionModel,WorkbenchModel,ThreadRuntimeModel,AppDelegate}.swift`
- Modify: `Package.swift`

**Registry rule:** local machine固定指向RuntimeEnvelope v1 UDS source；每台remote machine是独立`RelaySessionSource(.machine(id))`；UI只按machine scope取得`any SessionSource`；本机流量永不绕Relay。

- [ ] Step 1: 写registry/routing tests。local/remote同SessionSource facade、切machine取消旧observation、remote pair不影响local、local daemon offline typed state、preview显式fixture、ThreadRuntime使用canonical IDs且approval在receipt前不移除；只有local machine scope从registry取得`LocalPairingAdministration`，remote/fixture返回nil，禁止concrete downcast。
- [ ] Step 2: 运行三套Swift tests。 Expected: FAIL，registry/source不存在。
- [ ] Step 3: 封装现有RuntimeEnvelopeClient为LocalDaemonSessionSource并让它通过UDS实现`LocalPairingAdministration`，建立composition/registry的typed optional capability并迁移models。UI/model层不importCryptoKit或Relay wire，remote RelaySessionSource不实现本地批准能力。
- [ ] Step 4: 重跑Swift tests并同时连接local test daemon和remote synthetic machine。 Expected: 两个scope事件不串线，本机socket仍是UDS。
- [ ] Step 5: 运行N2/vendor branch lint与network boundary。
- [ ] Step 6: 提交。 `git add Package.swift Sources Tests && git commit -m "feat(macos): 统一本地与远程 SessionSource 路由"`

### Task P5.8：接入 AppKit machine scope、远程配对与 receipt UI

**Files:**
- Create: `Sources/AgentDeck/Machines/{MachineScopePickerView,RemotePairingSheetController,PendingDeviceApprovalController}.swift`
- Create: `Tests/AgentDeckTests/{MachineScopePickerTests,RemotePairingSheetTests,PendingDeviceApprovalTests}.swift`
- Modify: `Sources/AgentDeck/SessionSources/{LocalDaemonSessionSource,SessionSourceRegistry,AppSessionSourceComposition}.swift`
- Modify: `Sources/AgentDeck/{HistorySidebarViewController,InputBarView,ApprovalCardView,SessionViewController}.swift`
- Modify: `Sources/AgentDeck/Preview/PreviewBootstrap.swift`

- [ ] Step 1: 写AppKit assembly tests。 本机+remote机器选择、remote pair sheet机器root fingerprint确认、被控机local-only pending device fingerprint列表/approve/cancel、remote source不能出现批准入口、connection状态细分、prompt sending/queued/canonical、approval submitting/applied/alreadyHandled/deliveryFailed、preview fixture注入；禁止`if agentKind ==`决定数据源/渲染。
- [ ] Step 2: 运行新增tests与NoVendorBranchInUITests。 Expected: FAIL，machine scope/pair UI不存在。
- [ ] Step 3: 实现picker/remote pair sheet、pending-device approval controller和现有input/approval/sidebar接线。普通controller只调用SessionSource；PendingDeviceApprovalController注入`any LocalPairingAdministration`，由registry仅在local scope提供，不downcast concrete source。approve/cancel显示DeviceSign fingerprint与AlreadyHandled winner，请求方只见waiting/canceled/expired；本机入口无“经Relay”开关；远程错误显示typed原因。
- [ ] Step 4: 运行完整`swift test`与AppKit smoke/selfcheck。 Expected: PASS；关闭窗口不关闭daemon或remote source registry的其他scope。
- [ ] Step 5: 运行preview/golden UI tests并检查无新增SwiftUI。
- [ ] Step 6: 提交。 `git add Sources Tests && git commit -m "feat(macos): 加入远程机器 scope 与配对控制面"`

### Task P5.9：Simulator、物理iPhone与第二台macOS端到端门禁

**Files:**
- Create: `ios/AgentDeckMobileUITests/RelayCompanionUITests.swift`
- Create: `agentdeck-cli/examples/synthetic_machine.rs`
- Create: `scripts/run-relay-companion-simulator-e2e.sh`
- Create: `scripts/run-relay-companion-ios-device-smoke.sh`
- Create: `scripts/run-relay-companion-macos-e2e.sh`
- Modify: `ios/project.yml`
- Modify: `scripts/verify-relay-companion-mvp.sh`
- Modify: `README.md`, `ARCHITECTURE.md`, `docs/QUALITY.md`, `docs/AGENT_DIAGNOSTICS.md`, `docs/index.md`, `AGENTS.md`, `docs/RELAY_RUNBOOK.md`
- Modify: `docs/plans/2026-07-03-ios-uikit-frontend-design.md`

**Orchestrator inputs:** Simulator脚本只需本机工具链并自建temp TLS Relay/DB/synthetic machine/invite；物理iPhone脚本要求`AGENTDECK_IOS_DEVICE_E2E=1`、`AGENTDECK_IOS_DEVICE_UDID`、`AGENTDECK_DEVELOPMENT_TEAM`、`AGENTDECK_PUBLIC_RELAY_CONFIG`、`AGENTDECK_IOS_PAIR_INVITE_FILE`；第二Mac脚本要求`AGENTDECK_MACOS_REMOTE_E2E=1`、`AGENTDECK_REMOTE_MAC_SSH`、`AGENTDECK_REMOTE_MAC_APP_PATH`、相同Relay config/pinset、独立的`AGENTDECK_MACOS_PAIR_INVITE_FILE`和10分钟硬超时。两个invite都必须fresh/unused/unexpired，preflight验证pairRoute/requestHash互异并禁止任一文件复用。所有脚本preflight失败都非零退出且trap清理invite/temp DB/process。

- [ ] Step 1: 写UI/E2E tests与host harness。Simulator走temp TLS Relay+`cargo run -p agentdeck-cli --example synthetic_machine`完成PairRequest→requester waiting→被控机本地pending fingerprint读回/approve→pair/list/open/prompt/approval/reconnect/revoke；物理iPhone前台smoke经公开WSS用IOS专属invite完成同样的本地批准与控制流；第二控制Mac用另一份fresh invite独立配对并完成同流程，断言两个pairRoute/requestHash/grant不同，并验证远端自批被拒、Keychain/private-file absence与被控机本地App仍走UDS。
- [ ] Step 2: 运行 `bash scripts/run-relay-companion-simulator-e2e.sh`。 Expected: FAIL，host orchestrator/UI test target尚不存在。
- [ ] Step 3: 配置XcodeGen UI test target并实现三个orchestrator。 Simulator脚本负责启动/等待Relay和synthetic machine、生成invite、把路径与pin注入XCUITest、运行后读回结果并清理；iPhone脚本用指定UDID/Development Team运行signed test runner；Mac脚本经SSH执行安装/preflight/测试并读回远端Keychain/file scan。 verifier拒绝相同invite/route/requestHash，并把旧fixture设计标为preview/test-only历史事实。
- [ ] Step 4: 运行：
  ```bash
  swift test
  swift test --filter AgentDeckSessionSourceTests
  swift test --filter AgentDeckRelayClientTests
  bash scripts/run-relay-companion-simulator-e2e.sh
  AGENTDECK_IOS_DEVICE_E2E=1 bash scripts/run-relay-companion-ios-device-smoke.sh
  AGENTDECK_MACOS_REMOTE_E2E=1 bash scripts/run-relay-companion-macos-e2e.sh
  bash scripts/verify-relay-companion-mvp.sh p5
  scripts/verify-agent-docs.sh
  ```
  Expected: 默认/Simulator全部exit 0；gated物理iPhone与第二Mac分别输出pair/list/open/prompt/approval/reconnect evidence IDs；缺gated输入时明确BLOCKED，不能冒充P5退出门禁通过。
- [ ] Step 5: `git status --short --branch`，删除生成的xcodeproj/Info.plist变更、Keychain测试项、screenshots临时目录。
- [ ] Step 6: 提交。 `git add agentdeck-cli/examples/synthetic_machine.rs ios/project.yml ios/AgentDeckMobileUITests scripts README.md ARCHITECTURE.md AGENTS.md docs && git commit -m "test(companion): 收口 iOS 与远程 macOS 真链路"`

---

## Phase P6：Cross-device hardening、真实证据与运维收口

### Task P6.1：四 principal 多写者、故障注入与安全回归自动化

**Files:**
- Create: `agentdeckd/tests/multiwriter_e2e.rs`
- Create: `agentdeck-relay/tests/relay_v2_fault_injection_e2e.rs`
- Create: `agentdeck-cli/tests/remote_multiwriter_e2e.rs`
- Create: `Tests/AgentDeckRelayClientTests/CrossDeviceReducerTests.swift`
- Create: `ios/AgentDeckMobileTests/MultiWriterPresentationTests.swift`
- Modify: `scripts/verify-relay-companion-mvp.sh`

- [ ] Step 1: 写自动化矩阵。 用两个local UDS principal+两个remote device同时写同conversation，验证prompt严格commandSeq FIFO、不同conversation并行、approval恰好一赢家且四端state一致；注入Relay COMMIT前后、daemon五个exec boundary、Store full/busy/migration、slow reader、oversize/rate flood、revoke与prompt/approval竞态、counter rollback、gap/snapshot和key sync exhaustion。
- [ ] Step 2: 运行 `bash scripts/verify-relay-companion-mvp.sh p6-auto`。 Expected: FAIL，新suite尚未加入。
- [ ] Step 3: 完成fault harness、deterministic clock/failpoint和Swift presentation assertions；verifier默认运行所有不依赖vendor login/物理设备的测试。
- [ ] Step 4: 连续运行自动矩阵10次。 Expected: 每次相同canonical commandSeq/approval winner；无flaky sleep、无task leak、无明文sentinel。
- [ ] Step 5: 运行cargo/swift/iOS/network/schema/docs全门禁并整理工作区。
- [ ] Step 6: 提交。 `git add agentdeckd agentdeck-relay agentdeck-cli Sources Tests ios scripts && git commit -m "test(companion): 固化四端竞态与故障注入矩阵"`

### Task P6.2：完成运维工件、真实E2E harness 与独立代码复审

**Files:**
- Create: `packaging/agentdeck-relay.service`
- Create: `packaging/agentdeck-relay.toml.example`
- Create: `scripts/run-relay-companion-real-e2e.sh`
- Create: `scripts/verify-relay-companion-dod.sh`
- Create: `docs/evidence/relay-companion-mvp/README.md`
- Modify: `.gitignore`
- Modify: `README.md`, `NORTH_STAR.md`, `ARCHITECTURE.md`, `docs/QUALITY.md`, `docs/AGENT_DIAGNOSTICS.md`, `docs/index.md`, `AGENTS.md`, `docs/RELAY_RUNBOOK.md`

- [ ] Step 1: 写packaging/harness/verifier tests。 systemd固定non-root、NoNewPrivileges、ProtectSystem、PrivateTmp与最小data/cert路径；真实E2E preflight缺任一设备/config/login时BLOCKED且不生成summary；evidence manifest schema必须含source commit、tree digest、dirty=false、run ID、脱敏device IDs、redacted/raw artifact路径与hash；DoD verifier检查四schema、network/no-plaintext/no-token/no-cc-meta、LaunchAgent、foreground-only和§17证据槽位，并以fixture覆盖source commit祖先校验、candidate→HEAD差异allowlist、dirty/old/hash mismatch拒绝及`--require-local-raw`复算gitignored raw hash。
- [ ] Step 2: 运行packaging tests、真实脚本无环境preflight和`bash scripts/verify-relay-companion-dod.sh`。 Expected: 前两者按预期PASS/BLOCKED，DoD因尚无真实evidence而FAIL，且不会生成伪summary。
- [ ] Step 3: 实现systemd/config、从空环境读回runbook、真实E2E harness与完整DoD verifier。 verifier必须复算manifest/artifact hashes、确认source commit是当前HEAD祖先、只允许candidate→HEAD出现evidence与最终状态文档，并在`--require-local-raw`模式读回gitignored raw artifacts复算hash。原始未脱敏材料固定写入gitignored`artifacts/relay-companion-mvp/$RUN_ID/`；仓库内允许提交脱敏命令输出、日志摘录和截图，禁止invite/key/token/业务内容。
- [ ] Step 4: 使用`superpowers:requesting-code-review`做独立review，至少覆盖security boundary、crash recovery、Swift签名/并发/UI receipt、pair/reset、packaging；逐条复现并修复P0/P1，重复所有自动门禁。任何行为、安全或packaging修改必须在下一task重新采集真实证据。
- [ ] Step 5: 运行`bash scripts/verify-relay-companion-mvp.sh p6-auto`、packaging selfcheck、docs gate和`git status --short --branch`。 Expected: 所有自动门禁PASS，工作树只含本task文件，尚不把DoD宣称为完成。
- [ ] Step 6: 提交可供真实验收的干净candidate。 `git add .gitignore packaging scripts/run-relay-companion-real-e2e.sh scripts/verify-relay-companion-dod.sh README.md NORTH_STAR.md ARCHITECTURE.md AGENTS.md docs && git commit -m "chore(companion): 准备最终运维与真实验收候选"`

### Task P6.3：在干净candidate上执行真实跨网、两机配对与双agent证据运行

**Files:**
- Create after successful run: `docs/evidence/relay-companion-mvp/latest-redacted-summary.md`
- Create after successful run: `docs/evidence/relay-companion-mvp/runs/$RUN_ID/manifest.json`
- Create after successful run: `docs/evidence/relay-companion-mvp/runs/$RUN_ID/commands-redacted.md`
- Create after successful run: `docs/evidence/relay-companion-mvp/runs/$RUN_ID/relay-sentinel-redacted.md`
- Create after successful run: `docs/evidence/relay-companion-mvp/runs/$RUN_ID/screenshots/iphone-redacted.png`
- Create after successful run: `docs/evidence/relay-companion-mvp/runs/$RUN_ID/screenshots/macos-redacted.png`

**Gated inputs:** `AGENTDECK_REAL_E2E=1`、真实公网WSS、两个可丢弃的被控Mac用户/profile trust domains、物理iPhone、第二控制Mac、remote CLI、Codex login、Claude Code login。脚本只允许从clean P6.2 candidate commit启动；记录source commit/tree digest/dirty=false并在结束时复算。root-lost演练只在可丢弃trust domain二次确认后执行。

- [ ] Step 1: 运行preflight。 检查两个被控machine/profile、iPhone UDID/Development Team、控制Mac SSH、CLI installation、public WSS CA/pin、vendor login、candidate clean tree。 Expected: 任一缺失都BLOCKED且不创建evidence run。
- [ ] Step 2: 让iPhone分别用两个独立PairInvite向两台被控机器发起配对；每台机器都由本地App/CLI读回并确认不同DeviceSign fingerprint，先证明远端自批被拒，再记录不同root fingerprint/route/Keychain account/grant；在其中一台丢弃首次response并证明byte-identical PairRequest retry取回同一grant。
- [ ] Step 3: 执行client×agent×action矩阵。 物理iPhone必须亲自对Codex和Claude Code完成list/open/start/continue/prompt/approval/history/reconnect并读回完整canonical stream；远程Mac与CLI完成各自pair/control/reconnect；本地App加入同conversation四端竞态，并验证关闭本地App后turn/daemon继续。 iPhone记录cellular`NWPath`，Relay只记录脱敏source-network hash，用两者证明与被控机不同网络。
- [ ] Step 4: 执行安全、重启与两条独立reset run。 Relay/daemon/iOS network restart后不重配；sentinel在Relay DB/log/metrics/binary outer frame为0业务明文，vendor resume reference在client解密payload仍0 match；伪造/rollback/nonce/pin攻击fail-closed；revoke在2秒内terminal/close。 Run A有root：RetireMachine→purge/readback absent→重新enroll/pair。 Run B在新的有效route上删除root：remote blocked→admin purge/readback absent→再重新enroll/pair。
- [ ] Step 5: 生成manifest、脱敏命令/log摘录和脱敏截图；逐个打开artifact并复算hash，确认source commit/tree仍匹配且raw artifact存在。 任何测试暴露行为、安全或packaging缺陷时，废弃本run、回P6.2修复提交并从Step 1重跑，禁止沿用旧summary。
- [ ] Step 6: 只提交evidence。 核对`git diff --name-only $SOURCE_COMMIT..HEAD`在run前为空，run后stage仅`docs/evidence/relay-companion-mvp`，再`git commit -m "test(companion): 留存真实跨网与双 agent 验收证据"`。

### Task P6.4：验证当前candidate绑定的13项DoD并更新状态

**Files:**
- Modify: `docs/plans/2026-07-10-relay-companion-mvp-design.md`
- Modify: `docs/plans/2026-07-10-relay-companion-mvp-implementation.md`
- Modify: `README.md`, `NORTH_STAR.md`, `ARCHITECTURE.md`, `docs/QUALITY.md`, `docs/AGENT_DIAGNOSTICS.md`, `docs/index.md`, `AGENTS.md`, `docs/RELAY_RUNBOOK.md`

- [ ] Step 1: 运行P6.2已提交的DoD verifier读回P6.3 manifest与已提交脱敏artifacts；确认它复算hash、校验source commit祖先与candidate→HEAD差异allowlist，并用`--require-local-raw`读回gitignored raw artifacts。此task不得扩展或修改verifier；若能力缺失或校验失败，必须回P6.2修复、提交新candidate并重跑P6.3。
- [ ] Step 2: 更新设计状态为Implemented、本计划全部完成task checkbox和最终candidate/evidence IDs；只写已经由P6.3证明的事实。
- [ ] Step 3: 运行最终命令：
  ```bash
  cargo test
  cargo test -p agentdeck-relay --features server,tls --test relay_v2_hardening_e2e -- --test-threads=1
  cargo test -p agentdeck-relay --features server,tls --test relay_v2_security_e2e -- --test-threads=1
  swift test
  bash scripts/run-relay-companion-simulator-e2e.sh
  bash scripts/check-daemon-network-boundary.sh
  bash scripts/verify-relay-companion-mvp.sh p6
  bash scripts/verify-relay-companion-dod.sh --require-local-raw
  scripts/verify-agent-docs.sh
  ```
  Expected: 全部exit 0；DoD输出`13/13 verified`并打印与当前candidate绑定的真实run ID。 任一失败若需要改代码/security/packaging，必须回P6.2提交新candidate、废弃旧evidence并完整重跑P6.3，不能在本task就地修后沿用旧run。
- [ ] Step 4: 独立人工读回README/ARCHITECTURE/QUALITY/DIAGNOSTICS/Relay runbook中的install/enroll/pair/revoke/reset/systemd/LaunchAgent命令，确认没有把Simulator/loopback/旧evidence写成真实闭环。
- [ ] Step 5: 运行`git diff --check`与`git status --short --branch`；Expected: 只含本task状态文档，任何代码/packaging差异都必须回P6.2并重跑P6.3。
- [ ] Step 6: 提交最终收口。 `git add README.md NORTH_STAR.md ARCHITECTURE.md AGENTS.md docs && git commit -m "docs(companion): 完成 Relay Companion MVP 运维与 DoD 收口"`

---

## Definition of Done 证据映射

| 设计 §17 条目 | 自动门禁 | 必需真实证据 |
|---|---|---|
| 1. 唯一常驻 daemon | `daemon_namespace`、`shared_daemon`、`verify-daemon-install.sh` | `launchctl print`、同一PID、关闭App后turn继续 |
| 2. 可安装可升级 | `daemon_install`、`upgrade_idle` | 干净用户profile install/stage/idle-switch/uninstall/purge读回 |
| 3. 真实独立配对 | `pairing_state_machine`、iOS Pairing tests | iPhone对两台机器分别pair，Keychain与byte-identical retry证据 |
| 4. 真实双agent控制 | gated `e2e_remote_codex`/`e2e_remote_claude_code` | 物理iPhone的真实Codex/CC open/prompt/approval/history |
| 5. 多写者确定性 | `multiwriter_e2e`、`remote_multiwriter_e2e` | 本地App、远程Mac、iPhone、CLI同conversation结果对照 |
| 6. 普通重启连续 | `runtime_crash_recovery`、`remote_crypto_recovery`、resume tests | clean daemon/Relay/iOS network restart与存活orphan演练 |
| 7. 撤销与reset | `relay_v2_revocation_e2e`、enrollment/reset tests | 2秒terminal、RetireMachine、root-lost admin purge、旧route读回 |
| 8. daemon来源可验证 | crypto/security suites | 恶意device/Relay伪造与rollback/nonce攻击结果 |
| 9. Relay严格最小可见 | neutrality与sentinel suites | 真实Relay DB/log/metrics/outer bytes的0-match报告 |
| 10. 真实跨网 | 无默认CI替代 | 物理iPhone不同网络pair→reconnect截图/命令/log hash |
| 11. 第二桌面远控 | registry/macOS gated script | 第二Mac Keychain、完整控制流、本机仍UDS |
| 12. 全质量门禁 | `verify-relay-companion-dod.sh` | gated vendor/physical suites的redacted summary |
| 13. 运维文档可执行 | docs gate、selfcheck、packaging tests | 空环境按runbook部署Relay/daemon并读回 |

## 实施执行方式

1. **Subagent-Driven（推荐）**：当前会话使用 `superpowers:subagent-driven-development`；每个task交给独立实现agent，主agent在task间做spec/quality双重review并运行阶段门禁。适合本计划的多crate、多平台和安全边界。
2. **Inline Execution**：在单一执行会话使用 `superpowers:executing-plans`，严格按task顺序推进并在每个Phase退出门禁停下复核。适合不希望并行改同一工作区时使用。

无论选择哪种方式，P2.9原子cutover、P3.7 exec-gate、P4.5 counter recovery和P6.3真实设备证据禁止并行修改；这些task必须串行并在进入下一task前完成独立review。
