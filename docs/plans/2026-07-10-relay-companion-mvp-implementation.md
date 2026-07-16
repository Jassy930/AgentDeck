# AgentDeck Relay Companion MVP 实施计划

> **执行 harness：** 按 task TDD、独立 spec/security/quality review、scoped commit 推进。旧计划提到的
> `superpowers:*` skill 在当前 harness 不可用，不得声称已调用；使用当前可用的独立 subagent review 与
> controller fresh gates 等价执行。Steps 使用 checkbox（`- [ ]`）追踪。

**Goal:** 交付一个真实可用的端到端 Companion MVP：每个被控 macOS 登录用户只有一个 `launchd` 常驻 `agentdeckd`，本地 App/CLI 与多个远程 macOS/iOS/CLI 客户端共享同一 RuntimeCore；Relay 严格最小可见，Codex 与 Claude Code 均通过真实链路完成浏览、prompt、审批、重连与多写者裁决。

**Architecture:** P1–P3.8 先以 `RuntimeEnvelope v1` 建立 UDS/Core 基线；P3.9-C0 因新增 configuration、agent discovery 与 canonical metadata mutation，把共同业务 wire 原子升级为 `RuntimeEnvelope v2`，不提供 production v1/v2 双栈。`agentdeckd` 持有唯一 RuntimeCore、稳定 conversation 身份、SQLite journals、per-conversation actor、approval CAS 与两阶段 exec gate；Relay v2 只持有随机 route/stream/request 元数据、公开授权材料和 opaque sealed blob；Swift 的 `AgentDeckSessionSource` 统一本地与远程数据源，`AgentDeckRelayClient` 实现 WSS、CryptoKit、Keychain、replay 和 bounded stream。

**Tech Stack:** Rust 2024、Tokio、rusqlite/SQLite WAL、rustls、`hpke 0.14`、ChaCha20-Poly1305、Ed25519；Swift 6、Foundation/CryptoKit/URLSessionWebSocketTask、AppKit、UIKit、XCTest；macOS 15+、iOS 17+、XcodeGen、launchd、Linux systemd Relay。

**批准的设计事实源:** `docs/plans/2026-07-10-relay-companion-mvp-design.md`。实施中若发现设计无法落地，先更新设计决策与本计划，再继续代码；不得在实现里静默改变信任边界。

## Global Constraints

- 版本轴彼此独立：现有 local IPC `PROTOCOL_VERSION = 2`；Runtime 初始基线
  `RUNTIME_PROTOCOL_VERSION = 1`，P3.9-C0 因 wire 形态变化独立升级到 2；Relay
  `RELAY_PROTOCOL_VERSION = 2`；`E2EE_FORMAT_VERSION = 1`。Runtime bump 会进入 Relay cert/TBS 与
  compatibility vectors，但不得顺带改变 Relay/E2EE 自身版本常量。
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
- 资源硬上界：Relay frame 4 MiB；compact remote raw part 3.5 MiB；JSON/UDS raw part 固定
  700 KiB，并以 worst-case 实际编码证明完整 `RuntimeEnvelope` 严格小于 JSONL/UDS 1 MiB hard
  cap；compact transfer 最多 64 parts，JSON/UDS 最多 94 parts，两者共同受 64 MiB/5 分钟
  总上界；prompt 256 KiB；每 conversation
  32 个 queued prompt；全机 1,024 个/256 MiB/24 小时；Runtime DB 2 GiB。
- P3.6 固定配额：subscription 64/connection、4,096 global；pending capture 4/connection、
  128 global（Store capture/spawn 前准入）；barrier 4/connection、128 global、
  absolute TTL 5 分钟；snapshot sender 1/connection、2 global、build memory 128 MiB；transfer active
  64/connection，reassembly 128 MiB/connection+512 MiB global，completed tombstone 256/connection+
  8,192 global/5 分钟；read-only WAL pool 8、128 MiB、64 rows/8 MiB；publication dispatch
  64 rows/8 MiB、16 MiB；backfill 512 rows/64 MiB；snapshot 10,000 items/64 MiB。
- writer 默认 512 frames/16 MiB；Relay retention 默认每 stream 2,000 frames/64 MiB/24h、每 machine 512 MiB、全局 4 GiB；receive replay window 每 key 4,096 个 counter。
- Machine enrollment code与PairInvite secret均为256-bit随机值、5分钟单次；challenge nonce为32 bytes、30秒单次；approval自动投递每轮最多8次且60秒，默认deadline 30分钟；revoke terminal flush上限2秒。
- `AgentDeckCore` 继续只依赖平台无关 Foundation/Observation，不 import AppKit/UIKit/CryptoKit/网络。Swift 网络与 crypto 只在 `AgentDeckRelayClient`；UI 不拼 wire/crypto bytes。
- MVP 明确不引入 APNs、后台常驻 WSS、离线 transcript 数据库、附件、多租户/团队 ACL、托管 Relay 或账户级密钥恢复；iOS 后台主动断开，回前台从 cursor/snapshot 恢复。
- 不读取、不保存、不转发 Codex 或 Claude Code token；不创建 `cc-meta/`；不把 Runtime DB、Relay DB、日志、invite、证书私钥、Keychain 导出或用户项目数据提交进 git。
- 每个 task 都执行“新增失败测试→确认预期失败→最小实现→确认通过→文档/工作区检查→scoped commit”。不带 co-author，不执行 `git push`。
- 每个commit前先用`git status --short`和`git diff --name-only`核对当前task的Files；文中的目录级`git add`必须在执行时展开为本task实际变更的精确pathspec，任何用户既有/并行无关改动保持unstaged；禁止`git add -A`。
- Phase 状态分为“实现/自动门禁 candidate”与“真实退出门禁”两层。外部 provisioning、vendor login、
  公网 WSS、物理设备或第二台机器缺失时，可以在代码依赖已满足后继续后续自动实现，但对应 gated step、
  Phase exit 与 DoD 必须保持 BLOCKED；不得把 synthetic/Simulator/loopback 结果改写成真实完成。

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

> 本 task 记录 P1 的初始 contract；P3 stream 实现前必须先执行 P3.6-A contract finalization，
> P3.6-A 冻结的 cursor/identity/backfill/transfer 形状是后续唯一事实源。

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
- [x] Step 6: 已精确暂存本阶段的 protocol、Relay/admin/enrollment、测试、依赖锁与文档改动，并提交为 `ddc7250 feat(relay): 加入本机管理面与 machine enrollment`；未包含构建产物、运行数据或本地 SDD ledger。

### Task P2.8：重写 Rust Relay client 为 v2 WSS/pin client

**Files:**
- Create: `agentdeck-relay-client/src/v2/{mod,transport,connection,tls}.rs`
- Create: `agentdeck-relay-client/tests/relay_v2_client.rs`
- Modify: `agentdeck-relay-client/src/lib.rs`
- Modify: `agentdeck-relay-client/Cargo.toml`
- Modify: `agentdeck-protocol/src/{e2ee/pairing,relay_v2/enrollment,relay_v2/mod}.rs` 与 contract tests
- Modify: `agentdeck-cli/Cargo.toml`、`agentdeck-relay/Cargo.toml` 与真实 TLS client E2E（仅P2.9前显式`v1-compat`构建桥）
- Modify: `README.md`、`docs/{QUALITY,AGENT_DIAGNOSTICS,RELAY_RUNBOOK}.md`

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

- [x] Step 1: 已写9个网络contract tests、5个supervisor单测和compile-fail API隔离；覆盖CA/pin/hostname/redirect、binary/fresh reconnect/signed terminal、TLS-before-enrollment-secret+receipt、自动Pong、control reserve/outcome-unknown/abort、typed pairing/close ACK与4MiB上限。
- [x] Step 2: 已保留RED证据：新增测试最初因`RelayClientConfig`/`RelayTlsPolicy`不存在而编译失败；实现后focused与完整client均转绿。
- [x] Step 3: 已实现默认纯client crate。三种TLS策略不互相降级；principal/enrollment/pairing互斥；后台single reader/writer、有界data/control/urgent预算和fresh auth reconnect均已落地。P2.9前旧调用方仅通过非默认`v1-compat`显式桥接，避免workspace红态。
- [x] Step 4: client 5 unit + 9 integration + 1 compile-fail通过，真实Relay TLS E2E 11/11通过；默认normal tree不含`agentdeck-relay`、axum、rusqlite。receipt helper上移protocol，PairInvite/PairRequest/PairingEvent Debug脱敏。
- [x] Step 5: focused clippy `-D warnings`、rustdoc、rustfmt、protocol/client/Relay TLS回归、dependency tree与diff gate纳入本阶段门禁；独立安全复审无剩余P0/P1/P2。
- [x] Step 6: 已精确暂存client、protocol helper/redaction、真实Relay集成、临时consumer feature桥、依赖锁与阶段文档，并提交为 `ecf8102 feat(relay-client): 切换 v2 WSS 与 SPKI pin`；未包含构建产物、运行数据或本地SDD ledger。

### Task P2.9：原子切换 binary/CLI synthetic tests 并删除 Relay v1 生产代码

**Files:**
- Modify: `agentdeck-cli/src/{main,remote}.rs`, `agentdeck-cli/Cargo.toml`
- Modify: `agentdeck-protocol/src/{lib,neutrality_tests}.rs`, `agentdeck-protocol/src/{relay_v2/enrollment,runtime/{command,mod}}.rs`, `agentdeck-protocol/tests/relay_v2_contract.rs`, `agentdeck-protocol/Cargo.toml`
- Modify: `agentdeck-relay/src/{lib,main,config}.rs`, `agentdeck-relay/src/v2/{admin/command,server/mod}.rs`, `agentdeck-relay/tests/{relay_v2_admin_e2e,relay_v2_route_e2e}.rs`, `agentdeck-relay/Cargo.toml`
- Modify: `agentdeck-relay-client/src/{lib,v2/connection}.rs`, `agentdeck-relay-client/tests/relay_v2_client.rs`, `agentdeck-relay-client/Cargo.toml`
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
- Create: `agentdeck-relay/tests/relay_v2_cutover.rs`
- Modify: `protocol/agentdeck/runtime-protocol.schema.json`

- [x] Step 1: 已先写真实 DirectTLS/SPKI synthetic CLI E2E：一次性 enrollment、machine/device fresh challenge auth、InstallGrant、publish-before-subscribe byte-exact replay、Send/Reply、root-signed revoke terminal及重连 canonical bytes；SQLite/readback 与 AEAD sentinel 同时证明 opaque payload。
- [x] Step 2: 已保留 RED：旧 CLI 无 `synthetic --bundle` 且仍依赖 v1 surface；依赖切割后编译器进一步暴露所有旧 protocol/relay/client/daemon 引用。
- [x] Step 3: CLI 与 Relay binary/config/dependencies 已原子切到 v2；旧 protocol、server/router/store、client、daemon bridge 和测试已删除。旧 credential marker 只做 no-follow metadata 探测且零写/零拨号；旧 flag/env fail-close，persistent remote 在 P4 前返回 typed unsupported。
- [x] Step 4: `cargo test --locked` 全 workspace 通过；四份 schema byte-identical diff 通过；v1 production sentinel `rg` 零命中。Runtime 描述去除旧 seen-map 术语后已同步 schema 快照；Rustls 双 provider feature-unification 回归也已修复。
- [x] Step 5: `bash scripts/check-daemon-no-net.sh` 通过；CLI 与 relay-client normal dependency tree 均不含 Relay server/axum/rusqlite。
- [x] Step 6: 已精确stage并核对删除/修改清单，提交为 `edb9fa8 feat(relay): 原子切换 Relay v2 并移除 v1 生产路径`；未提交构建产物、运行数据或本地 SDD ledger。

### Task P2.10：Relay v2 hardening E2E、sentinel 与阶段文档收口

**Files:**
- Create: `agentdeck-relay/tests/{relay_v2_hardening_e2e,relay_v2_security_e2e}.rs`
- Modify: `scripts/verify-relay-companion-mvp.sh`
- Modify: `README.md`, `ARCHITECTURE.md`, `docs/QUALITY.md`, `docs/AGENT_DIAGNOSTICS.md`, `docs/index.md`, `AGENTS.md`
- Modify: `docs/RELAY_RUNBOOK.md`, `protocol/agentdeck/README.md`

- [x] Step 1: 已新增阶段级 hardening/security tests；完整矩阵由 Store/Auth/Stream/Revocation/Lifecycle/TLS 专项 suite 与两个组合 suite 共同承担。安全 sentinel 以六类 endpoint 明文经真实 AEAD+发送方签名后走生产 DirectTLS/WSS Challenge→Authenticate→RegisterStream→Publish/Core，并扫描 outer、响应、tracing、HTTP/metrics surface 和 SQLite DB/WAL 为零明文。
- [x] Step 2: 已对更新前 `HEAD` verifier 执行 `p2`，精确返回 usage 与 exit 2；保留了脚本尚只接受 `p0` 的 RED 证据。
- [x] Step 3: verifier 已支持 `p0|p2`，P2 明确编排全套专项矩阵、两个组合 suite、真实 CLI synthetic、四 schema、no-net、依赖边界和 v1 生产符号扫描；入口文档同步为当前仅 Relay v2，旧 R0/R1 只保留为历史记录。
- [x] Step 4: 已运行：
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
  全部 exit 0；统一 `p2` 门禁最终输出 PASS，security suite 输出
  `0 plaintext matches in outer + logs + HTTP/metrics + SQLite DB/WAL`。门禁首轮还真实抓到
  macOS `TMPDIR` 尾斜线形成非 canonical storage path，脚本改为 `pwd -P` 后完整重跑通过。
- [x] Step 5: 已执行 `git status --short --branch` 与 artifact 扫描；工作树只含本 task 的两套测试、verifier 与入口文档，无 Relay DB、证书私钥副本或日志产物。`.build/build.db` 是既有 gitignored Swift 构建缓存，不纳入 stage。
- [x] Step 6: 已精确暂存本 task 的 12 个文件并提交为
  `db74261 test(relay): 收口 v2 安全与故障门禁`；验证脚本的 executable bit 在随后的
  阶段记录提交中恢复，未提交 build/DB/log/secret 或本地 SDD ledger。

---

## Phase P3：Singleton RuntimeCore、UDS 与 LaunchAgent

### Task P3.1：建立 stable/ephemeral namespace、singleton lock 与 StorageKEK Keychain

**Files:**
- Create: `agentdeckd/src/{config,security/mod,security/key_store,security/macos_keychain}.rs`
- Create: `agentdeckd/src/runtime/{namespace,singleton}.rs`
- Create: `agentdeckd/tests/{daemon_namespace,daemon_startup,storage_kek}.rs`
- Modify: `agentdeckd/src/{lib,main,record}.rs`
- Modify: `agentdeckd/Cargo.toml`
- Modify: `Cargo.lock`
- Modify: `agentdeck-cli/src/transport.rs`
- Modify: `Sources/AgentDeck/ProcessDaemonTransport.swift`
- Create: `Tests/AgentDeckTests/ProcessDaemonTransportTests.swift`
- Modify: `README.md`, `ARCHITECTURE.md`, `AGENTS.md`
- Modify: `docs/{QUALITY,AGENT_DIAGNOSTICS,index}.md`

**Core interface:**
```rust
pub enum DaemonMode { Stable, Ephemeral { instance_id: String } }
pub struct DaemonPaths { pub data_dir: PathBuf, pub runtime_db: PathBuf, pub socket: PathBuf, pub lock: PathBuf, pub keychain_service: String, pub keychain_access_group: Option<String> }
pub trait KeyStore: Send + Sync { fn load(&self, account: &str) -> Result<Option<SecretBytes>, KeyStoreError>; fn store(&self, account: &str, value: &SecretBytes) -> Result<(), KeyStoreError>; fn delete(&self, account: &str) -> Result<(), KeyStoreError>; }
```

**Stable paths:** data root=`<OS account home>/Library/Application Support/AgentDeck`，DB=`runtime.db`，UDS=`agentdeckd.sock`，lock=`agentdeckd.lock`，Keychain service=`com.agentdeck.agentdeckd.stable`；home 通过当前 EUID 的 `getpwuid_r` 取得，不信任可变 `HOME`。release helper 的 daemon-only access group 必须是 entitlement 中展开后的`<实际 TeamIdentifier>.com.agentdeck.agentdeckd.stable`，并在编译时通过`AGENTDECK_DAEMON_KEYCHAIN_ACCESS_GROUP`注入；运行时环境不能替换，主App/CLI不持有该 entitlement。ephemeral 的 data root/DB/socket/lock/service 共享同一随机 instance ID 并位于私有 temp namespace。

- [x] Step 1: 已先写 namespace/lock/Keychain 与 binary startup tests。覆盖 stable 固定路径与 OS home、不完整 mode matrix、ephemeral 全资源隔离、第二进程锁拒绝、symlink/hardlink/宽权限拒绝、stable 旧目录仅精确 0755→0700 安全迁移（0775/0777/01755 拒绝）、fresh StorageKEK、DB/WAL/SHM 已存在时缺 key fail-close、持久化读回不一致和 secret Debug redaction。
- [x] Step 2: 已保留 TDD RED（缺少 config/security/namespace API），再运行聚焦矩阵；当前 `daemon_namespace` 18/18、`daemon_startup` 4/4、`storage_kek` 14 PASS，另有 1 个真实签名 Keychain roundtrip 按预期 gated ignored。
- [x] Step 3: 已实现 P3.1 当时的固定启动序列 `config → private namespace/singleton → keystore → StorageKEK → record namespace → selfcheck/stdio loop`。data root 以 0700 原子创建；只对当前 UID 拥有、权限精确为旧版 0755 的固定 stable 目录，在已 `O_NOFOLLOW` 打开的 directory fd 上收紧到 0700，其他宽权限拒绝；lock 只经该 dirfd 的 `openat` 建立，并在 `flock` 前后核对 owner/mode/nlink/dev/ino。stable Keychain 使用 protected、non-synchronizable、`AccessibleAfterFirstUnlockThisDeviceOnly`、空 access-control flags，缺 entitlement/backend 失败即关闭且无 memory/明文回退；ephemeral 才使用独立 memory store。P3.8 后过渡 stdio 调用方显式传 `--stdio-compat --ephemeral --no-remote --profile dev` 并移除继承的旧 namespace env；默认 shared-daemon client 切换仍属于 P3.9。
- [ ] Step 4: **GATED / BLOCKED（不是 PASS）**。唯一 service/account、RAII 清理的 ignored roundtrip 已存在，但本机没有匹配 access group 的 provisioning profile；Apple Development 与本地 self-signed helper 均可通过 `codesign --verify`，实际启动都被 AMFI 以 exit 137 终止。因此尚无真实 `set → load → delete` Keychain 读回证据，不能勾选本步，也不能据此宣布 P3.1/P3 完成；须在具备匹配 provisioning/entitlement 的已签名 helper 上重跑。
- [x] Step 5: 已运行聚焦 Rust tests、CLI tests、Swift tests、daemon no-net、`cargo fmt --check`、`git diff --check` 与 scoped clippy；结果为 CLI 27/27、Swift 243 XCTest + 35 Swift Testing、no-net/diff-check 通过，scoped clippy 在显式允许仓库既有 7 类 baseline lint 后以 `-D warnings` 通过。真实 `cargo run -q -p agentdeck-cli -- selfcheck` 返回 `ok`、`protocolVersion=2` 与双 adapter，临时 namespace 已清理；主执行者提交前又重跑完整 `cargo test`，全 workspace 通过（只有本 task 明确记录的真实签名 Keychain gate ignored）。
- [x] Step 6: 已核对 daemon、两个 stdio transport、测试与文档精确 pathspec，未使用 `git add -A`；提交为 `835a7b3 feat(daemon): 建立 singleton namespace 与 StorageKEK`。Step 4 仍是外部签名条件 gated，故该提交不构成 P3.1/P3 完成声明。

### Task P3.2：实现 Runtime SQLite journal、稳定身份与存储上界

**Files:**
- Create: `agentdeckd/src/runtime/model.rs`
- Create: `agentdeckd/src/runtime/store/{mod,worker,schema,sqlite,admission,cipher,recovery}.rs`
- Create: `agentdeckd/tests/runtime_store.rs`
- Modify: `agentdeckd/src/runtime/mod.rs`
- Modify: `agentdeckd/Cargo.toml`

**Core interface:**
```rust
impl RuntimeStoreHandle {
    pub async fn create_conversation(&self, input: NewConversation) -> Result<ConversationRecord, RuntimeStoreError>;
    pub async fn accept_command(&self, input: AcceptCommand) -> Result<AcceptOutcome, RuntimeStoreError>;
    pub async fn mark_started_with_event(&self, input: StartCommand) -> Result<StartOutcome, RuntimeStoreError>;
    pub async fn persist_execution_fence(&self, fence: ExecutionFence) -> Result<ExecutionFenceRecord, RuntimeStoreError>;
    pub async fn complete_command_with_event(&self, input: CompleteCommand) -> Result<CompleteOutcome, RuntimeStoreError>;
    pub async fn begin_recovery_scan(&self) -> Result<RecoveryCursor, RuntimeStoreError>;
    pub async fn load_recovery_page(&self, cursor: RecoveryCursor) -> Result<RecoveryPage, RuntimeStoreError>;
    pub async fn finish_recovery_scan(&self, completion: RecoveryCompletion) -> Result<(), RuntimeStoreError>;
}
```

Store 保留 SQLite/IO/crypto/commit-unknown 的内部精确语义，P3.4 `RuntimeCore` 才把
`RuntimeStoreError` 映射成 wire `RuntimeFailure`。`CommandReceipt` 的 wire 状态只有
Accepted/Replayed/Failed，因此 completion 必须返回内部 `CompleteOutcome`，不能伪造
不存在的 Completed receipt。

**Runtime DB schema 演进:** P3.2 schema v1 只创建本阶段实际负责并能验证的
`runtime_meta`、`conversations`、`commands`、`execution_intents`、`execution_fences`、
`event_journal`，以及不经 StorageKEK 包装的非秘密 rescue index
`machine_enrollment_receipts(relay_server_id, machine_route, root_fingerprint)`。P3.3 直接新增
两个 adapter 私有 namespace，不先创建再拆通用 `adapter_state_index`；P3.5 添加
`approval_ledger`；P3.6 schema v4 精确添加 `event_stream_index`、`event_retention`、
`catalog_journal`、`snapshots`、`publication_streams`、`publication_outbox` 六表，`event_journal`
继续作为 authenticated audit；P4 由各自 task migration 添加
auth/key/counter/replay/pair/revoke/retirement 表。machine-wide admin idempotency 使用独立
`admin_commands` 表，由真正拥有 admin 语义的后续 task 添加，不塞入 nullable command rows。

**2 GiB 边界:** 标准 SQLite 没有 custom quota VFS 时，不能把 `max_page_count` 冒充 active
WAL 的瞬时物理零超冲保证。MVP 固定使用 main+WAL+SHM observed footprint、保守 projected
transaction growth、`max_page_count`、有界 WAL checkpoint 与写后读回共同做 fail-closed
准入；checkpoint 被 reader 阻塞或接近水位时停止普通副作用。若未来要求任何瞬间绝不超过
2 GiB，必须另做 custom quota VFS。

**恢复物化边界:** 全库 `RecoveryState` 会让合法 256 MiB Accepted queue 因 sealed/struct
开销超过同名 lane cap，并让极端 Started event 接近 2 GiB OOM，因此生产 API 改为三阶段
paged recovery。begin 先 streaming integrity validation 与 expiry sweep，再冻结 authenticated
catalog HWM；page 使用 store 签发的 exact keyset cursor，每页一个 conversation，最多
32 Accepted + 一个 Started，retained hard cap 80 MiB；finish 只有累计 counts 与冻结 ledger
一致，并再次完成全库 integrity readback 后才开放 mutation。P3.4 必须逐页消费，禁止重新 collect。

**认证边界:** BIK MAC 覆盖 command/conversation/event canonical 元数据，`runtime_meta`
authenticated ledger 覆盖 catalog/queue/safety counters 与 conversation/command/event/intent/fence
总数；open/begin 流式认证 descriptor/全部行、逐 conversation actual MAX HWM、审计 linkage
和 orphan count，finish 在开放 mutation 前再验证一次。该机制不检测“整套 main+WAL 回滚到更早但内部自洽的有效快照”，必须由 P4
Keychain CounterGuard 绑定 generation/HWM 后闭环。非秘密 enrollment receipt 只是 root-lost
locator，P4 purge 必须另验 Relay/admin-signed receipt。

**执行记录（2026-07-11，P3.2-A～F，已完成）:** 已完成专用 blocking worker 的有界 normal lane 与
独立 shutdown control lane、严格七表 schema v1、WAL/FULL/FK/limit 读回、StorageKEK 包装的
行密钥/盲索引密钥、随机 nonce 行密文、真实 live `sqlite_schema` manifest 校验，以及 DB/WAL/SHM
owner/mode/nlink/symlink 预检。fresh DB 只在临时库完整 COMMIT + fsync 后原子 no-replace 发布；
错误 KEK、未知/更高 schema 与 live manifest drift 均在持久化 PRAGMA 前零写入拒绝。非秘密
machine enrollment rescue index 可在无 KEK 时读取 main DB 或已提交 WAL；WAL 恢复只发生在私有
副本，不改原始三文件。C～F 已加入 stable sequence/idempotency、单 Started/fence/release、
authenticated metadata/ledger、真实 COMMIT 分类、safety reserve、persistent WAL/显式 checkpoint
copy-peak、shutdown quiescence 与 paged recovery。当前最新聚焦证据：`runtime_store` 27/27、
`runtime_store_boundaries` 5/5、`runtime_store_capacity` 8/8、`runtime_store_hardening` 20/20、
`runtime_store_journal` 5/5、`runtime_store_recovery` 4/4。加入五类 authenticated total、
descriptor/HWM/finish 再验证后，完整 `cargo test -p agentdeckd -- --test-threads=1` 全绿；真实
1,024 × 256 KiB 项 262.35s，唯一 provisioned signed Keychain test 仍按 P3.1 既有边界
ignored/GATED。独立安全复核与容量/恢复/关停复核均未发现 P0/P1/P2。实现提交为
`8744750 feat(daemon): 建立 Runtime 持久化 journal`。

- [x] Step 1: 写store tests。 覆盖daemon先生成stable IDs，commandSeq/eventSeq/catalogRevision跨重启单调，Accepted COMMIT，conversation-scoped idempotency ledger至少保留30天；machine-wide admin ledger留给所属后续task。2GiB准入按main DB+WAL+SHM observed+projected总量、`max_page_count`与有界checkpoint共同计算，另保留512MiB或文件系统5%（取较大者）；1,024 prompts/256MiB/24h；disk-low拒绝新副作用但继续read/safety/rescue/diagnostics；敏感row非明文；删除全部Keychain item后仍从非秘密receipt index读old route/fingerprint且不生成新root/KEK。
- [x] Step 2: 运行 `cargo test -p agentdeckd --test runtime_store -- --test-threads=1`。 Expected: FAIL，RuntimeStore不存在。
- [x] Step 3: 实现专用 blocking store worker、WAL/FULL/FK/busy timeout与 StorageKEK row cipher。 `Started + ExecutionIntent + CommandStarted event` 在同一事务；所有 store failure返回 typed error。
- [x] Step 4: 重跑 store test，并把 DB复制/重开验证 recovery。 Expected: Accepted queue/HWM/idempotency恢复；wrapped field扫描不含 sentinel。
- [x] Step 5: fmt/clippy。
- [x] Step 6: 提交。 `git add agentdeckd && git commit -m "feat(daemon): 建立 Runtime 持久化 journal"`

### Task P3.3：建立 adapterStateKey 私有映射并收窄 N8

**Files:**
- Create: `agentdeckd/src/runtime/adapter_state.rs`
- Create: `agentdeckd/src/codex/state.rs`
- Create: `agentdeckd/src/claude_code/state.rs`
- Create: `agentdeckd/tests/adapter_state_boundary.rs`
- Create: `agentdeckd/tests/support/runtime_descriptor.rs`
- Modify: `agentdeckd/src/{agent,runtime/router}.rs`
- Modify: `agentdeckd/src/runtime/{hub,model,mod}.rs`
- Modify: `agentdeckd/src/runtime/store/{journal,mod,schema,sqlite,worker}.rs`
- Modify: `agentdeckd/src/codex/{mod,adapter,history}.rs`
- Modify: `agentdeckd/src/claude_code/{mod,adapter,history}.rs`
- Modify: `agentdeckd/tests/{agent_router,cc_adapter_shape,codex_adapter_shape,router_both_agents,runtime_store*}.rs`
- Modify: `ARCHITECTURE.md`, `AGENTS.md`, `README.md`, `docs/{AGENT_DIAGNOSTICS,QUALITY,index}.md`

- [x] Step 1: 写 boundary tests。 common catalog序列化只含随机 AdapterStateKey；Codex模块只能读 `codex_adapter_state` namespace，CC只能读 `claude_code_adapter_state`；跨模块读取失败；CC index可从原生 history重建；任何路径不创建 `cc-meta/`。
- [x] Step 2: 运行 adapter boundary test。 Expected: FAIL，当前 router仍以 SessionId/ThreadId为 canonical map。
- [x] Step 3: 实现 typed private state repositories并迁移 history/continue lookup。 旧 `ThreadId` 只留 stdio compatibility；vendor resume ref先用 StorageKEK包装，再写对应私有表；common层拿不到明文API。
- [x] Step 4: 重跑测试与 `rg -n 'thread_id|session_id' agentdeckd/src/runtime`。 Expected: 仅 compatibility/迁移注释允许命中，RuntimeCore key不含 vendor identity。
- [x] Step 5: 同步 N8：允许 adapter私有、派生、可重建映射，仍禁止新 CC 元数据事实源；运行 docs gate。
- [x] Step 6: 提交。 `3c58f2a refactor(daemon): 隔离 adapter 私有 resume 映射`

执行记录（2026-07-11）：

- RED 先后固定了 canonical contract 泄漏 vendor `ThreadId`、CC authoritative init 时序、
  descriptor 任意 bytes、agentKind/namespace 错绑、migration 零写边界、fresh-home retry、空/
  malformed native JSONL、Codex resume 缺 ID 与默认真实 E2E 副作用；实现后逐项转绿。
- Runtime physical schema 从严格 v1 七表原子迁移到严格 v2 九表，但冻结
  `RUNTIME_CRYPTO_CONTEXT_VERSION = 1`，既有 wrapped key/ciphertext 不重写。common catalog
  只接受 deny-unknown `ConversationDescriptor(agentKind,title,cwd)`；open/recovery/migration
  都做 canonical byte-for-byte readback。
- 通用 adapter-state bind/resolve 保持 worker 私有；namespace factory 仅 `runtime` 可见，
  `AgentRouter::with_runtime_store` 是唯一生产 composition，分别向 Codex/CC 注入固定 namespace
  typed vault。两张私表强制 descriptor agentKind、互斥 key、AEAD/blind token、authenticated
  totals、exact retry/conflict/cross-table tamper fail-close。
- Codex `thread/start` 在首个 turn 前绑定，`thread/resume` response 与后续 frame 均要求 exact
  persisted thread id。CC 首次先持久化 UUID 并用 `--session-id`；仅唯一 regular/non-memory
  JSONL 经 `O_NOFOLLOW`、inode 对齐、有界有效 JSONL readback 后才 `--resume`，fresh home
  缺 projects root 继续复用原 ID；authoritative `system.init.session_id` 匹配前不发布事件。
- 默认 `cargo test` 在任何 binary probe/spawn 前跳过真实 Codex/Claude model/history smoke；只有
  显式 `AGENTDECK_E2E=1` 才运行。真实 canonical Codex/CC smoke 分别 1/1 PASS（2.40s/5.61s）。
- 完整 `env -u AGENTDECK_E2E cargo test -p agentdeckd -- --test-threads=1` exit 0：lib
  114/114，真实 1,024 × 256 KiB/精确 256 MiB 边界 5/5（慢项 261.07s），StorageKEK
  14 PASS + 1 ignored signed Keychain gate；该 ignored 仍是 P3.1 外部 provisioning BLOCKED，
  不计作通过。两轮独立 architecture/security review 均无剩余 P0/P1/P2。

### Task P3.4：实现 transport-neutral RuntimeCore、principal 与 prompt actors

**Files:**
- Create: `agentdeckd/src/runtime/{core,connection,conversation,execution,read_pool}.rs`
- Create: `agentdeckd/tests/{runtime_core,runtime_store_p34}.rs`
- Modify: `agentdeckd/src/runtime/{mod,model,router,store/*}.rs`
- Modify: `agentdeck-protocol/src/runtime/*`、`agentdeck-protocol/tests/runtime_v1_contract.rs`
- Modify: `Sources/AgentDeckCore/Protocol/RuntimeV1Types.swift`、
  `Tests/AgentDeckTests/RuntimeV1ProtocolTests.swift` 与 Runtime schema/fixture

**Core interface:**
```rust
pub struct RuntimeCore { store: RuntimeStoreHandle, router: Arc<AgentRouter>, connections: ConnectionRegistry, conversations: ConversationRegistry }
impl RuntimeCore {
    pub fn connect(&self, principal: AuthenticatedPrincipal, sink: ConnectionSink) -> Result<ConnectionId, RuntimeFailure>;
    pub async fn handle(&self, connection_id: ConnectionId, request: RuntimeRequest) -> RuntimeReply;
    pub fn enqueue(&self, connection_id: ConnectionId, envelope: &RuntimeEnvelope) -> Result<(), RuntimeFailure>;
    pub async fn disconnect(&self, connection_id: ConnectionId);
    pub async fn recover(&self) -> Result<RecoveryReport, RuntimeFailure>;
}
```

- [x] Step 1: 写FakeAgent core tests。 两principal并发同conversation prompt按journal commandSeq FIFO；不同conversation并行；control lane不被prompt堵塞；queued prompt在Started前可取消、Started后只走明确cancel；每conversation32、全局1,024/256MiB；principal撤销后Accepted未Started终止为`RevokedBeforeStart`；512/16MiB慢writer只断自己；同idempotency key replay；remote grant serial renewal后同deviceRoute+DeviceSign owner仍重放原command。
- [x] Step 2: 运行 runtime_core test。 Expected: FAIL，当前 RuntimeHub绑死单 stdin/stdout。
- [x] Step 3: 实现 RuntimeCore与per-conversation actor；保留 RuntimeHub未接线作为 compatibility。 actor不await writer；ReadPool独立且满载立即overload；local/remote排序不含transport优先级。P3.7前production coordinator固定disabled，Accepted不写假Started/fence。
- [x] Step 4: 重跑100路同key Start竞态与actor并发测试。 Expected: 1 Created + 99 Replayed、一个actor；同conversation按commandSeq FIFO、不同conversation并行、shutdown后actor/writer归零。
- [x] Step 5: fmt/clippy。production新增范围无warning；字面全target clippy仍由既有 trunk/CC/Codex lint 阻塞，使用逐项列明的既有 lint allowance 后 `-D warnings` 通过。
- [x] Step 6: 按精确 pathspec 暂存 Rust/Swift Runtime v1 contract、schema/fixture、daemon
  Core/store/actor 与测试，并提交为 `a58d84e feat(daemon): 建立持久化 RuntimeCore 与会话 actor`；
  文档与 P3.5 细化计划留在后续独立 docs commit，未混入代码提交。

**P3.4 收口事实：** Runtime v1 已改为纯幂等 Start、显式 CancelQueued/CancelActive、
tagged QueryReceipt 与精确 CommandStatus；Store Safety lane 支持 Accepted→Canceled/
RevokedBeforeStart 原子终止，Read lane 同时校验 conversation+owner；opaque principal 对同一
完整身份共享强 authorization lease，runner 在 Started 前重新取 guard。connection 的
完整 `RuntimeEnvelope` 保留 version/messageId，512 frames/16 MiB 预算保持到 transport
write/flush ACK；ReadPool 不排无界 waiter，control 使用有界优先批次。Start 的稳定 ID 由
StorageKEK 域分离 capability 派生，不接受调用方注入的临时 key。execution `prepare` 只能返回
blocked gate+cold release capability，只有
durable release COMMIT 产生的 permit 才能取得 completion future。跨重启 remote Accepted 在
P4 auth ledger 前明确 RecoveryBlocked。真实 vendor exec 仍严格属于 P3.7 gate，不计为 P3.4
通过证据。

执行记录（2026-07-12）：

- `cargo test -p agentdeck-protocol -- --test-threads=1`、Swift `RuntimeV1ProtocolTests` 18/18、
  `cargo test -p agentdeckd --lib runtime:: -- --test-threads=1` 67/67、conversation 20/20、
  execution nonce 1/1、`runtime_store_p34` 13/13、`runtime_core` 2/2 均通过。
- 完整 `env -u AGENTDECK_E2E cargo test -p agentdeckd -- --test-threads=1` exit 0：lib
  154/154、全部 integration suites 通过；真实 1,024 × 256 KiB / 精确 256 MiB 慢门禁
  5/5（263.86s）。StorageKEK 14 PASS + 1 ignored signed Keychain gate；ignored 仍是 P3.1
  外部 provisioning BLOCKED，不计作通过。
- `cargo fmt --all -- --check`、P3.4 scoped all-target clippy `-D warnings`、
  `bash scripts/check-daemon-no-net.sh`、`scripts/verify-agent-docs.sh` 与 `git diff --check`
  均通过。actor 生命周期与 Core/security 两轮独立复核均无剩余 P0/P1/P2；actor 自身 panic
  后 registry dead entry 只 fail-close、不原地重建，作为非 safety blocker 留待进程重启恢复。

### Task P3.5：实现 approval first-wins、delivery retry 与精确 receipt

**Files:**
- Create: `agentdeckd/src/runtime/approval.rs`
- Create: `agentdeckd/tests/runtime_approval.rs`
- Modify: `agentdeckd/src/runtime/{core,conversation,execution,connection,model,mod}.rs`
- Modify: `agentdeckd/src/runtime/store/{schema,sqlite,journal,worker,identity,mod}.rs`
- Modify: `agentdeckd/src/{agent,codex/adapter,claude_code/adapter}.rs`
- Modify: `agentdeckd/src/runtime/router.rs`
- Modify: `agentdeckd/tests/{codex_adapter_shape,cc_adapter_shape}.rs`
- Modify: `agentdeck-protocol/src/runtime/failure.rs`
- Modify: `docs/{AGENT_DIAGNOSTICS,QUALITY}.md`、`ARCHITECTURE.md`

**Interfaces:**

- daemon-private `ApprovalPrincipalCapability::try_enter_approval()` 只为
  `AuthenticatedPrincipal` 实现，并返回字段私有的
  `ApprovalAuthorizationGuard`；它同时证明 principal 仍 Active、拥有 approval resolve/retry
  权限，并携带完整 authorization identity 的 opaque claimant key。permission 必须属于 issuer
  签发的 principal capability/共享 lease identity，不能用 `is_local()`、transport 字段或
  idempotency owner 代替。guard 生命周期覆盖 first-wins CAS COMMIT；claim 先提交后，delivery
  已归 daemon，之后的 client disconnect/revoke 不撤销赢家。
- `ApprovalPolicySnapshot` 在 ActionRequest 注册时冻结：精确 `agentKind/actionKind`、
  `allowApprove/allowDeny/allowPersist` 与可选 `deadlineAtMs`。Approve 必须满足 action
  capability；`persist=true` 只接受 Codex request 的 `canPersist=true` 且 session features
  包含 `CodexApprovalPersistence`；当前 Runtime `ActionRequest` 无 deadline 时使用创建后
  30 分钟。

  ```rust
  pub(crate) trait ApprovalPrincipalCapability {
      fn try_enter_approval(
          &self,
      ) -> Result<ApprovalAuthorizationGuard, PrincipalAccessError>;
  }

  pub(crate) struct ApprovalPolicySnapshot {
      pub(crate) agent_kind: AgentKind,
      pub(crate) action_kind: ActionKind,
      pub(crate) allow_approve: bool,
      pub(crate) allow_deny: bool,
      pub(crate) allow_persist: bool,
      pub(crate) deadline_at_ms: Option<u64>,
  }
  ```

- `BoundApprovalDelivery` 是绑定精确 active session、route 与 requestId 的 daemon-private
  capability；Runtime approval common 层不接收 raw `SessionId`，也不通过全局 router 再按
  requestId 猜 route。固定接口为：

  ```rust
  #[async_trait::async_trait]
  pub(crate) trait BoundApprovalDelivery: Send + Sync + 'static {
      fn policy(&self) -> &ApprovalPolicySnapshot;
      async fn deliver(
          &self,
          key: ApprovalAttemptKey,
          decision: &ActionDecision,
      ) -> ApprovalDeliveryOutcome;
  }

  pub(crate) enum ApprovalDeliveryOutcome {
      AppliedAck,
      DefinitelyNotDelivered { retryable: bool },
      OutcomeUnknown,
      PermanentlyRejected,
  }

  pub(crate) struct ApprovalAttemptKey {
      pub(crate) approval_id: RuntimeId,
      pub(crate) delivery_round: u32,
      pub(crate) attempt: u8,
  }
  ```

  `ApprovalAttemptKey` 固定携带 neutral `approvalId/deliveryRound/attempt`。adapter 只有在完整
  response write+newline+flush 成功后才返回 `AppliedAck`；部分写、flush 不明或 route 状态不明
  必须返回 `OutcomeUnknown`，禁止自动重投。Codex delivery 使用完整 `ActionDecision` 并正确映射
  `persist`；Claude Code speculative permission wire 未经 recorded fixture/live gate 验证时不得
  mint production `BoundApprovalDelivery` 或广告可用 Approval。
- `PreparedRuntimeExecution` 增加 bounded execution event receiver；事件接口固定为：

  ```rust
  pub(crate) enum RuntimeExecutionEvent {
      ActionRequest {
          request: ActionRequest,
          delivery: Arc<dyn BoundApprovalDelivery>,
      },
  }
  ```

  P3.5 用 side-effect-free fake 证明 actor/store/worker；P3.7 的真实 exec-gate coordinator
  负责把现有 `CanonicalAgentEvent::ActionRequest` 接入该 receiver，并由 router/adapter mint
  绑定 capability。

**SQLite schema v3 与 authenticated ledger：**

- `RUNTIME_SCHEMA_VERSION=3`，`EXPECTED_TABLES` 增加 `approval_ledger`；
  `RUNTIME_CRYPTO_CONTEXT_VERSION` 继续为 1，禁止因 physical migration 重加密既有 row 或
  重包 wrapped key bundle。fresh DB 顺序执行 DDL v1、migration v2、migration v3；既有 DB
  同时支持 authenticated `v1→v3` 与 `v2→v3`，迁移前先用旧 ledger token 完整认证旧表，
  COMMIT 后逐字节核对 databaseId/keyGeneration/wrapped bundle 与既有 ciphertext 未变。
- `runtime_meta` 新增 `approval_count` 与 `active_approval_count`，都纳入
  `runtime.meta.ledger.v3` MAC。`approval_count == COUNT(*)`；
  `active_approval_count == COUNT(state IN pending/claimed/applying/deliveryFailed)`。
  `DeliveryFailed` 仍可显式 retry，因此继续计为 active。Safety reserve 使用
  `active_approval_count * MAX_APPROVAL_TERMINATION_RESERVE_BYTES`，保证 adapter 已响应后仍能
  durable 写入 Applied/Expired；Applied/Expired 才递减 active count。
- `approval_ledger` 最小字段固定为：
  - identity：`approval_id` PK、`conversation_id`、`command_id`、`turn_id`，均为 16-byte
    neutral ID；FK 分别指向 conversations、commands、execution_intents。
  - blind tokens：`request_token`、nullable `decision_token`、nullable `claimant_token`，均为
    32 bytes；不得把 vendor requestId、principal、decision/persist 或 tool detail 放明文列。
  - state/time：`state` 只允许 `pending/claimed/applying/applied/deliveryFailed/expired`，以及
    `requested_at_ms/deadline_at_ms/claimed_at_ms/state_changed_at_ms`。
  - retry budget：`delivery_round`、`attempts_in_round`（0...8）、nullable
    `round_started_at_ms/last_attempt_at_ms`。
  - event/integrity：`state_version >= 1`、unique `last_event_id`（FK 到
    `event_journal.event_id`）、
    `logical_request_bytes/logical_decision_bytes`、32-byte `metadata_token`。
  - sealed payload：`sealed_request`、nullable `sealed_decision`、nullable
    `sealed_status_detail`。`sealed_request` 同时保存 canonical ActionRequest 与
    ApprovalPolicySnapshot；row AEAD 使用稳定 crypto context v1，metadata MAC 覆盖全部明文
    字段、token、密文字段存在性与长度。
- 新增 `RuntimeIdKind::Approval`、`idx_approval_active_turn(conversation_id, turn_id, state)` 与
  `idx_approval_deadline(state, deadline_at_ms)`。load 时解密并 canonical re-serialize request/
  decision，重算 blind token，校验 command/turn/conversation linkage、各 state 的 NULL/non-NULL
  不变量、ledger counts 与 deadline/attempt 单调性。
- Pending 注册与 canonical ActionRequest event 必须同事务；初始 `state_version=1`。每次真正
  状态转换写一条 ApprovalResolved event、递增 stateVersion/全局 eventCount 并更新
  lastEventId；`Applying→Applying` 的后续 attempt 只更新 authenticated attempt 计数，不伪造
  状态转换事件。完整性扫描验证 command 固有 event 数 + `SUM(approval.state_version)` 等于
  event journal 实际数，并逐条核对 approval event 的 id/turn/decision/state。

**状态机、CAS 与 daemon-owned worker：**

- 唯一合法转换为：`Pending→Claimed`、`Claimed→Applying`、
  `Applying→Applying/Applied/DeliveryFailed/Expired`、`DeliveryFailed→Applying/Expired`，以及
  `Pending/Claimed→Expired`。Applied、Expired 为终态；Claimed 后的 sealed winner 永不修改。
  后到 Resolve 返回 `AlreadyHandled(winner, exactState)`；未 claim 的 Pending 过期返回 Expired；
  已 claim 后过期返回 winner+Expired。
- first-wins 使用 `BEGIN IMMEDIATE`，在同一事务重新认证 row/ledger、验证 exact
  conversation+Started turn+approval+requestId、permission 与 policy，然后执行
  `UPDATE ... WHERE state='pending' AND metadata_token=?`。actor 串行不是正确性前提；store CAS
  必须独立通过 100 路竞态。赢家及 Claimed event COMMIT 后才可注册 delivery single-flight。
- 每个 approval mutation 都有 Before/AfterCommit fault point 与
  `RuntimeCommitOperation`；store outcome 使用 `Transitioned/Replayed/AlreadyHandled/ExpiredOrStale`。
  Claim COMMIT unknown 只允许以同一 request/decision token 重试；同 winner 返回 Replayed，
  不同 decision 返回 AlreadyHandled。BeginAttempt 按 round+expectedAttempt+metadataToken 重放，
  Applied/DeliveryFailed/Expired outcome unknown 只重试 journal transaction，绝不再次调用
  adapter。
- `ApprovalSupervisor` 由 conversation actor 持有 bounded `approvalId→JoinHandle` single-flight
  map，不属于 connection。Pending 只保留 deadline timer；Claimed 后 worker 接管 delivery；
  DeliveryFailed 停止自动 loop，只保留 deadline timer。connection disconnect 不取消任务；
  turn terminal 必须先 durable Expired，再 cancel/await worker。adapter deliver 不得在 actor
  control handler 内 await，completion 只通过 bounded runner/control event 回 actor，继续遵守
  control burst 公平点。
- 注入接口固定为共享 `Arc<dyn RuntimeClock>`、async `ApprovalSleeper` 与纯函数
  `ApprovalBackoff::delay_after(failed_attempt)`。attempt 1 立即执行，attempt 2...8 前依次等待
  `0.5/1/2/4/8/16/16s`，正常最大 47.5s；adapter 调用耗时也计入每轮 60s，若下一次开始会越过
  `roundStarted+60s` 或 approval deadline 就提前停止。每轮最多 8 次；自动预算耗尽但 deadline
  未到进入 DeliveryFailed。任一当前有 approval 权限的 client 可 `RetryApproval`，事务只读取并
  重用 sealed winner，round+1、attempt 重新计数，不能携带或覆盖 decision。为保持 Runtime v1
  wire 不变，成功启动 retry 返回 `AlreadyHandled(winner, Applying)`，不能用 Claimed 冒充再次
  赢得 first-wins。

  ```rust
  #[async_trait::async_trait]
  pub(crate) trait ApprovalSleeper: Send + Sync + 'static {
      async fn sleep(&self, duration: Duration);
  }

  pub(crate) trait ApprovalBackoff: Send + Sync + 'static {
      fn delay_after(&self, failed_attempt: u8) -> Duration;
  }
  ```
- adapter 返回 `AppliedAck` 后，如果 Applied journal 暂时失败，worker 只反复收口同一个
  safety transaction；`OutcomeUnknown` 或永久失败停止自动重投并写 DeliveryFailed+诊断详情，
  保留赢家供显式 same-decision Retry。
- command Completed/Failed/Interrupted 与该 turn 所有非 Applied approval 的 Expired 更新及
  canonical events 必须在同一个 Safety lane transaction 提交。分成两个事务会产生
  terminal turn 仍有 active approval 的 crash gap。register/claim/begin-attempt/manual-retry 走
  Normal lane；Applied/DeliveryFailed/Expired 与 terminal+expiry 走 Safety lane并使用预留空间。

- [x] Step 1: 先写以下 16 项 RED tests，测试名与断言固定，禁止合并成一个大用例。
  当前 `runtime_approval` 保留 16 个独立聚合项；由于 production API 均为 daemon-private，其中
  source-shape 断言只补接口/seam 覆盖，最终行为证据必须来自同名或对应 private
  unit/store/actor/fault tests：
  1. `pending_registration_is_atomic_with_action_request_event`：row、event、high-water、两个 ledger
     count 同事务；BeforeCommit fault 后没有半行。
  2. `principal_without_approval_permission_cannot_claim`：Active 但无 resolve 权限仍拒绝，adapter
     调用数为 0。
  3. `resolve_requires_exact_conversation_turn_approval_and_request_id`：四种 mismatch 分别
     fail-close，row 保持 Pending。
  4. `decision_must_match_bound_action_capability`：缺 Approval、agent/action 不匹配、不可 Approve、
     非法 persist 均拒绝。
  5. `one_of_100_concurrent_resolves_wins_sqlite_cas`：50 Approve+50 Deny 只有一个 Transitioned，
     其余 99 个观察同一 immutable winner。
  6. `claim_after_commit_unknown_replays_and_starts_one_worker`：AfterCommit fault 后 exact retry 为
     Replayed，adapter 最终只调用一次。
  7. `delivery_transitions_claimed_applying_applied_and_survives_disconnect`：断开 winner connection
     后 delivery 继续，状态/event 顺序精确。
  8. `delivery_budget_is_eight_attempts_and_never_exceeds_sixty_seconds`：paused/manual time 下最多
     8 次，调用时间符合 backoff，60s 后无第 9 次。
  9. `delivery_failed_retains_winner_and_exact_receipt`：预算耗尽为 DeliveryFailed，对立 decision
     只能得到原 winner+exact state。
  10. `retry_delivery_reuses_exact_sealed_decision_and_new_budget`：requestId/kind/persist 逐字段相同，
      round+1 且对立 Resolve 不能改判。
  11. `default_deadline_is_request_time_plus_thirty_minutes`：29:59.999 仍 active，30:00.000 精确
      Expired 且只有一个 terminal event。
  12. `capability_deadline_overrides_default_and_stops_backoff`：更短 capability deadline 阻止下一
      attempt 越界启动。
  13. `turn_terminal_expires_every_non_applied_approval_atomically`：Pending/Claimed/Applying/
      DeliveryFailed 全 Expired，Applied 保留，command terminal 与 approval events 同事务。
  14. `applied_commit_unknown_retries_store_only`：adapter 一次成功，Applied AfterCommit unknown
      只重试 store，最终仍只调用 adapter 一次。
  15. `restart_never_resumes_active_approval_delivery`：重启读到 Applying/DeliveryFailed 时 adapter
      调用为 0；P3.7 interruption hook 后全部 Expired。
  16. `approval_row_and_ledger_tampering_is_rejected`：篡改 state/attempt/deadline/decision token/
      approvalCount/activeApprovalCount 任一项都返回 UnknownOrCorruptSchema。
- [x] Step 2: 已先运行 RED gate；失败指向缺失 approval module/schema/store API/permission/delivery
  seam，不依赖 fixture、真实时间或 vendor 环境。后续固定命令仍为
  `cargo test -p agentdeckd --test runtime_approval -- --test-threads=1`，但该聚合 gate 不能替代
  private 行为测试。
- [x] Step 3: 已实现 schema v3、authenticated v1/v2→v3 migration、row sealing/MAC、
  `approval_count/active_approval_count` ledger MAC、每 active approval 1 MiB safety reserve、完整性
  扫描与 first-wins CAS/outcome replay。Pending 注册与 ActionRequest event 原子；100 路竞态、
  tamper、所有 mutation Before/AfterCommit 与 low-space safety 收口由 private store tests 验证。
- [x] Step 4: 已实现 ApprovalAuthorizationGuard、ApprovalPolicySnapshot、BoundApprovalDelivery 与
  bounded execution ActionRequest receiver seam。Codex route 覆盖完整 kind/persist 映射、单飞、
  write+newline+flush 后才 AppliedAck，失败保留 route；P3.5 当时只有 CC permission response shape
  私有测试，因此该阶段没有广告 CC Approval。P3.7 现已用 recorded `control_request(can_use_tool)`
  fixture 接通 canonical typed capability 与 durable response；live vendor 证据仍须独立 gated 验收。
  真实 RuntimeExecutionEvent/adapter session 绑定也由 P3.7 承接。
- [x] Step 5: 已实现 conversation-owned ApprovalSupervisor、默认 30 分钟/能力 deadline、每轮
  8 次且总计 60 秒、same-decision manual retry、disconnect/revoke 后 daemon ownership、worker
  panic supervision 与精确 receipt。BeginApprovalAttempt COMMIT 成功或 exact replay 后会刷新时钟
  并复核持久化 deadline/round budget，越界时不调用 adapter；adapter 已产生结果但 durable closure
  无法安全收敛会返回 FatalClosure，使 actor 进入 RecoveryBlocked、停止 approval task 且禁止重投。
  store 在 preflight 与 `BEGIN IMMEDIATE` authenticated reload 后都校验
  `max(stateChanged, roundStarted, lastAttempt)`；时钟回退时 row/event 不变且不签发 permit。
  Register/Claim/Retry 只对 operation 匹配的 CommitOutcomeUnknown 使用原 stable input 精确重试。
  Pending Expired 没有赢家；claimed Expired 返回原 winner+Expired。测试使用 injected/manual
  time，不等待真实 60 秒。
- [x] Step 6: 已把 Completed/Failed/Interrupted 与该 turn 全部非 Applied approval expiry 合并为
  同一个 Safety transaction，并按“先 durable terminal+expiry、后 cancel/await worker”收口。
  CompleteCommand AfterCommit unknown 使用同一 completion input 精确重放，已提交 terminal 不会
  错误进入 RecoveryBlocked；route 已清理或 generation 不匹配的迟到 FatalClosure 按 stale 忽略。
  deadline expiry 使用同一预留 safety lane；RecoveryBlocked 只停止进程内 delivery，不在缺少
  process fencing 证据时恢复投递或伪造 Expired/Interrupted。
- [x] Step 7: 最终重跑
  `cargo test -p agentdeckd --test runtime_approval -- --test-threads=1`、
  `cargo test -p agentdeckd --test codex_adapter_shape`、
  `cargo test -p agentdeckd --test cc_adapter_shape` 与
  `env -u AGENTDECK_E2E cargo test -p agentdeckd -- --test-threads=1`。固定 16 项只作聚合/shape
  补充；退出结论必须同时引用 `runtime::store::approval::tests`、`runtime::approval::tests`、
  `runtime::conversation::tests`、permission/Core 与 adapter private tests。最终证据：daemon lib
  253/253、approval store 30/30、conversation 38/38、固定聚合 16/16、Codex shape 8/8、CC shape
  12/12；`env -u AGENTDECK_E2E cargo test -p agentdeckd -- --test-threads=1` 整包 exit 0，包含
  256 MiB 真实边界，只有既有 codesigned Keychain roundtrip 1 项按外部门禁 ignored。protocol
  全包 exit 0，Swift `RuntimeV1ProtocolTests` 19/19。没有真实时间等待或 live vendor login 依赖。
- [x] Step 8: approval/authorization/delivery failure code、schema v3 migration/恢复说明、手动 QA
  边界与架构不变量已更新；独立 final review 结论 PASS、无剩余 P0/P1/P2。最终
  `cargo fmt --all -- --check`、目标范围 `cargo clippy -p agentdeckd --all-targets ... -D warnings`、
  `bash scripts/check-daemon-no-net.sh`、`scripts/verify-agent-docs.sh` 与 `git diff --check` 全部通过。
- [x] Step 9: 已提交 `0609152 feat(daemon): 实现 approval first-wins 与投递恢复`。提交前 staged
  diff 仅包含 P3.5 runtime/store/protocol failure code、测试与同步文档，无构建产物、运行日志或
  secret。

**P3.5 当前收口事实（2026-07-13，最终复核前）：** schema v3、approval row/ledger authenticated
integrity、1 MiB/active safety reserve、SQLite first-wins、exact COMMIT-unknown replay、
daemon-owned single-flight、8 次/60 秒、默认 30 分钟 deadline、OutcomeUnknown/DeliveryFailed、
same-decision retry、Pending/claimed Expired 精确回执，以及 terminal+expiry 单 Safety transaction
均已有 private 行为测试。Runtime/Swift required-null Expired contract 已随协议更新；Codex route
完整 flush 与 CC capability gate 已在 adapter 私域验证。Begin COMMIT 后时钟复核、FatalClosure
进入 RecoveryBlocked、Register/Claim/Retry 匹配 operation 的 exact COMMIT-unknown replay，以及
terminal 与全部 non-Applied approval 同一 Safety transaction，也已有对应 private 行为测试。
open/recovery 完整性审计已改为全 catalog conversation 分批、每批最多 16 MiB compact projection；
完整 canonical request 只留 keyed digest，event chain 按 eventSeq 常量空间归约，零-row orphan event
仍 fail-close。最终 daemon lib 253/253、approval store 30/30、聚合 16/16、Rust protocol 全包与
Swift Runtime 19/19 均通过；全回归、clippy/fmt/no-net/docs/diff 门禁和独立 review 已闭环。只剩
P3.5 已由 `0609152` 收口。P3.7 的 exec-gate、真实
RuntimeExecutionEvent 绑定与 live Codex/Claude Code approval 明确未完成。

**P3.7 依赖边界：** P3.5 的退出门禁是 schema/CAS/permission/worker/receipt 与 production
capability contract 在 fake execution 上全部可证；它不得用当前 in-process adapter spawn 冒充真实
vendor 闭环。P3.7 必须实现 blocked exec-gate、把 canonical adapter event receiver 接入
`RuntimeExecutionEvent`、在精确 transient session 上 mint `BoundApprovalDelivery`、完成真实
Codex/Claude Code gated approval，并在 orphan process group 已确认 fenced 后，使用 P3.5 的同一
terminal+expiry transaction 写 Interrupted+Expired。任何 Started turn 尚未证明 fenced 时，
P3.5 recovery 都保持 RecoveryBlocked、绝不恢复 approval delivery 或后续 Accepted command。

**P3.6 当前状态（2026-07-15）：** P3.6-A=`7731d1e`、P3.6-B=`02cc640`、
P3.6-C=`694f2d9`、P3.6-D=`b668d8f` 已提交；当前进入 P3.7。已读回 `runtime_stream` 45/45、
`runtime_transfer` 17/17、subscription 36/36、daemon lib 464/464（`runtime::` 366 项）、默认并发
`cargo test -p agentdeckd` exit 0，Swift 256 XCTest + 35 Swift Testing，以及 protocol/schema、fmt、
clippy、daemon no-net 与 diff gate 全通过。P3.1 provisioned signed Keychain roundtrip 仍有 1 项
ignored/BLOCKED；P3.7 exec gate 主体、边界裁决、两个 prepare finding 与 translator 阻断项已收口并通过
聚焦门禁，最终完整自动门禁与独立终审均已通过，并由 `5568e93` 完成主体 scoped commit、
`c9d2146` / `5713be4` 补齐真实 release 前取消与 sentinel 退出窗口门禁；P3.8 production UDS 已完成，
P3.9 shared-daemon client 与 P4 E2EE/Relay Publish 均未完成。

### Task P3.6-A：先冻结 Runtime/E2EE contract 与跨语言 wire

P3.6 后续代码只能消费本 task 冻结的类型；禁止在 store/barrier 实现中继续临时改 wire。

**Files:**
- Modify: `agentdeck-protocol/src/runtime/{catalog,command,envelope,event,identity,mod,schema,sync,transfer}.rs`
- Modify: `agentdeck-protocol/src/e2ee/{keys,payload,schema}.rs`
- Modify: `agentdeck-protocol/tests/{runtime_v1_contract,runtime_neutrality,transfer_envelope,e2ee_canonical_contract,relay_v2_contract}.rs`
- Modify: `agentdeck-crypto/src/{aead,lib}.rs`
- Modify: `agentdeck-crypto/tests/golden_vectors.rs`
- Modify: `Sources/AgentDeckCore/Protocol/RuntimeV1Types.swift`
- Modify: `Sources/AgentDeckRelayClient/Crypto/{CanonicalCodec,RelayCrypto}.swift`
- Modify: `Sources/AgentDeckRelayClient/Wire/RelayV2Types.swift`
- Modify: `Tests/AgentDeckTests/RuntimeV1ProtocolTests.swift`
- Modify: `Tests/AgentDeckRelayClientTests/RelayCryptoVectorTests.swift`
- Modify: `Tests/AgentDeckRelayClientTests/RelayV2WireTests.swift`
- Modify: `protocol/agentdeck/{runtime-protocol.schema.json,e2ee-v1.schema.json,crypto-vectors-v1.json}`
- Modify: `protocol/agentdeck/fixtures/{runtime-v1-wire.jsonl,relay-v2-wire-vectors.json}`

**Contract freeze:**

- `StreamCursor::checked_next()` 返回 checked result；`At(u64::MAX)` typed fail 并要求 generation
  rotation。新增 tagged `RuntimeInnerCursor::Catalog/Conversation` 与 tagged
  `RuntimeSubscriptionTarget`。
- `RuntimeEnvelope.version` 双端 ingress/egress 必须精确为 1；`messageId/transferId` 非空且最多
  1,024 UTF-8 bytes，schema 同时记录 `x-maxUtf8Bytes`，Rust/Swift/ADRT1 统一执行 byte gate。
- `RuntimeRequest` 固定为 `Subscribe(innerCursor)`、tagged
  `BackfillRequest::Catalog(after)|Conversation(conversationId,after)`、`Unsubscribe(target)`；新增
  directed `SubscriptionReceipt::Subscribed(streamGeneration)|Unsubscribed`，target 由原 request
  messageId 关联。`RuntimeSyncComplete` 只在 Reply，携带 outer generation/cursor 与 tagged inner
  cursor。
- `ConversationSnapshot.baseEventCursor`；`CatalogSnapshot.baseCatalogCursor` 与 opaque frozen
  `nextPageCursor`；`BackfillChunk::Catalog/Conversation` 的 `after/through` 必须连续非空，conversation
  序列有 capabilities preamble。
- `RuntimeEvent.itemId/entityId/commandId` 三键 required-null，矩阵固定为：Capabilities 三空；Item
  必须 itemId+entityId，UserMessage 还必须 commandId；TurnStarted/ActionRequest/ApprovalResolved/
  TurnCompleted/TurnInterrupted 必须 commandId；Error 的 item/entity 为空、command 可空。
  body 若仍携带 command identity 必须与外层逐字匹配；`SnapshotItem` 使用同一矩阵，Rust/Swift
  constructor 与 decoder 都拒绝违规组合。
- `TransferPart` 进入 Reply/Stream，Request 不接受。E2EE kind 新增 TransferPart；compact remote binary
  `RuntimeTransferCarrierV1` 固定包含 runtimeVersion/messageId/channel/transferId/index/count/total hash/
  total bytes/raw part。只有该 carrier 保留 3.5 MiB raw part；JSON/UDS raw part 固定 700 KiB，完整
  JSON/UDS frame 受 1 MiB hard cap；binary carrier worst-case AEAD+signed sealed+Relay outer 必须
  小于 Relay 4 MiB。JSON/UDS 的 `totalBytes <= partCount * 700 KiB`，remote carrier 则按
  `partCount * 3.5 MiB` 校验，二者仍受 64 MiB 总上限。
- `SealedPayloadKind` 只存在于 AEAD plaintext `ADSP1` carrier；Unsigned/Signed/Verified sealed-blob
  outer、canonical bytes 与 TBS 均不得携带业务 kind。Rust/Swift 共同拒绝 bad
  magic/version/kind/declared-length/trailing。
- transfer parts 全齐后必须先用已记账 `bufferedBytes` 核验声明 `totalBytes`，再分配 assembly
  buffer；length mismatch 先 abort/释放，不能产生未计入 128 MiB reassembly cap 的瞬时分配。
- required-null schema 必须同时把 key 放入 `required` 并允许 `null`；Backfill Rust/Swift 的 decode、
  direct enum egress、flatten reply egress 都执行连续/非空/512 entries/64 MiB 同一组 gate。
- daemon `EncodedRuntimeFrame` 必须消费 protocol 的 checked JSON bytes；实际 Core enqueue 对超 1 MiB
  Reply/Stream 在进入 16 MiB writer budget 前返回 `daemon.payload.item_too_large`，禁止只在 protocol
  convenience API 测试 framing cap。
- `EpochBarrierV1.eventSeq` 替换为 tagged inner cursor；Rust/Swift fixture 与 E2EE schema 同步。

- [x] Step 1: 先补 contract/negative/fixture tests，覆盖 max cursor、required-null matrix、错误 target、
  空/不连续 backfill、SyncComplete stream variant 拒绝、remote carrier 4 MiB 边界与 Swift parity。
- [x] Step 2: 运行 Rust/Swift 定向 tests。Expected: FAIL，现有 wire 仍是 unchecked cursor、
  conversation-only Subscribe、eventSeq-only sync/barrier 与 JSON 3.5 MiB part。
- [x] Step 3: 最小实现上述 contract；运行
  `UPDATE_RUNTIME_SCHEMA=1 UPDATE_E2EE_SCHEMA=1 UPDATE_WIRE_FIXTURES=1 cargo test -p agentdeck-protocol`
  更新 schema/fixtures，再以无 update env 重跑确认 byte-stable。
- [x] Step 4: 运行 `swift test --filter RuntimeV1ProtocolTests`、
  `swift test --filter RelayV2WireTests`、四份 schema diff 与 fixture `git diff --exit-code` 二次生成门禁。
- [x] Step 5: 已提交 `7731d1e`；除 protocol/crypto/Swift/schema/fixture 外，提交还包含冻结
  contract 所需的 daemon compatibility 与 persisted-event 配套调整，但未夹 P3.6-B store v4、
  P3.6-C stream/barrier 或本阶段 docs：
  `git commit -m "feat(protocol): 冻结 Runtime stream 与 transfer contract"`。

### Task P3.6-B：迁移 Runtime store v4 并建立真正 read-only WAL pool

**Files（`02cc640` 最终提交范围）:**
- Create: `agentdeckd/src/runtime/store/{stream,catalog,snapshot,publication}.rs`
- Modify: `agentdeckd/src/runtime/{model,read_pool}.rs`
- Modify: `agentdeckd/src/runtime/store/{mod,schema,sqlite,worker,approval,journal,cipher}.rs`
- Modify: `agentdeckd/tests/{runtime_store,runtime_store_boundaries,runtime_store_cipher}.rs`
- Create: `agentdeckd/tests/{runtime_store_stream_v4,runtime_store_read_pool}.rs`

**Schema/migration freeze:**

- schema v4 只新增 `event_stream_index`、`event_retention`、`catalog_journal`、`snapshots`、
  `publication_streams`、`publication_outbox` 六表；`event_journal` 保持 append-only audit。logical event
  suffix 每 conversation 10,000/64 MiB、global 131,072/512 MiB；catalog journal 10,000/64 MiB。
  这些不是物理回收承诺，main+WAL+SHM 仍受 2 GiB cap。
- snapshot 64 MiB/每 conversation 一个 ready/global 512 MiB；outbox 每 stream 2,000 rows/64 MiB、
  global 10,000/512 MiB，未 ACK 不删。publication row 记录 exact blob/hash/counter/inner range 与
  reserved/frozen/Relay-committed/ACK 状态；barrier 只能读取 Relay-committed outer+inner cut。
- v4 `runtime_meta` authenticated ledger 精确新增
  `audit_event_logical_bytes,event_stream_count/bytes,catalog_delta_count/bytes,`
  `catalog_retention_floor,snapshot_count/bytes,publication_stream_count,publication_outbox_count/bytes`；
  `event_retention` row 的 retained count/bytes/floor 由自己的 token 认证；逐 target 还要复算
  floor/through/HWM、range digest、snapshot hash、publication gap/overlap、FK/orphan。
- `RUNTIME_CRYPTO_CONTEXT_VERSION=1` 不变；v1/v2 直接到 v4，v3 到 v4，wrapped key、nonce、
  `sealed_event`/fixed event ciphertext byte-identical。event index 只物化经完整旧 ledger 验证后的最大
  连续 suffix；catalog 建当前 HWM snapshot baseline。
- worker 初始化/migration ready error 在对 caller 可见前必须释放 Runtime DB path lease；随后 exact
  reopen 不需要 polling，不能接受短暂 `StoreAlreadyOpen`。
- legacy event bridge 先 strict decode 新 DTO；失败后才接受完整 legacy RuntimeEvent JSON，从
  authenticated `event_journal.command_id` 注入/核验 command identity，旧 body command 必须匹配；
  补齐 required-null keys 后再次 strict decode。任何 opaque fixed event bytes 都不改写。
- ReadPool 固定 8 个 `mode=ro/query_only=ON` WAL connections、128 MiB retained page memory、每页
  64 rows/8 MiB；page 复制后先结束 read transaction/释放 connection，再交 reply pump。

- [x] Step 1: 写 schema/migration/ledger/read-pool RED tests。固定 fault 覆盖六表 row token、上述每个
  count/bytes、floor/through/HWM/range/hash/state、gap/overlap/FK/orphan；另覆盖 v1/v2/v3 migration、
  COMMIT unknown、legacy bridge command mismatch 与原 ciphertext/wrapped key byte identity。
- [x] Step 2: 运行三套新 integration tests及既有 store hardening/recovery。Expected: FAIL，schema
  仍为 v3，ReadPool 还不是独立 read-only WAL connections。
- [x] Step 3: 实现 v4 migration、logical suffix/retention pins、catalog/snapshot/publication repository
  与 read-only page API；禁止跨网络/await 持有 read transaction，禁止 DELETE audit rows。
- [x] Step 4: 重跑 fault matrix、真实 WAL checkpoint pressure 与容量 tests。Expected: writer 在慢 page
  consumer 下继续提交；任一 tamper fail-close；cap 满时拒绝新 logical row/outbox 而不删 unacked。
- [x] Step 5: 已按 store/read-pool 精确 pathspec 提交 `02cc640`：
  `git commit -m "feat(daemon): 建立 Runtime v4 stream store"`。

### Task P3.6-C：实现 StoreCommitHub、barrier/backfill/snapshot、transfer 与 publication 状态机

**Files（`694f2d9` 最终提交范围；目录项包含 private 子模块与 tests）:**
- Modify: `agentdeckd/Cargo.toml`
- Create: `agentdeckd/src/runtime/{backfill,catalog_snapshot,events,publication,snapshot,subscription,transfer}.rs`
- Create: `agentdeckd/src/runtime/{catalog_snapshot,publication,snapshot,subscription}/`
- Modify: `agentdeckd/src/runtime/{connection,core,mod,model,read_pool}.rs`
- Create: `agentdeckd/src/runtime/{connection,core}/` 下的 subscription/private tests
- Modify: `agentdeckd/src/runtime/store/{approval,catalog,cipher,journal,mod,publication,schema,snapshot,sqlite,stream,worker}.rs`
- Create: `agentdeckd/src/runtime/store/retention.rs` 与
  `agentdeckd/src/runtime/store/{publication,snapshot,stream,worker}/` private 模块/tests
- Create: `agentdeckd/src/runtime/store/worker/test_admission.rs`
- Create/Modify: `agentdeckd/tests/{runtime_approval,runtime_snapshot,runtime_store_read_pool,`
  `runtime_store_stream_v4,runtime_stream,runtime_transfer}.rs`
- Create: `agentdeckd/tests/runtime_stream/` 与 `agentdeckd/tests/support/` 下的共享测试模块（含
  integration `store_admission.rs`）

**Actor/state-machine freeze:**

- 唯一 store worker 作为 StoreCommitHub，线性化 watcher 注册与 H capture，并在所有 event COMMIT
  （含 approval worker）后 coalesce HWM；watch 不缓存 payload。first subscribe 在同一个 store
  operation 中先注册 watcher、再捕获对应 committed H/C cut，使 watcher 从 H+1 生效；随后由单
  connection egress gate 严格串行化 `snapshot/backfill → SyncComplete → catchup/live`。
- retained 连续区间才 backfill；裁剪进入内部 NeedSnapshot decision，当前 wire 返回
  `daemon.runtime.read_unavailable` 的 snapshot-required failure，不发 partial；空 inner 是 BeforeFirst，
  下一条 0 不丢。Catalog 使用同一算法。disconnect/Unsubscribe/absolute TTL/stale generation 幂等清理全部
  watch/task/memory/count；前置错误进入无 deadline terminal Failure wait 前先 exact release
  live/barrier/snapshot-sender registry quota，terminal writer job 自身保留到 ACK/disconnect；
  resubscribe/Unsubscribe/disconnect 对旧 terminal wait 的 control cancellation 属正常 generation
  handoff，不得 fail-close 新 generation；Core/actor/SQLite transaction 都不跨 writer wait。
- `commit` 必须立即把可取消后台 job 登记进 jobs map 并返回，不能让 Core operation 等 socket gate；
  job 激活锁序固定为 `egress → coordination`。teardown 在 coordination 内只 detach/cancel，释放锁后
  再 await handle，因此 disconnect/Unsubscribe/shutdown 都不等 terminal ACK、不形成反向锁环。
- pre-delivery error 的 terminal Failure 必须持有 per-connection egress gate 到 flush ACK/cancel，避免
  sibling job 撞单槽 paced reservation 并误 fail-close。gate wait 到 TTL 后必须先释放 registration、
  watch 与 TEMP pin，再进入无 deadline terminal wait。
- 同 target replacement 只让最新 generation 出帧；superseded pending job 不发 stale receipt，未来
  客户端必须在 replacement 时取消旧 request waiter。pending capture 在 Store capture/spawn 前受
  4/connection、128/global 硬上界；disconnect 胜出后 stale prepare 不得重建 per-connection slot。
- backfill/snapshot pin 必须在 oneshot send 前绑定 cleanup owner；receiver/caller 在 reply handoff
  窗口取消时由 owner 自动释放，不能留下 orphan pin。
- caps 固定为 Global Constraints/设计 §9.8；预算必须在 spawn task 前一次性 reserve。snapshot capture
  不跨 I/O 持 actor lock/SQLite transaction；同 connection 的 reply jobs 经同一 egress gate 串行，
  慢读者只 lag 自己。
- Transfer 只有 full parts+length/hash+canonical decode+target/generation/range+capabilities 校验，并在
  clone reducer 成功后，才原子 swap reducer/inner cursor一次；conflict/TTL/disconnect abort 释放预算，
  tombstone 防完整 retry 二次 apply。
- publication freeze exact fake blob/seq/counter/inner range，Relay COMMIT 后才推进 barrier 可见 cut；
  ACK 精确匹配 generation/seq/hash；重启逐字节 retry、每 stream 一个 in-flight、公平 dispatch。P3 fake
  blob 只证明 transport-neutral store algorithm，不算 P4 E2EE seal/counter/Relay Publish 证据。
  `TransferStateMachine` 与 publication dispatcher 均无 production remote owner。

固定 integration contract 以 test runner 的 `--list` 输出为事实源：`runtime_stream` 当前 45 项，
分为 `barrier_integrity` 14 项、`contract` 7 项与 `store_commit_hub` 24 项；`runtime_transfer` 当前
17 项。前者覆盖 authenticated snapshot/publication cut、StoreCommitHub COMMIT race、空流、
retention 与 identity contract；后者覆盖 JSON/UDS 94 parts、remote compact 64 parts、共同
64 MiB 与 5 分钟 TTL、duplicate/metadata/hash/length、stale generation、checked accounting
与 reducer single-apply。
subscription egress ordering、quota、disconnect/TTL cleanup、snapshot permit/pin ownership、catalog
expiry timer 与 publication dispatcher 的 private behavior 由 `cargo test -p agentdeckd --lib runtime::`
共同锁定，当前 subscription 串行门禁为 36 项。新增 terminal gate 6 项精确覆盖 disconnect 无锁环、
pending sibling Unsubscribe/shutdown 不等 Failure ACK、同 target 只发布最新 generation、gate wait
超时释放 snapshot pin、第五个 pending capture pre-spawn 拒绝，以及 disconnect 后 stale prepare 不
重建 slot；不得把计划中的旧候选测试名当成已存在的单独 integration test。

默认并发 daemon 回归另使用两层 test-only Store admission。威胁场景是 macOS `libtest` 在 soft FD
limit 256 下并发创建多份各含 1 writer + 8 WAL readers 的真实 Store，在业务断言前耗尽 FD；unit
`cfg(test)` worker 与 integration fixture 各自把单 test binary 同时存活 Store 限为 4，permit 覆盖
ReadPool/path lease teardown。production Store、固定 8-reader ReadPool 与运行时配额不变。

- [x] Step 1: 先加入上述固定 tests，运行两套 gate。Expected: FAIL，Core 对 Catalog/Subscribe 仍返回
  FeatureUnavailable，StoreCommitHub/reply pump/publication/transfer reducer 尚不存在。
- [x] Step 2: 实现最小 state machines 与预算 registry；使用 deterministic clock、manual writer ACK、
  commit hooks 和 fake sealed blob 注入所有 race/crash boundary。
- [x] Step 3: 已运行两套固定 gate、全部 runtime store tests、
  `cargo test -p agentdeckd --lib runtime:: -- --test-threads=1`、默认并发完整
  `cargo test -p agentdeckd` 与 protocol/Swift contract tests。
- [x] Step 4: fmt/clippy/no-net/schema/diff-check 全通过；已按 daemon runtime/store/tests 精确 pathspec
  提交 `694f2d9`：`git commit -m "feat(daemon): 实现 canonical stream 与 snapshot barrier"`。

最终读回：`runtime_stream` 45/45、`runtime_transfer` 17/17、subscription 36/36、daemon lib
464/464（`runtime::` 366 项）、默认并发整包 exit 0；Swift 256 XCTest + 35 Swift Testing，
`agentdeck-protocol`、schema diff、fmt、clippy、no-net 与 diff-check 全 PASS。codesigned Keychain
roundtrip 的 1 项 ignored 继续记为 P3.1 外部 BLOCKED，不能据此宣称 P3.1、P3 或 Companion 完成。

### Task P3.6-D：同步文档并做独立 scoped docs commit

**Files:**
- Modify: `README.md`, `ARCHITECTURE.md`, `AGENTS.md`
- Modify: `docs/{AGENT_DIAGNOSTICS,QUALITY,index}.md`
- Modify: `docs/plans/{README,2026-07-10-relay-companion-mvp-design,2026-07-10-relay-companion-mvp-implementation}.md`

- [x] Step 1: 只按已落地事实同步 Runtime wire、v4 migration、资源上限、failure code、诊断和验证入口；
  不把 P3 fake blob 写成 P4 E2EE/Relay 已完成，不写物理 event audit 回收承诺。
- [x] Step 2: 运行 `scripts/verify-agent-docs.sh`、`git diff --check`，并对 design §9、schema snapshot、
  Runtime constants 与 tests 做名称/数值交叉扫描。
- [x] Step 3: `git status --short --branch` 与 `git diff --name-only --cached` 证明 staged 仅上述 docs，
  提交 `b668d8f`：`git commit -m "docs(relay): 收口 P3.6 stream 与 barrier 事实"`。

### Task P3.7：实现两阶段 exec gate、ExecutionFence 与 orphan recovery

**完成（2026-07-15，commits `5568e93` + `c9d2146` + `5713be4`）：** 边界已裁决，完整门禁与独立终审已通过。前置分片已建立 typed `ExecutionId`、
`AgentTurnRequest`、`AdapterStateHandle`、bounded/redacted `ExecSpec` 与 daemon-owned
`PreparedAgentTurnHandle`；daemon 在 prepare 返回时与 handle consumption 时两次校验虚 getter 的 exact
execution/state binding。
canonical Item/Error 已改为 Store-owned typed append。fresh dynamic
event 与 approval 必须绑定 authenticated Started/turn 与 released Fence，且
`createdAt >= releaseAuthorizedAt`；caller 不能提交 raw event/bytes/error，
失败只落固定 `daemon.runtime.execution_failed`。canonical template 在单 build permit 下构造、按实际
retained allocation 计费，并在 transaction 内按真实 eventSeq 原地 finalize；event row/HWM/index/
ledger/watcher 同一 COMMIT，open-time audit 对真实 dynamic rows fail-close。prepared event receiver 只在
cold release 调用成功后转发，release 失败先丢弃 receiver，不能注册预排 approval。legacy terminal 已按
`command.terminal.v1/v2` token domain 分流，不按 payload shape 猜版本。audit 也明确拒绝 Raw、空
item/entity identity、orphan/gap 与错误 command/turn binding，不能把未建模或不可聚合事件放行。
open-time command integrity 另对有效 MAC 的 release 时间统一验证
`startedAt <= releaseAuthorizedAt <= terminalAt`（Started-only 只验下界）。

**终审裁决 A（2026-07-15，已确认）：** P3.7 的 PGID fence 只保证 cooperative descendants：vendor/tool
后代必须保持继承 PGID，不主动调用 `setsid`/`setpgid`，也不通过 `launchd`/launch service 或其他
supervisor 脱离。该边界内仍严格保证 release 前零 vendor/tool 副作用，以及 owner drop、cancel、崩溃和
vendor 先退出时对同组子孙的 TERM→KILL/reap。显式自守护/逃逸是流程外不支持行为；当前实现不声称
检测、枚举或收割它，也不得声称逃逸会触发 `RecoveryBlocked`。需要该能力时另立真正执行域隔离方案。

架构选择不再阻断 P3.7，两个实现 finding 也已关闭。blocked gate 从 Ready 起由唯一并行 reaper 持有
`Child`，release 前 cancel/cleanup 只有 exact KILL 与 owner reap 都成功才可标 clean。production
`execution.prepare` 只把调用 Tokio `Command::spawn()` 前、确认无 child 的错误分类为
`PrepareFailedClean`；从调用 Tokio spawn 起可能已创建 OS child，因此其所有错误以及任一无法证明
identity/清理结果的 attach failure 都 fail-close 为 RecoveryBlocked。actor 级测试同时锁定 queued
successor 不启动与 clean terminal COMMIT-unknown exact
retry。“normal completion 已先赢、晚到 Cancel 覆盖 Completed”的 P1 也已用 typed cancel disposition
修复并有确定性测试。

前置分片已有 builder、COMMIT-unknown、disk/clock replay、append-vs-terminal、eventId pointer collision、
seq 9→10、64 MiB/+1、oversized backfill、dynamic audit 与 v1 terminal fence matrix 证据；完整命令见
`docs/QUALITY.md`。本 task 随后完成 `GatedChild/attach`、私有 FD codec、PGID/start-time、neutral
`AdapterItemKey`、adapter spawn ownership、真实 coordinator、两遍 orphan recovery 与 main bootstrap。
terminal safety reserve
继续保留旧版精确 132 MiB；fragmented SQLite + pinned WAL 已分别覆盖无 approval terminal，以及单 turn
32 条最大 approval 的真实样本，但未授权收窄 reserve。当前树的三份 adapter fixture 已筛选脱敏并记录
provenance/hash；祖先 `68b6cfd` 的旧 CC fixture 历史处置仍需另行授权，不能宣称完整 Git history 已清理。
S1 fixture、typed adapter prepare 与 typed execution journal 已分别提交为 `819aa5e`、
`1acf8b8` 与 `3f22cf0`。最终实现使用当前 daemon binary 的 `--exec-gate` 子模式、有界 ADGX 私有 FD、
独立 PGID、PID/start-time 与随机 release token commitment；Codex/CC typed driver 只拿私有 stdio，
prompt 不进 argv/env，terminal 等待所有 AdapterEvent durable ACK。adapter binary 选择只走与 gate 相同
的固定目录集合，拒绝继承 PATH。两遍 recovery 在安装任何 actor 前完成 exact orphan fencing；remote
Accepted 在 P4 前全局拒绝，无法证明已知 PGID 内 cooperative descendants 退出的单 conversation 标
RecoveryBlocked。canonical CC driver 使用 `--permission-prompt-tool stdio`，typed builder 已广告
Approval 并接通 durable `control_response`，但筛选 fixture 不替代已登录 vendor 的 live approval
门禁。debug-only production
wiring probe 用真实 daemon binary 与 `/bin/sh` 无副作用 helper 贯穿 Core/actor→gate→typed driver→
Store ACK→terminal，并在 reopen/backfill 后读回 item 与唯一 terminal。

最终 translator 复审又关闭 2 个 P1 与 1 个 P2：Codex/CC approval summary 现在只从已验证的最小动作
字段生成，并做 source pre-cap、secret redaction 与 UTF-8 安全限长；Codex 自由文本用可见 JSON 编码
保留换行/控制符边界并在无法完整展示时拒绝，CC 才折叠控制字符并截断。Codex command action 来自具体
command、完整 commandActions 或已验证 network target；file action 绑定同一 in-flight fileChange 的非空
proposed changes，可选 grantRoot/reason 只补充上下文。非选中 raw 字段不进 durable Store。Codex
completed frame 必须与 started kind exact 一致，`declined` 为 Canceled，
`inProgress`、未知/缺失 terminal status fail-close 且保留 in-flight；legacy compatibility 同样不再把
这些状态降级为成功。CC `tool_result` 未提供权威进程退出码，canonical、legacy 与 native history
统一保持 `exit_code=None`。

第二轮独立终审再关闭 2 个 P1 与 2 个 P2：Codex/CC 缺少 tool-specific 具体动作时不再生成泛化 approval；
Codex permission summary 复用 adapter 官方 profile validator，完整展示实际回送的
read/write/entries/glob/network profile 字段结构及其脱敏投影，adapter 响应仍回送已验证的原始字段值；
空、仅 scan-depth、无法建模或超过 1 KiB 均拒绝；route/output
Debug 显式隐藏 raw params。文档已把依赖常驻 sentinel 的事实从错误的“leader 先退出”改为“vendor 先
退出”。同轮 schema 复核还锁定 canonical memoryCitation identity 不落盘、官方 PatchChangeKind object
映射与已知 non-authoritative notification 不抢占最终 item；这些是官方 schema 行为测试，不冒充 live
fixture。

最终 CC 2.1.207 对照又关闭 2 个 P1：真实受限样本证明正常 turn 会产生
`status(requesting)`、hook 与 task lifecycle，binary/SDK contract 还包含
`task_progress/task_updated/background_tasks_changed/tool_progress`。canonical translator 现在对这些
非权威帧执行封闭 shape 校验后丢弃，未知 subtype/patch 仍 fail-close；筛选 fixture 与 binary-contract
测试的证据边界已分别记录。`result` 只有精确的 `success + is_error=false + duration_ms +
terminal_reason=completed` 且没有 deferred tool 时才产生 TurnComplete，`tool_deferred` 不再被伪造成
Completed。

已提交 fixture SHA-256 分别为 Codex
`78a40e4cce9952818021cf1626f02619eb6a19cdcfd5c62e938d016e86029f05`、CC simple
`2c4438598bd25a653987aae034f893da79cf4d8b425d0cb7c56f42e5eb30682b`、CC Bash
`92d973335697759d2e8e4024988303d73188755be0105520739426ec2300c84a`、CC lifecycle
`5e1b95e27d957ff00a9cc6b1d4cd7e3fe10691c69b28a1ae2f7e6a33126844f5`。

**Files:**
- Create (typed journal 前置分片): `agentdeckd/src/runtime/store/{command_event,execution_event}.rs`
- Create (typed journal 前置分片): `agentdeckd/src/runtime/store/worker/{critical_command,execution_event}.rs`
- Create (typed journal 前置分片): `agentdeckd/tests/{runtime_store_execution_event,runtime_store_execution_event_commit,runtime_store_execution_event_tamper,runtime_store_legacy_terminal}.rs`
- Delete (由更严格 production typed crate gate 取代): `agentdeckd/tests/runtime_execution_fixture.rs`
- Create/Modify (typed journal 前置分片): `agentdeckd/tests/support/runtime_event_tamper.rs`、
  `agentdeckd/tests/fixtures/{README.md,claude_code/{simple_turn,bash_tool_use,lifecycle_frames}.jsonl,`
  `codex/simple_turn.jsonl}`；删除未消费且含不适合入库材料的 `claude_code/plan_mode.jsonl`
  （祖先历史处置另行授权）
- Modify (typed journal 前置分片): `agentdeck-protocol/{src/runtime/failure.rs,tests/runtime_v1_contract.rs}`、
  `agentdeckd/src/{agent.rs,codex/translate.rs}`、
  `agentdeckd/src/runtime/{conversation,execution,model,router}.rs`、
  `agentdeckd/src/runtime/core/subscription_tests.rs`、`agentdeckd/src/runtime/store/**`
- Modify (typed journal 前置分片):
  `agentdeckd/tests/{adapter_state_boundary,agent_router,agent_trait_shape,runtime_snapshot,`
  `runtime_store_boundaries,runtime_store_capacity,runtime_store_hardening,runtime_store_journal,`
  `runtime_store_p34,runtime_store_stream_v4,runtime_stream}.rs`、
  `agentdeckd/tests/runtime_stream/{barrier_integrity,contract,store_commit_hub}.rs`
- Modify (typed journal 前置分片): `AGENTS.md`、`ARCHITECTURE.md`、`README.md`、
  `docs/{AGENT_DIAGNOSTICS,QUALITY,index}.md`、
  `docs/plans/{README,2026-07-10-relay-companion-mvp-design,2026-07-10-relay-companion-mvp-implementation}.md`
- Create: `agentdeckd/src/exec_gate/{parent.rs}`、`agentdeckd/src/{exec_gate,runtime/recovery}.rs`
- Create: `agentdeckd/src/runtime/{process_identity,production_execution_probe,runtime_execution_fixture_tests}.rs`
- Create: `agentdeckd/src/codex/{driver,driver_tests,runtime_translate,runtime_translate_tests}.rs`
- Create: `agentdeckd/src/claude_code/{driver,driver_tests,runtime_translate,runtime_translate_tests}.rs`
- Create: `agentdeckd/tests/{exec_gate,runtime_crash_recovery,typed_spawn_ownership,production_execution_wiring}.rs`
- Create: `agentdeckd/tests/support/exec_gate_wire.rs`
- Modify: `agentdeckd/src/{main,agent}.rs`
- Modify: `agentdeckd/src/codex/{adapter,translate}.rs`
- Modify: `agentdeckd/src/claude_code/{adapter,translate}.rs`
- Modify: `agentdeckd/Cargo.toml`

**当前 scoped commit 精确路径（2026-07-15）：** 上述 Files 同时记录已提交的 typed-journal 前置分片，
不能直接当作本次暂存清单。Step 6 必须逐文件暂存以下当前 60 个路径，不得使用目录级 `git add`；本地
`.superpowers/sdd/progress.md` 受主仓 `.git/info/exclude` 排除，只作工作账，不进入提交。

- 根文档：`AGENTS.md`、`ARCHITECTURE.md`、`README.md`。
- daemon 根：`agentdeckd/src/{agent,config,lib,main}.rs`。
- Claude Code：`agentdeckd/src/claude_code/{adapter,capabilities,driver,driver_tests,history,mod,`
  `runtime_translate,runtime_translate_tests,translate}.rs`。
- Codex：`agentdeckd/src/codex/{adapter,driver,driver_tests,mod,runtime_translate,`
  `runtime_translate_tests,translate}.rs`。
- exec gate：`agentdeckd/src/exec_gate.rs`、`agentdeckd/src/exec_gate/parent.rs`。
- Runtime：`agentdeckd/src/runtime/{conversation,core,core/subscription_tests,execution,hub,mod,model,`
  `process_identity,production_execution_probe,recovery,router,runtime_execution_fixture_tests}.rs`，以及
  `agentdeckd/src/runtime/store/{journal,mod,worker}.rs`。
- daemon tests：`agentdeckd/tests/{adapter_state_boundary,cc_translate,daemon_startup,exec_gate,`
  `production_execution_wiring,runtime_approval,runtime_crash_recovery,runtime_store_recovery,`
  `typed_spawn_ownership}.rs`、`agentdeckd/tests/support/exec_gate_wire.rs`，并删除
  `agentdeckd/tests/runtime_execution_fixture.rs`。
- fixtures：`agentdeckd/tests/fixtures/README.md`、
  `agentdeckd/tests/fixtures/claude_code/{control_request_can_use_tool,lifecycle_frames}.jsonl`。
- 下游文档：`docs/{AGENT_DIAGNOSTICS,QUALITY,index}.md`、
  `docs/plans/{README,2026-07-10-relay-companion-mvp-design,`
  `2026-07-10-relay-companion-mvp-implementation}.md`。

**Adapter interface:**
```rust
impl AgentRouter {
    pub(crate) async fn prepare_turn(
        &self,
        agent_kind: AgentKind,
        request: AgentTurnRequest,
        state: AdapterStateHandle,
    ) -> Result<PreparedAgentTurnHandle, ProtocolError>;
}

#[async_trait]
pub trait Agent: Send + Sync + 'static {
    async fn prepare_adapter_turn(
        &self,
        capability: &mut PrepareAdapterTurnCapability,
        request: AgentTurnRequest,
        state: AdapterStateHandle,
    ) -> Result<Box<dyn PreparedAgentTurn>, ProtocolError>;
}

pub trait PreparedAgentTurn: Send + 'static {
    fn exec_spec(&self) -> &ExecSpec;
    fn attach(
        self: Box<Self>,
        child: GatedChildIo,
        events: AdapterEventSink,
        approvals: AdapterApprovalSink,
    ) -> Result<AdapterCompletionFuture, ProtocolError>;
}
```

approval 继续只使用 P3.5 的 exact transient `BoundApprovalDelivery`；不得新增
`Agent::resolve_approval(&ExecutionId, ...)`。cancel 继续消费 exact
`RuntimeExecutionControl::cancel_and_wait_fenced()`，不得新增按 `ExecutionId` 查找 session/process 的
控制面。`PreparedAgentTurn::attach` 仅在 gate child 与 durable AdapterEvent COMMIT ACK 屏障一并实现时
加入；join/terminal 必须等待所有已接收 AdapterEvent 的 ACK，不能在前置 typed contract 中先暴露半套 API。

- [x] Step 1: 五个 crash boundary、父死但 vendor group 存活、PID reuse/start-time mismatch、TERM→KILL失败与 Accepted queue fencing tests 已落地；`releaseAuthorizedAt` 只表示允许 release，不证明 token 已送达或 vendor 已 exec。
- [x] Step 2: RED 阶段证明 adapter 仍直接 spawn，随后 gate/recovery suites 在真实 current-binary 路径转绿。
- [x] Step 3: 实现当前运行 binary 的`--exec-gate`子模式、继承私有 FD handshake、独立 process group、nonce/release token与Fence事务。gate control/spec、prompt和secret不放 argv/env；所有 typed adapter spawn ownership 移入 gate，translator 只产 neutral `AdapterItemKey` 事件，attach/join/terminal 等待 durable ACK。
- [x] Step 4: 真实无副作用 helper 已覆盖 PGID 清理与固定启动顺序 `singleton lock → Keychain/DB reconcile → fence classification/RecoveryBlocked → emit RecoveryReadyPermit`。blocked gate 从 Ready 起由唯一 reaper 持有；release 前 cancel/attach cleanup 只有 exact KILL 与 owner reap 都成功才可 clean。调用 Tokio spawn 前且证明无 child 的失败直接 Interrupted；从调用 Tokio spawn 起、identity 或清理不确定全部 RecoveryBlocked。execution/actor/COMMIT-unknown 聚焦回归已通过，不在文档固化易漂移的测试计数。P3.8 仍须在 permit 后 bind UDS，再产生 `RemoteStartPermit`。
- [x] Step 5: 两份真实 Claude Code execution fixture、真实 `can_use_tool` 筛选 fixture 与真实脱敏 Codex fixture 已覆盖私有 typed translator、production append/reopen/backfill 和 durable approval response；canonical CC Approval capability 已接通但 live vendor evidence 仍 gated。最终稳定树已读回 canonical translators 43/43、driver 25/25、CC legacy 16/16、permission response 2/2、daemon lib 601/601 与完整 package exit 0（既有外部 signed Keychain gate 1 ignored）；all-target check/clippy、fmt、schema、ephemeral daemon 启动、Swift 256 XCTest + 35 Swift Testing、App selfcheck、no-net、docs 与 diff 全绿。独立终审 Approved，无剩余 P0/P1/P2。
- [x] Step 6: 已逐文件暂存当前 60 个路径（Git 将 delete+create 识别为 1 条 rename/59 条 change record），`git diff --cached --check` 通过，unstaged/untracked 均为 0；提交 `5568e93`：`feat(daemon): 用两阶段 exec gate 封住副作用边界`。未使用目录级 `git add agentdeckd`，未 push。
- [x] Follow-up: `c9d2146` 用真实 current-binary probe 卡住 Ready→release 窗口并经 RuntimeCore 发起 Cancel，读回 Canceled、零 vendor side effect、exact PGID 退出与唯一 Interrupted terminal；内部故障清理统一写入 active gate 的 cancel/fence bookkeeping。`5713be4` 对 sentinel leader 已退出、同组 child 短暂存活的 Unknown 只在既有 grace 内只读等待 PGID absence，持续 Unknown/error/identity mismatch 仍 fail-close；两种 probe 增加 30 秒内部清理 deadline 与 35 秒 subprocess watchdog。聚焦 production wiring 2/2、execution 12/12、conversation 50/50、exec-gate 6/6、daemon lib 603/603、完整 package exit 0、fmt/clippy/diff 与两轮独立 review 均通过；既有 signed Keychain 1 项仍 ignored/BLOCKED。

### Task P3.8：接入 RuntimeEnvelope v1 UDS 与 stdio compatibility

**阶段状态（2026-07-16）：** P3.8-A 已完成 accepted-stream transport primitives、显式
local-control principal、真实 backpressure cancellation 与用途感知 network guard；两轮独立终审无剩余
P0/P1/P2。P3.8-B 按单任务代码不超过 2,000 行的刹车线拆为 B1/B2：B1 secure listener
primitives 已完成并从 clean detached HEAD 独立复验；B2 config/stdio/main 与 Rust/Swift stdio
compatibility 参数的原子切换已由 `459f32a` 提交。P3.9 shared-daemon client cutover 尚未开始；P3.1
provisioned signed Keychain 外部门禁继续 BLOCKED。

#### Task P3.8-A：transport primitives、local-control principal 与精确 network guard

**Files:**
- Create: `agentdeckd/src/local/{mod,framing,peer,unix}.rs`
- Create: `agentdeckd/tests/local_uds.rs`
- Create: `scripts/check-daemon-network-boundary.sh`
- Modify: `agentdeckd/src/{lib}.rs`
- Modify: `agentdeckd/src/runtime/{connection,core,mod}.rs`
- Modify: `agentdeckd/Cargo.toml`, `scripts/verify-relay-companion-mvp.sh`
- Modify: `ARCHITECTURE.md`, `docs/QUALITY.md`, `AGENTS.md`
- Modify: `scripts/check-daemon-no-net.sh`（只保留 `exec` 权威 network-boundary guard 的兼容 wrapper）

- [x] Step 1: 先写 RED tests。覆盖 same-EUID 必须先于 preface read；strict
  `LocalClientPrefaceV1` 的 canonical non-nil UUID、4 KiB bound、reconnect owner 稳定；wrong envelope
  version flush 一条同 messageId typed failure 后 EOF，malformed/duplicate/oversize 零 reply；首帧必须
  Hello，inner mismatch 仍走 Core typed reply；exact 1 MiB 拒绝。覆盖显式 local-control
  `ResolveAndRetry`、read-only local 无 approval、lease permission conflict；`ConnectionWrite` shared bytes、
  Core abort cancellation、ACK-after-cancel、慢 writer 与 sibling 隔离；真实 UDS 两连接、disconnect 不停 Core。
- [x] Step 2: 运行 `cargo test -p agentdeckd --test local_uds`、connection/core focused tests 与新 guard。
  Expected: FAIL，local module、Tokio net、writer cancellation 与 guard 尚不存在。
- [x] Step 3: 最小实现 bounded JSONL framing、header-first version probe、same-UID peer gate、首帧 Hello、
  per-connection reader/writer、local-control issuer 与 ConnectionWrite cancellation。所有 socket write/flush
  成功后才 ACK；Core cancellation 获胜时只关当前连接。A 只实现已 accept/已验证 stream 的 connection
  actor；pathname listener 只能由 `cfg(test)` fixture/测试直接持有的 Tokio listener 提供，不得暴露
  production `bind(path)`。production secure bind 与唯一 permit constructor 全部留到 B，确保 A 自身不
  产生 recovery 前可达的 listener。
- [x] Step 4: 实现 source/path guard：pathname Tokio Unix 只允许 `src/local/`；std Unix socketpair 只精确
  allowlist `exec_gate.rs`、`exec_gate/parent.rs` 与 execution test pair；全 daemon 禁 TCP/UDP/WSS/
  reqwest/axum/hyper server/tungstenite；同时检查 Cargo dependency tree 中的 banned crates/features，
  不能只靠 source grep。更新 verifier，并保留旧 `check-daemon-no-net.sh` 作为只 `exec`
  `check-daemon-network-boundary.sh` 的兼容 wrapper；后者才是权威实现。
- [x] Step 5: 跑 local/connection/core tests、daemon package、fmt/clippy、new guard、docs/diff；至少对一条
  真实本机 UDS Hello + request/reply 样本读回，不以 synthetic codec 单测代替。
- [x] Step 6: 独立 spec/security review 后精确暂存本切片并提交
  `feat(local): 建立 RuntimeEnvelope UDS 传输原语`；禁止目录级 `git add agentdeckd`，不 push。

#### Task P3.8-B：production bootstrap、RemoteStartPermit 与 stdio 收窄

**切片状态（2026-07-16）：**

- [x] B1 secure listener primitives：绑定具体 `RuntimeCore` 的 recovery permit、单次
  `LocalReadyPermit → RemoteStartPermit`、私有 canonical `TMPDIR`、retained-dirfd stale cleanup、
  Darwin FD/path 独立 readback、graceful connection supervisor，以及真实 active-turn/backpressure
  组合测试。此切片不包含 `config.rs` / `main.rs`、stdio compatibility 或客户端 cutover；commit
  `1e7f9ea` 的 clean detached HEAD 已通过 listener 4/4、local listener 7/7、真实 UDS 4/4、namespace
  23/23、StorageKEK 14 passed + 1 个既有 signed gate ignored、全目标编译、Clippy、fmt、两条 network
  guard、docs 与 clean status。
- [x] B2 原子 cutover：config mode、stdio exhaustive allowlist、production main、Rust/Swift stdio
  compatibility 参数、binary smoke 与候选文档由 `459f32a` 提交；不包含 P3.9 shared-daemon client。

**Files（按 B1/B2 实际切片校准）：**
- B1 Create: `agentdeckd/src/local/listener.rs`、`agentdeckd/tests/local_listener.rs`
- B1 Modify: `agentdeckd/src/local/{mod,unix}.rs`、`agentdeckd/src/runtime/{conversation,core,mod,namespace,recovery,singleton}.rs`、`agentdeckd/tests/{daemon_namespace,daemon_startup,storage_kek}.rs`
- B2 Create: `agentdeckd/src/local/stdio_compat.rs`
- Modify: `agentdeckd/src/{main,config}.rs`
- B2 Modify: `agentdeckd/src/runtime/{core,hub}.rs`、`agentdeckd/src/local/{listener,mod}.rs`
- B2 Modify: `agentdeckd/tests/{daemon_namespace,daemon_startup,local_listener,storage_kek,typed_spawn_ownership}.rs`
- Modify: `agentdeck-cli/src/transport.rs`, `Sources/AgentDeck/ProcessDaemonTransport.swift`
- Modify: 对应 Rust/Swift transport 参数测试
- Modify: `README.md`, `ARCHITECTURE.md`, `docs/{QUALITY,AGENT_DIAGNOSTICS,index}.md`、`docs/plans/{README,2026-07-10-relay-companion-mvp-implementation}.md`、`AGENTS.md`

- [x] Step 1: 先写 RED production tests。listener 在 `RecoveryReadyPermit` 前不存在；stale cleanup 与 bind
  必须验证 owned 0700 parent。Darwin 真实样本中 listener FD 为 `nlink=0`、pathname 为 `nlink=1`，
  dev/ino 也不同，因此禁止断言 FD/path dev/ino 相等：FD `fstat` 只独立验证为 socket；pathname 通过
  retained parent dirfd 的 no-follow `fstatat` 独立验证 socket type、0600/current UID/exact `nlink=1` 并捕获
  dev/ino，cleanup 只在 pathname exact identity 仍匹配时 unlink。active/symlink/regular/inode swap
  均不 mint permit；完整 readback 后所有 UDS 模式产生不可构造
  `LocalReadyPermit`，只有 stable+remote-enabled+canonical socket 才再产生单次消费
  `RemoteStartPermit`，ephemeral/no-remote 永不产生。production parser 必须拒绝 `--socket`，daemon
  不读取 socket path env override；显式 path 仅留 test helper。覆盖 stable canonical socket、私有
  `TMPDIR` 下自动派生且唯一的 `ad-*/s`；readiness 是 preface+Hello reply；stable stdin EOF 不退出，
  signal shutdown 顺序正确。
- [x] Step 2: 为 `RuntimeHub::admin_only` 写 exhaustive allowlist tests：stdio 仅接受完整显式组合
  `--stdio-compat --ephemeral --no-remote`，缺一项均 fail-close；Rust/Swift 兼容 transport 必须同批
  补传 `--stdio-compat`。allowlist 仅含 Ping/Selfcheck/ProtocolSchema/
  Version、AgentList/Capabilities、History List/Read；Start/Continue、三种 History mutation、SessionCancel、
  ActionDecision、VendorControl 与未来未列举 variant typed reject 且不进 router。所有可选 stdio 模式都
  构造同一 allowlist hub；完整 `RuntimeHub::new` 只能 `cfg(test)`。
- [x] Step 3: 接线 production main：`singleton → Keychain/DB → recovery permit → secure UDS bind/readback →
  LocalReadyPermit → stable-only RemoteStartPermit → run`；stable 由 UDS+signal 驱动，ephemeral 默认走
  private `TMPDIR` 派生 UDS，只有显式 `--stdio-compat --ephemeral --no-remote` 才走 admin/read stdio。
  shutdown 固定 future remote → local
  listener/connections → Core。
- [x] Step 4: 跑 daemon startup/local UDS/stdio/typed ownership tests、完整 daemon package、fmt/clippy、
  schema、两条 guard、ephemeral UDS binary smoke、docs/diff。smoke 使用 private exact 0700 `TMPDIR`，
  发现并验证恰好一个 `ad-*/s`，不向 daemon 注入 path。确认 malformed/oversize/slow client 只关闭
  自身，Core/active turn/PID 不变。fresh 默认并发 daemon package 已读回 lib 636/636 与全部
  integration/doc tests exit 0；StorageKEK 14 passed + 1 个既有 signed gate ignored。Hub 10/10、
  namespace 24/24、binary startup 8/8、listener 7/7、ownership 7/7、Rust transport 4/4、Swift
  256 XCTest + 35 Swift Testing、App selfcheck、schema、Clippy/fmt/network/docs/diff 均通过。首次完整
  回归因 49 GiB incremental cache 把可用空间压到准入线而触发 `DiskLow`；仅删除可再生缓存后，
  同一默认并发与真实 1,024 × 256 MiB 数据规模在 253.52 秒内通过，未改产品准入或测试 fixture。
- [x] Step 5: 独立 spec/security/quality review，修完 P0/P1/P2 后同步 README/ARCHITECTURE/QUALITY/
  DIAGNOSTICS/AGENTS 与本计划；代码终审无 P0/P1/P2，文档旧参数、状态矩阵与文件账本 findings 已
  修复并复跑 docs gate。P3.1 signed Keychain 仍保持外部 BLOCKED。
- [x] Step 6: B2 精确暂存 23 个计划内路径（`+1141/-160`），cached diff 终审无 P0/P1/P2 后以
  `459f32a feat(daemon): 以 UDS 暴露 RuntimeEnvelope v1` 提交；未把 P3.9 App/CLI cutover、P4 remote
  start 或外部签名证据写成已完成，未 push。

### Task P3.9：macOS App 与 CLI 默认连接同一 UDS

**前置冻结（P3.9-C0）：** P3.8 只证明 RuntimeEnvelope v1 可以经安全 UDS 进入
`RuntimeCore`，尚未证明当前 App/CLI 的完整用户行为可以迁移。具体威胁场景是：若把默认 transport
直接从 IPC v2/stdin 换成 Runtime v1，当前 `SessionStart.vendorOptions` 会被丢弃，Codex sandbox /
approval/reasoning 与 CC permission mode 会静默回落到 daemon 默认值；history list/read/mutation、
agent capabilities 和 vendor control 也没有对应 request/reply，最终会出现“连接成功但策略、历史和控制
面退化”，并让 legacy `sessionId/threadId` 与 canonical `conversationId` 混用。故在任何 App/CLI 默认
cutover 前，必须先把 wire 原子升级为 Runtime v2，并完成 contract、schema、Rust fixture、Swift mirror、
configuration store/execution 与 native-history projection review；未完成 C0 时 P3.9 不得标 complete。

P3.9 固定以下迁移边界：

1. `RUNTIME_PROTOCOL_VERSION` 从 1 升到 2；新增 request/reply/event/configuration 后不提供 production
   双栈，v1 client 收到 typed protocol mismatch。同步 Runtime schema、Rust fixture、Swift mirror，重生成
   所有绑定 Runtime version 的 Relay cert/TBS、revocation 与 wire vectors；历史 P1–P3.8 记录仍保留为
   v1 事实，P3.9 之后的目标统一称 Runtime v2。
2. 新会话固定走 `Start → ConfigureConversation(expectedRevision=0) → Subscribe →
   SendPrompt(expectedConfigurationRevision=1)`。configuration 是 append-only revision；Configure 用 CAS+
   idempotency，Accepted command 在同一事务 pin exact revision，之后的配置更新不得改变已 Accepted/
   queued/recovery command。crash recovery 只能按 command 引用的 revision 构造 driver，不能读取“最新值”。
3. configuration 只能出现在 `vendorControl.*` namespace。Codex v2 冻结
   approvalPolicy/sandbox/reasoningEffort；CC v2 冻结 permissionMode/model/effort/outputStyle。Codex
   `persistApproval` 由每次 `ActionDecision.persist` 表达，`mcpOverrides` 无真实执行路径；CC `sessionId`
   永不进 wire，allowed/disallowed tools、mcp path、plugin dirs/hooks 暂不承诺，worktree/sessionName 取得
   真实首次启动+resume样本前非空 typed reject。配置变化发布 `ConfigurationChanged`；vendor panel event
   继续只在 `vendorPanel.*` namespace。
4. Runtime v2 增加 `DescribeAgents`，返回 capabilities 与 default configuration；任意已认证 Runtime
   principal 可读。`ping` 映射 Hello，普通 selfcheck/agent list/capabilities 映射 Hello+DescribeAgents；完整
   bootstrap selfcheck/diagnostics 保留显式 one-shot 运维入口，不新增 remote local-status 旁路。
5. 旧原生 history 不得把 Codex thread id、CC session id 或 raw transcript path 返回客户端，也不开放
   public “导入某 vendor ID” Runtime request。daemon bootstrap/reconciliation 让 adapter 私域有界扫描并
   验证真实 entry，再以 namespace+opaque reference 域分离稳定派生 `conversationId + adapterStateKey`，
   在一个事务提交 private binding、neutral descriptor 与 catalog delta。native transcript 不复制进 Runtime
   DB；adapter read 返回 stable native item key，Runtime 域分离派生稳定 item/entity/command identity，重复
   read/restart 必须 byte-stable。list/read 统一走 Catalog + Subscribe/Snapshot。managed conversation 的
   rename/archive 走 canonical metadata CAS；native-projected conversation 继续调用原生 mutation并读回投影，
   原生不支持时保留现有 typed unsupported，不静默改成 AgentDeck-only 行为。
   扫描/解析在 SQLite transaction 外完成；每轮最多检查 2,000 candidates、导入 500 conversations、累计
   读取 64 MiB、wall-clock 2 秒，达到任一上限保存 continuation 并让出。单 transcript snapshot 受
   64 MiB/10,000 items 上界，超限 typed fail，不阻塞 UDS readiness。
   Runtime store 明确持久化 authenticated `ConversationOrigin::Managed | NativeProjected(namespace)`：v4
   migration=Managed，projector import=NativeProjected，不以 adapter binding 猜 origin。native mutation 先用
   expected entry revision + idempotency key CAS claim，再由 conversation actor 串行执行 vendor/readback，并
   durable 记录 `Claimed/Applying/Applied/OutcomeUnknown/Failed`；未 claim writer 零 vendor 副作用。
   `NativeTurnKey` 派生 history commandId，`NativeItemKey` 派生 item/entity ID；同一 turn 共享 commandId，
   QueryReceipt 对已验证历史 ID返回 `daemon.command.history_only`，绝不冒充 Accepted。
   只有完整 scan generation 后确认 absent 才发布 Catalog Removed；partial page 不删除。binding/identity
   tombstone 保留 30 天且不计 active 1,024 cap，重现复用同 conversation；达到 active cap 时 typed truncated。
6. v2 从 `ConversationEntry`、`ConversationStartReceipt`、Swift mirror、schema 与 fixture 删除
   `adapterStateKey`。client 只持 `conversationId`，daemon 内部从 authenticated store 解析 exact private
   handle；全 public wire/log/Debug 扫描不得再出现它。
7. App 与 CLI 各持一份安装级 `clientInstallationId`；App 固定
   `~/Library/Application Support/AgentDeck/clients/macos-app/installation-id.v1`，CLI 固定
   `~/Library/Application Support/AgentDeck/clients/cli/installation-id.v1`。parent exact 0700、record exact
   0600、`O_NOFOLLOW`、同目录 temp + fsync，并用 Darwin
   `renameatx_np(..., RENAME_EXCL)` no-replace 提交 final path；首次并发 loser 只读回并验证 winner，绝不
   覆盖。损坏、symlink、hardlink、owner/mode 不符都 fail-close，不能静默轮换。该 ID 不是 secret，也
   不能替代内核 peer credential。home 必须由当前 EUID 的 `getpwuid_r` 解析，禁止信任 `HOME`。
8. stable App/CLI 只发现 `DaemonPaths.socket`；dev/test 只能由显式注入的已验证 endpoint 或 private
   `TMPDIR/ad-*/s` discovery 进入。production client 不读取任意 socket path env override，也不 fallback
   spawn。普通 App/CLI selfcheck 走 UDS Hello+DescribeAgents；`ProcessDaemonTransport` 只留 preview/test 与
   显式 one-shot bootstrap 的 `--stdio-compat --ephemeral --no-remote` compatibility，production App 永不因
   selfcheck 或 connect failure fallback spawn。
9. Parser/转换逻辑遵守真实数据先行：先读回现有 `NewSessionDialogEncodingTests` 的真实 Swift
   `SessionStart` 编码与一份真实 UDS Hello/reply；configuration parser 只接受已冻结的可验证子集。history
   projector 在被视为可用前必须对一份真实 `~/.claude/projects/.../*.jsonl` 完成
   list→import→Catalog→Snapshot/readback；合成 round-trip/fixture 不能替代真实样本。

**Files:**
- Create: `agentdeck-protocol/src/runtime/{configuration,metadata,upgrade}.rs`
- Create: `agentdeck-protocol/tests/runtime_v2_dto_primitives.rs`
- Rename/Modify: `agentdeck-protocol/tests/runtime_v1_contract.rs` → `runtime_v2_contract.rs`
- Create: `protocol/agentdeck/fixtures/runtime-v2-wire.jsonl`；既有 `runtime-v1-wire.jsonl` 在 A2 前继续
  作为 frozen Swift compatibility artifact 保留，current Rust contract gate 原子切换到新增 v2 fixture
- Create: `agentdeck-cli/src/unix_transport.rs`
- Create: `agentdeck-cli/src/installation.rs`
- Create: `agentdeck-cli/tests/shared_daemon.rs`
- Create: `Sources/AgentDeck/{UnixSocketDaemonTransport,RuntimeEnvelopeClient}.swift`
- Create: `Sources/AgentDeck/LocalClientInstallation.swift`
- Create: `Tests/AgentDeckTests/{UnixSocketDaemonTransportTests,RuntimeEnvelopeClientTests}.swift`
- Create: `scripts/run-local-runtime-smoke.sh`
- Modify: `agentdeck-protocol/src/runtime/{command,envelope,event,receipt,catalog,sync,schema,mod}.rs`
- Modify: `protocol/agentdeck/runtime-protocol.schema.json`
- Rename: `Sources/AgentDeckCore/Protocol/RuntimeV1Types.swift` → `RuntimeWireTypes.swift`（只做 version-neutral
  文件归位，不 bulk 改 3,000+ 行 leaf symbol）
- Create: `Sources/AgentDeckCore/Protocol/RuntimeV2Types.swift`（A2a：复用 wire 未变的 leaf DTO）
- Create: `Sources/AgentDeckCore/Protocol/RuntimeV2StreamTypes.swift`（A2b：catalog/event/snapshot/backfill）
- Create: `Sources/AgentDeckCore/Protocol/RuntimeV2WireCodec.swift`（A2c：outer/current codec/transfer）
- Rename: `Tests/AgentDeckTests/RuntimeV1ProtocolTests.swift` → `RuntimeProtocolCompatibilityTests.swift`
- Create: `Tests/AgentDeckTests/RuntimeV2ProtocolTests.swift`
- Modify: `agentdeckd/src/runtime/{core,conversation,execution,snapshot,events,model,router}.rs`
- Modify: `agentdeckd/src/runtime/store/{schema,worker,journal,catalog}.rs`
- Modify: `agentdeckd/src/{agent,codex/adapter,claude_code/adapter}.rs`
- Modify: `agentdeckd/src/claude_code/{history,state}.rs`
- Modify: `agentdeck-protocol/src/relay_v2/{auth,frame}.rs`
- Modify: `agentdeck-protocol/tests/{relay_v2_contract,relay_v2_revocation_canonical_contract}.rs`
- Modify: `protocol/agentdeck/fixtures/relay-v2-wire-vectors.json`
- Create: `agentdeckd/src/runtime/store/configuration.rs`
- Create: `agentdeckd/tests/{runtime_configuration,native_history_projection,runtime_metadata_mutation}.rs`
- Modify: `agentdeck-cli/src/{transport,client,commands,output,main,main_types}.rs`
- Modify: `Sources/AgentDeck/{DaemonTransport,ProcessDaemonTransport,DaemonClient,SessionModel,WorkbenchModel,ThreadRuntimeModel,AppDelegate,main}.swift`
- Modify: `Sources/AgentDeck/session/{NewSessionDialog,AgentControlBar}.swift`
- Modify: `Sources/AgentDeck/agent/{codex/CodexSessionOptionsForm,claudecode/ClaudeCodeSessionOptionsForm}.swift`
- Modify: `Sources/AgentDeck/capability/CapabilityRouter.swift`
- Modify: `Sources/AgentDeck/Preview/{MockDaemonScript,MockDaemonTransport,PreviewBootstrap}.swift`
- Modify: `Sources/AgentDeckCore/HistoryModel.swift`
- Modify: `Tests/AgentDeckTests/{NewSessionDialogEncodingTests,RuntimeAgentKindTests}.swift`

- [x] **P3.9-C0-A0 version-neutral 机械切片：** 只把 Swift mirror/test 文件移动到 version-neutral 名称，
  不 bulk 重命名 3,000+ 行 leaf symbols、不改 wire；运行原 Swift contract 全绿并独立 review/提交。该切片
  只消除文件名误导，不宣称 Runtime v2。commit `d4057f1`；Swift compatibility 26/26、完整
  256 XCTest + 35 Swift Testing 全绿。独立 review 唯一 P2 是旧 filter 会 0-test 假绿，已同步修正
  AGENTS/QUALITY 三个可执行入口后关闭；最终无 P0/P1/P2。
- [x] **P3.9-C0-A1 Runtime v2 Rust contract：** 先读回真实 Swift `SessionStart` 样本；冻结
  `DescribeAgents`、`ConfigureConversation`、`UpdateConversationMetadata`、dormant local-only
  `StageUpgrade`、configuration/metadata/upgrade receipts、
  `SendPrompt.expectedConfigurationRevision`、receipt/snapshot/event revision。把 Runtime version 升到 2，
  从 Start receipt/Catalog 删除 adapterStateKey，保留 frozen v1 fixture 并新增 v2 fixture、原子切换
  current Rust gate，更新 schema 与 Relay-bound vectors；v1 mismatch、neutrality、deny-unknown、CAS DTO
  与 private-handle scan 全绿，独立
  review 后提交
  `feat(protocol): 升级 shared daemon Runtime v2 契约`。
  - [x] **A1a1 additive validated DTO primitives：** 只增加 configuration、metadata、upgrade 与 agent
    discovery 的 validated DTO、receipt 对称校验和行为测试；不提升 production Runtime version、不删除
    既有 public 字段、不改 daemon callsite/schema/vector。commit `3b83391`；代码与测试共 1,373 行，
    DTO 3/3、protocol all-target check、production lib clippy、fmt/diff 与 clean detached HEAD 独立复验
    全绿，终审无 P0/P1/P2。
  - [x] **A1a2 Runtime v2 outer cutover/callsite/vectors：** 已原子提升 Runtime version、接入 outer
    request/reply/event/snapshot/catalog，删除 public private-handle，明确 daemon rev0/feature-unavailable
    过渡语义，并同步 schema、current Runtime fixture、共享 crypto golden 与 Relay fixture metadata。
    frozen v1 Swift compatibility fixture 继续保留；v4 persisted catalog/snapshot 使用严格 legacy
    dual-decode/readback，`runtime_meta.schema_version` 未变化时不会把已存在状态误判损坏。
    最终按新增行口径复算为 2,143 行，不能用删除旧 contract test 后的净增规避 2,000 行刹车线，因此拆成：
    - [x] **A1a2a main cutover：** commit `c28a968`；Rust/Swift 代码与测试新增 1,748 行，包含 Runtime v2
      outer/callsites、carrier-specific transfer 上限、legacy dual-decode、schema/fixture/vector 与
      production pump typed `PayloadTooLarge` 映射。
    - [x] **A1a2b real-data reader：** commit `c36a4f9`；新增 395 行，只接入 ignored 真实样本 reader，
      不增加 production API 或旁路构造器。cutover 前 `3b83391` 的真实 Runtime v1 writer 生成临时 DB
      v4/KEK，当前 reader 完成 catalog delta、既有 catalog baseline 与两段 conversation snapshot
      transfer 的 v2 readback；该门禁发现并修复了“转换后 DTO 与旧 plaintext 做 canonical 比较”的
      baseline bug。ciphertext logical manifest 前后均为
      `488193ed84b3c777fb0cf394845e5068ff0f6b21f8d782a13bf2ebffa7ad779a`；legacy plaintext=
      `e48db4fcec7a42edf6b2d94de719216cc9bfc1f65d9cdb9f88237727cc139491`，v2 wire=
      `d5607fa2d85ea9ee97f0359761c7bd442d15456b40419ce47ff4b6788f013e5e`；临时 KEK/DB 与 1.1 GiB
      archive target 已按 exact tempdir 删除。
    JSON/UDS 使用独立 94-part ceiling 表达完整 64 MiB，remote compact 保持 64 parts；若合法 v1
    plaintext 已恰好占满 64 MiB，新增必填字段后向 subscription client 返回 typed
    `daemon.payload.item_too_large`，不截断、rebuild 或改写旧 ciphertext。独立 spec/security/quality
    终审发现的 1 个 P1 与 4 个 P2 均已修复并复核，无残留 P0/P1/P2。A1a1+A1a2 已完成，故 A1a
    complete；总 A1 由下面 A1b 一并收口。
  - [x] **A1b signed-material hard-cutover gate：** commit `ef830cd`；以真实 Ed25519 key 从 current TBS
    只改 `runtime_protocol_version=1`，证明旧签名对 v1 TBS 有效、对 current v2 TBS 无效。升级前已按
    exact canonical hash 持久化的 cert/grant 在 Store reopen 后经 current challenge possession proof
    仍统一拒绝；current MachineAccess 提交旧 grant/revocation/retirement 也全部返回
    `relay.auth.invalid_grant`。同一 SQLite observer 的 `data_version`/授权语义快照与五个
    pre-COMMIT/confirm tripwire 共同证明 Store 零提交且 transition 完整回滚。独立 Direct TLS enrollment
    E2E 又分别证明旧 Link/Data cert 返回通用 403，且同一未消费 code 的原 v2 request 随后成功。
    终审发现的 2 个 P1 与 2 个 P2 均已 red→green，最终 spec/security/quality 三路 Approved；代码与
    测试新增 730 行，低于 2,000 行刹车线。P4 投产前的开发凭据必须执行受控
    reset/re-enroll/re-pair；当前不新增 production 双栈或 legacy verifier。A1a/A1b 均完成，故 A1 complete。
- [ ] **P3.9-C0-A2 Swift v2 mirror：** 具体威胁场景是：若直接复用 Swift synthesized `Codable`、现有
  宽松 `VendorPanelPayload` 或 Runtime v1 transfer codec，Rust 已拒绝的 unknown/missing/null 输入会被
  Swift 接受或重编码漂移，JSON/UDS 的 64-part 旧上限还会截断合法 64 MiB v2 transfer。故 A2 必须使用
  strict exact-key decoder、required-null presence check 与独立 v2 carrier profile；不把 fixture 正向
  round-trip 当成全部证据。
  在三个职责单一的 v2 文件只实现 changed DTO/stream/codec，复用 wire 未变的既有 leaf types，禁止一次性
  全文件符号替换。A2c 必须新增可编译、被测试直接调用的
  `runtimeProtocolVersionV2: UInt16 = 2`、
  `runtimeProtocolVersionCurrent: UInt16 = runtimeProtocolVersionV2` 与
  `typealias RuntimeWireCodec = RuntimeV2WireCodec`；v1 codec 仅供 frozen compatibility tests 使用。
  production source 静态扫描不得引用 v1；这不代表 App/CLI 已完成 UDS
  cutover。预估完整代码与测试
  3,100–3,800 行，按新增/修改代码口径预先拆为三片，每片独立 TDD/review/commit：
  - [ ] **A2-0 真实 UDS 样本前置门禁（不新增 production code）：** 在写 Swift outer validator 前，启动
    current Rust ephemeral/no-remote daemon，经其实际派生并验证的 UDS endpoint 发送 preface + Runtime v2
    Hello，捕获一份 exact raw reply 到仓库外 0600 临时文件；记录 byte count 与 SHA-256，并先用 current
    Rust codec 读回。A2c 必须再让 Swift `RuntimeWireCodec` 解码同一份 raw bytes 并做语义等价重编码后才可
    删除临时样本；`runtime-v2-wire.jsonl` 或合成 socketpair 不能替代该门禁。不得向 daemon 注入任意 socket
    path，也不得把运行记录、用户路径或临时样本提交进仓库。
  - [ ] **A2a strict DTO/receipt primitives（约 1,100–1,300 行）：** configuration、metadata、upgrade、
    agent descriptions 与 changed receipt；手写 deny-unknown、missing/null/default、文本/agent/revision
    validation，禁止改宽 IPC v2 公共 vendor 类型。Codex 三个 configuration 字段全部 required；CC
    `permissionMode` required，`model/effort/outputStyle` 均允许 missing 或 null，统一规范化为 `nil` 且
    egress 显式 `null`，非 nil 文本必须为 1…1024 UTF-8 bytes 且不含 NUL。vendor tag、capabilities 与
    default configuration 必须 agent 匹配；AgentDescriptions 允许空、最多 16 个且 agent kind 不重复。
    `ConversationConfigurationState` 只允许
    `revision=0 + configuration=null` 或 `revision>0 + configuration!=null`；Rename 的 `title` key 必须存在，
    可为 null；非 nil title 允许空字符串、最多 4096 UTF-8 bytes 且不含 NUL。只有 configuration/metadata
    `Applied/Replayed` revision 强制非零；configuration/metadata 的
    expected/conflict revision、CommandReceipt/CommandStatus configuration revision 均允许 0，以读回 legacy
    recovery；CommandStatus `turnId` 的 missing/null 都接受，不擅自按 status 加严。upgrade 必须对称校验
    lowercase 64-hex SHA、1…128 bytes ASCII target（拒绝 `.`/`..`）、`localOnly` scope 与
    `AwaitingIdle.activeTurns>0`。新增 ingress 与 egress 对称负向测试，不能只测 decoder。
    提交前运行 focused A2a tests、完整 `swift test`、既定 iOS XcodeGen + `xcodebuild test`、docs/diff gate，
    并独立复审；任何 0-test filter 不算通过。
  - [ ] **A2b stream projection types（约 850–1,100 行）：** catalog、event、Runtime 专用 strict
    vendor-panel、snapshot、backfill；固定 required-null identity、capabilities-first、configuration agent
    match。Catalog reply `nextPageCursor` 必须 present、可为 null；entry 的 `title/cwd` 允许 missing 或 null
    并统一为 `nil`、egress 显式 null，`entryRevision/lastActiveMs/catalogRevision` 均允许 0；Catalog 拒绝
    第 501 row 与 bare encoded bytes `>64 MiB`，Removed change 保持 Rust wire 的
    `conversation_id` key。Runtime event 的 `commandId/itemId/entityId` 及 ApprovalResolved `decision` 必须
    present、可为 null，`eventSeq=0` 合法；按 body 执行 command/item/entity identity 矩阵。Runtime 专用
    vendor-panel 外层与嵌套 payload 都拒绝 unknown；CC panel optional 的 missing/null 都规范化为 nil、egress
    显式 null。Snapshot 必须非空、capabilities first 且恰好一次，configuration 非空时 agent 必须匹配。
    Backfill 是 after-exclusive/through-inclusive 的 1…512 连续范围，拒绝第 513 entry、空/非连续 range、
    delta/event sequence 或 conversation scope 不匹配、bare encoded bytes `>64 MiB`；所有门禁均有
    ingress/egress 负向测试。Swift 符号
    `RuntimeAdapterStateKey` 改为明确的 `RuntimeAdapterStateKeyV1Compatibility`，只允许出现在
    compatibility kind/typealias 定义、`RuntimeConversationEntryV1`、`ConversationStartReceiptV1` 的字段/codec
    与 frozen v1 compatibility tests；不改 legacy JSON key，也不删除 frozen v1 fixture。专门的 source
    gate 必须证明 frozen `RuntimeWireTypes.swift` 中 unsuffixed `RuntimeAdapterStateKey(Kind)` exact token 为
    0、`RuntimeAdapterStateKeyV1CompatibilityKind` exact token 为 2、
    `RuntimeAdapterStateKeyV1Compatibility` exact token 为 6，且 compatibility tests 以外的其他 Swift source
    为 0；不能因整文件排除而漏过旧 public alias。提交前运行 focused A2b tests、完整 `swift test`、既定
    iOS XcodeGen + `xcodebuild test`、docs/diff gate并独立复审；任何 0-test filter 不算通过。
  - [ ] **A2c outer/codec/current gate（约 1,150–1,400 行）：** request/reply/message/stream/envelope、
    JSON/UDS 700 KiB × 94 parts、compact 3.5 MiB × 64 parts、共同 64 MiB 与 `ADRT1` carrier version 2；
    Catalog request `pageCursor` 必须 present、可为 null；`ttlSecs` missing 固定默认 300、显式 null 拒绝；
    message/transfer ID 必须为 1…1024 UTF-8 bytes。
    JSON/UDS envelope 与 request 都严格 `<1 MiB`，exact 1 MiB ingress/egress 拒绝；compact carrier 严格
    `<4 MiB`，并对 SHA-256 exact 32 bytes、index/count、part/total、`partCount × profilePartBytes`
    representability 做双向负向测试，明确证明 JSON 的 64 parts 不能表达 64 MiB、94 parts 可以，而
    compact 仍只允许 64 parts。全量 98 条 Rust fixture 必须断言 case 唯一及 96 envelope + 1 JSON transfer
    + 1 compact carrier，逐条语义等价、compact byte-exact、v1/v2 mismatch；
    `RuntimeWireCodec` 的测试必须证明 current constant 为 2、v1 JSON/compact ingress 与构造 version=1 的
    egress 均拒绝，避免 no-v1 scan 在 A2 前空跑。静态 gate 精确扫描 `Sources/AgentDeck/`、
    `Sources/AgentDeckRelayClient/`、`ios/AgentDeckMobile/` 与除 `RuntimeWireTypes.swift` 外的
    `Sources/AgentDeckCore/`，不得引用 v1 protocol constant/error、changed outer/stream DTO、codec/transfer 或
    `RuntimeAdapterStateKey*`；三个 v2 文件、v2 schema 与 fixture 不得出现 `adapterStateKey`。只排除 frozen
    `RuntimeWireTypes.swift`、compatibility tests 与 v1 fixture，避免兼容工件造成假失败；Core 同时保持无
    AppKit/UIKit/Network/CryptoKit。提交前运行 focused A2c/98-fixture/current-facade tests、完整
    `swift test`、既定 iOS XcodeGen + `xcodebuild test`、App selfcheck、docs/diff gate，并独立复审；任何
    0-test filter 不算通过。A2-0 捕获的真实 UDS Hello reply 必须由 current Swift codec 成功读回后才算
    A2 complete。
    任一切片超过 2,000 行立即停下再拆，不以删除/机械 rename 抵消新增行。
- [ ] **P3.9-C0-B configuration store/execution：** Runtime DB v5 增加 append-only sealed
  configuration versions、conversation/command revision 与 idempotency/token ledger；Configure CAS 与 metadata
  mutation 分开提交：Configure 只推进 configuration journal + `ConfigurationChanged` conversation event，
  不改 catalog；metadata mutation 只更新 descriptor/lifecycle + entry/catalog revision + CatalogDelta，不写
  conversation event。canonical prepare 消费 command pin 的 exact config；覆盖并发
  writer、重放/冲突、配置后改不影响 queued command、restart/recovery、receipt/event/snapshot 一致。用
  recorded vendor argv/control fixture 验证冻结字段，但不冒充 live login。独立 review/提交。
- [ ] v4→v5 migration 固定：existing conversation 迁为 rev0/unconfigured；迁移前已 Accepted/Started command
  以 command revision 0 表示 frozen P3.7 legacy defaults，且只允许 recovery 消费；所有 v5 新 command 必须
  引用存在的非零 revision。用户继续既有 v4 conversation 前必须先 Configure；native importer 原子种入
  DescribeAgents 对应 default rev1，避免把 native history 错当 legacy command。
- [ ] **P3.9-C0-C native history projection：** daemon bootstrap/reconciliation 调 adapter-private
  projector；CC 使用 OS account home、no-follow/current-UID/regular-file/有界 JSONL 读取，单事务 import
  private reference + canonical descriptor/catalog；adapter read 返回 stable native item key，Runtime 不复制
  transcript 而生成 byte-stable snapshot identity。真实 CC JSONL 完成 list→import→Catalog→Snapshot
  readback；重复扫描/读取、重启、碰撞、append、原生 rename/unsupported archive 与 raw-id/path wire scan
  全绿。Codex backend 未实现时能力明确 unavailable，不伪造对等。独立 review/提交。
- [ ] **P3.9-A Rust client：** 写 installation record 的 symlink/hardlink/mode/owner/corrupt/concurrent
  tests，再实现 CLI 独立 installation store、Unix transport、preface+Hello、messageId correlation、bounded
  reply/stream pumps 与 close-only shutdown。CLI 默认 stable UDS，显式 test endpoint 只能经注入；默认路径
  静态/动态证明不 spawn。focused tests 与 clippy/fmt 通过后独立提交。
- [ ] **P3.9-B Swift client：** 先写 installation/Unix socket/partial write/oversize/EOF/protocol mismatch/
  out-of-order reply/stream/backpressure tests，再实现 `LocalClientInstallation`、
  `UnixSocketDaemonTransport` 和 actor-owned `RuntimeEnvelopeClient`。所有 request 由 client 生成 canonical
  messageId，reply 精确相关，stream 独立有界；析构/窗口关闭只 close fd，不终止 daemon。focused 与完整
  `swift test` 通过后独立提交。
- [ ] **P3.9-C3 App model cutover：** 迁移 `SessionModel`/`WorkbenchModel`/`ThreadRuntimeModel` 到
  conversationId/eventId/itemId/entityId/commandId；删除 synthetic agentItem 序号和 legacy identity adoption，
  prompt/approval/vendor control/history 都走 `RuntimeEnvelopeClient` receipt/stream。preview/mock 可显式保留
  compatibility fixture，production App 不得构造 `ProcessDaemonTransport`。完整 Swift tests 后独立提交。
- [ ] **P3.9-D 默认入口与真实 smoke：** Rust CLI与Swift client连接同一 private-TMPDIR daemon，看到
  同一 conversation/queue/receipt；关闭任一客户端后 daemon PID/active turn 不变。脚本只以
  `agentdeckd --ephemeral --no-remote` 启动并发现/验证恰好一个 `TMPDIR/ad-*/s`，不向 daemon 注入 path；
  两个真实 client 进程重启读回各自稳定 installation ID。再验证 stable endpoint 缺失时 typed fail、无
  fallback spawn。运行完整 cargo/swift/selfcheck/network/schema/docs/diff gates并独立提交。
- [ ] **P3.9-E 收口：** 独立 spec/security/quality review，修完 P0/P1/P2；同步 README、
  ARCHITECTURE、QUALITY、DIAGNOSTICS、AGENTS、本计划与 progress。依赖真实 Codex/CC login 的 initial
  config/control smoke 单独 gate；缺登录时保留 BLOCKED，不影响 transport synthetic 事实但 P3 phase exit
  不得冒充全绿。最终核对精确 pathspec 和 clean git status。

### Task P3.10：实现 LaunchAgent 安装、versioned upgrade 与保留数据的 uninstall

**前置冻结：** local-only typed `StageUpgrade` request/reply、授权与错误语义已纳入 P3.9-C0-A 的 Runtime
v2 contract；P3.9 Core 对它固定返回 typed feature-unavailable，remote principal/Relay 路径 typed reject。
P3.10 只补执行语义，不再改变 wire 或升级 Runtime v3，也不得临时复用 generic command/vendor control。

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

- [ ] Step 1: 写crypto/replay/publication tests。 CatalogKey/ConversationDEK/DeviceCommandTxKey/DeviceReplyTxKey方向；MachineDataSign来源；新增/撤销设备轮换catalog与active conversation epoch，新设备拿不到旧epoch且从barrier定向snapshot接续；EpochBarrier绑定generation/outer cursor/tagged inner cursor/key revision，且只使用Relay-committed outer+inner对应cut；unknown higher revision 3次/30s KeySync；lower revision隔离；CounterGuard先于DB、DB备份rollback、nonce reuse、4,096 window、retired key 24h+1h。 对catalog/event/barrier分别注入四个publish边界，重启只允许逐字节重发冻结blob。
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
- Create: `scripts/run-relay-companion-p4-real-e2e.sh`
- Modify: `scripts/verify-relay-companion-mvp.sh`
- Modify: `README.md`, `ARCHITECTURE.md`, `docs/QUALITY.md`, `docs/AGENT_DIAGNOSTICS.md`, `docs/index.md`, `AGENTS.md`, `docs/RELAY_RUNBOOK.md`

- [ ] Step 1: 写默认合成E2E与gated真实E2E。 合成链路不需vendor login，完成enroll→invite→PairRequest→本地pending fingerprint读回/approve→grant→catalog→open→prompt→approval→reconnect/replay→revoke，并证明远端confirm被拒；真实suite分别验证Codex/CC start/continue/approval/history且receipt来自daemon。real harness preflight 还必须读回 provisioned release-signed daemon helper 与 CLI 的 TeamIdentifier/entitlement/access-group，运行 daemon signed Keychain set→load→delete、versioned helper readback 和 CLI persistent identity/counter restart；在双 vendor 证据之后，以可丢弃 trust domain 执行完整 `daemon uninstall --purge`，读回 RetireMachine/Relay purge absent、`launchctl bootout`、PID/UDS 消失、版本目录/plist 与本地 DB/Keychain/receipt 全部删除，再重新 install/enroll 证明可恢复。缺任一签名输入、vendor login 或 destructive-profile 二次确认都输出BLOCKED且不生成evidence。
- [ ] Step 2: 运行 `bash scripts/verify-relay-companion-mvp.sh p4-auto`。 Expected: FAIL，脚本尚未编排新RemoteLink/CLI suites或文档仍称remote skeleton。
- [ ] Step 3: 扩展verifier和入口文档；记录Linux仅支持ephemeral test client、macOS persistent Keychain、root lost reset步骤。
- [ ] Step 4: 先运行自动 candidate 门禁：
  ```bash
  cargo test
  swift test
  bash scripts/check-daemon-network-boundary.sh
  bash scripts/verify-relay-companion-mvp.sh p4-auto
  scripts/verify-agent-docs.sh
  ```
  Expected: 全部 exit 0，只证明 P4 automatic candidate。随后运行
  `AGENTDECK_P4_REAL_E2E=1 bash scripts/run-relay-companion-p4-real-e2e.sh`；脚本在 provisioned signed
  helper/CLI、公开 WSS 或 Codex/Claude Code login 缺失时必须明确 BLOCKED 且不生成 evidence；输入齐全时
  才运行 signed Keychain/CLI restart 与两个真实 vendor suites，并输出各自 conversation/command evidence
  reference；最后运行完整 trust-reset/uninstall-purge/readback/reinstall 子流程。未通过 real gate 时 P4
  exit 保持 BLOCKED。
- [ ] Step 5: `git status --short --branch`，清理临时Keychain accounts、DB、invite与logs。
- [ ] Step 6: 提交 automatic candidate 与 gated harness。精确展开本 task pathspec 后执行
  `git commit -m "test(remote): 建立 P4 自动与真实验收门禁"`；若 real gate BLOCKED，文档必须保留该状态，
  不得把本提交命名或描述为真实双 agent 已收口。

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
- [ ] Step 5: 运行 `cd ios && xcodegen generate && xcodebuild -project AgentDeckMobile.xcodeproj -scheme AgentDeckMobile -destination 'platform=iOS Simulator,name=iPhone 17' -only-testing:AgentDeckMobileTests/RelayClientStorageIntegrationTests test`，验证 API 配置、属性读回、backup exclusion 与 crash recovery contract，再运行AgentDeckRelayClient完整tests。Simulator 不能证明物理设备锁屏时的 ThisDeviceOnly/FileProtection 行为；该生产证据必须留给 P5.9 物理 iPhone gate。
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

**Registry rule:** local machine固定指向RuntimeEnvelope v2 UDS source；每台remote machine是独立`RelaySessionSource(.machine(id))`；UI只按machine scope取得`any SessionSource`；本机流量永不绕Relay。

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

- [ ] Step 1: 写UI/E2E tests与host harness。Simulator走temp TLS Relay+`cargo run -p agentdeck-cli --example synthetic_machine`完成PairRequest→requester waiting→被控机本地pending fingerprint读回/approve→pair/list/open/prompt/approval/reconnect/revoke；物理iPhone前台smoke经公开WSS用IOS专属invite完成同样的本地批准与控制流。signed runner 必须读回 Keychain `WhenUnlockedThisDeviceOnly` + non-sync 属性、文件 `NSFileProtectionComplete` + backup exclusion，再做两阶段锁屏/解锁：在 bounded background task 内观察 protected-data unavailable，锁屏访问只记录 typed inaccessible/OSStatus，解锁后读回原 item/file hash；第二控制Mac用另一份fresh invite独立配对并完成同流程，断言两个pairRoute/requestHash/grant不同，并验证远端自批被拒、Keychain/private-file absence与被控机本地App仍走UDS。锁屏阶段不把 secret 写进日志，Simulator 属性测试不能替代这条物理证据。
- [ ] Step 2: 运行 `bash scripts/run-relay-companion-simulator-e2e.sh`。 Expected: FAIL，host orchestrator/UI test target尚不存在。
- [ ] Step 3: 配置XcodeGen UI test target并实现三个orchestrator。 Simulator脚本负责启动/等待Relay和synthetic machine、生成invite、把路径与pin注入XCUITest、运行后读回结果并清理；iPhone脚本用指定UDID/Development Team运行signed test runner，并以 2 分钟 hard deadline 编排人工/host lock→unlock 两阶段及 protection attribute/hash readback；Mac脚本经SSH执行安装/preflight/测试并读回远端Keychain/file scan。 verifier拒绝相同invite/route/requestHash，并把旧fixture设计标为preview/test-only历史事实。
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
  Expected: 默认/Simulator全部exit 0；gated物理iPhone输出pair/list/open/prompt/approval/reconnect 与
  Keychain/file protection attributes、locked-access fail-closed、protected-data transition 与 unlock hash
  evidence IDs，第二Mac输出独立远控 evidence ID；缺gated输入时明确BLOCKED，
  不能冒充P5退出门禁通过。
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
- [ ] Step 4: 使用当前 harness 的独立 subagent review，至少覆盖security boundary、crash recovery、Swift签名/并发/UI receipt、pair/reset、packaging；逐条复现并修复P0/P1，重复所有自动门禁。不得声称调用当前不可用的 `superpowers:*` skill；任何行为、安全或packaging修改必须在下一task重新采集真实证据。
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

**Gated inputs:** `AGENTDECK_REAL_E2E=1`、真实公网WSS、两台物理上独立且可丢弃的被控 Mac A/B（各自独立用户/profile trust domain）、物理iPhone、remote CLI、Codex login、Claude Code login，以及可从空环境部署/读回的可丢弃 Linux systemd Relay host 或其全新隔离实例。Mac B 可以同时作为控制 A 的第二桌面客户端，但必须使用与 B 自身 daemon trust domain 分离的 client installation/key records；不因此要求第三台 Mac。脚本只允许从clean P6.2 candidate commit启动；记录source commit/tree digest/dirty=false并在结束时复算。root-lost演练只在可丢弃trust domain二次确认后执行。

- [ ] Step 1: 运行preflight。 检查物理 Mac A/B 及两个独立 trust domains、B→A 控制端 SSH/client installation、iPhone UDID/Development Team、CLI installation、public WSS CA/pin、双 vendor login、可丢弃 clean systemd host/instance 与candidate clean tree。 Expected: 任一缺失都BLOCKED且不创建evidence run。
- [ ] Step 2: 在 clean Linux host/instance 按 runbook 安装 systemd unit、证书与 config，读回 non-root sandbox、data/cert paths、health/readiness 和公网 WSS；冻结该实例 ID/证书 pin/空 DB hash。后续 Step 3–5 必须全部使用这一个刚部署的 Relay，不能换成另一个预存实例。
- [ ] Step 3: 让iPhone分别用两个独立PairInvite向两台被控机器发起配对；每台机器都由本地App/CLI读回并确认不同DeviceSign fingerprint，先证明远端自批被拒，再记录不同root fingerprint/route/Keychain account/grant；在其中一台丢弃首次response并证明byte-identical PairRequest retry取回同一grant。
- [ ] Step 4: 在 Step 2 同一 systemd Relay 上执行client×agent×action矩阵、安全、重启与两条独立reset run。物理iPhone必须亲自对Codex和Claude Code完成list/open/start/continue/prompt/approval/history/reconnect并读回完整canonical stream；远程Mac与CLI完成各自pair/control/reconnect；本地App加入同conversation四端竞态，并验证关闭本地App后turn/daemon继续。iPhone记录cellular`NWPath`，Relay只记录脱敏source-network hash。Relay/daemon/iOS network restart后不重配；sentinel在Relay DB/log/metrics/binary outer frame为0业务明文，vendor resume reference在client解密payload仍0 match；伪造/rollback/nonce/pin攻击fail-closed；revoke在2秒内terminal/close。Run A有root：RetireMachine→purge/readback absent→重新enroll/pair。Run B在新的有效route上删除root：remote blocked→admin purge/readback absent→再重新enroll/pair。
- [ ] Step 5: 生成manifest、脱敏命令/log摘录和脱敏截图；逐个打开artifact并复算hash，确认source commit/tree仍匹配且raw artifact存在。 任何测试暴露行为、安全或packaging缺陷时，废弃本run、回P6.2修复提交并从Step 1重跑，禁止沿用旧summary。
- [ ] Step 6: 只提交evidence。 核对`git diff --name-only $SOURCE_COMMIT..HEAD`在run前为空，run后stage仅`docs/evidence/relay-companion-mvp`，再`git commit -m "test(companion): 留存真实跨网与双 agent 验收证据"`。

### Task P6.4：验证当前candidate绑定的13项DoD并更新状态

**Files:**
- Modify: `docs/plans/2026-07-10-relay-companion-mvp-design.md`
- Modify: `docs/plans/2026-07-10-relay-companion-mvp-implementation.md`
- Modify: `README.md`, `NORTH_STAR.md`, `ARCHITECTURE.md`, `docs/QUALITY.md`, `docs/AGENT_DIAGNOSTICS.md`, `docs/index.md`, `AGENTS.md`, `docs/RELAY_RUNBOOK.md`

- [ ] Step 1: 运行P6.2已提交的DoD verifier读回P6.3 manifest与已提交脱敏artifacts；确认它复算hash、校验source commit祖先与candidate→HEAD差异allowlist，并用`--require-local-raw`读回gitignored raw artifacts。此task不得扩展或修改verifier；若能力缺失或校验失败，必须回P6.2修复、提交新candidate并重跑P6.3。
- [ ] Step 2: 在尚未改状态文档前运行最终命令：
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
- [ ] Step 3: 只有 Step 1/2 全部通过后，才更新设计状态为 Implemented、本计划全部完成 task checkbox 和最终 candidate/evidence IDs；只写已经由 P6.3 证明且被当前 verifier 读回的事实。更新后重新运行 docs、DoD verifier 与 diff gate；任一失败不得保留完成措辞。
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

1. **Subagent-Driven（推荐）**：使用当前 harness 可用的独立实现/审查 subagent；主agent在task间做spec/quality双重review并运行阶段门禁。适合本计划的多crate、多平台和安全边界。
2. **Inline Execution**：在单一执行会话严格按task顺序推进并在每个Phase退出门禁停下复核。适合不希望并行改同一工作区时使用。

无论选择哪种方式，P2.9原子cutover、P3.7 exec-gate、P4.5 counter recovery和P6.3真实设备证据禁止并行修改；这些task必须串行并在进入下一task前完成独立review。
