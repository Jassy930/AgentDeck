# Companion MVP 纠偏决策（2026-07-18）

> 本文档是 `2026-07-10-relay-companion-mvp-implementation.md` 的上位纠偏决策。
> 与原计划冲突之处，以本文档为准；执行前先把「决策 2」的规则修订同步回原计划的
> Global Constraints 与 B3a 切片刹车线段落，避免按旧规则继续递归拆片。

## 背景诊断（简）

截至 2026-07-17 的诊断点，分支 `codex/relay-companion-mvp` 领先 master 119 commits，
P0–P2、P3.1 production candidate 与 P3.2–P3.8 已完成；P3.1 signed gate 保留 1 项
ignored/BLOCKED，已完成阶段的自动门禁保持全绿。
但执行卡在 P3.9-C0-B 的第 5 层子片（B3a → B3a2 → B3a2-B → B3）约两天：
7/17 的 28 个 commit 中有 13 个 docs commit；前半仍包含 v5/configuration/pin 功能推进，后半逐步陷入
「同 UID SQLite WAL 篡改」取证与微片收口。根因有三：威胁模型发散（防御一个计划自认"不可消灭"的 TOCTOU
窗口）、流程刹车线导致分形拆片（每微片双路终审 + 255s 全量慢门禁）、以及
P3.1 外部签名门禁被误当作可代码解决的阻塞。

## 决策 1：威胁模型收口——停止同 UID 在线竞态加固

**边界定义（写入 ARCHITECTURE.md 的 Runtime store 不变量）：**
Runtime store 的 P3 防御承诺是「**离线篡改 fail-close**：已有 committed artifact 中，缺 KEK 或
无法通过当前 KEK/database/domain 认证的行/页改删及跨库移植，在 open/recovery 的全库认证审计中
被拒绝，且拒绝路径不改写 artifact」。整套 DB/main/WAL/SHM 消失，或整套 main+WAL 回滚到更早但
内部自洽的有效快照，均不属于 P3 承诺，须由 P4 CounterGuard 检测。**同 UID 在线竞态攻击者明确不在
防御范围**：该攻击者可 ptrace
daemon、替换二进制或直接读取使用中的内存密钥，SQLite 层的任何竞态防御都不
构成真实安全边界。此为已接受的 residual risk，记录一次即可。

**落地动作：**
- 已绿的 B3 切片（`open_inner<F>` hook + identity 复核 +
  `current_open_rejects_post_inspection_wal_tamper_without_rewriting_artifacts`）
  已由 `974f9b1` 提交，作为该方向**最后一笔**。
- 此后任何切片不得再为同 UID 竞态场景新增测试、hook 或取证机制；
  review 中此类 finding 一律标记 out-of-scope 关闭。
- **P3 Phase Exit 采用方案 A（2026-07-20）**：不下调既有离线 fail-close 承诺。`0057824`
  已把 legacy v1-v6 ledger/既有行认证统一前移到原库 RW open/migration 之前，显式 committed-WAL
  篡改矩阵覆盖 v1-v4，migration focused suite `40/40`。这属于离线认证补洞，不撤销
  `974f9b1` 之后停止同 UID 在线竞态加固的裁决。
- 安装 verifier 只承诺同 PGID 资源与清理边界：`773a2b3` 固定绝对 deadline、聚合输出与双向 pipe
  上界，`81cc314` / `9efb28d` 保证 leader 直接 reap，并在返回前把同 PGID descendants 收口到
  non-executable/zombie。主动 `setsid`/`setpgid` 或 launch service 逃离 PGID 不在该边界内；这不是
  针对恶意同 UID 代码的 sandbox 承诺。
- B3a2-C 按原计划的"纯函数锁 MAX-1/MAX + 真实 DiskLow/StoreFull 零漂移"
  最小化执行，不造百万行证明机（原计划本有此禁令，照办即可）。

## 决策 2：流程刹车线调整——恢复 Task 粒度

原计划的微片流程（每片独立双路终审 + 全量慢门禁 + 单独 docs 收口 commit）
是速度坍缩的直接原因（诊断时 119 commits 中 44 个为 `docs:*`，约 37%）。修订为：

1. **拆片线只计 production 代码 additions**；测试与文档行数不计入
   1,800/2,000 行刹车线。
2. **双路独立终审（spec/security 与 quality）只在 Task 收口和 Phase exit 执行**：Task 指
   B3a、B3b、B4、B5、C0-C、P3.9-A/B/C3/D/E 这一层级；每个 Task 收口一次，Phase exit 再做一次
   phase 级终审；子片只做执行者自查 + focused tests。
3. **全量 package 门禁（含 1,024×256 KiB 约 255s 慢测试）只在 Task 收口
   与 Phase exit 运行**；子片只跑 focused tests + clippy + fmt。
4. **取消子片级 docs 收口 commit**；执行记录在 Task 收口时一次性写入
   计划文档，一个 docs commit。
5. 原有安全底线不变：RED→GREEN、精确 pathspec、无 co-author、不 push、
   neutrality/sentinel 门禁照旧。

## 决策 3：P3.1 采用方案 b，signed Keychain 移入 post-MVP

该项是外部签名环境问题（缺匹配 keychain-access-groups 的 provisioning
profile，self-signed helper 被 AMFI exit 137 终止），**代码不可解**。

- 已拍板采用方案 b：MVP 阶段接受 dev/ephemeral Keychain 路径；这只证明开发与合成链路，
  不宣称 stable production signing 已完成。
- provisioned signed Keychain set/load/delete roundtrip 移入 post-MVP，继续以
  ignored/BLOCKED 证据槽位保留，但不再阻塞 P3/P4 phase exit 或 MVP 完成。
- 同一分层适用于 P3.10：自动 MVP 门禁使用 dev/ephemeral 隔离 harness 与注入的 launchctl/signature
  verifier；production constructor 和签名校验不降级，但 provisioned production-signed LaunchAgent
  roundtrip 保留为 post-MVP BLOCKED，不用 ad-hoc/injected 证据冒充 production PASS。
- 若 post-MVP 需要解锁该槽位，再在 Apple Developer 为 daemon helper 配置含
  `keychain-access-groups` entitlement 的 provisioning profile 并提供 Team ID；在此之前不再花执行时间
  尝试绕过 AMFI。

## 决策 4：P4–P6 范围收敛（MVP 验收面收窄）

- **P4 全保留**：machine identity、pairing、RemoteLink、远程 CLI 与 Codex/CC
  canonical adapter 穿透能力全部实现；MVP 以合成链路验证，真实 vendor login
  evidence 按 P6 规则进入 post-MVP 槽位。这是 MVP 的核心价值，不删功能或 harness。
- **P5 收敛**：MVP 验收只包含 iOS Simulator 自动 E2E；本机第二客户端迁入 P6 synthetic DoD。
  物理 iPhone 与第二台 Mac 的 gated E2E 移为 post-MVP 项，保留脚本与
  BLOCKED 语义，不作为 MVP 完成条件。
- **P6 收敛**：本机第二客户端与 DoD 十三项中的合成链路可自动化项保留为 MVP 门禁；
  真实双 vendor login + 物理设备矩阵 + 公网 systemd host 移为 post-MVP
  证据槽位（verifier 保留槽位输出 BLOCKED，不生成伪 summary）。

## 执行顺序（建议一周内）

1. **已完成**：B3 最后一笔由 `974f9b1` 提交；本决策已同步到原计划 Global Constraints/B3a
   刹车线与 ARCHITECTURE/QUALITY，B3a2-B 收口。
2. **已完成**：B3a2-C（quota 纯函数）+ B3a3（Core/actor 传递 expected
   revision、两个稳定 failure code、docs 同步），B3a Task 级终审一次。
3. **已完成**：B3b exact execution → B4 metadata → B5 cross-layer
   closeout，按新刹车线执行。
4. **已完成（2026-07-19）**：C0-C native history projection、P3.9-A/B/C3/D/E
   App/CLI cutover与会话可靠性收口。
5. **已完成（2026-07-20）**：按决策 4 的范围重估与 P4–P6 Task checklist 执行前审计已逐项同步；
   当时 P4/P5/P6 的执行前基线固定为 0/7、0/9、0/4；P5 MVP 只保留 Simulator 自动 E2E，本机第二
   客户端迁入 P6 synthetic DoD，物理设备/公网/vendor/Linux 保持 versioned post-MVP BLOCKED 槽位。
6. **P3 automatic scope complete（2026-07-20，6/6）**：P3.10 主体由 `19622ab` 提交；Phase review
   hardening 又由 `773a2b3` / `0057824` / `81cc314` / `9efb28d` 收口。以 `9efb28d` 为 code baseline
   的 `bash scripts/verify-relay-companion-mvp.sh p3` exit 0：daemon lib 两轮均为 `905 passed / 3 ignored`
   （218.23s / 154.45s），1,024 × 256 KiB capacity 两轮均 `5/5`（284.97s / 286.07s），Swift
   `527 XCTest + 35 Swift Testing`、iOS Simulator `20/20`；signed exact BLOCKED contract、四 schema、
   network、docs、local smoke 与 diagnostics 全绿。两路 phase code review 均为 P0/P1/P2=0。
   provisioned production-signed LaunchAgent/Keychain roundtrip 仍按方案 b 保持 post-MVP BLOCKED，
   不是 PASS。
7. **P4.1 已完成；下一项 P4.2（当前 P4 1/7）**：`3cd76d2`、`644712c`、`95090c1`、`85df3d2`、
   `f137112`、`46c6bb8` 已建立四组 machine key、authenticated schema v8/24 表、key-directory guard、
   通用 CounterGuard IO 与 `Preparing → Active` bootstrap。focused bootstrap `18/18`、identity keys
   `11/11`、store identity `11/11`、RootKeyId `2/2`、v7→v8 migration `1/1` 通过；完整 daemon package
   exit 0（lib `916 passed / 3 ignored`，capacity 慢项 284.28s），两路独立终审均 Approved。P4.1
   严格零 cert、零 enrollment workflow、零 receipt IO、零 RemoteLink；通用 CounterGuard IO 不代表
   active symmetric key reservation、DB high-water 绑定或整库回滚闭环已完成。link/data cert、enrollment
   receipt、RemoteTransport 与两条 trust-reset 路径从 P4.2 开始；P3.1 signed gate 继续按方案 b 保持
   post-MVP BLOCKED。

## 不变项

- 信任边界不降级：Relay 零业务字段、E2EE 套件、persist-before-deliver、
  approval CAS first-wins、fail-closed TLS 等全部维持原计划约束。
- 本决策只裁剪「防不住的对手」与「流程开销」，不裁剪任何用户可感知的
  MVP 功能或跨端验收的合成链路证据。
