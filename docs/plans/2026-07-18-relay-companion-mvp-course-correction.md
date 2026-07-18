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
Runtime store 的防御承诺是「**离线篡改 fail-close**：缺 KEK 且无法通过当前
KEK/database/domain 认证的磁盘级篡改、删除或跨库移植，在 open/recovery 的全库
认证审计中被拒绝，且拒绝路径不改写 artifact」。整套 main+WAL 回滚到更早但
内部自洽的有效快照仍须 P4 CounterGuard 检测。**同 UID 在线竞态攻击者明确不在
防御范围**：该攻击者可 ptrace
daemon、替换二进制或直接读取使用中的内存密钥，SQLite 层的任何竞态防御都不
构成真实安全边界。此为已接受的 residual risk，记录一次即可。

**落地动作：**
- 已绿的 B3 切片（`open_inner<F>` hook + identity 复核 +
  `current_open_rejects_post_inspection_wal_tamper_without_rewriting_artifacts`）
  已由 `974f9b1` 提交，作为该方向**最后一笔**。
- 此后任何切片不得再为同 UID 竞态场景新增测试、hook 或取证机制；
  review 中此类 finding 一律标记 out-of-scope 关闭。
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
- 若 post-MVP 需要解锁该槽位，再在 Apple Developer 为 daemon helper 配置含
  `keychain-access-groups` entitlement 的 provisioning profile 并提供 Team ID；在此之前不再花执行时间
  尝试绕过 AMFI。

## 决策 4：P4–P6 范围收敛（MVP 验收面收窄）

- **P4 全保留**：machine identity、pairing、RemoteLink、远程 CLI 与 Codex/CC
  canonical adapter 穿透能力全部实现；MVP 以合成链路验证，真实 vendor login
  evidence 按 P6 规则进入 post-MVP 槽位。这是 MVP 的核心价值，不删功能或 harness。
- **P5 收敛**：MVP 验收 = iOS Simulator 自动 E2E + 本机第二客户端；
  物理 iPhone 与第二台 Mac 的 gated E2E 移为 post-MVP 项，保留脚本与
  BLOCKED 语义，不作为 MVP 完成条件。
- **P6 收敛**：DoD 十三项中，合成链路可自动化项保留为 MVP 门禁；
  真实双 vendor login + 物理设备矩阵 + 公网 systemd host 移为 post-MVP
  证据槽位（verifier 保留槽位输出 BLOCKED，不生成伪 summary）。

## 执行顺序（建议一周内）

1. **已完成**：B3 最后一笔由 `974f9b1` 提交；本决策已同步到原计划 Global Constraints/B3a
   刹车线与 ARCHITECTURE/QUALITY，B3a2-B 收口。
2. **1 天**：B3a2-C（quota 纯函数）+ B3a3（Core/actor 传递 expected
   revision、两个稳定 failure code、docs 同步），B3a Task 级终审一次。
3. **2–3 天**：B3b exact execution → B4 metadata → B5 cross-layer
   closeout，按新刹车线执行。
4. **2–3 天**：C0-C native history projection、P3.9-A/B/C3/D/E
   App/CLI cutover。
5. **P4 开始前**：按决策 4 重估 P4–P6 剩余步骤，更新计划勾选清单。

## 不变项

- 信任边界不降级：Relay 零业务字段、E2EE 套件、persist-before-deliver、
  approval CAS first-wins、fail-closed TLS 等全部维持原计划约束。
- 本决策只裁剪「防不住的对手」与「流程开销」，不裁剪任何用户可感知的
  MVP 功能或跨端验收的合成链路证据。
