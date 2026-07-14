# AgentDeck 文档索引

本目录是 AgentDeck 的仓库内记录系统。`AGENTS.md` 只做入口导航；稳定知识必须落到这里或仓库根部的专门文档中。

## 顶层文档

- `../NORTH_STAR.md`：产品北极星、v0.1 双拍和不做什么。
- `../README.md`：项目介绍、当前功能、构建运行和测试入口。
- `../ARCHITECTURE.md`：稳定架构、分层边界、依赖方向和不变量。
- `../AGENTS.md`：代理工作入口和仓库导航。

## 运行与诊断

- `AGENT_DIAGNOSTICS.md`：自检命令、诊断日志位置、Relay v2 failure code、v1 marker
  显式 reset 和排查流程。
- `QUALITY.md`：按变更范围选择验证命令，以及 Companion MVP P2、P3.1–P3.6 与文档结构检查入口。
- `RELAY_RUNBOOK.md`：production Relay v2 Direct TLS、本机 admin UDS、machine
  enrollment、fingerprint-bound readback/purge 与 root-lost 重新配对操作手册。

## 计划与历史

- `plans/README.md`：设计文档和实施计划的命名、内容和归档规则。
- `plans/*-design.md`：功能设计、架构取舍和验收标准。
- `plans/*-implementation.md`：可执行实施步骤、验证命令和收口记录。

### iOS 前端计划（2026-07-03）

- `plans/2026-07-03-ios-uikit-frontend-design.md`：iOS UIKit companion 前端设计（fixture 驱动，R3 界面骨架，状态：Implemented）。
- `plans/2026-07-03-ios-uikit-frontend-implementation.md`：iOS UIKit companion 前端实施计划（Task 1–15，含 AgentDeckCore 共享库抽取）。

### Relay R0 契约 spike（2026-07-07，历史）

- `plans/2026-07-07-relay-r0-contract-spike-design.md`：Relay R0 契约 spike 设计（控制面/数据面分层、fleet 协议、内存 FakeRelay + 真实 daemon 组合、CLI remote 接口基线）。
- `plans/2026-07-07-relay-r0-contract-spike-implementation.md`：Relay R0 契约 spike 实施计划（Task 1–9，含 T1–T4 测试矩阵与文档收口）。

### Relay R1a 传输 + 鉴权骨架（2026-07-08，历史）

- `plans/2026-07-08-relay-r1-design-review.md`：Relay R1 设计评审（就绪度评估、决策拍板、R1a/R1b/R1c 切分）。
- `plans/2026-07-08-relay-r1a-transport-auth-design.md`：Relay R1a 传输+鉴权骨架设计。
- `plans/2026-07-08-relay-r1a-transport-auth-implementation.md`：Relay R1a 12 任务 TDD 实施计划（已全部落地）。

### Relay R1b 存储 + Router 健壮化（2026-07-09，历史）

- `plans/2026-07-09-relay-r1b-storage-hardening-design.md`
- `plans/2026-07-09-relay-r1b-storage-hardening-implementation.md`

### Relay Companion MVP（2026-07-10）

- `plans/2026-07-10-relay-companion-mvp-design.md`：已批准的目标架构；固定 singleton daemon、多读者/多写者串行裁决、按机器独立配对、Relay 严格最小可见与真实 iOS Companion 边界。
- `plans/2026-07-10-relay-companion-mvp-implementation.md`：P0–P6 的逐文件 TDD 执行清单。P2.10 与 P3.5 已完成；P3.6-A Runtime/transfer contract、P3.6-B Runtime store v4、P3.6-C StoreCommitHub/barrier/backfill/snapshot/bounded transfer/fake sealed publication 组件分别提交为 `7731d1e` / `02cc640` / `694f2d9`，默认并发完整 daemon gate 已 exit 0，当前只待 P3.6-D 独立 docs commit。P3.1 的真实 provisioned signed Keychain roundtrip 仍因本机缺 provisioning profile / AMFI exit 137 而保留 1 项 ignored/gated BLOCKED；production execution、singleton UDS、transfer/publication production remote owner、真实 E2EE/Relay Publish 与远程 Companion 均未完成，docs commit 后的下一项是 P3.7 exec gate。

## 协议资料

- `../protocol/SPIKE_FINDINGS.md`：Codex app-server wire framing、方法和 schema 事实源。
- `../protocol/CODEX_VERSION.txt`：生成当前 schema 时使用的 Codex 版本。
- `../protocol/*.json`：官方 schema 快照。
- `../protocol/agentdeck/`：AgentDeck 自身中立协议 schema 与说明。`agentdeck-protocol.schema.json` 由 schemars 从 Rust 类型派生生成（非手写），`README.md` 说明生成与更新流程。

## 更新规则

- 代码行为变化时，同步更新对应产品、架构、诊断或计划文档。
- 文档不要重复大段实现细节；稳定事实放专门文档，临时决策放计划文档。
- 如果某条规则需要长期执行，优先补测试、脚本或 CI 检查，而不是只写自然语言。
- 每次阶段性收口前运行 `scripts/verify-agent-docs.sh`，确认文档入口没有漂移。
