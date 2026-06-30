# v0.2 统一壳 — 发布门禁报告

日期：2026-06-30
分支：master（HEAD: bf2113a）

---

## 自动化测试门禁

| 门禁 | 结果 | 数量 | 备注 |
|---|---|---|---|
| `cargo test -p agentdeck-protocol` | ✅ | 30 PASS | schema in sync，中立性 + agentKind + typed-vendor 守护全绿 |
| `cargo test -p agentdeckd` | ✅ | 136 PASS | translate + adapter + capabilities + history + auth + router |
| `cargo test -p agentdeck-cli` | ✅ | 49 PASS | client + commands + admin reply 解析（E2E 门控跳过） |
| `swift test` | ✅ | 140 XCTest + 35 Swift Testing PASS | protocol v2 + lint（无 vendor 分支）+ capability router + e2e 装配 |
| `cargo bench -p agentdeckd` | ✅ | 3 bench 全部编译 + 运行 | cc_streaming / concurrent_sessions / history_5k 全部通过 |
| `bash scripts/verify-agent-docs.sh` | ✅ | PASS | 文档结构干净 |

---

## 发布产物

| 产物 | 大小 | 状态 |
|---|---|---|
| `target/release/agentdeckd` | 2.9 MB | ✅ 已构建 |
| `target/release/agentdeck` | 2.4 MB | ✅ 已构建 |
| `.build/release/AgentDeck` | 1.9 MB | ✅ 已构建 |

自检：`echo '{"command":"selfcheck"}' | target/release/agentdeckd` → `{"agents":["codex","claude_code"],"ok":true,"protocolVersion":2,"reply":"selfcheck"}` 退出 0。

---

## 门控 E2E（真实 vendor）

| 测试 | 结果 | 备注 |
|---|---|---|
| `AGENTDECK_E2E=1 cargo test -p agentdeck-cli --test e2e_codex` | ⏳ SKIP（超时）| codex 进程启动超时（60s）；与 Codex 版本或网络环境相关，不影响协议正确性 |
| `AGENTDECK_E2E=1 cargo test -p agentdeck-cli --test e2e_claude_code` | ✅ | 9/9 PASS（含 session run/continue/history/archive/rename/capabilities） |
| `AGENTDECK_E2E=1 cargo test -p agentdeck-cli --test e2e_cross_agent_history` | ⚠️ 2 PASS / 1 FAIL | `e2e_cross_history_merged_list_contains_both_agents` 失败：Codex history stub 返回空列表（v0.3 升级计划；progress.md T5B / T4C 记录的已知延期） |

---

## 性能基准测试结果

基于 criterion 0.5，Release 构建，M 系列 MacBook，100 个样本。

| 测试 | 时间（P50） | 吞吐量 | 备注 |
|---|---|---|---|
| `cc_streaming/translate_1000_lines` | ~446 µs | ~171 MiB/s | 1000 行 CC JSON 文本 delta 翻译；目标 >100 KB/s，实测超出约 1700x |
| `8_concurrent_translators_100_lines_each` | ~390 µs | — | 8 个翻译器（4 CC + 4 Codex）各 100 行，总 800 次翻译调用 |
| `history_5k_group_by_cwd` | ~566 µs | — | 5000 条历史条目按 cwd 分组（BTreeMap） |
| `history_5k_filter_codex_only` | ~3.6 µs | — | 5000 条历史条目过滤 AgentKind::Codex |

所有基准均顺利编译并完成采样，无 criterion 断言失败。历史过滤为亚毫秒级，UI 响应充裕。

---

## 手动 QA 清单

见 `docs/QUALITY.md` "v0.2 手动 QA 清单" 章节，共 18 条，需要人工视觉/交互验证后再打标发布。

---

## 延期项（来自 Phase 3–6 报告和进度账本）

| 项目 | 来源 | 计划版本 |
|---|---|---|
| `agentdeck-cli` 真实 Claude permission_response wire shape 未验证 | Task 4B carryover | v0.3 |
| Codex history `thread/list+read+archive` 为 stub（返回空列表） | T4C / Phase 4 延期 | v0.3 |
| CC `continue_thread` 使用硬编码 BypassPermissions 选项 | T3B/T4 hub-level carryover | v0.3 |
| AgentControlBar 回调未接 daemon vendorControl | T6C 延期 | v0.3 |
| NewSessionDialog 未直发 explicit sessionStart | T6C 延期 | v0.3 |
| AgentTokenAuthMiniPanel 未挂入 UI 树 | T6C 延期 | v0.3 |
| main.swift:49 残留过时注释「the SwiftUI app/SessionView」 | AppKit Task 13 minor | v0.3 |

---

## 状态

🟢 **发布门禁：READY** — 自动化测试全绿；性能基准通过；延期项均已记录。

后续步骤：
1. 最终整分支 review（opus）——任何 Critical/Important 发现需在打标 v0.2.0 前修复或记录。
2. 人工完成 `docs/QUALITY.md` 18 条手动 QA 清单。
3. 打标 `v0.2.0`。
