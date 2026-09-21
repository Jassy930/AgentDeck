# 后端 M0 与持久 CLI 实施记录

日期：2026-09-21
基线：`32f10e6`，以下为 2026-09-21 本次变更的本地验证回执；远端 CI 结果另列。

## Goal

补齐 Codex 最小后端闭环，通过实际 CLI 驱动累计消息、多轮、取消恢复和关闭回收。
真实 vendor 验收与默认离线门禁分别记录，不据此扩展 desktop 或 Claude Code 的能力声明。

## Architecture

- protocol v4 的 AgentItem 必须带 caller-owned turnId、稳定 itemId 和 streaming/completed；
  Codex adapter 发送累计文本，owner 校验 thread/turn 关联并在终态清理缓存。
- `agentdeck session live` 双向传递现有 typed JSONL，持有同一 daemon；EOF、输入错误
  或输出断开均执行有界 shutdown。run/continue 保留原 one-shot 行为。
- router 在 spawn 前打开 session record；单 writer 记录事件并关闭 footer。stdout 失联后
  停止 intake，继续保存清理终态。记录写失败是可定位的非终态告警。
- lifecycle diagnostics 记录版本、child PID、RPC、turn 与 cleanup；diagnosticRef 对应
  实际 runId/eventSeq。JSONL 先组成完整 buffer 再写入，避免线程间拼接 JSON 行。
- Swift mirror、累计消息 reducer 和 iOS fixture 消费方同步 v4。

## Tech Stack

沿用 Rust/Tokio、现有 serde/schemars 协议及 Swift/UIKit 模型，不增加依赖。

## 本地验证

| 验证 | 结果与证据边界 |
| --- | --- |
| `scripts/verify-offline-tests.sh` | 通过；unset/0 跑完整 workspace，空值/false/其他值跑 gated integration，marker 未被调用。普通 E2E passed 包含提前 skip。 |
| 实际 CLI `session_live` integration | 6 项通过：四轮/累计消息/Ping/取消恢复/同 PID 回收、EOF、坏输入、record open 失败、append/close 失败、输出管道断开。使用 fake Codex。 |
| Codex/session focused | session 26 项通过；Codex lib 合计 82 项通过。覆盖 streaming 关联、跨轮 reset、failure 引用与 cleanup。 |
| RuntimeHub focused | 17 项通过，包含 stdout 失联后唯一 SessionClosed/footer 读回。 |
| 协议与 translator | protocol 36、Codex translator 10、CC translator 19 项通过，schema 已同步。 |
| 当前 checkout daemon/CLI | build、CLI selfcheck（protocolVersion=4）、schema diff、diagnostics report 读回通过。 |
| `swift test` | 通过。 |
| iOS | XcodeGen 与 generic Simulator build-for-testing 通过；iPhone 17 test 执行 0 项、exit 70。运行时注册指向缺失的挂载目录，设备不可用，尚无本轮 UIKit 单测通过证据。 |

离线门禁日志：`/tmp/agentdeck-m0-offline-gate.log`。
CLI 自检与诊断回执：`/tmp/agentdeck-m0-validation.lrhu6O/`。
iOS 日志：`/tmp/agentdeck-m0-ios-build.log`、`/tmp/agentdeck-m0-ios-retry-tests.log`。

## 真实验收与剩余边界

用户已授权并执行真实 Codex 调用。固定版本为 0.145.0，使用当前 checkout 的 daemon
及原生登录环境；四轮 M0 用例通过（58.39 秒）。

本机默认配置含 `[features.context_management]` table，固定版本要求 bool，导致
initialize 成功而 thread/start 拒绝。首次失败未发送 prompt，诊断引用为
`cli-live-m0:7`，child wait、进程组消失和 stderr pump join 均已确认。
无 prompt 的官方 app-server 探测确认 `-c features.context_management=false` 可解除该
类型冲突；随后用临时 PATH launcher 执行真实 binary，全局配置及认证文件均未修改。
launcher 内容为：

```sh
#!/bin/sh
exec /opt/homebrew/Caskroom/codex/0.145.0/codex-aarch64-apple-darwin \
  -c features.context_management=false "$@"
```

真实四轮运行命令为：

```bash
PATH="/tmp/agentdeck-m0-real-launcher-efmchgel:$PATH" \
AGENTDECK_DAEMON_BIN="$PWD/target/debug/agentdeckd" AGENTDECK_E2E=1 \
  cargo test --locked -p agentdeck-cli --test e2e_codex \
  e2e_codex_live_four_turn_lifecycle -- --nocapture
```

| 真实四轮检查 | 结果 |
| --- | --- |
| 轮次终态 | succeeded / succeeded / canceled / succeeded，均回 Ready |
| 累计 streaming | 各轮 29 / 30 / 2 / 28 份，item identity 与累计文本断言通过 |
| 进程与 thread 复用 | 同一 PID `9186`、threadId `01a0c1d3-2841-75e1-93f7-fb678dd68b4a` |
| close | 唯一 SessionClosed(closed)，child wait 与进程组消失断言通过 |
| RunRecord | 单一记录覆盖四轮，IPC 事件同序，header/footer 完整 |
| diagnostics report | 32 / 32 行成功解析，无 error 级事件 |

真实四轮日志、临时 launcher 与诊断回执：`/tmp/agentdeck-m0-real-launcher-efmchgel/`。
record/diagnostic 原始证据：
`/var/folders/zy/fn4lmxbx1cd5flcp81mk2xx80000gn/T/agentdeck-codex-live-e2e-9179-1789958234236367000/`。
首次默认配置失败日志：`/tmp/agentdeck-m0-real-codex.log`。

其余 Codex E2E 已单独执行，避免重复四轮模型调用：agent list、capabilities、Ping、
selfcheck、one-shot run 和 continue 通过；history list 首轮超过 30 秒总 deadline。
官方 thread/list 独立探测复刻默认 500 条请求，实际分五页各 100 条，耗时依次为
3.70 / 6.10 / 6.17 / 5.23 / 4.35 秒，总计 25.64 秒，接近 28 秒工作截止时间。
未延长 deadline、缩小默认条数或改为 DB-only；分页探测回执为 `history-probe.jsonl`。
同条件 focused 复验返回 500 条并通过（27.57 秒），回执为 `history-recheck.log`。
因此 8 项用例均取得单项通过证据，但首轮套件不是全绿，历史查询仍有接近 deadline
的稳定性风险；不能把复验通过描述成该风险已修复。

当前只证明上述临时配置环境下的 M0，默认本机配置仍不兼容。真实 failed 模型 turn、
history read/管理、Claude Code partial streaming/审批、远程能力和 GPUI desktop 接入
仍是独立后续工作；iOS 设备测试缺口见上表。
