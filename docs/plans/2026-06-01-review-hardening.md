# Review Hardening Notes

## 背景

2026-06-01 的 review 指出 5 个问题：`turnComplete` 与 worker done
之间的竞态、Codex app-server stderr 丢失、Swift/Rust 字段名契约覆盖不足、
adapter 生命周期措辞不清、以及 run record 脱敏启发式可能误伤长标识符。

## 本轮处理

- 修复 `turnComplete` 竞态：turn 成功路径在发出 ready / `turnComplete`
  之前先向 RuntimeHub 发送 `RuntimeHubWorkerDone::Turn`，并用一次性标记避免
  worker 退出时重复发送。这样 Swift 收到 `turnComplete` 后再 drain 下一条
  prompt 时，daemon 在处理该 stdin line 前一定能清理 `running_sessions`。
- 捕获 Codex app-server stderr：adapter spawn 时把 stderr 改为 piped，由后台
  reader 保存有限尾部摘要；stdout EOF 断连时把摘要附加到 `CodexError`，后续
  通过现有错误路径进入 diagnostic log 和 UI error。
- 更新 README、ARCHITECTURE 和诊断文档，使 turn 级 adapter 生命周期和 stderr
  可观测性与实现一致。

## 已知后续项

- 跨语言字段名契约需要更完整的 fixture 驱动测试：Rust 序列化每种
  `AgentItemKind` 的全字段，Swift `AgentItemReducer` 读取同一 fixture 并断言字段
  不静默丢失。优先覆盖 `durationMs`、`exitCode`、`savedPath`、`resourceUri`、
  `reasoningEffort`、`senderThreadId` 等曾经依赖 serde rename 的字段。
- run record 脱敏仍是 best-effort 非安全边界。若后续发现长 base64 片段或正常长
  ID 被过度打码，再收紧 `record.rs` 中混合大小写+数字的长度规则；安全性优先于
  可读性。

## 验证

本轮应至少运行：

```bash
cargo test
scripts/verify-agent-docs.sh
```

涉及 daemon、adapter、诊断和文档入口；若后续碰 Swift reducer fixture，则加跑
`swift test`。
