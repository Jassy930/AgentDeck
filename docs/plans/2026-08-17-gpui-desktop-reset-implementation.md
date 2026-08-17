# GPUI 桌面端重启实施计划

日期：2026-08-17

## Goal

把 macOS 桌面入口重置为一个可构建、可启动、可自检的 GPUI 最小应用，同时删掉
旧 AppKit target，不接入远程能力或 daemon。

## Architecture

- `agentdeck-desktop/`：唯一 macOS GUI crate。
- `script/build_and_run.sh`：唯一 build/run 和 `.app` 装配入口。
- `Package.swift`：只保留 iOS 使用的 `AgentDeckCore` 与 Core 测试。
- 后端 crates 保持独立，本切片不改协议类型或 runtime 行为。GPUI 间接启用
  `serde_json/preserve_order` 后，`protocol_schema()` 会递归排序 JSON object key，保证
  聚合 schema 文本仍可复现；这是构建确定性修复，不改变 wire schema。

## Tech Stack

- Rust 2024
- GPUI 0.2.2，`runtime_shaders`
- gpui-component 0.5.1
- macOS 15+

## Tasks

- [x] 删除 `Sources/AgentDeck/` 和 `Tests/AgentDeckTests/`。
- [x] 从旧测试中迁出仍只依赖 `AgentDeckCore` 的测试。
- [x] 新增 `agentdeck-desktop` workspace member、窗口、组件和 selfcheck。
- [x] 把 `script/build_and_run.sh` 改为 Cargo build 与 Rust `.app` 装配；无效 mode
  在停止进程、构建或改写 bundle 前返回 exit 2。
- [x] 更新 North Star、README、架构、质量、诊断和 agent 入口文档。
- [x] 执行门禁并完成真实窗口点击冒烟。

## 验证结果

2026-08-17 在 macOS 15 arm64 本机完成：

```bash
cargo check -p agentdeck-desktop
cargo test -p agentdeck-desktop
cargo run -p agentdeck-desktop -- --selfcheck
cargo test
cargo run -q -p agentdeck-cli -- protocol schema \
  | diff - protocol/agentdeck/agentdeck-protocol.schema.json
swift test
cd ios && xcodegen generate && \
  xcodebuild -project AgentDeckMobile.xcodeproj -scheme AgentDeckMobile \
    -destination 'platform=iOS Simulator,name=iPhone 17' test
(cd designs/agentdeck-design-system && bun run check)
bash -n script/build_and_run.sh
./script/build_and_run.sh --verify
scripts/verify-agent-docs.sh
git diff --check
```

- 以上命令全部通过；iOS Simulator 为 20/20。
- selfcheck 输出
  `{"status":"ok","surface":"desktop","ui":"gpui"}`。
- bundle readback 确认进程来自当前 `dist/AgentDeck.app`，Info.plist 与 Mach-O 的
 最低系统版本均为 15.0。
- 临时唯一 bundle 的窗口可见，并已实际点击“关闭”确认 GPUI handler 退出进程；
  同机另一 worktree 的旧实例保持运行。
- 本轮改动文件通过 `cargo fmt --check -p agentdeck-desktop` 和对
  `agentdeck-protocol/src/lib.rs` 的定向 rustfmt。
- `block 0.1.6` 会产生 future-incompatibility warning，不阻塞当前 P0 构建。

## 完成边界

本计划完成只代表 GPUI 桌面基础可运行。daemon/IPC、单会话、历史、审批、Markdown
与真实产品交互均属于后续独立切片。
