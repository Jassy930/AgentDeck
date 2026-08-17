# GPUI 桌面端重启设计

日期：2026-08-17

## 背景

旧 macOS AppKit 客户端已经积累了完整桌面功能和大量行为测试，但它同时绑定了
Swift UI、旧 daemon transport 与正在扩张的 Relay 路线。当前产品决策是停止在旧
桌面端上继续迁移或兼容，以最小 GPUI 实现重新建立快速迭代节奏。

## 目标

- 删除旧 AppKit executable、资源和桌面专属测试。
- 用 Rust、GPUI 和 gpui-component 建立可启动的 macOS `.app`。
- 保留统一 build/run 入口和机器可读 selfcheck。
- 保留 Rust daemon/protocol/CLI、Swift `AgentDeckCore` 与 iOS。
- 后续优先做本机单会话纵向切片，Relay 不进入桌面启动路径。

## 非目标

- 不复刻旧 AppKit UI 或迁移旧 SessionModel。
- 不在首个切片连接 daemon、IPC 或 vendor CLI。
- 不实现 Relay、远程机器、配对、历史、审批、Markdown 或多窗口。
- 不为旧 Swift 桌面接口建立兼容层。

## 架构

当前 P0：

```text
AgentDeck.app
└─ agentdeck-desktop
   ├─ GPUI Application / Window
   ├─ gpui-component Root / Button
   └─ --selfcheck
```

下一阶段允许的本机路径：

```text
agentdeck-desktop → typed local client → agentdeckd → vendor adapter
```

禁止把 `agentdeckd` 链接进 GUI 进程；禁止 UI 直接解析 vendor JSON。Relay 保留为
独立代码线，但不是桌面依赖或默认质量门禁。

## 依赖选择

P0 固定 `gpui = 0.2.2`、`gpui-component = 0.5.1`，并启用
`runtime_shaders`。选择发布版本是为了尽快获得可复现基线；流式 Markdown、动态
列表和无障碍能力在相应功能切片开始时重新评估，不在 P0 预先设计。

## 错误处理与可观测性

- 窗口创建失败直接终止并输出明确错误。
- `--selfcheck` 创建隐藏窗口并初始化 Metal、Root 和组件树，成功时输出单行 JSON。
- selfcheck 明确报告 `relay=disabled`，不把未实现能力伪装为健康。
- build/run 脚本验证实际 bundle 进程路径、Info.plist minOS 和 Mach-O minOS。

## 验收标准

- `cargo check -p agentdeck-desktop` 通过。
- `cargo test -p agentdeck-desktop` 通过。
- `cargo run -p agentdeck-desktop -- --selfcheck` 退出码为 0。
- `swift test` 保留共享 Core 的有效测试并通过。
- `./script/build_and_run.sh --verify` 启动新 bundle 并完成读回。
- 仓库中不再存在 `Sources/AgentDeck/` 或 `Tests/AgentDeckTests/`。

## 已知边界

`gpui-component 0.5.1` 的流式 Markdown 和组件无障碍能力不足以直接承诺最终
transcript；这是未来切片的真实技术门槛，不阻塞当前最小壳。
