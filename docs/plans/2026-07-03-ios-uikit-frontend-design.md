# AgentDeck iOS UIKit 前端设计（fixture 驱动，先前端后链路）

| 字段 | 值 |
|---|---|
| 状态 | Implemented |
| 日期 | 2026-07-03 |
| 主题 | iOS UIKit companion 前端骨架，用协议对齐 fixture 回放代替真实链路 |
| 关联 | `NORTH_STAR.md`、`docs/plans/2026-07-01-agentdeck-mobile-relay-design.md`、`designs/agentdeck-design-system/` |

## 1. 背景和用户问题

`2026-07-01-agentdeck-mobile-relay-design.md` 已确认手机端方向：薄 Relay + `agentdeckd` remote mode + iOS UIKit companion，原路线是 R0-R2 先做服务端、R3 再做 iOS。本设计把 R3 的**前端部分提前**：不等 Relay 与 remote mode，先用协议对齐的 fixture 回放把 iOS UIKit 界面骨架完整跑起来，验证产品形态与渲染语义；真实链路（配对、网络、通知、实机）后置。

## 2. 目标

- 在 iPhone 模拟器上跑通 R3 companion 全部界面：机器列表、会话列表、会话详情（流式）、审批卡片、prompt 输入、配对入口、事件收件箱。
- 假数据用 `agentdeck-protocol` 语义的事件序列回放，接真实链路时 UI 层零迁移。
- 把平台无关的协议类型与会话模型抽成共享 SPM 库，macOS / iOS 共同依赖，边界由编译器保证。
- iOS 视觉沿用 `designs/agentdeck-design-system` 同一份 token SSOT。

## 3. 非目标

- 不做 Relay、remote mode、任何网络代码或 daemon 直连。
- 不做真实扫码配对、相机权限、APNs 推送。
- 不做数据持久化（杀 app 重置 fixture 状态）。
- 不做 iPad 适配、横屏、明暗主题切换。
- 不做 iOS 端编辑器、文件浏览器、Git 面板（沿用 relay 设计的 companion 边界）。

## 4. 已确认的决策

- 功能范围：按 relay 设计 R3 companion 范围。
- Mock 方式：协议对齐 fixture 回放，经 `MobileSessionSource` 协议进入 UI。
- 工程组织：同仓 `ios/` 目录 + XcodeGen（xcodeproj 不入库）。
- 代码共享：抽 `AgentDeckCore` SPM 共享库（方案 A，优于零侵入 source glob 与只共享协议类型两个备选）。
- 设备目标：iPhone 竖屏优先，iOS 17+。

## 5. 架构方案与边界

```text
仓库根
├── Package.swift                    # 新增 AgentDeckCore library target（macOS 14 + iOS 17）
├── Sources/
│   ├── AgentDeckCore/               # 新：平台无关共享层（从 AgentDeck 移入，零逻辑改动）
│   │   ├── Protocol/V2Types.swift   # 协议类型（agentdeck-protocol 的 Swift 镜像）
│   │   ├── AgentItemReducer.swift   # 流式累积 reducer
│   │   └── ConversationTurn.swift / HistoryModel.swift / ...（以实际依赖为准）
│   └── AgentDeck/                   # 现有 macOS AppKit 前端，改为依赖 AgentDeckCore
├── ios/
│   ├── project.yml                  # XcodeGen 声明式工程
│   ├── AgentDeckMobile/
│   │   ├── App/                     # AppDelegate / SceneDelegate / 导航
│   │   ├── Screens/                 # 各屏 VC + @Observable view model
│   │   ├── DataSource/              # MobileSessionSource 协议 + FixtureSessionSource
│   │   ├── DesignTokens.swift      # 生成物：UIKit 版 token（禁止手改）
│   │   └── Fixtures/                # 协议语义对齐的 JSON fixture
│   └── AgentDeckMobileTests/
```

边界约束：

- `AgentDeckCore` 只含 Foundation/Observation 代码，不得 import AppKit/UIKit；macOS 端迁移只做文件移动与必要的 `public` 化，零逻辑改动。
- iOS app 的唯一数据入口是 `MobileSessionSource` 协议；本期唯一实现是 `FixtureSessionSource`。未来 Relay 就绪时新增 `RelaySessionSource`，视图层不动。
- 会话渲染路径按 `SessionCapabilities` 路由，禁止 `if agentKind == .codex` 硬编码分支（沿用 N2）。
- vendor 原词（审批文案、徽章）原样展示，不强行统一语义。

## 6. 界面结构与导航

单 `UINavigationController` 栈，iPhone 竖屏：

```text
机器列表 (根屏)
 ├─→ 配对 (右上角入口, modal)
 ├─→ 收件箱 (待审批/完成/失败聚合, 右上角入口)
 └─→ 会话列表 (选中某机器)
       └─→ 会话详情 (流式)
             ├─ 内嵌审批卡片 cell
             └─ 底部 prompt 输入栏
```

1. **机器列表**：机器卡片（名称、在线/离线状态点、最近心跳、活跃会话数），有待审批时带 badge。
2. **会话列表**：按「等待审批 / 活跃 / 最近历史」分组；行内显示 vendor 徽章、cwd、最后一条摘要。
3. **会话详情**：`UICollectionView`（compositional list layout + diffable data source）。cell 类型：用户消息、assistant markdown（流式增量）、reasoning（默认折叠）、工具调用/shell（折叠，与 macOS 折叠规范一致）、diff 摘要、错误状态。数据由共享 `AgentItemReducer` 驱动。Markdown 第一期用系统 `AttributedString(markdown:)`，不移植 macOS 的 AppKit builder，效果不足再评估。
4. **审批卡片**：详情流内嵌 cell，显示 vendor 原词 + 风险上下文（命令/路径摘要），approve / deny 两键；fixture 模式下走假状态机，决议后流继续回放。
5. **prompt 输入栏**：固定底部、多行增高；发送后乐观插入用户消息，fixture 回一条假 assistant 响应。
6. **配对屏**（modal）：扫码区域 UI 占位（不接相机）+ 手动粘贴配对码 + 已配对设备列表与注销按钮，全部假数据。
7. **收件箱**：app 内事件列表（等待审批、turn 完成、失败），点击跳转对应会话。不做 APNs。

## 7. 数据流与 fixture

数据源协议（iOS 端定义）：

```swift
protocol MobileSessionSource {
    func machines() -> AsyncStream<[MachineSummary]>
    func sessions(machineID: String) -> AsyncStream<[SessionSummary]>
    func events(sessionID: String) -> AsyncStream<SessionEvent>
    func sendPrompt(sessionID: String, text: String) async
    func resolveApproval(sessionID: String, approvalID: String, approve: Bool) async
}
```

fixture 直接用协议 payload，不自造格式：JSON 为 `agentdeck-protocol` 语义的事件序列，用 `AgentDeckCore` 的 `V2Types` 解码，外层只套薄回放信封：

```json
{ "delayMs": 400, "event": { /* 协议原样的事件 payload */ } }
```

数据流向：`FixtureSessionSource`（按 `delayMs` 定时吐事件）→ 每屏一个 `@Observable` view model → 会话详情把事件喂给 `AgentItemReducer` → diffable snapshot 更新 UICollectionView。

fixture 场景清单（bundle 内按场景分文件）：

- 两台机器：一台在线（2 个活跃会话）、一台离线。
- Codex 会话：含 reasoning、shell 工具调用、diff 摘要的完整流式回放。
- Claude Code 会话：对应 CC 的事件形状。
- 等待审批会话：进入即有 pending 审批卡，approve / deny 后流继续。
- 失败会话：中途报错的错误态。
- 空状态：无会话的机器。

假状态机：`FixtureSessionSource` 内存维持会话状态（审批已决、乐观插入的 prompt），切屏返回状态保持，杀 app 重置。

## 8. 设计系统对接

- iOS 的 `DesignTokens.swift` 是生成物：扩展 `designs/agentdeck-design-system/tools/build.mjs`，从同一份 `tokens/tokens.json` SSOT 额外生成 UIKit 版（`UIColor`/`UIFont`），输出到 `ios/AgentDeckMobile/DesignTokens.swift`，文件头带「生成物禁止手改」标记。
- 组件语义（胶囊徽章、cwd 灰字、工具调用折叠样式）沿用 `COMPONENTS.md` 规范。
- 第一期单主题（codex 主题），与 macOS 一致。

## 9. 错误处理与可观测性

- 统一 `EmptyStateView`（iOS 版）承担空列表 / 加载占位 / 错误提示三种形态。
- fixture 解码失败：debug 下断言，release 下渲染错误 cell，不静默吞掉——fixture 是协议理解的检验点，坏了必须立刻可见。
- 数据源断流：详情屏显示重连占位态（为未来真实链路预留 UI 语义）。
- 本期无网络与磁盘日志需求；不写入 `~/Library/Application Support/AgentDeck/`。

## 10. 测试与验收标准

验证命令：

```bash
# macOS 零回归（AgentDeckCore 抽取后必须全绿）
swift test

# iOS 工程生成 + 构建 + 测试
cd ios && xcodegen generate && \
  xcodebuild -scheme AgentDeckMobile \
    -destination 'platform=iOS Simulator,name=iPhone 16' build test

# 文档结构检查
scripts/verify-agent-docs.sh
```

iOS 单测重点：

1. 所有 bundle fixture 能被 `V2Types` 成功解码（防 fixture 漂移）。
2. `AgentItemReducer` 消费完整 fixture 后的 turn / 行数断言。
3. `FixtureSessionSource` 假状态机：审批决议后状态正确、prompt 乐观插入正确。

验收标准（模拟器）：

- 机器列表 → 会话列表 → 会话详情全链路可导航，fixture 数据渲染正确。
- Codex 与 Claude Code 两条会话流均能流式回放，折叠元素可展开。
- 审批卡可 approve / deny，卡片状态变化且流继续。
- prompt 输入后用户消息乐观出现，假响应回流。
- 配对屏与收件箱骨架可进入、可返回。
- `swift test` 全绿（macOS 无回归），iOS 单测全绿，`scripts/verify-agent-docs.sh` 通过。

## 12. 实现偏差记录

实现阶段与本设计的差异如下，均属有意决策：

1. **FixtureSessionSource 状态保持**：`FixtureSessionSource` 在内存中维护完整 transcript 缓冲区（`Playback.transcript`），切屏返回时新订阅者立即收到全量 transcript 回放，与设计文档「切屏返回状态保持」一致。prompt 回声后流式 `turnComplete` 正常收尾，回放 transcript 不截断。
2. **DesignTokens 实名**：iOS `DesignTokens.swift` 生成的语义色实名为 `text`、`text2`、`surface`（来自设计 SSOT `tokens.json` 的实际 key），设计期草案内文描述曾引用 `fg`/`fgMuted`/`bgRaised` 作为占位名称，以生成物为准。
3. **强制暗色**：iOS app 在 `SceneDelegate` 中对 `UIWindow` 设置 `overrideUserInterfaceStyle = .dark`，与 macOS 端设计风格一致（纯暗色 token 设计，本期不做明暗切换）。

## 11. 后续衔接

- R1/R2（Relay 与 remote mode）落地后，新增 `RelaySessionSource` 实现 `MobileSessionSource`，替换 fixture 数据源；配对屏接真实扫码与 credential 流程。
- 收件箱升级为 APNs 通知入口（沿用 relay 设计的通知 hook）。
- `AGENTS.md`、`README.md`、`docs/index.md` 需在实现阶段同步补 iOS 目录说明与验证命令。
