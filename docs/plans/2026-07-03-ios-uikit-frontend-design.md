# AgentDeck iOS UIKit 前端设计（fixture 驱动，先前端后链路）

| 字段 | 值 |
|---|---|
| 状态 | Implemented（P5.5 automatic；发行 composition 待 P5.6） |
| 日期 | 2026-07-03 |
| 最近更新 | 2026-07-27 |
| 主题 | iOS UIKit companion 前端骨架，用 canonical SessionSource fixture 回放代替真实链路 |
| 关联 | `NORTH_STAR.md`、`docs/plans/2026-07-01-agentdeck-mobile-relay-design.md`、`designs/agentdeck-design-system/` |

## 1. 背景和用户问题

`2026-07-01-agentdeck-mobile-relay-design.md` 已确认手机端方向：薄 Relay + `agentdeckd` remote mode + iOS UIKit companion，原路线是 R0-R2 先做服务端、R3 再做 iOS。本设计把 R3 的**前端部分提前**：不等 Relay 与 remote mode，先用协议对齐的 fixture 回放把 iOS UIKit 界面骨架完整跑起来，验证产品形态与渲染语义；真实链路（配对、网络、通知、实机）后置。

## 2. 目标

- 在 iPhone 模拟器上跑通 R3 companion 全部界面：机器列表、会话列表、会话详情（流式）、审批卡片、prompt 输入、配对入口、事件收件箱。
- 假数据直接用 canonical `ConversationSnapshotV2` + `RuntimeEventV2` 回放，接真实链路时 ViewModel 不更换
  数据协议。
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
- Mock 方式：canonical fixture 回放，经共享 `AgentDeckSessionSource.SessionSource` facade 进入 UI；旧
  `MobileSessionSource` 已在 P5.5 删除。
- 工程组织：同仓 `ios/` 目录 + XcodeGen（xcodeproj 不入库）。
- 代码共享：抽 `AgentDeckCore` SPM 共享库（方案 A，优于零侵入 source glob 与只共享协议类型两个备选）。
- 设备目标：iPhone 竖屏优先，iOS 17+。

## 5. 架构方案与边界

```text
仓库根
├── Package.swift                    # 新增 AgentDeckCore library target（macOS 14 + iOS 17）
├── Sources/
│   ├── AgentDeckCore/               # 平台无关共享层（含 canonical reducer/projection）
│   │   ├── Protocol/V2Types.swift   # 协议类型（agentdeck-protocol 的 Swift 镜像）
│   │   ├── AgentItemReducer.swift   # 流式累积 reducer
│   │   └── ConversationTurn.swift / HistoryModel.swift / ...（以实际依赖为准）
│   └── AgentDeck/                   # 现有 macOS AppKit 前端，改为依赖 AgentDeckCore
├── ios/
│   ├── project.yml                  # XcodeGen 声明式工程
│   ├── AgentDeckMobile/
│   │   ├── App/                     # AppDelegate / SceneDelegate / 导航
│   │   ├── Screens/                 # 各屏 VC + @MainActor view model
│   │   ├── DataSource/              # SessionSource 的 preview/test FixtureSessionSource 实现
│   │   ├── DesignTokens.swift      # 生成物：UIKit 版 token（禁止手改）
│   │   └── Fixtures/                # 协议语义对齐的 JSON fixture
│   └── AgentDeckMobileTests/
```

边界约束：

- `AgentDeckCore` 只含 Foundation/Observation 代码，不得 import AppKit/UIKit；canonical item/cursor projection
  与 `RuntimeConversationState` 已下沉至此，macOS、Relay client 与 iOS 共用同一 reducer。
- iOS app 的唯一数据入口是共享 `SessionSource`；`FixtureSessionSource` 只用于 preview/test。production
  `RelaySessionSource` 已在共享 client target 存在，但当前 `SceneDelegate` 的发行 composition 切换、真实配对
  与生命周期接线属于 P5.6，视图层不应 downcast concrete source。
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

1. **机器列表**：机器卡片（名称、typed connection state、最近心跳、活跃会话数），有待审批时带 badge；
   Relay 不可达、machine offline、reconnecting、revoked、incompatible、securityError 不压成一个 Bool。
2. **会话列表**：按「等待审批 / 活跃 / 最近历史」分组；行内显示 vendor 徽章、cwd、最后一条摘要。
3. **会话详情**：`UICollectionView`（compositional list layout + diffable data source）。cell 类型：用户消息、assistant markdown（流式增量）、reasoning（默认折叠）、工具调用/shell（折叠，与 macOS 折叠规范一致）、diff 摘要、错误状态。数据由共享 `AgentItemReducer` 驱动。Markdown 第一期用系统 `AttributedString(markdown:)`，不移植 macOS 的 AppKit builder，效果不足再评估。
4. **审批卡片**：详情流内嵌 cell，显示 vendor 原词 + 风险上下文（命令/路径摘要），approve / deny 两键；
   submitting、applied、already handled、delivery failed、expired 与 submission failed 都来自 canonical/receipt
   归并，不在点击时直接假定成功。
5. **prompt 输入栏**：固定底部、多行增高；发送后显示绑定 idempotency key 的本地 pending row，收到
   Accepted/Replayed 后按 commandID 等待 canonical user item 并替换，fixture 再回一条 assistant 响应。
6. **配对屏**（modal）：扫码区域 UI 占位（不接相机）+ 手动粘贴配对码 + 已配对设备列表与注销按钮，全部假数据。
7. **收件箱**：app 内事件列表（等待审批、turn 完成、失败），点击跳转对应会话。不做 APNs。

## 7. 数据流与 fixture

数据源协议由共享 `AgentDeckSessionSource` target 定义，iOS 只消费下列 facade 语义：

```swift
protocol SessionSource: Sendable {
    func machines() async -> AsyncStream<ResourceState<[MachineSummary]>>
    func conversations(machineID: String) async
        -> AsyncStream<ResourceState<[ConversationSummary]>>
    func conversation(conversationID: String) async -> AsyncStream<ConversationUpdate>
    func inbox() async -> AsyncStream<ResourceState<[InboxItem]>>
    func sendPrompt(conversationID: String, text: String, idempotencyKey: UUID) async throws
        -> CommandReceipt
    func resolveApproval(
        conversationID: String,
        turnID: String,
        approvalID: String,
        decision: ActionDecisionKind,
        idempotencyKey: UUID
    ) async throws -> ApprovalReceipt
}
```

fixture 不维护 `ServerEvent` 或 iOS 私有 event 镜像。每份 conversation 文件直接承载 canonical snapshot 与
Runtime v2 event，外层只保留回放 delay/approval gate：

```json
{
  "snapshot": { /* ConversationSnapshotV2 */ },
  "steps": [
    { "delayMs": 400, "awaitApproval": false, "event": { /* RuntimeEventV2 */ } }
  ]
}
```

数据流向：`FixtureSessionSource`（actor，按 `delayMs` 发布 snapshot/event/connection state）→ 每屏一个
`@MainActor` view model → 会话详情把 canonical 输入喂给 `RuntimeConversationState` → shared presentation
构造 display rows → diffable snapshot 更新 UICollectionView。

fixture 场景清单（bundle 内按场景分文件）：

- 两台机器：一台在线（2 个活跃会话）、一台离线。
- Codex 会话：含 reasoning、shell 工具调用、diff 摘要的完整流式回放。
- Claude Code 会话：对应 CC 的事件形状。
- 等待审批会话：进入即有 pending 审批卡，approve / deny 后流继续。
- 失败会话：中途报错的错误态。
- 空状态：无会话的机器。

fixture 状态机：source 内存维持 canonical snapshot、exact-next cursor、prompt/approval idempotency replay 与
有界 transcript。审批连续发布 `Claimed → Applying → Applied` 后返回 Applied receipt；prompt 返回
Accepted/Replayed，再发布同 commandID 的 canonical user/assistant/terminal。切屏返回状态保持，杀 app 重置。

## 8. 设计系统对接

- iOS 的 `DesignTokens.swift` 是生成物：扩展 `designs/agentdeck-design-system/tools/build.mjs`，从同一份 `tokens/tokens.json` SSOT 额外生成 UIKit 版（`UIColor`/`UIFont`），输出到 `ios/AgentDeckMobile/DesignTokens.swift`，文件头带「生成物禁止手改」标记。
- 组件语义（胶囊徽章、cwd 灰字、工具调用折叠样式）沿用 `COMPONENTS.md` 规范。
- 第一期单主题（codex 主题），与 macOS 一致。

## 9. 错误处理与可观测性

- 统一 `EmptyStateView`（iOS 版）承担空列表 / 加载占位 / 错误提示三种形态。
- fixture 解码、cursor、identity 或 approval transition 校验失败：发出/进入 typed `securityError`，不跳过坏
  event；fixture 是 canonical contract 的检验点，坏了必须立刻可见。
- 暂态断流显示 Relay unavailable / machine offline / reconnecting / lagged；revoked、incompatible、
  securityError 是不可逆 terminal，取消 observation、prompt 与 approval task 并禁止后续操作。
- 本期无网络与磁盘日志需求；不写入 `~/Library/Application Support/AgentDeck/`。

## 10. 测试与验收标准

验证命令：

```bash
# macOS 零回归（AgentDeckCore 抽取后必须全绿）
swift test

# iOS 工程生成 + 构建 + 测试
cd ios && xcodegen generate && \
  xcodebuild -project AgentDeckMobile.xcodeproj -scheme AgentDeckMobile \
    -destination 'platform=iOS Simulator,name=iPhone 17' test

# 文档结构检查
scripts/verify-agent-docs.sh
```

iOS 单测重点：

1. 所有 bundle fixture 能解码为 canonical snapshot + Runtime v2 event，并由 shared reducer exact-next 消费。
2. Core/Relay reducer 对 approval identity、赢家与 Claimed/Applying/Applied/DeliveryFailed/Expired 合法转换保持
   一致；pending + resolved identity 每 turn 最多 32，`.at(H)` snapshot 的 mid-turn inference 只绑定一次；
   错误输入原子失败且不污染旧 state。
3. `FixtureSessionSource`：首帧 snapshot、初始 connected、审批三段发布、idempotency replay、512 overflow
   终止旧 subscriber 与 late subscriber fresh snapshot 恢复。
4. `SessionDetailViewModel`：prompt/approval single-flight、transport-unknown 同 key 重试、commandID 精确过滤、
   receipt/canonical 乱序单调归并、event-seq retry fence、retired-operation 迟到 receipt 校验、fresh snapshot
   generation floor、terminal-only turn advance 与 direct-terminal fail-close、lagged 恢复、Expired 不臆造赢家、
   身份/赢家错绑和 fatal connection fail-close。commandless Error 只显示 diagnostic 并保持 streaming；只有
   fixed command-bound Failed Error 才结束 turn。snapshot direct Failed 没有 turnID 时，以全局唯一 commandID
   与本地 terminal-only approval 证据归并；上一 command 的 terminal 不能消费下一 prompt receipt。
5. Machine/Session/Inbox resource ViewModel：retryable `.failed` 清空旧 ready 投影并触发一次 `onUpdate`。

验收标准（模拟器）：

- 机器列表 → 会话列表 → 会话详情全链路可导航，fixture 数据渲染正确。
- Codex 与 Claude Code 两条会话流均能流式回放，折叠元素可展开。
- 审批卡可 approve / deny，卡片按 receipt/canonical 状态变化且流继续；delivery failed 只能重试同赢家。
- prompt 输入后 pending row 出现，canonical 同 commandID 消息到达后无重复替换，假响应回流。
- 配对屏与收件箱骨架可进入、可返回。
- `swift test` 全绿（macOS/共享 Core 无回归），iOS 单测全绿，`scripts/verify-agent-docs.sh` 通过。

P5.5 fresh automatic 证据：顶层 `swift test` 为
`980 XCTest / 4 skipped + 35 Swift Testing / 0 failure`；Core/Relay/protocol、SessionDetail/fixture、fresh
DerivedData iOS Simulator 与 Rust fixed Error producer/integrity 的精确计数见 `docs/QUALITY.md`。

## 11. 实现偏差记录

实现阶段与本设计的差异如下，均属有意决策：

1. **FixtureSessionSource 状态保持改为有界恢复**：conversation buffer 固定 512；慢 subscriber overflow 后
   收到 lagged 并终止。source 同时持续更新 compacted canonical snapshot，late subscriber 先收 fresh snapshot
   再连续恢复，不保留无界完整 transcript。
2. **DesignTokens 实名**：iOS `DesignTokens.swift` 生成的语义色实名为 `text`、`text2`、`surface`（来自设计 SSOT `tokens.json` 的实际 key），设计期草案内文描述曾引用 `fg`/`fgMuted`/`bgRaised` 作为占位名称，以生成物为准。
3. **强制暗色**：iOS app 在 `SceneDelegate` 中对 `UIWindow` 设置 `overrideUserInterfaceStyle = .dark`，与 macOS 端设计风格一致（纯暗色 token 设计，本期不做明暗切换）。
4. **VM 未用 @Observable**：实现为普通 `@MainActor` class + `onUpdate` 闭包（UIKit 无自动观察，四屏一致），设计文档 §7 中"每屏一个 `@Observable` view model"的描述属于草案占位，以实现为准。
5. **typed 断流/终态 presentation 已实现，真实重连未接线**：四组 ViewModel 能区分暂态与 fatal state；
   当前 `SceneDelegate` 仍注入 fixture，因此真实 WSS 重连与发行 lifecycle 证据后置到 P5.6/P5.9。
6. **机器卡片「最近心跳」字段本期未在 UI 展示**：`MachineSummary` 中已计算 `lastHeartbeat` 字段，但本期 UI 未展示，待 Relay 接入后随真实心跳数据一起在机器卡片显示。

## 12. 后续衔接

- P5.6 新增发行 composition root，把 `SceneDelegate` 从 preview/test `FixtureSessionSource` 切到既有
  `RelaySessionSource`，并接真实扫码、credential 与前后台 lifecycle；不恢复或复制
  `MobileSessionSource`。
- 收件箱升级为 APNs 通知入口（沿用 relay 设计的通知 hook）。
- P5.9 在 fresh temp Relay + 真实 P4 daemon RemoteLink + synthetic vendor adapter + production Swift client +
  iOS Simulator 固定拓扑验收真实 source composition；物理 iPhone、公网、production-signed Keychain、第二
  Mac 与真实 vendor 继续 post-MVP BLOCKED，不能由 fixture/Simulator 结果替代。
- （已完成：AGENTS.md、README.md、docs/index.md 已补 iOS 入口与验证命令。）
