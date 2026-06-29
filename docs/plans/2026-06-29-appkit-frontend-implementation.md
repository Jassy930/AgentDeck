# AppKit 前端重写实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把 AgentDeck 的 macOS 前端从 SwiftUI 整体重写为纯 AppKit（移除 SwiftUI 与 `Textual` 依赖、markdown 改用原生 `NSAttributedString`、会话流用虚拟化 NSTableView、历史侧栏用 NSOutlineView），功能/视觉对等，模型层零改动，并补上 Swift↔协议契约一致性测试。

**Architecture:** 模型/逻辑层（`SessionModel/WorkbenchModel/ThreadRuntimeModel/AgentItemReducer/ConversationTurn/ConversationRailNavigator/ToolPresentation/HistoryModel/DaemonClient 栈/StreamingTextBuffer/TurnJumpRailLayout`）保持不动，AppKit 侧用统一 `ObservationBinder` 消费 `@Observable`。先增量加入纯逻辑单元与 AppKit 视图组件（与现有 SwiftUI 应用并存、保持 `swift build` 绿），最后一次性切换入口（`main.swift` → `NSApplication`+`AppDelegate`）并删除 SwiftUI 视图与 `Textual`。

**Tech Stack:** Swift 6 / SwiftPM、AppKit（NSViewController/NSTableView/NSOutlineView/NSTextView/NSAttributedString）、Swift Observation（`@Observable` + `withObservationTracking`）；测试用 `swift test`；后端不动（`cargo` 仅用于回归确认）。

## Global Constraints

- 设计依据：`docs/plans/2026-06-29-appkit-frontend-design.md`（本计划逐条覆盖它）。
- **模型/逻辑/DaemonClient 文件零改动**：`SessionModel.swift`、`WorkbenchModel.swift`、`ThreadRuntimeModel.swift`、`AgentItemReducer.swift`、`ConversationTurn.swift`、`ConversationRailNavigator.swift`、`ToolPresentation.swift`、`HistoryModel.swift`、`DaemonClient.swift`、`DaemonTransport.swift`、`ProcessDaemonTransport.swift`、`SessionModel` 内的 `StreamingTextBuffer`/`TurnJumpRailLayout`。如确需新增可被复用的小接口，先在任务里说明，不得改其现有语义。
- **功能/视觉对等**：现有 SwiftUI 源是视觉的事实源，按 file:line 对照复现，不借机重设计。
- **零 `import SwiftUI`**：重写完成后全仓库不得残留 `import SwiftUI`（含 `NSViewRepresentable`，它属 SwiftUI）。
- **不引新运行时依赖**：markdown 用系统 `NSAttributedString(markdown:)`，不引第三方。
- 不改后端/daemon/协议/IPC 线格式；不做 `.app` 打包，沿用现有 SwiftPM 可执行 + `setActivationPolicy(.regular)`。
- 中立边界不变：UI 只消费中立 `AgentItem`，不解析供应商 JSON。
- 失败可见、不静默挂起（Eng premise 9）；A1 daemon 生命周期仍由 DaemonClient/transport 负责。
- 每个任务边界 `swift build` 必须通过；测试输出 pristine（无新增警告）。
- 提交信息用 conventional commit 前缀，**不含任何协作者/co-author 信息**。
- 不擅自 `git push` / 发布。
- 平台：macOS 15（`Package.swift` 现有 `.macOS(.v15)`）。

---

### Task 1: Swift↔协议契约一致性测试

补上子项目 1 推迟的项：以仓库内 schema 为基准校验 Swift 解码契约。纯测试，无 UI 依赖，独立可做。

**Files:**
- Create: `Tests/AgentDeckTests/ProtocolConformanceTests.swift`

**Interfaces:**
- Consumes: 仓库内 `protocol/agentdeck/agentdeck-protocol.schema.json`（子项目 1 产物）；Swift 侧 `IpcMessage`（`DaemonClient.swift`）、`AgentItem` 解码路径（`AgentItemReducer`/`HistoryModel`）。
- Produces: 无（仅测试）。

- [ ] **Step 1: 写失败测试——schema 中的 AgentItemKind 取值集合被 Swift 侧覆盖**

`Tests/AgentDeckTests/ProtocolConformanceTests.swift`：
```swift
import XCTest
@testable import AgentDeck

final class ProtocolConformanceTests: XCTestCase {
    /// 读取仓库内协议 schema（子项目 1 提交的生成产物）。
    private func loadSchema() throws -> [String: Any] {
        // 测试运行的 CWD 是包根；schema 在 protocol/agentdeck 下。
        let path = "protocol/agentdeck/agentdeck-protocol.schema.json"
        let url = URL(fileURLWithPath: path)
        let data = try Data(contentsOf: url)
        let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        return json ?? [:]
    }

    /// schema 的 definitions.AgentItemKind 列出的 kind 标签，必须都是 Swift 侧
    /// 已知能渲染的 kind（与 SessionView 行分发 / AgentItemReducer 对齐）。
    func testAgentItemKindTagsAreAllHandledBySwift() throws {
        let schema = try loadSchema()
        let defs = schema["definitions"] as? [String: Any] ?? [:]
        let kindSchema = defs["AgentItemKind"] as? [String: Any] ?? [:]
        let tags = AgentItemKindTagExtractor.tags(from: kindSchema)
        XCTAssertFalse(tags.isEmpty, "schema 未解析出 AgentItemKind 标签")

        // Swift 侧已知 kind（事实源：行分发 switch / reducer）。
        let known: Set<String> = [
            "user", "message", "reasoning", "shell", "fileEdit", "webSearch",
            "plan", "hookPrompt", "toolCall", "collabAgentToolCall", "media",
            "reviewMode", "contextCompaction", "raw",
        ]
        let missing = tags.subtracting(known)
        XCTAssertTrue(missing.isEmpty, "契约新增了 Swift 未处理的 AgentItem kind: \(missing.sorted())")
    }
}
```

- [ ] **Step 2: 运行确认失败（缺 `AgentItemKindTagExtractor`）**

Run: `swift test --filter ProtocolConformanceTests`
Expected: 编译失败 / FAIL —— 找不到 `AgentItemKindTagExtractor`。

- [ ] **Step 3: 实现 schema 标签抽取助手**

在同文件加入（schemars 对内部 tag 枚举常见生成 `oneOf` 数组，每支带 `properties.kind.enum: ["x"]` 或 `const`）：
```swift
enum AgentItemKindTagExtractor {
    /// 从 AgentItemKind 的 JSON Schema 片段里抽出所有 kind 标签字符串。
    /// 兼容 schemars 0.8 的内部 tag 枚举形态：oneOf -> 每支 properties.kind.{enum|const}。
    static func tags(from kindSchema: [String: Any]) -> Set<String> {
        var out = Set<String>()
        let branches = (kindSchema["oneOf"] as? [[String: Any]])
            ?? (kindSchema["anyOf"] as? [[String: Any]])
            ?? []
        for branch in branches {
            guard let props = branch["properties"] as? [String: Any],
                  let kind = props["kind"] as? [String: Any] else { continue }
            if let e = kind["enum"] as? [String] { out.formUnion(e) }
            if let c = kind["const"] as? String { out.insert(c) }
        }
        return out
    }
}
```

- [ ] **Step 4: 运行确认通过**

Run: `swift test --filter ProtocolConformanceTests`
Expected: PASS。若 FAIL 且报告 `missing` 非空，说明契约确实新增了 Swift 未处理 kind —— 那是真实缺口，停下并上报（不要为通过测试而把未知 kind 塞进 `known`）。

- [ ] **Step 5: 提交**
```bash
git add Tests/AgentDeckTests/ProtocolConformanceTests.swift
git commit -m "test(swift): protocol schema conformance for AgentItem kinds"
```

---

### Task 2: MarkdownAttributedStringBuilder（原生 markdown 渲染单元）

去 `Textual` 的核心替代：markdown 文本 → `NSAttributedString`。纯函数、可单测。本任务不接线 UI（与 SwiftUI 并存，build 绿）。

**Files:**
- Create: `Sources/AgentDeck/MarkdownAttributedStringBuilder.swift`
- Create: `Tests/AgentDeckTests/MarkdownAttributedStringBuilderTests.swift`

**Interfaces:**
- Produces:
  - `struct MarkdownStyle { var bodyFont: NSFont; var codeFont: NSFont; var textColor: NSColor; var codeBackground: NSColor; var linkColor: NSColor; static var standard: MarkdownStyle }`
  - `enum MarkdownAttributedStringBuilder { static func attributedString(from markdown: String, style: MarkdownStyle = .standard) -> NSAttributedString }`
- Consumes: AppKit `NSAttributedString`/`NSFont`/`NSColor`。

- [ ] **Step 1: 写失败测试**

`Tests/AgentDeckTests/MarkdownAttributedStringBuilderTests.swift`：
```swift
import XCTest
import AppKit
@testable import AgentDeck

final class MarkdownAttributedStringBuilderTests: XCTestCase {
    func testPlainParagraphPreservesText() {
        let s = MarkdownAttributedStringBuilder.attributedString(from: "hello world")
        XCTAssertEqual(s.string, "hello world")
    }

    func testInlineCodeUsesMonospacedFont() {
        let s = MarkdownAttributedStringBuilder.attributedString(from: "a `code` b")
        // 找到 "code" 区段，断言其字体是等宽。
        let ns = s.string as NSString
        let r = ns.range(of: "code")
        let font = s.attribute(.font, at: r.location, effectiveRange: nil) as? NSFont
        XCTAssertTrue(font?.fontDescriptor.symbolicTraits.contains(.monoSpace) ?? false,
                      "行内代码应使用等宽字体")
    }

    func testUnsupportedTableDowngradesToPlainTextWithoutCrash() {
        let table = "| a | b |\n|---|---|\n| 1 | 2 |"
        let s = MarkdownAttributedStringBuilder.attributedString(from: table)
        XCTAssertFalse(s.string.isEmpty, "表格降级为纯文本，不应为空或崩溃")
    }

    func testEmptyStringYieldsEmpty() {
        XCTAssertEqual(MarkdownAttributedStringBuilder.attributedString(from: "").string, "")
    }
}
```

- [ ] **Step 2: 运行确认失败**

Run: `swift test --filter MarkdownAttributedStringBuilderTests`
Expected: 编译失败（缺类型）。

- [ ] **Step 3: 实现 builder**

`Sources/AgentDeck/MarkdownAttributedStringBuilder.swift`：
```swift
import AppKit

struct MarkdownStyle {
    var bodyFont: NSFont
    var codeFont: NSFont
    var textColor: NSColor
    var codeBackground: NSColor
    var linkColor: NSColor

    static var standard: MarkdownStyle {
        MarkdownStyle(
            bodyFont: .systemFont(ofSize: NSFont.systemFontSize),
            codeFont: .monospacedSystemFont(ofSize: NSFont.systemFontSize - 1, weight: .regular),
            textColor: .labelColor,
            codeBackground: .quaternaryLabelColor,
            linkColor: .linkColor
        )
    }
}

enum MarkdownAttributedStringBuilder {
    static func attributedString(from markdown: String, style: MarkdownStyle = .standard) -> NSAttributedString {
        // 用 Foundation 的 AttributedString markdown 解析（保留 inline intents），
        // 失败或不支持的语法降级为纯文本，绝不崩溃。
        var options = AttributedString.MarkdownParsingOptions()
        options.interpretedSyntax = .inlineOnlyPreservingWhitespace
        let parsed: AttributedString
        if let a = try? AttributedString(markdown: markdown, options: options) {
            parsed = a
        } else {
            return NSAttributedString(
                string: markdown,
                attributes: [.font: style.bodyFont, .foregroundColor: style.textColor]
            )
        }
        let result = NSMutableAttributedString(attributedString: NSAttributedString(parsed))
        let full = NSRange(location: 0, length: result.length)
        // 基线样式
        result.addAttributes([.font: style.bodyFont, .foregroundColor: style.textColor], range: full)
        // 行内代码：AttributedString 的 inlinePresentationIntent.code → 等宽 + 背景
        result.enumerateAttribute(.init("NSInlinePresentationIntent"), in: full) { value, range, _ in
            // 回退：直接对带 code intent 的区段应用等宽（见下方 applyInlineCode）
            _ = value; _ = range
        }
        applyInlineCode(to: result, parsed: parsed, style: style)
        applyLinks(to: result, style: style)
        return result
    }

    /// 遍历 AttributedString runs，把 inlinePresentationIntent 含 .code 的 run 映射到
    /// NSAttributedString 等宽 + 背景。
    private static func applyInlineCode(to ns: NSMutableAttributedString, parsed: AttributedString, style: MarkdownStyle) {
        var cursor = 0
        for run in parsed.runs {
            let length = parsed[run.range].characters.count
            let range = NSRange(location: cursor, length: length)
            if let intent = run.inlinePresentationIntent, intent.contains(.code), range.location + range.length <= ns.length {
                ns.addAttributes([.font: style.codeFont, .backgroundColor: style.codeBackground], range: range)
            }
            cursor += length
        }
    }

    private static func applyLinks(to ns: NSMutableAttributedString, style: MarkdownStyle) {
        let full = NSRange(location: 0, length: ns.length)
        ns.enumerateAttribute(.link, in: full) { value, range, _ in
            guard value != nil else { return }
            ns.addAttributes([.foregroundColor: style.linkColor, .underlineStyle: NSUnderlineStyle.single.rawValue], range: range)
        }
    }
}
```
> 注：`inlinePresentationIntent` 的 run 长度用字符计数累加映射到 NSRange；若实现时发现 emoji/组合字符导致 NSRange 偏移，改用 `NSAttributedString(parsed)` 的 `Range<AttributedString.Index>` → `NSRange(_:in:)` 转换。先按上面实现，测试若因偏移失败再切换该转换法。

- [ ] **Step 4: 运行确认通过**

Run: `swift test --filter MarkdownAttributedStringBuilderTests`
Expected: PASS（4 个）。若行内代码区段定位失败，改用 `NSRange(run.range, in: parsed)` 转换后重试。

- [ ] **Step 5: 提交**
```bash
git add Sources/AgentDeck/MarkdownAttributedStringBuilder.swift Tests/AgentDeckTests/MarkdownAttributedStringBuilderTests.swift
git commit -m "feat(ui): native NSAttributedString markdown builder"
```

---

### Task 3: ConversationDisplayRow（把 turns 摊平成可虚拟化行模型）

**Files:**
- Create: `Sources/AgentDeck/ConversationDisplayRow.swift`
- Create: `Tests/AgentDeckTests/ConversationDisplayRowTests.swift`

**Interfaces:**
- Consumes: `ConversationTurn`、`UIItem`（`SessionModel.swift`/`ConversationTurn.swift`）。复用既有 `makeConversationTurns(from:)`（框架无关，返回 `[ConversationTurn]`，每个含 user `UIItem?` 与 assistant `[UIItem]`）。
- Produces:
  - `enum ConversationDisplayRow: Identifiable { case userPrompt(turnId: String, item: UIItem); case assistantItem(turnId: String, item: UIItem); case approval(turnId: String, item: UIItem); case error(turnId: String, item: UIItem); case warning(turnId: String, item: UIItem) }`，含 `var id: String`、`var turnId: String`、`var item: UIItem`、`var firstInTurn: Bool`、`var lastInTurn: Bool`（后两者由构造时填充，存为关联值或包装 struct——见下）。
  - `enum ConversationDisplayRowBuilder { static func rows(from turns: [ConversationTurn]) -> [ConversationDisplayRow] }`
- 注：为携带 `firstInTurn/lastInTurn`，用包装 struct 更清晰：

- [ ] **Step 1: 写失败测试**

先确认 `UIItem`/`ConversationTurn` 字段（实现者读 `Sources/AgentDeck/ConversationTurn.swift` 与 `SessionModel.swift` 中 `UIItem` 定义；下面用占位字段名 `id`/`kind`，按真实定义调整）。

`Tests/AgentDeckTests/ConversationDisplayRowTests.swift`：
```swift
import XCTest
@testable import AgentDeck

final class ConversationDisplayRowTests: XCTestCase {
    func testUserThenAssistantItemsFlattenInOrderWithBoundaries() {
        // 用既有工厂构造一个 turn：1 个 user + 2 个 assistant item。
        // （实现者：用 makeConversationTurns 或直接构造 ConversationTurn，按真实初始化器。）
        let turns = ConversationDisplayRowTestSupport.sampleTurns()
        let rows = ConversationDisplayRowBuilder.rows(from: turns)

        XCTAssertEqual(rows.count, 3)
        XCTAssertTrue(rows[0].firstInTurn)
        XCTAssertTrue(rows[2].lastInTurn)
        XCTAssertEqual(rows.map(\.turnId).filter { $0 == rows[0].turnId }.count, 3,
                       "同一 turn 的行 turnId 一致")
        // id 唯一
        XCTAssertEqual(Set(rows.map(\.id)).count, rows.count)
    }
}
```
（`ConversationDisplayRowTestSupport.sampleTurns()` 由实现者在测试文件内写一个最小构造，基于真实 `ConversationTurn`/`UIItem` 初始化器。）

- [ ] **Step 2: 运行确认失败**

Run: `swift test --filter ConversationDisplayRowTests`
Expected: 编译失败（缺类型）。

- [ ] **Step 3: 实现摊平器**

`Sources/AgentDeck/ConversationDisplayRow.swift`（读真实 `ConversationTurn`/`UIItem` 字段后落地；结构如下）：
```swift
import Foundation

struct ConversationDisplayRow: Identifiable {
    enum Role { case userPrompt, assistantItem, approval, error, warning }
    let role: Role
    let turnId: String
    let item: UIItem
    let firstInTurn: Bool
    let lastInTurn: Bool

    // 行唯一 id：turnId + item.id + role（同一 item 不会同时出现在两种 role）。
    var id: String { "\(turnId)#\(item.id)#\(role)" }
}

enum ConversationDisplayRowBuilder {
    /// 把 [ConversationTurn] 摊平成可虚拟化的扁平行序列；
    /// 每个 turn 的首/尾行打 firstInTurn/lastInTurn 标志承载 turn 视觉分组。
    static func rows(from turns: [ConversationTurn]) -> [ConversationDisplayRow] {
        var out: [ConversationDisplayRow] = []
        for turn in turns {
            var turnRows: [(ConversationDisplayRow.Role, UIItem)] = []
            if let user = turn.userItem {            // 按真实字段名调整
                turnRows.append((.userPrompt, user))
            }
            for item in turn.assistantItems {        // 按真实字段名调整
                let role: ConversationDisplayRow.Role
                switch item.kind {                   // 按真实 kind 表达调整
                case "approval": role = .approval     // 若审批不是 UIItem.kind，见下注
                case "error": role = .error
                case "warning": role = .warning
                default: role = .assistantItem
                }
                turnRows.append((role, item))
            }
            for (idx, pair) in turnRows.enumerated() {
                out.append(ConversationDisplayRow(
                    role: pair.0,
                    turnId: turn.id,                 // 按真实字段名调整
                    item: pair.1,
                    firstInTurn: idx == 0,
                    lastInTurn: idx == turnRows.count - 1
                ))
            }
        }
        return out
    }
}
```
> 注：审批/错误/警告在现有模型里如何承载（是 `UIItem.kind` 还是 `ThreadRuntimeModel.pendingActionRequest` 独立字段），实现者读 `ThreadRuntimeModel.swift`/`SessionModel.swift` 确认。若审批是独立的 `pendingActionRequest`（非 items 流），则 `.approval` 行不在此摊平，而在 ConversationViewController 末尾单列一行（Task 8 处理）；本任务的摊平只覆盖进入 `items` 的内容，并在测试中按真实模型构造。保持摊平器对「进入 items 的 kind」完整、对独立审批字段不臆造。

- [ ] **Step 4: 运行确认通过**

Run: `swift test --filter ConversationDisplayRowTests`
Expected: PASS。

- [ ] **Step 5: 提交**
```bash
git add Sources/AgentDeck/ConversationDisplayRow.swift Tests/AgentDeckTests/ConversationDisplayRowTests.swift
git commit -m "feat(ui): flatten conversation turns into virtualizable display rows"
```

---

### Task 4: ObservationBinder（@Observable → AppKit 刷新桥）

**Files:**
- Create: `Sources/AgentDeck/ObservationBinder.swift`
- Create: `Tests/AgentDeckTests/ObservationBinderTests.swift`

**Interfaces:**
- Produces:
  - `final class ObservationBinder { init(); func bind(_ read: @escaping () -> Void, onChange: @escaping () -> Void); func invalidate() }`
  - 语义：`bind` 立即在跟踪上下文里执行一次 `read`（建立依赖），当被读字段变化时调度 `onChange` 到 MainActor 并**自动重新 arm**（再次跟踪 `read`），直到 `invalidate()`。
- Consumes: Swift `Observation`（`withObservationTracking`）。

- [ ] **Step 1: 写失败测试（@Observable 变化触发 onChange 且能持续触发）**

`Tests/AgentDeckTests/ObservationBinderTests.swift`：
```swift
import XCTest
import Observation
@testable import AgentDeck

@MainActor
final class ObservationBinderTests: XCTestCase {
    @Observable final class Counter { var value = 0 }

    func testOnChangeFiresOnEachMutation() async {
        let counter = Counter()
        let binder = ObservationBinder()
        var fires = 0
        binder.bind({ _ = counter.value }, onChange: { fires += 1 })

        counter.value = 1
        await Task.yield()            // 让 MainActor 调度的 onChange 跑完
        counter.value = 2            // 第二次变化 —— 验证已 re-arm
        await Task.yield()

        XCTAssertGreaterThanOrEqual(fires, 2, "onChange 应在每次变化后触发（含 re-arm）")
        binder.invalidate()
    }

    func testInvalidateStopsObservation() async {
        let counter = Counter()
        let binder = ObservationBinder()
        var fires = 0
        binder.bind({ _ = counter.value }, onChange: { fires += 1 })
        binder.invalidate()
        counter.value = 99
        await Task.yield()
        XCTAssertEqual(fires, 0, "invalidate 后不应再触发")
    }
}
```

- [ ] **Step 2: 运行确认失败**

Run: `swift test --filter ObservationBinderTests`
Expected: 编译失败（缺类型）。

- [ ] **Step 3: 实现 binder**

`Sources/AgentDeck/ObservationBinder.swift`：
```swift
import Foundation
import Observation

/// 把 @Observable 的字段读取桥接到一次性回调，并自动 re-arm，便于 AppKit
/// 在模型变化时命令式刷新对应区域。onChange 总在 MainActor 调用。
@MainActor
final class ObservationBinder {
    private var isValid = true

    func bind(_ read: @escaping () -> Void, onChange: @escaping @MainActor () -> Void) {
        guard isValid else { return }
        withObservationTracking {
            read()
        } onChange: { [weak self] in
            // onChange 在变化发生的线程同步触发；跳回 MainActor 再刷新并 re-arm。
            Task { @MainActor in
                guard let self, self.isValid else { return }
                onChange()
                self.bind(read, onChange: onChange)   // re-arm
            }
        }
    }

    func invalidate() {
        isValid = false
    }
}
```

- [ ] **Step 4: 运行确认通过**

Run: `swift test --filter ObservationBinderTests`
Expected: PASS（2 个）。

- [ ] **Step 5: 提交**
```bash
git add Sources/AgentDeck/ObservationBinder.swift Tests/AgentDeckTests/ObservationBinderTests.swift
git commit -m "feat(ui): ObservationBinder bridging @Observable to AppKit refresh"
```

---

### Task 5: 文本行高测量助手 + 高度缓存

虚拟化 NSTableView 的 `heightOfRow` 基石。纯逻辑、可单测。

**Files:**
- Create: `Sources/AgentDeck/RowHeightCache.swift`
- Create: `Tests/AgentDeckTests/RowHeightCacheTests.swift`

**Interfaces:**
- Produces:
  - `func measuredTextHeight(_ attributed: NSAttributedString, width: CGFloat) -> CGFloat`（用 `NSTextStorage`+`NSLayoutManager`+`NSTextContainer` 量 used height；宽度受限、高度无限）。
  - `final class RowHeightCache { func height(rowId: String, version: Int, width: CGFloat, compute: () -> CGFloat) -> CGFloat; func invalidate(rowId: String); func invalidateAll() }`，键为 `rowId × version × width`，命中返回缓存，未命中调用 `compute` 并存。
- Consumes: AppKit 文本栈。

- [ ] **Step 1: 写失败测试**

`Tests/AgentDeckTests/RowHeightCacheTests.swift`：
```swift
import XCTest
import AppKit
@testable import AgentDeck

final class RowHeightCacheTests: XCTestCase {
    func testMeasuredHeightGrowsWithMoreText() {
        let short = NSAttributedString(string: "one line")
        let long = NSAttributedString(string: String(repeating: "wrap this text many times ", count: 50))
        let hShort = measuredTextHeight(short, width: 200)
        let hLong = measuredTextHeight(long, width: 200)
        XCTAssertGreaterThan(hLong, hShort)
    }

    func testCacheReturnsStoredValueUntilVersionOrWidthChanges() {
        let cache = RowHeightCache()
        var computeCount = 0
        let compute: () -> CGFloat = { computeCount += 1; return 42 }

        _ = cache.height(rowId: "r1", version: 1, width: 300, compute: compute)
        _ = cache.height(rowId: "r1", version: 1, width: 300, compute: compute)
        XCTAssertEqual(computeCount, 1, "同键应命中缓存")

        _ = cache.height(rowId: "r1", version: 2, width: 300, compute: compute) // version 变
        _ = cache.height(rowId: "r1", version: 2, width: 320, compute: compute) // width 变
        XCTAssertEqual(computeCount, 3)
    }

    func testInvalidateForcesRecompute() {
        let cache = RowHeightCache()
        var n = 0
        _ = cache.height(rowId: "r", version: 1, width: 10) { n += 1; return 1 }
        cache.invalidate(rowId: "r")
        _ = cache.height(rowId: "r", version: 1, width: 10) { n += 1; return 1 }
        XCTAssertEqual(n, 2)
    }
}
```

- [ ] **Step 2: 运行确认失败**

Run: `swift test --filter RowHeightCacheTests`
Expected: 编译失败。

- [ ] **Step 3: 实现**

`Sources/AgentDeck/RowHeightCache.swift`：
```swift
import AppKit

/// 在受限宽度下测量 attributed string 的排版高度（高度无限）。
func measuredTextHeight(_ attributed: NSAttributedString, width: CGFloat) -> CGFloat {
    let textStorage = NSTextStorage(attributedString: attributed)
    let container = NSTextContainer(size: NSSize(width: max(width, 1), height: .greatestFiniteMagnitude))
    container.lineFragmentPadding = 0
    let layoutManager = NSLayoutManager()
    layoutManager.addTextContainer(container)
    textStorage.addLayoutManager(layoutManager)
    layoutManager.ensureLayout(for: container)
    return ceil(layoutManager.usedRect(for: container).height)
}

/// 行高缓存：键 = rowId × version × width。版本或宽度变化即未命中。
final class RowHeightCache {
    private struct Key: Hashable { let rowId: String; let version: Int; let width: CGFloat }
    private var store: [Key: CGFloat] = [:]

    func height(rowId: String, version: Int, width: CGFloat, compute: () -> CGFloat) -> CGFloat {
        let key = Key(rowId: rowId, version: version, width: width)
        if let cached = store[key] { return cached }
        let value = compute()
        store[key] = value
        return value
    }

    func invalidate(rowId: String) {
        store = store.filter { $0.key.rowId != rowId }
    }

    func invalidateAll() {
        store.removeAll()
    }
}
```

- [ ] **Step 4: 运行确认通过**

Run: `swift test --filter RowHeightCacheTests`
Expected: PASS（3 个）。

- [ ] **Step 5: 提交**
```bash
git add Sources/AgentDeck/RowHeightCache.swift Tests/AgentDeckTests/RowHeightCacheTests.swift
git commit -m "feat(ui): text height measurement + row height cache"
```

---

### Task 6: 复用 AppKit 流式文本视图内核（解耦自 NSViewRepresentable）

把 `StreamingTextView.swift` 里已是 AppKit 的 NSView/NSTextView 内核暴露为可被 AppKit 直接使用的视图，**不删除现有 NSViewRepresentable 包装**（SessionView 仍用），保持 build 绿。

**Files:**
- Modify: `Sources/AgentDeck/StreamingTextView.swift`（仅新增/暴露 NSView 内核入口，不动 SwiftUI 包装）
- Create: `Tests/AgentDeckTests/StreamingTextCoreTests.swift`

**Interfaces:**
- 现有：`StreamingTextContainerView`(NSView)、`CoordinatedStreamingTextView`(NSTextView)、`StreamingTextBuffer`、`StreamingTextStorageSynchronizer`（见 `StreamingTextView.swift`）。
- Produces：确保可在不经 SwiftUI 的情况下构造一个绑定 `StreamingTextBuffer` 的 `StreamingTextContainerView`，并支持「重绑到另一个 buffer」（复用关键）：新增 `func bind(to buffer: StreamingTextBuffer, font: NSFont, color: NSColor)` 与 `func unbind()`（若现有内核已具备，则补一个公开入口并测试）。
- Consumes：`StreamingTextBuffer`。

- [ ] **Step 1: 写失败/特征测试（构造内核 + 重绑后显示新内容）**

`Tests/AgentDeckTests/StreamingTextCoreTests.swift`：
```swift
import XCTest
import AppKit
@testable import AgentDeck

@MainActor
final class StreamingTextCoreTests: XCTestCase {
    func testBindShowsBufferTextAndRebindSwitchesContent() {
        let bufferA = StreamingTextBuffer()
        bufferA.replace(with: "alpha")            // 按真实 API 调整（append/replace）
        let bufferB = StreamingTextBuffer()
        bufferB.replace(with: "beta")

        let view = StreamingTextContainerView(frame: .zero)
        view.bind(to: bufferA, font: .monospacedSystemFont(ofSize: 12, weight: .regular), color: .labelColor)
        XCTAssertEqual(view.currentText, "alpha")  // 暴露只读 currentText 供测试

        view.bind(to: bufferB, font: .monospacedSystemFont(ofSize: 12, weight: .regular), color: .labelColor)
        XCTAssertEqual(view.currentText, "beta", "重绑后应显示新 buffer 内容（复用关键）")

        bufferB.append("!")
        XCTAssertEqual(view.currentText, "beta!", "绑定后应随 buffer 追加更新")
    }
}
```

- [ ] **Step 2: 运行确认失败**

Run: `swift test --filter StreamingTextCoreTests`
Expected: 失败（缺 `bind/unbind/currentText` 或行为不符）。

- [ ] **Step 3: 在内核上实现 bind/unbind/currentText**

读 `StreamingTextView.swift` 现有内核，给 `StreamingTextContainerView` 加：
- `private var observerToken` 记录当前 buffer 订阅；`bind(to:font:color:)`：先 `unbind()`，设置字体/颜色，用 buffer 当前内容初始化 NSTextStorage，再订阅 buffer 的 append/replace 回调（沿用既有 `StreamingTextStorageSynchronizer` 机制）。
- `unbind()`：注销订阅。
- `var currentText: String { textView.string }`（测试只读入口）。
保持 NSViewRepresentable 包装路径不受影响（它内部可改为调用 `bind`，但不改其对外 SwiftUI 行为）。

- [ ] **Step 4: 运行确认通过 + 全量 build**

Run: `swift test --filter StreamingTextCoreTests`
Expected: PASS。
Run: `swift build`
Expected: 通过（SwiftUI 应用仍编译）。

- [ ] **Step 5: 提交**
```bash
git add Sources/AgentDeck/StreamingTextView.swift Tests/AgentDeckTests/StreamingTextCoreTests.swift
git commit -m "feat(ui): expose rebindable AppKit streaming text core"
```

---

### Task 7: 会话行视图 + ConversationRowFactory（按 kind 分发，像素级对照现有）

为每种 `DisplayRow` 造 AppKit cell 视图，并提供工厂。**视觉事实源 = 现有 `SessionView.swift` 对应分支**，按 file:line 复现。与 SwiftUI 并存，build 绿。

**Files:**
- Create: `Sources/AgentDeck/ConversationRowViews.swift`（各 `NSTableCellView` 子类）
- Create: `Sources/AgentDeck/ConversationRowFactory.swift`
- Create: `Tests/AgentDeckTests/ConversationRowFactoryTests.swift`

**Interfaces:**
- Consumes：`ConversationDisplayRow`（Task 3）、`MarkdownAttributedStringBuilder`（Task 2）、`StreamingTextContainerView.bind`（Task 6）、`ToolPresentation`（既有）、`measuredTextHeight`（Task 5）。
- Produces：
  - 各 cell：`UserPromptCellView`、`MessageCellView`、`ReasoningCellView`、`ShellCellView`、`FileEditCellView`、`WebSearchCellView`、`PlanCellView`、`HookPromptCellView`、`ToolCallCellView`、`CollabAgentCellView`、`MediaCellView`、`ReviewModeCellView`、`ContextCompactionCellView`、`ErrorCellView`、`WarningCellView`、`RawCellView`，均 `NSTableCellView` 子类，含 `func configure(row: ConversationDisplayRow, width: CGFloat, model: SessionModel)`。
  - `enum ConversationRowFactory { static func reuseIdentifier(for row: ConversationDisplayRow) -> NSUserInterfaceItemIdentifier; static func makeCell(for row: ConversationDisplayRow) -> NSTableCellView; static func height(for row: ConversationDisplayRow, width: CGFloat) -> CGFloat }`

视觉对照表（实现者逐条读源复现）：

| kind | 现有源（SessionView.swift） | AppKit cell 复现要点 |
|---|---|---|
| user | `UserPromptBlock`(MessageRoleViews.swift) + `StaticRichMessageView` | 用户气泡：markdown via Task2，左对齐留白同现状 |
| message | `assistantItemRow` "message" + RichMessageView | 流式 markdown：`StreamingTextBuffer`→builder→NSTextView |
| reasoning | `ReasoningRow`(line 977) | 默认折叠、运行中自动展开；disclosure + 等宽流式 |
| shell | "shell" case (line 566) | header 命令 + 退出码着色 + disclosure 输出（延迟物化） |
| fileEdit | "fileEdit" (line 611) | 路径 header + disclosure diff |
| webSearch | "webSearch" (line 661) | `ToolPresentation.webSearchTitle` + metadata 行 |
| plan/hookPrompt/toolCall/collabAgent/media/reviewMode/contextCompaction | lines 692–728, 865 | 逐一对照；media 用 `NSImageView` |
| error/warning | `errorRow`(893)/`warningRow`(903) | 文案 + 颜色同现状 |
| approval | `approvalRow`(915) | 唯一卡片（`NSBox`）+ Approve/Deny |

- [ ] **Step 1: 写失败测试（工厂 reuse id 与 height 单调）**

`Tests/AgentDeckTests/ConversationRowFactoryTests.swift`：
```swift
import XCTest
import AppKit
@testable import AgentDeck

@MainActor
final class ConversationRowFactoryTests: XCTestCase {
    func testReuseIdentifierDiffersByRole() {
        let rows = ConversationDisplayRowTestSupport.oneOfEachRole()   // 测试支撑：每种 role 一行
        let ids = Set(rows.map { ConversationRowFactory.reuseIdentifier(for: $0).rawValue })
        XCTAssertEqual(ids.count, rows.count, "不同 role 的 reuse id 应不同")
    }

    func testMakeCellMatchesIdentifierType() {
        let row = ConversationDisplayRowTestSupport.messageRow(text: "hi")
        let cell = ConversationRowFactory.makeCell(for: row)
        XCTAssertEqual(cell.identifier, ConversationRowFactory.reuseIdentifier(for: row))
    }

    func testHeightIsPositiveForMessage() {
        let row = ConversationDisplayRowTestSupport.messageRow(text: "hello world")
        XCTAssertGreaterThan(ConversationRowFactory.height(for: row, width: 400), 0)
    }
}
```

- [ ] **Step 2: 运行确认失败**

Run: `swift test --filter ConversationRowFactoryTests`
Expected: 编译失败。

- [ ] **Step 3: 实现各 cell + 工厂（含按行复现现有视觉）**

按上表逐一实现 cell 视图（Auto Layout 约束 + 既有语义颜色 `Color(nsColor:)` 对应的 `NSColor`），`configure` 内：message/reasoning/shell/fileEdit 用 `StreamingTextContainerView.bind` 接 `UIItem` 的 buffer；其余用 `MarkdownAttributedStringBuilder` 或纯 `NSTextField`/`NSImageView`。工厂 `height` 用 `measuredTextHeight` + 行内固定元素高度求和（disclosure 折叠态只算 header）。

- [ ] **Step 4: 运行确认通过 + build**

Run: `swift test --filter ConversationRowFactoryTests` → PASS
Run: `swift build` → 通过

- [ ] **Step 5: 提交**
```bash
git add Sources/AgentDeck/ConversationRowViews.swift Sources/AgentDeck/ConversationRowFactory.swift Tests/AgentDeckTests/ConversationRowFactoryTests.swift
git commit -m "feat(ui): AppKit conversation row views + factory"
```

---

### Task 8: ConversationViewController（虚拟化 NSTableView 装配）

把行工厂、行高缓存、流式复用、disclosure、滚动定位、输入栏、审批装进一个 controller。

**Files:**
- Create: `Sources/AgentDeck/ConversationViewController.swift`
- Create: `Sources/AgentDeck/InputBarView.swift`
- Create: `Sources/AgentDeck/ApprovalCardView.swift`

**Interfaces:**
- Consumes：`SessionModel`（状态源）、`ConversationDisplayRowBuilder`、`ConversationRowFactory`、`RowHeightCache`、`ObservationBinder`、`WorkbenchModel.submit/decidePendingAction`（经 SessionModel 暴露的提交/审批入口——实现者读 `SessionModel`）。
- Produces：`final class ConversationViewController: NSViewController`，对外 `init(model: SessionModel)`。

实现要点（无独立单测，靠 `swift build` + 后续手动验证；纯逻辑已在 Task 3/5 覆盖）：
- `NSScrollView` + `NSTableView`（单列、`headerView=nil`、`usesAutomaticRowHeights=false`）。`numberOfRows` = 当前 `rows.count`；`rows` 由 `ConversationDisplayRowBuilder.rows(from: makeConversationTurns(from: model.selectedItems))` 计算。
- `tableView(_:heightOfRow:)` → `RowHeightCache.height(rowId:version:width:)`，version 取该 item 的内容版本（用 `StreamingTextBuffer` 的变更计数或 item 的文本长度近似），width 取列宽。
- `viewFor`：`makeView(withIdentifier:)` 复用，命中则 `configure(row:width:model:)` 重绑（含流式 buffer 重绑、disclosure 态从模型读取）。
- 用 `ObservationBinder` 绑 `model.selectedItems`/`phase`/`scrollToLatestRequest` 等：变化时 diff 行集 → `reloadData` 或精细 `insertRows/reloadData(forRowIndexes:)` + `noteHeightOfRows`；`scrollToLatestRequest` 变化 → `scrollRowToVisible(lastRow)`。
- 观察 `scrollView.contentView.boundsDidChange`（`postsBoundsChangedNotifications=true`）→ 算视口顶部行 → 暴露 `topVisibleTurnId` 给 SessionViewController（驱动 rail）。
- disclosure 切换回调 → 改 `model` 展开态 → `cache.invalidate(rowId:)` + `noteHeightOfRows`。
- 选择协调：持有一个 `SessionTextSelectionCoordinator`，cell 在 `configure`/`prepareForReuse` 时注册/注销其 NSTextView。
- `InputBarView`：1–4 行自增 `NSTextView`，Enter 提交 → `model.submit(...)`，运行中显示排队计数；`ApprovalCardView`：Approve/Deny → `model` 审批入口。审批若是 `pendingActionRequest` 独立字段，则作为 table 末尾的 footer 视图或额外一行渲染（实现者按模型决定，二选一并在注释说明）。

- [ ] **Step 1: 实现三个文件（结构如上；读 SessionModel/ThreadRuntimeModel 确认提交/审批/展开态 API）**
- [ ] **Step 2: build**

Run: `swift build`
Expected: 通过。

- [ ] **Step 3: 烟测可构造（最小 XCTest 构造 controller 不崩）**

加 `Tests/AgentDeckTests/ConversationViewControllerSmokeTests.swift`：
```swift
import XCTest
@testable import AgentDeck
@MainActor
final class ConversationViewControllerSmokeTests: XCTestCase {
    func testConstructsAndLoadsView() {
        let model = SessionModel()                 // 按真实初始化器
        let vc = ConversationViewController(model: model)
        XCTAssertNotNil(vc.view)                    // 触发 loadView，不崩
    }
}
```
Run: `swift test --filter ConversationViewControllerSmokeTests` → PASS

- [ ] **Step 4: 提交**
```bash
git add Sources/AgentDeck/ConversationViewController.swift Sources/AgentDeck/InputBarView.swift Sources/AgentDeck/ApprovalCardView.swift Tests/AgentDeckTests/ConversationViewControllerSmokeTests.swift
git commit -m "feat(ui): virtualized conversation view controller with input + approval"
```

---

### Task 9: HistorySidebarViewController（NSOutlineView 源列表）

**Files:**
- Create: `Sources/AgentDeck/HistorySidebarViewController.swift`
- Create: `Sources/AgentDeck/HistoryRowViews.swift`

**Interfaces:**
- Consumes：`SessionModel`（`historyGroups`/`historySearchTerm`/`openHistoryThread`/`renameHistoryThread`/`archiveHistoryThread`/`startNewSession(inProjectCwd:)`——读 `SessionModel`/`HistoryModel` 确认）、`HistoryAgentImageCache`（既有）、`ObservationBinder`。
- Produces：`final class HistorySidebarViewController: NSViewController { init(model: SessionModel) }`。

实现要点（视觉对照 `SessionView.swift` 130–351）：
- `NSSearchField`（绑 `historySearchTerm`，编辑即过滤）+ `NSScrollView`+`NSOutlineView`（`selectionHighlightStyle=.sourceList`，view-based）。
- 数据源：顶层 = `historyGroups`（项目组，group row），子项 = 组内线程。`isItemExpandable` 仅项目组可展开。
- group row：项目名 + `+`（新建会话）；thread row（`HistoryThreadRowView`）：accent 条、agent 图标、runtime 相位点、未读点、标题/元信息（复现 `historyThreadRow` 230–296、`historyThreadRuntimeDot` 351）。
- 选中线程 → `model.openHistoryThread(...)`；右键 `NSMenu`：Rename（`NSAlert`+`NSTextField`）、Archive。
- `ObservationBinder` 绑 `historyGroups`/各 runtime 相位/未读计数 → `reloadData` 或 `reloadItem`。

- [ ] **Step 1: 实现两个文件**
- [ ] **Step 2: build + 烟测构造**

加最小 smoke test（构造 vc、触发 `view` 不崩），Run `swift build` + `swift test --filter HistorySidebar` → PASS。

- [ ] **Step 3: 提交**
```bash
git add Sources/AgentDeck/HistorySidebarViewController.swift Sources/AgentDeck/HistoryRowViews.swift Tests/AgentDeckTests/HistorySidebarSmokeTests.swift
git commit -m "feat(ui): history sidebar with NSOutlineView source list"
```

---

### Task 10: StatusBarView + TurnJumpRailView（AppKit）

**Files:**
- Create: `Sources/AgentDeck/StatusBarView.swift`
- Create: `Sources/AgentDeck/TurnJumpRailView.swift`

**Interfaces:**
- Consumes：`SessionModel`（`phase`/`statusText`/`cwd`/项目名/经过秒数/`startNewSessionFromCurrentProject`）、`TurnJumpRailLayout`（既有纯几何）、`RailInteractionNSView`（既有 AppKit，从 `SessionView.swift` 抽出到本文件或保留引用）、`ConversationRailNavigator`（既有）。
- Produces：`final class StatusBarView: NSView { init(model: SessionModel) }`；`final class TurnJumpRailView: NSView { init(model: SessionModel); var onSelectTurn: ((String) -> Void)? ; func syncSelection(topVisibleTurnId: String?) }`。

实现要点：
- StatusBar 复现 `SessionView.statusBar`：相位点（颜色按 phase）+ 状态文本 + 经过秒数 + 项目名 + New session 按钮。
- TurnJumpRail 复用 `TurnJumpRailLayout` 算点位；点与 dock 放大用 `CALayer`/`NSView.draw` + 显式 `CABasicAnimation`（替代 `withAnimation`）；交互用既有 `RailInteractionNSView`（mouseMoved/mouseDown/scrollWheel），滚轮步进经 `ConversationRailNavigator.next(...)`。

> 把 `RailInteractionNSView`/`TurnJumpRailLayout`/`TurnJumpRailHitTarget` 从 `SessionView.swift` 迁到本文件（它们是 AppKit/纯逻辑，迁移不改语义）。`TurnJumpRailLayout` 的既有测试须继续通过。

- [ ] **Step 1: 迁移 Rail 相关 AppKit/逻辑类型 + 实现两视图**
- [ ] **Step 2: build + 既有 rail 几何/导航测试仍通过**

Run: `swift build`；`swift test --filter TurnJumpRailLayout`；`swift test --filter ConversationRailNavigator` → PASS

- [ ] **Step 3: 提交**
```bash
git add Sources/AgentDeck/StatusBarView.swift Sources/AgentDeck/TurnJumpRailView.swift Sources/AgentDeck/SessionView.swift
git commit -m "feat(ui): AppKit status bar and turn-jump rail"
```

---

### Task 11: SessionViewController（NSSplitView 装配 + 空状态 + 选目录）

**Files:**
- Create: `Sources/AgentDeck/SessionViewController.swift`
- Create: `Sources/AgentDeck/EmptyStateView.swift`

**Interfaces:**
- Consumes：`SessionModel`、`StatusBarView`、`HistorySidebarViewController`、`ConversationViewController`、`TurnJumpRailView`、`NSOpenPanel`。
- Produces：`final class SessionViewController: NSViewController { init(model: SessionModel) }`。

实现要点：
- 顶层 vertical stack：`StatusBarView` + 分隔线 + `NSSplitViewController`（左 `HistorySidebarViewController` 固定 260pt、右内容）。
- 右内容：`cwd == nil` 时显示 `EmptyStateView`（复现 D5 文案 + “Choose project…” `NSOpenPanel` + Refresh）；否则 `ConversationViewController` + 叠加 `TurnJumpRailView`（trailing overlay 28pt）。
- 用 `ObservationBinder` 绑 `model.cwd` 切换空态/会话；把 `ConversationViewController.topVisibleTurnId` 变化喂给 `TurnJumpRailView.syncSelection`，`TurnJumpRailView.onSelectTurn` → 让会话滚到该 turn。

- [ ] **Step 1: 实现两文件 + smoke test 构造**
- [ ] **Step 2: build + smoke**

Run: `swift build`；`swift test --filter SessionViewControllerSmoke` → PASS

- [ ] **Step 3: 提交**
```bash
git add Sources/AgentDeck/SessionViewController.swift Sources/AgentDeck/EmptyStateView.swift Tests/AgentDeckTests/SessionViewControllerSmokeTests.swift
git commit -m "feat(ui): session view controller assembling split layout + empty state"
```

---

### Task 12: 切换入口到 AppKit + 删除 SwiftUI（cutover）

把 `main.swift` 从 SwiftUI App 切到 `NSApplication`+`AppDelegate`，接 `SessionViewController`，删除 SwiftUI 视图与 `Textual`，修 `TextualCompatibilityTests`。这一步后全仓库零 `import SwiftUI`。

**Files:**
- Modify: `Sources/AgentDeck/main.swift`（保留 profile 解析与 headless 分流，替换 App 部分）
- Create: `Sources/AgentDeck/AppDelegate.swift`
- Delete: `Sources/AgentDeck/SessionView.swift`、`Sources/AgentDeck/MessageRoleViews.swift`、`Sources/AgentDeck/RichMessageView.swift`
- Modify: `Sources/AgentDeck/StreamingTextView.swift`、`Sources/AgentDeck/SessionTextSelectionCoordinator.swift`（删除 `NSViewRepresentable` 包装，保留 NSView/NSTextView 内核）
- Modify: `Package.swift`（移除 `Textual` 依赖与 target 依赖、移除 `resources` 若不再需要保留）
- Modify/Replace: `Tests/AgentDeckTests/TextualCompatibilityTests.swift`（删除构造 SwiftUI 视图的用例；保留/迁移其中框架无关的 `ConversationTurn`/几何断言到既有测试文件，或改名为 `RichRenderingTests` 仅测 `MarkdownAttributedStringBuilder`）

**Interfaces:**
- Consumes：`SessionViewController`、`AgentDeckProfile`、`AgentDeckQuitCommand`。
- Produces：`final class AppDelegate: NSObject, NSApplicationDelegate`。

- [ ] **Step 1: 写 AppDelegate**

`Sources/AgentDeck/AppDelegate.swift`：
```swift
import AppKit

final class AppDelegate: NSObject, NSApplicationDelegate {
    private let profile: AgentDeckProfile
    private var window: NSWindow?
    private let model = SessionModel()             // 按真实初始化器

    init(profile: AgentDeckProfile) { self.profile = profile }

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        let vc = SessionViewController(model: model)
        let win = NSWindow(contentViewController: vc)
        win.title = profile.windowTitle
        win.setContentSize(NSSize(width: 1100, height: 720))
        win.styleMask.insert([.titled, .closable, .miniaturizable, .resizable])
        win.center()
        win.makeKeyAndOrderFront(nil)
        self.window = win
        NSApp.activate(ignoringOtherApps: true)
        installMainMenu()
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }

    /// 复现 Cmd-Q（AgentDeckQuitCommand）。
    private func installMainMenu() {
        let mainMenu = NSMenu()
        let appItem = NSMenuItem()
        mainMenu.addItem(appItem)
        let appMenu = NSMenu()
        appMenu.addItem(withTitle: AgentDeckQuitCommand.title,
                        action: #selector(NSApplication.terminate(_:)),
                        keyEquivalent: AgentDeckQuitCommand.shortcutKey)
        appItem.submenu = appMenu
        NSApp.mainMenu = mainMenu
    }
}
```

- [ ] **Step 2: 改 main.swift 的 App 部分为 AppKit 启动**

把 `main.swift` 末尾 `struct AgentDeckApp: App { ... }` + `AgentDeckApp.main()` 替换为（保留前面的 profile 解析与 `--selfcheck`/`--diagnostics-report` 分流不变）：
```swift
let app = NSApplication.shared
let delegate = AppDelegate(profile: launchProfile)
app.delegate = delegate
app.run()
```
并把文件顶部 `import SwiftUI` 改为 `import AppKit`。

- [ ] **Step 3: 删 SwiftUI 视图文件 + 去 NSViewRepresentable 包装**

删除 `SessionView.swift`、`MessageRoleViews.swift`、`RichMessageView.swift`。在 `StreamingTextView.swift`、`SessionTextSelectionCoordinator.swift` 中删除 `NSViewRepresentable` 类型（`StreamingTextView`、`SessionTextSelectionActivationMonitor`），保留 NSView/NSTextView/coordinator 内核（Task 6 已让内核可独立用）。

- [ ] **Step 4: 改 Package.swift 去 Textual**

把 `Package.swift` 的 `dependencies` 移除 textual；`AgentDeck` target 与 `AgentDeckTests` 的 `.product(name: "Textual", ...)` 依赖删除。`Resources` 若仍含图标资源（CodexIcon 等）则保留 `.process("Resources")`。

- [ ] **Step 5: 修测试（删 SwiftUI 构造用例）**

把 `TextualCompatibilityTests.swift` 中构造 `RichMessageView`/`UserPromptBlock`/`StaticRichMessageView`/`CodexTurnSection`/`TurnJumpRail` 的用例删除；其中对 `ConversationTurn` 分组、`TurnJumpRailLayout` 几何、`ConversationScrollSpy` 的断言——若这些类型仍存在（几何/逻辑保留），迁到一个不 import SwiftUI 的测试文件（如重命名为 `RichRenderingTests.swift`，仅保留框架无关断言 + `MarkdownAttributedStringBuilder` 已在 Task 2 覆盖）。删除任何 `import SwiftUI` 的测试代码。

- [ ] **Step 6: 验证零 SwiftUI + 全量构建测试**

Run: `grep -rn "import SwiftUI" Sources Tests || echo "no SwiftUI imports ✓"`
Expected: `no SwiftUI imports ✓`
Run: `swift build`
Expected: 通过。
Run: `swift test`
Expected: 全部通过（模型层测试零改动；新增 UI 单元测试通过；无 SwiftUI 构造测试残留）。

- [ ] **Step 7: 手动验证（dev profile 真实跑）**

Run: `swift run AgentDeck`
Expected: 弹出 AppKit 窗口（标题含 Dev）；可选目录→开始流式会话→审批→打开历史→续聊→搜索/rename/archive→rail 导航；逐项对照现有功能。
Run: `swift run AgentDeck -- --selfcheck`
Expected: headless 自检仍通过。

- [ ] **Step 8: 提交**
```bash
git add -A
git commit -m "feat(ui): cut over entry point to AppKit, remove SwiftUI and Textual"
```

---

### Task 13: 文档与收口

**Files:**
- Modify: `ARCHITECTURE.md`、`README.md`、`docs/QUALITY.md`

**Interfaces:** 无代码接口。

- [ ] **Step 1: 更新 ARCHITECTURE.md**

把「总体结构」里 `AgentDeck.app (macOS, SwiftUI + AppKit)` 改为纯 AppKit；说明：前端为 AppKit（NSViewController 树）、markdown 用原生 `NSAttributedString`（移除 Textual）、会话流虚拟化 NSTableView、历史侧栏 NSOutlineView、模型层经 `ObservationBinder` 消费 `@Observable`；分层边界与不变量（中立 `AgentItem`、A1）不变。

- [ ] **Step 2: 更新 README.md**

更新涉及 SwiftUI / Textual 的描述；构建运行命令（`swift run AgentDeck`）保持，注明前端已为 AppKit。

- [ ] **Step 3: 更新 docs/QUALITY.md**

补 AppKit 重写后的验证：`swift build`/`swift test`（含 markdown builder、display-row、observation binder、行高缓存、契约一致性测试）、`grep -rn "import SwiftUI"` 应为空、`swift run AgentDeck` 手动核验清单、headless 自检。

- [ ] **Step 4: 文档结构检查 + 全量验证**

Run: `bash scripts/verify-agent-docs.sh` → `verify-agent-docs: ok`
Run: `swift test` → 通过
Run: `cargo test` → 通过（确认后端/契约未被牵动）

- [ ] **Step 5: 提交**
```bash
git add ARCHITECTURE.md README.md docs/QUALITY.md
git commit -m "docs: document AppKit frontend rewrite and verification"
```

---

## Self-Review

**Spec 覆盖核对（对照 design 各节）：**
- 入口切换 SwiftUI→AppKit → Task 12。
- 移除 SwiftUI + Textual / 原生 markdown → Task 2（builder）+ Task 12（删依赖/视图）。
- 功能/视觉对等（各 item-kind 行、历史侧栏、状态栏、空状态、rename、media、审批、rail）→ Task 7/8/9/10/11，按 file:line 对照现有源。
- 会话流虚拟化 NSTableView（行模型/行高缓存/复用重绑/disclosure/滚动定位）→ Task 3/5/6/7/8。
- 历史侧栏 NSOutlineView → Task 9。
- Observation 绑定 → Task 4，各 controller 消费。
- Swift↔契约一致性测试 → Task 1。
- 模型层零改动 → Global Constraints + 各任务仅“读模型”。
- 测试策略（模型测试存活、替换 TextualCompatibilityTests、新增纯单元、手动 swift run、headless 保留）→ Task 1/2/3/4/5/6/7 单测 + Task 12 替换测试 + Task 12/13 手动与全量验证。
- 文档更新 → Task 13。
- 非目标（不改后端/协议、不重设计、不打包、不引新依赖、零 SwiftUI）→ 全程遵守。

**占位符扫描：** 纯逻辑任务（1–6）含完整 TDD 代码；视图任务（7–11）给结构骨架 + 完整非平凡逻辑 + 按 file:line 指向现有 SwiftUI 源作为视觉事实源（像素值不臆造，由实现者读源复现）——这是「对等复现」型重写的精确做法，非占位。少数字段名（`UIItem`/`ConversationTurn` 的 `userItem`/`assistantItems`/`kind`/`id`、`SessionModel` 的提交/审批/展开态 API）标注为「实现者读真实定义后调整」，因这些是既有未改动类型、其确切签名以源码为准——已明确指向源文件，非含糊占位。

**类型一致性核对：** `MarkdownAttributedStringBuilder.attributedString(from:style:)`、`ConversationDisplayRow`/`ConversationDisplayRowBuilder.rows(from:)`、`ObservationBinder.bind/invalidate`、`measuredTextHeight`/`RowHeightCache.height(rowId:version:width:compute:)`、`StreamingTextContainerView.bind(to:font:color:)/currentText`、`ConversationRowFactory.{reuseIdentifier,makeCell,height}`、各 `ViewController.init(model:)`、`AppDelegate(profile:)` 在定义与使用处签名一致。每个任务边界 `swift build` 可过：纯单元（1–6）与 AppKit 组件（7–11）与现有 SwiftUI 并存编译，Task 12 才 cutover 删除——无悬空引用。
