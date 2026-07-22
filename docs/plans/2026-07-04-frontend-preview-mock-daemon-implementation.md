# 前端预览测试台（mock daemon）实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 增加 `swift run AgentDeck -- --preview` 模式，用进程内 mock daemon 驱动完全真实的前端，内容复刻设计稿图1，专供前端对齐与调试。

**Architecture:** 唯一后端替换点是注入 `DaemonClient(transport:)` 的 `MockDaemonTransport`（进程内实现 `DaemonTransport`，收前端真实 IPC 请求、异步回吐脚本化 `{"reply":...}` 与 `ServerEvent` 帧）。前端从 `SessionModel → DaemonClient → IPC 编解码 → 路由 → 渲染` 全真实。环境面板重构为图1 只读 Changes/Git 布局 + 数据驱动，preview 在引导层注入 mock 值（面板不走 IPC，因其暂无 daemon 后端）。

**Tech Stack:** Swift 5.9 / AppKit / SwiftPM；`XCTest`；协议类型来自 `AgentDeckCore`（`ClientCommand`/`ServerEvent`/`HistoryResponse`/`AgentItem` 均 `Codable`）。

## Global Constraints

- 永远用中文回答用户；项目文档用中文。
- JS/TS 用 `bun`，Python 用 `uv`（本任务不涉及）。
- 不改 daemon（Rust）、不改 IPC v2 协议类型、不改 history 数据结构（守 N1–N8）。
- UI 渲染层禁止出现 `if preview` 分支；mock 全部收敛在 `Sources/AgentDeck/Preview/` + 注入点。
- 非 preview 启动行为必须完全不变。
- 提交 commit 不加 co-author / Codex 合作者信息。
- 验证入口：涉及 Swift UI/会话模型/历史回放时至少跑 `swift test`。

---

### Task 1: `EnvironmentInfo` 数据模型 + `SessionModel.environmentInfo`

**Files:**
- Create: `Sources/AgentDeck/EnvironmentInfo.swift`
- Modify: `Sources/AgentDeck/SessionModel.swift`（在属性区新增字段，约 `:88` 附近）
- Test: `Tests/AgentDeckTests/EnvironmentInfoTests.swift`

**Interfaces:**
- Produces:
  - `struct EnvironmentInfo: Equatable { let added: Int; let removed: Int; let fileCount: Int; let branch: String?; let commit: String?; var changesSummary: String; var fileCountSummary: String }`
  - `SessionModel.environmentInfo: EnvironmentInfo?`（`@Observable` 存储属性，默认 `nil`）

- [ ] **Step 1: 写失败测试**

`Tests/AgentDeckTests/EnvironmentInfoTests.swift`：
```swift
import XCTest
@testable import AgentDeck

final class EnvironmentInfoTests: XCTestCase {
    func testChangesSummaryFormatsSignedCounts() {
        let info = EnvironmentInfo(added: 128, removed: 34, fileCount: 3, branch: "main", commit: "a1b2c3d")
        XCTAssertEqual(info.changesSummary, "+128 -34")
        XCTAssertEqual(info.fileCountSummary, "3 文件")
    }

    func testZeroChangesStillSigned() {
        let info = EnvironmentInfo(added: 0, removed: 0, fileCount: 0, branch: nil, commit: nil)
        XCTAssertEqual(info.changesSummary, "+0 -0")
        XCTAssertEqual(info.fileCountSummary, "0 文件")
    }
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `swift test --filter EnvironmentInfoTests`
Expected: FAIL —— `cannot find 'EnvironmentInfo' in scope`。

- [ ] **Step 3: 实现 `EnvironmentInfo`**

`Sources/AgentDeck/EnvironmentInfo.swift`：
```swift
import Foundation

/// 右上环境面板的只读数据模型（macOS UI chrome，不进 AgentDeckCore 共享层）。
/// 真实 app 暂无 daemon 后端提供它（见 2026-07-01-codex-desktop-chrome-sync.md），
/// 默认 nil 时面板不显示且不占位；preview 在引导层注入 mock 值。
struct EnvironmentInfo: Equatable {
    let added: Int
    let removed: Int
    let fileCount: Int
    let branch: String?
    let commit: String?

    var changesSummary: String { "+\(added) -\(removed)" }
    var fileCountSummary: String { "\(fileCount) 文件" }
}
```

- [ ] **Step 4: 给 `SessionModel` 加字段**

在 `Sources/AgentDeck/SessionModel.swift` 的可观察属性区（`historySearchTerm` 一带，约 `:88`）新增：
```swift
    /// 右上环境面板数据源。真实 app 默认 nil（面板不显示且不占位）；
    /// preview 引导层注入 mock 值。不经 IPC——面板暂无 daemon 后端。
    var environmentInfo: EnvironmentInfo?
```

- [ ] **Step 5: 跑测试确认通过**

Run: `swift test --filter EnvironmentInfoTests`
Expected: PASS（2 个测试）。

- [ ] **Step 6: 提交**

```bash
git add Sources/AgentDeck/EnvironmentInfo.swift Sources/AgentDeck/SessionModel.swift Tests/AgentDeckTests/EnvironmentInfoTests.swift
git commit -m "feat(macos): EnvironmentInfo 数据模型 + SessionModel.environmentInfo 字段"
```

---

### Task 2: 重构 `CodexEnvironmentPanelView` 为图1 只读 Changes/Git 布局 + 数据驱动

**Files:**
- Modify: `Sources/AgentDeck/CodexDesktopChrome.swift:164-262`（整体重写 `CodexEnvironmentPanelView`）
- Modify: `Sources/AgentDeck/ConversationViewController.swift:78`（`environmentPanel` 改为 `init(model:)`）
- Test: `Tests/AgentDeckTests/EnvironmentPanelSmokeTests.swift`

**Interfaces:**
- Consumes: `SessionModel.environmentInfo`（Task 1）、`EnvironmentInfo.changesSummary/fileCountSummary`（Task 1）
- Produces: `CodexEnvironmentPanelView(model: SessionModel)`（替换原 `init(frame:)`）；面板随 `model.environmentInfo` 变化刷新。

- [ ] **Step 1: 写失败测试（smoke + 数据驱动）**

`Tests/AgentDeckTests/EnvironmentPanelSmokeTests.swift`：
```swift
import XCTest
import AppKit
@testable import AgentDeck

@MainActor
final class EnvironmentPanelSmokeTests: XCTestCase {
    func testConstructsWithModelAndRendersChanges() {
        let model = SessionModel(turnStarter: NoopRuntimeTurnStarter())
        model.environmentInfo = EnvironmentInfo(added: 128, removed: 34, fileCount: 3, branch: "main", commit: "a1b2c3d")
        let panel = CodexEnvironmentPanelView(model: model)
        panel.layoutSubtreeIfNeeded()
        // 面板把 changesSummary 暴露给测试断言（accessibilityIdentifier 承载）。
        let labels = panel.allLabelsForTest()
        XCTAssertTrue(labels.contains("+128 -34"), "应渲染带符号的变更统计")
        XCTAssertTrue(labels.contains("main"), "应渲染分支名")
        XCTAssertTrue(labels.contains("a1b2c3d"), "应渲染提交短哈希")
    }
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `swift test --filter EnvironmentPanelSmokeTests`
Expected: FAIL —— `CodexEnvironmentPanelView` 无 `init(model:)` / 无 `allLabelsForTest`。

- [ ] **Step 3: 重写 `CodexEnvironmentPanelView`**

替换 `Sources/AgentDeck/CodexDesktopChrome.swift:164-262` 整个类为：
```swift
@MainActor
final class CodexEnvironmentPanelView: NSView {
    private weak var model: SessionModel?
    private let binder = ObservationBinder()

    private let changesValue = NSTextField(labelWithString: "")
    private let fileCountValue = NSTextField(labelWithString: "")
    private let branchValue = NSTextField(labelWithString: "")
    private let commitValue = NSTextField(labelWithString: "")

    init(model: SessionModel) {
        self.model = model
        super.init(frame: .zero)
        build()
        bind()
        refresh()
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) not supported") }

    private func build() {
        translatesAutoresizingMaskIntoConstraints = false
        CodexDesktopChrome.roundedPanel(self, radius: DesignTokens.radiusLg, shadow: true)

        // 标题：变更 Changes
        let title = label("变更 Changes", size: 13, weight: .medium, color: DesignTokens.text2)

        // 大号统计：+128 -34   3 文件
        changesValue.font = .systemFont(ofSize: 22, weight: .semibold)
        changesValue.textColor = DesignTokens.text
        fileCountValue.font = .systemFont(ofSize: 12, weight: .regular)
        fileCountValue.textColor = DesignTokens.text3
        let changesRow = row([changesValue, fileCountValue, spacer()], spacing: 10)

        // 分组标题：Git
        let gitTitle = label("Git", size: 13, weight: .medium, color: DesignTokens.text2)

        // 键值：分支 …… main / 提交 …… a1b2c3d（值右对齐）
        let branchRow = keyValueRow("分支", value: branchValue)
        let commitRow = keyValueRow("提交", value: commitValue)

        let stack = NSStackView(views: [title, changesRow, gitTitle, branchRow, commitRow])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 12
        stack.translatesAutoresizingMaskIntoConstraints = false
        addSubview(stack)

        NSLayoutConstraint.activate([
            widthAnchor.constraint(equalToConstant: 260),
            stack.topAnchor.constraint(equalTo: topAnchor, constant: 16),
            stack.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 16),
            stack.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -16),
            stack.bottomAnchor.constraint(lessThanOrEqualTo: bottomAnchor, constant: -16),
        ])
    }

    private func bind() {
        binder.bind({ [weak self] in
            _ = self?.model?.environmentInfo
        }, onChange: { [weak self] in
            self?.refresh()
        })
    }

    private func refresh() {
        let info = model?.environmentInfo
        changesValue.stringValue = info?.changesSummary ?? "+0 -0"
        fileCountValue.stringValue = info?.fileCountSummary ?? "0 文件"
        branchValue.stringValue = info?.branch ?? "—"
        commitValue.stringValue = info?.commit ?? "—"
    }

    private func keyValueRow(_ key: String, value: NSTextField) -> NSView {
        let k = label(key, size: 13, weight: .regular, color: DesignTokens.text2)
        value.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
        value.textColor = DesignTokens.text
        value.alignment = .right
        return row([k, spacer(), value], spacing: 10)
    }

    private func label(_ s: String, size: CGFloat, weight: NSFont.Weight, color: NSColor) -> NSTextField {
        let l = NSTextField(labelWithString: s)
        l.font = .systemFont(ofSize: size, weight: weight)
        l.textColor = color
        l.translatesAutoresizingMaskIntoConstraints = false
        return l
    }

    private func row(_ views: [NSView], spacing: CGFloat) -> NSStackView {
        let stack = NSStackView(views: views)
        stack.orientation = .horizontal
        stack.alignment = .firstBaseline
        stack.spacing = spacing
        stack.translatesAutoresizingMaskIntoConstraints = false
        stack.widthAnchor.constraint(equalToConstant: 228).isActive = true
        return stack
    }

    private func spacer() -> NSView {
        let v = NSView()
        v.translatesAutoresizingMaskIntoConstraints = false
        v.setContentHuggingPriority(.defaultLow, for: .horizontal)
        return v
    }

    /// 测试辅助：收集所有子 label 文本。
    func allLabelsForTest() -> [String] {
        func collect(_ v: NSView) -> [String] {
            var out: [String] = []
            if let tf = v as? NSTextField { out.append(tf.stringValue) }
            for sub in v.subviews { out += collect(sub) }
            return out
        }
        return collect(self)
    }

    deinit {
        let b = binder
        Task { @MainActor in b.invalidate() }
    }
}
```

- [ ] **Step 4: 更新 `ConversationViewController` 的面板构造**

`Sources/AgentDeck/ConversationViewController.swift:78`，把
```swift
    private let environmentPanel = CodexEnvironmentPanelView()
```
改为
```swift
    private lazy var environmentPanel = CodexEnvironmentPanelView(model: model)
```
（`model` 是该控制器已有的存储属性；`lazy` 保证在 `model` 就绪后构造。）

- [ ] **Step 5: 跑测试确认通过 + 无回归**

Run: `swift test --filter EnvironmentPanelSmokeTests`
Expected: PASS。
Run: `swift test`
Expected: 全绿（含既有 `CodexDesktopChromeTests`；若其断言旧「环境信息」标题，需同步更新为「变更 Changes」）。

- [ ] **Step 6: 提交**

```bash
git add Sources/AgentDeck/CodexDesktopChrome.swift Sources/AgentDeck/ConversationViewController.swift Tests/AgentDeckTests/EnvironmentPanelSmokeTests.swift
git commit -m "feat(macos): 环境面板重构为图1 只读 Changes/Git 布局 + 数据驱动"
```

---

### Task 3: `MockDaemonScript` mock 数据源

**Files:**
- Create: `Sources/AgentDeck/Preview/MockDaemonScript.swift`
- Test: `Tests/AgentDeckTests/MockDaemonScriptTests.swift`

**Interfaces:**
- Consumes: `EnvironmentInfo`（Task 1）、`AgentDeckCore` 协议类型（`HistoryListItem`/`HistoryReadResponse`/`HistoryTurn`/`AgentItem`/`AgentItemMeta`/`DiffFile`/`ServerEvent`/`TurnSummary`）
- Produces:
  - `enum MockDaemonScript`
  - `static let previewCwd: String`
  - `static func historyList() -> [HistoryListItem]`
  - `static func readResponse(threadId: String) -> HistoryReadResponse`
  - `static func liveTurnEvents(sessionId: String, threadId: String) -> [ServerEvent]`
  - `static let environmentInfo: EnvironmentInfo`
  - `static let primaryThreadId: String`

- [ ] **Step 1: 写失败测试**

`Tests/AgentDeckTests/MockDaemonScriptTests.swift`：
```swift
import XCTest
import AgentDeckCore
@testable import AgentDeck

final class MockDaemonScriptTests: XCTestCase {
    func testHistoryListContainsPrimaryThread() {
        let list = MockDaemonScript.historyList()
        XCTAssertFalse(list.isEmpty)
        XCTAssertTrue(list.contains { $0.threadId == MockDaemonScript.primaryThreadId })
        XCTAssertTrue(list.contains { ($0.title ?? "").contains("把登录模块拆分为独立 service") })
    }

    func testReadResponseHasShellAndDiffItems() {
        let resp = MockDaemonScript.readResponse(threadId: MockDaemonScript.primaryThreadId)
        let items = resp.turns.flatMap { $0.items }
        XCTAssertTrue(items.contains { if case .shell = $0 { return true } else { return false } })
        XCTAssertTrue(items.contains { if case .diff = $0 { return true } else { return false } })
    }

    func testLiveTurnStartsAndCompletes() {
        let events = MockDaemonScript.liveTurnEvents(sessionId: "s1", threadId: "t1")
        guard case .sessionStarted = events.first else { return XCTFail("首帧应为 sessionStarted") }
        guard case .turnComplete = events.last else { return XCTFail("末帧应为 turnComplete") }
    }

    func testEnvironmentInfoMatchesDesign() {
        XCTAssertEqual(MockDaemonScript.environmentInfo.changesSummary, "+128 -34")
        XCTAssertEqual(MockDaemonScript.environmentInfo.fileCount, 3)
        XCTAssertEqual(MockDaemonScript.environmentInfo.branch, "main")
    }
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `swift test --filter MockDaemonScriptTests`
Expected: FAIL —— `cannot find 'MockDaemonScript' in scope`。

- [ ] **Step 3: 实现 `MockDaemonScript`**

`Sources/AgentDeck/Preview/MockDaemonScript.swift`：
```swift
import Foundation
import AgentDeckCore

/// preview 模式的 mock 数据源，复刻设计稿图1。仅被 preview 路径引用。
enum MockDaemonScript {
    static let previewCwd = "/Users/preview/glm/AgentDeck"
    static let primaryThreadId = "mock-thread-split-auth"
    static let environmentInfo = EnvironmentInfo(
        added: 128, removed: 34, fileCount: 3, branch: "main", commit: "a1b2c3d"
    )

    private static func meta() -> AgentItemMeta { AgentItemMeta() }

    static func historyList() -> [HistoryListItem] {
        let now: UInt64 = 1_720_000_000_000
        func item(_ id: String, _ title: String, _ cwd: String, _ ageMs: UInt64) -> HistoryListItem {
            HistoryListItem(threadId: id, agentKind: .codex, title: title, cwd: cwd,
                            lastActiveMs: now - ageMs, archived: false)
        }
        let refactor = previewCwd
        let docs = "/Users/preview/glm/agentdeck-docs"
        return [
            item(primaryThreadId, "把登录模块拆分为独立 service", refactor, 0),
            item("mock-thread-token-race", "修复 token 刷新竞态", refactor, 60_000),
            item("mock-thread-deploy-doc", "补充部署章节", docs, 120_000),
        ]
    }

    static func readResponse(threadId: String) -> HistoryReadResponse {
        HistoryReadResponse(threadId: threadId, agentKind: .codex, turns: [
            HistoryTurn(items: [
                .userMessage(text: "把登录模块拆分成独立的 auth service，抽出 token 刷新逻辑，并补齐单元测试。", meta: meta()),
                .reasoning(text: "先梳理 auth 目录下的依赖关系，确认哪些函数被外部引用，再决定拆分边界。", meta: meta()),
                .shell(command: "rg \"login\" src/ -l",
                       status: .completed, exitCode: 0, durationMs: 40, meta: meta()),
                .diff(files: [DiffFile(path: "auth/service.ts", status: .modified,
                                       patch: "@@ +64 -12 @@\n+ export class AuthService {}\n")],
                      meta: meta()),
                .assistantMessage(text: "正在运行测试 npm test -- auth …", meta: meta()),
            ]),
        ])
    }

    static func liveTurnEvents(sessionId: String, threadId: String) -> [ServerEvent] {
        [
            .sessionStarted(sessionId: sessionId, threadId: threadId, agentKind: .codex),
            .agentItem(sessionId: sessionId, threadId: threadId, agentKind: .codex,
                       item: .reasoning(text: "收到，我先跑一遍现有测试确认基线。", meta: meta())),
            .agentItem(sessionId: sessionId, threadId: threadId, agentKind: .codex,
                       item: .shell(command: "npm test -- auth", status: .completed, exitCode: 0, durationMs: 1200, meta: meta())),
            .agentItem(sessionId: sessionId, threadId: threadId, agentKind: .codex,
                       item: .assistantMessage(text: "测试通过，auth service 已拆分完成。", meta: meta())),
            .turnComplete(sessionId: sessionId, threadId: threadId, agentKind: .codex,
                          summary: TurnSummary(elapsedMs: 1500)),
        ]
    }
}
```

- [ ] **Step 4: 跑测试确认通过**

Run: `swift test --filter MockDaemonScriptTests`
Expected: PASS（4 个测试）。

- [ ] **Step 5: 提交**

```bash
git add Sources/AgentDeck/Preview/MockDaemonScript.swift Tests/AgentDeckTests/MockDaemonScriptTests.swift
git commit -m "feat(macos): preview mock 数据源 MockDaemonScript（复刻图1）"
```

---

### Task 4: `MockDaemonTransport` 进程内传输实现

**Files:**
- Create: `Sources/AgentDeck/Preview/MockDaemonTransport.swift`
- Test: `Tests/AgentDeckTests/MockDaemonTransportTests.swift`

**Interfaces:**
- Consumes: `DaemonTransport`（`Sources/AgentDeck/DaemonTransport.swift`）、`MockDaemonScript`（Task 3）、`ClientCommand`/`ServerEvent`/`HistoryResponse`（AgentDeckCore）
- Produces: `final class MockDaemonTransport: DaemonTransport`，`init()`。收 `ClientCommand` 行、异步回帧。

- [ ] **Step 1: 写失败测试**

`Tests/AgentDeckTests/MockDaemonTransportTests.swift`：
```swift
import XCTest
import AgentDeckCore
@testable import AgentDeck

final class MockDaemonTransportTests: XCTestCase {
    private func lines(from transport: MockDaemonTransport, after send: ClientCommand, count: Int, timeout: TimeInterval = 2) -> [String] {
        var received: [String] = []
        let exp = expectation(description: "frames")
        transport.setIncomingHandler { line in
            received.append(line)
            if received.count >= count { exp.fulfill() }
        }
        try? transport.start()
        let data = try! JSONEncoder().encode(send)
        try? transport.send(String(data: data, encoding: .utf8)!)
        wait(for: [exp], timeout: timeout)
        return received
    }

    func testHistoryListReplyDecodes() {
        let t = MockDaemonTransport()
        let frames = lines(from: t, after: .history(.list(agentKind: nil, cwdFilter: nil, limit: nil)), count: 1)
        XCTAssertEqual(frames.count, 1)
        let obj = try! JSONSerialization.jsonObject(with: Data(frames[0].utf8)) as! [String: Any]
        XCTAssertEqual(obj["reply"] as? String, "history")
        let responseData = try! JSONSerialization.data(withJSONObject: obj["response"]!)
        let resp = try! JSONDecoder().decode(HistoryResponse.self, from: responseData)
        guard case .list(let items) = resp else { return XCTFail("应为 list") }
        XCTAssertFalse(items.isEmpty)
    }

    func testSessionStartEmitsStartedThenComplete() {
        let t = MockDaemonTransport()
        let start = SessionStart(agentKind: .codex, cwd: MockDaemonScript.previewCwd, prompt: "hi",
                                 vendorOptions: .codex(CodexSessionOptions(approvalPolicy: .onRequest, sandbox: .workspaceWrite, persistApproval: false, reasoningEffort: .medium)))
        let frames = lines(from: t, after: .sessionStart(start), count: 5, timeout: 4)
        let events = frames.compactMap { try? DaemonClient.decodeServerEvent($0) }
        guard case .sessionStarted = events.first else { return XCTFail("首帧 sessionStarted") }
        guard case .turnComplete = events.last else { return XCTFail("末帧 turnComplete") }
    }

    func testUnknownLineEmitsError() {
        let t = MockDaemonTransport()
        var received: [String] = []
        let exp = expectation(description: "err")
        t.setIncomingHandler { line in received.append(line); exp.fulfill() }
        try? t.start()
        try? t.send("{\"garbage\":true}")
        wait(for: [exp], timeout: 2)
        let ev = try? DaemonClient.decodeServerEvent(received[0])
        if case .error = ev {} else { XCTFail("未知行应回 ServerEvent.error") }
    }
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `swift test --filter MockDaemonTransportTests`
Expected: FAIL —— `cannot find 'MockDaemonTransport'`。

- [ ] **Step 3: 实现 `MockDaemonTransport`**

`Sources/AgentDeck/Preview/MockDaemonTransport.swift`：
```swift
import Foundation
import AgentDeckCore

/// preview 模式的进程内 mock 后端：实现 DaemonTransport，收前端真实 IPC 请求、
/// 异步回吐脚本化帧。前端全链路（编解码、路由、渲染）保持真实。仅 preview 路径引用。
final class MockDaemonTransport: DaemonTransport {
    private let queue = DispatchQueue(label: "agentdeck.mock-daemon")
    private var incoming: ((String) -> Void)?
    private var disconnect: (() -> Void)?
    private var started = false
    private var sessionCounter = 0
    private let encoder = JSONEncoder()

    var isStarted: Bool { started }
    var isAlive: Bool { started }

    func setIncomingHandler(_ handler: @escaping (String) -> Void) { incoming = handler }
    func setDisconnectHandler(_ handler: @escaping () -> Void) { disconnect = handler }

    func start() throws { started = true }

    func shutdown() {
        guard started else { return }
        started = false
        disconnect?()
    }

    func send(_ line: String) throws {
        guard started else { throw TransportError.notStarted }
        guard let command = try? JSONDecoder().decode(ClientCommand.self, from: Data(line.utf8)) else {
            emit(errorFrame(message: "unparseable client line: \(line)"))
            return
        }
        handle(command)
    }

    // MARK: - Command dispatch

    private func handle(_ command: ClientCommand) {
        switch command {
        case .ping:
            emitAdmin(reply: "ping", extra: [:])
        case .selfcheck:
            emitAdmin(reply: "selfcheck", extra: [:])
        case .protocolSchema:
            emitAdmin(reply: "protocolSchema", extra: [:])
        case .protocolVersion:
            emitAdmin(reply: "protocolVersion", extra: ["version": 2])
        case .agentList:
            emitAdmin(reply: "agentList", extra: ["agents": ["codex", "claude_code"]])
        case .agentCapabilities:
            // preview 未走该 admin 调用；返回裸 reply（若被调用会由前端报缺字段，属预期）。
            emitAdmin(reply: "agentCapabilities", extra: [:])
        case .history(let req):
            handleHistory(req)
        case .sessionStart:
            emitLiveTurn(threadId: "mock-live-thread")
        case .sessionContinue(let threadId, _, _, _):
            emitLiveTurn(threadId: threadId)
        case .actionDecision, .vendorControl, .sessionCancel:
            break // preview 下静默 ack
        }
    }

    private func handleHistory(_ req: HistoryRequest) {
        let response: HistoryResponse
        switch req {
        case .list:
            response = .list(MockDaemonScript.historyList())
        case .read(let threadId, _):
            response = .read(MockDaemonScript.readResponse(threadId: threadId))
        case .archive, .unarchive, .rename:
            response = .ack
        }
        guard let responseJSON = try? String(data: encoder.encode(response), encoding: .utf8) ?? "" else { return }
        emit("{\"reply\":\"history\",\"response\":\(responseJSON)}")
    }

    private func emitLiveTurn(threadId: String) {
        sessionCounter += 1
        let sessionId = "mock-session-\(sessionCounter)"
        for event in MockDaemonScript.liveTurnEvents(sessionId: sessionId, threadId: threadId) {
            if let json = try? String(data: encoder.encode(event), encoding: .utf8) ?? "" {
                emit(json)
            }
        }
    }

    // MARK: - Frame emission

    private func emit(_ line: String) {
        queue.asyncAfter(deadline: .now() + 0.03) { [weak self] in
            self?.incoming?(line)
        }
    }

    private func emitAdmin(reply: String, extra: [String: Any]) {
        var obj: [String: Any] = ["reply": reply]
        obj.merge(extra) { _, new in new }
        if let data = try? JSONSerialization.data(withJSONObject: obj),
           let line = String(data: data, encoding: .utf8) {
            emit(line)
        }
    }

    private func errorFrame(message: String) -> String {
        let event = ServerEvent.error(sessionId: nil, error: ProtocolError(code: "mock.malformed", message: message))
        return (try? String(data: encoder.encode(event), encoding: .utf8) ?? "") ?? ""
    }
}
```

- [ ] **Step 4: 跑测试确认通过**

Run: `swift test --filter MockDaemonTransportTests`
Expected: PASS（3 个测试）。

- [ ] **Step 5: 提交**

```bash
git add Sources/AgentDeck/Preview/MockDaemonTransport.swift Tests/AgentDeckTests/MockDaemonTransportTests.swift
git commit -m "feat(macos): 进程内 MockDaemonTransport（真实 IPC、脚本化回帧）"
```

---

### Task 5: `--preview` flag + preview 工厂 + `AppDelegate` 接线

**Files:**
- Create: `Sources/AgentDeck/Preview/PreviewBootstrap.swift`
- Modify: `Sources/AgentDeck/main.swift:145-148`（解析 flag、传入 AppDelegate）
- Modify: `Sources/AgentDeck/AppDelegate.swift:8-37`（preview 分支构造 model）
- Test: `Tests/AgentDeckTests/PreviewBootstrapTests.swift`

**Interfaces:**
- Consumes: `MockDaemonTransport`（Task 4）、`MockDaemonScript`（Task 3）、`DaemonClient(profile:transport:)`、`SessionModel(client:)`、`SessionModel.environmentInfo`（Task 1）
- Produces:
  - `enum PreviewBootstrap { static func makeSessionModel() -> SessionModel }`
  - `AppDelegate.init(profile:preview:)`

- [ ] **Step 1: 写失败测试**

`Tests/AgentDeckTests/PreviewBootstrapTests.swift`：
```swift
import XCTest
@testable import AgentDeck

@MainActor
final class PreviewBootstrapTests: XCTestCase {
    func testPreviewModelHasEnvironmentInfoAndLoadsMockHistory() {
        let model = PreviewBootstrap.makeSessionModel()
        XCTAssertEqual(model.environmentInfo?.branch, "main")
        // 走真实 loadHistory → 真实 DaemonClient → MockDaemonTransport → 真实解码。
        model.loadHistory()
        XCTAssertFalse(model.historyGroups.isEmpty, "preview 应通过真实链路加载到 mock 历史")
        XCTAssertNil(model.historyErrorMessage)
    }
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `swift test --filter PreviewBootstrapTests`
Expected: FAIL —— `cannot find 'PreviewBootstrap'`。

- [ ] **Step 3: 实现 `PreviewBootstrap`**

`Sources/AgentDeck/Preview/PreviewBootstrap.swift`：
```swift
import Foundation

/// preview 模式引导：构造一个由进程内 mock daemon 驱动、前端完全真实的 SessionModel。
enum PreviewBootstrap {
    @MainActor
    static func makeSessionModel() -> SessionModel {
        let client = DaemonClient(profile: .dev, transport: MockDaemonTransport())
        let model = SessionModel(client: client)
        model.environmentInfo = MockDaemonScript.environmentInfo
        return model
    }
}
```

- [ ] **Step 4: 跑测试确认通过**

Run: `swift test --filter PreviewBootstrapTests`
Expected: PASS。

- [ ] **Step 5: `AppDelegate` 支持 preview 分支**

`Sources/AgentDeck/AppDelegate.swift`，把 `init` 与 `model` 改为：
```swift
    private let profile: AgentDeckProfile
    private var window: NSWindow?
    private let model: SessionModel

    init(profile: AgentDeckProfile, preview: Bool = false) {
        self.profile = profile
        self.model = preview ? PreviewBootstrap.makeSessionModel() : SessionModel()
    }
```
（其余方法不变；`applicationDidFinishLaunching` 里已有的 `SessionViewController(model: model)` 会自动经 Task 前面的 viewDidAppear 触发 `loadHistoryOnAppear` → mock 历史。）

- [ ] **Step 6: `main.swift` 解析 `--preview`**

`Sources/AgentDeck/main.swift:145-148`，把
```swift
let app = NSApplication.shared
let delegate = AppDelegate(profile: launchProfile)
app.delegate = delegate
app.run()
```
改为
```swift
let previewMode = CommandLine.arguments.contains("--preview")
if previewMode {
    FileHandle.standardError.write(Data("[AgentDeck] preview mode: mock daemon\n".utf8))
}
let app = NSApplication.shared
let delegate = AppDelegate(profile: launchProfile, preview: previewMode)
app.delegate = delegate
app.run()
```

- [ ] **Step 7: 跑全量测试 + 手动验证**

Run: `swift test`
Expected: 全绿，无回归。
手动（可选）：`swift run AgentDeck -- --preview` → 侧栏出现 `refactor-auth`/`agentdeck-docs` 项目与 mock 会话；点「把登录模块拆分为独立 service」渲染命令块 + diff + 运行中；右上面板显示 `+128 -34 / 3 文件 / main / a1b2c3d`；发送一条 prompt 出现乐观插入并流式渲染。

- [ ] **Step 8: 更新文档 + 提交**

在 `README.md` 的运行/调试小节补一行：`swift run AgentDeck -- --preview`（前端 mock 预览，不连真实 daemon）。
在 `docs/plans/2026-07-04-frontend-preview-mock-daemon-design.md` 末尾追加「实现已落地」一行。
```bash
git add Sources/AgentDeck/Preview/PreviewBootstrap.swift Sources/AgentDeck/AppDelegate.swift Sources/AgentDeck/main.swift Tests/AgentDeckTests/PreviewBootstrapTests.swift README.md docs/plans/2026-07-04-frontend-preview-mock-daemon-design.md
git commit -m "feat(macos): --preview 前端 mock 预览模式（真实前端 + 进程内 mock daemon）"
```

---

## 收口

- 全部 5 个任务完成后跑 `swift test` 确认全绿。
- `git status --short --branch` 确认工作区干净。
- 复核：UI 渲染层无 `if preview` 分支；非 preview 启动路径未改行为（仅 `AppDelegate.init` 增加默认 `false` 参数）。
