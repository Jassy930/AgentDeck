import XCTest
import AppKit
@testable import AgentDeck

@MainActor
final class ConversationViewControllerSmokeTests: XCTestCase {
    /// Constructing the controller and accessing `.view` (which triggers
    /// `loadView`) must not crash and must NOT spawn `agentdeckd` — `SessionModel()`
    /// only builds a `DaemonClient`, whose transport stays dormant until
    /// `start()` (never called here), exactly like the existing IpcTests.
    func testConstructsAndLoadsView() {
        let model = SessionModel()
        let vc = ConversationViewController(model: model)
        XCTAssertNotNil(vc.view)
    }

    /// 设计系统标准画布为 1280×820：216pt 侧栏和 44pt header 之下，
    /// ConversationViewController 实际获得约 1064×776 的 body。带 inspector
    /// 时 transcript / footer / composer 必须共享同一条 620pt 内容轴。
    func testStandard1280By820WorkbenchUsesSharedContentAxisWithInspector() throws {
        let model = SessionModel(turnStarter: NoopRuntimeTurnStarter())
        model.cwd = URL(fileURLWithPath: NSTemporaryDirectory())
        model.environmentInfo = EnvironmentInfo(
            added: 12,
            removed: 3,
            fileCount: 2,
            branch: "main",
            commit: "abc1234"
        )

        let session = SessionViewController(model: model)
        let window = NSWindow(contentViewController: session)
        window.styleMask.insert([.titled, .resizable, .fullSizeContentView])
        window.setContentSize(NSSize(width: 1280, height: 820))
        window.makeKeyAndOrderFront(nil)
        defer { window.close() }
        RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.1))

        let root = try XCTUnwrap(
            window.contentView?.descendant(id: "conversation-transcript")?.superview
        )
        let transcript = try XCTUnwrap(root.descendant(id: "conversation-transcript"))
        let footer = try XCTUnwrap(root.descendant(id: "conversation-footer"))
        let composer = try XCTUnwrap(root.descendant(id: "conversation-input-bar"))
        let panel = try XCTUnwrap(root.descendant(id: "codex-environment-panel"))

        for view in [transcript, footer, composer] {
            XCTAssertEqual(
                view.frame.width,
                ConversationLayoutMetrics.contentMaxWidth,
                accuracy: 1,
                "标准窗口下所有主内容都应使用 620pt 内容列"
            )
            XCTAssertEqual(view.frame.minX, transcript.frame.minX, accuracy: 1)
            XCTAssertEqual(view.frame.maxX, transcript.frame.maxX, accuracy: 1)
        }

        let expectedContentMidX = (
            ConversationLayoutMetrics.horizontalInset
                + root.bounds.width
                - ConversationLayoutMetrics.inspectorReserve
        ) / 2
        XCTAssertEqual(transcript.frame.midX, expectedContentMidX, accuracy: 1)
        XCTAssertEqual(panel.frame.width, 260, accuracy: 1)
        XCTAssertEqual(
            root.bounds.maxX - panel.frame.maxX,
            ConversationLayoutMetrics.environmentTrailing,
            accuracy: 1
        )
    }

    func testNilEnvironmentCollapsesPanelAndRecentersSharedContentAxis() throws {
        let model = SessionModel(turnStarter: NoopRuntimeTurnStarter())
        XCTAssertNil(model.environmentInfo)
        let vc = ConversationViewController(model: model)
        vc.view.frame = NSRect(x: 0, y: 0, width: 1064, height: 776)
        vc.view.layoutSubtreeIfNeeded()

        let transcript = try XCTUnwrap(vc.view.descendant(id: "conversation-transcript"))
        let footer = try XCTUnwrap(vc.view.descendant(id: "conversation-footer"))
        let composer = try XCTUnwrap(vc.view.descendant(id: "conversation-input-bar"))

        XCTAssertNil(
            vc.view.descendant(id: "codex-environment-panel"),
            "nil environmentInfo 时面板必须移出视图层级，不能只设 isHidden"
        )
        XCTAssertEqual(transcript.frame.width, ConversationLayoutMetrics.contentMaxWidth, accuracy: 1)
        XCTAssertEqual(transcript.frame.midX, vc.view.bounds.midX, accuracy: 1)
        XCTAssertEqual(footer.frame.minX, transcript.frame.minX, accuracy: 1)
        XCTAssertEqual(footer.frame.maxX, transcript.frame.maxX, accuracy: 1)
        XCTAssertEqual(composer.frame.minX, transcript.frame.minX, accuracy: 1)
        XCTAssertEqual(composer.frame.maxX, transcript.frame.maxX, accuracy: 1)
    }

    func testEnvironmentPanelAttachesAndDetachesWhenDataAvailabilityChanges() throws {
        let model = SessionModel(turnStarter: NoopRuntimeTurnStarter())
        let vc = ConversationViewController(model: model)
        vc.view.frame = NSRect(x: 0, y: 0, width: 1064, height: 776)
        vc.view.layoutSubtreeIfNeeded()
        XCTAssertNil(vc.view.descendant(id: "codex-environment-panel"))

        model.environmentInfo = EnvironmentInfo(
            added: 1,
            removed: 0,
            fileCount: 1,
            branch: "main",
            commit: "abc1234"
        )
        RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.05))
        vc.view.layoutSubtreeIfNeeded()
        let panel = try XCTUnwrap(vc.view.descendant(id: "codex-environment-panel"))
        XCTAssertEqual(panel.frame.width, 260, accuracy: 1)

        model.environmentInfo = nil
        RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.05))
        vc.view.layoutSubtreeIfNeeded()
        XCTAssertNil(vc.view.descendant(id: "codex-environment-panel"))
        let transcript = try XCTUnwrap(vc.view.descendant(id: "conversation-transcript"))
        XCTAssertEqual(transcript.frame.midX, vc.view.bounds.midX, accuracy: 1)
    }

    func testNarrowPaneCollapsesInspectorToPreserveComposerWidth() throws {
        let model = SessionModel(turnStarter: NoopRuntimeTurnStarter())
        model.environmentInfo = EnvironmentInfo(
            added: 1,
            removed: 0,
            fileCount: 1,
            branch: "main",
            commit: "abc1234"
        )
        let vc = ConversationViewController(model: model)
        vc.view.frame = NSRect(x: 0, y: 0, width: 300, height: 620)
        vc.view.layoutSubtreeIfNeeded()

        let composer = try XCTUnwrap(vc.view.descendant(id: "conversation-input-bar"))
        XCTAssertNil(
            vc.view.descendant(id: "codex-environment-panel"),
            "窄窗应响应式折叠 inspector，不能把 composer 挤到不可用"
        )
        XCTAssertEqual(
            composer.frame.width,
            ConversationLayoutMetrics.contentMinimumWidth,
            accuracy: 1
        )
        XCTAssertFalse(composer.hasAmbiguousLayout)
    }
}
