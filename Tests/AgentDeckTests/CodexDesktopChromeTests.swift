import XCTest
import AppKit
@testable import AgentDeck

@MainActor
final class CodexDesktopChromeTests: XCTestCase {
    func testEmptyStateUsesCodexDesktopPrompt() {
        let view = EmptyStateView(model: SessionModel())

        XCTAssertNotNil(
            view.findTextField(containing: "我们应该在 AgentDeck 中构建什么？"),
            "空态首屏应使用 Codex Desktop 风格的大标题"
        )
    }

    func testInputBarUsesCodexComposerChrome() {
        let bar = InputBarView()
        let chrome = bar.findView(accessibilityIdentifier: "codex-composer")

        XCTAssertNotNil(chrome, "输入框应暴露 Codex composer chrome 供 smoke test 锁定")
        XCTAssertGreaterThanOrEqual(chrome?.layer?.cornerRadius ?? 0, 18)
    }

    func testSessionViewInstallsRightPaneHeader() {
        let vc = SessionViewController(model: SessionModel())
        _ = vc.view

        XCTAssertNotNil(
            vc.view.findView(accessibilityIdentifier: "codex-content-header"),
            "右侧内容区应拥有 Codex Desktop 风格的 thread header"
        )
    }

    func testContentHeaderOpensCurrentDirectoryAndHidesUnsupportedControls() throws {
        let model = SessionModel(turnStarter: NoopRuntimeTurnStarter())
        let cwd = URL(fileURLWithPath: NSTemporaryDirectory())
        model.cwd = cwd
        var openedURL: URL?
        let header = CodexContentHeaderView(model: model) { url in
            openedURL = url
        }
        header.frame = NSRect(x: 0, y: 0, width: 900, height: 44)
        header.layoutSubtreeIfNeeded()

        let openButton = try XCTUnwrap(header.button(id: "codex-open-location"))
        XCTAssertFalse(openButton.isHidden)
        openButton.performClick(nil)
        XCTAssertEqual(openedURL, cwd)

        let controls = try XCTUnwrap(header.button(id: "codex-content-controls"))
        XCTAssertTrue(controls.isHidden, "未实现的界面选项不应显示为伪控件")
    }
}

private extension NSView {
    func findView(accessibilityIdentifier target: String) -> NSView? {
        if accessibilityIdentifier() == target {
            return self
        }
        for subview in subviews {
            if let match = subview.findView(accessibilityIdentifier: target) {
                return match
            }
        }
        return nil
    }

    func findTextField(containing text: String) -> NSTextField? {
        if let field = self as? NSTextField, field.stringValue.contains(text) {
            return field
        }
        for subview in subviews {
            if let match = subview.findTextField(containing: text) {
                return match
            }
        }
        return nil
    }
}
