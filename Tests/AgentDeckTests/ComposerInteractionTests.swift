import XCTest
import AppKit
@testable import AgentDeck

/// 端到端交互：会话发送 / 输入框。
/// 驱动真实 InputBarView → 真实 SessionModel（spy turnStarter），
/// 模拟输入/点击/回车，断言提交、清空、滚动请求等交互结果。
@MainActor
final class ComposerInteractionTests: XCTestCase {

    private func makeComposer() -> (bar: InputBarView, model: SessionModel, spy: SpyTurnStarter, tv: InputTextView) {
        let spy = SpyTurnStarter()
        let model = SessionModel(turnStarter: spy)
        model.cwd = URL(fileURLWithPath: "/tmp/agentdeck-e2e")   // 有 cwd 才能新建 runtime
        let bar = InputBarView(model: model)
        bar.frame = NSRect(x: 0, y: 0, width: 860, height: 120)
        bar.layoutSubtreeIfNeeded()
        guard let tv = bar.firstDescendant(ofType: InputTextView.self) else {
            fatalError("composer 内应有 InputTextView")
        }
        return (bar, model, spy, tv)
    }

    private func type(_ text: String, into tv: InputTextView) {
        tv.string = text
        tv.didChangeText()   // 触发 onTextChange → 更新发送按钮启用态
    }

    func testSendDisabledWhenEmpty() {
        let c = makeComposer()
        type("", into: c.tv)
        let send = c.bar.button(id: "composer-send")
        XCTAssertNotNil(send, "发送按钮应可通过 a11y id 定位")
        XCTAssertFalse(send!.isEnabled, "空输入时发送按钮应禁用")
    }

    func testTypingEnablesSend() {
        let c = makeComposer()
        type("hello", into: c.tv)
        XCTAssertTrue(c.bar.button(id: "composer-send")!.isEnabled, "有文本时发送按钮应启用")
    }

    func testComposerOnlyExposesImplementedActionWithUsableHitTarget() throws {
        let c = makeComposer()
        let buttons = c.bar.allDescendants(ofType: NSButton.self)
        let send = try XCTUnwrap(c.bar.button(id: "composer-send"))

        XCTAssertEqual(buttons, [send], "未接通的附件和语音入口不应伪装成可点击按钮")
        XCTAssertGreaterThanOrEqual(send.frame.width, 44)
        XCTAssertGreaterThanOrEqual(send.frame.height, 44)
    }

    func testNarrowComposerKeepsSendAvailableWhenBadgesNeedMoreSpace() throws {
        let spy = SpyTurnStarter()
        let model = SessionModel(turnStarter: spy)
        model.cwd = URL(fileURLWithPath: "/tmp/agentdeck-e2e")
        model.queuedPrompts = Array(repeating: "queued", count: 999)

        let bar = InputBarView(model: model)
        bar.applyState(planMode: true)
        bar.frame = NSRect(x: 0, y: 0, width: 252, height: bar.fittingSize.height)
        bar.layoutSubtreeIfNeeded()

        let send = try XCTUnwrap(bar.button(id: "composer-send"))
        let badges = try XCTUnwrap(bar.descendant(id: "composer-badges"))
        let textView = try XCTUnwrap(bar.firstDescendant(ofType: InputTextView.self))

        XCTAssertEqual(send.frame.width, 44, accuracy: 0.5)
        XCTAssertGreaterThanOrEqual(send.frame.height, 44)
        XCTAssertEqual(send.frame.maxX, bar.bounds.maxX - 12, accuracy: 0.5)
        XCTAssertLessThanOrEqual(badges.frame.maxX, send.frame.minX - 12 + 0.5)
        XCTAssertGreaterThanOrEqual(badges.frame.minX, 13.5)
        XCTAssertFalse(bar.hasAmbiguousLayout)
        XCTAssertFalse(badges.hasAmbiguousLayout)

        type("窄窗口仍可发送", into: textView)
        XCTAssertTrue(send.isEnabled)
        send.performClick(nil)
        XCTAssertEqual(spy.lastPrompt, "窄窗口仍可发送")
    }

    func testClickSendSubmitsAndClears() {
        let c = makeComposer()
        type("拆分登录模块", into: c.tv)
        c.bar.button(id: "composer-send")!.performClick(nil)
        XCTAssertEqual(c.spy.lastPrompt, "拆分登录模块", "点击发送应把文本提交到 turnStarter")
        XCTAssertEqual(c.tv.string, "", "发送后应清空输入框")
        XCTAssertGreaterThan(c.model.scrollToLatestRequest, 0, "发送后应请求滚到最新")
    }

    func testEnterKeySubmits() {
        let c = makeComposer()
        type("回车发送", into: c.tv)
        c.tv.doCommand(by: #selector(NSResponder.insertNewline(_:)))
        XCTAssertEqual(c.spy.lastPrompt, "回车发送", "回车应提交")
    }

    func testWhitespaceOnlyDoesNotSubmit() {
        let c = makeComposer()
        type("   ", into: c.tv)
        c.bar.button(id: "composer-send")?.performClick(nil)
        XCTAssertNil(c.spy.lastPrompt, "纯空白不应提交")
    }
}
