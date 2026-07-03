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
