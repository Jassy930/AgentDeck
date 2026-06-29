import XCTest
import AppKit
@testable import AgentDeck

@MainActor
final class StreamingTextCoreTests: XCTestCase {
    func testBindShowsBufferTextAndRebindSwitchesContent() {
        let bufferA = StreamingTextBuffer()
        bufferA.replace(with: "alpha")
        let bufferB = StreamingTextBuffer()
        bufferB.replace(with: "beta")

        let view = StreamingTextContainerView(frame: .zero)
        view.bindBuffer(to: bufferA, font: .monospacedSystemFont(ofSize: 12, weight: .regular), color: .labelColor)
        XCTAssertEqual(view.currentText, "alpha")

        view.bindBuffer(to: bufferB, font: .monospacedSystemFont(ofSize: 12, weight: .regular), color: .labelColor)
        XCTAssertEqual(view.currentText, "beta", "重绑后应显示新 buffer 内容（复用关键）")

        bufferB.append("!")
        XCTAssertEqual(view.currentText, "beta!", "绑定后应随 buffer 追加更新")
    }

    func testUnbindStopsUpdates() {
        let buffer = StreamingTextBuffer()
        buffer.replace(with: "hello")

        let view = StreamingTextContainerView(frame: .zero)
        view.bindBuffer(to: buffer, font: .monospacedSystemFont(ofSize: 12, weight: .regular), color: .labelColor)
        XCTAssertEqual(view.currentText, "hello")

        view.unbind()
        buffer.append(" world")
        // 解绑后 buffer 更新不应反映到 view
        XCTAssertEqual(view.currentText, "hello", "解绑后 buffer 追加不应更新 view")
    }
}
