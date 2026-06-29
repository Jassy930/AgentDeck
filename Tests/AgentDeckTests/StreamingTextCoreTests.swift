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

    // MARK: - Markdown mode (design §5)

    /// Binding markdown to the markdown entry point must produce a bold run for
    /// `**bold**` — i.e. rich attributes, NOT uniform plain text. We compare the
    /// font traits of the bold word against the surrounding plain word.
    func testMarkdownModeRendersBoldRun() {
        let buffer = StreamingTextBuffer()
        buffer.replace(with: "plain **bold** plain")

        let view = StreamingTextContainerView(frame: .zero)
        view.bindMarkdownBuffer(to: buffer, style: .standard)

        let attributed = view.currentAttributedText
        // The rendered plain string drops the markdown syntax markers.
        XCTAssertEqual(view.currentText, "plain bold plain", "markdown 语法标记应被解析掉")

        let boldRange = (attributed.string as NSString).range(of: "bold")
        let plainRange = (attributed.string as NSString).range(of: "plain")
        XCTAssertNotEqual(boldRange.location, NSNotFound)
        XCTAssertNotEqual(plainRange.location, NSNotFound)

        let boldFont = attributed.attribute(.font, at: boldRange.location, effectiveRange: nil) as? NSFont
        let plainFont = attributed.attribute(.font, at: plainRange.location, effectiveRange: nil) as? NSFont
        XCTAssertNotNil(boldFont)
        XCTAssertNotNil(plainFont)
        XCTAssertTrue(
            boldFont!.fontDescriptor.symbolicTraits.contains(.bold),
            "markdown 模式下 **bold** 区段应为粗体（富属性，非纯文本）"
        )
        XCTAssertFalse(
            plainFont!.fontDescriptor.symbolicTraits.contains(.bold),
            "周围纯文本不应为粗体——证明渲染是按 run 区分的富 markdown"
        )
    }

    /// Streaming appends in markdown mode must re-render the WHOLE buffer (the
    /// builder is whole-string), so a `**bold**` arriving across appends still
    /// ends up bold.
    func testMarkdownModeReRendersOnAppend() {
        let buffer = StreamingTextBuffer()
        let view = StreamingTextContainerView(frame: .zero)
        view.bindMarkdownBuffer(to: buffer, style: .standard)

        buffer.append("**bo")
        buffer.append("ld**")

        let attributed = view.currentAttributedText
        XCTAssertEqual(view.currentText, "bold", "追加完成后应解析为去标记的 bold")
        let boldFont = attributed.attribute(.font, at: 0, effectiveRange: nil) as? NSFont
        XCTAssertNotNil(boldFont)
        XCTAssertTrue(
            boldFont!.fontDescriptor.symbolicTraits.contains(.bold),
            "跨多次 append 形成的 **bold** 仍应整体重算为粗体"
        )
    }

    /// Rebinding the same view from markdown mode back to plain-text mode must
    /// drop the rich attributes (cell reuse safety).
    func testRebindFromMarkdownToPlainDropsRichAttributes() {
        let markdownBuffer = StreamingTextBuffer()
        markdownBuffer.replace(with: "**bold**")
        let view = StreamingTextContainerView(frame: .zero)
        view.bindMarkdownBuffer(to: markdownBuffer, style: .standard)
        XCTAssertEqual(view.currentText, "bold")

        let plainBuffer = StreamingTextBuffer()
        plainBuffer.replace(with: "**bold**")
        view.bindBuffer(to: plainBuffer, font: .monospacedSystemFont(ofSize: 12, weight: .regular), color: .labelColor)

        // Plain mode keeps the literal markers and a uniform monospaced font.
        XCTAssertEqual(view.currentText, "**bold**", "纯文本模式应保留字面标记")
        let font = view.currentAttributedText.attribute(.font, at: 0, effectiveRange: nil) as? NSFont
        XCTAssertNotNil(font)
        XCTAssertFalse(
            font!.fontDescriptor.symbolicTraits.contains(.bold),
            "切回纯文本模式后不应残留粗体富属性（复用安全）"
        )
    }
}
