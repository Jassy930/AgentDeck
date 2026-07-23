import XCTest
import AppKit
import AgentDeckCore
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
        XCTAssertTrue(view.usesInlineCodeLayoutManagerForTesting)

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

    func testMarkdownReplaceUpdatesAttributesWhenRenderedStringIsUnchanged() throws {
        let buffer = StreamingTextBuffer()
        buffer.replace(with: "plain")
        let view = StreamingTextContainerView(frame: .zero)
        view.bindMarkdownBuffer(to: buffer, style: .standard)
        let selection = NSRange(location: 1, length: 3)
        view.selectedRangeForTesting = selection

        buffer.replace(with: "**plain**")

        XCTAssertEqual(view.currentText, "plain")
        let font = try XCTUnwrap(
            view.currentAttributedText.attribute(.font, at: 0, effectiveRange: nil) as? NSFont
        )
        XCTAssertTrue(
            font.fontDescriptor.symbolicTraits.contains(.bold),
            "显示字符串相同但 markdown 属性变化时仍必须更新 text storage"
        )
        XCTAssertEqual(
            view.selectedRangeForTesting,
            selection,
            "仅 Markdown 属性变化时必须保留用户正在选择的可见文本"
        )
    }

    func testCollapsibleEmptyMarkdownHasZeroHeightAndExpandsWhenTextArrives() {
        let buffer = StreamingTextBuffer()
        let view = StreamingTextContainerView(
            frame: NSRect(x: 0, y: 0, width: 280, height: 1)
        )
        view.collapsesWhenEmpty = true
        view.bindMarkdownBuffer(to: buffer, style: .reasoning)

        XCTAssertEqual(view.fittingHeight(for: 280), 0, accuracy: 0.001)

        buffer.append("中")

        XCTAssertEqual(
            view.fittingHeight(for: 280),
            ceil(DesignTokens.typeCallout * DesignTokens.lineHeightCJK),
            accuracy: 0.5,
            "空 reasoning 收到首个 token 后必须恢复设计系统正文行高"
        )
    }

    func testRebindSameMarkdownBufferAppliesChangedTypographyStyle() throws {
        let buffer = StreamingTextBuffer()
        buffer.replace(with: "reasoning text")
        let view = StreamingTextContainerView(frame: .zero)
        view.bindMarkdownBuffer(to: buffer, style: .standard)
        view.bindMarkdownBuffer(to: buffer, style: .reasoning)

        let font = try XCTUnwrap(
            view.currentAttributedText.attribute(.font, at: 0, effectiveRange: nil) as? NSFont
        )
        let color = try XCTUnwrap(
            view.currentAttributedText.attribute(.foregroundColor, at: 0, effectiveRange: nil)
                as? NSColor
        )
        XCTAssertEqual(font.pointSize, DesignTokens.typeCallout)
        XCTAssertTrue(color.isEqual(DesignTokens.text2))
    }

    func testMarkdownFittingHeightMatchesSharedAttributedMeasurement() {
        let cases: [(text: String, style: MarkdownStyle)] = [
            ("中文第一行\n中文第二行包含 **重点**", .standard),
            ("English first line\nEnglish second line with **emphasis**", .standard),
            ("先梳理依赖\n再执行修复", .reasoning),
            ("Inspect dependencies\nThen implement the fix", .reasoning),
        ]

        for width: CGFloat in [280, 620] {
            for testCase in cases {
                let buffer = StreamingTextBuffer()
                buffer.replace(with: testCase.text)
                let view = StreamingTextContainerView(
                    frame: NSRect(x: 0, y: 0, width: width, height: 1)
                )
                view.bindMarkdownBuffer(to: buffer, style: testCase.style)
                let expected = measuredTextHeight(
                    MarkdownAttributedStringBuilder.attributedString(
                        from: testCase.text,
                        style: testCase.style
                    ),
                    width: width
                )

                XCTAssertEqual(
                    view.fittingHeight(for: width),
                    expected,
                    accuracy: 0.5,
                    "width=\(width), text=\(testCase.text) 的渲染和测高必须同源"
                )
            }
        }
    }

    /// C2: re-binding the SAME markdown buffer object (the streaming
    /// reconfigure path) must keep the live subscription and NOT collapse a
    /// selection the user is making. Previously `bindMarkdownBuffer` always
    /// unbound + re-observed, which rewrote the storage and reset selection.
    func testRebindSameMarkdownBufferPreservesSelection() {
        let buffer = StreamingTextBuffer()
        buffer.replace(with: "hello world from agent")
        let view = StreamingTextContainerView(frame: .zero)
        view.bindMarkdownBuffer(to: buffer, style: .standard)

        // User selects "world".
        let worldRange = (view.currentText as NSString).range(of: "world")
        view.selectedRangeForTesting = worldRange
        XCTAssertEqual(view.selectedRangeForTesting, worldRange)

        // A streaming flush reconfigures the cell with the same buffer.
        view.bindMarkdownBuffer(to: buffer, style: .standard)
        XCTAssertEqual(
            view.selectedRangeForTesting, worldRange,
            "重绑同一 markdown buffer 不应清空用户选区（C2）"
        )

        // And the live subscription still flows new tokens in.
        buffer.append(" tail")
        XCTAssertEqual(view.currentText, "hello world from agent tail", "同一 buffer 仍随追加更新")
    }

    /// C2: an unchanged markdown replace (the buffer notifies with text that
    /// renders to the same string) must skip the storage rewrite so a selection
    /// survives — mirroring the plain path's `.unchanged` early-return.
    func testUnchangedMarkdownReplacePreservesSelection() {
        let buffer = StreamingTextBuffer()
        buffer.replace(with: "alpha beta gamma")
        let view = StreamingTextContainerView(frame: .zero)
        view.bindMarkdownBuffer(to: buffer, style: .standard)

        let betaRange = (view.currentText as NSString).range(of: "beta")
        view.selectedRangeForTesting = betaRange

        // Replace with the identical text → rendered string unchanged.
        buffer.replace(with: "alpha beta gamma")
        XCTAssertEqual(
            view.selectedRangeForTesting, betaRange,
            "重算结果字符串未变时应跳过 setAttributedString，保留选区（C2）"
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
