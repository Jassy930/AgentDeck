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
