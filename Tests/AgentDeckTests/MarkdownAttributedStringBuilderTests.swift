import XCTest
import AppKit
@testable import AgentDeck

final class MarkdownAttributedStringBuilderTests: XCTestCase {
    func testGeneratedTypographyTokensDriveMarkdownStyles() {
        XCTAssertEqual(DesignTokens.typeBody, 14)
        XCTAssertEqual(DesignTokens.typeCallout, 13)
        XCTAssertEqual(DesignTokens.typeCaption, 11)
        XCTAssertEqual(DesignTokens.typeMono, 12.5)
        XCTAssertEqual(DesignTokens.lineHeightCJK, 1.72)
        XCTAssertEqual(DesignTokens.lineHeightLatin, 1.45)

        XCTAssertEqual(MarkdownStyle.standard.bodyFont.pointSize, DesignTokens.typeBody)
        XCTAssertEqual(MarkdownStyle.standard.codeFont.pointSize, DesignTokens.typeMono)
        XCTAssertEqual(MarkdownStyle.reasoning.bodyFont.pointSize, DesignTokens.typeCallout)
        XCTAssertTrue(MarkdownStyle.reasoning.textColor.isEqual(DesignTokens.text2))
    }

    func testPlainParagraphPreservesText() {
        let s = MarkdownAttributedStringBuilder.attributedString(from: "hello world")
        XCTAssertEqual(s.string, "hello world")
    }

    func testAutomaticParagraphLineHeightDistinguishesCJKLatinAndMixedText() throws {
        let s = MarkdownAttributedStringBuilder.attributedString(
            from: "中文正文\nEnglish paragraph\nEnglish 中文"
        )
        let ns = s.string as NSString

        let cjk = try paragraphStyle(in: s, substring: "中文正文")
        let latin = try paragraphStyle(in: s, substring: "English paragraph")
        let mixed = try paragraphStyle(in: s, substring: "English 中文")

        let cjkHeight = DesignTokens.typeBody * DesignTokens.lineHeightCJK
        let latinHeight = DesignTokens.typeBody * DesignTokens.lineHeightLatin
        XCTAssertEqual(cjk.minimumLineHeight, cjkHeight, accuracy: 0.001)
        XCTAssertEqual(cjk.maximumLineHeight, cjkHeight, accuracy: 0.001)
        XCTAssertEqual(latin.minimumLineHeight, latinHeight, accuracy: 0.001)
        XCTAssertEqual(latin.maximumLineHeight, latinHeight, accuracy: 0.001)
        XCTAssertEqual(mixed.minimumLineHeight, cjkHeight, accuracy: 0.001)
        XCTAssertNotEqual(ns.range(of: "English paragraph").location, NSNotFound)
    }

    func testReasoningStyleIsThirteenPointSecondaryMarkdownWithCJKLineHeight() throws {
        let s = MarkdownAttributedStringBuilder.attributedString(
            from: "先 **梳理** 依赖",
            style: .reasoning
        )
        XCTAssertEqual(s.string, "先 梳理 依赖")

        let ns = s.string as NSString
        let plainRange = ns.range(of: "先")
        let boldRange = ns.range(of: "梳理")
        let plainFont = try XCTUnwrap(
            s.attribute(.font, at: plainRange.location, effectiveRange: nil) as? NSFont
        )
        let boldFont = try XCTUnwrap(
            s.attribute(.font, at: boldRange.location, effectiveRange: nil) as? NSFont
        )
        let color = try XCTUnwrap(
            s.attribute(.foregroundColor, at: plainRange.location, effectiveRange: nil) as? NSColor
        )
        let paragraph = try paragraphStyle(in: s, substring: "先")

        XCTAssertEqual(plainFont.pointSize, DesignTokens.typeCallout)
        XCTAssertFalse(plainFont.fontDescriptor.symbolicTraits.contains(.bold))
        XCTAssertEqual(boldFont.pointSize, DesignTokens.typeCallout)
        XCTAssertTrue(boldFont.fontDescriptor.symbolicTraits.contains(.bold))
        XCTAssertTrue(color.isEqual(DesignTokens.text2))
        XCTAssertEqual(
            paragraph.minimumLineHeight,
            DesignTokens.typeCallout * DesignTokens.lineHeightCJK,
            accuracy: 0.001
        )
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

    private func paragraphStyle(
        in attributed: NSAttributedString,
        substring: String
    ) throws -> NSParagraphStyle {
        let range = (attributed.string as NSString).range(of: substring)
        XCTAssertNotEqual(range.location, NSNotFound)
        return try XCTUnwrap(
            attributed.attribute(.paragraphStyle, at: range.location, effectiveRange: nil)
                as? NSParagraphStyle
        )
    }
}
