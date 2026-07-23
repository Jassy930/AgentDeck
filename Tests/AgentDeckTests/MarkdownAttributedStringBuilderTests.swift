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
        XCTAssertEqual(MarkdownStyle.standard.headingFont.pointSize, DesignTokens.typeTitle)
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

    func testInlineCodeUsesMonospacedFontAndRoundedDecorationAttribute() {
        let s = MarkdownAttributedStringBuilder.attributedString(from: "a `code` b")
        // 找到 "code" 区段，断言其字体是等宽且由 layout manager 绘制圆角底，
        // 不回退到原生方形 backgroundColor。
        let ns = s.string as NSString
        let r = ns.range(of: "code")
        let font = s.attribute(.font, at: r.location, effectiveRange: nil) as? NSFont
        let background = s.attribute(.backgroundColor, at: r.location, effectiveRange: nil)
        let decoration = s.attribute(.agentDeckInlineCode, at: r.location, effectiveRange: nil)
        XCTAssertTrue(font?.fontDescriptor.symbolicTraits.contains(.monoSpace) ?? false,
                      "行内代码应使用等宽字体")
        XCTAssertNil(background, "行内代码不应使用原生方形文字背景")
        XCTAssertNotNil(decoration, "行内代码应交给自定义圆角装饰绘制")
    }

    func testHeadingsListsAndParagraphBreaksRenderWithoutLiteralMarkers() throws {
        let s = MarkdownAttributedStringBuilder.attributedString(
            from: "## 当前执行状态\n\n- **完成** 第一项\n- 第二项"
        )
        XCTAssertEqual(s.string, "当前执行状态\n•  完成 第一项\n•  第二项")
        XCTAssertFalse(s.string.contains("##"))

        let headingRange = (s.string as NSString).range(of: "当前执行状态")
        let headingFont = try XCTUnwrap(
            s.attribute(.font, at: headingRange.location, effectiveRange: nil) as? NSFont
        )
        XCTAssertEqual(headingFont.pointSize, DesignTokens.typeTitle)
        XCTAssertTrue(headingFont.fontDescriptor.symbolicTraits.contains(.bold))

        let listStyle = try paragraphStyle(in: s, substring: "•  完成")
        XCTAssertEqual(listStyle.headIndent, 18, accuracy: 0.001)
        XCTAssertEqual(listStyle.paragraphSpacingBefore, DesignTokens.sp2, accuracy: 0.001)
    }

    func testFencedCodeUsesMonospacedBlockDecorationAndDropsFence() throws {
        let s = MarkdownAttributedStringBuilder.attributedString(
            from: "正文\n\n```swift\nlet value = 1\n```\n\n结论"
        )
        XCTAssertEqual(s.string, "正文\nlet value = 1\n结论")
        XCTAssertFalse(s.string.contains("```"))

        let codeRange = (s.string as NSString).range(of: "let value = 1")
        let font = try XCTUnwrap(
            s.attribute(.font, at: codeRange.location, effectiveRange: nil) as? NSFont
        )
        XCTAssertTrue(font.fontDescriptor.symbolicTraits.contains(.monoSpace))
        XCTAssertNotNil(
            s.attribute(.agentDeckCodeBlock, at: codeRange.location, effectiveRange: nil)
        )
    }

    func testUnclosedStreamingFenceStillFormsOneCodeBlock() {
        let s = MarkdownAttributedStringBuilder.attributedString(
            from: "```json\n{\"state\": \"running\"}"
        )
        XCTAssertEqual(s.string, "{\"state\": \"running\"}")
        XCTAssertNotNil(s.attribute(.agentDeckCodeBlock, at: 0, effectiveRange: nil))
    }

    func testGFMTableUsesNativeTextTableBlocksAndDropsSyntaxRows() throws {
        let markdown = """
        | 项目 | 占用 |
        | :--- | ---: |
        | APFS 数据卷 | **847 GiB** / 926 GiB |
        | 可用空间 | 约 41 GiB |
        """
        let s = MarkdownAttributedStringBuilder.attributedString(from: markdown)

        XCTAssertEqual(
            s.string,
            "项目\n占用\nAPFS 数据卷\n847 GiB / 926 GiB\n可用空间\n约 41 GiB"
        )
        XCTAssertFalse(s.string.contains("---"), "表格分隔行不应作为正文显示")
        XCTAssertFalse(s.string.contains("|"), "结构管道符不应作为正文显示")

        let headerProject = try tableBlock(in: s, substring: "项目")
        let headerUsage = try tableBlock(in: s, substring: "占用")
        let volume = try tableBlock(in: s, substring: "APFS 数据卷")
        let available = try tableBlock(in: s, substring: "可用空间")
        XCTAssertTrue(headerProject.table === headerUsage.table)
        XCTAssertTrue(headerProject.table === volume.table)
        XCTAssertEqual(headerProject.table.numberOfColumns, 2)
        XCTAssertEqual(headerProject.startingRow, 0)
        XCTAssertEqual(headerProject.startingColumn, 0)
        XCTAssertEqual(headerUsage.startingRow, 0)
        XCTAssertEqual(headerUsage.startingColumn, 1)
        XCTAssertEqual(volume.startingRow, 1)
        XCTAssertEqual(volume.startingColumn, 0)
        XCTAssertEqual(available.startingRow, 2)
        XCTAssertEqual(available.startingColumn, 0)
        XCTAssertTrue(headerProject.backgroundColor?.isEqual(DesignTokens.surface2) == true)
        XCTAssertNil(volume.backgroundColor)

        let headerFont = try font(in: s, substring: "项目")
        let emphasizedFont = try font(in: s, substring: "847 GiB")
        XCTAssertTrue(headerFont.fontDescriptor.symbolicTraits.contains(.bold))
        XCTAssertTrue(emphasizedFont.fontDescriptor.symbolicTraits.contains(.bold))

        XCTAssertEqual(try paragraphStyle(in: s, substring: "项目").alignment, .left)
        XCTAssertEqual(try paragraphStyle(in: s, substring: "占用").alignment, .right)
        XCTAssertEqual(try paragraphStyle(in: s, substring: "约 41 GiB").alignment, .right)
    }

    func testGFMTablePreservesInlineCodeEscapedPipesAndCenteredColumns() throws {
        let markdown = """
        | 路径 | 状态 |
        | --- | :---: |
        | ngoro\\|glm 与 `cache|path` | [正常](https://example.com) |
        """
        let s = MarkdownAttributedStringBuilder.attributedString(from: markdown)

        XCTAssertEqual(s.string, "路径\n状态\nngoro|glm 与 cache|path\n正常")
        let codeRange = (s.string as NSString).range(of: "cache|path")
        XCTAssertNotNil(s.attribute(.agentDeckInlineCode, at: codeRange.location, effectiveRange: nil))
        let linkRange = (s.string as NSString).range(of: "正常")
        XCTAssertNotNil(s.attribute(.link, at: linkRange.location, effectiveRange: nil))
        XCTAssertEqual(try paragraphStyle(in: s, substring: "正常").alignment, .center)
    }

    func testIncompleteOrMismatchedTableRemainsReadablePlainText() {
        let incomplete = MarkdownAttributedStringBuilder.attributedString(
            from: "| 项目 | 占用 |\n| --- |"
        )
        XCTAssertEqual(incomplete.string, "| 项目 | 占用 |\n| --- |")

        let missingDelimiter = MarkdownAttributedStringBuilder.attributedString(
            from: "| 项目 | 占用 |\n| APFS | 847 GiB |"
        )
        XCTAssertEqual(missingDelimiter.string, "| 项目 | 占用 |\n| APFS | 847 GiB |")
    }

    func testTableStopsBeforeFollowingMarkdownBlocks() throws {
        let markdown = """
        | 项目 | 占用 |
        | --- | --- |
        | APFS | 847 GiB |

        **结论**：空间偏紧。
        """
        let s = MarkdownAttributedStringBuilder.attributedString(from: markdown)

        XCTAssertEqual(s.string, "项目\n占用\nAPFS\n847 GiB\n结论：空间偏紧。")
        XCTAssertNotNil(try tableBlock(in: s, substring: "APFS"))
        let conclusion = (s.string as NSString).range(of: "结论")
        XCTAssertNil(s.attribute(.paragraphStyle, at: conclusion.location, effectiveRange: nil)
            .flatMap { ($0 as? NSParagraphStyle)?.textBlocks.first })
    }

    func testTablePadsMissingCellsAndKeepsEmptyFinalCell() throws {
        let s = MarkdownAttributedStringBuilder.attributedString(
            from: "| 第一列 | 第二列 |\n| --- | --- |\n| 只有一个值 |"
        )

        XCTAssertEqual(s.string, "第一列\n第二列\n只有一个值\n\n")
        let paragraph = try XCTUnwrap(
            s.attribute(.paragraphStyle, at: s.length - 1, effectiveRange: nil)
                as? NSParagraphStyle
        )
        let block = try XCTUnwrap(paragraph.textBlocks.first as? NSTextTableBlock)
        XCTAssertEqual(block.startingRow, 1)
        XCTAssertEqual(block.startingColumn, 1)
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

    private func tableBlock(
        in attributed: NSAttributedString,
        substring: String
    ) throws -> NSTextTableBlock {
        let paragraph = try paragraphStyle(in: attributed, substring: substring)
        return try XCTUnwrap(paragraph.textBlocks.first as? NSTextTableBlock)
    }

    private func font(
        in attributed: NSAttributedString,
        substring: String
    ) throws -> NSFont {
        let range = (attributed.string as NSString).range(of: substring)
        XCTAssertNotEqual(range.location, NSNotFound)
        return try XCTUnwrap(
            attributed.attribute(.font, at: range.location, effectiveRange: nil) as? NSFont
        )
    }
}
