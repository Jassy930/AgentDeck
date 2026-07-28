import AppKit

extension NSAttributedString.Key {
    /// 由 `InlineCodeLayoutManager` 绘制低对比圆角底与描边。
    static let agentDeckInlineCode = NSAttributedString.Key("com.agentdeck.inline-code")
    /// 由 `InlineCodeLayoutManager` 绘制整块 fenced code 容器。
    static let agentDeckCodeBlock = NSAttributedString.Key("com.agentdeck.code-block")
}

struct MarkdownStyle {
    var bodyFont: NSFont
    var headingFont: NSFont
    var codeFont: NSFont
    var textColor: NSColor
    var linkColor: NSColor
    var lineHeightLanguage: ConversationLineHeightLanguage

    static var standard: MarkdownStyle {
        MarkdownStyle(
            bodyFont: ConversationTypography.bodyFont,
            headingFont: .systemFont(ofSize: DesignTokens.typeTitle, weight: .semibold),
            codeFont: ConversationTypography.monoFont,
            textColor: DesignTokens.text,
            linkColor: .linkColor,
            lineHeightLanguage: .automatic
        )
    }

    static var reasoning: MarkdownStyle {
        MarkdownStyle(
            bodyFont: ConversationTypography.reasoningFont,
            headingFont: .systemFont(ofSize: DesignTokens.typeCallout, weight: .semibold),
            codeFont: ConversationTypography.monoFont,
            textColor: DesignTokens.text2,
            linkColor: .linkColor,
            lineHeightLanguage: .automatic
        )
    }

    func isVisuallyEquivalent(to other: MarkdownStyle) -> Bool {
        bodyFont.isEqual(other.bodyFont)
            && headingFont.isEqual(other.headingFont)
            && codeFont.isEqual(other.codeFont)
            && textColor.isEqual(other.textColor)
            && linkColor.isEqual(other.linkColor)
            && lineHeightLanguage == other.lineHeightLanguage
    }
}

enum MarkdownAttributedStringBuilder {
    private enum TableAlignment: Equatable {
        case left
        case center
        case right

        var textAlignment: NSTextAlignment {
            switch self {
            case .left: .left
            case .center: .center
            case .right: .right
            }
        }
    }

    private struct TableCell: Equatable {
        var tableID: Int
        var row: Int
        var column: Int
        var columnCount: Int
        var alignment: TableAlignment
        var isHeader: Bool
    }

    private enum BlockKind: Equatable {
        case paragraph
        case heading(level: Int)
        case unorderedList(indent: Int)
        case orderedList(indent: Int)
        case quote(indent: Int)
        case code
        case tableCell(TableCell)
    }

    private struct PreparedLine {
        var text: String
        var kind: BlockKind
        var separatedFromPrevious: Bool
        var isFirstCodeLine = false
        var isLastCodeLine = false
    }

    static func attributedString(from markdown: String, style: MarkdownStyle = .standard) -> NSAttributedString {
        guard !markdown.isEmpty else { return NSAttributedString() }

        let lines = preparedLines(from: markdown)
        let result = NSMutableAttributedString()
        var tables: [Int: NSTextTable] = [:]
        for (index, line) in lines.enumerated() {
            let table: NSTextTable?
            if case .tableCell(let cell) = line.kind {
                if let existing = tables[cell.tableID] {
                    table = existing
                } else {
                    let created = makeTable(columnCount: cell.columnCount)
                    tables[cell.tableID] = created
                    table = created
                }
            } else {
                table = nil
            }
            result.append(attributedLine(
                line,
                style: style,
                table: table,
                isFirstOutputLine: index == 0,
                appendNewline: index < lines.count - 1
            ))
        }
        return result
    }

    /// Foundation 的 `.full` markdown 解析会把块间换行只保存在
    /// `presentationIntent`，直接桥接到 `NSAttributedString` 后标题、列表和
    /// code block 会粘连。这里先做一层很小的行级块语法归一，再让每一行继续
    /// 使用 Foundation 解析 inline intents；既去掉 `##` / fence 等字面标记，
    /// 又保持流式重算、文本选择和表格测高仍消费同一份 attributed string。
    private static func preparedLines(from markdown: String) -> [PreparedLine] {
        let sourceLines = markdown.components(separatedBy: "\n").map { line in
            line.hasSuffix("\r") ? String(line.dropLast()) : line
        }
        var output: [PreparedLine] = []
        var pendingSeparation = false
        var activeFence: String?
        var codeStartIndex: Int?
        var tableID = 0
        var sourceIndex = 0

        while sourceIndex < sourceLines.count {
            let raw = sourceLines[sourceIndex]
            let trimmed = raw.trimmingCharacters(in: .whitespaces)

            if let marker = fenceMarker(in: trimmed) {
                if let openFence = activeFence, marker == openFence {
                    if let codeStartIndex, output.indices.contains(codeStartIndex) {
                        output[codeStartIndex].isFirstCodeLine = true
                        output[output.count - 1].isLastCodeLine = true
                    }
                    pendingSeparation = true
                    codeStartIndex = nil
                    activeFence = nil
                } else if activeFence == nil {
                    activeFence = marker
                    codeStartIndex = output.count
                    pendingSeparation = true
                }
                sourceIndex += 1
                continue
            }

            if activeFence != nil {
                output.append(PreparedLine(
                    text: raw,
                    kind: .code,
                    separatedFromPrevious: pendingSeparation
                ))
                pendingSeparation = false
                sourceIndex += 1
                continue
            }

            if trimmed.isEmpty {
                pendingSeparation = !output.isEmpty
                sourceIndex += 1
                continue
            }

            if sourceIndex + 1 < sourceLines.count,
               let header = splitTableRow(raw),
               let alignments = tableAlignments(from: sourceLines[sourceIndex + 1]),
               header.count == alignments.count {
                let currentTableID = tableID
                tableID += 1
                var rows = [header]
                var nextIndex = sourceIndex + 2

                while nextIndex < sourceLines.count {
                    let candidate = sourceLines[nextIndex]
                    guard !candidate.trimmingCharacters(in: .whitespaces).isEmpty,
                          fenceMarker(in: candidate.trimmingCharacters(in: .whitespaces)) == nil,
                          let cells = splitTableRow(candidate) else {
                        break
                    }
                    rows.append(normalized(cells: cells, columnCount: alignments.count))
                    nextIndex += 1
                }

                for (rowIndex, cells) in rows.enumerated() {
                    for columnIndex in 0..<alignments.count {
                        output.append(PreparedLine(
                            text: cells[columnIndex],
                            kind: .tableCell(TableCell(
                                tableID: currentTableID,
                                row: rowIndex,
                                column: columnIndex,
                                columnCount: alignments.count,
                                alignment: alignments[columnIndex],
                                isHeader: rowIndex == 0
                            )),
                            separatedFromPrevious: rowIndex == 0
                                && columnIndex == 0
                                && pendingSeparation
                        ))
                    }
                }

                pendingSeparation = false
                sourceIndex = nextIndex
                continue
            }

            let classified = classify(raw)
            output.append(PreparedLine(
                text: classified.text,
                kind: classified.kind,
                separatedFromPrevious: pendingSeparation
            ))
            pendingSeparation = false
            sourceIndex += 1
        }

        // 流式内容可能暂时没有收到 closing fence；仍把当前末尾当作完整视觉块，
        // 下一次 token 到来时会整串重算并自然延长容器。
        if let codeStartIndex, output.indices.contains(codeStartIndex) {
            output[codeStartIndex].isFirstCodeLine = true
            output[output.count - 1].isLastCodeLine = true
        }
        return output
    }

    private static func fenceMarker(in trimmed: String) -> String? {
        if trimmed.hasPrefix("```") { return "```" }
        if trimmed.hasPrefix("~~~") { return "~~~" }
        return nil
    }

    /// 拆分 GFM 表格行。结构管道符会分列；反斜杠转义的管道符和 inline code
    /// 内的管道符保留给后续 inline Markdown 解析，不会误切单元格。
    private static func splitTableRow(_ raw: String) -> [String]? {
        let characters = Array(raw)
        var cells: [String] = []
        var current = ""
        var codeDelimiterLength: Int?
        var sawStructuralPipe = false
        var index = 0

        while index < characters.count {
            let character = characters[index]

            if character == "\\", codeDelimiterLength == nil, index + 1 < characters.count {
                current.append(character)
                current.append(characters[index + 1])
                index += 2
                continue
            }

            if character == "`" {
                var runLength = 1
                while index + runLength < characters.count,
                      characters[index + runLength] == "`" {
                    runLength += 1
                }
                current.append(contentsOf: String(repeating: "`", count: runLength))
                if let activeLength = codeDelimiterLength {
                    if runLength == activeLength { codeDelimiterLength = nil }
                } else {
                    codeDelimiterLength = runLength
                }
                index += runLength
                continue
            }

            if character == "|", codeDelimiterLength == nil {
                cells.append(current.trimmingCharacters(in: .whitespaces))
                current = ""
                sawStructuralPipe = true
                index += 1
                continue
            }

            current.append(character)
            index += 1
        }

        guard sawStructuralPipe else { return nil }
        cells.append(current.trimmingCharacters(in: .whitespaces))

        if raw.drop(while: { $0 == " " || $0 == "\t" }).first == "|" {
            cells.removeFirst()
        }
        if structuralPipeTerminates(raw), cells.last?.isEmpty == true {
            cells.removeLast()
        }
        return cells.isEmpty ? nil : cells
    }

    private static func structuralPipeTerminates(_ raw: String) -> Bool {
        let trimmed = raw.drop(while: { $0 == " " || $0 == "\t" })
            .reversed()
            .drop(while: { $0 == " " || $0 == "\t" })
        guard trimmed.first == "|" else { return false }

        var precedingBackslashes = 0
        for character in trimmed.dropFirst() {
            guard character == "\\" else { break }
            precedingBackslashes += 1
        }
        return precedingBackslashes.isMultiple(of: 2)
    }

    private static func tableAlignments(from raw: String) -> [TableAlignment]? {
        guard let cells = splitTableRow(raw), !cells.isEmpty else { return nil }
        var alignments: [TableAlignment] = []

        for cell in cells {
            let marker = cell.trimmingCharacters(in: .whitespaces)
            let leadingColon = marker.first == ":"
            let trailingColon = marker.last == ":"
            let hyphens = marker.dropFirst(leadingColon ? 1 : 0)
                .dropLast(trailingColon ? 1 : 0)
            guard hyphens.count >= 3, hyphens.allSatisfy({ $0 == "-" }) else {
                return nil
            }

            switch (leadingColon, trailingColon) {
            case (true, true): alignments.append(.center)
            case (false, true): alignments.append(.right)
            default: alignments.append(.left)
            }
        }
        return alignments
    }

    private static func normalized(cells: [String], columnCount: Int) -> [String] {
        if cells.count >= columnCount {
            return Array(cells.prefix(columnCount))
        }
        return cells + Array(repeating: "", count: columnCount - cells.count)
    }

    private static func makeTable(columnCount: Int) -> NSTextTable {
        let table = NSTextTable()
        table.numberOfColumns = columnCount
        table.layoutAlgorithm = .automaticLayoutAlgorithm
        table.collapsesBorders = true
        table.hidesEmptyCells = false
        table.setValue(100, type: .percentageValueType, for: .width)
        table.setWidth(
            DesignTokens.sp2,
            type: .absoluteValueType,
            for: .margin,
            edge: .minY
        )
        table.setWidth(
            DesignTokens.sp2,
            type: .absoluteValueType,
            for: .margin,
            edge: .maxY
        )
        return table
    }

    private static func classify(_ raw: String) -> (text: String, kind: BlockKind) {
        let leadingWidth = indentationWidth(in: raw)
        let trimmed = raw.drop(while: { $0 == " " || $0 == "\t" })

        let headingMarks = trimmed.prefix(while: { $0 == "#" })
        if (1...6).contains(headingMarks.count) {
            let remainder = trimmed.dropFirst(headingMarks.count)
            if remainder.first == " " || remainder.first == "\t" {
                return (
                    String(remainder.drop(while: { $0 == " " || $0 == "\t" })),
                    .heading(level: headingMarks.count)
                )
            }
        }

        if let first = trimmed.first,
           ["-", "*", "+"].contains(first),
           trimmed.dropFirst().first == " " {
            let body = trimmed.dropFirst(2).drop(while: { $0 == " " || $0 == "\t" })
            return ("•  \(body)", .unorderedList(indent: leadingWidth))
        }

        let digits = trimmed.prefix(while: { $0.isNumber })
        let orderedSuffix = trimmed.dropFirst(digits.count)
        if !digits.isEmpty, orderedSuffix.hasPrefix(". ") {
            let body = orderedSuffix.dropFirst(2).drop(while: { $0 == " " || $0 == "\t" })
            return ("\(digits).  \(body)", .orderedList(indent: leadingWidth))
        }

        if trimmed.hasPrefix("> ") {
            let body = trimmed.dropFirst(2).drop(while: { $0 == " " || $0 == "\t" })
            return (String(body), .quote(indent: leadingWidth))
        }

        return (raw, .paragraph)
    }

    private static func indentationWidth(in line: String) -> Int {
        line.prefix(while: { $0 == " " || $0 == "\t" }).reduce(into: 0) { result, character in
            result += character == "\t" ? 4 : 1
        }
    }

    private static func attributedLine(
        _ line: PreparedLine,
        style: MarkdownStyle,
        table: NSTextTable?,
        isFirstOutputLine: Bool,
        appendNewline: Bool
    ) -> NSAttributedString {
        let parsed: AttributedString?
        if line.kind == .code {
            parsed = nil
        } else {
            var options = AttributedString.MarkdownParsingOptions()
            options.interpretedSyntax = .inlineOnlyPreservingWhitespace
            parsed = try? AttributedString(markdown: line.text, options: options)
        }

        let result: NSMutableAttributedString
        if let parsed {
            result = NSMutableAttributedString(attributedString: NSAttributedString(parsed))
        } else {
            result = NSMutableAttributedString(string: line.text)
        }

        let baseFont = font(for: line.kind, style: style)
        let contentRange = NSRange(location: 0, length: result.length)
        if contentRange.length > 0 {
            result.addAttributes([
                .font: baseFont,
                .foregroundColor: foregroundColor(for: line.kind, style: style),
            ], range: contentRange)
            if let parsed {
                applyEmphasis(to: result, parsed: parsed, baseFont: baseFont)
                applyInlineCode(to: result, parsed: parsed, style: style)
                applyLinks(to: result, style: style)
            }
        }

        let needsEmptyTableCellTerminator: Bool
        if case .tableCell = line.kind {
            needsEmptyTableCellTerminator = result.length == 0
        } else {
            needsEmptyTableCellTerminator = false
        }
        if appendNewline || needsEmptyTableCellTerminator {
            result.append(NSAttributedString(string: "\n"))
        }

        let paragraphRange = NSRange(location: 0, length: result.length)
        if paragraphRange.length > 0 {
            let paragraph = paragraphStyle(
                for: line,
                baseFont: baseFont,
                style: style,
                table: table,
                isFirstOutputLine: isFirstOutputLine
            )
            result.addAttribute(.paragraphStyle, value: paragraph, range: paragraphRange)

            if line.kind == .code {
                result.addAttributes([
                    .font: style.codeFont,
                    .foregroundColor: style.textColor,
                    .agentDeckCodeBlock: NSNumber(value: true),
                ], range: paragraphRange)
            }
        }
        return result
    }

    private static func font(for kind: BlockKind, style: MarkdownStyle) -> NSFont {
        switch kind {
        case .heading:
            return style.headingFont
        case .code:
            return style.codeFont
        case .tableCell(let cell) where cell.isHeader:
            return .systemFont(ofSize: style.bodyFont.pointSize, weight: .semibold)
        default:
            return style.bodyFont
        }
    }

    private static func foregroundColor(for kind: BlockKind, style: MarkdownStyle) -> NSColor {
        switch kind {
        case .quote:
            return DesignTokens.text2
        default:
            return style.textColor
        }
    }

    private static func paragraphStyle(
        for line: PreparedLine,
        baseFont: NSFont,
        style: MarkdownStyle,
        table: NSTextTable?,
        isFirstOutputLine: Bool
    ) -> NSParagraphStyle {
        let paragraph = ConversationTypography.paragraphStyle(
            for: baseFont,
            text: line.text,
            language: style.lineHeightLanguage
        ).mutableCopy() as! NSMutableParagraphStyle

        switch line.kind {
        case .paragraph:
            paragraph.paragraphSpacingBefore = line.separatedFromPrevious ? DesignTokens.sp2 : 0
        case .heading:
            paragraph.paragraphSpacingBefore = isFirstOutputLine
                ? 0
                : (line.separatedFromPrevious ? DesignTokens.sp4 : DesignTokens.sp3)
            paragraph.paragraphSpacing = DesignTokens.sp2
        case .unorderedList(let indent):
            let base = CGFloat(min(indent, 12))
            paragraph.firstLineHeadIndent = base
            paragraph.headIndent = base + 18
            paragraph.tailIndent = 0
            paragraph.paragraphSpacingBefore = line.separatedFromPrevious ? DesignTokens.sp2 : 0
        case .orderedList(let indent):
            let base = CGFloat(min(indent, 12))
            paragraph.firstLineHeadIndent = base
            paragraph.headIndent = base + 24
            paragraph.tailIndent = 0
            paragraph.paragraphSpacingBefore = line.separatedFromPrevious ? DesignTokens.sp2 : 0
        case .quote(let indent):
            let base = CGFloat(min(indent, 12)) + DesignTokens.sp3
            paragraph.firstLineHeadIndent = base
            paragraph.headIndent = base
            paragraph.paragraphSpacingBefore = line.separatedFromPrevious ? DesignTokens.sp2 : 0
        case .code:
            paragraph.firstLineHeadIndent = DesignTokens.sp3
            paragraph.headIndent = DesignTokens.sp3
            paragraph.tailIndent = -DesignTokens.sp3
            paragraph.lineBreakMode = .byCharWrapping
            paragraph.paragraphSpacingBefore = line.isFirstCodeLine
                ? (line.separatedFromPrevious ? DesignTokens.sp2 : DesignTokens.sp1)
                : 0
            paragraph.paragraphSpacing = line.isLastCodeLine ? DesignTokens.sp2 : 0
        case .tableCell(let cell):
            guard let table else { break }
            let block = NSTextTableBlock(
                table: table,
                startingRow: cell.row,
                rowSpan: 1,
                startingColumn: cell.column,
                columnSpan: 1
            )
            block.verticalAlignment = .topAlignment
            block.setWidth(
                DesignTokens.sp2,
                type: .absoluteValueType,
                for: .padding,
                edge: .minX
            )
            block.setWidth(
                DesignTokens.sp2,
                type: .absoluteValueType,
                for: .padding,
                edge: .maxX
            )
            block.setWidth(
                6,
                type: .absoluteValueType,
                for: .padding,
                edge: .minY
            )
            block.setWidth(
                6,
                type: .absoluteValueType,
                for: .padding,
                edge: .maxY
            )
            block.setWidth(0.5, type: .absoluteValueType, for: .border)
            block.setBorderColor(DesignTokens.border)
            block.backgroundColor = cell.isHeader ? DesignTokens.surface2 : nil
            paragraph.alignment = cell.alignment.textAlignment
            paragraph.lineBreakMode = .byCharWrapping
            paragraph.paragraphSpacingBefore = 0
            paragraph.paragraphSpacing = 0
            paragraph.textBlocks = [block]
        }
        return paragraph
    }

    /// 遍历 AttributedString runs，把 inlinePresentationIntent 含 .code 的 run 映射到
    /// 等宽字体和自定义圆角装饰属性。布局管理器负责真正绘制，避免原生
    /// `.backgroundColor` 产生方形、高对比的“选区条”。
    private static func applyInlineCode(
        to ns: NSMutableAttributedString,
        parsed: AttributedString,
        style: MarkdownStyle
    ) {
        for run in parsed.runs {
            guard let intent = run.inlinePresentationIntent, intent.contains(.code) else { continue }
            let nsRange = NSRange(run.range, in: parsed)
            guard nsRange.location != NSNotFound, nsRange.location + nsRange.length <= ns.length else { continue }
            ns.addAttributes([
                .font: style.codeFont,
                .agentDeckInlineCode: NSNumber(value: true),
            ], range: nsRange)
        }
    }

    private static func applyEmphasis(
        to ns: NSMutableAttributedString,
        parsed: AttributedString,
        baseFont: NSFont
    ) {
        for run in parsed.runs {
            guard let intent = run.inlinePresentationIntent else { continue }
            let isStrong = intent.contains(.stronglyEmphasized)
            let isItalic = intent.contains(.emphasized)
            guard isStrong || isItalic else { continue }

            var font = isStrong
                ? NSFont.systemFont(ofSize: baseFont.pointSize, weight: .semibold)
                : baseFont
            if isItalic {
                var traits = font.fontDescriptor.symbolicTraits
                traits.insert(.italic)
                if let italicFont = NSFont(
                    descriptor: font.fontDescriptor.withSymbolicTraits(traits),
                    size: font.pointSize
                ) {
                    font = italicFont
                }
            }

            let nsRange = NSRange(run.range, in: parsed)
            guard nsRange.location != NSNotFound,
                  nsRange.location + nsRange.length <= ns.length else {
                continue
            }
            ns.addAttribute(.font, value: font, range: nsRange)
        }
    }

    private static func applyLinks(to ns: NSMutableAttributedString, style: MarkdownStyle) {
        let full = NSRange(location: 0, length: ns.length)
        ns.enumerateAttribute(.link, in: full) { value, range, _ in
            guard value != nil else { return }
            ns.addAttributes([
                .foregroundColor: style.linkColor,
                .underlineStyle: NSUnderlineStyle.single.rawValue,
            ], range: range)
        }
    }
}
