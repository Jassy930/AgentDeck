import AppKit

struct MarkdownStyle {
    var bodyFont: NSFont
    var codeFont: NSFont
    var textColor: NSColor
    var codeBackground: NSColor
    var linkColor: NSColor
    var lineHeightLanguage: ConversationLineHeightLanguage

    static var standard: MarkdownStyle {
        MarkdownStyle(
            bodyFont: ConversationTypography.bodyFont,
            codeFont: ConversationTypography.monoFont,
            textColor: DesignTokens.text,
            codeBackground: DesignTokens.text3,
            linkColor: .linkColor,
            lineHeightLanguage: .automatic
        )
    }

    static var reasoning: MarkdownStyle {
        MarkdownStyle(
            bodyFont: ConversationTypography.reasoningFont,
            codeFont: ConversationTypography.monoFont,
            textColor: DesignTokens.text2,
            codeBackground: DesignTokens.text3,
            linkColor: .linkColor,
            lineHeightLanguage: .automatic
        )
    }

    func isVisuallyEquivalent(to other: MarkdownStyle) -> Bool {
        bodyFont.isEqual(other.bodyFont)
            && codeFont.isEqual(other.codeFont)
            && textColor.isEqual(other.textColor)
            && codeBackground.isEqual(other.codeBackground)
            && linkColor.isEqual(other.linkColor)
            && lineHeightLanguage == other.lineHeightLanguage
    }
}

enum MarkdownAttributedStringBuilder {
    static func attributedString(from markdown: String, style: MarkdownStyle = .standard) -> NSAttributedString {
        guard !markdown.isEmpty else { return NSAttributedString() }

        // 用 Foundation 的 AttributedString markdown 解析（保留 inline intents），
        // 失败或不支持的语法降级为纯文本，绝不崩溃。
        var options = AttributedString.MarkdownParsingOptions()
        options.interpretedSyntax = .inlineOnlyPreservingWhitespace
        let parsed: AttributedString
        if let a = try? AttributedString(markdown: markdown, options: options) {
            parsed = a
        } else {
            let fallback = NSMutableAttributedString(
                string: markdown,
                attributes: [.font: style.bodyFont, .foregroundColor: style.textColor]
            )
            ConversationTypography.applyParagraphStyles(
                to: fallback,
                font: style.bodyFont,
                language: style.lineHeightLanguage
            )
            return fallback
        }
        let result = NSMutableAttributedString(attributedString: NSAttributedString(parsed))
        let full = NSRange(location: 0, length: result.length)
        // 基线样式
        result.addAttributes([.font: style.bodyFont, .foregroundColor: style.textColor], range: full)
        applyEmphasis(to: result, parsed: parsed, style: style)
        // 行内代码：AttributedString 的 inlinePresentationIntent.code → 等宽 + 背景
        applyInlineCode(to: result, parsed: parsed, style: style)
        applyLinks(to: result, style: style)
        ConversationTypography.applyParagraphStyles(
            to: result,
            font: style.bodyFont,
            language: style.lineHeightLanguage
        )
        return result
    }

    /// 遍历 AttributedString runs，把 inlinePresentationIntent 含 .code 的 run 映射到
    /// NSAttributedString 等宽 + 背景。
    /// 使用 NSRange(run.range, in: parsed) 方式以正确处理 emoji/组合字符偏移。
    private static func applyInlineCode(to ns: NSMutableAttributedString, parsed: AttributedString, style: MarkdownStyle) {
        for run in parsed.runs {
            guard let intent = run.inlinePresentationIntent, intent.contains(.code) else { continue }
            let nsRange = NSRange(run.range, in: parsed)
            guard nsRange.location != NSNotFound, nsRange.location + nsRange.length <= ns.length else { continue }
            ns.addAttributes([.font: style.codeFont, .backgroundColor: style.codeBackground], range: nsRange)
        }
    }

    private static func applyEmphasis(
        to ns: NSMutableAttributedString,
        parsed: AttributedString,
        style: MarkdownStyle
    ) {
        for run in parsed.runs {
            guard let intent = run.inlinePresentationIntent else { continue }
            var traits = style.bodyFont.fontDescriptor.symbolicTraits
            var changed = false
            if intent.contains(.stronglyEmphasized) {
                traits.insert(.bold)
                changed = true
            }
            if intent.contains(.emphasized) {
                traits.insert(.italic)
                changed = true
            }
            guard changed else { continue }

            let nsRange = NSRange(run.range, in: parsed)
            let descriptor = style.bodyFont.fontDescriptor.withSymbolicTraits(traits)
            guard nsRange.location != NSNotFound,
                  nsRange.location + nsRange.length <= ns.length,
                  let font = NSFont(descriptor: descriptor, size: style.bodyFont.pointSize) else {
                continue
            }
            ns.addAttribute(.font, value: font, range: nsRange)
        }
    }

    private static func applyLinks(to ns: NSMutableAttributedString, style: MarkdownStyle) {
        let full = NSRange(location: 0, length: ns.length)
        ns.enumerateAttribute(.link, in: full) { value, range, _ in
            guard value != nil else { return }
            ns.addAttributes([.foregroundColor: style.linkColor, .underlineStyle: NSUnderlineStyle.single.rawValue], range: range)
        }
    }
}
