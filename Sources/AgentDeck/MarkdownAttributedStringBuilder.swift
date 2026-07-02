import AppKit

struct MarkdownStyle {
    var bodyFont: NSFont
    var codeFont: NSFont
    var textColor: NSColor
    var codeBackground: NSColor
    var linkColor: NSColor

    static var standard: MarkdownStyle {
        MarkdownStyle(
            bodyFont: .systemFont(ofSize: NSFont.systemFontSize),
            codeFont: .monospacedSystemFont(ofSize: NSFont.systemFontSize - 1, weight: .regular),
            textColor: DesignTokens.text,
            codeBackground: DesignTokens.text3,
            linkColor: .linkColor
        )
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
            return NSAttributedString(
                string: markdown,
                attributes: [.font: style.bodyFont, .foregroundColor: style.textColor]
            )
        }
        let result = NSMutableAttributedString(attributedString: NSAttributedString(parsed))
        let full = NSRange(location: 0, length: result.length)
        // 基线样式
        result.addAttributes([.font: style.bodyFont, .foregroundColor: style.textColor], range: full)
        // 行内代码：AttributedString 的 inlinePresentationIntent.code → 等宽 + 背景
        applyInlineCode(to: result, parsed: parsed, style: style)
        applyLinks(to: result, style: style)
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

    private static func applyLinks(to ns: NSMutableAttributedString, style: MarkdownStyle) {
        let full = NSRange(location: 0, length: ns.length)
        ns.enumerateAttribute(.link, in: full) { value, range, _ in
            guard value != nil else { return }
            ns.addAttributes([.foregroundColor: style.linkColor, .underlineStyle: NSUnderlineStyle.single.rawValue], range: range)
        }
    }
}
