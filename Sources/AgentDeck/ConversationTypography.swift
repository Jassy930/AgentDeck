import AppKit

/// 会话流排版契约。字号与行高倍率来自设计系统生成 token；这里仅负责把
/// Web 端的语言行高语义映射为 TextKit 可消费的段落样式。
enum ConversationLineHeightLanguage: Equatable {
    case automatic
    case cjk
    case latin
}

enum ConversationTypography {
    static var bodyFont: NSFont {
        .systemFont(ofSize: DesignTokens.typeBody, weight: .regular)
    }

    static var calloutFont: NSFont {
        .systemFont(ofSize: DesignTokens.typeCallout, weight: .regular)
    }

    static var reasoningFont: NSFont { calloutFont }

    static var captionFont: NSFont {
        .systemFont(ofSize: DesignTokens.typeCaption, weight: .regular)
    }

    static var monoFont: NSFont {
        .monospacedSystemFont(ofSize: DesignTokens.typeMono, weight: .regular)
    }

    static func targetLineHeight(
        for font: NSFont,
        text: String,
        language: ConversationLineHeightLanguage = .automatic
    ) -> CGFloat {
        let resolved = resolvedLanguage(for: text, requested: language)
        let multiplier = resolved == .latin
            ? DesignTokens.lineHeightLatin
            : DesignTokens.lineHeightCJK
        return font.pointSize * multiplier
    }

    static func paragraphStyle(
        for font: NSFont,
        text: String,
        language: ConversationLineHeightLanguage = .automatic
    ) -> NSParagraphStyle {
        let style = NSMutableParagraphStyle()
        let lineHeight = targetLineHeight(for: font, text: text, language: language)
        // CSS line-height 以字号为基准；TextKit 的 lineHeightMultiple 以字体自然
        // 行框为基准，两者不等价，因此直接设置目标行框，保证渲染和测高一致。
        style.minimumLineHeight = lineHeight
        style.maximumLineHeight = lineHeight
        style.lineSpacing = 0
        style.paragraphSpacing = 0
        style.paragraphSpacingBefore = 0
        return style
    }

    /// 给每个段落独立选择 CJK / Latin 行高。混排段落只要含 CJK 字符，就采用
    /// CJK 行高；纯拉丁段落使用更紧凑的 Latin 行高。
    static func applyParagraphStyles(
        to attributed: NSMutableAttributedString,
        font: NSFont,
        language: ConversationLineHeightLanguage = .automatic
    ) {
        guard attributed.length > 0 else { return }
        let string = attributed.string as NSString
        var location = 0

        while location < string.length {
            var paragraphStart = 0
            var paragraphEnd = 0
            var contentsEnd = 0
            string.getParagraphStart(
                &paragraphStart,
                end: &paragraphEnd,
                contentsEnd: &contentsEnd,
                for: NSRange(location: location, length: 0)
            )

            let contentRange = NSRange(
                location: paragraphStart,
                length: contentsEnd - paragraphStart
            )
            let paragraphRange = NSRange(
                location: paragraphStart,
                length: paragraphEnd - paragraphStart
            )
            let paragraphText = string.substring(with: contentRange)
            attributed.addAttribute(
                .paragraphStyle,
                value: paragraphStyle(for: font, text: paragraphText, language: language),
                range: paragraphRange
            )

            guard paragraphEnd > location else { break }
            location = paragraphEnd
        }
    }

    private static func resolvedLanguage(
        for text: String,
        requested: ConversationLineHeightLanguage
    ) -> ConversationLineHeightLanguage {
        switch requested {
        case .cjk, .latin:
            return requested
        case .automatic:
            if text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                return .cjk
            }
            return containsCJK(text) ? .cjk : .latin
        }
    }

    private static func containsCJK(_ text: String) -> Bool {
        text.unicodeScalars.contains { scalar in
            switch scalar.value {
            case 0x2E80...0x303F,   // CJK radicals / punctuation
                 0x3040...0x30FF,   // Hiragana / Katakana
                 0x31F0...0x31FF,   // Katakana extensions
                 0x3400...0x4DBF,   // CJK Extension A
                 0x4E00...0x9FFF,   // CJK Unified Ideographs
                 0xAC00...0xD7AF,   // Hangul syllables
                 0xF900...0xFAFF,   // CJK Compatibility Ideographs
                 0x20000...0x2FA1F: // CJK extensions / compatibility supplement
                return true
            default:
                return false
            }
        }
    }
}
