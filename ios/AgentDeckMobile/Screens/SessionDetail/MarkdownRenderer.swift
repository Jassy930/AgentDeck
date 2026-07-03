import UIKit

/// 第一期用系统 AttributedString(markdown:)（设计文档第 6 节取舍），
/// 不移植 macOS 的 AppKit builder。
enum MarkdownRenderer {
    static func attributed(_ text: String, color: UIColor) -> NSAttributedString {
        var attributed = (try? AttributedString(
            markdown: text,
            options: .init(interpretedSyntax: .inlineOnlyPreservingWhitespace)
        )) ?? AttributedString(text)
        attributed.foregroundColor = color
        attributed.font = .preferredFont(forTextStyle: .body)
        return NSAttributedString(attributed)
    }
}
