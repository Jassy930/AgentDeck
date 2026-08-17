import Foundation

/// 清洗 Claude Code CLI 注入到用户消息里的 XML 元数据噪声。
///
/// CLI 会把本地命令/斜杠命令的执行痕迹以成对标签包进 userMessage.text：
///   `<local-command-caveat>Caveat: …</local-command-caveat>`
///   `<command-name>/clear</command-name><command-message>…</command-message><command-args>…</command-args>`
///   `<command-stdout>…</command-stdout>` / `<command-stderr>…</command-stderr>`
///   `<local-command-stdout>…</local-command-stdout>` / `<local-command-stderr>…</local-command-stderr>`
/// 这些是 CLI 内部管道，不属于用户真正输入。设计系统的对话流是干净的
/// 「用户气泡 + 助手 item」轮次，不应出现这些标签。
///
/// 本工具是纯函数（可测），既用于对话流构建（`makeConversationTurns`），
/// 也用于侧栏标题/预览的清洗。
public enum CommandMessageSanitizer {
    /// 需整块移除（含标签内文字）的噪声标签。
    private static let noiseTags = [
        "local-command-caveat",
        "command-name",
        "command-message",
        "command-args",
        "command-stdout",
        "command-stderr",
        "local-command-stdout",
        "local-command-stderr",
        "command-contents",
    ]

    /// 返回清洗后的用户文本；若整条只是 CLI 命令元数据（应从对话流/标题中隐藏），
    /// 返回 `nil`。带真实正文的消息会剥离残留标签后原样返回。
    public static func sanitize(userText raw: String) -> String? {
        var text = raw
        for tag in noiseTags {
            text = removeBlocks(of: tag, in: text)
        }
        // 兜底：移除任何残留的成对 `<command-*>…</command-*>` 块。
        text = removeBlocks(matching: "<command-[a-z-]+(?:\\s[^>]*)?>[\\s\\S]*?</command-[a-z-]+>", in: text)
        let cleaned = text.trimmingCharacters(in: .whitespacesAndNewlines)
        return cleaned.isEmpty ? nil : cleaned
    }

    /// 清洗用于展示的文本（标题/预览）：与 `sanitize(userText:)` 同规则，
    /// 但纯噪声时返回空串而非 `nil`，方便调用方走既有的空串回退逻辑。
    public static func cleanedForDisplay(_ raw: String) -> String {
        sanitize(userText: raw) ?? ""
    }

    private static func removeBlocks(of tag: String, in text: String) -> String {
        removeBlocks(matching: "<\(tag)(?:\\s[^>]*)?>[\\s\\S]*?</\(tag)>", in: text)
    }

    private static func removeBlocks(matching pattern: String, in text: String) -> String {
        guard let re = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]) else {
            return text
        }
        let range = NSRange(text.startIndex..., in: text)
        return re.stringByReplacingMatches(in: text, options: [], range: range, withTemplate: "")
    }
}
