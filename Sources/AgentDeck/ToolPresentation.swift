import Foundation

/// Pure presentation helpers for tool / shell / web-search rows in
/// `SessionView`. Extracted from `SessionView` so the string/metadata logic can
/// be unit-tested without standing up a SwiftUI view tree. All functions are
/// `static`, depend only on their parameters, and must remain free of any
/// SwiftUI / `@State` / model access (Eng D2: UI side stays neutral, but here
/// the stricter rule is "pure transform over a `UIItem`").
enum ToolPresentation {

    /// Render a "Show output (N lines)" style label for a disclosure trigger.
    /// `noun` lets the caller switch the noun (e.g. "diff"). One-line or empty
    /// payloads collapse to "Show <noun>" — the line count is only useful when
    /// the user is about to expand multi-line text.
    static func outputLabel(_ text: String, noun: String = "output") -> String {
        let lines = text.split(separator: "\n", omittingEmptySubsequences: false).count
        return lines <= 1
            ? "Show \(noun)"
            : "Show \(noun) (\(lines) lines)"
    }

    /// Title for a web-search row. Mirrors the daemon's `action` taxonomy and
    /// falls back to "Web search · <action>" for unknown verbs so a future
    /// adapter doesn't silently render an empty header.
    static func webSearchTitle(_ item: UIItem) -> String {
        switch item.action {
        case "search": return "Web search"
        case "openPage": return "Open web page"
        case "findInPage": return "Find in web page"
        case "other": return "Web search action"
        case "": return "Web search"
        default: return "Web search · \(item.action)"
        }
    }

    /// Caption parts for a shell row (status, cwd, duration, source, pid). The
    /// caller joins them with " · ". Empty fields are skipped at source so the
    /// caller doesn't have to filter again.
    static func shellMetadata(_ item: UIItem) -> [String] {
        var parts: [String] = []
        if !item.statusName.isEmpty { parts.append(item.statusName) }
        if !item.cwdText.isEmpty { parts.append(item.cwdText) }
        if let duration = item.durationMs { parts.append("\(duration)ms") }
        if !item.sourceName.isEmpty { parts.append(item.sourceName) }
        if !item.processId.isEmpty { parts.append("pid \(item.processId)") }
        return parts
    }

    /// Display name for a tool call: `server/tool` or `namespace/tool` when a
    /// scope is present, otherwise the bare tool name. The first non-empty of
    /// `server` then `namespace` wins.
    static func toolName(_ item: UIItem) -> String {
        let prefix = [item.server, item.namespace].first { !$0.isEmpty }
        if let prefix {
            return "\(prefix)/\(item.tool)"
        }
        return item.tool
    }

    /// Caption parts for a generic tool-call row (status, success/failed,
    /// duration, resource URI). Mirrors `shellMetadata`'s contract.
    static func toolMetadata(_ item: UIItem) -> [String] {
        var parts = [item.statusName].filter { !$0.isEmpty }
        if let success = item.success { parts.append(success ? "success" : "failed") }
        if let duration = item.durationMs { parts.append("\(duration)ms") }
        if !item.resourceUri.isEmpty { parts.append(item.resourceUri) }
        return parts
    }
}
