import Foundation

/// Pure presentation helpers for tool / shell / web-search rows in
/// `SessionView`. Extracted from `SessionView` so the string/metadata logic can
/// be unit-tested without standing up a SwiftUI view tree. All functions are
/// `static`, depend only on their parameters, and must remain free of any
/// SwiftUI / `@State` / model access (Eng D2: UI side stays neutral, but here
/// the stricter rule is "pure transform over a `UIItem`").
public enum ToolPresentation {

    /// Render a "Show output (N lines)" style label for a disclosure trigger.
    /// `noun` lets the caller switch the noun (e.g. "diff"). One-line or empty
    /// payloads collapse to "Show <noun>" — the line count is only useful when
    /// the user is about to expand multi-line text.
    public static func outputLabel(_ text: String, noun: String = "output") -> String {
        let lines = text.split(separator: "\n", omittingEmptySubsequences: false).count
        return lines <= 1
            ? "Show \(noun)"
            : "Show \(noun) (\(lines) lines)"
    }

    /// Title for a web-search row. Mirrors the daemon's `action` taxonomy and
    /// falls back to "Web search · <action>" for unknown verbs so a future
    /// adapter doesn't silently render an empty header.
    public static func webSearchTitle(_ item: UIItem) -> String {
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
    public static func shellMetadata(_ item: UIItem) -> [String] {
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
    public static func toolName(_ item: UIItem) -> String {
        let prefix = [item.server, item.namespace].first { !$0.isEmpty }
        if let prefix {
            return "\(prefix)/\(item.tool)"
        }
        if !item.tool.isEmpty { return item.tool }
        return item.toolKind == "mcp" ? "MCP tool" : "Tool"
    }

    /// Compact, discriminating context for a tool-call header. Tool payloads
    /// often contain a large JSON object, but the path/query target is enough
    /// to tell adjacent `Read` / `Grep` calls apart while they are collapsed.
    /// Full arguments remain available in `toolPayload(_:)`.
    public static func toolContextSummary(_ item: UIItem) -> String {
        var fields: [String: Any] = [:]
        if let data = item.arguments.data(using: .utf8),
           let decoded = try? JSONSerialization.jsonObject(with: data),
           let dictionary = decoded as? [String: Any] {
            fields = dictionary
        }

        // Malformed/adapter-specific payloads can contain aliases such as both
        // `file_path` and `filePath`; keep the first value instead of trapping
        // on duplicate normalized keys.
        var normalizedFields: [String: Any] = [:]
        for key in fields.keys.sorted() where normalizedFields[normalizedKey(key)] == nil {
            normalizedFields[normalizedKey(key)] = fields[key]
        }
        var parts: [String] = []

        let queryKeys = ["query", "pattern", "searchquery", "searchterm", "needle", "glob"]
        if let query = firstDisplayValue(in: normalizedFields, keys: queryKeys) {
            parts.append("query: \(query)")
        }

        let pathKeys = [
            "filepath", "path", "notebookpath", "directorypath", "directory",
            "folder", "cwd", "root", "url", "uri",
        ]
        if let path = firstDisplayValue(in: normalizedFields, keys: pathKeys) {
            parts.append("path: \(path)")
        } else if !item.resourceUri.isEmpty {
            parts.append("path: \(compactPreview(item.resourceUri))")
        }

        return parts.joined(separator: " · ")
    }

    /// One canonical status for the compact header. Prefer explicit failure
    /// evidence, then adapter status, then completion evidence, and finally
    /// the neutral lifecycle value carried by legacy history items.
    public static func toolStatus(_ item: UIItem) -> String {
        if item.success == false || !item.errorText.isEmpty { return "failed" }
        if !item.statusName.isEmpty { return item.statusName }
        if item.success == true || !item.result.isEmpty { return "completed" }
        return item.lifecycle
    }

    /// Caption parts for a generic tool-call row (status, success/failed,
    /// duration, resource URI). Mirrors `shellMetadata`'s contract.
    public static func toolMetadata(_ item: UIItem) -> [String] {
        var parts = [item.statusName].filter { !$0.isEmpty }
        if let success = item.success { parts.append(success ? "success" : "failed") }
        if let duration = item.durationMs { parts.append("\(duration)ms") }
        if !item.resourceUri.isEmpty { parts.append(item.resourceUri) }
        return parts
    }

    /// Human-readable payload for a tool call: arguments / result / error,
    /// each pretty-printed (compact JSON → indented) so the disclosure body is
    /// legible instead of a single wrapped line. Empty sections are skipped.
    public static func toolPayload(_ item: UIItem) -> String {
        var blocks: [String] = []
        if !item.arguments.isEmpty { blocks.append("arguments\n" + prettyJSON(item.arguments)) }
        if !item.result.isEmpty { blocks.append("result\n" + prettyJSON(item.result)) }
        if !item.errorText.isEmpty { blocks.append("error\n" + item.errorText) }
        return blocks.joined(separator: "\n\n")
    }

    /// Re-indent a compact JSON string. Falls back to the original text when it
    /// isn't valid JSON (e.g. a plain string result) so nothing is ever lost.
    public static func prettyJSON(_ compact: String) -> String {
        guard let data = compact.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data),
              let pretty = try? JSONSerialization.data(
                withJSONObject: object,
                options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]),
              let string = String(data: pretty, encoding: .utf8)
        else { return compact }
        return string
    }

    private static func normalizedKey(_ key: String) -> String {
        key.lowercased().filter { $0.isLetter || $0.isNumber }
    }

    private static func firstDisplayValue(
        in fields: [String: Any],
        keys: [String]
    ) -> String? {
        for key in keys {
            guard let value = fields[key] else { continue }
            if let string = value as? String, !string.isEmpty {
                let preview = compactPreview(string)
                if !preview.isEmpty { return preview }
            }
            if let number = value as? NSNumber {
                return number.stringValue
            }
        }
        return nil
    }

    private static func compactPreview(_ value: String, limit: Int = 180) -> String {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.count > limit else { return trimmed }
        return String(trimmed.prefix(limit - 1)) + "…"
    }
}
