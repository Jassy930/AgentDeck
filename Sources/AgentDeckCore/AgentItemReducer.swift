import Foundation

/// Cumulative-semantics agent item store. v2 (Task 6A) ingests typed
/// `AgentItem` values from the daemon's `ServerEvent::AgentItem` and
/// translates them into the existing `UIItem` rendering shape (kept stable
/// to preserve all rendering work from v0.1).
///
/// The daemon now emits cumulative AgentItems (each event is the complete
/// current state), so the reducer no longer needs delta accumulation logic
/// — each `apply` replaces the matching slot.
public struct AgentItemStore {
    public var items: [UIItem] = []
    public var itemIndexById: [String: Int] = [:]

    public init() {}
}

public enum AgentItemReducer {
    /// Apply a typed v2 AgentItem to the store. The store key is a stable id
    /// derived from item content + a monotonic per-store sequence — since
    /// daemon AgentItems don't carry their own id we synthesize one per
    /// (kind, position) pair using the caller-provided `itemId`.
    public static func apply(_ item: AgentItem, itemId: String, into store: inout AgentItemStore) {
        var ui = store.itemIndexById[itemId].flatMap { idx in
            store.items.indices.contains(idx) ? store.items[idx] : nil
        } ?? UIItem(id: itemId, lifecycle: "completed", kind: kindLabel(for: item))
        ui.id = itemId
        ui.kind = kindLabel(for: item)
        ui.lifecycle = "completed"
        populate(&ui, from: item)
        if let idx = store.itemIndexById[itemId], store.items.indices.contains(idx) {
            store.items[idx] = ui
        } else {
            store.itemIndexById[itemId] = store.items.count
            store.items.append(ui)
        }
    }

    /// Map AgentItem variant → legacy `UIItem.kind` label, kept for UI compat.
    public static func kindLabel(for item: AgentItem) -> String {
        switch item {
        case .userMessage: "user"
        case .assistantMessage: "message"
        case .reasoning: "reasoning"
        case .shell: "shell"
        case .diff: "fileEdit"
        case .plan: "plan"
        case .imageReference: "media"
        case .toolCall: "toolCall"
        case .raw: "raw"
        }
    }

    private static func populate(_ ui: inout UIItem, from item: AgentItem) {
        switch item {
        case .userMessage(let text, _),
             .assistantMessage(let text, _),
             .reasoning(let text, _):
            ui.text = text
            ui.textBuffer.replace(with: text)
            ui.hasNonWhitespaceText = agentDeckContainsNonWhitespace(text)
        case .shell(let command, let status, let exitCode, let durationMs, _):
            ui.command = command
            ui.statusName = status.rawValue
            ui.exitCode = exitCode
            if let durationMs { ui.durationMs = Int(durationMs) }
        case .diff(let files, _):
            if let first = files.first {
                ui.path = first.path
                ui.statusName = first.status.rawValue
                ui.diff = first.patch ?? ""
                ui.diffBuffer.replace(with: first.patch ?? "")
                ui.changes = files.map { f in
                    HistoryFileChange(path: f.path, diff: f.patch ?? "", changeKind: f.status.rawValue)
                }
            }
        case .plan(let steps, _):
            let serialized = steps.map { step -> String in
                let detail = step.detail.map { ": \($0)" } ?? ""
                return "[\(step.status.rawValue)] \(step.title)\(detail)"
            }
            ui.text = serialized.joined(separator: "\n")
            ui.textBuffer.replace(with: ui.text)
        case .imageReference(let savedPath, let originalPath, _):
            ui.mediaKind = "image"
            ui.savedPath = savedPath ?? ""
            ui.path = originalPath ?? savedPath ?? ""
        case .toolCall(let name, let args, let result, let meta):
            ui.tool = name
            ui.server = stringExtension("server", from: meta) ?? ""
            ui.namespace = stringExtension("namespace", from: meta) ?? ""
            ui.statusName = stringExtension("status", from: meta) ?? ""
            ui.durationMs = integerExtension("durationMs", from: meta)
            ui.resourceUri = stringExtension("resourceUri", from: meta)
                ?? stringExtension("mcpAppResourceUri", from: meta)
                ?? ""
            ui.action = stringExtension("actionName", from: meta) ?? ""
            ui.toolKind = ui.server.isEmpty && ui.namespace.isEmpty ? "generic" : "mcp"
            let metadataReportsError = booleanExtension("isError", from: meta) == true
            ui.success = metadataReportsError ? false : nil
            if let argsData = try? JSONSerialization.data(
                withJSONObject: AgentItemReducer.unwrap(args.value),
                options: [.sortedKeys]
            ), let argsStr = String(data: argsData, encoding: .utf8) {
                ui.arguments = argsStr
            }
            if let result {
                if let resData = try? JSONSerialization.data(
                    withJSONObject: AgentItemReducer.unwrap(result.value),
                    options: [.sortedKeys]
                ), let resStr = String(data: resData, encoding: .utf8) {
                    ui.result = resStr
                }
                if !metadataReportsError,
                   let resultObject = result.value as? [String: Any],
                   let success = resultObject["success"] as? Bool {
                    ui.success = success
                }
            }
        case .raw(let rawKind, let rawPayload, _):
            ui.descriptionText = "unsupported item type: \(rawKind)"
            ui.text = rawPayload
        }
    }

    /// JSONSerialization rejects raw primitives at top level (it expects an
    /// object/array). Wrap primitives so they round-trip cleanly.
    private static func unwrap(_ value: Any) -> Any {
        if JSONSerialization.isValidJSONObject(value) {
            return value
        }
        // Wrap as single-item array so JSONSerialization can encode it; the
        // caller surfaces this as the argument blob anyway.
        return [value]
    }

    private static func stringExtension(_ key: String, from meta: AgentItemMeta) -> String? {
        meta.vendorExtensions[key]?.value as? String
    }

    private static func booleanExtension(_ key: String, from meta: AgentItemMeta) -> Bool? {
        meta.vendorExtensions[key]?.value as? Bool
    }

    private static func integerExtension(_ key: String, from meta: AgentItemMeta) -> Int? {
        guard let value = meta.vendorExtensions[key]?.value else { return nil }
        switch value {
        case let value as Int:
            return value
        case let value as Int64:
            return Int(exactly: value)
        case let value as Double where value.isFinite && value.rounded() == value:
            return Int(exactly: value)
        case let value as NSNumber:
            return value.intValue
        default:
            return nil
        }
    }
}
