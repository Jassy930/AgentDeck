import Foundation

/// Semantic categories used to describe a burst of real tool activity without
/// exposing adapter-specific tool names as the primary UI language.
public enum ToolActivityCategory: String, Hashable {
    case read
    case command
    case edit
    case search
    case image
    case tool
    case mixed
}

/// Pure, platform-neutral presentation rules for a collapsed tool-activity
/// group. The macOS cell maps `primaryCategory` to an SF Symbol; iOS keeps the
/// grouping policy disabled and is therefore unaffected.
public enum ToolActivityGroupPresentation {
    private enum ActivityState: Equatable {
        case failed
        case running
        case pending
        case completed
        case canceled
        case unknown
    }

    /// These are execution records rather than user-visible prose/artifacts.
    /// Media and collaboration rows intentionally remain hard boundaries.
    public static func isGroupable(_ item: UIItem) -> Bool {
        guard ["shell", "fileEdit", "webSearch", "toolCall"].contains(item.kind) else {
            return false
        }
        guard item.kind == "toolCall" else { return true }

        if item.activityKind.caseInsensitiveCompare("collaboration") == .orderedSame {
            return false
        }
        if item.activityKind.caseInsensitiveCompare("contextMaintenance") == .orderedSame {
            return false
        }

        // Some adapters currently lower collaboration controls to a generic
        // toolCall. Keep their task/status affordance outside execution groups
        // even before a richer neutral subtype reaches UIItem.
        let surface = [item.server, item.namespace, item.tool]
            .joined(separator: "/")
            .lowercased()
        return !containsAny(surface, [
            "collaboration", "spawn_agent", "spawnagent", "followup_task",
            "followuptask", "send_message", "sendmessage", "wait_agent",
            "waitagent", "list_agents", "listagents", "interrupt_agent",
            "interruptagent",
        ])
    }

    public static func category(for item: UIItem) -> ToolActivityCategory {
        switch item.kind {
        case "shell":
            return .command
        case "fileEdit":
            return .edit
        case "webSearch":
            return .search
        case "toolCall":
            let components = [item.server, item.namespace, item.tool, item.toolKind]
                .map { $0.lowercased() }
                .filter { !$0.isEmpty }
            if componentsMatch(components, tokens: ["view_image", "screenshot", "image", "photo"]) {
                return .image
            }
            if componentsMatch(components, tokens: ["apply_patch", "write", "edit", "patch", "replace_file"]) {
                return .edit
            }
            if components.contains("rg")
                || componentsMatch(components, tokens: ["grep", "glob", "search", "find", "query"]) {
                return .search
            }
            if componentsMatch(
                components,
                tokens: ["read", "read_file", "load_file", "open_file", "list_files"]
            ) {
                return .read
            }
            if componentsMatch(components, tokens: ["exec", "shell", "bash", "terminal", "command"]) {
                return .command
            }
            return .tool
        default:
            return .tool
        }
    }

    public static func primaryCategory(in items: [UIItem]) -> ToolActivityCategory {
        let categories = Set(activityItems(in: items).map(category(for:)))
        guard categories.count == 1, let category = categories.first else { return .mixed }
        return category
    }

    /// Natural-language summary such as “已读取 1 个文件并运行 3 个命令”.
    public static func summary(_ items: [UIItem]) -> String {
        let activities = activityItems(in: items)
        guard !activities.isEmpty else { return "工具活动" }

        var orderedCategories: [ToolActivityCategory] = []
        var counts: [ToolActivityCategory: Int] = [:]
        for item in activities {
            let category = category(for: item)
            if counts[category] == nil { orderedCategories.append(category) }
            counts[category, default: 0] += unitCount(for: item, category: category)
        }

        let actions = orderedCategories.map { category in
            actionPhrase(for: category, count: counts[category, default: 0])
        }
        let states = activities.map(activityState(for:))
        let prefix: String
        if states.allSatisfy({ $0 == .completed }) {
            prefix = "已"
        } else if states.contains(.running), !states.contains(.failed) {
            prefix = "正在"
        } else {
            // Pending, failed, canceled and unknown states stay neutral. The
            // adjacent status label carries the precise lifecycle without the
            // title inventing either completion or success.
            prefix = ""
        }
        var result = prefix + joinedActions(actions)

        // Opaque generic surfaces (for example node_repl/js) often carry a
        // meaningful operation title in arguments. Preserve one concise clue
        // while keeping the full per-call payload behind the disclosure.
        if orderedCategories == [.tool] {
            let activeActivities = activities.filter {
                let state = activityState(for: $0)
                return state == .running || state == .pending
            }
            let contextCandidates = activeActivities.isEmpty ? activities : activeActivities
            if let context = contextCandidates.reversed().lazy
                .map(ToolPresentation.toolContextSummary)
                .first(where: { !$0.isEmpty }) {
                result += "：\(context)"
                if activities.count > 1 { result += "等" }
            }
        }
        return result
    }

    /// Semantic state used by the macOS cell for color. Failure always remains
    /// visible even when other calls in the same burst are still running.
    public static func semanticStatus(_ items: [UIItem]) -> String {
        let states = activityItems(in: items).map(activityState(for:))
        if states.contains(.failed) { return "failed" }
        if states.contains(.running) { return "running" }
        if states.contains(.pending) { return "pending" }
        if !states.isEmpty, states.allSatisfy({ $0 == .completed }) { return "completed" }
        if !states.isEmpty, states.allSatisfy({ $0 == .canceled }) { return "canceled" }
        return ""
    }

    public static func statusSummary(_ items: [UIItem]) -> String {
        let activities = activityItems(in: items)
        guard !activities.isEmpty else { return "" }
        let states = activities.map(activityState(for:))
        let failures = states.filter { $0 == .failed }.count
        if failures > 0 {
            return "\(failures) 项失败"
        }
        if states.contains(.running) { return "进行中" }
        if states.contains(.pending) { return "等待中" }
        if states.allSatisfy({ $0 == .canceled }) { return "已取消" }
        if states.allSatisfy({ $0 == .completed }),
           activities.allSatisfy({ $0.durationMs != nil }) {
            let total = activities.compactMap(\.durationMs).reduce(0, +)
            return formattedDuration(total)
        }
        return ""
    }

    private static func activityItems(in items: [UIItem]) -> [UIItem] {
        items.filter(isGroupable)
    }

    private static func containsAny(_ value: String, _ needles: [String]) -> Bool {
        needles.contains(where: value.contains)
    }

    /// Match tool-name components at a semantic boundary. Plain substring
    /// matching turns `create_thread` into a read operation because `thread`
    /// contains “read”; prefix/delimiter matching keeps names honest while
    /// still covering forms such as `readMcpResource` and `memory_search`.
    private static func componentsMatch(_ components: [String], tokens: [String]) -> Bool {
        components.contains { component in
            tokens.contains { token in
                component == token
                    || component.hasPrefix(token)
                    || component.contains("_\(token)")
                    || component.contains("-\(token)")
            }
        }
    }

    private static func actionPhrase(for category: ToolActivityCategory, count: Int) -> String {
        switch category {
        case .read: return "读取 \(count) 个文件"
        case .command: return "运行 \(count) 个命令"
        case .edit: return "修改 \(count) 个文件"
        case .search: return "执行 \(count) 次搜索"
        case .image: return "查看 \(count) 张图像"
        case .tool, .mixed: return "执行 \(count) 项工具操作"
        }
    }

    private static func unitCount(for item: UIItem, category: ToolActivityCategory) -> Int {
        // A single neutral Diff activity can describe changes to several files.
        // Keep the right-side "N 项" count tied to execution records, while the
        // natural-language action accurately reports the number of files.
        if category == .edit {
            return max(item.changes.count, 1)
        }
        return 1
    }

    private static func joinedActions(_ actions: [String]) -> String {
        guard let last = actions.last else { return "执行工具操作" }
        if actions.count == 1 { return last }
        return actions.dropLast().joined(separator: "、") + "并" + last
    }

    private static func activityState(for item: UIItem) -> ActivityState {
        if item.success == false || !item.errorText.isEmpty {
            return .failed
        }
        if item.kind == "shell", let exitCode = item.exitCode, exitCode != 0 {
            return .failed
        }

        let raw: String
        if !item.statusName.isEmpty {
            raw = item.statusName
        } else if item.success == true || !item.result.isEmpty {
            raw = "completed"
        } else if item.kind == "fileEdit" || item.kind == "toolCall" {
            // A diff's statusName describes the file change (added/modified),
            // not execution success. Tool-call lifecycle is also a legacy
            // neutral fallback that may be hard-coded to completed at start.
            // Neither is enough evidence to invent a green completion state.
            return .unknown
        } else {
            raw = item.lifecycle
        }

        switch raw.lowercased() {
        case "failed", "failure", "error": return .failed
        case "running", "starting", "inprogress", "in_progress", "in progress": return .running
        case "pending", "queued": return .pending
        case "completed", "complete", "done", "success", "succeeded": return .completed
        case "canceled", "cancelled": return .canceled
        default: return .unknown
        }
    }

    private static func formattedDuration(_ durationMs: Int) -> String {
        durationMs < 1_000
            ? "\(durationMs)ms"
            : String(format: "%.1fs", Double(durationMs) / 1_000)
    }
}
