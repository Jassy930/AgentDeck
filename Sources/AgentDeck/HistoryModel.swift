import Foundation

/// Neutral summary for one persisted agent thread. Mirrors the daemon's
/// history shape; Swift never parses vendor thread JSON directly.
struct HistoryThreadSummary: Identifiable, Codable, Equatable {
    let id: String
    var name: String?
    var preview: String
    var cwd: String
    var createdAt: Int
    var updatedAt: Int
    var status: String
    var modelProvider: String
    var source: String

    var displayTitle: String {
        let title = (name ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        if !title.isEmpty { return title }
        let fallback = preview.trimmingCharacters(in: .whitespacesAndNewlines)
        return fallback.isEmpty ? "Untitled thread" : fallback
    }
}

struct HistoryProjectGroup: Identifiable, Equatable {
    var id: String { cwd }
    let cwd: String
    let threads: [HistoryThreadSummary]

    var projectName: String {
        URL(fileURLWithPath: cwd).lastPathComponent
    }

    static func group(_ threads: [HistoryThreadSummary]) -> [HistoryProjectGroup] {
        let grouped = Dictionary(grouping: threads, by: \.cwd)
        return grouped.map { cwd, items in
            HistoryProjectGroup(
                cwd: cwd,
                threads: items.sorted { lhs, rhs in
                    if lhs.updatedAt != rhs.updatedAt {
                        return lhs.updatedAt > rhs.updatedAt
                    }
                    return lhs.id < rhs.id
                }
            )
        }
        .sorted { lhs, rhs in
            let leftUpdated = lhs.threads.first?.updatedAt ?? 0
            let rightUpdated = rhs.threads.first?.updatedAt ?? 0
            if leftUpdated != rightUpdated {
                return leftUpdated > rightUpdated
            }
            return lhs.cwd < rhs.cwd
        }
    }
}

struct HistoryThreadListPayload: Codable, Equatable {
    var threads: [HistoryThreadSummary]
    var nextCursor: String?
}

struct HistoryReplayItem: Codable, Equatable, Identifiable {
    let id: String
    var lifecycle: String
    var kind: String
    var text: String = ""
    var command: String = ""
    var output: String?
    var exitCode: Int?
    var path: String = ""
    var diff: String?
    var description: String?
    var query: String = ""
    var action: String = ""
    var actionQuery: String?
    var queries: [String] = []
    var url: String?
    var pattern: String?

    enum CodingKeys: String, CodingKey {
        case id, lifecycle, kind, text, command, output, exitCode, path, diff, description
        case query, action, actionQuery, queries, url, pattern
    }

    init(
        id: String,
        lifecycle: String,
        kind: String,
        text: String = "",
        command: String = "",
        output: String? = nil,
        exitCode: Int? = nil,
        path: String = "",
        diff: String? = nil,
        description: String? = nil,
        query: String = "",
        action: String = "",
        actionQuery: String? = nil,
        queries: [String] = [],
        url: String? = nil,
        pattern: String? = nil
    ) {
        self.id = id
        self.lifecycle = lifecycle
        self.kind = kind
        self.text = text
        self.command = command
        self.output = output
        self.exitCode = exitCode
        self.path = path
        self.diff = diff
        self.description = description
        self.query = query
        self.action = action
        self.actionQuery = actionQuery
        self.queries = queries
        self.url = url
        self.pattern = pattern
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        lifecycle = try c.decode(String.self, forKey: .lifecycle)
        kind = try c.decode(String.self, forKey: .kind)
        text = try c.decodeIfPresent(String.self, forKey: .text) ?? ""
        command = try c.decodeIfPresent(String.self, forKey: .command) ?? ""
        output = try c.decodeIfPresent(String.self, forKey: .output)
        exitCode = try c.decodeIfPresent(Int.self, forKey: .exitCode)
        path = try c.decodeIfPresent(String.self, forKey: .path) ?? ""
        diff = try c.decodeIfPresent(String.self, forKey: .diff)
        description = try c.decodeIfPresent(String.self, forKey: .description)
        query = try c.decodeIfPresent(String.self, forKey: .query) ?? ""
        action = try c.decodeIfPresent(String.self, forKey: .action) ?? ""
        actionQuery = try c.decodeIfPresent(String.self, forKey: .actionQuery)
        queries = try c.decodeIfPresent([String].self, forKey: .queries) ?? []
        url = try c.decodeIfPresent(String.self, forKey: .url)
        pattern = try c.decodeIfPresent(String.self, forKey: .pattern)
    }
}

struct HistoryThreadDetail: Codable, Equatable {
    var thread: HistoryThreadSummary
    var items: [HistoryReplayItem]
}
