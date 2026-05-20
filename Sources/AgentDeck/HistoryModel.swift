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
}

struct HistoryThreadDetail: Codable, Equatable {
    var thread: HistoryThreadSummary
    var items: [HistoryReplayItem]
}
