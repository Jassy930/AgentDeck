import Foundation

/// Neutral summary for one persisted agent thread. Mirrors the daemon's
/// history shape; Swift never parses vendor thread JSON directly.
///
/// `Hashable` 保留该值模型在客户端集合中的稳定值语义。
public struct HistoryThreadSummary: Identifiable, Codable, Hashable, Sendable {
    public let id: String
    public var name: String?
    public var preview: String
    public var cwd: String
    public var createdAt: Int
    public var updatedAt: Int
    public var status: String
    public var modelProvider: String
    public var source: String
    public var agentKind: AgentKind

    public init(id: String, name: String? = nil, preview: String, cwd: String, createdAt: Int, updatedAt: Int, status: String, modelProvider: String, source: String, agentKind: AgentKind) {
        self.id = id
        self.name = name
        self.preview = preview
        self.cwd = cwd
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.status = status
        self.modelProvider = modelProvider
        self.source = source
        self.agentKind = agentKind
    }

    public var displayTitle: String {
        let title = (name ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        if !title.isEmpty { return title }
        // 兜底清洗预览里的 CLI 命令元数据标签（持久化线程的 preview 可能仍带标签）。
        let fallback = CommandMessageSanitizer.cleanedForDisplay(preview)
        return fallback.isEmpty ? "Untitled thread" : fallback
    }
}

/// `Hashable` 同 `HistoryThreadSummary`，用于稳定的值集合语义。
public struct HistoryProjectGroup: Identifiable, Hashable {
    public var id: String { cwd }
    public let cwd: String
    public let threads: [HistoryThreadSummary]

    public init(cwd: String, threads: [HistoryThreadSummary]) {
        self.cwd = cwd
        self.threads = threads
    }

    public var projectName: String {
        URL(fileURLWithPath: cwd).lastPathComponent
    }

    public static func group(_ threads: [HistoryThreadSummary]) -> [HistoryProjectGroup] {
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

public struct HistoryThreadListPayload: Codable, Equatable {
    public var threads: [HistoryThreadSummary]
    public var nextCursor: String?

    public init(threads: [HistoryThreadSummary], nextCursor: String? = nil) {
        self.threads = threads
        self.nextCursor = nextCursor
    }
}

public struct HistoryReference: Codable, Equatable {
    public var kind: String
    public var text: String?
    public var url: String?
    public var path: String?
    public var name: String?

    public init(kind: String, text: String? = nil, url: String? = nil, path: String? = nil, name: String? = nil) {
        self.kind = kind
        self.text = text
        self.url = url
        self.path = path
        self.name = name
    }
}

public struct HistoryHookFragment: Codable, Equatable {
    public var hookRunId: String
    public var text: String

    public init(hookRunId: String, text: String) {
        self.hookRunId = hookRunId
        self.text = text
    }
}

public struct HistoryFileChange: Codable, Equatable {
    public var path: String
    public var diff: String
    public var changeKind: String

    public init(path: String, diff: String, changeKind: String) {
        self.path = path
        self.diff = diff
        self.changeKind = changeKind
    }
}

public struct HistoryToolAction: Codable, Equatable {
    public var kind: String
    public var command: String
    public var path: String?
    public var name: String?
    public var query: String?

    public init(kind: String, command: String, path: String? = nil, name: String? = nil, query: String? = nil) {
        self.kind = kind
        self.command = command
        self.path = path
        self.name = name
        self.query = query
    }
}

public struct HistoryReplayItem: Codable, Equatable, Identifiable {
    public let id: String
    public var lifecycle: String
    public var kind: String
    public var text: String = ""
    public var command: String = ""
    public var output: String?
    public var exitCode: Int?
    public var path: String = ""
    public var diff: String?
    public var description: String?
    public var query: String = ""
    public var action: String = ""
    public var actionQuery: String?
    public var queries: [String] = []
    public var url: String?
    public var pattern: String?
    public var attachments: [HistoryReference] = []
    public var phase: String?
    public var memoryCitation: String?
    public var cwd: String?
    public var status: String?
    public var durationMs: Int?
    public var source: String?
    public var processId: String?
    public var actions: [HistoryToolAction] = []
    public var changes: [HistoryFileChange] = []
    public var fragments: [HistoryHookFragment] = []
    public var toolKind: String = ""
    public var server: String?
    public var namespace: String?
    public var tool: String = ""
    public var arguments: String = ""
    public var result: String?
    public var error: String?
    public var success: Bool?
    public var resourceUri: String?
    public var contentItems: [HistoryReference] = []
    public var prompt: String?
    public var model: String?
    public var reasoningEffort: String?
    public var senderThreadId: String?
    public var receiverThreadIds: [String] = []
    public var agentsStates: String?
    public var mediaKind: String = ""
    public var savedPath: String?
    public var revisedPrompt: String?
    public var review: String?

    public enum CodingKeys: String, CodingKey {
        case id, lifecycle, kind, text, command, output, exitCode, path, diff, description
        case query, action, actionQuery, queries, url, pattern
        case attachments, phase, memoryCitation, cwd, status, durationMs, source, processId, actions
        case changes, fragments, toolKind, server, namespace, tool, arguments, result, error, success
        case resourceUri, contentItems, prompt, model, reasoningEffort, senderThreadId
        case receiverThreadIds, agentsStates, mediaKind, savedPath, revisedPrompt, review
    }

    public init(
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
        pattern: String? = nil,
        attachments: [HistoryReference] = [],
        phase: String? = nil,
        memoryCitation: String? = nil,
        cwd: String? = nil,
        status: String? = nil,
        durationMs: Int? = nil,
        source: String? = nil,
        processId: String? = nil,
        actions: [HistoryToolAction] = [],
        changes: [HistoryFileChange] = [],
        fragments: [HistoryHookFragment] = [],
        toolKind: String = "",
        server: String? = nil,
        namespace: String? = nil,
        tool: String = "",
        arguments: String = "",
        result: String? = nil,
        error: String? = nil,
        success: Bool? = nil,
        resourceUri: String? = nil,
        contentItems: [HistoryReference] = [],
        prompt: String? = nil,
        model: String? = nil,
        reasoningEffort: String? = nil,
        senderThreadId: String? = nil,
        receiverThreadIds: [String] = [],
        agentsStates: String? = nil,
        mediaKind: String = "",
        savedPath: String? = nil,
        revisedPrompt: String? = nil,
        review: String? = nil
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
        self.attachments = attachments
        self.phase = phase
        self.memoryCitation = memoryCitation
        self.cwd = cwd
        self.status = status
        self.durationMs = durationMs
        self.source = source
        self.processId = processId
        self.actions = actions
        self.changes = changes
        self.fragments = fragments
        self.toolKind = toolKind
        self.server = server
        self.namespace = namespace
        self.tool = tool
        self.arguments = arguments
        self.result = result
        self.error = error
        self.success = success
        self.resourceUri = resourceUri
        self.contentItems = contentItems
        self.prompt = prompt
        self.model = model
        self.reasoningEffort = reasoningEffort
        self.senderThreadId = senderThreadId
        self.receiverThreadIds = receiverThreadIds
        self.agentsStates = agentsStates
        self.mediaKind = mediaKind
        self.savedPath = savedPath
        self.revisedPrompt = revisedPrompt
        self.review = review
    }

    public init(from decoder: Decoder) throws {
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
        attachments = try c.decodeIfPresent([HistoryReference].self, forKey: .attachments) ?? []
        phase = try c.decodeIfPresent(String.self, forKey: .phase)
        memoryCitation = try c.decodeIfPresent(String.self, forKey: .memoryCitation)
        cwd = try c.decodeIfPresent(String.self, forKey: .cwd)
        status = try c.decodeIfPresent(String.self, forKey: .status)
        durationMs = try c.decodeIfPresent(Int.self, forKey: .durationMs)
        source = try c.decodeIfPresent(String.self, forKey: .source)
        processId = try c.decodeIfPresent(String.self, forKey: .processId)
        actions = try c.decodeIfPresent([HistoryToolAction].self, forKey: .actions) ?? []
        changes = try c.decodeIfPresent([HistoryFileChange].self, forKey: .changes) ?? []
        fragments = try c.decodeIfPresent([HistoryHookFragment].self, forKey: .fragments) ?? []
        toolKind = try c.decodeIfPresent(String.self, forKey: .toolKind) ?? ""
        server = try c.decodeIfPresent(String.self, forKey: .server)
        namespace = try c.decodeIfPresent(String.self, forKey: .namespace)
        tool = try c.decodeIfPresent(String.self, forKey: .tool) ?? ""
        arguments = try c.decodeIfPresent(String.self, forKey: .arguments) ?? ""
        result = try c.decodeIfPresent(String.self, forKey: .result)
        error = try c.decodeIfPresent(String.self, forKey: .error)
        success = try c.decodeIfPresent(Bool.self, forKey: .success)
        resourceUri = try c.decodeIfPresent(String.self, forKey: .resourceUri)
        contentItems = try c.decodeIfPresent([HistoryReference].self, forKey: .contentItems) ?? []
        prompt = try c.decodeIfPresent(String.self, forKey: .prompt)
        model = try c.decodeIfPresent(String.self, forKey: .model)
        reasoningEffort = try c.decodeIfPresent(String.self, forKey: .reasoningEffort)
        senderThreadId = try c.decodeIfPresent(String.self, forKey: .senderThreadId)
        receiverThreadIds = try c.decodeIfPresent([String].self, forKey: .receiverThreadIds) ?? []
        agentsStates = try c.decodeIfPresent(String.self, forKey: .agentsStates)
        mediaKind = try c.decodeIfPresent(String.self, forKey: .mediaKind) ?? ""
        savedPath = try c.decodeIfPresent(String.self, forKey: .savedPath)
        revisedPrompt = try c.decodeIfPresent(String.self, forKey: .revisedPrompt)
        review = try c.decodeIfPresent(String.self, forKey: .review)
    }
}

public struct HistoryThreadDetail: Codable, Equatable {
    public var thread: HistoryThreadSummary
    public var items: [HistoryReplayItem]

    public init(thread: HistoryThreadSummary, items: [HistoryReplayItem]) {
        self.thread = thread
        self.items = items
    }
}
