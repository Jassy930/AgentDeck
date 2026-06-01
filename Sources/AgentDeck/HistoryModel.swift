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

struct HistoryThreadRowPresentation: Equatable {
    enum VisualState: Equatable {
        case idle
        case hovered
        case selected
        case opening
    }

    let visualState: VisualState
    let usesFullRowHitTarget = true
    let agentSourceLabel: String
    let agentSourceImageName: String
    let runtimePhase: SessionModel.Phase?
    let unreadEventCount: Int

    init(
        threadId: String,
        selectedThreadId: String?,
        openingThreadId: String?,
        hoveredThreadId: String?,
        modelProvider: String = "",
        source: String = "",
        runtimePhase: SessionModel.Phase? = nil,
        unreadEventCount: Int = 0
    ) {
        if openingThreadId == threadId {
            visualState = .opening
        } else if selectedThreadId == threadId {
            visualState = .selected
        } else if hoveredThreadId == threadId {
            visualState = .hovered
        } else {
            visualState = .idle
        }

        let marker = HistoryAgentSourceMarker(modelProvider: modelProvider, source: source)
        agentSourceLabel = marker.label
        agentSourceImageName = marker.imageName
        self.runtimePhase = runtimePhase
        self.unreadEventCount = unreadEventCount
    }

    var isEmphasized: Bool {
        visualState == .selected || visualState == .opening
    }

    var hasRuntimeIndicator: Bool {
        runtimePhase != nil
    }

    var hasUnreadIndicator: Bool {
        unreadEventCount > 0
    }

    var runtimeStatusLabel: String? {
        runtimePhase?.rawValue
    }
}

struct HistoryAgentSourceMarker: Equatable {
    let label: String
    let imageName: String

    init(modelProvider: String, source: String) {
        let normalizedProvider = modelProvider.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let normalizedSource = source.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()

        if normalizedProvider.contains("openai")
            || normalizedSource.contains("codex")
            || normalizedSource == "cli" {
            label = "Codex"
            imageName = "CodexIcon"
        } else {
            label = normalizedSource.isEmpty ? "Unknown agent" : source
            imageName = "UnknownAgentIcon"
        }
    }
}

struct HistoryThreadListPayload: Codable, Equatable {
    var threads: [HistoryThreadSummary]
    var nextCursor: String?
}

struct HistoryReference: Codable, Equatable {
    var kind: String
    var text: String?
    var url: String?
    var path: String?
    var name: String?
}

struct HistoryHookFragment: Codable, Equatable {
    var hookRunId: String
    var text: String
}

struct HistoryFileChange: Codable, Equatable {
    var path: String
    var diff: String
    var changeKind: String
}

struct HistoryToolAction: Codable, Equatable {
    var kind: String
    var command: String
    var path: String?
    var name: String?
    var query: String?
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
    var attachments: [HistoryReference] = []
    var phase: String?
    var memoryCitation: String?
    var cwd: String?
    var status: String?
    var durationMs: Int?
    var source: String?
    var processId: String?
    var actions: [HistoryToolAction] = []
    var changes: [HistoryFileChange] = []
    var fragments: [HistoryHookFragment] = []
    var toolKind: String = ""
    var server: String?
    var namespace: String?
    var tool: String = ""
    var arguments: String = ""
    var result: String?
    var error: String?
    var success: Bool?
    var resourceUri: String?
    var contentItems: [HistoryReference] = []
    var prompt: String?
    var model: String?
    var reasoningEffort: String?
    var senderThreadId: String?
    var receiverThreadIds: [String] = []
    var agentsStates: String?
    var mediaKind: String = ""
    var savedPath: String?
    var revisedPrompt: String?
    var review: String?

    enum CodingKeys: String, CodingKey {
        case id, lifecycle, kind, text, command, output, exitCode, path, diff, description
        case query, action, actionQuery, queries, url, pattern
        case attachments, phase, memoryCitation, cwd, status, durationMs, source, processId, actions
        case changes, fragments, toolKind, server, namespace, tool, arguments, result, error, success
        case resourceUri, contentItems, prompt, model, reasoningEffort, senderThreadId
        case receiverThreadIds, agentsStates, mediaKind, savedPath, revisedPrompt, review
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

struct HistoryThreadDetail: Codable, Equatable {
    var thread: HistoryThreadSummary
    var items: [HistoryReplayItem]
}
