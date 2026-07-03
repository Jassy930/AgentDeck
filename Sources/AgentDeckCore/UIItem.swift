import Foundation

/// A neutral agent item as the UI sees it. Mirrors the v0.1 rendering shape;
/// the UI renderers depend on these field names.
public struct UIItem: Identifiable {
    public var id: String
    public var lifecycle: String
    public var kind: String
    public var text: String = ""
    public var command: String = ""
    public var output: String = ""
    public var exitCode: Int?
    public var path: String = ""
    public var diff: String = ""
    public var query: String = ""
    public var action: String = ""
    public var actionQuery: String = ""
    public var queries: [String] = []
    public var url: String = ""
    public var pattern: String = ""
    public var attachments: [HistoryReference] = []
    public var phaseName: String = ""
    public var memoryCitation: String = ""
    public var cwdText: String = ""
    public var statusName: String = ""
    public var durationMs: Int?
    public var sourceName: String = ""
    public var processId: String = ""
    public var actions: [HistoryToolAction] = []
    public var changes: [HistoryFileChange] = []
    public var fragments: [HistoryHookFragment] = []
    public var toolKind: String = ""
    public var server: String = ""
    public var namespace: String = ""
    public var tool: String = ""
    public var arguments: String = ""
    public var result: String = ""
    public var errorText: String = ""
    public var success: Bool?
    public var resourceUri: String = ""
    public var contentItems: [HistoryReference] = []
    public var prompt: String = ""
    public var model: String = ""
    public var reasoningEffort: String = ""
    public var senderThreadId: String = ""
    public var receiverThreadIds: [String] = []
    public var agentsStates: String = ""
    public var mediaKind: String = ""
    public var savedPath: String = ""
    public var revisedPrompt: String = ""
    public var review: String = ""
    public var descriptionText: String = ""
    public var hasNonWhitespaceText = false
    public var hasDeferredOutputBuffer = false
    public var hasDeferredDiffBuffer = false
    public var textBuffer = StreamingTextBuffer()
    public var outputBuffer = StreamingTextBuffer()
    public var diffBuffer = StreamingTextBuffer()

    public init(id: String, lifecycle: String, kind: String, text: String = "") {
        self.id = id
        self.lifecycle = lifecycle
        self.kind = kind
        self.text = text
    }
}

public func agentDeckContainsNonWhitespace(_ text: String) -> Bool {
    text.unicodeScalars.contains { scalar in
        !CharacterSet.whitespacesAndNewlines.contains(scalar)
    }
}

public func agentDeckStringArray(from value: Any?) -> [String]? {
    if let strings = value as? [String] {
        return strings
    }
    if let values = value as? [Any] {
        return values.compactMap { $0 as? String }
    }
    return nil
}

public func agentDeckUIItem(from replay: HistoryReplayItem, largeHistoryTextThreshold: Int = 16 * 1024) -> UIItem {
    var item = UIItem(id: replay.id, lifecycle: replay.lifecycle, kind: replay.kind)
    item.text = replay.text
    item.command = replay.command
    item.output = replay.output ?? ""
    item.exitCode = replay.exitCode
    item.path = replay.path
    item.diff = replay.diff ?? ""
    item.descriptionText = replay.description ?? ""
    item.query = replay.query
    item.action = replay.action
    item.actionQuery = replay.actionQuery ?? ""
    item.queries = replay.queries
    item.url = replay.url ?? ""
    item.pattern = replay.pattern ?? ""
    item.attachments = replay.attachments
    item.phaseName = replay.phase ?? ""
    item.memoryCitation = replay.memoryCitation ?? ""
    item.cwdText = replay.cwd ?? ""
    item.statusName = replay.status ?? ""
    item.durationMs = replay.durationMs
    item.sourceName = replay.source ?? ""
    item.processId = replay.processId ?? ""
    item.actions = replay.actions
    item.changes = replay.changes
    item.fragments = replay.fragments
    item.toolKind = replay.toolKind
    item.server = replay.server ?? ""
    item.namespace = replay.namespace ?? ""
    item.tool = replay.tool
    item.arguments = replay.arguments
    item.result = replay.result ?? ""
    item.errorText = replay.error ?? ""
    item.success = replay.success
    item.resourceUri = replay.resourceUri ?? ""
    item.contentItems = replay.contentItems
    item.prompt = replay.prompt ?? ""
    item.model = replay.model ?? ""
    item.reasoningEffort = replay.reasoningEffort ?? ""
    item.senderThreadId = replay.senderThreadId ?? ""
    item.receiverThreadIds = replay.receiverThreadIds
    item.agentsStates = replay.agentsStates ?? ""
    item.mediaKind = replay.mediaKind
    item.savedPath = replay.savedPath ?? ""
    item.revisedPrompt = replay.revisedPrompt ?? ""
    item.review = replay.review ?? ""
    item.hasNonWhitespaceText = agentDeckContainsNonWhitespace(replay.text)
    item.textBuffer.replace(with: replay.text)
    if item.output.utf8.count > largeHistoryTextThreshold {
        item.hasDeferredOutputBuffer = true
    } else {
        item.outputBuffer.replace(with: item.output)
    }
    if item.diff.utf8.count > largeHistoryTextThreshold {
        item.hasDeferredDiffBuffer = true
    } else {
        item.diffBuffer.replace(with: item.diff)
    }
    return item
}
