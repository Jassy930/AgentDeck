import Foundation
import Observation

/// A neutral agent item as the UI sees it. Mirrors the daemon's AgentItem
/// (Eng D4 per-kind). The Swift app NEVER parses vendor formats — it only
/// ever decodes this neutral shape (Eng D2). Adding a Claude Code adapter
/// later changes nothing here.
struct UIItem: Identifiable {
    let id: String
    var lifecycle: String          // started | delta | completed
    var kind: String               // reasoning | shell | fileEdit | webSearch | raw
    // Per-kind fields (only the relevant ones are populated).
    var text: String = ""          // reasoning
    var command: String = ""       // shell
    var output: String = ""        // shell
    var exitCode: Int?             // shell
    var path: String = ""          // fileEdit
    var diff: String = ""          // fileEdit
    var query: String = ""         // webSearch
    var action: String = ""        // webSearch
    var actionQuery: String = ""   // webSearch
    var queries: [String] = []     // webSearch
    var url: String = ""           // webSearch
    var pattern: String = ""       // webSearch
    var attachments: [HistoryReference] = []
    var phaseName: String = ""
    var memoryCitation: String = ""
    var cwdText: String = ""
    var statusName: String = ""
    var durationMs: Int?
    var sourceName: String = ""
    var processId: String = ""
    var actions: [HistoryToolAction] = []
    var changes: [HistoryFileChange] = []
    var fragments: [HistoryHookFragment] = []
    var toolKind: String = ""
    var server: String = ""
    var namespace: String = ""
    var tool: String = ""
    var arguments: String = ""
    var result: String = ""
    var errorText: String = ""
    var success: Bool?
    var resourceUri: String = ""
    var contentItems: [HistoryReference] = []
    var prompt: String = ""
    var model: String = ""
    var reasoningEffort: String = ""
    var senderThreadId: String = ""
    var receiverThreadIds: [String] = []
    var agentsStates: String = ""
    var mediaKind: String = ""
    var savedPath: String = ""
    var revisedPrompt: String = ""
    var review: String = ""
    var descriptionText: String = "" // raw (neutralized unknown)
    var hasNonWhitespaceText = false
    var hasDeferredOutputBuffer = false
    var hasDeferredDiffBuffer = false
    var textBuffer = StreamingTextBuffer()
    var outputBuffer = StreamingTextBuffer()
    var diffBuffer = StreamingTextBuffer()
}

func agentDeckContainsNonWhitespace(_ text: String) -> Bool {
    text.unicodeScalars.contains { scalar in
        !CharacterSet.whitespacesAndNewlines.contains(scalar)
    }
}

func agentDeckStringArray(from value: Any?) -> [String]? {
    if let strings = value as? [String] {
        return strings
    }
    if let values = value as? [Any] {
        return values.compactMap { $0 as? String }
    }
    return nil
}

func agentDeckUIItem(from replay: HistoryReplayItem, largeHistoryTextThreshold: Int = 16 * 1024) -> UIItem {
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

struct HistoryOpenTiming: Equatable {
    let threadId: String
    let itemCount: Int
    let readMilliseconds: Int
    let applyMilliseconds: Int
    let totalMilliseconds: Int
}

/// The session view model. `@MainActor` + `@Observable`: every mutation is
/// main-thread (Eng C-uitest), SwiftUI observes it directly.
///
/// `state` is a MIRROR of the daemon's session state machine (Eng D9). The
/// daemon is the sole source of truth; this never invents a transition, it
/// only reflects `sessionState` messages. `statusText` drives the D6
/// transition copy ("Connecting to Codex…" etc).
@MainActor
@Observable
final class SessionModel {
    enum Phase: String {
        case idle, starting, ready, running, waitingApproval, draining, failed, closed
    }

    /// The chosen project directory (Eng D3: Swift validates before the
    /// daemon's authoritative check). nil → show the empty state (D5).
    var cwd: URL?
    var phase: Phase = .idle {
        didSet {
            switch phase {
            case .starting, .running:
                if oldValue != .starting && oldValue != .running {
                    runStartedAt = Date()
                }
            case .ready, .failed, .closed, .idle:
                runStartedAt = nil
            default: break
            }
            tickIfNeeded()
        }
    }

    /// True while a turn is in flight — the view auto-EXPANDS reasoning so
    /// the user sees the chain-of-thought stream while waiting for the
    /// final answer (which Codex sends in one burst). When the turn ends,
    /// reasoning collapses back to its D3 secondary role.
    var shouldShowReasoningExpanded: Bool {
        selectedPhase == .running || selectedPhase == .starting
    }
    var items: [UIItem] = []
    var errorMessage: String?
    var warningMessage: String?
    var selectedErrorMessage: String? {
        workbench.selectedRuntime?.errorMessage ?? errorMessage
    }
    var selectedWarningMessage: String? {
        workbench.selectedRuntime == nil ? warningMessage : nil
    }
    /// When the current turn began. `nil` outside a turn.
    var runStartedAt: Date?
    /// Driven by a tick timer; the status bar reads this so the elapsed
    /// counter updates once per second while a turn is running.
    var tickNow: Date = .now
    private var tickTimer: Timer?
    /// Prompts queued while a turn runs (Eng I1). v0.1: enqueue, auto-send
    /// on turn completion. Step 5 wires the auto-send; Step 4 shows the count.
    var queuedPrompts: [String] {
        get {
            workbench.selectedRuntime?.queuedPrompts ?? legacyQueuedPrompts
        }
        set {
            if let runtime = workbench.selectedRuntime {
                runtime.queuedPrompts = newValue
            } else {
                legacyQueuedPrompts = newValue
            }
        }
    }
    private var legacyQueuedPrompts: [String] = []
    var historyThreads: [HistoryThreadSummary] = []
    var historyErrorMessage: String?
    var isLoadingHistory = false
    var openingHistoryThreadId: String?
    var lastHistoryOpenTiming: HistoryOpenTiming?
    var historySearchTerm = ""
    var selectedHistoryThreadId: String?
    var conversationViewportIdentity = "live:0"
    var scrollToLatestRequest = 0
    private var didRequestInitialHistoryRefresh = false

    var historyGroups: [HistoryProjectGroup] {
        HistoryProjectGroup.group(historyThreads)
    }

    var selectedItems: [UIItem] {
        workbench.selectedRuntime?.items ?? items
    }

    var selectedPhase: Phase {
        workbench.selectedRuntime?.phase ?? phase
    }

    let workbench: WorkbenchModel

    private let client: SessionClienting
    private let historyDetailClient: HistoryDetailReading
    private var daemonStarted = false
    private var itemIndexById: [String: Int] = [:]
    private var pendingAgentItems: [[String: Any]] = []
    private var renderFlushTimer: Timer?
    private let renderFlushInterval: TimeInterval = 1.0 / 30.0
    private let largeHistoryTextThreshold = 16 * 1024
    private var conversationViewportRevision = 0

    enum DeferredContent {
        case output
        case diff
    }

    init(
        client: SessionClienting = DaemonClient(),
        historyDetailClient: HistoryDetailReading? = nil,
        runtimeTurnStarter: RuntimeTurnStarting? = nil
    ) {
        self.client = client
        self.workbench = WorkbenchModel(
            turnStarter: runtimeTurnStarter
                ?? (client as? RuntimeTurnStarting)
                ?? NoopRuntimeTurnStarter()
        )
        self.historyDetailClient = historyDetailClient ?? DaemonHistoryDetailReader()
    }

    /// Elapsed seconds in the current turn (nil outside a turn). Driven by
    /// `tickNow` so SwiftUI re-renders every second.
    var elapsedSeconds: Int? {
        guard let start = runStartedAt else { return nil }
        return max(0, Int(tickNow.timeIntervalSince(start)))
    }

    /// D6 transition copy: reuse the D9 state machine, not a generic spinner.
    /// When a turn is running, append elapsed seconds so the user can SEE
    /// time passing while Codex assembles the final answer.
    var statusText: String {
        let base: String
        switch selectedPhase {
        case .idle: base = "Ready"
        case .starting: base = "Connecting to Codex…"
        case .ready: base = "Ready"
        case .running: base = "Codex is working…"
        case .waitingApproval: base = "Waiting for your approval"
        case .draining: base = "Finishing up…"
        case .failed: base = "Failed"
        case .closed: base = "Closed"
        }
        if workbench.selectedRuntime == nil,
           let s = elapsedSeconds,
           phase == .running || phase == .starting {
            return "\(base)  \(s)s"
        }
        return base
    }

    var historyTimingSummary: String {
        guard let timing = lastHistoryOpenTiming else { return "" }
        return "history read \(timing.readMilliseconds)ms · apply \(timing.applyMilliseconds)ms · \(timing.itemCount) items"
    }

    /// Start/stop the 1Hz tick so `elapsedSeconds` updates while a turn
    /// runs and stays still otherwise (no idle CPU).
    func tickIfNeeded() {
        let needsTick = (phase == .running || phase == .starting)
        if needsTick && tickTimer == nil {
            tickTimer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
                Task { @MainActor in self?.tickNow = .now }
            }
        } else if !needsTick {
            tickTimer?.invalidate()
            tickTimer = nil
        }
    }

    /// Eng D3: Swift-side cwd validation (existence/readability) — closest to
    /// the user, fastest feedback. The daemon does the authoritative final
    /// check before app-server.
    func chooseCwd(_ url: URL) -> String? {
        var isDir: ObjCBool = false
        let ok = FileManager.default.fileExists(
            atPath: url.path, isDirectory: &isDir)
        guard ok, isDir.boolValue else {
            return "Not a directory: \(url.path)"
        }
        guard FileManager.default.isReadableFile(atPath: url.path) else {
            return "Directory is not readable: \(url.path)"
        }
        cwd = url
        return nil
    }

    func submit(_ prompt: String) {
        if workbench.selectedRuntime != nil {
            workbench.submit(prompt)
            return
        }

        let trimmed = prompt.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, let cwd else { return }

        // Eng I1: a turn in flight → enqueue, don't drop, don't interrupt.
        if phase == .running || phase == .starting || phase == .waitingApproval {
            legacyQueuedPrompts.append(trimmed)
            return
        }

        if !ensureDaemonStarted() {
            return
        }

        let userItem = UIItem(id: "user-\(UUID().uuidString)",
                              lifecycle: "completed", kind: "user", text: trimmed)
        itemIndexById[userItem.id] = items.count
        items.append(userItem)
        scrollToLatestRequest += 1
        errorMessage = nil
        warningMessage = nil
        phase = .starting

        let onLine: @MainActor (String) -> Void = { [weak self] raw in
            guard let self else { return }
            self.ingest(rawLine: raw)
        }
        if let threadId = selectedHistoryThreadId {
            client.startTurn(threadId: threadId, prompt: trimmed, onLine: onLine)
        } else {
            client.startSession(cwd: cwd.path, prompt: trimmed, onLine: onLine)
        }
    }

    @discardableResult
    private func ensureDaemonStarted() -> Bool {
        if !daemonStarted {
            do {
                try client.start()
                daemonStarted = true
            } catch {
                phase = .failed
                errorMessage = "\(error)"
                return false
            }
        }
        return true
    }

    func setHistoryThreads(_ threads: [HistoryThreadSummary]) {
        historyThreads = threads
    }

    func shouldAutoRefreshHistoryOnAppear() -> Bool {
        guard !didRequestInitialHistoryRefresh else { return false }
        didRequestInitialHistoryRefresh = true
        return true
    }

    func loadHistoryOnAppear() {
        guard shouldAutoRefreshHistoryOnAppear() else { return }
        loadHistory()
    }

    func loadHistory(currentProjectOnly: Bool = false) {
        guard !isLoadingHistory else { return }
        guard ensureDaemonStarted() else { return }
        isLoadingHistory = true
        historyErrorMessage = nil
        let cwdFilter = currentProjectOnly ? cwd?.path : nil
        let search = historySearchTerm.trimmingCharacters(in: .whitespacesAndNewlines)
        do {
            let list = try client.listHistoryThreads(
                cwd: cwdFilter,
                searchTerm: search.isEmpty ? nil : search,
                cursor: nil,
                limit: 50
            )
            setHistoryThreads(list.threads)
        } catch {
            historyErrorMessage = "\(error)"
        }
        isLoadingHistory = false
    }

    func openHistoryThread(_ thread: HistoryThreadSummary) {
        if historyDetailClient === client {
            guard ensureDaemonStarted() else { return }
        }
        openingHistoryThreadId = thread.id
        historyErrorMessage = nil
        lastHistoryOpenTiming = nil
        let reader = historyDetailClient
        let startedAt = Date()
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let result = Result { try reader.readHistoryThread(threadId: thread.id) }
            let readFinishedAt = Date()
            DispatchQueue.main.async { [weak self] in
                guard let self, self.openingHistoryThreadId == thread.id else { return }
                self.openingHistoryThreadId = nil
                switch result {
                case .success(let detail):
                    let applyStartedAt = Date()
                    self.applyHistoryThreadDetail(detail)
                    let appliedAt = Date()
                    self.lastHistoryOpenTiming = HistoryOpenTiming(
                        threadId: thread.id,
                        itemCount: detail.items.count,
                        readMilliseconds: Self.milliseconds(from: startedAt, to: readFinishedAt),
                        applyMilliseconds: Self.milliseconds(from: applyStartedAt, to: appliedAt),
                        totalMilliseconds: Self.milliseconds(from: startedAt, to: appliedAt)
                    )
                case .failure(let error):
                    self.historyErrorMessage = "\(error)"
                }
            }
        }
    }

    func applyHistoryThreadDetail(_ detail: HistoryThreadDetail) {
        cwd = URL(fileURLWithPath: detail.thread.cwd)
        selectedHistoryThreadId = detail.thread.id
        resetConversationViewport(prefix: "history:\(detail.thread.id)")
        workbench.applyHistoryThreadDetail(detail)
    }

    func startNewSessionFromCurrentProject() {
        selectedHistoryThreadId = nil
        workbench.selectedSessionId = nil
        openingHistoryThreadId = nil
        resetConversationViewport(prefix: "live")
        items.removeAll()
        itemIndexById.removeAll(keepingCapacity: true)
        errorMessage = nil
        warningMessage = nil
        phase = cwd == nil ? .idle : .ready
    }

    private func resetConversationViewport(prefix: String) {
        conversationViewportRevision += 1
        conversationViewportIdentity = "\(prefix):\(conversationViewportRevision)"
    }

    func archiveHistoryThread(_ thread: HistoryThreadSummary) {
        guard ensureDaemonStarted() else { return }
        do {
            try client.archiveHistoryThread(threadId: thread.id)
            if selectedHistoryThreadId == thread.id {
                startNewSessionFromCurrentProject()
            }
            loadHistory()
        } catch {
            historyErrorMessage = "\(error)"
        }
    }

    func renameHistoryThread(_ thread: HistoryThreadSummary, name: String) {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, ensureDaemonStarted() else { return }
        do {
            try client.renameHistoryThread(threadId: thread.id, name: trimmed)
            loadHistory()
        } catch {
            historyErrorMessage = "\(error)"
        }
    }

    func materializeDeferredContent(itemId: String, content: DeferredContent) {
        if let runtime = workbench.selectedRuntime {
            runtime.materializeDeferredContent(itemId: itemId, content: content)
            return
        }
        guard let idx = itemIndexById[itemId], items.indices.contains(idx) else { return }
        switch content {
        case .output:
            guard items[idx].hasDeferredOutputBuffer else { return }
            items[idx].outputBuffer.replace(with: items[idx].output)
            items[idx].hasDeferredOutputBuffer = false
        case .diff:
            guard items[idx].hasDeferredDiffBuffer else { return }
            items[idx].diffBuffer.replace(with: items[idx].diff)
            items[idx].hasDeferredDiffBuffer = false
        }
    }

    func ingest(rawLine raw: String) {
        let msg = (try? JSONDecoder().decode(
            IpcMessage.self, from: Data(raw.utf8)))
            ?? IpcMessage(kind: "error", id: nil,
                payload: AnyCodable(["message": "malformed reply"]))
        ingest(msg)
    }

    func ingest(_ msg: IpcMessage) {
        switch msg.kind {
        case "agentItem":
            if let dict = msg.payload?.value as? [String: Any] {
                enqueueAgentItem(dict)
            }
        case "sessionState":
            flushPendingAgentItems()
            if let s = (msg.payload?.value as? [String: Any])?["state"] as? String,
               let p = Phase(rawValue: s) {
                phase = p
            }
        case "turnComplete":
            flushPendingAgentItems()
            phase = .ready
            drainQueueIfPossible()
        case "error":
            flushPendingAgentItems()
            let m = (msg.payload?.value as? [String: Any])?["message"] as? String
            errorMessage = m ?? "unknown error"
            phase = .failed
        case "warning":
            let m = (msg.payload?.value as? [String: Any])?["message"] as? String
            warningMessage = m ?? "unknown warning"
        default:
            break
        }
    }

    private func enqueueAgentItem(_ item: [String: Any]) {
        pendingAgentItems.append(item)
        guard renderFlushTimer == nil else { return }
        renderFlushTimer = Timer.scheduledTimer(
            withTimeInterval: renderFlushInterval,
            repeats: false
        ) { [weak self] _ in
            Task { @MainActor in self?.flushPendingAgentItems() }
        }
    }

    /// Applies all pending stream deltas in one SwiftUI-observable mutation
    /// window. This keeps the daemon faithful while preventing token-rate UI
    /// invalidation from fighting ScrollView interaction.
    func flushPendingAgentItems() {
        renderFlushTimer?.invalidate()
        renderFlushTimer = nil
        guard !pendingAgentItems.isEmpty else { return }
        let pending = pendingAgentItems
        pendingAgentItems.removeAll(keepingCapacity: true)
        for item in pending {
            upsert(item)
        }
    }

    /// Merge a streamed item by id: started creates, delta appends, completed
    /// finalizes. Delta rate is throttled by `flushPendingAgentItems`.
    private func upsert(_ d: [String: Any]) {
        guard let id = d["id"] as? String,
              let kind = d["kind"] as? String,
              let life = d["lifecycle"] as? String else { return }

        // `raw` = a neutralized unknown vendor item (incl. the echoed
        // userMessage). The daemon still records it for audit, but it is
        // meaningless NOISE in the UI — this is exactly what the user saw
        // ("unsupported item type: userMessage / reasoning"). Drop it from
        // the UI stream. Filtering here (not in the view) keeps the noise
        // out of the UI data model entirely.
        if kind == "raw" { return }

        var item = itemIndexById[id].flatMap { idx in
            items.indices.contains(idx) ? items[idx] : nil
        } ?? UIItem(id: id, lifecycle: life, kind: kind)
        item.lifecycle = life
        item.kind = kind
        switch kind {
        case "user", "message", "reasoning":
            // message = primary answer; reasoning = collapsed chain-of-
            // thought. Both accumulate text the same way: delta appends.
            // started/completed REPLACE — UNLESS the incoming text is empty
            // (Codex's reasoning `completed` sometimes ships with empty
            // content/summary, which would wipe out the delta stream the
            // user just watched arrive — the "blank when expanded" bug).
            // Empty incoming → keep the accumulated text.
            let t = d["text"] as? String ?? ""
            if life == "delta" {
                item.text.append(contentsOf: t)
                item.textBuffer.append(t)
                item.hasNonWhitespaceText = item.hasNonWhitespaceText || agentDeckContainsNonWhitespace(t)
            } else if !t.isEmpty {
                item.text = t
                item.textBuffer.replace(with: t)
                item.hasNonWhitespaceText = agentDeckContainsNonWhitespace(t)
            }
        case "shell":
            item.command = d["command"] as? String ?? item.command
            if let o = d["output"] as? String {
                if life == "delta" {
                    item.output.append(contentsOf: o)
                    item.outputBuffer.append(o)
                } else {
                    item.output = o
                    item.outputBuffer.replace(with: o)
                }
            }
            item.exitCode = d["exitCode"] as? Int ?? item.exitCode
            item.cwdText = d["cwd"] as? String ?? item.cwdText
            item.statusName = d["status"] as? String ?? item.statusName
            item.durationMs = d["durationMs"] as? Int ?? item.durationMs
            item.sourceName = d["source"] as? String ?? item.sourceName
            item.processId = d["processId"] as? String ?? item.processId
        case "fileEdit":
            item.path = d["path"] as? String ?? item.path
            if let diff = d["diff"] as? String {
                item.diff = diff
                item.diffBuffer.replace(with: diff)
            }
            item.statusName = d["status"] as? String ?? item.statusName
        case "webSearch":
            item.query = d["query"] as? String ?? item.query
            item.action = d["action"] as? String ?? item.action
            item.actionQuery = d["actionQuery"] as? String ?? item.actionQuery
            item.queries = agentDeckStringArray(from: d["queries"]) ?? item.queries
            item.url = d["url"] as? String ?? item.url
            item.pattern = d["pattern"] as? String ?? item.pattern
        case "plan", "reviewMode":
            item.text = d["text"] as? String ?? item.text
            item.review = d["review"] as? String ?? item.review
            item.action = d["action"] as? String ?? item.action
        case "toolCall":
            item.toolKind = d["toolKind"] as? String ?? item.toolKind
            item.server = d["server"] as? String ?? item.server
            item.namespace = d["namespace"] as? String ?? item.namespace
            item.tool = d["tool"] as? String ?? item.tool
            item.statusName = d["status"] as? String ?? item.statusName
            item.arguments = d["arguments"] as? String ?? item.arguments
            item.result = d["result"] as? String ?? item.result
            item.errorText = d["error"] as? String ?? item.errorText
            item.durationMs = d["durationMs"] as? Int ?? item.durationMs
            item.success = d["success"] as? Bool ?? item.success
            item.resourceUri = d["resourceUri"] as? String ?? item.resourceUri
        case "collabAgentToolCall":
            item.tool = d["tool"] as? String ?? item.tool
            item.statusName = d["status"] as? String ?? item.statusName
            item.prompt = d["prompt"] as? String ?? item.prompt
            item.model = d["model"] as? String ?? item.model
            item.reasoningEffort = d["reasoningEffort"] as? String ?? item.reasoningEffort
            item.senderThreadId = d["senderThreadId"] as? String ?? item.senderThreadId
            item.receiverThreadIds = agentDeckStringArray(from: d["receiverThreadIds"]) ?? item.receiverThreadIds
            item.agentsStates = d["agentsStates"] as? String ?? item.agentsStates
        case "media":
            item.mediaKind = d["mediaKind"] as? String ?? item.mediaKind
            item.path = d["path"] as? String ?? item.path
            item.statusName = d["status"] as? String ?? item.statusName
            item.result = d["result"] as? String ?? item.result
            item.revisedPrompt = d["revisedPrompt"] as? String ?? item.revisedPrompt
            item.savedPath = d["savedPath"] as? String ?? item.savedPath
        case "raw":
            item.descriptionText = d["description"] as? String ?? ""
        default:
            break
        }

        if let idx = itemIndexById[id], items.indices.contains(idx) {
            items[idx] = item
        } else {
            itemIndexById[item.id] = items.count
            items.append(item)
        }
    }

    private func drainQueueIfPossible() {
        guard !legacyQueuedPrompts.isEmpty, phase == .ready else { return }
        let next = legacyQueuedPrompts.removeFirst()
        submit(next)
    }

    private static func milliseconds(from start: Date, to end: Date) -> Int {
        max(0, Int((end.timeIntervalSince(start) * 1000).rounded()))
    }

    func teardown() {
        flushPendingAgentItems()
        renderFlushTimer?.invalidate()
        tickTimer?.invalidate()
        historyDetailClient.shutdown()
        client.shutdown()
    }

}
