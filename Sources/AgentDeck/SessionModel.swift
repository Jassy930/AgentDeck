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
        workbench.selectedRuntime?.warningMessage ?? warningMessage
    }
    var selectedActionRequest: ActionRequest? {
        workbench.selectedRuntime?.pendingActionRequest
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
                ?? NoopRuntimeTurnStarter(),
            actionDecider: client as? RuntimeActionDeciding
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
        let trimmed = prompt.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }

        if workbench.selectedRuntime != nil {
            let oldCount = selectedItems.count
            workbench.submit(trimmed)
            if selectedItems.count > oldCount {
                scrollToLatestRequest += 1
            }
            return
        }

        guard !trimmed.isEmpty, let cwd else { return }

        let sessionId = "live-\(UUID().uuidString)"
        selectedHistoryThreadId = nil
        workbench.ensureRuntime(sessionId: sessionId, threadId: nil, cwd: cwd)
        workbench.selectRuntime(sessionId: sessionId)
        let oldCount = selectedItems.count
        workbench.submit(trimmed)
        if selectedItems.count > oldCount {
            scrollToLatestRequest += 1
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

    func startNewSession(inProjectCwd projectCwd: String) {
        cwd = URL(fileURLWithPath: projectCwd)
        startNewSessionFromCurrentProject()
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

    func decidePendingAction(_ decision: String) {
        workbench.decidePendingAction(decision)
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
        var store = AgentItemStore(items: items, itemIndexById: itemIndexById)
        AgentItemReducer.upsert(d, into: &store)
        items = store.items
        itemIndexById = store.itemIndexById
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
