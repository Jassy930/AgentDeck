import Foundation
import AgentDeckCore
import Observation

struct HistoryOpenTiming: Equatable {
    let threadId: String
    let itemCount: Int
    let readMilliseconds: Int
    let applyMilliseconds: Int
    let totalMilliseconds: Int
}

/// Session view model. `@MainActor` + `@Observable`. v2 (Task 6A): pure
/// orchestrator over `WorkbenchModel`; the cross-agent history layer is
/// pending Task 6.5 and is currently a stub.
@MainActor
@Observable
final class SessionModel {
    enum Phase: String {
        case idle, starting, ready, running, waitingApproval, draining, failed, closed
    }

    enum DeferredContent {
        case output
        case diff
    }

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
    var selectedActionRequest: PendingActionRequest? {
        workbench.selectedRuntime?.pendingActionRequest
    }
    var runStartedAt: Date?
    var tickNow: Date = .now
    private var tickTimer: Timer?

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

    /// v2 cross-agent history — stub until Task 6.5 wires daemon history.
    /// Existing UI references this; we keep the API so the UI compiles.
    private(set) var historyThreads: [HistoryThreadSummary] = []
    var historyGroups: [HistoryProjectGroup] {
        HistoryProjectGroup.group(combinedHistoryThreads())
    }
    var historyErrorMessage: String?
    var isLoadingHistory = false
    var openingHistoryThreadId: String?
    var lastHistoryOpenTiming: HistoryOpenTiming?
    var historySearchTerm = ""
    /// 右上环境面板数据源。真实 app 默认 nil（面板显示零值占位）；
    /// preview 引导层注入 mock 值。不经 IPC——面板暂无 daemon 后端。
    var environmentInfo: EnvironmentInfo?
    var selectedHistoryThreadId: String?
    var selectedSidebarThreadId: String? {
        selectedHistoryThreadId ?? workbench.selectedSessionId
    }
    var conversationViewportIdentity = "live:0"
    var scrollToLatestRequest = 0
    private var didRequestInitialHistoryRefresh = false

    var selectedItems: [UIItem] {
        workbench.selectedRuntime?.items ?? items
    }

    var selectedPhase: Phase {
        workbench.selectedRuntime?.phase ?? phase
    }

    let workbench: WorkbenchModel

    private let client: DaemonClient?
    private var daemonStarted = false
    private var conversationViewportRevision = 0

    init(
        client: DaemonClient? = nil,
        runtimeTurnStarter: RuntimeTurnStarting? = nil
    ) {
        let daemon = client ?? DaemonClient()
        self.client = daemon
        self.workbench = WorkbenchModel(
            turnStarter: runtimeTurnStarter ?? daemon,
            actionDecider: daemon
        )
    }

    /// Test-only init: bypass DaemonClient entirely.
    init(turnStarter: RuntimeTurnStarting, actionDecider: RuntimeActionDeciding? = nil) {
        self.client = nil
        self.workbench = WorkbenchModel(turnStarter: turnStarter, actionDecider: actionDecider)
    }

    var elapsedSeconds: Int? {
        guard let start = runStartedAt else { return nil }
        return max(0, Int(tickNow.timeIntervalSince(start)))
    }

    var statusText: String {
        let base: String
        switch selectedPhase {
        case .idle: base = "Ready"
        case .starting: base = "Starting…"
        case .ready: base = "Ready"
        case .running: base = "Working…"
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

    func submit(_ prompt: String, agentKind: AgentKind = .codex) {
        submit(prompt, agentKind: agentKind, sessionStart: nil)
    }

    /// Submit with a pre-built `SessionStart` (vendor options carried).
    /// Used by NewSessionDialog so the user-chosen sandbox/approval/
    /// permission_mode actually reach the daemon (C1 fix, v0.2 final
    /// review). On legacy fall-through (no SessionStart) we synthesize
    /// defaults inside `DaemonClient.startTurn`, preserving existing
    /// behavior for input-bar submissions.
    func submit(_ prompt: String, agentKind: AgentKind, sessionStart: SessionStart?) {
        let trimmed = prompt.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }

        if workbench.selectedRuntime != nil {
            let oldCount = selectedItems.count
            if let sessionStart {
                workbench.submit(trimmed, sessionStart: sessionStart)
            } else {
                workbench.submit(trimmed)
            }
            if selectedItems.count > oldCount {
                scrollToLatestRequest += 1
            }
            return
        }

        guard !trimmed.isEmpty, let cwd else { return }

        let sessionId = "live-\(UUID().uuidString)"
        selectedHistoryThreadId = nil
        workbench.ensureRuntime(sessionId: sessionId, agentKind: agentKind, threadId: nil, cwd: cwd)
        workbench.selectRuntime(sessionId: sessionId)
        let oldCount = selectedItems.count
        if let sessionStart {
            workbench.submit(trimmed, sessionStart: sessionStart)
        } else {
            workbench.submit(trimmed)
        }
        if selectedItems.count > oldCount {
            scrollToLatestRequest += 1
        }
    }

    @discardableResult
    private func ensureDaemonStarted() -> Bool {
        guard let client else { return true }
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

    private func combinedHistoryThreads() -> [HistoryThreadSummary] {
        let persistedIds = Set(historyThreads.map(\.id))
        let liveThreads = workbench.runtimeList.compactMap { runtime -> HistoryThreadSummary? in
            if persistedIds.contains(runtime.id) { return nil }
            if let threadId = runtime.threadId, persistedIds.contains(threadId) { return nil }
            return liveHistoryThreadSummary(for: runtime)
        }
        return historyThreads + liveThreads
    }

    private func liveHistoryThreadSummary(for runtime: ThreadRuntimeModel) -> HistoryThreadSummary {
        // 取第一条「真实」用户消息作为预览：跳过 CLI 命令元数据（caveat / 斜杠命令），
        // 并剥离残留标签，避免侧栏标题显示成 `<local-command-cave…>`。
        let prompt = runtime.items
            .lazy
            .filter { $0.kind == "user" }
            .compactMap { CommandMessageSanitizer.sanitize(userText: $0.text) }
            .first?
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let preview = (prompt?.isEmpty == false ? prompt : nil) ?? runtime.displayTitle
        return HistoryThreadSummary(
            id: runtime.id,
            name: nil,
            preview: preview,
            cwd: runtime.cwd.path,
            createdAt: Int(runtime.createdAt.timeIntervalSince1970),
            updatedAt: Int(runtime.updatedAt.timeIntervalSince1970),
            status: runtime.phase.rawValue,
            modelProvider: runtime.agentKind == .codex ? "openai" : "anthropic",
            source: "live",
            agentKind: runtime.agentKind
        )
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
        guard let client else {
            historyErrorMessage = "no daemon client"
            return
        }
        guard ensureDaemonStarted() else { return }
        isLoadingHistory = true
        historyErrorMessage = nil
        let cwdFilter = currentProjectOnly ? cwd?.path : nil
        do {
            let response = try client.history(.list(agentKind: nil, cwdFilter: cwdFilter, limit: nil))
            if case .list(let items) = response {
                let summaries = items.map { item in
                    HistoryThreadSummary(
                        id: item.threadId,
                        name: item.title,
                        preview: item.title ?? "",
                        cwd: item.cwd,
                        createdAt: Int(item.lastActiveMs / 1000),
                        updatedAt: Int(item.lastActiveMs / 1000),
                        status: item.archived ? "archived" : "ready",
                        modelProvider: item.agentKind == .codex ? "openai" : "anthropic",
                        source: item.agentKind == .codex ? "codex" : "claude_code",
                        agentKind: item.agentKind
                    )
                }
                setHistoryThreads(summaries)
            }
        } catch {
            historyErrorMessage = "\(error)"
        }
        isLoadingHistory = false
    }

    func openHistoryThread(_ thread: HistoryThreadSummary) {
        if thread.source == "live", let runtime = workbench.runtime(sessionId: thread.id) {
            cwd = runtime.cwd
            selectedHistoryThreadId = nil
            resetConversationViewport(prefix: "live:\(thread.id)")
            workbench.selectRuntime(sessionId: thread.id)
            return
        }
        guard let client else { return }
        guard ensureDaemonStarted() else { return }
        openingHistoryThreadId = thread.id
        historyErrorMessage = nil
        lastHistoryOpenTiming = nil
        let agentKind: AgentKind = thread.agentKind
        let startedAt = Date()
        DispatchQueue.global(qos: .userInitiated).async { [weak self, weak client] in
            guard let client else { return }
            let result = Result<HistoryResponse, Error> {
                try client.history(.read(threadId: thread.id, agentKind: agentKind))
            }
            let readFinishedAt = Date()
            DispatchQueue.main.async { [weak self] in
                guard let self, self.openingHistoryThreadId == thread.id else { return }
                self.openingHistoryThreadId = nil
                switch result {
                case .success(let response):
                    if case .read(let detail) = response {
                        let applyStartedAt = Date()
                        self.applyHistoryReadResponse(detail, originalThread: thread)
                        let appliedAt = Date()
                        self.lastHistoryOpenTiming = HistoryOpenTiming(
                            threadId: thread.id,
                            itemCount: detail.turns.reduce(0) { $0 + $1.items.count },
                            readMilliseconds: Self.milliseconds(from: startedAt, to: readFinishedAt),
                            applyMilliseconds: Self.milliseconds(from: applyStartedAt, to: appliedAt),
                            totalMilliseconds: Self.milliseconds(from: startedAt, to: appliedAt)
                        )
                    }
                case .failure(let error):
                    self.historyErrorMessage = "\(error)"
                }
            }
        }
    }

    func applyHistoryReadResponse(_ response: HistoryReadResponse, originalThread thread: HistoryThreadSummary) {
        cwd = URL(fileURLWithPath: thread.cwd)
        selectedHistoryThreadId = thread.id
        resetConversationViewport(prefix: "history:\(thread.id)")
        let runtime = ThreadRuntimeModel(
            id: thread.id,
            agentKind: response.agentKind,
            threadId: thread.id,
            cwd: URL(fileURLWithPath: thread.cwd)
        )
        runtime.applyReplayTurns(response.turns)
        workbench.installRuntime(runtime)
        workbench.selectRuntime(sessionId: thread.id)
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
        guard let client, ensureDaemonStarted() else { return }
        let agentKind: AgentKind = thread.agentKind
        do {
            _ = try client.history(.archive(threadId: thread.id, agentKind: agentKind))
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
        guard !trimmed.isEmpty, let client, ensureDaemonStarted() else { return }
        let agentKind: AgentKind = thread.agentKind
        do {
            _ = try client.history(.rename(threadId: thread.id, agentKind: agentKind, title: trimmed))
            loadHistory()
        } catch {
            historyErrorMessage = "\(error)"
        }
    }

    func materializeDeferredContent(itemId: String, content: DeferredContent) {
        workbench.selectedRuntime?.materializeDeferredContent(itemId: itemId, content: content)
    }

    func decidePendingAction(_ decision: ActionDecisionKind, persist: Bool = false) {
        workbench.decidePendingAction(decision, persist: persist)
    }

    func ingest(_ event: ServerEvent) {
        workbench.ingestServerEvent(event)
    }

    /// Push a typed vendor-control update for the live runtime over the
    /// daemon socket. Used by AgentControlBar so user toggles on the
    /// sandbox / approval / permission popups reach the daemon
    /// mid-session (C2 fix, v0.2 final review). Errors are swallowed
    /// here — the daemon will surface `cc-vendor-control-requires-new-turn`
    /// (or similar) via the normal events stream if rejected.
    func submitVendorControl(sessionId: String, payload: VendorControlPayload) {
        guard let client else { return }
        do {
            try client.submitVendorControl(sessionId: sessionId, payload: payload)
        } catch {
            // Best-effort: log to stderr, do not interrupt the UI.
            FileHandle.standardError.write(
                Data("[AgentDeck] submitVendorControl failed: \(error)\n".utf8)
            )
        }
    }

    private static func milliseconds(from start: Date, to end: Date) -> Int {
        max(0, Int((end.timeIntervalSince(start) * 1000).rounded()))
    }

    func teardown() {
        tickTimer?.invalidate()
        client?.shutdown()
    }
}
