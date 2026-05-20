import Foundation
import Observation

/// A neutral agent item as the UI sees it. Mirrors the daemon's AgentItem
/// (Eng D4 per-kind). The Swift app NEVER parses vendor formats — it only
/// ever decodes this neutral shape (Eng D2). Adding a Claude Code adapter
/// later changes nothing here.
struct UIItem: Identifiable {
    let id: String
    var lifecycle: String          // started | delta | completed
    var kind: String               // reasoning | shell | fileEdit | raw
    // Per-kind fields (only the relevant ones are populated).
    var text: String = ""          // reasoning
    var command: String = ""       // shell
    var output: String = ""        // shell
    var exitCode: Int?             // shell
    var path: String = ""          // fileEdit
    var diff: String = ""          // fileEdit
    var descriptionText: String = "" // raw (neutralized unknown)
    var hasNonWhitespaceText = false
    var textBuffer = StreamingTextBuffer()
    var outputBuffer = StreamingTextBuffer()
    var diffBuffer = StreamingTextBuffer()
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
        phase == .running || phase == .starting
    }
    var items: [UIItem] = []
    var errorMessage: String?
    /// When the current turn began. `nil` outside a turn.
    var runStartedAt: Date?
    /// Driven by a tick timer; the status bar reads this so the elapsed
    /// counter updates once per second while a turn is running.
    var tickNow: Date = .now
    private var tickTimer: Timer?
    /// Prompts queued while a turn runs (Eng I1). v0.1: enqueue, auto-send
    /// on turn completion. Step 5 wires the auto-send; Step 4 shows the count.
    var queuedPrompts: [String] = []
    var historyThreads: [HistoryThreadSummary] = []
    var historyErrorMessage: String?
    var isLoadingHistory = false
    var historySearchTerm = ""
    var selectedHistoryThreadId: String?

    var historyGroups: [HistoryProjectGroup] {
        HistoryProjectGroup.group(historyThreads)
    }

    private let client = DaemonClient()
    private var daemonStarted = false
    private var itemIndexById: [String: Int] = [:]
    private var pendingAgentItems: [[String: Any]] = []
    private var renderFlushTimer: Timer?
    private let renderFlushInterval: TimeInterval = 1.0 / 30.0

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
        switch phase {
        case .idle: base = "Ready"
        case .starting: base = "Connecting to Codex…"
        case .ready: base = "Ready"
        case .running: base = "Codex is working…"
        case .waitingApproval: base = "Waiting for your approval"
        case .draining: base = "Finishing up…"
        case .failed: base = "Failed"
        case .closed: base = "Closed"
        }
        if let s = elapsedSeconds, phase == .running || phase == .starting {
            return "\(base)  \(s)s"
        }
        return base
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
        guard !trimmed.isEmpty, let cwd else { return }

        // Eng I1: a turn in flight → enqueue, don't drop, don't interrupt.
        if phase == .running || phase == .starting || phase == .waitingApproval {
            queuedPrompts.append(trimmed)
            return
        }

        if !ensureDaemonStarted() {
            return
        }

        let userItem = UIItem(id: "user-\(UUID().uuidString)",
                              lifecycle: "completed", kind: "user", text: trimmed)
        itemIndexById[userItem.id] = items.count
        items.append(userItem)
        errorMessage = nil
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
                searchTerm: search.isEmpty ? nil : search
            )
            setHistoryThreads(list.threads)
        } catch {
            historyErrorMessage = "\(error)"
        }
        isLoadingHistory = false
    }

    func openHistoryThread(_ thread: HistoryThreadSummary) {
        guard ensureDaemonStarted() else { return }
        do {
            let detail = try client.readHistoryThread(threadId: thread.id)
            applyHistoryThreadDetail(detail)
        } catch {
            historyErrorMessage = "\(error)"
        }
    }

    func applyHistoryThreadDetail(_ detail: HistoryThreadDetail) {
        flushPendingAgentItems()
        cwd = URL(fileURLWithPath: detail.thread.cwd)
        selectedHistoryThreadId = detail.thread.id
        itemIndexById.removeAll(keepingCapacity: true)
        items = detail.items.map(uiItem)
        for (index, item) in items.enumerated() {
            itemIndexById[item.id] = index
        }
        errorMessage = nil
        phase = .ready
    }

    func startNewSessionFromCurrentProject() {
        selectedHistoryThreadId = nil
        items.removeAll()
        itemIndexById.removeAll(keepingCapacity: true)
        errorMessage = nil
        phase = cwd == nil ? .idle : .ready
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

    private func uiItem(from replay: HistoryReplayItem) -> UIItem {
        var item = UIItem(id: replay.id, lifecycle: replay.lifecycle, kind: replay.kind)
        item.text = replay.text
        item.command = replay.command
        item.output = replay.output ?? ""
        item.exitCode = replay.exitCode
        item.path = replay.path
        item.diff = replay.diff ?? ""
        item.descriptionText = replay.description ?? ""
        item.hasNonWhitespaceText = containsNonWhitespace(replay.text)
        item.textBuffer.replace(with: replay.text)
        item.outputBuffer.replace(with: item.output)
        item.diffBuffer.replace(with: item.diff)
        return item
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
                item.hasNonWhitespaceText = item.hasNonWhitespaceText || containsNonWhitespace(t)
            } else if !t.isEmpty {
                item.text = t
                item.textBuffer.replace(with: t)
                item.hasNonWhitespaceText = containsNonWhitespace(t)
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
        case "fileEdit":
            item.path = d["path"] as? String ?? item.path
            if let diff = d["diff"] as? String {
                item.diff = diff
                item.diffBuffer.replace(with: diff)
            }
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
        guard !queuedPrompts.isEmpty, phase == .ready else { return }
        let next = queuedPrompts.removeFirst()
        submit(next)
    }

    private func containsNonWhitespace(_ text: String) -> Bool {
        text.unicodeScalars.contains { scalar in
            !CharacterSet.whitespacesAndNewlines.contains(scalar)
        }
    }

    func teardown() {
        flushPendingAgentItems()
        renderFlushTimer?.invalidate()
        tickTimer?.invalidate()
        client.shutdown()
    }

}
