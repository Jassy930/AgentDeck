import Foundation
import Observation

@MainActor
@Observable
final class WorkbenchModel {
    private(set) var runtimes: [String: ThreadRuntimeModel] = [:]
    var selectedSessionId: String?
    private let turnStarter: RuntimeTurnStarting
    private let actionDecider: RuntimeActionDeciding

    init(
        turnStarter: RuntimeTurnStarting = DaemonClient(),
        actionDecider: RuntimeActionDeciding? = nil
    ) {
        self.turnStarter = turnStarter
        self.actionDecider = actionDecider ?? (turnStarter as? RuntimeActionDeciding) ?? NoopRuntimeActionDecider()
    }

    var selectedRuntime: ThreadRuntimeModel? {
        guard let selectedSessionId else { return nil }
        return runtimes[selectedSessionId]
    }

    var runtimeList: [ThreadRuntimeModel] {
        runtimes.values.sorted { lhs, rhs in
            if lhs.id == selectedSessionId { return true }
            if rhs.id == selectedSessionId { return false }
            return lhs.displayTitle.localizedStandardCompare(rhs.displayTitle) == .orderedAscending
        }
    }

    func ensureRuntime(sessionId: String, agentKind: AgentKind, threadId: String?, cwd: URL) {
        if let runtime = runtimes[sessionId] {
            if runtime.threadId == nil {
                runtime.threadId = threadId
            }
            return
        }
        runtimes[sessionId] = ThreadRuntimeModel(
            id: sessionId, agentKind: agentKind, threadId: threadId, cwd: cwd
        )
        if selectedSessionId == nil {
            selectRuntime(sessionId: sessionId)
        }
    }

    func runtime(sessionId: String) -> ThreadRuntimeModel? {
        runtimes[sessionId]
    }

    func selectRuntime(sessionId: String) {
        guard runtimes[sessionId] != nil else { return }
        selectedSessionId = sessionId
        runtimes[sessionId]?.unreadEventCount = 0
    }

    /// Direct insertion used by history replay paths to install a hydrated
    /// runtime. Keeps the `private(set)` access on `runtimes` so streaming
    /// callers must go through `ensureRuntime`/`ingestServerEvent`.
    func installRuntime(_ runtime: ThreadRuntimeModel) {
        runtimes[runtime.id] = runtime
    }

    func applyHistoryThreadDetail(_ detail: HistoryThreadDetail) {
        let sessionId = detail.thread.id
        let agentKind = inferAgentKind(from: detail.thread)
        let runtime = ThreadRuntimeModel(
            id: sessionId,
            agentKind: agentKind,
            threadId: detail.thread.id,
            cwd: URL(fileURLWithPath: detail.thread.cwd)
        )
        runtime.applyReplayItems(detail.items)
        runtimes[sessionId] = runtime
        selectedSessionId = sessionId
    }

    func submit(_ prompt: String) {
        guard let runtime = selectedRuntime else { return }
        submit(prompt, to: runtime, sessionStart: nil)
    }

    /// Submit with a fully-formed `SessionStart` (vendor options
    /// included). Used by NewSessionDialog so user-chosen sandbox,
    /// approval policy, permission mode, etc., actually reach the
    /// daemon on the first turn (C1 fix, v0.2 final review).
    /// When the runtime already has a `threadId`, the `sessionStart`
    /// is unused — vendor options come from the original session.
    func submit(_ prompt: String, sessionStart: SessionStart) {
        guard let runtime = selectedRuntime else { return }
        submit(prompt, to: runtime, sessionStart: sessionStart)
    }

    func decidePendingAction(_ decision: ActionDecisionKind, persist: Bool = false) {
        guard let runtime = selectedRuntime,
              let pending = runtime.resolvePendingAction() else { return }
        actionDecider.sendActionDecision(
            sessionId: runtime.id,
            requestId: pending.requestId,
            decision: decision,
            persist: persist
        )
    }

    /// Ingest a v2 ServerEvent into the matching runtime.
    func ingestServerEvent(_ event: ServerEvent) {
        guard let sessionId = event.sessionId,
              let runtime = runtimes[sessionId] else { return }
        let action = runtime.ingest(event)
        if selectedSessionId == sessionId {
            runtime.unreadEventCount = 0
        }
        handle(action, for: runtime)
    }

    private func submit(_ prompt: String, to runtime: ThreadRuntimeModel, sessionStart: SessionStart?) {
        let trimmed = prompt.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }

        if runtime.phase == .running || runtime.phase == .starting || runtime.phase == .waitingApproval {
            runtime.queuedPrompts.append(trimmed)
            return
        }

        let optimisticUserItemId = runtime.appendUserPrompt(trimmed)
        runtime.errorMessage = nil
        runtime.warningMessage = nil
        runtime.phase = .starting
        turnStarter.startTurn(
            sessionId: runtime.id,
            threadId: runtime.threadId,
            agentKind: runtime.agentKind,
            cwd: runtime.cwd,
            prompt: trimmed,
            optimisticUserItemId: optimisticUserItemId,
            // C1 fix: propagate the caller's `SessionStart` so vendor
            // options from NewSessionDialog (sandbox / approval /
            // permission_mode / etc.) actually reach the daemon
            // instead of being silently replaced by synthesized
            // defaults.
            sessionStart: sessionStart
        ) { [weak self] event in
            self?.ingestServerEvent(event)
        }
    }

    private func handle(_ action: RuntimeAction?, for runtime: ThreadRuntimeModel) {
        guard let action else { return }
        switch action {
        case .drainNextPrompt(let prompt):
            // Drained prompts always run as continuations of an
            // existing runtime — no new vendor options to plumb.
            submit(prompt, to: runtime, sessionStart: nil)
        }
    }

    /// Legacy `HistoryThreadSummary.source/modelProvider` mapping — v0.2 we
    /// default to `.codex` for backward-compat with persisted v0.1 records,
    /// but cross-agent history lookup (T6.5) replaces this with a real lookup.
    private func inferAgentKind(from thread: HistoryThreadSummary) -> AgentKind {
        let src = thread.source.lowercased()
        if src.contains("claude") { return .claudeCode }
        return .codex
    }
}

@MainActor
final class NoopRuntimeTurnStarter: RuntimeTurnStarting {
    func startTurn(
        sessionId: String,
        threadId: String?,
        agentKind: AgentKind,
        cwd: URL,
        prompt: String,
        optimisticUserItemId: String,
        sessionStart: SessionStart?,
        onEvent: @escaping @MainActor (ServerEvent) -> Void
    ) {}
}

@MainActor
final class NoopRuntimeActionDecider: RuntimeActionDeciding {
    func sendActionDecision(sessionId: String, requestId: String, decision: ActionDecisionKind, persist: Bool) {}
}
