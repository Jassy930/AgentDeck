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

    func ensureRuntime(sessionId: String, threadId: String?, cwd: URL) {
        if let runtime = runtimes[sessionId] {
            if runtime.threadId == nil {
                runtime.threadId = threadId
            }
            return
        }

        runtimes[sessionId] = ThreadRuntimeModel(id: sessionId, threadId: threadId, cwd: cwd)
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

    func applyHistoryThreadDetail(_ detail: HistoryThreadDetail) {
        let sessionId = detail.thread.id
        let runtime = ThreadRuntimeModel(
            id: sessionId,
            threadId: detail.thread.id,
            cwd: URL(fileURLWithPath: detail.thread.cwd)
        )
        runtime.applyReplayItems(detail.items)
        runtimes[sessionId] = runtime
        selectedSessionId = sessionId
    }

    func submit(_ prompt: String) {
        guard let runtime = selectedRuntime else { return }
        submit(prompt, to: runtime)
    }

    func decidePendingAction(_ decision: String) {
        guard let runtime = selectedRuntime,
              let pending = runtime.resolvePendingAction() else { return }
        actionDecider.sendActionDecision(
            sessionId: runtime.id,
            requestId: pending.requestId,
            decision: decision
        )
    }

    func ingestSessionEvent(_ msg: IpcMessage) {
        guard msg.kind == "session/event",
              let sessionId = msg.sessionId,
              let runtime = runtimes[sessionId],
              let payload = msg.payload?.value as? [String: Any],
              let event = payload["event"] as? [String: Any],
              let kind = event["kind"] as? String else { return }

        if runtime.threadId == nil {
            runtime.threadId = msg.threadId
        }

        let action = runtime.ingest(IpcMessage(
            kind: kind,
            sessionId: sessionId,
            threadId: msg.threadId,
            payload: legacyPayload(from: event)
        ))
        if selectedSessionId == sessionId {
            runtime.unreadEventCount = 0
        }
        handle(action, for: runtime)
    }

    private func submit(_ prompt: String, to runtime: ThreadRuntimeModel) {
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
            cwd: runtime.cwd,
            prompt: trimmed,
            optimisticUserItemId: optimisticUserItemId
        ) { [weak self] msg in
            self?.ingestSessionEvent(msg)
        }
    }

    private func handle(_ action: RuntimeAction?, for runtime: ThreadRuntimeModel) {
        guard let action else { return }
        switch action {
        case .drainNextPrompt(let prompt):
            submit(prompt, to: runtime)
        }
    }

    private func legacyPayload(from event: [String: Any]) -> AnyCodable? {
        if let wrappedPayload = event["payload"] {
            return AnyCodable(wrappedPayload)
        }

        let unwrapped = event.filter { key, _ in key != "kind" }
        return unwrapped.isEmpty ? nil : AnyCodable(unwrapped)
    }
}

@MainActor
final class NoopRuntimeTurnStarter: RuntimeTurnStarting {
    func startTurn(
        sessionId: String,
        threadId: String?,
        cwd: URL,
        prompt: String,
        optimisticUserItemId: String,
        onEvent: @escaping @MainActor @Sendable (IpcMessage) -> Void
    ) {}
}

@MainActor
final class NoopRuntimeActionDecider: RuntimeActionDeciding {
    func sendActionDecision(sessionId: String, requestId: UInt64, decision: String) {}
}
