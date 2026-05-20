import Foundation
import Observation

@MainActor
@Observable
final class WorkbenchModel {
    private(set) var runtimes: [String: ThreadRuntimeModel] = [:]
    var selectedSessionId: String?
    private let turnStarter: RuntimeTurnStarting

    init(turnStarter: RuntimeTurnStarting = DaemonClient()) {
        self.turnStarter = turnStarter
    }

    var selectedRuntime: ThreadRuntimeModel? {
        guard let selectedSessionId else { return nil }
        return runtimes[selectedSessionId]
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
            selectedSessionId = sessionId
        }
    }

    func runtime(sessionId: String) -> ThreadRuntimeModel? {
        runtimes[sessionId]
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
        handle(action, for: runtime)
    }

    private func submit(_ prompt: String, to runtime: ThreadRuntimeModel) {
        let trimmed = prompt.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }

        if runtime.phase == .running || runtime.phase == .starting || runtime.phase == .waitingApproval {
            runtime.queuedPrompts.append(trimmed)
            return
        }

        runtime.appendUserPrompt(trimmed)
        runtime.errorMessage = nil
        runtime.phase = .starting
        turnStarter.startTurn(
            sessionId: runtime.id,
            threadId: runtime.threadId,
            cwd: runtime.cwd,
            prompt: trimmed
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
