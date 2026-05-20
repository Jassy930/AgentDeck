import Foundation
import Observation

@MainActor
@Observable
final class WorkbenchModel {
    private(set) var runtimes: [String: ThreadRuntimeModel] = [:]
    var selectedSessionId: String?

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

        runtime.ingest(IpcMessage(
            kind: kind,
            sessionId: sessionId,
            threadId: msg.threadId,
            payload: legacyPayload(from: event)
        ))
    }

    private func legacyPayload(from event: [String: Any]) -> AnyCodable? {
        if let wrappedPayload = event["payload"] {
            return AnyCodable(wrappedPayload)
        }

        let unwrapped = event.filter { key, _ in key != "kind" }
        return unwrapped.isEmpty ? nil : AnyCodable(unwrapped)
    }
}
