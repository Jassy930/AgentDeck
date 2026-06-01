import Foundation
import Observation

enum RuntimeAction: Equatable {
    case drainNextPrompt(String)
}

struct ActionRequest: Equatable {
    let requestId: UInt64
    let itemId: String
    let approvalId: String?
    let actionKind: String
    let title: String
    let detail: String
}

@MainActor
@Observable
final class ThreadRuntimeModel: Identifiable {
    let id: String
    var threadId: String?
    var cwd: URL
    var phase: SessionModel.Phase = .ready
    var items: [UIItem] = []
    var queuedPrompts: [String] = []
    var errorMessage: String?
    var warningMessage: String?
    var pendingActionRequest: ActionRequest?
    var unreadEventCount = 0
    var itemIndexById: [String: Int] = [:]
    var pendingAgentItems: [[String: Any]] = []
    private var renderFlushTimer: Timer?
    private let renderFlushInterval: TimeInterval = 1.0 / 30.0

    init(id: String, threadId: String?, cwd: URL) {
        self.id = id
        self.threadId = threadId
        self.cwd = cwd
    }

    var displayTitle: String {
        let project = cwd.lastPathComponent
        if !project.isEmpty {
            return project
        }
        return threadId ?? id
    }

    var statusLabel: String {
        if !queuedPrompts.isEmpty {
            return "\(phase.rawValue) +\(queuedPrompts.count)"
        }
        return phase.rawValue
    }

    @discardableResult
    func ingest(_ msg: IpcMessage) -> RuntimeAction? {
        unreadEventCount += 1

        switch msg.kind {
        case "agentItem":
            if let dict = msg.payload?.value as? [String: Any] {
                enqueueAgentItem(dict)
            }
            return nil
        case "sessionState":
            flushPendingAgentItems()
            if let s = (msg.payload?.value as? [String: Any])?["state"] as? String,
               let p = SessionModel.Phase(rawValue: s) {
                phase = p
            }
            return nil
        case "turnComplete":
            flushPendingAgentItems()
            phase = .ready
            return drainQueueIfPossible()
        case "error":
            flushPendingAgentItems()
            let m = (msg.payload?.value as? [String: Any])?["message"] as? String
            errorMessage = m ?? "unknown error"
            phase = .failed
            return nil
        case "warning":
            let m = (msg.payload?.value as? [String: Any])?["message"] as? String
            warningMessage = m ?? "unknown warning"
            return nil
        case "actionRequest":
            flushPendingAgentItems()
            if let action = Self.actionRequest(from: msg.payload?.value as? [String: Any]) {
                pendingActionRequest = action
                phase = .waitingApproval
            }
            return nil
        default:
            return nil
        }
    }

    func resolvePendingAction() -> ActionRequest? {
        let request = pendingActionRequest
        pendingActionRequest = nil
        if phase == .waitingApproval {
            phase = .running
        }
        return request
    }

    @discardableResult
    func appendUserPrompt(_ prompt: String) -> String {
        let userItem = UIItem(
            id: "user-\(UUID().uuidString)",
            lifecycle: "completed",
            kind: "user",
            text: prompt
        )
        itemIndexById[userItem.id] = items.count
        items.append(userItem)
        return userItem.id
    }

    private func drainQueueIfPossible() -> RuntimeAction? {
        guard !queuedPrompts.isEmpty, phase == .ready else { return nil }
        return .drainNextPrompt(queuedPrompts.removeFirst())
    }

    private func enqueueAgentItem(_ item: [String: Any]) {
        pendingAgentItems.append(item)
        if item["lifecycle"] as? String != "delta" {
            flushPendingAgentItems()
            return
        }
        guard renderFlushTimer == nil else {
            return
        }
        renderFlushTimer = Timer.scheduledTimer(
            withTimeInterval: renderFlushInterval,
            repeats: false
        ) { [weak self] _ in
            Task { @MainActor in self?.flushPendingAgentItems() }
        }
    }

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

    func applyReplayItems(_ replayItems: [HistoryReplayItem]) {
        flushPendingAgentItems()
        itemIndexById.removeAll(keepingCapacity: true)
        items = replayItems.map { agentDeckUIItem(from: $0) }
        for (index, item) in items.enumerated() {
            itemIndexById[item.id] = index
        }
        errorMessage = nil
        phase = .ready
    }

    @discardableResult
    func materializeDeferredContent(itemId: String, content: SessionModel.DeferredContent) -> Bool {
        let lookupId = itemIndexById[itemId] == nil
            ? itemId.split(separator: ":", maxSplits: 1).last.map(String.init)
            : itemId
        guard let lookupId,
              let idx = itemIndexById[lookupId],
              items.indices.contains(idx) else { return false }
        switch content {
        case .output:
            guard items[idx].hasDeferredOutputBuffer else { return false }
            items[idx].outputBuffer.replace(with: items[idx].output)
            items[idx].hasDeferredOutputBuffer = false
        case .diff:
            guard items[idx].hasDeferredDiffBuffer else { return false }
            items[idx].diffBuffer.replace(with: items[idx].diff)
            items[idx].hasDeferredDiffBuffer = false
        }
        return true
    }

    private func upsert(_ d: [String: Any]) {
        var store = AgentItemStore(items: items, itemIndexById: itemIndexById)
        AgentItemReducer.upsert(d, into: &store)
        items = store.items
        itemIndexById = store.itemIndexById
    }

    private static func actionRequest(from payload: [String: Any]?) -> ActionRequest? {
        guard let payload,
              let requestId = payload["requestId"] as? UInt64 ?? (payload["requestId"] as? Int).map(UInt64.init),
              let itemId = payload["itemId"] as? String,
              let actionKind = payload["actionKind"] as? String,
              let title = payload["title"] as? String,
              let detail = payload["detail"] as? String else { return nil }
        return ActionRequest(
            requestId: requestId,
            itemId: itemId,
            approvalId: payload["approvalId"] as? String,
            actionKind: actionKind,
            title: title,
            detail: detail
        )
    }
}
