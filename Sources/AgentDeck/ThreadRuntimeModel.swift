import Foundation
import Observation

enum RuntimeAction: Equatable {
    case drainNextPrompt(String)
}

/// UI-shaped pending action snapshot. v2 (Task 6A): builds from
/// `ServerEvent.actionRequest` carrying typed `ActionRequest`.
struct PendingActionRequest: Equatable {
    let requestId: String
    let actionKind: ActionKind
    let summary: String
    let vendor: ActionRequestVendor

    static func == (lhs: PendingActionRequest, rhs: PendingActionRequest) -> Bool {
        lhs.requestId == rhs.requestId &&
        lhs.actionKind == rhs.actionKind &&
        lhs.summary == rhs.summary
    }
}

@MainActor
@Observable
final class ThreadRuntimeModel: Identifiable {
    let id: String                                      // sessionId
    let agentKind: AgentKind
    var threadId: String?
    var cwd: URL
    var phase: SessionModel.Phase = .ready
    var items: [UIItem] = []
    var queuedPrompts: [String] = []
    var errorMessage: String?
    var warningMessage: String?
    var pendingActionRequest: PendingActionRequest?
    var unreadEventCount = 0
    var itemIndexById: [String: Int] = [:]
    private(set) var capabilities: SessionCapabilities?
    private var agentItemSeq: Int = 0

    init(id: String, agentKind: AgentKind, threadId: String? = nil, cwd: URL) {
        self.id = id
        self.agentKind = agentKind
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

    func applyCapabilities(_ caps: SessionCapabilities) {
        self.capabilities = caps
    }

    /// Consume a single v2 ServerEvent. Returns a follow-up action (e.g.
    /// drain queued prompts on turn complete) so the caller can route it.
    @discardableResult
    func ingest(_ event: ServerEvent) -> RuntimeAction? {
        unreadEventCount += 1
        switch event {
        case .sessionStarted(_, let tid, _):
            if let tid, threadId == nil { threadId = tid }
            return nil
        case .sessionCapabilities(_, _, let caps):
            applyCapabilities(caps)
            return nil
        case .agentItem(_, let tid, _, let item):
            if threadId == nil { threadId = tid }
            applyAgentItem(item)
            return nil
        case .actionRequest(_, _, _, let req):
            phase = .waitingApproval
            pendingActionRequest = PendingActionRequest(
                requestId: req.requestId,
                actionKind: req.kind,
                summary: req.summary,
                vendor: req.vendor
            )
            return nil
        case .turnComplete:
            phase = .ready
            return drainQueueIfPossible()
        case .error(_, let err):
            errorMessage = err.message
            phase = .failed
            return nil
        case .vendorControl, .vendorPanelEvent:
            // v0.2: UI ignores vendor side-channels for now; T6B will route.
            return nil
        }
    }

    func resolvePendingAction() -> PendingActionRequest? {
        let pending = pendingActionRequest
        pendingActionRequest = nil
        if phase == .waitingApproval {
            phase = .running
        }
        return pending
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

    func applyReplayTurns(_ turns: [HistoryTurn]) {
        itemIndexById.removeAll(keepingCapacity: true)
        items.removeAll(keepingCapacity: true)
        for turn in turns {
            for item in turn.items {
                applyAgentItem(item)
            }
        }
        errorMessage = nil
        phase = .ready
    }

    /// Bridge for legacy v0.1 `HistoryReplayItem` arrays produced by
    /// HistoryModel decoding. Phase 7+ will replace with native v2 history
    /// once daemon serves the new HistoryResponse shape end-to-end.
    func applyReplayItems(_ replayItems: [HistoryReplayItem]) {
        itemIndexById.removeAll(keepingCapacity: true)
        items.removeAll(keepingCapacity: true)
        for replay in replayItems {
            var ui = agentDeckUIItem(from: replay)
            ui.id = replay.id
            itemIndexById[ui.id] = items.count
            items.append(ui)
        }
        errorMessage = nil
        phase = .ready
    }

    private func drainQueueIfPossible() -> RuntimeAction? {
        guard !queuedPrompts.isEmpty, phase == .ready else { return nil }
        return .drainNextPrompt(queuedPrompts.removeFirst())
    }

    private func applyAgentItem(_ item: AgentItem) {
        agentItemSeq += 1
        let itemId = "ai-\(agentItemSeq)"
        var store = AgentItemStore(items: items, itemIndexById: itemIndexById)
        AgentItemReducer.apply(item, itemId: itemId, into: &store)
        items = store.items
        itemIndexById = store.itemIndexById
    }

    @discardableResult
    func materializeDeferredContent(itemId: String, content: SessionModel.DeferredContent) -> Bool {
        guard let idx = itemIndexById[itemId], items.indices.contains(idx) else { return false }
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
}
