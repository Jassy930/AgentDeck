import Foundation
import AgentDeckMobileCore

enum ApprovalState: Equatable { case none, pending, approved, denied }

@MainActor
final class SessionDetailViewModel {
    private let source: MobileSessionSource
    let sessionID: String
    private(set) var rows: [ConversationDisplayRow] = []
    private(set) var pendingApproval: ActionRequest?
    private(set) var approvalState: ApprovalState = .none
    private(set) var errorText: String?
    private(set) var isStreaming = true
    var onUpdate: (() -> Void)?
    private var store = AgentItemStore()
    private var task: Task<Void, Never>?

    init(source: MobileSessionSource, sessionID: String) {
        self.source = source
        self.sessionID = sessionID
    }

    func start() {
        task = Task { [weak self] in
            guard let source = self?.source, let sessionID = self?.sessionID else { return }
            let stream = source.events(sessionID: sessionID)
            for await element in stream {
                guard let self else { break }
                self.handle(element)
            }
            // 流结束后若 turnComplete 尚未将 isStreaming 设为 false，
            // 在此兜底（error-only 会话不会收到 turnComplete）。
            if self?.isStreaming == true {
                self?.isStreaming = false
                self?.onUpdate?()
            }
        }
    }

    func resolveApproval(approve: Bool) {
        guard let request = pendingApproval else { return }
        approvalState = approve ? .approved : .denied
        onUpdate?()
        Task { [weak self] in
            guard let self else { return }
            await source.resolveApproval(sessionID: sessionID, requestID: request.requestId, approve: approve)
        }
    }

    func sendPrompt(_ text: String) {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, !isStreaming else { return }
        isStreaming = true
        onUpdate?()
        Task { [weak self] in
            guard let self else { return }
            await source.sendPrompt(sessionID: sessionID, text: trimmed)
            // FixtureSessionSource 会在同一 events 流上推送回声（若流已结束，
            // 重新订阅一次以接收后续事件）。
            start()
        }
    }

    private func handle(_ element: SessionStreamElement) {
        var needsUpdate = true
        switch element.event {
        case .agentItem(_, _, _, _, let itemId, let state, let item):
            AgentItemReducer.apply(item, itemId: itemId, state: state, into: &store)
        case .actionRequest(_, _, _, let request):
            pendingApproval = request
            approvalState = .pending
        case .error(_, let protocolError):
            errorText = protocolError.message
            isStreaming = false
        case .turnFinished(_, _, _, _, let outcome, _, _, let error):
            isStreaming = false
            if outcome == .failed {
                errorText = error?.message
            }
        case .sessionClosed(_, _, _, _, let error):
            isStreaming = false
            if let error {
                errorText = error.message
            }
        case .turnComplete:
            isStreaming = false
        case .sessionStarted, .sessionCapabilities, .turnStarted, .vendorControl, .vendorPanelEvent:
            needsUpdate = false
        }
        rows = ConversationDisplayRowBuilder.rows(from: makeConversationTurns(from: store.items))
        if needsUpdate {
            onUpdate?()
        }
    }

    deinit { task?.cancel() }
}
