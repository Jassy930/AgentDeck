import Foundation
import AgentDeckCore

struct HistoryThreadRowPresentation: Equatable {
    enum VisualState: Equatable {
        case idle
        case hovered
        case selected
        case opening
    }

    let visualState: VisualState
    let usesFullRowHitTarget = true
    let runtimePhase: SessionModel.Phase?
    let unreadEventCount: Int

    init(
        threadId: String,
        selectedThreadId: String?,
        openingThreadId: String?,
        hoveredThreadId: String?,
        runtimePhase: SessionModel.Phase? = nil,
        unreadEventCount: Int = 0
    ) {
        if openingThreadId == threadId {
            visualState = .opening
        } else if selectedThreadId == threadId {
            visualState = .selected
        } else if hoveredThreadId == threadId {
            visualState = .hovered
        } else {
            visualState = .idle
        }

        self.runtimePhase = runtimePhase
        self.unreadEventCount = unreadEventCount
    }

    var isEmphasized: Bool {
        visualState == .selected || visualState == .opening
    }

    var hasRuntimeIndicator: Bool {
        runtimePhase != nil
    }

    var hasUnreadIndicator: Bool {
        unreadEventCount > 0
    }

    var runtimeStatusLabel: String? {
        runtimePhase?.rawValue
    }
}
