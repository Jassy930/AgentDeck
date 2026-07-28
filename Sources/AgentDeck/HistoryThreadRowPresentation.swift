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
        threadIdentity: HistoryThreadIdentity,
        selectedThreadIdentity: HistoryThreadIdentity?,
        openingThreadIdentity: HistoryThreadIdentity?,
        hoveredThreadIdentity: HistoryThreadIdentity?,
        runtimePhase: SessionModel.Phase? = nil,
        unreadEventCount: Int = 0
    ) {
        if openingThreadIdentity == threadIdentity {
            visualState = .opening
        } else if selectedThreadIdentity == threadIdentity {
            visualState = .selected
        } else if hoveredThreadIdentity == threadIdentity {
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
