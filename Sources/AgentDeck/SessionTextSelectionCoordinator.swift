import AppKit

@MainActor
final class SessionTextSelectionOwner {
    private let clearHandler: () -> Void

    convenience init(_ clearHandler: @escaping () -> Void) {
        self.init(clearHandler: clearHandler)
    }

    init(clearHandler: @escaping () -> Void) {
        self.clearHandler = clearHandler
    }

    func clearSelection() {
        clearHandler()
    }
}

@MainActor
final class SessionTextSelectionCoordinator {
    static let shared = SessionTextSelectionCoordinator()

    private weak var activeOwner: SessionTextSelectionOwner?

    func activate(_ owner: SessionTextSelectionOwner) {
        guard activeOwner !== owner else { return }
        activeOwner?.clearSelection()
        activeOwner = owner
    }

    func deactivate(_ owner: SessionTextSelectionOwner) {
        guard activeOwner === owner else { return }
        activeOwner = nil
    }

    /// Clear the currently active selection (if any) and deregister the owner.
    /// After this call, a freshly activated owner will NOT trigger the old
    /// owner's clearSelection — proving activeOwner was reset.
    func clearActiveSelection() {
        activeOwner?.clearSelection()
        activeOwner = nil
    }
}

