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
}

final class SessionTextSelectionActivationView: NSView {
    weak var owner: SessionTextSelectionOwner?
    var selectionCoordinator: SessionTextSelectionCoordinator = .shared
    nonisolated(unsafe) private var localMouseDownMonitor: Any?

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        installMonitor()
    }

    required init?(coder: NSCoder) {
        super.init(coder: coder)
        installMonitor()
    }

    deinit {
        if let localMouseDownMonitor {
            NSEvent.removeMonitor(localMouseDownMonitor)
        }
    }

    override func hitTest(_ point: NSPoint) -> NSView? {
        nil
    }

    private func installMonitor() {
        localMouseDownMonitor = NSEvent.addLocalMonitorForEvents(matching: .leftMouseDown) { [weak self] event in
            self?.activateIfEventIsInside(event)
            return event
        }
    }

    private func activateIfEventIsInside(_ event: NSEvent) {
        guard let owner, event.window === window else { return }
        let localPoint = convert(event.locationInWindow, from: nil)
        if bounds.contains(localPoint) {
            selectionCoordinator.activate(owner)
        }
    }
}
