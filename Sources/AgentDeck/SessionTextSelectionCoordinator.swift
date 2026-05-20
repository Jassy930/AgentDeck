import AppKit
import SwiftUI

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

struct SessionTextSelectionActivationMonitor: NSViewRepresentable {
    let owner: SessionTextSelectionOwner
    var coordinator: SessionTextSelectionCoordinator = .shared

    func makeNSView(context: Context) -> SessionTextSelectionActivationView {
        let view = SessionTextSelectionActivationView()
        view.owner = owner
        view.selectionCoordinator = coordinator
        return view
    }

    func updateNSView(_ nsView: SessionTextSelectionActivationView, context: Context) {
        nsView.owner = owner
        nsView.selectionCoordinator = coordinator
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
