import Foundation

enum StreamingTextBufferChange: Equatable {
    case append(String)
    case replace(String)
}

// Owned by the main-render path. Marked unchecked only so AppKit deinit can
// detach observers under Swift 6's nonisolated deinitializer rules.
final class StreamingTextBuffer: @unchecked Sendable {
    private var observers: [UUID: (StreamingTextBufferChange) -> Void] = [:]
    private(set) var text = ""

    func append(_ suffix: String) {
        guard !suffix.isEmpty else { return }
        text.append(contentsOf: suffix)
        notify(.append(suffix))
    }

    func replace(with nextText: String) {
        text = nextText
        notify(.replace(nextText))
    }

    func observe(_ handler: @escaping (StreamingTextBufferChange) -> Void) -> UUID {
        let id = UUID()
        observers[id] = handler
        handler(.replace(text))
        return id
    }

    func removeObserver(_ id: UUID) {
        observers.removeValue(forKey: id)
    }

    private func notify(_ change: StreamingTextBufferChange) {
        for observer in observers.values {
            observer(change)
        }
    }
}
