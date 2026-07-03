import Foundation

public enum StreamingTextBufferChange: Equatable {
    case append(String)
    case replace(String)
}

// Owned by the main-render path. Marked unchecked only so AppKit deinit can
// detach observers under Swift 6's nonisolated deinitializer rules.
public final class StreamingTextBuffer: @unchecked Sendable {
    private var observers: [UUID: (StreamingTextBufferChange) -> Void] = [:]
    public private(set) var text = ""

    public init() {}

    public func append(_ suffix: String) {
        guard !suffix.isEmpty else { return }
        text.append(contentsOf: suffix)
        notify(.append(suffix))
    }

    public func replace(with nextText: String) {
        text = nextText
        notify(.replace(nextText))
    }

    public func observe(_ handler: @escaping (StreamingTextBufferChange) -> Void) -> UUID {
        let id = UUID()
        observers[id] = handler
        handler(.replace(text))
        return id
    }

    public func removeObserver(_ id: UUID) {
        observers.removeValue(forKey: id)
    }

    private func notify(_ change: StreamingTextBufferChange) {
        for observer in observers.values {
            observer(change)
        }
    }
}
