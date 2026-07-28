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
    /// 单调递增的内容版本。会话表格用它做 O(1) 行高缓存失效，避免仅按
    /// UTF-8 字节数判断时漏掉 `abc` → `中` 这类等字节替换。
    public private(set) var revision: UInt64 = 0

    public init() {}

    public func append(_ suffix: String) {
        guard !suffix.isEmpty else { return }
        text.append(contentsOf: suffix)
        revision &+= 1
        notify(.append(suffix))
    }

    public func replace(with nextText: String) {
        text = nextText
        revision &+= 1
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
