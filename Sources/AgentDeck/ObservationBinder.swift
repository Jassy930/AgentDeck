import Foundation
import Observation

/// 把 @Observable 的字段读取桥接到一次性回调，并自动 re-arm，便于 AppKit
/// 在模型变化时命令式刷新对应区域。onChange 总在 MainActor 调用。
@MainActor
final class ObservationBinder {
    private var isValid = true

    /// 在 `read` 的跟踪上下文中建立依赖；每次被读字段变化时在 MainActor
    /// 调用 `onChange` 并自动重新 arm，直到 `invalidate()`。
    func bind(_ read: @escaping @MainActor () -> Void, onChange: @escaping @MainActor () -> Void) {
        arm(read: read, onChange: onChange)
    }

    private func arm(read: @escaping @MainActor () -> Void, onChange: @escaping @MainActor () -> Void) {
        guard isValid else { return }
        // withObservationTracking 的 apply 闭包在当前 actor 上同步执行。
        withObservationTracking {
            read()
        } onChange: { [weak self] in
            // onChange 回调在变化发生的线程上同步触发（可能不在 MainActor）。
            // 用 MainActor.run 保证 onChange() 和 re-arm 在 MainActor 上执行。
            Task { @MainActor [weak self] in
                guard let self, self.isValid else { return }
                onChange()
                self.arm(read: read, onChange: onChange)
            }
        }
    }

    func invalidate() {
        isValid = false
    }
}
