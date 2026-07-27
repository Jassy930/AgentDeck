import AgentDeckSessionSource
import Foundation

@MainActor
final class InboxViewModel {
    private let source: any SessionSource
    private(set) var resourceState: ResourceState<[InboxItem]> = .loading(previous: nil)
    private(set) var items: [InboxItem] = []
    var onUpdate: (() -> Void)?
    private var task: Task<Void, Never>?

    init(source: any SessionSource) {
        self.source = source
    }

    func start() {
        guard task == nil else { return }
        let source = source
        task = Task { [weak self, source] in
            let stream = await source.inbox()
            for await state in stream {
                guard !Task.isCancelled, let self else { break }
                consume(state)
            }
            guard let self else { return }
            task = nil
        }
    }

    private func consume(_ state: ResourceState<[InboxItem]>) {
        resourceState = state
        switch state {
        case .loading(let previous):
            if let previous { items = previous }
        case .ready(let value, _), .stale(let value, _):
            items = value
        case .failed:
            items = []
        }
        onUpdate?()
    }

    deinit { task?.cancel() }
}
