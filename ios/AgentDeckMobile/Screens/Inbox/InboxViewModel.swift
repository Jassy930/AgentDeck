import Foundation

@MainActor
final class InboxViewModel {
    private let source: MobileSessionSource
    private(set) var items: [InboxItem] = []
    var onUpdate: (() -> Void)?
    private var task: Task<Void, Never>?

    init(source: MobileSessionSource) {
        self.source = source
    }

    func start() {
        task = Task { [weak self] in
            guard let stream = self?.source.inbox() else { return }
            for await items in stream {
                self?.items = items
                self?.onUpdate?()
            }
        }
    }

    deinit { task?.cancel() }
}
