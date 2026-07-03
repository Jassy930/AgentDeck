import Foundation

@MainActor
final class MachineListViewModel {
    private let source: MobileSessionSource
    private(set) var machines: [MachineSummary] = []
    var onUpdate: (() -> Void)?
    private var task: Task<Void, Never>?

    init(source: MobileSessionSource) {
        self.source = source
    }

    func start() {
        task = Task { [weak self] in
            guard let stream = self?.source.machines() else { return }
            for await machines in stream {
                self?.machines = machines
                self?.onUpdate?()
            }
        }
    }

    deinit { task?.cancel() }
}
