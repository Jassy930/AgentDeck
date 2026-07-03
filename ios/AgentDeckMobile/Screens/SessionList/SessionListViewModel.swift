import Foundation

@MainActor
final class SessionListViewModel {
    private let source: MobileSessionSource
    private let machineID: String
    private(set) var groups: [(group: SessionGroup, sessions: [SessionSummary])] = []
    var onUpdate: (() -> Void)?
    private var task: Task<Void, Never>?

    init(source: MobileSessionSource, machineID: String) {
        self.source = source
        self.machineID = machineID
    }

    func start() {
        task = Task { [weak self] in
            guard let source = self?.source, let machineID = self?.machineID else { return }
            let stream = source.sessions(machineID: machineID)
            for await sessions in stream {
                self?.groups = [SessionGroup.waitingApproval, .active, .recent].compactMap { group in
                    let matched = sessions.filter { $0.group == group }
                    return matched.isEmpty ? nil : (group, matched)
                }
                self?.onUpdate?()
            }
        }
    }

    deinit { task?.cancel() }
}
