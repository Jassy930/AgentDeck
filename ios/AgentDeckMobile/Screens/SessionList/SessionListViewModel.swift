import AgentDeckSessionSource
import Foundation

@MainActor
final class SessionListViewModel {
    private let source: any SessionSource
    private let machineID: String
    private(set) var resourceState: ResourceState<[ConversationSummary]> = .loading(previous: nil)
    private(set) var groups: [(group: ConversationGroup, sessions: [ConversationSummary])] = []
    var onUpdate: (() -> Void)?
    private var task: Task<Void, Never>?

    init(source: any SessionSource, machineID: String) {
        self.source = source
        self.machineID = machineID
    }

    func start() {
        guard task == nil else { return }
        let source = source
        let machineID = machineID
        task = Task { [weak self, source, machineID] in
            let stream = await source.conversations(machineID: machineID)
            for await state in stream {
                guard !Task.isCancelled, let self else { break }
                consume(state)
            }
            guard let self else { return }
            task = nil
        }
    }

    private func consume(_ state: ResourceState<[ConversationSummary]>) {
        resourceState = state
        switch state {
        case .loading(let previous):
            if let previous { rebuildGroups(from: previous) }
        case .ready(let value, _), .stale(let value, _):
            rebuildGroups(from: value)
        case .failed:
            groups = []
        }
        onUpdate?()
    }

    private func rebuildGroups(from conversations: [ConversationSummary]) {
        groups = [ConversationGroup.waitingApproval, .active, .recent].compactMap { group in
            let matches = conversations.filter { $0.group == group }
            return matches.isEmpty ? nil : (group, matches)
        }
    }

    deinit { task?.cancel() }
}
