import AgentDeckSessionSource
import Foundation

struct MachineRowPresentation: Equatable {
    enum Indicator: Equatable {
        case healthy
        case neutral
        case warning
        case danger
    }

    let statusText: String
    let isSelectable: Bool
    let indicator: Indicator

    static func make(from machine: MachineSummary) -> MachineRowPresentation {
        switch machine.connectionState {
        case .connected:
            MachineRowPresentation(
                statusText: "在线",
                isSelectable: true,
                indicator: .healthy
            )
        case .connecting:
            MachineRowPresentation(
                statusText: "正在连接",
                isSelectable: false,
                indicator: .neutral
            )
        case .relayUnavailable:
            MachineRowPresentation(
                statusText: "Relay 不可达",
                isSelectable: false,
                indicator: .warning
            )
        case .machineOffline:
            MachineRowPresentation(
                statusText: "机器离线",
                isSelectable: false,
                indicator: .neutral
            )
        case .reconnecting:
            MachineRowPresentation(
                statusText: "正在重连",
                isSelectable: false,
                indicator: .warning
            )
        case .lagged:
            MachineRowPresentation(
                statusText: "正在重新同步",
                isSelectable: false,
                indicator: .warning
            )
        case .revoked:
            MachineRowPresentation(
                statusText: "授权已撤销",
                isSelectable: false,
                indicator: .danger
            )
        case .incompatible:
            MachineRowPresentation(
                statusText: "版本不兼容",
                isSelectable: false,
                indicator: .danger
            )
        case .securityError:
            MachineRowPresentation(
                statusText: "安全错误",
                isSelectable: false,
                indicator: .danger
            )
        }
    }
}

@MainActor
final class MachineListViewModel {
    private let source: any SessionSource
    private(set) var resourceState: ResourceState<[MachineSummary]> = .loading(previous: nil)
    private(set) var machines: [MachineSummary] = []
    var onUpdate: (() -> Void)?
    private var task: Task<Void, Never>?

    init(source: any SessionSource) {
        self.source = source
    }

    func start() {
        guard task == nil else { return }
        let source = source
        task = Task { [weak self, source] in
            let stream = await source.machines()
            for await state in stream {
                guard !Task.isCancelled, let self else { break }
                consume(state)
            }
            guard let self else { return }
            task = nil
        }
    }

    private func consume(_ state: ResourceState<[MachineSummary]>) {
        resourceState = state
        switch state {
        case .loading(let previous):
            if let previous { machines = previous }
        case .ready(let value, _), .stale(let value, _):
            machines = value
        case .failed:
            machines = []
        }
        onUpdate?()
    }

    deinit { task?.cancel() }
}
