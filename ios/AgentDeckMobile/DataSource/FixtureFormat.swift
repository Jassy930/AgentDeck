import AgentDeckCore
import AgentDeckSessionSource
import Foundation

enum FixtureMachineConnectionState: String, Decodable, Equatable, Sendable {
    case connecting
    case connected
    case relayUnavailable
    case machineOffline
    case reconnecting
    case revoked
    case incompatible
    case securityError

    var sessionSourceValue: SessionConnectionState {
        switch self {
        case .connecting: .connecting
        case .connected: .connected
        case .relayUnavailable: .relayUnavailable
        case .machineOffline: .machineOffline
        case .reconnecting: .reconnecting
        case .revoked: .revoked
        case .incompatible: .incompatible
        case .securityError: .securityError
        }
    }
}

struct FixtureMachine: Decodable, Sendable {
    let id: String
    let name: String
    let connectionState: FixtureMachineConnectionState
    /// 相对秒数而非绝对时间戳，让 fixture 不随日期腐烂。
    let lastHeartbeatSecondsAgo: Int?
}

struct FixtureSession: Decodable, Sendable {
    let id: String
    let machineId: String
    let title: String
    let cwd: String
    let agentKind: AgentKind
    let group: ConversationGroup
    let lastActiveMs: UInt64
    let archived: Bool
    let revision: UInt64
    /// 对应 ios/Fixtures/<stream>.json；无流的纯历史行可为 nil。
    let stream: String?
}

struct FixtureDeck: Decodable, Sendable {
    let machines: [FixtureMachine]
    let sessions: [FixtureSession]
}

/// Fixture 直接承载共享 canonical snapshot 和 Runtime v2 event，不再维护一套
/// `ServerEvent` 镜像。approval step 在 `awaitApproval` 后暂停，由 actor 插入
/// exact-next `approvalResolved`，因此下一条静态 event 会预留一个 sequence。
struct FixtureConversation: Decodable, Sendable {
    let snapshot: ConversationSnapshotV2
    let steps: [FixtureStreamStep]
}

struct FixtureStreamStep: Decodable, Sendable {
    let delayMs: Int
    let awaitApproval: Bool?
    let event: RuntimeEventV2
}
