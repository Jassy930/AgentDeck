import Foundation
import AgentDeckMobileCore

struct FixtureMachine: Decodable {
    let id: String
    let name: String
    let isOnline: Bool
    /// 相对秒数而非绝对时间戳，让 fixture 不随日期腐烂。
    let lastHeartbeatSecondsAgo: Int?
}

struct FixtureSession: Decodable {
    let id: String
    let machineId: String
    let title: String
    let cwd: String
    let agentKind: AgentKind
    let group: SessionGroup
    /// 对应 ios/Fixtures/<stream>.json；无流的会话（纯历史行）可为 nil。
    let stream: String?
}

struct FixtureDeck: Decodable {
    let machines: [FixtureMachine]
    let sessions: [FixtureSession]
}

/// 回放信封：event 是协议原样的 ServerEvent JSON；itemId 供 AgentItemReducer
/// 做累积语义槽位（同一 itemId 的后续事件替换同一槽位，模拟流式增长）；
/// awaitApproval=true 表示回放在该事件后暂停，直到 resolveApproval。
struct FixtureStreamStep: Decodable {
    let delayMs: Int
    let itemId: String?
    let awaitApproval: Bool?
    let event: ServerEvent
}
