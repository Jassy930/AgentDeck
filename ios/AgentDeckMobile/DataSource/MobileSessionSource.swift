import Foundation
import AgentDeckCore

/// iOS 端唯一数据入口。当前唯一实现是 FixtureSessionSource（bundle 内
/// JSON 回放）；真实数据源不在本轮范围内。
@MainActor
protocol MobileSessionSource: AnyObject {
    func machines() -> AsyncStream<[MachineSummary]>
    func sessions(machineID: String) -> AsyncStream<[SessionSummary]>
    func events(sessionID: String) -> AsyncStream<SessionStreamElement>
    func inbox() -> AsyncStream<[InboxItem]>
    func sendPrompt(sessionID: String, text: String) async
    func resolveApproval(sessionID: String, requestID: String, approve: Bool) async
}
