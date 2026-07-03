import Foundation
import AgentDeckCore

/// iOS 端唯一数据入口。本期唯一实现是 FixtureSessionSource（bundle 内
/// JSON 回放）；R2 Relay 就绪后新增 RelaySessionSource，视图层不动。
@MainActor
protocol MobileSessionSource: AnyObject {
    func machines() -> AsyncStream<[MachineSummary]>
    func sessions(machineID: String) -> AsyncStream<[SessionSummary]>
    func events(sessionID: String) -> AsyncStream<SessionStreamElement>
    func inbox() -> AsyncStream<[InboxItem]>
    func sendPrompt(sessionID: String, text: String) async
    func resolveApproval(sessionID: String, requestID: String, approve: Bool) async
}
