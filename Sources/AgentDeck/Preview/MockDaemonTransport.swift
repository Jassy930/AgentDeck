import Foundation
import AgentDeckCore

/// preview 模式的进程内 mock 后端：实现 DaemonTransport，收前端真实 IPC 请求、
/// 异步回吐脚本化帧。前端全链路（编解码、路由、渲染）保持真实。仅 preview 路径引用。
final class MockDaemonTransport: DaemonTransport {
    private let queue = DispatchQueue(label: "agentdeck.mock-daemon")
    private var incoming: ((String) -> Void)?
    private var disconnect: (() -> Void)?
    private var started = false
    private var sessionCounter = 0
    private let encoder = JSONEncoder()

    var isStarted: Bool { started }
    var isAlive: Bool { started }

    func setIncomingHandler(_ handler: @escaping (String) -> Void) { incoming = handler }
    func setDisconnectHandler(_ handler: @escaping () -> Void) { disconnect = handler }

    func start() throws { started = true }

    func shutdown() {
        guard started else { return }
        started = false
        disconnect?()
    }

    func send(_ line: String) throws {
        guard started else { throw TransportError.notStarted }
        guard let command = try? JSONDecoder().decode(ClientCommand.self, from: Data(line.utf8)) else {
            emit(errorFrame(message: "unparseable client line: \(line)"))
            return
        }
        handle(command)
    }

    // MARK: - Command dispatch

    private func handle(_ command: ClientCommand) {
        switch command {
        case .ping:
            emitAdmin(reply: "ping", extra: [:])
        case .selfcheck:
            emitAdmin(reply: "selfcheck", extra: [:])
        case .protocolSchema:
            emitAdmin(reply: "protocolSchema", extra: [:])
        case .protocolVersion:
            emitAdmin(reply: "protocolVersion", extra: ["version": 2])
        case .agentList:
            emitAdmin(reply: "agentList", extra: ["agents": ["codex", "claude_code"]])
        case .agentCapabilities:
            // preview 未走该 admin 调用；返回裸 reply（若被调用会由前端报缺字段，属预期）。
            emitAdmin(reply: "agentCapabilities", extra: [:])
        case .history(let req):
            handleHistory(req)
        case .sessionStart:
            emitLiveTurn(threadId: "mock-live-thread")
        case .sessionContinue(let threadId, _, _, _):
            emitLiveTurn(threadId: threadId)
        case .actionDecision, .vendorControl, .sessionCancel:
            break // preview 下静默 ack
        }
    }

    private func handleHistory(_ req: HistoryRequest) {
        let response: HistoryResponse
        switch req {
        case .list:
            response = .list(MockDaemonScript.historyList())
        case .read(let threadId, _):
            response = .read(MockDaemonScript.readResponse(threadId: threadId))
        case .archive, .unarchive, .rename:
            response = .ack
        }
        guard let responseJSON = try? String(data: encoder.encode(response), encoding: .utf8) ?? "" else { return }
        emit("{\"reply\":\"history\",\"response\":\(responseJSON)}")
    }

    private func emitLiveTurn(threadId: String) {
        sessionCounter += 1
        let sessionId = "mock-session-\(sessionCounter)"
        for event in MockDaemonScript.liveTurnEvents(sessionId: sessionId, threadId: threadId) {
            if let json = try? String(data: encoder.encode(event), encoding: .utf8) ?? "" {
                emit(json)
            }
        }
    }

    // MARK: - Frame emission

    private func emit(_ line: String) {
        queue.asyncAfter(deadline: .now() + 0.03) { [weak self] in
            self?.incoming?(line)
        }
    }

    private func emitAdmin(reply: String, extra: [String: Any]) {
        var obj: [String: Any] = ["reply": reply]
        obj.merge(extra) { _, new in new }
        if let data = try? JSONSerialization.data(withJSONObject: obj),
           let line = String(data: data, encoding: .utf8) {
            emit(line)
        }
    }

    private func errorFrame(message: String) -> String {
        let event = ServerEvent.error(sessionId: nil, error: ProtocolError(code: "mock.malformed", message: message))
        return (try? String(data: encoder.encode(event), encoding: .utf8) ?? "") ?? ""
    }
}
