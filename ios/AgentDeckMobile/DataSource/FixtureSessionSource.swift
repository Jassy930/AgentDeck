import Foundation
import AgentDeckCore

@MainActor
final class FixtureSessionSource: MobileSessionSource {

    private final class Playback {
        var transcript: [SessionStreamElement] = []
        var subscribers: [UUID: AsyncStream<SessionStreamElement>.Continuation] = [:]
        var approvalGate: CheckedContinuation<Void, Never>?
        var started = false
        var finished = false
    }

    private let bundle: Bundle
    private let tickScale: Double
    private var machineRows: [FixtureMachine] = []
    private var sessionRows: [SessionSummary] = []
    private var playbacks: [String: Playback] = [:]
    private var machineSubs: [UUID: AsyncStream<[MachineSummary]>.Continuation] = [:]
    private var sessionSubs: [UUID: (machineID: String, cont: AsyncStream<[SessionSummary]>.Continuation)] = [:]
    private var inboxItems: [InboxItem] = []
    private var inboxSubs: [UUID: AsyncStream<[InboxItem]>.Continuation] = [:]
    private var promptSeq = 0

    init(bundle: Bundle = .main, tickScale: Double = 1.0) {
        self.bundle = bundle
        self.tickScale = tickScale
        loadDeck()
    }

    private func loadDeck() {
        guard let url = bundle.url(forResource: "deck", withExtension: "json"),
              let deck = try? JSONDecoder().decode(FixtureDeck.self, from: Data(contentsOf: url))
        else {
            assertionFailure("deck.json 缺失或无法解码")
            return
        }
        machineRows = deck.machines
        sessionRows = deck.sessions.map {
            SessionSummary(
                id: $0.id, machineID: $0.machineId, title: $0.title, cwd: $0.cwd,
                agentKind: $0.agentKind, group: $0.group, streamResource: $0.stream
            )
        }
        inboxItems = sessionRows.filter { $0.group == .waitingApproval }.map {
            InboxItem(id: "inbox-\($0.id)", sessionID: $0.id, machineID: $0.machineID,
                      kind: .waitingApproval, title: $0.title)
        }
    }

    // MARK: - Snapshots

    private func machineSummaries() -> [MachineSummary] {
        machineRows.map { m in
            let sessions = sessionRows.filter { $0.machineID == m.id }
            return MachineSummary(
                id: m.id, name: m.name, isOnline: m.isOnline,
                lastHeartbeat: m.lastHeartbeatSecondsAgo.map { Date(timeIntervalSinceNow: -Double($0)) },
                activeSessionCount: sessions.filter { $0.group == .active }.count,
                pendingApprovalCount: sessions.filter { $0.group == .waitingApproval }.count
            )
        }
    }

    private func broadcastState() {
        let machines = machineSummaries()
        for cont in machineSubs.values { cont.yield(machines) }
        for (_, sub) in sessionSubs {
            sub.cont.yield(sessionRows.filter { $0.machineID == sub.machineID })
        }
        for cont in inboxSubs.values { cont.yield(inboxItems) }
    }

    // MARK: - MobileSessionSource

    func machines() -> AsyncStream<[MachineSummary]> {
        AsyncStream { cont in
            let id = UUID()
            machineSubs[id] = cont
            cont.yield(machineSummaries())
            cont.onTermination = { _ in
                Task { @MainActor [weak self] in self?.machineSubs[id] = nil }
            }
        }
    }

    func sessions(machineID: String) -> AsyncStream<[SessionSummary]> {
        AsyncStream { cont in
            let id = UUID()
            sessionSubs[id] = (machineID, cont)
            cont.yield(sessionRows.filter { $0.machineID == machineID })
            cont.onTermination = { _ in
                Task { @MainActor [weak self] in self?.sessionSubs[id] = nil }
            }
        }
    }

    func events(sessionID: String) -> AsyncStream<SessionStreamElement> {
        let playback = playbacks[sessionID] ?? Playback()
        playbacks[sessionID] = playback
        startPlaybackIfNeeded(sessionID: sessionID, playback: playback)
        return AsyncStream { cont in
            let id = UUID()
            for element in playback.transcript { cont.yield(element) }
            if playback.finished {
                cont.finish()
            } else {
                playback.subscribers[id] = cont
                cont.onTermination = { _ in
                    Task { @MainActor [weak self] in self?.playbacks[sessionID]?.subscribers[id] = nil }
                }
            }
        }
    }

    func inbox() -> AsyncStream<[InboxItem]> {
        AsyncStream { cont in
            let id = UUID()
            inboxSubs[id] = cont
            cont.yield(inboxItems)
            cont.onTermination = { _ in
                Task { @MainActor [weak self] in self?.inboxSubs[id] = nil }
            }
        }
    }

    func sendPrompt(sessionID: String, text: String) async {
        guard let playback = playbacks[sessionID] else { return }
        guard let session = sessionRows.first(where: { $0.id == sessionID }) else { return }
        promptSeq += 1
        let seq = promptSeq
        playback.finished = false
        let kind = session.agentKind
        let threadId = "t-prompt-\(seq)"
        emit(SessionStreamElement(
            itemId: "prompt-user-\(seq)",
            event: .agentItem(sessionId: sessionID, threadId: threadId, agentKind: kind,
                              item: .userMessage(text: text, meta: AgentItemMeta()))
        ), sessionID: sessionID, playback: playback)
        let reply = "（fixture 回声）收到：\(text)。真实链路接入后此处为 agent 输出。"
        await sleepTicks(600)
        emit(SessionStreamElement(
            itemId: "prompt-reply-\(seq)",
            event: .agentItem(sessionId: sessionID, threadId: threadId, agentKind: kind,
                              item: .assistantMessage(text: reply, meta: AgentItemMeta()))
        ), sessionID: sessionID, playback: playback)
        await sleepTicks(200)
        emit(SessionStreamElement(
            itemId: nil,
            event: .turnComplete(sessionId: sessionID, threadId: threadId, agentKind: kind,
                                 summary: TurnSummary(elapsedMs: 800))
        ), sessionID: sessionID, playback: playback)
        appendInbox(.init(id: "inbox-turn-\(sessionID)-\(seq)", sessionID: sessionID,
                          machineID: session.machineID, kind: .turnCompleted, title: session.title))
        // sendPrompt 发完后标记完成，允许当前订阅者及后续二次订阅拿到完整 transcript。
        playback.finished = true
        for cont in playback.subscribers.values { cont.finish() }
        playback.subscribers.removeAll()
    }

    func resolveApproval(sessionID: String, requestID: String, approve: Bool) async {
        guard let playback = playbacks[sessionID] else { return }
        if let index = sessionRows.firstIndex(where: { $0.id == sessionID }) {
            sessionRows[index].group = .active
        }
        inboxItems.removeAll { $0.sessionID == sessionID && $0.kind == .waitingApproval }
        broadcastState()
        playback.approvalGate?.resume()
        playback.approvalGate = nil
        _ = approve // fixture 状态机不区分 approve/deny 的后续流；卡片状态由 view model 记录
    }

    // MARK: - Playback

    private func startPlaybackIfNeeded(sessionID: String, playback: Playback) {
        guard !playback.started else { return }
        playback.started = true
        guard let resource = sessionRows.first(where: { $0.id == sessionID })?.streamResource,
              let url = bundle.url(forResource: resource, withExtension: "json"),
              let steps = try? JSONDecoder().decode([FixtureStreamStep].self, from: Data(contentsOf: url))
        else {
            playback.finished = true
            return
        }
        Task { [weak self] in
            for step in steps {
                await self?.sleepTicks(step.delayMs)
                guard let self else { return }
                self.emit(SessionStreamElement(itemId: step.itemId, event: step.event),
                          sessionID: sessionID, playback: playback)
                self.noteSideEffects(of: step.event, sessionID: sessionID)
                if step.awaitApproval == true {
                    await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
                        playback.approvalGate = cont
                    }
                }
            }
            playback.finished = true
            for cont in playback.subscribers.values { cont.finish() }
            playback.subscribers.removeAll()
        }
    }

    private func emit(_ element: SessionStreamElement, sessionID: String, playback: Playback) {
        playback.transcript.append(element)
        for cont in playback.subscribers.values { cont.yield(element) }
    }

    private func noteSideEffects(of event: ServerEvent, sessionID: String) {
        guard let session = sessionRows.first(where: { $0.id == sessionID }) else { return }
        switch event {
        case .actionRequest:
            if let index = sessionRows.firstIndex(where: { $0.id == sessionID }) {
                sessionRows[index].group = .waitingApproval
            }
            if !inboxItems.contains(where: { $0.sessionID == sessionID && $0.kind == .waitingApproval }) {
                inboxItems.append(.init(id: "inbox-\(sessionID)", sessionID: sessionID,
                                        machineID: session.machineID, kind: .waitingApproval, title: session.title))
            }
            broadcastState()
        case .turnComplete:
            appendInbox(.init(id: "inbox-done-\(sessionID)", sessionID: sessionID,
                              machineID: session.machineID, kind: .turnCompleted, title: session.title))
        case .error:
            if let index = sessionRows.firstIndex(where: { $0.id == sessionID }) {
                sessionRows[index].group = .recent
            }
            appendInbox(.init(id: "inbox-fail-\(sessionID)", sessionID: sessionID,
                              machineID: session.machineID, kind: .failed, title: session.title))
            broadcastState()
        default:
            break
        }
    }

    private func appendInbox(_ item: InboxItem) {
        guard !inboxItems.contains(where: { $0.id == item.id }) else { return }
        inboxItems.append(item)
        for cont in inboxSubs.values { cont.yield(inboxItems) }
    }

    private func sleepTicks(_ ms: Int) async {
        let ns = UInt64(Double(ms) * 1_000_000 * tickScale)
        if ns > 0 { try? await Task.sleep(nanoseconds: ns) }
    }
}
