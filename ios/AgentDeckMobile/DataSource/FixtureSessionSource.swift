import AgentDeckCore
import AgentDeckSessionSource
import Foundation

actor FixtureSessionSource: SessionSource {
    static let resourceBufferLimit = 1
    static let conversationBufferLimit = 512

    private struct PendingPrompt: Sendable {
        let conversationID: String
        let text: String
        let commandID: RuntimeCommandID
    }

    private struct PromptReplay: Sendable {
        let conversationID: String
        let text: String
        let commandID: RuntimeCommandID
        let configurationRevision: UInt64
    }

    private struct PendingApproval: Sendable {
        let turnID: RuntimeTurnID
        let commandID: RuntimeCommandID
        let approvalID: RuntimeApprovalID
        let request: RuntimeActionRequestV1
    }

    private struct ApprovalOutcome: Sendable {
        let turnID: RuntimeTurnID
        let decision: ActionDecisionKind
        var state: ApprovalDeliveryStateV1
    }

    private struct ApprovalReplay: Sendable {
        let conversationID: String
        let turnID: String
        let approvalID: String
        let decision: ActionDecisionKind
        let receipt: ApprovalReceipt
    }

    private final class Playback {
        let fixture: FixtureConversation
        let connectionState: SessionConnectionState
        var transcript: [ConversationUpdate]
        var subscribers: [UUID: AsyncStream<ConversationUpdate>.Continuation] = [:]
        var approvalGate: CheckedContinuation<Void, Never>?
        var pendingApproval: PendingApproval?
        var approvalOutcomes: [RuntimeApprovalID: ApprovalOutcome] = [:]
        var pendingPrompts: [PendingPrompt] = []
        var nextEventSeq: UInt64
        var started = false
        var scriptFinished = false
        var promptDrainRunning = false
        var task: Task<Void, Never>?
        var canonicalState: RuntimeConversationState
        var currentSnapshot: ConversationSnapshotV2
        var snapshotItems: [SnapshotItemV1]
        var snapshotItemIndexByID: [RuntimeItemID: Int]
        var transcriptWasCompacted = false

        init(
            fixture: FixtureConversation,
            connectionState: SessionConnectionState
        ) throws {
            var canonicalState = try RuntimeConversationState(
                conversationID: fixture.snapshot.conversationID
            )
            try canonicalState.apply(fixture.snapshot)
            var snapshotItemIndexByID: [RuntimeItemID: Int] = [:]
            for (index, item) in fixture.snapshot.items.enumerated() {
                if case .item(let itemID, _, _, _) = item {
                    snapshotItemIndexByID[itemID] = index
                }
            }

            self.fixture = fixture
            self.connectionState = connectionState
            transcript = [
                .snapshot(fixture.snapshot),
                .connectionState(connectionState),
            ]
            nextEventSeq = try fixture.snapshot.baseEventCursor.checkedNext()
            self.canonicalState = canonicalState
            currentSnapshot = fixture.snapshot
            snapshotItems = fixture.snapshot.items
            self.snapshotItemIndexByID = snapshotItemIndexByID
        }

        func applyCanonicalEvent(_ event: RuntimeEventV2) throws {
            var nextState = canonicalState
            try nextState.apply(event)

            var nextItems = snapshotItems
            var nextItemIndexByID = snapshotItemIndexByID
            var nextConfiguration = currentSnapshot.configurationState
            switch event.body {
            case .capabilities(let capabilities):
                guard !nextItems.isEmpty,
                    case .capabilities = nextItems[0]
                else {
                    throw SessionSourceFailure(
                        code: .securityError,
                        message: "fixture snapshot 缺少 capabilities"
                    )
                }
                nextItems[0] = .capabilities(capabilities)
            case .configurationChanged(let configuration):
                nextConfiguration = configuration
            case .item(let item):
                guard let itemID = event.itemID, let entityID = event.entityID else {
                    throw SessionSourceFailure(
                        code: .securityError,
                        message: "fixture item event 缺少 canonical identity"
                    )
                }
                let snapshotItem = SnapshotItemV1.item(
                    itemID: itemID,
                    entityID: entityID,
                    commandID: event.commandID,
                    item: item
                )
                if let index = nextItemIndexByID[itemID] {
                    nextItems[index] = snapshotItem
                } else {
                    nextItemIndexByID[itemID] = nextItems.count
                    nextItems.append(snapshotItem)
                }
            case .vendorPanelEvent, .turnStarted, .actionRequest, .approvalResolved,
                .turnCompleted, .turnInterrupted, .error:
                break
            }

            let nextSnapshot = try ConversationSnapshotV2(
                conversationID: fixture.snapshot.conversationID,
                baseEventCursor: nextState.cursorState.cursor,
                configurationState: nextConfiguration,
                items: nextItems
            )
            canonicalState = nextState
            currentSnapshot = nextSnapshot
            snapshotItems = nextItems
            snapshotItemIndexByID = nextItemIndexByID
        }

        func refreshCompactedTranscriptForLateSubscriber() {
            guard transcriptWasCompacted else { return }
            transcript = [
                .snapshot(currentSnapshot),
                .connectionState(connectionState),
            ]
        }
    }

    private let bundle: Bundle
    private let tickScale: Double
    private var machineRows: [FixtureMachine] = []
    private var conversationRows: [ConversationSummary] = []
    private var streamResourceByConversation: [String: String] = [:]
    private var playbacks: [String: Playback] = [:]
    private var machineSubscribers:
        [UUID: AsyncStream<ResourceState<[MachineSummary]>>.Continuation] = [:]
    private var conversationListSubscribers:
        [UUID: (
            machineID: String,
            continuation: AsyncStream<ResourceState<[ConversationSummary]>>.Continuation
        )] = [:]
    private var inboxItems: [InboxItem] = []
    private var inboxSubscribers: [UUID: AsyncStream<ResourceState<[InboxItem]>>.Continuation] = [:]
    private var resourceRevision: UInt64 = 1
    private var promptReplays: [UUID: PromptReplay] = [:]
    private var approvalReplays: [UUID: ApprovalReplay] = [:]

    init(bundle: Bundle = .main, tickScale: Double = 1.0) {
        self.bundle = bundle
        self.tickScale = tickScale
        guard let url = bundle.url(forResource: "deck", withExtension: "json"),
            let deck = try? JSONDecoder().decode(
                FixtureDeck.self,
                from: Data(contentsOf: url)
            )
        else {
            assertionFailure("deck.json 缺失或无法解码")
            return
        }

        machineRows = deck.machines
        var resources: [String: String] = [:]
        conversationRows = deck.sessions.map { fixture in
            if let stream = fixture.stream {
                resources[fixture.id] = stream
            }
            return ConversationSummary(
                id: fixture.id,
                machineID: fixture.machineId,
                title: fixture.title,
                cwd: fixture.cwd,
                agentKind: fixture.agentKind,
                group: fixture.group,
                lastActiveMs: fixture.lastActiveMs,
                archived: fixture.archived,
                revision: fixture.revision
            )
        }
        streamResourceByConversation = resources
        inboxItems =
            conversationRows
            .filter { $0.group == .waitingApproval }
            .map {
                InboxItem(
                    id: "inbox-\($0.id)",
                    conversationID: $0.id,
                    machineID: $0.machineID,
                    kind: .waitingApproval,
                    title: $0.title
                )
            }
    }

    // MARK: - SessionSource observations

    func machines() async -> AsyncStream<ResourceState<[MachineSummary]>> {
        let id = UUID()
        let pair = AsyncStream<ResourceState<[MachineSummary]>>.makeStream(
            bufferingPolicy: .bufferingNewest(Self.resourceBufferLimit)
        )
        machineSubscribers[id] = pair.continuation
        pair.continuation.yield(
            .ready(value: machineSummaries(), revision: resourceRevision)
        )
        pair.continuation.onTermination = { [weak self] _ in
            Task { await self?.removeMachineSubscriber(id) }
        }
        return pair.stream
    }

    func conversations(
        machineID: String
    ) async -> AsyncStream<ResourceState<[ConversationSummary]>> {
        let id = UUID()
        let pair = AsyncStream<ResourceState<[ConversationSummary]>>.makeStream(
            bufferingPolicy: .bufferingNewest(Self.resourceBufferLimit)
        )
        conversationListSubscribers[id] = (machineID, pair.continuation)
        pair.continuation.yield(
            .ready(
                value: conversations(for: machineID),
                revision: resourceRevision
            )
        )
        pair.continuation.onTermination = { [weak self] _ in
            Task { await self?.removeConversationListSubscriber(id) }
        }
        return pair.stream
    }

    func conversation(conversationID: String) async -> AsyncStream<ConversationUpdate> {
        let pair = AsyncStream<ConversationUpdate>.makeStream(
            bufferingPolicy: .bufferingNewest(Self.conversationBufferLimit)
        )
        guard let playback = ensurePlayback(conversationID: conversationID) else {
            pair.continuation.yield(.connectionState(.securityError))
            pair.continuation.finish()
            return pair.stream
        }

        playback.refreshCompactedTranscriptForLateSubscriber()
        let id = UUID()
        playback.subscribers[id] = pair.continuation
        for update in playback.transcript {
            pair.continuation.yield(update)
        }
        pair.continuation.onTermination = { [weak self] _ in
            Task { await self?.removeConversationSubscriber(id, conversationID: conversationID) }
        }
        startPlaybackIfNeeded(conversationID: conversationID, playback: playback)
        return pair.stream
    }

    func inbox() async -> AsyncStream<ResourceState<[InboxItem]>> {
        let id = UUID()
        let pair = AsyncStream<ResourceState<[InboxItem]>>.makeStream(
            bufferingPolicy: .bufferingNewest(Self.resourceBufferLimit)
        )
        inboxSubscribers[id] = pair.continuation
        pair.continuation.yield(
            .ready(value: inboxItems, revision: resourceRevision)
        )
        pair.continuation.onTermination = { [weak self] _ in
            Task { await self?.removeInboxSubscriber(id) }
        }
        return pair.stream
    }

    // MARK: - Commands

    func sendPrompt(
        conversationID: String,
        text: String,
        idempotencyKey: UUID
    ) async throws -> CommandReceipt {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty,
            let conversation = conversationRows.first(where: { $0.id == conversationID }),
            machineIsConnected(conversation.machineID),
            let playback = ensurePlayback(conversationID: conversationID)
        else {
            throw SessionSourceFailure(
                code: .machineOffline,
                message: "fixture 机器当前离线"
            )
        }

        if let replay = promptReplays[idempotencyKey] {
            guard replay.conversationID == conversationID, replay.text == trimmed else {
                throw SessionSourceFailure(
                    code: .commandRejected,
                    message: "同一 idempotency key 绑定了不同 prompt"
                )
            }
            return .replayed(
                commandID: replay.commandID,
                configurationRevision: replay.configurationRevision
            )
        }

        let commandID = RuntimeCommandID(
            rawValue: "fixture-command-\(idempotencyKey.uuidString.lowercased())"
        )
        let replay = PromptReplay(
            conversationID: conversationID,
            text: trimmed,
            commandID: commandID,
            configurationRevision: 1
        )
        promptReplays[idempotencyKey] = replay
        let queuePosition = UInt32(clamping: playback.pendingPrompts.count)
        playback.pendingPrompts.append(
            PendingPrompt(
                conversationID: conversationID,
                text: trimmed,
                commandID: commandID
            )
        )
        startPlaybackIfNeeded(conversationID: conversationID, playback: playback)
        if playback.scriptFinished {
            schedulePendingPrompts(conversationID: conversationID, playback: playback)
        }
        return .accepted(
            commandID: commandID,
            queuePosition: queuePosition,
            configurationRevision: 1
        )
    }

    func resolveApproval(
        conversationID: String,
        turnID: String,
        approvalID: String,
        decision: ActionDecisionKind,
        idempotencyKey: UUID
    ) async throws -> ApprovalReceipt {
        if let replay = approvalReplays[idempotencyKey] {
            guard replay.conversationID == conversationID,
                replay.turnID == turnID,
                replay.approvalID == approvalID,
                replay.decision == decision
            else {
                throw SessionSourceFailure(
                    code: .commandRejected,
                    message: "同一 idempotency key 绑定了不同审批输入"
                )
            }
            return replay.receipt
        }
        guard let playback = playbacks[conversationID] else {
            throw SessionSourceFailure(code: .commandRejected, message: "审批会话不存在")
        }
        let typedApprovalID = RuntimeApprovalID(rawValue: approvalID)
        if let outcome = playback.approvalOutcomes[typedApprovalID] {
            guard outcome.turnID.rawValue == turnID else {
                throw SessionSourceFailure(code: .commandRejected, message: "审批身份不匹配")
            }
            let receipt = ApprovalReceipt.alreadyHandled(
                approvalID: typedApprovalID,
                decision: outcome.decision,
                state: outcome.state
            )
            approvalReplays[idempotencyKey] = ApprovalReplay(
                conversationID: conversationID,
                turnID: turnID,
                approvalID: approvalID,
                decision: decision,
                receipt: receipt
            )
            return receipt
        }
        guard let pending = playback.pendingApproval,
            pending.turnID.rawValue == turnID,
            pending.approvalID == typedApprovalID
        else {
            throw SessionSourceFailure(code: .commandRejected, message: "审批身份不匹配")
        }

        let deliveryStates: [(String, ApprovalDeliveryStateV1)] = [
            ("claimed", .claimed),
            ("applying", .applying),
            ("applied", .applied),
        ]
        for (suffix, state) in deliveryStates {
            let event = try makeEvent(
                playback: playback,
                conversationID: conversationID,
                eventIDPrefix: "fixture-approval-\(suffix)",
                commandID: pending.commandID,
                body: .approvalResolved(
                    turnID: pending.turnID,
                    approvalID: pending.approvalID,
                    decision: decision,
                    state: state
                )
            )
            guard emitEvent(event, conversationID: conversationID, playback: playback) else {
                throw SessionSourceFailure(
                    code: .securityError,
                    message: "fixture event sequence 漂移"
                )
            }
            noteSideEffects(of: event, conversationID: conversationID, playback: playback)
        }
        playback.approvalOutcomes[typedApprovalID] = ApprovalOutcome(
            turnID: pending.turnID,
            decision: decision,
            state: .applied
        )
        playback.pendingApproval = nil
        playback.approvalGate?.resume()
        playback.approvalGate = nil

        let receipt = ApprovalReceipt.applied(typedApprovalID)
        approvalReplays[idempotencyKey] = ApprovalReplay(
            conversationID: conversationID,
            turnID: turnID,
            approvalID: approvalID,
            decision: decision,
            receipt: receipt
        )
        return receipt
    }

    func retryApprovalDelivery(
        conversationID: String,
        approvalID: String
    ) async throws -> ApprovalReceipt {
        guard let playback = playbacks[conversationID],
            let outcome = playback.approvalOutcomes[
                RuntimeApprovalID(rawValue: approvalID)
            ]
        else {
            throw SessionSourceFailure(code: .commandRejected, message: "审批记录不存在")
        }
        let typedApprovalID = RuntimeApprovalID(rawValue: approvalID)
        guard outcome.state == .deliveryFailed else {
            return .alreadyHandled(
                approvalID: typedApprovalID,
                decision: outcome.decision,
                state: outcome.state
            )
        }
        playback.approvalOutcomes[typedApprovalID]?.state = .applied
        return .applied(typedApprovalID)
    }

    // Pairing/revoke 是 P5.6 的发行 composition；P5.5 fixture 只提供明确 typed refusal。
    func inspectPairInvite(_ encoded: String) async throws -> PairingPreview {
        _ = encoded
        throw SessionSourceFailure(code: .invalidPairInvite, message: "fixture 不执行真实配对")
    }

    func pair(
        _ encodedInvite: String
    ) async throws -> AsyncThrowingStream<PairingProgress, any Error> {
        _ = encodedInvite
        return AsyncThrowingStream { continuation in
            continuation.finish(
                throwing: SessionSourceFailure(
                    code: .invalidPairInvite,
                    message: "fixture 不执行真实配对"
                )
            )
        }
    }

    func revokeSelf(machineID: String) async throws -> RevocationReceipt {
        _ = machineID
        throw SessionSourceFailure(code: .commandRejected, message: "fixture 不执行真实撤销")
    }

    // MARK: - Playback

    private func ensurePlayback(conversationID: String) -> Playback? {
        if let playback = playbacks[conversationID] { return playback }
        guard let resource = streamResourceByConversation[conversationID],
            let conversation = conversationRows.first(where: { $0.id == conversationID }),
            let machine = machineRows.first(where: { $0.id == conversation.machineID }),
            let url = bundle.url(forResource: resource, withExtension: "json"),
            let fixture = try? JSONDecoder().decode(
                FixtureConversation.self,
                from: Data(contentsOf: url)
            ),
            fixture.snapshot.conversationID.rawValue == conversationID,
            let playback = try? Playback(
                fixture: fixture,
                connectionState: machine.connectionState.sessionSourceValue
            )
        else {
            return nil
        }
        playbacks[conversationID] = playback
        return playback
    }

    private func startPlaybackIfNeeded(
        conversationID: String,
        playback: Playback
    ) {
        guard !playback.started else { return }
        playback.started = true
        playback.task = Task { [weak self] in
            await self?.runPlayback(conversationID: conversationID)
        }
    }

    private func runPlayback(conversationID: String) async {
        guard let playback = playbacks[conversationID] else { return }
        for step in playback.fixture.steps {
            await sleepTicks(step.delayMs)
            guard !Task.isCancelled else { return }
            guard emitEvent(step.event, conversationID: conversationID, playback: playback) else {
                emit(.connectionState(.securityError), playback: playback)
                return
            }
            noteSideEffects(of: step.event, conversationID: conversationID, playback: playback)
            if step.awaitApproval == true {
                await withCheckedContinuation { continuation in
                    playback.approvalGate = continuation
                }
            }
        }
        playback.scriptFinished = true
        await drainPendingPrompts(conversationID: conversationID)
    }

    private func schedulePendingPrompts(
        conversationID: String,
        playback: Playback
    ) {
        guard !playback.promptDrainRunning else { return }
        playback.task = Task { [weak self] in
            await self?.drainPendingPrompts(conversationID: conversationID)
        }
    }

    private func drainPendingPrompts(conversationID: String) async {
        guard let playback = playbacks[conversationID] else { return }
        guard !playback.promptDrainRunning else { return }
        playback.promptDrainRunning = true
        defer { playback.promptDrainRunning = false }
        while !playback.pendingPrompts.isEmpty {
            let prompt = playback.pendingPrompts.removeFirst()
            do {
                try emitPrompt(prompt, playback: playback)
                await sleepTicks(600)
                try emitPromptReply(prompt, playback: playback)
                await sleepTicks(200)
                try emitPromptTerminal(prompt, playback: playback)
            } catch {
                emit(.connectionState(.securityError), playback: playback)
                return
            }
        }
    }

    private func emitPrompt(_ prompt: PendingPrompt, playback: Playback) throws {
        let turnID = RuntimeTurnID(rawValue: "turn-\(prompt.commandID.rawValue)")
        let started = try makeEvent(
            playback: playback,
            conversationID: prompt.conversationID,
            eventIDPrefix: "fixture-prompt-started",
            commandID: prompt.commandID,
            body: .turnStarted(turnID: turnID)
        )
        guard emitEvent(started, conversationID: prompt.conversationID, playback: playback) else {
            throw SessionSourceFailure(code: .securityError)
        }
        let user = try makeEvent(
            playback: playback,
            conversationID: prompt.conversationID,
            eventIDPrefix: "fixture-prompt-user",
            commandID: prompt.commandID,
            itemID: RuntimeItemID(rawValue: "item-user-\(prompt.commandID.rawValue)"),
            entityID: RuntimeEntityID(rawValue: "entity-user-\(prompt.commandID.rawValue)"),
            body: .item(
                .userMessage(text: prompt.text, meta: RuntimeAgentItemMetaV1())
            )
        )
        guard emitEvent(user, conversationID: prompt.conversationID, playback: playback) else {
            throw SessionSourceFailure(code: .securityError)
        }
    }

    private func emitPromptReply(_ prompt: PendingPrompt, playback: Playback) throws {
        let reply = "（fixture 回声）收到：\(prompt.text)。真实链路接入后此处为 agent 输出。"
        let event = try makeEvent(
            playback: playback,
            conversationID: prompt.conversationID,
            eventIDPrefix: "fixture-prompt-reply",
            commandID: prompt.commandID,
            itemID: RuntimeItemID(rawValue: "item-reply-\(prompt.commandID.rawValue)"),
            entityID: RuntimeEntityID(rawValue: "entity-reply-\(prompt.commandID.rawValue)"),
            body: .item(
                .assistantMessage(text: reply, meta: RuntimeAgentItemMetaV1())
            )
        )
        guard emitEvent(event, conversationID: prompt.conversationID, playback: playback) else {
            throw SessionSourceFailure(code: .securityError)
        }
    }

    private func emitPromptTerminal(_ prompt: PendingPrompt, playback: Playback) throws {
        let summary = try JSONDecoder().decode(
            RuntimeTurnSummaryV1.self,
            from: Data(#"{"totalInputTokens":null,"totalOutputTokens":null,"elapsedMs":800}"#.utf8)
        )
        let event = try makeEvent(
            playback: playback,
            conversationID: prompt.conversationID,
            eventIDPrefix: "fixture-prompt-complete",
            commandID: prompt.commandID,
            body: .turnCompleted(
                turnID: RuntimeTurnID(rawValue: "turn-\(prompt.commandID.rawValue)"),
                summary: summary
            )
        )
        guard emitEvent(event, conversationID: prompt.conversationID, playback: playback) else {
            throw SessionSourceFailure(code: .securityError)
        }
        noteSideEffects(of: event, conversationID: prompt.conversationID, playback: playback)
    }

    private func makeEvent(
        playback: Playback,
        conversationID: String,
        eventIDPrefix: String,
        commandID: RuntimeCommandID?,
        itemID: RuntimeItemID? = nil,
        entityID: RuntimeEntityID? = nil,
        body: RuntimeEventBodyV2
    ) throws -> RuntimeEventV2 {
        try RuntimeEventV2(
            conversationID: RuntimeConversationID(rawValue: conversationID),
            eventID: RuntimeEventID(
                rawValue: "\(eventIDPrefix)-\(playback.nextEventSeq)"
            ),
            eventSeq: playback.nextEventSeq,
            commandID: commandID,
            itemID: itemID,
            entityID: entityID,
            body: body
        )
    }

    @discardableResult
    private func emitEvent(
        _ event: RuntimeEventV2,
        conversationID: String,
        playback: Playback
    ) -> Bool {
        guard event.conversationID.rawValue == conversationID,
            event.eventSeq == playback.nextEventSeq,
            playback.nextEventSeq < UInt64.max
        else {
            return false
        }
        do {
            try playback.applyCanonicalEvent(event)
        } catch {
            return false
        }
        playback.nextEventSeq += 1
        emit(.event(event), playback: playback)
        return true
    }

    private func emit(_ update: ConversationUpdate, playback: Playback) {
        let updateIsRepresentedByCurrentSnapshot: Bool
        if case .event = update {
            updateIsRepresentedByCurrentSnapshot = true
        } else {
            updateIsRepresentedByCurrentSnapshot = false
        }
        var compactedForUpdate = false
        if playback.transcript.count >= Self.conversationBufferLimit {
            playback.transcript = [
                .snapshot(playback.currentSnapshot),
                .connectionState(playback.connectionState),
            ]
            playback.transcriptWasCompacted = true
            compactedForUpdate = true
        }
        if !(compactedForUpdate && updateIsRepresentedByCurrentSnapshot) {
            playback.transcript.append(update)
        }
        for subscriberID in Array(playback.subscribers.keys) {
            guard let continuation = playback.subscribers[subscriberID] else { continue }
            let result = continuation.yield(update)
            if case .dropped = result {
                continuation.yield(
                    .connectionState(.lagged(reason: .bufferDropped))
                )
                continuation.finish()
                playback.subscribers[subscriberID] = nil
            }
        }
    }

    // MARK: - Derived resource state

    private func noteSideEffects(
        of event: RuntimeEventV2,
        conversationID: String,
        playback: Playback
    ) {
        guard let conversation = conversationRows.first(where: { $0.id == conversationID }) else {
            return
        }
        switch event.body {
        case .actionRequest(let turnID, let approvalID, let request):
            guard let commandID = event.commandID else { return }
            playback.pendingApproval = PendingApproval(
                turnID: turnID,
                commandID: commandID,
                approvalID: approvalID,
                request: request
            )
            updateConversationGroup(conversationID, to: .waitingApproval)
            if !inboxItems.contains(where: {
                $0.conversationID == conversationID && $0.kind == .waitingApproval
            }) {
                inboxItems.append(
                    InboxItem(
                        id: "inbox-\(conversationID)",
                        conversationID: conversationID,
                        machineID: conversation.machineID,
                        kind: .waitingApproval,
                        title: conversation.title
                    )
                )
            }
            broadcastResourceState()
        case .approvalResolved(_, _, _, let state):
            if state == .applied {
                updateConversationGroup(conversationID, to: .active)
                inboxItems.removeAll {
                    $0.conversationID == conversationID && $0.kind == .waitingApproval
                }
                broadcastResourceState()
            }
        case .turnCompleted:
            appendInbox(
                InboxItem(
                    id: "inbox-done-\(conversationID)-\(event.eventSeq)",
                    conversationID: conversationID,
                    machineID: conversation.machineID,
                    kind: .turnCompleted,
                    title: conversation.title
                )
            )
        case .error where event.commandID != nil:
            updateConversationGroup(conversationID, to: .recent)
            appendInbox(
                InboxItem(
                    id: "inbox-fail-\(conversationID)-\(event.eventSeq)",
                    conversationID: conversationID,
                    machineID: conversation.machineID,
                    kind: .failed,
                    title: conversation.title
                )
            )
        case .error, .capabilities, .configurationChanged, .vendorPanelEvent, .item,
            .turnStarted, .turnInterrupted:
            break
        }
    }

    private func machineSummaries() -> [MachineSummary] {
        machineRows.map { machine in
            let conversations = conversationRows.filter { $0.machineID == machine.id }
            return MachineSummary(
                id: machine.id,
                name: machine.name,
                connectionState: machine.connectionState.sessionSourceValue,
                lastHeartbeat: machine.lastHeartbeatSecondsAgo.map {
                    Date(timeIntervalSinceNow: -Double($0))
                },
                activeConversationCount: conversations.filter { $0.group == .active }.count,
                pendingApprovalCount: conversations.filter {
                    $0.group == .waitingApproval
                }.count
            )
        }
    }

    private func conversations(for machineID: String) -> [ConversationSummary] {
        conversationRows.filter { $0.machineID == machineID }
    }

    private func machineIsConnected(_ machineID: String) -> Bool {
        machineRows.first(where: { $0.id == machineID })?.connectionState == .connected
    }

    private func updateConversationGroup(
        _ conversationID: String,
        to group: ConversationGroup
    ) {
        guard let index = conversationRows.firstIndex(where: { $0.id == conversationID }) else {
            return
        }
        let value = conversationRows[index]
        conversationRows[index] = ConversationSummary(
            id: value.id,
            machineID: value.machineID,
            title: value.title,
            cwd: value.cwd,
            agentKind: value.agentKind,
            group: group,
            lastActiveMs: value.lastActiveMs,
            archived: value.archived,
            revision: value.revision + 1
        )
    }

    private func appendInbox(_ item: InboxItem) {
        guard !inboxItems.contains(where: { $0.id == item.id }) else { return }
        inboxItems.append(item)
        broadcastResourceState()
    }

    private func broadcastResourceState() {
        if resourceRevision < UInt64.max { resourceRevision += 1 }
        let machines = machineSummaries()
        for continuation in machineSubscribers.values {
            continuation.yield(.ready(value: machines, revision: resourceRevision))
        }
        for subscriber in conversationListSubscribers.values {
            subscriber.continuation.yield(
                .ready(
                    value: conversations(for: subscriber.machineID),
                    revision: resourceRevision
                )
            )
        }
        for continuation in inboxSubscribers.values {
            continuation.yield(.ready(value: inboxItems, revision: resourceRevision))
        }
    }

    private func removeMachineSubscriber(_ id: UUID) {
        machineSubscribers[id] = nil
    }

    private func removeConversationListSubscriber(_ id: UUID) {
        conversationListSubscribers[id] = nil
    }

    private func removeConversationSubscriber(_ id: UUID, conversationID: String) {
        playbacks[conversationID]?.subscribers[id] = nil
    }

    private func removeInboxSubscriber(_ id: UUID) {
        inboxSubscribers[id] = nil
    }

    private func sleepTicks(_ milliseconds: Int) async {
        let nanoseconds = UInt64(
            max(0, Double(milliseconds) * 1_000_000 * tickScale)
        )
        if nanoseconds > 0 {
            try? await Task.sleep(nanoseconds: nanoseconds)
        } else {
            await Task.yield()
        }
    }
}
