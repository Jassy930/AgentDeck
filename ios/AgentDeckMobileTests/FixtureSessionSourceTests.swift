import AgentDeckCore
import AgentDeckSessionSource
import XCTest

@testable import AgentDeckMobile

final class FixtureSessionSourceTests: XCTestCase {
    private var testBundle: Bundle { Bundle(for: MachineListViewController.self) }

    private func makeSource() -> FixtureSessionSource {
        FixtureSessionSource(bundle: testBundle, tickScale: 0)
    }

    private func collect<T>(
        _ stream: AsyncStream<T>,
        until stop: @escaping (T) -> Bool
    ) async -> [T] {
        var output: [T] = []
        for await value in stream {
            output.append(value)
            if stop(value) { break }
        }
        return output
    }

    private func awaitValue<T: Sendable>(
        from task: Task<T, Never>,
        timeoutNanoseconds: UInt64 = 2_000_000_000
    ) async -> T? {
        await withTaskGroup(of: T?.self) { group in
            group.addTask { await task.value }
            group.addTask {
                try? await Task.sleep(nanoseconds: timeoutNanoseconds)
                return nil
            }
            let first = await group.next() ?? nil
            if first == nil { task.cancel() }
            group.cancelAll()
            return first
        }
    }

    func testFixtureIsSendableActorWithExplicitBufferLimits() {
        func requireSendable<T: Sendable>(_: T.Type) {}
        requireSendable(FixtureSessionSource.self)
        XCTAssertEqual(FixtureSessionSource.resourceBufferLimit, 1)
        XCTAssertEqual(FixtureSessionSource.conversationBufferLimit, 512)
    }

    func testMachinesReturnsTypedReadySnapshot() async {
        let source = makeSource()
        var iterator = await source.machines().makeAsyncIterator()
        guard case .ready(let machines, let revision)? = await iterator.next() else {
            return XCTFail("fixture machines 首帧应为 ready")
        }
        XCTAssertEqual(revision, 1)
        XCTAssertEqual(machines.map(\.id).sorted(), ["mac-studio", "macbook-air"])
        let studio = machines.first { $0.id == "mac-studio" }
        XCTAssertEqual(studio?.activeConversationCount, 2)
        XCTAssertEqual(studio?.pendingApprovalCount, 1)
    }

    func testConversationReplaysCanonicalSnapshotAndEvents() async {
        let source = makeSource()
        func isTurnComplete(_ update: ConversationUpdate) -> Bool {
            guard case .event(let event) = update else { return false }
            if case .turnCompleted = event.body { return true }
            return false
        }

        let first = await collect(
            await source.conversation(conversationID: "sess-codex-01"),
            until: isTurnComplete
        )
        guard case .snapshot(let snapshot)? = first.first else {
            return XCTFail("首帧必须是 canonical snapshot")
        }
        XCTAssertEqual(snapshot.conversationID.rawValue, "sess-codex-01")
        XCTAssertTrue(
            first.contains { update in
                guard case .event(let event) = update,
                    case .item(.userMessage) = event.body
                else { return false }
                return event.commandID != nil && event.itemID != nil && event.entityID != nil
            })

        let second = await collect(
            await source.conversation(conversationID: "sess-codex-01"),
            until: isTurnComplete
        )
        XCTAssertEqual(second.count, first.count)
    }

    func testConversationStartsWithSnapshotThenConnectedState() async {
        let source = makeSource()
        var iterator = await source.conversation(
            conversationID: "sess-cc-01"
        ).makeAsyncIterator()

        guard case .snapshot? = await iterator.next() else {
            return XCTFail("conversation 首帧必须是 canonical snapshot")
        }
        guard case .connectionState(.connected)? = await iterator.next() else {
            return XCTFail("connected fixture 的 snapshot 后必须发布 connected")
        }
    }

    func testApprovalReturnsAppliedReceiptAndResumesSameObservation() async {
        let source = makeSource()
        var iterator = await source.conversation(
            conversationID: "sess-approval-01"
        ).makeAsyncIterator()
        var updates: [ConversationUpdate] = []
        var observedApprovalRequest = false
        while let update = await iterator.next() {
            updates.append(update)
            guard case .event(let event) = update,
                case .actionRequest(_, let approvalID, _) = event.body,
                approvalID.rawValue == "approval-1"
            else { continue }
            observedApprovalRequest = true
            break
        }
        XCTAssertTrue(observedApprovalRequest)

        let receipt = try? await source.resolveApproval(
            conversationID: "sess-approval-01",
            turnID: "turn-approval-01",
            approvalID: "approval-1",
            decision: .approve,
            idempotencyKey: UUID(uuidString: "00000000-0000-0000-0000-000000000001")!
        )
        guard case .applied(let approvalID)? = receipt else {
            return XCTFail("fixture 首次审批应返回 Applied")
        }
        XCTAssertEqual(approvalID.rawValue, "approval-1")

        while let update = await iterator.next() {
            updates.append(update)
            guard case .event(let event) = update,
                case .turnCompleted = event.body
            else { continue }
            break
        }
        let approvalStates = updates.compactMap { update -> ApprovalDeliveryStateV1? in
            guard case .event(let event) = update,
                case .approvalResolved(_, _, let decision, let state) = event.body,
                decision == .approve
            else { return nil }
            return state
        }
        XCTAssertEqual(approvalStates, [.claimed, .applying, .applied])
    }

    func testPromptReceiptIsDeterministicAndCanonicalEchoCarriesCommandID() async {
        let source = makeSource()
        let key = UUID(uuidString: "00000000-0000-0000-0000-000000000002")!

        let first = try? await source.sendPrompt(
            conversationID: "sess-cc-01",
            text: "继续，补第三个边界",
            idempotencyKey: key
        )
        let second = try? await source.sendPrompt(
            conversationID: "sess-cc-01",
            text: "继续，补第三个边界",
            idempotencyKey: key
        )

        let commandID: RuntimeCommandID
        guard case .accepted(let acceptedID, _, _)? = first else {
            return XCTFail("首次 prompt 应 accepted")
        }
        commandID = acceptedID
        guard case .replayed(let replayedID, _)? = second else {
            return XCTFail("同 idempotency key 应 replayed")
        }
        XCTAssertEqual(replayedID, commandID)

        let updates = await collect(
            await source.conversation(conversationID: "sess-cc-01")
        ) { update in
            guard case .event(let event) = update,
                event.commandID == commandID,
                case .turnCompleted = event.body
            else { return false }
            return true
        }
        let echoes = updates.compactMap { update -> String? in
            guard case .event(let event) = update,
                event.commandID == commandID,
                case .item(.userMessage(let text, _)) = event.body
            else { return nil }
            return text
        }
        XCTAssertEqual(echoes, ["继续，补第三个边界"])
    }

    func testFailedFixtureUsesDaemonTerminalAndAcceptsNextPromptTurn() async throws {
        let source = makeSource()
        var initialInbox = await source.inbox().makeAsyncIterator()
        guard case .ready(_, let initialResourceRevision)? = await initialInbox.next() else {
            return XCTFail("fixture inbox 首帧应为 ready")
        }
        let initial = await collect(
            await source.conversation(conversationID: "sess-failed-01")
        ) { update in
            guard case .event(let event) = update,
                case .error = event.body
            else { return false }
            return true
        }
        guard
            let failedEvent = initial.compactMap({ update -> RuntimeEventV2? in
                guard case .event(let event) = update,
                    case .error = event.body
                else { return nil }
                return event
            }).last,
            case .error(let failure) = failedEvent.body
        else {
            return XCTFail("failed fixture 必须发布 command-bound Error 终态")
        }
        XCTAssertEqual(failedEvent.commandID?.rawValue, "command-failed-01")
        XCTAssertEqual(failure.code, "daemon.runtime.execution_failed")
        XCTAssertEqual(failure.message, "agent execution failed")
        XCTAssertNil(failure.diagnosticRef)

        var failedInbox = await source.inbox().makeAsyncIterator()
        guard case .ready(let failedItems, let failedResourceRevision)? = await failedInbox.next()
        else {
            return XCTFail("failed fixture 后 inbox 应保持 ready")
        }
        XCTAssertEqual(failedResourceRevision, initialResourceRevision + 1)
        XCTAssertEqual(
            failedItems.filter {
                $0.conversationID == "sess-failed-01" && $0.kind == .failed
            }.count,
            1
        )

        let receipt = try await source.sendPrompt(
            conversationID: "sess-failed-01",
            text: "失败后继续",
            idempotencyKey: UUID(
                uuidString: "00000000-0000-0000-0000-000000000003"
            )!
        )
        guard case .accepted(let commandID, _, _) = receipt else {
            return XCTFail("failed turn 后的新 prompt 应 accepted")
        }

        let followUpStream = await source.conversation(
            conversationID: "sess-failed-01"
        )
        let followUp = Task { () -> String in
            for await update in followUpStream {
                if case .connectionState(.securityError) = update {
                    return "securityError"
                }
                guard case .event(let event) = update,
                    event.commandID == commandID,
                    case .turnCompleted = event.body
                else { continue }
                return "completed"
            }
            return "ended"
        }
        let outcome = await awaitValue(from: followUp)
        XCTAssertEqual(outcome, "completed")
    }

    func testCommandlessDiagnosticDoesNotProjectFailedInboxItem() async {
        let source = makeSource()
        let updates = await collect(
            await source.conversation(conversationID: "sess-codex-01")
        ) { update in
            guard case .event(let event) = update,
                case .turnCompleted = event.body
            else { return false }
            return true
        }
        XCTAssertTrue(
            updates.contains { update in
                guard case .event(let event) = update,
                    event.commandID == nil,
                    case .error = event.body
                else { return false }
                return true
            }
        )

        var iterator = await source.inbox().makeAsyncIterator()
        guard case .ready(let items, _)? = await iterator.next() else {
            return XCTFail("fixture inbox 首帧应为 ready")
        }
        let conversationItems = items.filter { $0.conversationID == "sess-codex-01" }
        XCTAssertEqual(conversationItems.map(\.kind), [.turnCompleted])
        XCTAssertFalse(conversationItems.contains { $0.kind == .failed })
    }

    func testApprovalOutcomeRejectsMismatchedTurnBeforeAlreadyHandled() async throws {
        let source = makeSource()
        var iterator = await source.conversation(
            conversationID: "sess-approval-01"
        ).makeAsyncIterator()
        while let update = await iterator.next() {
            guard case .event(let event) = update,
                case .actionRequest = event.body
            else { continue }
            break
        }

        _ = try await source.resolveApproval(
            conversationID: "sess-approval-01",
            turnID: "turn-approval-01",
            approvalID: "approval-1",
            decision: .approve,
            idempotencyKey: UUID()
        )

        let alreadyHandled = try await source.resolveApproval(
            conversationID: "sess-approval-01",
            turnID: "turn-approval-01",
            approvalID: "approval-1",
            decision: .deny,
            idempotencyKey: UUID()
        )
        guard case .alreadyHandled(_, let winner, let state) = alreadyHandled else {
            return XCTFail("同一审批的后到决定应返回 AlreadyHandled")
        }
        XCTAssertEqual(winner, .approve)
        XCTAssertEqual(state, .applied)

        do {
            _ = try await source.resolveApproval(
                conversationID: "sess-approval-01",
                turnID: "turn-wrong",
                approvalID: "approval-1",
                decision: .deny,
                idempotencyKey: UUID()
            )
            XCTFail("错误 turnID 不得复用 approval outcome")
        } catch let failure as SessionSourceFailure {
            XCTAssertEqual(failure.code, .commandRejected)
        }
    }

    func testConversationOverflowTerminatesSlowSubscriberAndLateSubscriberGetsFreshSnapshot()
        async throws
    {
        let source = makeSource()
        let slowStream = await source.conversation(conversationID: "sess-cc-01")
        let fastStream = await source.conversation(conversationID: "sess-cc-01")
        let keys = (0..<130).map { _ in UUID() }
        let lastKey = try XCTUnwrap(keys.last)
        let lastCommandID = RuntimeCommandID(
            rawValue: "fixture-command-\(lastKey.uuidString.lowercased())"
        )

        let fastConsumer = Task { () -> UInt64 in
            for await update in fastStream {
                guard case .event(let event) = update,
                    event.commandID == lastCommandID,
                    case .turnCompleted = event.body
                else { continue }
                return event.eventSeq
            }
            return UInt64.max
        }

        for (index, key) in keys.enumerated() {
            let receipt = try await source.sendPrompt(
                conversationID: "sess-cc-01",
                text: "overflow prompt \(index)",
                idempotencyKey: key
            )
            guard case .accepted = receipt else {
                return XCTFail("fresh fixture prompt 应返回 Accepted")
            }
        }

        let observedTerminalSequence = await awaitValue(from: fastConsumer)
        let terminalSequence = try XCTUnwrap(
            observedTerminalSequence,
            "fast subscriber 应完整读到最后一个 prompt terminal"
        )
        XCTAssertNotEqual(terminalSequence, UInt64.max)

        let slowConsumer = Task { () -> (firstWasLagged: Bool, streamEnded: Bool) in
            var iterator = slowStream.makeAsyncIterator()
            let first = await iterator.next()
            let firstWasLagged: Bool
            if case .connectionState(.lagged(reason: .bufferDropped))? = first {
                firstWasLagged = true
            } else {
                firstWasLagged = false
            }
            let second = await iterator.next()
            return (firstWasLagged, second == nil)
        }
        let observedSlowOutcome = await awaitValue(from: slowConsumer)
        let slowOutcome = try XCTUnwrap(
            observedSlowOutcome,
            "slow subscriber 应在 overflow 后及时结束"
        )
        XCTAssertTrue(
            slowOutcome.firstWasLagged,
            "overflow 必须原子清队列，使 slow subscriber 的下一项直接为 lagged"
        )
        XCTAssertTrue(slowOutcome.streamEnded, "lagged 后必须结束旧 generation")

        var lateIterator = await source.conversation(
            conversationID: "sess-cc-01"
        ).makeAsyncIterator()
        guard case .snapshot(let snapshot)? = await lateIterator.next() else {
            return XCTFail("late subscriber 必须从 fresh snapshot 恢复")
        }
        XCTAssertEqual(snapshot.baseEventCursor, .at(terminalSequence))
        XCTAssertTrue(
            snapshot.items.contains { item in
                guard case .item(_, _, let commandID, .userMessage) = item else {
                    return false
                }
                return commandID == lastCommandID
            })
        guard case .connectionState(.connected)? = await lateIterator.next() else {
            return XCTFail("fresh snapshot 后必须恢复当前 connected state")
        }
    }
}
