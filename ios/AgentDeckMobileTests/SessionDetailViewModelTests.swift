import AgentDeckCore
import AgentDeckSessionSource
import XCTest

@testable import AgentDeckMobile

@MainActor
final class SessionDetailViewModelTests: XCTestCase {
  private let conversationID = "conversation-1"

  func testPromptSubmissionReadinessWaitsForConnectedInitialSnapshot() async throws {
    let source = SessionSourceSpy()
    let vm = SessionDetailViewModel(source: source, conversationID: conversationID)

    vm.start()
    await source.waitForConversationSubscriptions(1)
    XCTAssertFalse(vm.canSubmitPrompt)

    await source.emitConversation(.connectionState(.connected))
    await waitForMainActorState { vm.connectionState == .connected }
    XCTAssertFalse(
      vm.canSubmitPrompt,
      "transport connected 不能替代 conversation snapshot/SyncComplete 闭环"
    )

    await source.emitConversation(
      .snapshot(try SessionSourceTestValues.snapshot(conversationID: conversationID))
    )
    await waitForMainActorState { vm.canSubmitPrompt }

    await source.emitConversation(.connectionState(.lagged(reason: .snapshotRequired)))
    await waitForMainActorState {
      vm.connectionState == .lagged(reason: .snapshotRequired)
    }
    XCTAssertFalse(vm.canSubmitPrompt)
  }

  func testStartIsIdempotentAndSendPromptDoesNotResubscribe() async throws {
    let source = SessionSourceSpy()
    let vm = SessionDetailViewModel(source: source, conversationID: conversationID)

    vm.start()
    vm.start()
    await source.waitForConversationSubscriptions(1)
    let initialSubscriptionCount = await source.conversationSubscriptionCount()
    XCTAssertEqual(initialSubscriptionCount, 1)

    await source.emitConversation(
      .snapshot(try SessionSourceTestValues.snapshot(conversationID: conversationID))
    )
    vm.sendPrompt("补一个 canonical identity 用例")
    await source.waitForPromptCalls(1)
    await waitForMainActorState {
      if case .queued = vm.promptState { return true }
      return false
    }

    let finalSubscriptionCount = await source.conversationSubscriptionCount()
    let promptCalls = await source.recordedPromptCalls()
    XCTAssertEqual(finalSubscriptionCount, 1)
    XCTAssertEqual(promptCalls.first?.text, "补一个 canonical identity 用例")
  }

  func testPromptMovesSendingToQueuedThenCanonicalUserMessageReplacesTemporaryRow() async throws {
    let source = SessionSourceSpy()
    await source.setCommandBehavior(.suspended)
    let vm = SessionDetailViewModel(source: source, conversationID: conversationID)
    vm.start()
    await source.waitForConversationSubscriptions(1)
    await source.emitConversation(
      .snapshot(try SessionSourceTestValues.snapshot(conversationID: conversationID))
    )

    vm.sendPrompt("继续，补第三个边界")
    await source.waitForPromptCalls(1)
    guard case .sending = vm.promptState else {
      return XCTFail("receipt 返回前必须显示 sending")
    }
    XCTAssertEqual(vm.draftText, "继续，补第三个边界")
    XCTAssertEqual(vm.rows.last?.item.text, "继续，补第三个边界")
    XCTAssertEqual(vm.rows.last?.item.lifecycle, "sending")

    let commandID = RuntimeCommandID(rawValue: "command-prompt-1")
    await source.completeCommand(
      with: .accepted(
        commandID: commandID,
        queuePosition: 2,
        configurationRevision: 1
      )
    )
    await waitForMainActorState {
      vm.promptState == .queued(commandID: commandID, queuePosition: 2)
    }
    XCTAssertEqual(vm.draftText, "")
    XCTAssertEqual(vm.rows.last?.item.lifecycle, "queued")

    await source.emitConversation(
      .event(
        try SessionSourceTestValues.userMessage(
          conversationID: conversationID,
          commandID: commandID.rawValue,
          itemID: "canonical-user-item",
          text: "继续，补第三个边界",
          eventSeq: 0
        )
      )
    )
    await waitForMainActorState {
      vm.promptState == .idle && vm.rows.last?.item.id == "canonical-user-item"
    }

    XCTAssertEqual(vm.rows.filter { $0.item.text == "继续，补第三个边界" }.count, 1)
    XCTAssertEqual(vm.rows.last?.item.id, "canonical-user-item")
    let subscriptionCount = await source.conversationSubscriptionCount()
    XCTAssertEqual(subscriptionCount, 1)
  }

  func testOfflinePromptFailureKeepsDraft() async {
    let source = SessionSourceSpy()
    await source.setCommandBehavior(
      .failure(
        SessionSourceFailure(
          code: .machineOffline,
          message: "机器当前离线"
        )
      )
    )
    let vm = SessionDetailViewModel(source: source, conversationID: conversationID)

    vm.sendPrompt("不要丢掉这段草稿")
    await source.waitForPromptCalls(1)
    await waitForMainActorState {
      if case .failed = vm.promptState { return true }
      return false
    }

    XCTAssertEqual(vm.draftText, "不要丢掉这段草稿")
    XCTAssertTrue(vm.errorText?.contains("机器当前离线") == true)
  }

  func testFailedCommandReceiptKeepsDraftAndRemovesTemporaryRow() async {
    let source = SessionSourceSpy()
    await source.setCommandBehavior(
      .immediate(
        .failed(
          RuntimeFailureV1(
            code: "daemon.command.rejected",
            message: "命令已明确拒绝"
          )
        )
      )
    )
    let vm = SessionDetailViewModel(source: source, conversationID: conversationID)

    vm.sendPrompt("保留这段草稿")
    await source.waitForPromptCalls(1)
    await waitForMainActorState {
      vm.promptState == .failed(message: "命令已明确拒绝")
    }

    XCTAssertEqual(vm.draftText, "保留这段草稿")
    XCTAssertFalse(vm.rows.contains { $0.item.text == "保留这段草稿" })
  }

  func testTransportUnknownPromptRetryReusesExactIdempotencyKey() async {
    let source = SessionSourceSpy()
    await source.setCommandBehavior(
      .failure(SessionSourceFailure(code: .transportUnavailable))
    )
    let vm = SessionDetailViewModel(source: source, conversationID: conversationID)

    vm.sendPrompt("同字节重试")
    await source.waitForPromptCalls(1)
    await waitForMainActorState {
      if case .failed = vm.promptState { return true }
      return false
    }

    let commandID = RuntimeCommandID(rawValue: "command-replayed")
    await source.setCommandBehavior(
      .immediate(
        .replayed(commandID: commandID, configurationRevision: 1)
      )
    )
    vm.sendPrompt("同字节重试")
    await source.waitForPromptCalls(2)
    await waitForMainActorState {
      vm.promptState == .queued(commandID: commandID, queuePosition: nil)
    }

    let calls = await source.recordedPromptCalls()
    XCTAssertEqual(calls.count, 2)
    XCTAssertEqual(calls[0].idempotencyKey, calls[1].idempotencyKey)
  }

  func testCanonicalUserEventBeforeReceiptStillReplacesTemporaryRow() async throws {
    let source = SessionSourceSpy()
    await source.setCommandBehavior(.suspended)
    let vm = SessionDetailViewModel(source: source, conversationID: conversationID)
    vm.start()
    await source.waitForConversationSubscriptions(1)
    await source.emitConversation(
      .snapshot(try SessionSourceTestValues.snapshot(conversationID: conversationID))
    )

    vm.sendPrompt("canonical 先到")
    await source.waitForPromptCalls(1)
    let commandID = RuntimeCommandID(rawValue: "command-canonical-first")
    await source.emitConversation(
      .event(
        try SessionSourceTestValues.userMessage(
          conversationID: conversationID,
          commandID: commandID.rawValue,
          text: "canonical 先到",
          eventSeq: 0
        )
      )
    )
    await source.completeCommand(
      with: .accepted(
        commandID: commandID,
        queuePosition: 0,
        configurationRevision: 1
      )
    )
    await waitForMainActorState { vm.promptState == .idle }

    XCTAssertEqual(vm.rows.filter { $0.item.text == "canonical 先到" }.count, 1)
    XCTAssertEqual(vm.rows.last?.item.id, "item-user")
  }

  func testCanonicalFailureBeforeAcceptedReceiptCannotLeavePromptQueued() async throws {
    let commandID = RuntimeCommandID(rawValue: "command-terminal-first-accepted")
    try await assertCanonicalFailureBeforeReceiptCannotLeavePromptQueued(
      commandID: commandID,
      receipt: .accepted(
        commandID: commandID,
        queuePosition: 0,
        configurationRevision: 1
      )
    )
  }

  func testCanonicalFailureBeforeReplayedReceiptCannotLeavePromptQueued() async throws {
    let commandID = RuntimeCommandID(rawValue: "command-terminal-first-replayed")
    try await assertCanonicalFailureBeforeReceiptCannotLeavePromptQueued(
      commandID: commandID,
      receipt: .replayed(commandID: commandID, configurationRevision: 1)
    )
  }

  func testPreviousCompletedTerminalCannotConsumeNextPromptReceipt() async throws {
    let source = SessionSourceSpy()
    await source.setCommandBehavior(.suspended)
    let vm = SessionDetailViewModel(source: source, conversationID: conversationID)
    vm.start()
    await source.waitForConversationSubscriptions(1)
    await source.emitConversation(
      .snapshot(try SessionSourceTestValues.snapshot(conversationID: conversationID))
    )
    await source.emitConversation(
      .event(
        try SessionSourceTestValues.turnStarted(
          conversationID: conversationID,
          commandID: "command-completed-before-next-prompt",
          turnID: "turn-completed-before-next-prompt",
          eventSeq: 0
        )
      )
    )
    await source.emitConversation(
      .event(
        try SessionSourceTestValues.turnCompleted(
          conversationID: conversationID,
          commandID: "command-completed-before-next-prompt",
          turnID: "turn-completed-before-next-prompt",
          eventSeq: 1
        )
      )
    )
    await waitForMainActorState { !vm.isStreaming }

    vm.sendPrompt("next prompt after completed terminal")
    await source.waitForPromptCalls(1)
    let nextCommandID = RuntimeCommandID(rawValue: "command-after-completed-terminal")
    await source.completeCommand(
      with: .accepted(
        commandID: nextCommandID,
        queuePosition: 1,
        configurationRevision: 1
      )
    )
    await waitForMainActorState {
      vm.promptState == .queued(commandID: nextCommandID, queuePosition: 1)
    }

    XCTAssertEqual(vm.rows.last?.item.lifecycle, "queued")
    XCTAssertTrue(vm.isStreaming)
  }

  private func assertCanonicalFailureBeforeReceiptCannotLeavePromptQueued(
    commandID: RuntimeCommandID,
    receipt: CommandReceipt
  ) async throws {
    let source = SessionSourceSpy()
    await source.setCommandBehavior(.suspended)
    let vm = SessionDetailViewModel(source: source, conversationID: conversationID)
    vm.start()
    await source.waitForConversationSubscriptions(1)
    await source.emitConversation(
      .snapshot(try SessionSourceTestValues.snapshot(conversationID: conversationID))
    )

    let prompt = "fatal completion before receipt"
    vm.sendPrompt(prompt)
    await source.waitForPromptCalls(1)
    await source.emitConversation(
      .event(
        try SessionSourceTestValues.turnStarted(
          conversationID: conversationID,
          commandID: commandID.rawValue,
          turnID: "turn-terminal-first",
          eventSeq: 0
        )
      )
    )
    await source.emitConversation(
      .event(
        try makeErrorEvent(
          commandID: commandID.rawValue,
          code: "daemon.runtime.execution_failed",
          message: "agent execution failed",
          eventSeq: 1
        )
      )
    )
    await waitForMainActorState {
      !vm.isStreaming && vm.errorText == "agent execution failed"
    }

    await source.completeCommand(with: receipt)
    await waitForMainActorState {
      vm.promptState == .failed(message: "agent execution failed")
    }

    XCTAssertEqual(vm.draftText, prompt)
    XCTAssertFalse(vm.rows.contains { $0.item.lifecycle == "queued" })
    XCTAssertFalse(vm.isStreaming)

    let nextCommandID = RuntimeCommandID(rawValue: "\(commandID.rawValue)-retry")
    await source.setCommandBehavior(
      .immediate(
        .accepted(
          commandID: nextCommandID,
          queuePosition: 0,
          configurationRevision: 1
        )
      )
    )
    vm.sendPrompt(prompt)
    await source.waitForPromptCalls(2)
    await waitForMainActorState {
      vm.promptState == .queued(commandID: nextCommandID, queuePosition: 0)
    }
    let calls = await source.recordedPromptCalls()
    XCTAssertEqual(calls.map(\.text), [prompt, prompt])
    XCTAssertNotEqual(calls[0].idempotencyKey, calls[1].idempotencyKey)

    await source.emitConversation(
      .event(
        try SessionSourceTestValues.turnStarted(
          conversationID: conversationID,
          commandID: nextCommandID.rawValue,
          turnID: "turn-after-terminal-first",
          eventSeq: 2
        )
      )
    )
    await waitForMainActorState { vm.isStreaming }
  }

  func testCommandStateOnlyAffectsMatchingLocalOrActiveCommand() async throws {
    let source = SessionSourceSpy()
    await source.setCommandBehavior(.suspended)
    let vm = SessionDetailViewModel(source: source, conversationID: conversationID)
    vm.start()
    await source.waitForConversationSubscriptions(1)
    await source.emitConversation(
      .snapshot(try SessionSourceTestValues.snapshot(conversationID: conversationID))
    )

    vm.sendPrompt("只响应匹配 command")
    await source.waitForPromptCalls(1)
    let commandID = RuntimeCommandID(rawValue: "command-local")
    await source.completeCommand(
      with: .accepted(
        commandID: commandID,
        queuePosition: 0,
        configurationRevision: 1
      )
    )
    await waitForMainActorState {
      vm.promptState == .queued(commandID: commandID, queuePosition: 0)
    }

    await source.emitConversation(
      .commandState(
        SessionSourceTestValues.commandStatus(
          conversationID: conversationID,
          commandID: "command-unrelated",
          status: .completed
        )
      )
    )
    await source.emitConversation(.connectionState(.reconnecting))
    await waitForMainActorState { vm.connectionState == .reconnecting }
    XCTAssertTrue(vm.isStreaming)

    await source.emitConversation(
      .commandState(
        SessionSourceTestValues.commandStatus(
          conversationID: conversationID,
          commandID: commandID.rawValue,
          status: .failed
        )
      )
    )
    await waitForMainActorState {
      vm.promptState == .failed(message: "命令状态：failed")
    }
    XCTAssertEqual(vm.draftText, "只响应匹配 command")
  }

  func testConnectionRecoversThenFatalStateIgnoresLaterUpdates() async {
    let source = SessionSourceSpy()
    let vm = SessionDetailViewModel(source: source, conversationID: conversationID)
    vm.start()
    await source.waitForConversationSubscriptions(1)

    await source.emitConversation(.connectionState(.reconnecting))
    await waitForMainActorState { vm.connectionState == .reconnecting }
    XCTAssertEqual(vm.errorText, "正在重连")

    await source.emitConversation(.connectionState(.connected))
    await waitForMainActorState {
      vm.connectionState == .connected && vm.errorText == nil
    }

    await source.emitConversation(.connectionState(.revoked))
    await waitForMainActorState { vm.isTerminal }
    await source.emitConversation(.connectionState(.connected))
    vm.sendPrompt("终态后不能发送")
    await Task.yield()

    XCTAssertEqual(vm.connectionState, .revoked)
    let promptCallCount = await source.recordedPromptCalls().count
    XCTAssertEqual(promptCallCount, 0)
  }

  func testInitialSnapshotDoesNotImpersonateLagRecovery() async throws {
    let source = SessionSourceSpy()
    let vm = SessionDetailViewModel(source: source, conversationID: conversationID)
    var updateCount = 0
    vm.onUpdate = { updateCount += 1 }
    vm.start()
    await source.waitForConversationSubscriptions(1)

    await source.emitConversation(
      .snapshot(try SessionSourceTestValues.snapshot(conversationID: conversationID))
    )
    await waitForMainActorState { updateCount >= 1 }

    XCTAssertEqual(vm.connectionState, .connecting)
    XCTAssertNil(vm.errorText)
    XCTAssertFalse(vm.isTerminal)
  }

  func testFatalPromptFailuresFailClosedAndRejectLaterCommands() async {
    let cases: [(SessionSourceFailureCode, SessionConnectionState)] = [
      (.revoked, .revoked),
      (.incompatible, .incompatible),
      (.securityError, .securityError),
    ]

    for (failureCode, expectedState) in cases {
      let source = SessionSourceSpy()
      await source.setCommandBehavior(
        .failure(SessionSourceFailure(code: failureCode))
      )
      let vm = SessionDetailViewModel(source: source, conversationID: conversationID)

      vm.sendPrompt("触发不可逆终态")
      await source.waitForPromptCalls(1)
      await waitForMainActorState { vm.isTerminal }
      XCTAssertEqual(vm.connectionState, expectedState)

      vm.sendPrompt("终态后不能重发")
      await Task.yield()
      let calls = await source.recordedPromptCalls()
      XCTAssertEqual(calls.count, 1)
    }
  }

  func testCommandlessDiagnosticDoesNotStopActiveTurnStreaming() async throws {
    let source = SessionSourceSpy()
    let vm = SessionDetailViewModel(source: source, conversationID: conversationID)
    vm.start()
    await source.waitForConversationSubscriptions(1)
    await source.emitConversation(
      .snapshot(try SessionSourceTestValues.snapshot(conversationID: conversationID))
    )
    await source.emitConversation(.connectionState(.connected))
    await source.emitConversation(
      .event(
        try SessionSourceTestValues.turnStarted(
          conversationID: conversationID,
          commandID: "command-turn-1",
          turnID: "turn-1",
          eventSeq: 0
        )
      )
    )
    await waitForMainActorState { vm.isStreaming }

    await source.emitConversation(
      .event(
        try makeErrorEvent(
          commandID: nil,
          code: "daemon.runtime.diagnostic",
          message: "transient adapter warning",
          eventSeq: 1
        )
      )
    )
    await waitForMainActorState {
      vm.errorText == "transient adapter warning"
    }

    XCTAssertTrue(vm.isStreaming)
    XCTAssertFalse(vm.isTerminal)
    XCTAssertEqual(vm.connectionState, .connected)
  }

  func testCommandBoundFailureStopsStreamingAndAllowsNextPromptTurn() async throws {
    let source = SessionSourceSpy()
    let nextCommandID = RuntimeCommandID(rawValue: "command-turn-2")
    await source.setCommandBehavior(
      .immediate(
        .accepted(
          commandID: nextCommandID,
          queuePosition: 0,
          configurationRevision: 1
        )
      )
    )
    let vm = SessionDetailViewModel(source: source, conversationID: conversationID)
    vm.start()
    await source.waitForConversationSubscriptions(1)
    await source.emitConversation(
      .snapshot(try SessionSourceTestValues.snapshot(conversationID: conversationID))
    )
    await source.emitConversation(.connectionState(.connected))
    await source.emitConversation(
      .event(
        try SessionSourceTestValues.turnStarted(
          conversationID: conversationID,
          commandID: "command-turn-1",
          turnID: "turn-1",
          eventSeq: 0
        )
      )
    )
    await source.emitConversation(
      .event(
        try makeErrorEvent(
          commandID: "command-turn-1",
          code: "daemon.runtime.execution_failed",
          message: "agent execution failed",
          eventSeq: 1
        )
      )
    )
    await waitForMainActorState {
      !vm.isStreaming && vm.errorText == "agent execution failed"
    }

    XCTAssertFalse(vm.isTerminal)
    vm.sendPrompt("失败后继续")
    await source.waitForPromptCalls(1)
    await waitForMainActorState {
      vm.promptState == .queued(commandID: nextCommandID, queuePosition: 0)
    }
    await source.emitConversation(
      .event(
        try SessionSourceTestValues.turnStarted(
          conversationID: conversationID,
          commandID: nextCommandID.rawValue,
          turnID: "turn-2",
          eventSeq: 2
        )
      )
    )
    await waitForMainActorState { vm.isStreaming }

    XCTAssertFalse(vm.isTerminal)
    XCTAssertEqual(vm.connectionState, .connected)
  }

  func testApprovalSubmittingOnlyBecomesAppliedAfterReceipt() async throws {
    let source = SessionSourceSpy()
    await source.setApprovalBehavior(.suspended)
    let vm = try await makePendingApprovalViewModel(source: source)

    vm.resolveApproval(approve: true)
    await source.waitForApprovalCalls(1)
    XCTAssertEqual(vm.approvalState, .submitting(.approve))

    await source.completeApproval(
      with: .applied(RuntimeApprovalID(rawValue: "approval-1"))
    )
    await waitForMainActorState {
      vm.approvalResponseGeneration == 1
        && vm.approvalState == .applied(.approve)
    }
    XCTAssertEqual(vm.approvalState, .applied(.approve))
  }

  func testApprovalDoubleTapIsSingleFlight() async throws {
    let source = SessionSourceSpy()
    await source.setApprovalBehavior(.suspended)
    let vm = try await makePendingApprovalViewModel(source: source)

    vm.resolveApproval(approve: true)
    vm.resolveApproval(approve: false)
    await source.waitForApprovalCalls(1)
    let calls = await source.recordedApprovalCalls()
    XCTAssertEqual(calls.count, 1)
    XCTAssertEqual(calls.first?.decision, .approve)

    await source.completeApproval(
      with: .claimed(RuntimeApprovalID(rawValue: "approval-1"))
    )
    await waitForMainActorState { vm.approvalState == .submitting(.approve) }
  }

  func testApprovalOutcomeUnknownRetryReusesDecisionAndKey() async throws {
    let source = SessionSourceSpy()
    await source.setApprovalBehavior(
      .failure(SessionSourceFailure(code: .transportUnavailable))
    )
    let vm = try await makePendingApprovalViewModel(source: source)

    vm.resolveApproval(approve: true)
    await source.waitForApprovalCalls(1)
    await waitForMainActorState {
      vm.approvalState == .submissionFailed(.approve)
    }

    await source.setApprovalBehavior(
      .immediate(.claimed(RuntimeApprovalID(rawValue: "approval-1")))
    )
    vm.retryApprovalDelivery()
    await source.waitForApprovalCalls(2)
    await waitForMainActorState { vm.approvalState == .submitting(.approve) }

    let calls = await source.recordedApprovalCalls()
    XCTAssertEqual(calls.map(\.decision), [.approve, .approve])
    XCTAssertEqual(calls[0].idempotencyKey, calls[1].idempotencyKey)
  }

  func testCanonicalApprovalChainDoesNotRegressWhenClaimedReceiptArrivesLate() async throws {
    let source = SessionSourceSpy()
    await source.setApprovalBehavior(.suspended)
    let vm = try await makePendingApprovalViewModel(source: source)

    vm.resolveApproval(approve: true)
    await source.waitForApprovalCalls(1)
    for (sequence, state) in [
      (UInt64(2), ApprovalDeliveryStateV1.claimed),
      (3, .applying),
      (4, .applied),
    ] {
      await source.emitConversation(
        .event(
          try SessionSourceTestValues.approvalResolved(
            conversationID: conversationID,
            commandID: "command-turn-1",
            turnID: "turn-1",
            approvalID: "approval-1",
            decision: .approve,
            state: state,
            eventSeq: sequence
          )
        )
      )
    }
    await waitForMainActorState { vm.approvalState == .applied(.approve) }

    await source.completeApproval(
      approvalID: "approval-1",
      with: .claimed(RuntimeApprovalID(rawValue: "approval-1"))
    )
    await waitForMainActorState { vm.approvalResponseGeneration == 1 }
    XCTAssertEqual(vm.approvalState, .applied(.approve))
  }

  func testAppliedReceiptDoesNotRegressWhileCanonicalStreamCatchesUp() async throws {
    let source = SessionSourceSpy()
    await source.setApprovalBehavior(
      .immediate(.applied(RuntimeApprovalID(rawValue: "approval-1")))
    )
    let vm = try await makePendingApprovalViewModel(source: source)
    var updateCount = 0
    vm.onUpdate = { updateCount += 1 }

    vm.resolveApproval(approve: true)
    await source.waitForApprovalCalls(1)
    await waitForMainActorState {
      vm.approvalResponseGeneration == 1
        && vm.approvalState == .applied(.approve)
    }
    let receiptUpdateCount = updateCount

    for (sequence, state) in [
      (UInt64(2), ApprovalDeliveryStateV1.claimed),
      (3, .applying),
    ] {
      await source.emitConversation(
        .event(
          try SessionSourceTestValues.approvalResolved(
            conversationID: conversationID,
            commandID: "command-turn-1",
            turnID: "turn-1",
            approvalID: "approval-1",
            decision: .approve,
            state: state,
            eventSeq: sequence
          )
        )
      )
    }
    await waitForMainActorState { updateCount >= receiptUpdateCount + 2 }
    XCTAssertEqual(vm.approvalState, .applied(.approve))
  }

  func testAppliedReceiptSurvivesLaggedSnapshotAndReplayedCanonicalPrefix() async throws {
    let source = SessionSourceSpy()
    await source.setApprovalBehavior(
      .immediate(.applied(RuntimeApprovalID(rawValue: "approval-1")))
    )
    let vm = try await makePendingApprovalViewModel(source: source)

    vm.resolveApproval(approve: true)
    await waitForMainActorState {
      vm.approvalResponseGeneration == 1
        && vm.approvalState == .applied(.approve)
    }

    await source.emitConversation(.connectionState(.lagged(reason: .bufferDropped)))
    await waitForMainActorState {
      vm.connectionState == .lagged(reason: .bufferDropped)
    }
    XCTAssertEqual(vm.errorText, "事件流落后，正在重新同步")

    await source.emitConversation(
      .snapshot(try SessionSourceTestValues.snapshot(conversationID: conversationID))
    )
    await waitForMainActorState {
      vm.connectionState == .connected
        && vm.errorText == nil
        && vm.approvalState == .applied(.approve)
    }

    var updateCount = 0
    vm.onUpdate = { updateCount += 1 }
    await source.emitConversation(
      .event(
        try SessionSourceTestValues.turnStarted(
          conversationID: conversationID,
          commandID: "command-turn-1",
          turnID: "turn-1",
          eventSeq: 0
        )
      )
    )
    await source.emitConversation(
      .event(
        try SessionSourceTestValues.actionRequest(
          conversationID: conversationID,
          commandID: "command-turn-1",
          turnID: "turn-1",
          approvalID: "approval-1",
          eventSeq: 1
        )
      )
    )
    for (sequence, state) in [
      (UInt64(2), ApprovalDeliveryStateV1.claimed),
      (3, .applying),
    ] {
      await source.emitConversation(
        .event(
          try SessionSourceTestValues.approvalResolved(
            conversationID: conversationID,
            commandID: "command-turn-1",
            turnID: "turn-1",
            approvalID: "approval-1",
            decision: .approve,
            state: state,
            eventSeq: sequence
          )
        )
      )
    }
    await waitForMainActorState { updateCount >= 4 }

    XCTAssertFalse(vm.isTerminal)
    XCTAssertEqual(vm.approvalState, .applied(.approve))
    vm.resolveApproval(approve: false)
    await Task.yield()
    let calls = await source.recordedApprovalCalls()
    XCTAssertEqual(calls.count, 1)
  }

  func testAppliedReceiptSurvivesTwoConsecutiveRecoveryGenerations() async throws {
    let source = SessionSourceSpy()
    await source.setApprovalBehavior(
      .immediate(.applied(RuntimeApprovalID(rawValue: "approval-1")))
    )
    let vm = try await makePendingApprovalViewModel(source: source)
    var updateCount = 0
    vm.onUpdate = { updateCount += 1 }

    vm.resolveApproval(approve: true)
    await waitForMainActorState {
      vm.approvalResponseGeneration == 1
        && vm.approvalState == .applied(.approve)
    }

    for generation in 1...2 {
      await source.emitConversation(
        .connectionState(.lagged(reason: .snapshotRequired))
      )
      await waitForMainActorState {
        vm.connectionState == .lagged(reason: .snapshotRequired)
      }
      await source.emitConversation(
        .snapshot(try SessionSourceTestValues.snapshot(conversationID: conversationID))
      )
      await waitForMainActorState { vm.connectionState == .connected }
      let replayUpdateCount = updateCount
      await source.emitConversation(
        .event(
          try SessionSourceTestValues.turnStarted(
            conversationID: conversationID,
            commandID: "command-turn-1",
            turnID: "turn-1",
            eventSeq: 0
          )
        )
      )
      await source.emitConversation(
        .event(
          try SessionSourceTestValues.actionRequest(
            conversationID: conversationID,
            commandID: "command-turn-1",
            turnID: "turn-1",
            approvalID: "approval-1",
            eventSeq: 1
          )
        )
      )
      await source.emitConversation(
        .event(
          try SessionSourceTestValues.approvalResolved(
            conversationID: conversationID,
            commandID: "command-turn-1",
            turnID: "turn-1",
            approvalID: "approval-1",
            decision: .approve,
            state: .claimed,
            eventSeq: 2
          )
        )
      )
      if generation == 2 {
        await source.emitConversation(
          .event(
            try SessionSourceTestValues.approvalResolved(
              conversationID: conversationID,
              commandID: "command-turn-1",
              turnID: "turn-1",
              approvalID: "approval-1",
              decision: .approve,
              state: .applying,
              eventSeq: 3
            )
          )
        )
      }
      await waitForMainActorState {
        updateCount >= replayUpdateCount + (generation == 1 ? 3 : 4)
      }
      XCTAssertEqual(vm.approvalState, .applied(.approve))
    }

    let finalReplayUpdateCount = updateCount
    await source.emitConversation(
      .event(
        try SessionSourceTestValues.approvalResolved(
          conversationID: conversationID,
          commandID: "command-turn-1",
          turnID: "turn-1",
          approvalID: "approval-1",
          decision: .approve,
          state: .applied,
          eventSeq: 4
        )
      )
    )
    await waitForMainActorState { updateCount >= finalReplayUpdateCount + 1 }
    XCTAssertEqual(vm.approvalState, .applied(.approve))
    XCTAssertFalse(vm.isTerminal)
  }

  func testRecoverySnapshotRejectsReboundApprovalIdentity() async throws {
    let cases = [
      (commandID: "command-turn-1", turnID: "turn-foreign", requestID: "request-1"),
      (commandID: "command-turn-1", turnID: "turn-1", requestID: "request-foreign"),
      (commandID: "command-foreign", turnID: "turn-1", requestID: "request-1"),
    ]

    for value in cases {
      let source = SessionSourceSpy()
      let vm = try await makePendingApprovalViewModel(source: source)
      await source.emitConversation(.connectionState(.lagged(reason: .cursorGap)))
      await waitForMainActorState {
        vm.connectionState == .lagged(reason: .cursorGap)
      }
      await source.emitConversation(
        .snapshot(try SessionSourceTestValues.snapshot(conversationID: conversationID))
      )
      await waitForMainActorState { vm.connectionState == .connected }

      await source.emitConversation(
        .event(
          try SessionSourceTestValues.turnStarted(
            conversationID: conversationID,
            commandID: value.commandID,
            turnID: value.turnID,
            eventSeq: 0
          )
        )
      )
      await source.emitConversation(
        .event(
          try SessionSourceTestValues.actionRequest(
            conversationID: conversationID,
            commandID: value.commandID,
            turnID: value.turnID,
            approvalID: "approval-1",
            requestID: value.requestID,
            eventSeq: 1
          )
        )
      )
      await waitForMainActorState { vm.isTerminal }

      XCTAssertEqual(vm.connectionState, .securityError)
      XCTAssertEqual(vm.approvalState, .none)
    }
  }

  func testRecoverySnapshotRejectsForeignApprovalIDWhileExistingApprovalIsUnresolved()
    async throws
  {
    let source = SessionSourceSpy()
    let vm = try await makePendingApprovalViewModel(source: source)

    await source.emitConversation(.connectionState(.lagged(reason: .cursorGap)))
    await waitForMainActorState {
      vm.connectionState == .lagged(reason: .cursorGap)
    }
    await source.emitConversation(
      .snapshot(try SessionSourceTestValues.snapshot(conversationID: conversationID))
    )
    await waitForMainActorState { vm.connectionState == .connected }
    await source.emitConversation(
      .event(
        try SessionSourceTestValues.turnStarted(
          conversationID: conversationID,
          commandID: "command-turn-1",
          turnID: "turn-1",
          eventSeq: 0
        )
      )
    )
    await source.emitConversation(
      .event(
        try SessionSourceTestValues.actionRequest(
          conversationID: conversationID,
          commandID: "command-turn-1",
          turnID: "turn-1",
          approvalID: "approval-foreign",
          requestID: "request-foreign",
          eventSeq: 1
        )
      )
    )
    await waitForMainActorState { vm.isTerminal }

    XCTAssertEqual(vm.connectionState, .securityError)
    XCTAssertEqual(vm.approvalState, .none)
    XCTAssertNil(vm.pendingApproval)
  }

  func testRecoverySnapshotRejectsDirectResolutionWithReboundTurnOrCommand() async throws {
    let cases = [
      (commandID: "command-turn-1", turnID: "turn-foreign"),
      (commandID: "command-foreign", turnID: "turn-1"),
    ]

    for value in cases {
      let source = SessionSourceSpy()
      let vm = try await makePendingApprovalViewModel(source: source)
      await source.emitConversation(.connectionState(.lagged(reason: .snapshotRequired)))
      await waitForMainActorState {
        vm.connectionState == .lagged(reason: .snapshotRequired)
      }
      await source.emitConversation(
        .snapshot(
          try SessionSourceTestValues.snapshot(
            conversationID: conversationID,
            baseEventCursor: ["at": 4]
          )
        )
      )
      await waitForMainActorState { vm.connectionState == .connected }

      await source.emitConversation(
        .event(
          try SessionSourceTestValues.approvalResolved(
            conversationID: conversationID,
            commandID: value.commandID,
            turnID: value.turnID,
            approvalID: "approval-1",
            decision: .approve,
            state: .applying,
            eventSeq: 5
          )
        )
      )
      await waitForMainActorState { vm.isTerminal }

      XCTAssertEqual(vm.connectionState, .securityError)
      XCTAssertEqual(vm.approvalState, .none)
    }
  }

  func testRecoverySnapshotRejectsDirectTurnTerminalWhileApprovalIsNonterminal() async throws {
    let source = SessionSourceSpy()
    let vm = try await makePendingApprovalViewModel(source: source)
    await source.emitConversation(.connectionState(.lagged(reason: .snapshotRequired)))
    await waitForMainActorState {
      vm.connectionState == .lagged(reason: .snapshotRequired)
    }
    await source.emitConversation(
      .snapshot(
        try SessionSourceTestValues.snapshot(
          conversationID: conversationID,
          baseEventCursor: ["at": 4]
        )
      )
    )
    await waitForMainActorState { vm.connectionState == .connected }

    await source.emitConversation(
      .event(
        try SessionSourceTestValues.turnCompleted(
          conversationID: conversationID,
          commandID: "command-turn-1",
          turnID: "turn-1",
          eventSeq: 5
        )
      )
    )
    await waitForMainActorState { vm.isTerminal }

    XCTAssertEqual(vm.connectionState, .securityError)
    XCTAssertEqual(vm.approvalState, .none)
    XCTAssertNil(vm.pendingApproval)
  }

  func testRecoverySnapshotRejectsDirectFailedTerminalWhileApprovalIsNonterminal() async throws {
    let source = SessionSourceSpy()
    let vm = try await makePendingApprovalViewModel(source: source)
    await source.emitConversation(.connectionState(.lagged(reason: .snapshotRequired)))
    await waitForMainActorState {
      vm.connectionState == .lagged(reason: .snapshotRequired)
    }
    await source.emitConversation(
      .snapshot(
        try SessionSourceTestValues.snapshot(
          conversationID: conversationID,
          baseEventCursor: ["at": 4]
        )
      )
    )
    await waitForMainActorState { vm.connectionState == .connected }

    await source.emitConversation(
      .event(
        try makeErrorEvent(
          commandID: "command-turn-1",
          code: "daemon.runtime.execution_failed",
          message: "agent execution failed",
          eventSeq: 5
        )
      )
    )
    await waitForMainActorState { vm.isTerminal }

    XCTAssertEqual(vm.connectionState, .securityError)
    XCTAssertEqual(vm.approvalState, .none)
    XCTAssertNil(vm.pendingApproval)
  }

  func testRecoverySnapshotAcceptsDirectFailedTerminalAfterApprovalApplied() async throws {
    let source = SessionSourceSpy()
    await source.setApprovalBehavior(
      .immediate(.applied(RuntimeApprovalID(rawValue: "approval-1")))
    )
    let vm = try await makePendingApprovalViewModel(source: source)
    vm.resolveApproval(approve: true)
    await waitForMainActorState {
      vm.approvalResponseGeneration == 1
        && vm.approvalState == .applied(.approve)
    }

    await source.emitConversation(.connectionState(.lagged(reason: .snapshotRequired)))
    await waitForMainActorState {
      vm.connectionState == .lagged(reason: .snapshotRequired)
    }
    await source.emitConversation(
      .snapshot(
        try SessionSourceTestValues.snapshot(
          conversationID: conversationID,
          baseEventCursor: ["at": 4]
        )
      )
    )
    await waitForMainActorState { vm.connectionState == .connected }

    await source.emitConversation(
      .event(
        try makeErrorEvent(
          commandID: "command-turn-1",
          code: "daemon.runtime.execution_failed",
          message: "agent execution failed",
          eventSeq: 5
        )
      )
    )
    await waitForMainActorState {
      vm.errorText == "agent execution failed"
    }

    XCTAssertFalse(vm.isTerminal)
    XCTAssertFalse(vm.isStreaming)
    XCTAssertEqual(vm.connectionState, .connected)
    XCTAssertEqual(vm.approvalState, .applied(.approve))
  }

  func testRecoverySnapshotKeepsInFlightApprovalOperation() async throws {
    let source = SessionSourceSpy()
    await source.setApprovalBehavior(.suspended)
    let vm = try await makePendingApprovalViewModel(source: source)

    vm.resolveApproval(approve: true)
    await source.waitForApprovalCalls(1)
    await source.emitConversation(.connectionState(.lagged(reason: .snapshotRequired)))
    await waitForMainActorState {
      vm.connectionState == .lagged(reason: .snapshotRequired)
    }
    await source.emitConversation(
      .snapshot(try SessionSourceTestValues.snapshot(conversationID: conversationID))
    )
    await waitForMainActorState { vm.connectionState == .connected }
    XCTAssertEqual(vm.approvalState, .submitting(.approve))

    await source.completeApproval(
      with: .applied(RuntimeApprovalID(rawValue: "approval-1"))
    )
    await waitForMainActorState {
      vm.approvalResponseGeneration == 1
        && vm.approvalState == .applied(.approve)
    }
    let calls = await source.recordedApprovalCalls()
    XCTAssertEqual(calls.count, 1)
  }

  func testDeliveryFailedReceiptSurvivesRecoveryAndKeepsWinnerOnlyRetryable() async throws {
    let source = SessionSourceSpy()
    await source.setApprovalBehavior(
      .immediate(.deliveryFailed(RuntimeApprovalID(rawValue: "approval-1")))
    )
    await source.setRetryBehavior(
      .immediate(.applied(RuntimeApprovalID(rawValue: "approval-1")))
    )
    let vm = try await makePendingApprovalViewModel(source: source)

    vm.resolveApproval(approve: true)
    await waitForMainActorState { vm.approvalState == .deliveryFailed(.approve) }
    await source.emitConversation(.connectionState(.lagged(reason: .cursorGap)))
    await waitForMainActorState {
      vm.connectionState == .lagged(reason: .cursorGap)
    }
    await source.emitConversation(
      .snapshot(try SessionSourceTestValues.snapshot(conversationID: conversationID))
    )
    await waitForMainActorState { vm.connectionState == .connected }
    var updateCount = 0
    vm.onUpdate = { updateCount += 1 }
    await source.emitConversation(
      .event(
        try SessionSourceTestValues.turnStarted(
          conversationID: conversationID,
          commandID: "command-turn-1",
          turnID: "turn-1",
          eventSeq: 0
        )
      )
    )
    await source.emitConversation(
      .event(
        try SessionSourceTestValues.actionRequest(
          conversationID: conversationID,
          commandID: "command-turn-1",
          turnID: "turn-1",
          approvalID: "approval-1",
          eventSeq: 1
        )
      )
    )
    await source.emitConversation(
      .event(
        try SessionSourceTestValues.approvalResolved(
          conversationID: conversationID,
          commandID: "command-turn-1",
          turnID: "turn-1",
          approvalID: "approval-1",
          decision: .approve,
          state: .claimed,
          eventSeq: 2
        )
      )
    )
    await waitForMainActorState { updateCount >= 3 }
    XCTAssertEqual(vm.approvalState, .deliveryFailed(.approve))

    for (sequence, state) in [
      (UInt64(3), ApprovalDeliveryStateV1.applying),
      (4, .deliveryFailed),
    ] {
      await source.emitConversation(
        .event(
          try SessionSourceTestValues.approvalResolved(
            conversationID: conversationID,
            commandID: "command-turn-1",
            turnID: "turn-1",
            approvalID: "approval-1",
            decision: .approve,
            state: state,
            eventSeq: sequence
          )
        )
      )
    }
    await waitForMainActorState { updateCount >= 5 }

    vm.resolveApproval(approve: false)
    await Task.yield()
    let approvalCallCount = await source.recordedApprovalCalls().count
    XCTAssertEqual(approvalCallCount, 1)
    vm.retryApprovalDelivery()
    await source.waitForRetryCalls(1)
    await waitForMainActorState { vm.approvalState == .applied(.approve) }
  }

  func testBareExpiredReceiptSurvivesRecoveryWithoutInventingWinner() async throws {
    let source = SessionSourceSpy()
    await source.setApprovalBehavior(
      .immediate(.expired(RuntimeApprovalID(rawValue: "approval-1")))
    )
    let vm = try await makePendingApprovalViewModel(source: source)

    vm.resolveApproval(approve: true)
    await waitForMainActorState { vm.approvalState == .expired(nil) }
    await source.emitConversation(.connectionState(.lagged(reason: .snapshotRequired)))
    await waitForMainActorState {
      vm.connectionState == .lagged(reason: .snapshotRequired)
    }
    await source.emitConversation(
      .snapshot(try SessionSourceTestValues.snapshot(conversationID: conversationID))
    )
    await waitForMainActorState { vm.connectionState == .connected }
    var updateCount = 0
    vm.onUpdate = { updateCount += 1 }
    await source.emitConversation(
      .event(
        try SessionSourceTestValues.turnStarted(
          conversationID: conversationID,
          commandID: "command-turn-1",
          turnID: "turn-1",
          eventSeq: 0
        )
      )
    )
    await source.emitConversation(
      .event(
        try SessionSourceTestValues.actionRequest(
          conversationID: conversationID,
          commandID: "command-turn-1",
          turnID: "turn-1",
          approvalID: "approval-1",
          eventSeq: 1
        )
      )
    )
    await source.emitConversation(
      .event(
        try SessionSourceTestValues.approvalResolved(
          conversationID: conversationID,
          commandID: "command-turn-1",
          turnID: "turn-1",
          approvalID: "approval-1",
          decision: nil,
          state: .expired,
          eventSeq: 2
        )
      )
    )
    await waitForMainActorState { updateCount >= 3 }
    XCTAssertEqual(vm.approvalState, .expired(nil))

    XCTAssertFalse(vm.isTerminal)
    vm.resolveApproval(approve: false)
    await Task.yield()
    let approvalCallCount = await source.recordedApprovalCalls().count
    XCTAssertEqual(approvalCallCount, 1)
  }

  func testTransportUnknownApprovalRetrySurvivesRecoveryAndReusesKey() async throws {
    let source = SessionSourceSpy()
    await source.setApprovalBehavior(
      .failure(SessionSourceFailure(code: .transportUnavailable))
    )
    let vm = try await makePendingApprovalViewModel(source: source)

    vm.resolveApproval(approve: true)
    await source.waitForApprovalCalls(1)
    await waitForMainActorState {
      vm.approvalState == .submissionFailed(.approve)
    }
    await source.emitConversation(.connectionState(.lagged(reason: .bufferDropped)))
    await waitForMainActorState {
      vm.connectionState == .lagged(reason: .bufferDropped)
    }
    await source.emitConversation(
      .snapshot(try SessionSourceTestValues.snapshot(conversationID: conversationID))
    )
    await waitForMainActorState { vm.connectionState == .connected }
    await source.emitConversation(
      .event(
        try SessionSourceTestValues.turnStarted(
          conversationID: conversationID,
          commandID: "command-turn-1",
          turnID: "turn-1",
          eventSeq: 0
        )
      )
    )
    await source.emitConversation(
      .event(
        try SessionSourceTestValues.actionRequest(
          conversationID: conversationID,
          commandID: "command-turn-1",
          turnID: "turn-1",
          approvalID: "approval-1",
          eventSeq: 1
        )
      )
    )
    await source.setApprovalBehavior(
      .immediate(.claimed(RuntimeApprovalID(rawValue: "approval-1")))
    )
    vm.retryApprovalDelivery()
    await source.waitForApprovalCalls(2)
    await waitForMainActorState { vm.approvalState == .submitting(.approve) }

    let calls = await source.recordedApprovalCalls()
    XCTAssertEqual(calls.map(\.decision), [.approve, .approve])
    XCTAssertEqual(calls[0].idempotencyKey, calls[1].idempotencyKey)
  }

  func testRetryDeliveryCanonicalBaselineRemainsMonotonicAcrossSnapshot() async throws {
    let source = SessionSourceSpy()
    await source.setApprovalBehavior(
      .immediate(.deliveryFailed(RuntimeApprovalID(rawValue: "approval-1")))
    )
    await source.setRetryBehavior(.suspended)
    let vm = try await makePendingApprovalViewModel(source: source)
    var updateCount = 0
    vm.onUpdate = { updateCount += 1 }

    vm.resolveApproval(approve: true)
    await waitForMainActorState { vm.approvalState == .deliveryFailed(.approve) }
    let receiptUpdateCount = updateCount
    for (sequence, state) in [
      (UInt64(2), ApprovalDeliveryStateV1.claimed),
      (3, .applying),
      (4, .deliveryFailed),
    ] {
      await source.emitConversation(
        .event(
          try SessionSourceTestValues.approvalResolved(
            conversationID: conversationID,
            commandID: "command-turn-1",
            turnID: "turn-1",
            approvalID: "approval-1",
            decision: .approve,
            state: state,
            eventSeq: sequence
          )
        )
      )
    }
    await waitForMainActorState { updateCount >= receiptUpdateCount + 3 }
    XCTAssertEqual(vm.approvalState, .deliveryFailed(.approve))
    vm.retryApprovalDelivery()
    await source.waitForRetryCalls(1)

    await source.emitConversation(.connectionState(.lagged(reason: .cursorGap)))
    await waitForMainActorState {
      vm.connectionState == .lagged(reason: .cursorGap)
    }
    await source.emitConversation(
      .snapshot(
        try SessionSourceTestValues.snapshot(
          conversationID: conversationID,
          baseEventCursor: ["at": 4]
        )
      )
    )
    await waitForMainActorState { vm.connectionState == .connected }
    await source.emitConversation(
      .event(
        try SessionSourceTestValues.approvalResolved(
          conversationID: conversationID,
          commandID: "command-turn-1",
          turnID: "turn-1",
          approvalID: "approval-1",
          decision: .approve,
          state: .applying,
          eventSeq: 5
        )
      )
    )
    await waitForMainActorState { vm.approvalState == .submitting(.approve) }
    await source.completeRetry(
      with: .alreadyHandled(
        approvalID: RuntimeApprovalID(rawValue: "approval-1"),
        decision: .approve,
        state: .applying
      )
    )
    await waitForMainActorState {
      vm.approvalResponseGeneration == 2
        && vm.approvalState == .submitting(.approve)
    }

    await source.emitConversation(
      .event(
        try SessionSourceTestValues.approvalResolved(
          conversationID: conversationID,
          commandID: "command-turn-1",
          turnID: "turn-1",
          approvalID: "approval-1",
          decision: .approve,
          state: .applied,
          eventSeq: 6
        )
      )
    )
    await waitForMainActorState {
      vm.approvalState == .applied(.approve)
    }
    XCTAssertEqual(vm.approvalState, .applied(.approve))
    XCTAssertFalse(vm.isTerminal)
  }

  func testRetryDeliverySurvivesOldCanonicalPrefixBeforeReceipt() async throws {
    let source = SessionSourceSpy()
    await source.setApprovalBehavior(
      .immediate(.deliveryFailed(RuntimeApprovalID(rawValue: "approval-1")))
    )
    await source.setRetryBehavior(.suspended)
    let vm = try await makePendingApprovalViewModel(source: source)
    var updateCount = 0
    vm.onUpdate = { updateCount += 1 }

    vm.resolveApproval(approve: true)
    await waitForMainActorState { vm.approvalState == .deliveryFailed(.approve) }
    let receiptUpdateCount = updateCount
    for (sequence, state) in [
      (UInt64(2), ApprovalDeliveryStateV1.claimed),
      (3, .applying),
      (4, .deliveryFailed),
    ] {
      await source.emitConversation(
        .event(
          try SessionSourceTestValues.approvalResolved(
            conversationID: conversationID,
            commandID: "command-turn-1",
            turnID: "turn-1",
            approvalID: "approval-1",
            decision: .approve,
            state: state,
            eventSeq: sequence
          )
        )
      )
    }
    await waitForMainActorState { updateCount >= receiptUpdateCount + 3 }

    vm.retryApprovalDelivery()
    await source.waitForRetryCalls(1)
    await source.emitConversation(.connectionState(.lagged(reason: .cursorGap)))
    await waitForMainActorState {
      vm.connectionState == .lagged(reason: .cursorGap)
    }
    await source.emitConversation(
      .snapshot(try SessionSourceTestValues.snapshot(conversationID: conversationID))
    )
    await waitForMainActorState { vm.connectionState == .connected }

    await source.emitConversation(
      .event(
        try SessionSourceTestValues.turnStarted(
          conversationID: conversationID,
          commandID: "command-turn-1",
          turnID: "turn-1",
          eventSeq: 0
        )
      )
    )
    await source.emitConversation(
      .event(
        try SessionSourceTestValues.actionRequest(
          conversationID: conversationID,
          commandID: "command-turn-1",
          turnID: "turn-1",
          approvalID: "approval-1",
          eventSeq: 1
        )
      )
    )
    let replayUpdateCount = updateCount
    for (sequence, state) in [
      (UInt64(2), ApprovalDeliveryStateV1.claimed),
      (3, .applying),
      (4, .deliveryFailed),
    ] {
      await source.emitConversation(
        .event(
          try SessionSourceTestValues.approvalResolved(
            conversationID: conversationID,
            commandID: "command-turn-1",
            turnID: "turn-1",
            approvalID: "approval-1",
            decision: .approve,
            state: state,
            eventSeq: sequence
          )
        )
      )
    }
    await waitForMainActorState { updateCount >= replayUpdateCount + 3 }
    XCTAssertEqual(vm.approvalState, .deliveryFailed(.approve))
    XCTAssertEqual(vm.approvalResponseGeneration, 1)

    await source.completeRetry(
      with: .alreadyHandled(
        approvalID: RuntimeApprovalID(rawValue: "approval-1"),
        decision: .approve,
        state: .applying
      )
    )
    await waitForMainActorState {
      vm.approvalResponseGeneration == 2
        && vm.approvalState == .submitting(.approve)
    }

    for (sequence, state) in [
      (UInt64(5), ApprovalDeliveryStateV1.applying),
      (6, .applied),
    ] {
      await source.emitConversation(
        .event(
          try SessionSourceTestValues.approvalResolved(
            conversationID: conversationID,
            commandID: "command-turn-1",
            turnID: "turn-1",
            approvalID: "approval-1",
            decision: .approve,
            state: state,
            eventSeq: sequence
          )
        )
      )
    }
    await waitForMainActorState { vm.approvalState == .applied(.approve) }
    XCTAssertFalse(vm.isTerminal)
    let retryApprovalIDs = await source.recordedRetryApprovalIDs()
    XCTAssertEqual(retryApprovalIDs, ["approval-1"])
  }

  func testRetryDeliveryIgnoresUnrelatedCursorAdvanceAfterOldFailure() async throws {
    let source = SessionSourceSpy()
    await source.setApprovalBehavior(
      .immediate(.deliveryFailed(RuntimeApprovalID(rawValue: "approval-1")))
    )
    await source.setRetryBehavior(.suspended)
    let vm = try await makePendingApprovalViewModel(source: source)
    var updateCount = 0
    vm.onUpdate = { updateCount += 1 }

    vm.resolveApproval(approve: true)
    await waitForMainActorState { vm.approvalState == .deliveryFailed(.approve) }
    let receiptUpdateCount = updateCount
    for (sequence, state) in [
      (UInt64(2), ApprovalDeliveryStateV1.claimed),
      (3, .applying),
      (4, .deliveryFailed),
    ] {
      await source.emitConversation(
        .event(
          try SessionSourceTestValues.approvalResolved(
            conversationID: conversationID,
            commandID: "command-turn-1",
            turnID: "turn-1",
            approvalID: "approval-1",
            decision: .approve,
            state: state,
            eventSeq: sequence
          )
        )
      )
    }
    await waitForMainActorState { updateCount >= receiptUpdateCount + 3 }

    vm.retryApprovalDelivery()
    await source.waitForRetryCalls(1)
    await source.emitConversation(
      .event(
        try SessionSourceTestValues.userMessage(
          conversationID: conversationID,
          commandID: "command-turn-1",
          itemID: "unrelated-retry-fence",
          text: "与审批 resolution 无关的 canonical item",
          eventSeq: 5
        )
      )
    )
    await source.completeRetry(
      with: .alreadyHandled(
        approvalID: RuntimeApprovalID(rawValue: "approval-1"),
        decision: .approve,
        state: .applying
      )
    )
    await waitForMainActorState {
      vm.approvalResponseGeneration == 2
        && vm.approvalState == .submitting(.approve)
    }

    XCTAssertFalse(vm.isTerminal)
    let retryApprovalIDs = await source.recordedRetryApprovalIDs()
    XCTAssertEqual(retryApprovalIDs, ["approval-1"])
  }

  func testRetryTransportFailureDoesNotTrustOldApplyingAcrossSnapshot() async throws {
    let source = SessionSourceSpy()
    await source.setApprovalBehavior(
      .immediate(.deliveryFailed(RuntimeApprovalID(rawValue: "approval-1")))
    )
    await source.setRetryBehavior(.suspended)
    let vm = try await makePendingApprovalViewModel(source: source)
    var updateCount = 0
    vm.onUpdate = { updateCount += 1 }

    vm.resolveApproval(approve: true)
    await waitForMainActorState { vm.approvalState == .deliveryFailed(.approve) }
    let receiptUpdateCount = updateCount
    for (sequence, state) in [
      (UInt64(2), ApprovalDeliveryStateV1.claimed),
      (3, .applying),
      (4, .deliveryFailed),
    ] {
      await source.emitConversation(
        .event(
          try SessionSourceTestValues.approvalResolved(
            conversationID: conversationID,
            commandID: "command-turn-1",
            turnID: "turn-1",
            approvalID: "approval-1",
            decision: .approve,
            state: state,
            eventSeq: sequence
          )
        )
      )
    }
    await waitForMainActorState { updateCount >= receiptUpdateCount + 3 }

    vm.retryApprovalDelivery()
    await source.waitForRetryCalls(1)
    await source.emitConversation(.connectionState(.lagged(reason: .cursorGap)))
    await waitForMainActorState {
      vm.connectionState == .lagged(reason: .cursorGap)
    }
    await source.emitConversation(
      .snapshot(try SessionSourceTestValues.snapshot(conversationID: conversationID))
    )
    await waitForMainActorState { vm.connectionState == .connected }
    let replayUpdateCount = updateCount
    for update in [
      ConversationUpdate.event(
        try SessionSourceTestValues.turnStarted(
          conversationID: conversationID,
          commandID: "command-turn-1",
          turnID: "turn-1",
          eventSeq: 0
        )
      ),
      .event(
        try SessionSourceTestValues.actionRequest(
          conversationID: conversationID,
          commandID: "command-turn-1",
          turnID: "turn-1",
          approvalID: "approval-1",
          eventSeq: 1
        )
      ),
      .event(
        try SessionSourceTestValues.approvalResolved(
          conversationID: conversationID,
          commandID: "command-turn-1",
          turnID: "turn-1",
          approvalID: "approval-1",
          decision: .approve,
          state: .claimed,
          eventSeq: 2
        )
      ),
      .event(
        try SessionSourceTestValues.approvalResolved(
          conversationID: conversationID,
          commandID: "command-turn-1",
          turnID: "turn-1",
          approvalID: "approval-1",
          decision: .approve,
          state: .applying,
          eventSeq: 3
        )
      ),
    ] {
      await source.emitConversation(update)
    }
    await waitForMainActorState { updateCount >= replayUpdateCount + 4 }

    await source.failRetry(
      with: SessionSourceFailure(code: .transportUnavailable)
    )
    await waitForMainActorState {
      vm.approvalResponseGeneration == 2
        && vm.approvalState == .deliveryFailed(.approve)
    }
    XCTAssertEqual(vm.errorText, "Relay 不可达")

    vm.retryApprovalDelivery()
    await Task.yield()
    var retryApprovalIDs = await source.recordedRetryApprovalIDs()
    XCTAssertEqual(retryApprovalIDs, ["approval-1"])

    let beforeFailureReplayUpdateCount = updateCount
    await source.emitConversation(
      .event(
        try SessionSourceTestValues.approvalResolved(
          conversationID: conversationID,
          commandID: "command-turn-1",
          turnID: "turn-1",
          approvalID: "approval-1",
          decision: .approve,
          state: .deliveryFailed,
          eventSeq: 4
        )
      )
    )
    await waitForMainActorState {
      updateCount >= beforeFailureReplayUpdateCount + 1
    }
    XCTAssertEqual(vm.approvalState, .deliveryFailed(.approve))
    await source.setRetryBehavior(
      .immediate(
        .alreadyHandled(
          approvalID: RuntimeApprovalID(rawValue: "approval-1"),
          decision: .approve,
          state: .applying
        )
      )
    )
    vm.retryApprovalDelivery()
    await source.waitForRetryCalls(2)
    retryApprovalIDs = await source.recordedRetryApprovalIDs()
    XCTAssertEqual(retryApprovalIDs, ["approval-1", "approval-1"])

    for (sequence, state) in [
      (UInt64(5), ApprovalDeliveryStateV1.applying),
      (6, .applied),
    ] {
      await source.emitConversation(
        .event(
          try SessionSourceTestValues.approvalResolved(
            conversationID: conversationID,
            commandID: "command-turn-1",
            turnID: "turn-1",
            approvalID: "approval-1",
            decision: .approve,
            state: state,
            eventSeq: sequence
          )
        )
      )
    }
    await waitForMainActorState { vm.approvalState == .applied(.approve) }
  }

  func testDeliveryFailedFloorYieldsToLaterAppliedWithoutFailureReplay() async throws {
    let source = SessionSourceSpy()
    let vm = try await makePendingApprovalViewModel(source: source)

    for (sequence, state) in [
      (UInt64(2), ApprovalDeliveryStateV1.claimed),
      (3, .applying),
      (4, .deliveryFailed),
    ] {
      await source.emitConversation(
        .event(
          try SessionSourceTestValues.approvalResolved(
            conversationID: conversationID,
            commandID: "command-turn-1",
            turnID: "turn-1",
            approvalID: "approval-1",
            decision: .approve,
            state: state,
            eventSeq: sequence
          )
        )
      )
    }
    let failedState = ApprovalState.alreadyHandled(
      decision: .approve,
      deliveryState: .deliveryFailed
    )
    await waitForMainActorState { vm.approvalState == failedState }

    await source.emitConversation(.connectionState(.lagged(reason: .snapshotRequired)))
    await waitForMainActorState {
      vm.connectionState == .lagged(reason: .snapshotRequired)
    }
    await source.emitConversation(
      .snapshot(
        try SessionSourceTestValues.snapshot(
          conversationID: conversationID,
          baseEventCursor: ["at": 4]
        )
      )
    )
    await waitForMainActorState { vm.connectionState == .connected }
    for (sequence, state) in [
      (UInt64(5), ApprovalDeliveryStateV1.applying),
      (6, .applied),
    ] {
      await source.emitConversation(
        .event(
          try SessionSourceTestValues.approvalResolved(
            conversationID: conversationID,
            commandID: "command-turn-1",
            turnID: "turn-1",
            approvalID: "approval-1",
            decision: .approve,
            state: state,
            eventSeq: sequence
          )
        )
      )
    }
    await waitForMainActorState {
      vm.approvalState
        == .alreadyHandled(decision: .approve, deliveryState: .applied)
    }
    XCTAssertFalse(vm.isTerminal)
  }

  func testCanonicalTerminalFloorSurvivesRecoveryReplay() async throws {
    let source = SessionSourceSpy()
    let vm = try await makePendingApprovalViewModel(source: source)

    for (sequence, state) in [
      (UInt64(2), ApprovalDeliveryStateV1.claimed),
      (3, .applying),
      (4, .applied),
    ] {
      await source.emitConversation(
        .event(
          try SessionSourceTestValues.approvalResolved(
            conversationID: conversationID,
            commandID: "command-turn-1",
            turnID: "turn-1",
            approvalID: "approval-1",
            decision: .approve,
            state: state,
            eventSeq: sequence
          )
        )
      )
    }
    let terminalState = ApprovalState.alreadyHandled(
      decision: .approve,
      deliveryState: .applied
    )
    await waitForMainActorState { vm.approvalState == terminalState }

    await source.emitConversation(.connectionState(.lagged(reason: .bufferDropped)))
    await waitForMainActorState {
      vm.connectionState == .lagged(reason: .bufferDropped)
    }
    await source.emitConversation(
      .snapshot(try SessionSourceTestValues.snapshot(conversationID: conversationID))
    )
    await waitForMainActorState { vm.connectionState == .connected }

    var updateCount = 0
    vm.onUpdate = { updateCount += 1 }
    await source.emitConversation(
      .event(
        try SessionSourceTestValues.turnStarted(
          conversationID: conversationID,
          commandID: "command-turn-1",
          turnID: "turn-1",
          eventSeq: 0
        )
      )
    )
    await source.emitConversation(
      .event(
        try SessionSourceTestValues.actionRequest(
          conversationID: conversationID,
          commandID: "command-turn-1",
          turnID: "turn-1",
          approvalID: "approval-1",
          eventSeq: 1
        )
      )
    )
    for (sequence, state) in [
      (UInt64(2), ApprovalDeliveryStateV1.claimed),
      (3, .applying),
    ] {
      await source.emitConversation(
        .event(
          try SessionSourceTestValues.approvalResolved(
            conversationID: conversationID,
            commandID: "command-turn-1",
            turnID: "turn-1",
            approvalID: "approval-1",
            decision: .approve,
            state: state,
            eventSeq: sequence
          )
        )
      )
    }
    await waitForMainActorState { updateCount >= 4 }

    XCTAssertFalse(vm.isTerminal)
    XCTAssertEqual(vm.approvalState, terminalState)
  }

  func testDeliveryFailedReceiptOnlyYieldsAfterCanonicalFailureCatchesUp() async throws {
    let source = SessionSourceSpy()
    await source.setApprovalBehavior(
      .immediate(.deliveryFailed(RuntimeApprovalID(rawValue: "approval-1")))
    )
    let vm = try await makePendingApprovalViewModel(source: source)
    var updateCount = 0
    vm.onUpdate = { updateCount += 1 }

    vm.resolveApproval(approve: true)
    await source.waitForApprovalCalls(1)
    await waitForMainActorState {
      vm.approvalResponseGeneration == 1
        && vm.approvalState == .deliveryFailed(.approve)
    }
    let receiptUpdateCount = updateCount

    for (sequence, state) in [
      (UInt64(2), ApprovalDeliveryStateV1.claimed),
      (3, .applying),
    ] {
      await source.emitConversation(
        .event(
          try SessionSourceTestValues.approvalResolved(
            conversationID: conversationID,
            commandID: "command-turn-1",
            turnID: "turn-1",
            approvalID: "approval-1",
            decision: .approve,
            state: state,
            eventSeq: sequence
          )
        )
      )
    }
    await waitForMainActorState { updateCount >= receiptUpdateCount + 2 }
    XCTAssertEqual(vm.approvalState, .deliveryFailed(.approve))

    await source.emitConversation(
      .event(
        try SessionSourceTestValues.approvalResolved(
          conversationID: conversationID,
          commandID: "command-turn-1",
          turnID: "turn-1",
          approvalID: "approval-1",
          decision: .approve,
          state: .deliveryFailed,
          eventSeq: 4
        )
      )
    )
    await waitForMainActorState { updateCount >= receiptUpdateCount + 3 }
    XCTAssertEqual(vm.approvalState, .deliveryFailed(.approve))

    for (sequence, state) in [
      (UInt64(5), ApprovalDeliveryStateV1.applying),
      (6, .applied),
    ] {
      await source.emitConversation(
        .event(
          try SessionSourceTestValues.approvalResolved(
            conversationID: conversationID,
            commandID: "command-turn-1",
            turnID: "turn-1",
            approvalID: "approval-1",
            decision: .approve,
            state: state,
            eventSeq: sequence
          )
        )
      )
    }
    await waitForMainActorState { vm.approvalState == .applied(.approve) }
  }

  func testCanonicalPendingApprovalCanExpireWithoutDecision() async throws {
    let source = SessionSourceSpy()
    let vm = try await makePendingApprovalViewModel(source: source)

    await source.emitConversation(
      .event(
        try SessionSourceTestValues.approvalResolved(
          conversationID: conversationID,
          commandID: "command-turn-1",
          turnID: "turn-1",
          approvalID: "approval-1",
          decision: nil,
          state: .expired,
          eventSeq: 2
        )
      )
    )
    await waitForMainActorState { vm.approvalState == .expired(nil) }
  }

  func testExpiredReceiptDoesNotInventSubmittedDecision() async throws {
    let source = SessionSourceSpy()
    await source.setApprovalBehavior(
      .immediate(.expired(RuntimeApprovalID(rawValue: "approval-1")))
    )
    let vm = try await makePendingApprovalViewModel(source: source)
    var updateCount = 0
    vm.onUpdate = { updateCount += 1 }

    vm.resolveApproval(approve: true)

    await waitForMainActorState {
      vm.approvalResponseGeneration == 1
        && vm.approvalState == .expired(nil)
    }
    let receiptUpdateCount = updateCount

    await source.emitConversation(
      .event(
        try SessionSourceTestValues.approvalResolved(
          conversationID: conversationID,
          commandID: "command-turn-1",
          turnID: "turn-1",
          approvalID: "approval-1",
          decision: nil,
          state: .expired,
          eventSeq: 2
        )
      )
    )
    await waitForMainActorState { updateCount >= receiptUpdateCount + 1 }
    XCTAssertFalse(vm.isTerminal)
    XCTAssertEqual(vm.approvalState, .expired(nil))
  }

  func testExpiredReceiptFailsClosedIfCanonicalEvidenceHasWinner() async throws {
    let source = SessionSourceSpy()
    await source.setApprovalBehavior(
      .immediate(.expired(RuntimeApprovalID(rawValue: "approval-1")))
    )
    let vm = try await makePendingApprovalViewModel(source: source)

    vm.resolveApproval(approve: true)
    await waitForMainActorState {
      vm.approvalResponseGeneration == 1
        && vm.approvalState == .expired(nil)
    }

    await source.emitConversation(
      .event(
        try SessionSourceTestValues.approvalResolved(
          conversationID: conversationID,
          commandID: "command-turn-1",
          turnID: "turn-1",
          approvalID: "approval-1",
          decision: .approve,
          state: .claimed,
          eventSeq: 2
        )
      )
    )
    await waitForMainActorState { vm.isTerminal }

    XCTAssertEqual(vm.connectionState, .securityError)
    XCTAssertEqual(vm.approvalState, .none)
  }

  func testCanonicalTerminalStillValidatesConflictingLateReceipt() async throws {
    let source = SessionSourceSpy()
    await source.setApprovalBehavior(.suspended)
    let vm = try await makePendingApprovalViewModel(source: source)

    vm.resolveApproval(approve: true)
    await source.waitForApprovalCalls(1)
    for (sequence, state) in [
      (UInt64(2), ApprovalDeliveryStateV1.claimed),
      (3, .applying),
      (4, .applied),
    ] {
      await source.emitConversation(
        .event(
          try SessionSourceTestValues.approvalResolved(
            conversationID: conversationID,
            commandID: "command-turn-1",
            turnID: "turn-1",
            approvalID: "approval-1",
            decision: .approve,
            state: state,
            eventSeq: sequence
          )
        )
      )
    }
    await waitForMainActorState { vm.approvalState == .applied(.approve) }

    await source.completeApproval(
      with: .alreadyHandled(
        approvalID: RuntimeApprovalID(rawValue: "approval-1"),
        decision: .deny,
        state: .applied
      )
    )
    await waitForMainActorState {
      vm.approvalResponseGeneration == 1 && vm.isTerminal
    }

    XCTAssertEqual(vm.connectionState, .securityError)
    XCTAssertEqual(vm.approvalState, .none)
  }

  func testCanonicalExpiredRejectsLateAppliedReceiptForSameWinner() async throws {
    let source = SessionSourceSpy()
    await source.setApprovalBehavior(.suspended)
    let vm = try await makePendingApprovalViewModel(source: source)

    vm.resolveApproval(approve: true)
    await source.waitForApprovalCalls(1)
    for (sequence, state) in [
      (UInt64(2), ApprovalDeliveryStateV1.claimed),
      (3, .expired),
    ] {
      await source.emitConversation(
        .event(
          try SessionSourceTestValues.approvalResolved(
            conversationID: conversationID,
            commandID: "command-turn-1",
            turnID: "turn-1",
            approvalID: "approval-1",
            decision: .approve,
            state: state,
            eventSeq: sequence
          )
        )
      )
    }
    await waitForMainActorState { vm.approvalState == .expired(.approve) }

    await source.completeApproval(
      with: .applied(RuntimeApprovalID(rawValue: "approval-1"))
    )
    await waitForMainActorState {
      vm.approvalResponseGeneration == 1 && vm.isTerminal
    }

    XCTAssertEqual(vm.connectionState, .securityError)
    XCTAssertEqual(vm.approvalState, .none)
  }

  func testCanonicalTerminalStillValidatesLateReceiptIdentity() async throws {
    let source = SessionSourceSpy()
    await source.setApprovalBehavior(.suspended)
    let vm = try await makePendingApprovalViewModel(source: source)

    vm.resolveApproval(approve: true)
    await source.waitForApprovalCalls(1)
    for (sequence, state) in [
      (UInt64(2), ApprovalDeliveryStateV1.claimed),
      (3, .applying),
      (4, .applied),
    ] {
      await source.emitConversation(
        .event(
          try SessionSourceTestValues.approvalResolved(
            conversationID: conversationID,
            commandID: "command-turn-1",
            turnID: "turn-1",
            approvalID: "approval-1",
            decision: .approve,
            state: state,
            eventSeq: sequence
          )
        )
      )
    }
    await waitForMainActorState { vm.approvalState == .applied(.approve) }

    await source.completeApproval(
      with: .applied(RuntimeApprovalID(rawValue: "approval-foreign"))
    )
    await waitForMainActorState {
      vm.approvalResponseGeneration == 1 && vm.isTerminal
    }

    XCTAssertEqual(vm.connectionState, .securityError)
    XCTAssertEqual(vm.approvalState, .none)
  }

  func testCanonicalTerminalStillLatchesLateFatalApprovalFailure() async throws {
    for code in [
      SessionSourceFailureCode.securityError,
      .revoked,
      .incompatible,
    ] {
      let source = SessionSourceSpy()
      await source.setApprovalBehavior(.suspended)
      let vm = try await makePendingApprovalViewModel(source: source)

      vm.resolveApproval(approve: true)
      await source.waitForApprovalCalls(1)
      for (sequence, state) in [
        (UInt64(2), ApprovalDeliveryStateV1.claimed),
        (3, .applying),
        (4, .applied),
      ] {
        await source.emitConversation(
          .event(
            try SessionSourceTestValues.approvalResolved(
              conversationID: conversationID,
              commandID: "command-turn-1",
              turnID: "turn-1",
              approvalID: "approval-1",
              decision: .approve,
              state: state,
              eventSeq: sequence
            )
          )
        )
      }
      await waitForMainActorState { vm.approvalState == .applied(.approve) }

      await source.failApproval(with: SessionSourceFailure(code: code))
      await waitForMainActorState {
        vm.approvalResponseGeneration == 1 && vm.isTerminal
      }

      XCTAssertEqual(
        vm.connectionState,
        code == .revoked ? .revoked : code == .incompatible ? .incompatible : .securityError
      )
    }
  }

  func testNewTurnStartRetiresPreviousApprovalProjectionBeforeNextRequest() async throws {
    let source = SessionSourceSpy()
    await source.setApprovalBehavior(
      .immediate(.applied(RuntimeApprovalID(rawValue: "approval-1")))
    )
    let vm = try await makePendingApprovalViewModel(source: source)
    var updateCount = 0
    vm.onUpdate = { updateCount += 1 }

    vm.resolveApproval(approve: true)
    await waitForMainActorState { vm.approvalState == .applied(.approve) }
    let beforeCanonicalChainUpdateCount = updateCount
    for (sequence, state) in [
      (UInt64(2), ApprovalDeliveryStateV1.claimed),
      (3, .applying),
      (4, .applied),
    ] {
      await source.emitConversation(
        .event(
          try SessionSourceTestValues.approvalResolved(
            conversationID: conversationID,
            commandID: "command-turn-1",
            turnID: "turn-1",
            approvalID: "approval-1",
            decision: .approve,
            state: state,
            eventSeq: sequence
          )
        )
      )
    }
    await waitForMainActorState {
      updateCount >= beforeCanonicalChainUpdateCount + 3
    }
    XCTAssertEqual(vm.approvalState, .applied(.approve))

    let beforeTurnCompletedUpdateCount = updateCount
    await source.emitConversation(
      .event(
        try SessionSourceTestValues.turnCompleted(
          conversationID: conversationID,
          commandID: "command-turn-1",
          turnID: "turn-1",
          eventSeq: 5
        )
      )
    )
    await waitForMainActorState {
      updateCount >= beforeTurnCompletedUpdateCount + 1
    }

    let beforeNewTurnUpdateCount = updateCount
    await source.emitConversation(
      .event(
        try SessionSourceTestValues.turnStarted(
          conversationID: conversationID,
          commandID: "command-turn-2",
          turnID: "turn-2",
          eventSeq: 6
        )
      )
    )
    await waitForMainActorState { updateCount >= beforeNewTurnUpdateCount + 1 }

    XCTAssertEqual(vm.approvalState, .none)
    XCTAssertNil(vm.pendingApproval)
    vm.resolveApproval(approve: false)
    vm.retryApprovalDelivery()
    await Task.yield()
    let approvalCalls = await source.recordedApprovalCalls()
    let retryApprovalIDs = await source.recordedRetryApprovalIDs()
    XCTAssertEqual(approvalCalls.count, 1)
    XCTAssertTrue(retryApprovalIDs.isEmpty)

    await source.emitConversation(
      .event(
        try SessionSourceTestValues.actionRequest(
          conversationID: conversationID,
          commandID: "command-turn-2",
          turnID: "turn-2",
          approvalID: "approval-2",
          requestID: "request-2",
          eventSeq: 7
        )
      )
    )
    await waitForMainActorState { vm.approvalState == .pending }
  }

  func testLateReceiptForResolvedApprovalCannotMutateNextCard() async throws {
    let source = SessionSourceSpy()
    await source.setApprovalBehavior(.suspended)
    let vm = SessionDetailViewModel(source: source, conversationID: conversationID)
    vm.start()
    await source.waitForConversationSubscriptions(1)
    await source.emitConversation(
      .snapshot(try SessionSourceTestValues.snapshot(conversationID: conversationID))
    )
    await source.emitConversation(
      .event(
        try SessionSourceTestValues.turnStarted(
          conversationID: conversationID,
          commandID: "command-turn-1",
          turnID: "turn-1",
          eventSeq: 0
        )
      )
    )
    for (sequence, approvalID) in [(UInt64(1), "approval-a"), (2, "approval-b")] {
      await source.emitConversation(
        .event(
          try SessionSourceTestValues.actionRequest(
            conversationID: conversationID,
            commandID: "command-turn-1",
            turnID: "turn-1",
            approvalID: approvalID,
            requestID: "request-\(approvalID)",
            eventSeq: sequence
          )
        )
      )
    }
    await waitForMainActorState { vm.approvalState == .pending }

    vm.resolveApproval(approve: true)
    await source.waitForApprovalCalls(1)
    await source.emitConversation(
      .event(
        try SessionSourceTestValues.approvalResolved(
          conversationID: conversationID,
          commandID: "command-turn-1",
          turnID: "turn-1",
          approvalID: "approval-a",
          decision: .approve,
          state: .claimed,
          eventSeq: 3
        )
      )
    )
    await waitForMainActorState { vm.approvalState == .pending }
    vm.resolveApproval(approve: false)
    await source.waitForApprovalCalls(2)

    await source.completeApproval(
      approvalID: "approval-a",
      with: .applied(RuntimeApprovalID(rawValue: "approval-a"))
    )
    await waitForMainActorState { vm.approvalResponseGeneration == 1 }
    XCTAssertEqual(vm.approvalState, .submitting(.deny))

    await source.completeApproval(
      approvalID: "approval-b",
      with: .claimed(RuntimeApprovalID(rawValue: "approval-b"))
    )
    await waitForMainActorState { vm.approvalResponseGeneration == 2 }
  }

  func testWrongApprovalReceiptIdentityFailsClosed() async throws {
    let source = SessionSourceSpy()
    await source.setApprovalBehavior(.suspended)
    let vm = try await makePendingApprovalViewModel(source: source)

    vm.resolveApproval(approve: true)
    await source.waitForApprovalCalls(1)
    await source.completeApproval(
      with: .claimed(RuntimeApprovalID(rawValue: "approval-foreign"))
    )
    await waitForMainActorState {
      vm.approvalResponseGeneration == 1 && vm.isTerminal
    }

    XCTAssertEqual(vm.connectionState, .securityError)
    vm.resolveApproval(approve: false)
    await Task.yield()
    let calls = await source.recordedApprovalCalls()
    XCTAssertEqual(calls.count, 1)
  }

  func testFatalApprovalFailureFailsClosed() async throws {
    let source = SessionSourceSpy()
    await source.setApprovalBehavior(
      .failure(SessionSourceFailure(code: .securityError))
    )
    let vm = try await makePendingApprovalViewModel(source: source)

    vm.resolveApproval(approve: true)
    await source.waitForApprovalCalls(1)
    await waitForMainActorState {
      vm.approvalResponseGeneration == 1 && vm.isTerminal
    }

    XCTAssertEqual(vm.connectionState, .securityError)
    XCTAssertEqual(vm.approvalState, .none)
  }

  func testAlreadyHandledShowsActualWinnerAndDeliveryState() async throws {
    let source = SessionSourceSpy()
    await source.setApprovalBehavior(
      .immediate(
        .alreadyHandled(
          approvalID: RuntimeApprovalID(rawValue: "approval-1"),
          decision: .deny,
          state: .deliveryFailed
        )
      )
    )
    let vm = try await makePendingApprovalViewModel(source: source)

    vm.resolveApproval(approve: true)
    await source.waitForApprovalCalls(1)
    await waitForMainActorState {
      vm.approvalState
        == .alreadyHandled(
          decision: .deny,
          deliveryState: .deliveryFailed
        )
    }

    XCTAssertEqual(
      vm.approvalState,
      .alreadyHandled(decision: .deny, deliveryState: .deliveryFailed)
    )
  }

  func testDeliveryFailedOnlyRetriesTheClaimedDecision() async throws {
    let source = SessionSourceSpy()
    await source.setApprovalBehavior(
      .immediate(.deliveryFailed(RuntimeApprovalID(rawValue: "approval-1")))
    )
    await source.setRetryBehavior(.suspended)
    let vm = try await makePendingApprovalViewModel(source: source)
    var updateCount = 0
    vm.onUpdate = { updateCount += 1 }

    vm.resolveApproval(approve: true)
    await source.waitForApprovalCalls(1)
    await waitForMainActorState {
      vm.approvalState == .deliveryFailed(.approve)
    }

    vm.resolveApproval(approve: false)
    await Task.yield()
    let approvalCallCount = await source.recordedApprovalCalls().count
    XCTAssertEqual(approvalCallCount, 1)

    vm.retryApprovalDelivery()
    await Task.yield()
    let earlyRetryApprovalIDs = await source.recordedRetryApprovalIDs()
    XCTAssertTrue(earlyRetryApprovalIDs.isEmpty)
    XCTAssertEqual(vm.errorText, "等待审批投递失败状态同步后再重试")

    let receiptUpdateCount = updateCount
    for (sequence, state) in [
      (UInt64(2), ApprovalDeliveryStateV1.claimed),
      (3, .applying),
      (4, .deliveryFailed),
    ] {
      await source.emitConversation(
        .event(
          try SessionSourceTestValues.approvalResolved(
            conversationID: conversationID,
            commandID: "command-turn-1",
            turnID: "turn-1",
            approvalID: "approval-1",
            decision: .approve,
            state: state,
            eventSeq: sequence
          )
        )
      )
    }
    await waitForMainActorState { updateCount >= receiptUpdateCount + 3 }

    vm.retryApprovalDelivery()
    await source.waitForRetryCalls(1)
    XCTAssertEqual(vm.approvalState, .submitting(.approve))
    let retriedApprovalIDs = await source.recordedRetryApprovalIDs()
    XCTAssertEqual(retriedApprovalIDs, ["approval-1"])

    await source.completeRetry(
      with: .alreadyHandled(
        approvalID: RuntimeApprovalID(rawValue: "approval-1"),
        decision: .approve,
        state: .applying
      )
    )
    await waitForMainActorState { vm.approvalResponseGeneration == 2 }
    XCTAssertEqual(vm.approvalState, .submitting(.approve))

    for (sequence, state) in [
      (UInt64(5), ApprovalDeliveryStateV1.applying),
      (6, .applied),
    ] {
      await source.emitConversation(
        .event(
          try SessionSourceTestValues.approvalResolved(
            conversationID: conversationID,
            commandID: "command-turn-1",
            turnID: "turn-1",
            approvalID: "approval-1",
            decision: .approve,
            state: state,
            eventSeq: sequence
          )
        )
      )
    }
    await waitForMainActorState { vm.approvalState == .applied(.approve) }
  }

  func testRetiredApprovalOperationLimitFailsClosedOnThirtyThirdWithoutReceiptMutation()
    async throws
  {
    let source = SessionSourceSpy()
    await source.setApprovalBehavior(.suspended)
    let vm = SessionDetailViewModel(source: source, conversationID: conversationID)
    vm.start()
    await source.waitForConversationSubscriptions(1)
    await source.emitConversation(
      .snapshot(try SessionSourceTestValues.snapshot(conversationID: conversationID))
    )

    var eventSeq: UInt64 = 0
    await source.emitConversation(
      .event(
        try SessionSourceTestValues.turnStarted(
          conversationID: conversationID,
          commandID: "command-turn-1",
          turnID: "turn-1",
          eventSeq: eventSeq
        )
      )
    )
    eventSeq += 1

    for index in 1...32 {
      let approvalID = "approval-\(index)"
      await source.emitConversation(
        .event(
          try SessionSourceTestValues.actionRequest(
            conversationID: conversationID,
            commandID: "command-turn-1",
            turnID: "turn-1",
            approvalID: approvalID,
            requestID: "request-\(index)",
            eventSeq: eventSeq
          )
        )
      )
      eventSeq += 1
      await waitForMainActorState { vm.approvalState == .pending }
      vm.resolveApproval(approve: true)
      await source.waitForApprovalCalls(index)

      for state in [
        ApprovalDeliveryStateV1.claimed,
        .applying,
        .applied,
      ] {
        await source.emitConversation(
          .event(
            try SessionSourceTestValues.approvalResolved(
              conversationID: conversationID,
              commandID: "command-turn-1",
              turnID: "turn-1",
              approvalID: approvalID,
              decision: .approve,
              state: state,
              eventSeq: eventSeq
            )
          )
        )
        eventSeq += 1
      }
      await waitForMainActorState { vm.approvalState == .applied(.approve) }
      XCTAssertFalse(vm.isTerminal)
    }

    await source.emitConversation(
      .event(
        try SessionSourceTestValues.turnCompleted(
          conversationID: conversationID,
          commandID: "command-turn-1",
          turnID: "turn-1",
          eventSeq: eventSeq
        )
      )
    )
    eventSeq += 1
    await source.emitConversation(
      .event(
        try SessionSourceTestValues.turnStarted(
          conversationID: conversationID,
          commandID: "command-turn-2",
          turnID: "turn-2",
          eventSeq: eventSeq
        )
      )
    )
    eventSeq += 1
    await waitForMainActorState { vm.approvalState == .none }

    let overflowApprovalID = "approval-33"
    await source.emitConversation(
      .event(
        try SessionSourceTestValues.actionRequest(
          conversationID: conversationID,
          commandID: "command-turn-2",
          turnID: "turn-2",
          approvalID: overflowApprovalID,
          requestID: "request-33",
          eventSeq: eventSeq
        )
      )
    )
    eventSeq += 1
    await waitForMainActorState { vm.approvalState == .pending }
    vm.resolveApproval(approve: true)
    await source.waitForApprovalCalls(33)

    for state in [
      ApprovalDeliveryStateV1.claimed,
      .applying,
    ] {
      await source.emitConversation(
        .event(
          try SessionSourceTestValues.approvalResolved(
            conversationID: conversationID,
            commandID: "command-turn-2",
            turnID: "turn-2",
            approvalID: overflowApprovalID,
            decision: .approve,
            state: state,
            eventSeq: eventSeq
          )
        )
      )
      eventSeq += 1
    }
    XCTAssertFalse(vm.isTerminal)
    XCTAssertEqual(vm.approvalResponseGeneration, 0)

    await source.emitConversation(
      .event(
        try SessionSourceTestValues.approvalResolved(
          conversationID: conversationID,
          commandID: "command-turn-2",
          turnID: "turn-2",
          approvalID: overflowApprovalID,
          decision: .approve,
          state: .applied,
          eventSeq: eventSeq
        )
      )
    )
    await waitForMainActorState { vm.isTerminal }

    XCTAssertEqual(vm.connectionState, .securityError)
    XCTAssertEqual(vm.errorText, "审批回执校验队列超过安全上限")
    XCTAssertEqual(vm.approvalState, .none)
    XCTAssertEqual(vm.approvalResponseGeneration, 0)
    let approvalCalls = await source.recordedApprovalCalls()
    XCTAssertEqual(approvalCalls.count, 33)

    for index in 1...33 {
      let approvalID = "approval-\(index)"
      await source.completeApproval(
        approvalID: approvalID,
        with: .claimed(RuntimeApprovalID(rawValue: approvalID))
      )
    }
    await waitForMainActorState { vm.approvalResponseGeneration == 33 }
    XCTAssertTrue(vm.isTerminal)
  }

  func testNewTurnAdvanceOnlyAcceptsTerminalAlreadyHandledDeliveryStates() async throws {
    let cases: [(ApprovalDeliveryStateV1, Bool)] = [
      (.claimed, false),
      (.applying, false),
      (.deliveryFailed, false),
      (.applied, true),
      (.expired, true),
    ]

    for (deliveryState, canAdvance) in cases {
      let source = SessionSourceSpy()
      await source.setApprovalBehavior(
        .immediate(
          .alreadyHandled(
            approvalID: RuntimeApprovalID(rawValue: "approval-1"),
            decision: .approve,
            state: deliveryState
          )
        )
      )
      let vm = try await makePendingApprovalViewModel(source: source)
      vm.resolveApproval(approve: true)
      await waitForMainActorState { vm.approvalResponseGeneration == 1 }
      XCTAssertEqual(
        vm.approvalState,
        .alreadyHandled(decision: .approve, deliveryState: deliveryState)
      )

      await source.emitConversation(.connectionState(.lagged(reason: .cursorGap)))
      await waitForMainActorState {
        vm.connectionState == .lagged(reason: .cursorGap)
      }
      await source.emitConversation(
        .snapshot(try SessionSourceTestValues.snapshot(conversationID: conversationID))
      )
      await waitForMainActorState { vm.connectionState == .connected }
      await source.emitConversation(
        .event(
          try SessionSourceTestValues.turnStarted(
            conversationID: conversationID,
            commandID: "command-turn-2",
            turnID: "turn-2",
            eventSeq: 0
          )
        )
      )

      if canAdvance {
        await waitForMainActorState { vm.approvalState == .none }
        XCTAssertFalse(vm.isTerminal)
        XCTAssertNil(vm.pendingApproval)
      } else {
        await waitForMainActorState { vm.isTerminal }
        XCTAssertEqual(vm.connectionState, .securityError)
        XCTAssertEqual(vm.approvalState, .none)
      }
    }
  }

  func testDeinitCancelsObservationWithoutWaitingForSuspendedPrompt() async {
    let source = SessionSourceSpy()
    await source.setCommandBehavior(.suspended)
    weak var releasedViewModel: SessionDetailViewModel?
    do {
      let vm = SessionDetailViewModel(source: source, conversationID: conversationID)
      releasedViewModel = vm
      vm.start()
      await source.waitForConversationSubscriptions(1)
      vm.sendPrompt("挂起的 prompt")
      await source.waitForPromptCalls(1)
    }

    await source.waitForConversationTerminations(1)
    XCTAssertNil(releasedViewModel)
    await source.completeCommand(
      with: .failed(RuntimeFailureV1(code: "test.cleanup", message: "cleanup"))
    )
  }

  private func makePendingApprovalViewModel(
    source: SessionSourceSpy
  ) async throws -> SessionDetailViewModel {
    let vm = SessionDetailViewModel(source: source, conversationID: conversationID)
    vm.start()
    await source.waitForConversationSubscriptions(1)
    await source.emitConversation(
      .snapshot(try SessionSourceTestValues.snapshot(conversationID: conversationID))
    )
    await source.emitConversation(
      .event(
        try SessionSourceTestValues.turnStarted(
          conversationID: conversationID,
          commandID: "command-turn-1",
          turnID: "turn-1",
          eventSeq: 0
        )
      )
    )
    await source.emitConversation(
      .event(
        try SessionSourceTestValues.actionRequest(
          conversationID: conversationID,
          commandID: "command-turn-1",
          turnID: "turn-1",
          approvalID: "approval-1",
          eventSeq: 1
        )
      )
    )
    await waitForMainActorState { vm.approvalState == .pending }
    XCTAssertEqual(vm.pendingApproval?.summary, "uv run alembic upgrade head")
    return vm
  }

  private func makeErrorEvent(
    commandID: String?,
    code: String,
    message: String,
    eventSeq: UInt64
  ) throws -> RuntimeEventV2 {
    try RuntimeEventV2(
      conversationID: RuntimeConversationID(rawValue: conversationID),
      eventID: RuntimeEventID(rawValue: "event-error-\(eventSeq)"),
      eventSeq: eventSeq,
      commandID: commandID.map(RuntimeCommandID.init(rawValue:)),
      itemID: nil,
      entityID: nil,
      body: .error(
        RuntimeFailureV1(
          code: code,
          message: message,
          diagnosticRef: nil
        )
      )
    )
  }
}
