import AgentDeckCore
import AppKit
import Foundation
import XCTest

@testable import AgentDeck

/// 端到端交互：真实 InputBarView → SessionModel → canonical Runtime v2 wire。
/// 模拟输入、点击与回车，并验证新会话严格走 daemon-issued conversation identity。
@MainActor
final class ComposerInteractionTests: XCTestCase {
  private func makeComposer() throws -> (
    bar: InputBarView,
    model: SessionModel,
    wire: ComposerRuntimeWire,
    tv: InputTextView
  ) {
    try makeComposer(gateFirstPrompt: false)
  }

  private func makeComposer(
    gateFirstPrompt: Bool,
    gatedBootstrapFailure: ComposerBootstrapFailure? = nil,
    draftCacheLimits: InputBarDraftCacheLimits = .production
  ) throws -> (
    bar: InputBarView,
    model: SessionModel,
    wire: ComposerRuntimeWire,
    tv: InputTextView
  ) {
    let wire = try ComposerRuntimeWire(
      conversationID: RuntimeConversationID(rawValue: "conversation-composer"),
      gateFirstPrompt: gateFirstPrompt,
      gatedBootstrapFailure: gatedBootstrapFailure
    )
    let model = SessionModel(runtimeWire: wire)
    model.cwd = URL(fileURLWithPath: "/tmp/agentdeck-composer")
    let bar = InputBarView(model: model, draftCacheLimits: draftCacheLimits)
    bar.frame = NSRect(x: 0, y: 0, width: 860, height: 120)
    bar.layoutSubtreeIfNeeded()
    guard let tv = bar.firstDescendant(ofType: InputTextView.self) else {
      fatalError("composer 内应有 InputTextView")
    }
    return (bar, model, wire, tv)
  }

  private func type(_ text: String, into tv: InputTextView) {
    tv.string = text
    tv.didChangeText()
  }

  func testSendDisabledWhenEmpty() throws {
    let c = try makeComposer()
    defer { c.model.teardown() }

    type("", into: c.tv)
    let send = c.bar.button(id: "composer-send")
    XCTAssertNotNil(send, "发送按钮应可通过 a11y id 定位")
    XCTAssertFalse(send!.isEnabled, "空输入时发送按钮应禁用")
  }

  func testTypingEnablesSend() throws {
    let c = try makeComposer()
    defer { c.model.teardown() }

    type("hello", into: c.tv)
    XCTAssertTrue(c.bar.button(id: "composer-send")!.isEnabled, "有文本时发送按钮应启用")
  }

  func testClickSendUsesCanonicalRuntimeSequenceAndClears() async throws {
    let c = try makeComposer()
    defer { c.model.teardown() }

    type("拆分登录模块", into: c.tv)
    c.bar.button(id: "composer-send")!.performClick(nil)

    XCTAssertEqual(c.tv.string, "", "发送后应立即清空输入框")
    try await c.wire.waitForPrompt("拆分登录模块")
    await assertCanonicalSequence(c.wire, prompt: "拆分登录模块")
    XCTAssertEqual(
      c.model.workbench.selectedConversationID,
      RuntimeConversationID(rawValue: "conversation-composer")
    )
  }

  func testEnterKeyUsesCanonicalRuntimeSequence() async throws {
    let c = try makeComposer()
    defer { c.model.teardown() }

    type("回车发送", into: c.tv)
    c.tv.doCommand(by: #selector(NSResponder.insertNewline(_:)))

    try await c.wire.waitForPrompt("回车发送")
    await assertCanonicalSequence(c.wire, prompt: "回车发送")
  }

  func testComposerPreservesLeadingAndTrailingWhitespaceBytes() async throws {
    let c = try makeComposer()
    defer { c.model.teardown() }
    let prompt = "  byte exact prompt  \n"

    type(prompt, into: c.tv)
    c.bar.button(id: "composer-send")!.performClick(nil)

    try await c.wire.waitForPrompt(prompt)
    await assertCanonicalSequence(c.wire, prompt: prompt)
  }

  func testWhitespaceOnlyDoesNotSubmit() async throws {
    let c = try makeComposer()
    defer { c.model.teardown() }

    type("   ", into: c.tv)
    c.bar.button(id: "composer-send")?.performClick(nil)
    await Task.yield()

    let operations = await c.wire.recordedOperations()
    XCTAssertEqual(operations, [])
    XCTAssertNil(c.model.workbench.selectedConversationID)
  }

  func testAdmissionInFlightKeepsLaterComposerDraft() async throws {
    let c = try makeComposer(gateFirstPrompt: true)
    defer { c.model.teardown() }

    type("first prompt", into: c.tv)
    c.bar.button(id: "composer-send")!.performClick(nil)
    try await c.wire.waitForPrompt("first prompt")
    XCTAssertEqual(c.tv.string, "")

    type("later draft", into: c.tv)
    c.bar.refreshPromptStatus()
    XCTAssertFalse(c.bar.button(id: "composer-send")!.isEnabled)
    c.tv.doCommand(by: #selector(NSResponder.insertNewline(_:)))

    XCTAssertEqual(
      c.tv.string,
      "later draft",
      "已有 daemon admission 时，拒绝的新提交不得清空用户正在编辑的文本"
    )
    await c.wire.releaseGatedPromptSuccess()
    await Task.yield()
    let promptOperations = await c.wire.recordedOperations().filter {
      if case .sendPrompt = $0 { return true }
      return false
    }
    XCTAssertEqual(promptOperations.count, 1, "被拒绝的 Enter 不得进入后台队列后重复发送")
  }

  func testFailedAdmissionRestoresExactRetryDraft() async throws {
    let c = try makeComposer(gateFirstPrompt: true)
    defer { c.model.teardown() }

    type("retry exact prompt", into: c.tv)
    c.bar.button(id: "composer-send")!.performClick(nil)
    try await c.wire.waitForPrompt("retry exact prompt")
    XCTAssertEqual(c.tv.string, "")

    await c.wire.releaseGatedPromptFailure()
    try await waitUntil { c.model.retryRequiredPrompt == "retry exact prompt" }
    c.bar.refreshPromptStatus()

    XCTAssertEqual(
      c.tv.string,
      "retry exact prompt",
      "admission 失败后必须把 exact draft 恢复到空 composer，供用户显式重试"
    )
    XCTAssertTrue(c.bar.button(id: "composer-send")!.isEnabled)
    XCTAssertEqual(
      InputBarView.promptStatusText(
        sendingCount: c.model.sendingPrompts.count,
        queuedCount: c.model.queuedPrompts.count,
        retryRequired: c.model.retryRequiredPrompt != nil
      ),
      "retry required"
    )
  }

  func testFailedAdmissionNeverOverwritesNewComposerDraft() async throws {
    let c = try makeComposer(gateFirstPrompt: true)
    defer { c.model.teardown() }

    type("failed prompt", into: c.tv)
    c.bar.button(id: "composer-send")!.performClick(nil)
    try await c.wire.waitForPrompt("failed prompt")
    type("new user draft", into: c.tv)

    await c.wire.releaseGatedPromptFailure()
    try await waitUntil { c.model.retryRequiredPrompt == "failed prompt" }
    c.bar.refreshPromptStatus()

    XCTAssertEqual(
      c.tv.string,
      "new user draft",
      "失败 prompt 的 retry 恢复不得覆盖用户已开始编辑的新意图"
    )
    XCTAssertTrue(c.bar.button(id: "composer-send")!.isEnabled)
  }

  func testDefinitiveStartFailureKeepsLogicalBootstrapOwnerAndLaterDraft() async throws {
    let c = try makeComposer(
      gateFirstPrompt: false,
      gatedBootstrapFailure: .startDefinitive
    )
    defer { c.model.teardown() }

    type("original bootstrap prompt", into: c.tv)
    c.bar.button(id: "composer-send")!.performClick(nil)
    try await c.wire.waitForBootstrapFailureGate()
    let originalOwner = c.model.promptComposerOwner
    type("later unsent draft", into: c.tv)

    await c.wire.releaseBootstrapFailure()
    try await waitUntil { c.model.retryableConversationDraft != nil }
    c.bar.refreshPromptStatus()

    XCTAssertEqual(
      c.model.promptComposerOwner,
      originalOwner,
      "同一 bootstrap 的 definitive retry 即使换实际 Start key，也必须保留 logical owner"
    )
    XCTAssertEqual(
      c.tv.string,
      "later unsent draft",
      "Start failure 不得把用户在途新草稿藏进永不再激活的旧 key cache"
    )
  }

  func testPromptRecoveryFailureTightensPriorFreshRetryPolicyToExact() async throws {
    let c = try makeComposer(
      gateFirstPrompt: true,
      gatedBootstrapFailure: .startDefinitive
    )
    defer { c.model.teardown() }

    type("first rejected prompt", into: c.tv)
    c.bar.button(id: "composer-send")!.performClick(nil)
    try await c.wire.waitForBootstrapFailureGate()
    await c.wire.releaseBootstrapFailure()
    try await waitUntil { c.model.retryableConversationDraft != nil }
    c.bar.refreshPromptStatus()

    type("replacement prompt reaches daemon", into: c.tv)
    c.bar.button(id: "composer-send")!.performClick(nil)
    try await c.wire.waitForPrompt("replacement prompt reaches daemon")
    c.model.workbench.cancelConversationStart()
    await c.wire.releaseGatedPromptFailure()
    try await waitUntil {
      c.model.retryableConversationDraft?.prompt?.rawValue
        == "replacement prompt reaches daemon"
    }

    let conflictingIntent = try composerDraft(
      prompt: "a different post-failure intent",
      keySuffix: "must-not-replace-uncertain-prompt"
    )
    XCTAssertFalse(
      c.model.startConversation(conflictingIntent),
      "Prompt 已可能到达 daemon 后，即使旧策略允许 fresh，也必须收紧为 exact retry"
    )
  }

  func testExactBootstrapRetryDoesNotImmediatelyRefillSubmittedPrompt() async throws {
    let c = try makeComposer(
      gateFirstPrompt: false,
      gatedBootstrapFailure: .startTransport
    )
    defer { c.model.teardown() }

    type("exact bootstrap retry", into: c.tv)
    c.bar.button(id: "composer-send")!.performClick(nil)
    try await c.wire.waitForBootstrapFailureGate()
    await c.wire.releaseBootstrapFailure()
    try await waitUntil { c.model.retryableConversationDraft != nil }
    c.bar.refreshPromptStatus()
    XCTAssertEqual(c.tv.string, "exact bootstrap retry")

    c.bar.button(id: "composer-send")!.performClick(nil)

    XCTAssertEqual(
      c.tv.string,
      "",
      "已经重新提交的 exact prompt 在 bootstrap pending 期间不得被旧 retry state 立即回填"
    )
    try await c.wire.waitForStartRequestCount(2)
    let keys = await c.wire.recordedBootstrapKeys()
    XCTAssertEqual(keys.start.count, 2)
    XCTAssertEqual(keys.start[0], keys.start[1])
  }

  func testExactBootstrapRetryStaysDiscoverableBesideLaterDraft() async throws {
    let c = try makeComposer(
      gateFirstPrompt: false,
      gatedBootstrapFailure: .startTransport
    )
    defer { c.model.teardown() }

    type("exact bootstrap prompt", into: c.tv)
    c.bar.button(id: "composer-send")!.performClick(nil)
    try await c.wire.waitForBootstrapFailureGate()
    type("later draft must remain", into: c.tv)

    await c.wire.releaseBootstrapFailure()
    try await waitUntil { c.model.retryableConversationDraft != nil }
    c.bar.refreshPromptStatus()

    XCTAssertEqual(c.tv.string, "later draft must remain")
    let retry = try XCTUnwrap(c.bar.button(id: "composer-retry-start"))
    XCTAssertFalse(retry.isHidden, "later draft 不得遮蔽 exact bootstrap retry 入口")
    XCTAssertTrue(retry.isEnabled)
    XCTAssertFalse(
      c.bar.button(id: "composer-send")!.isEnabled,
      "不同文本不是合法 exact retry，必须先处理明确的 retry 入口"
    )

    retry.performClick(nil)
    XCTAssertEqual(c.tv.string, "later draft must remain")
    try await c.wire.waitForStartRequestCount(2)
    let keys = await c.wire.recordedBootstrapKeys()
    XCTAssertEqual(keys.start.count, 2)
    XCTAssertEqual(keys.start[0], keys.start[1])
    try await waitUntil {
      c.model.workbench.selectedConversationID
        == RuntimeConversationID(rawValue: "conversation-composer")
    }
    c.bar.refreshPromptStatus()
    XCTAssertEqual(c.tv.string, "later draft must remain")
    XCTAssertTrue(c.bar.button(id: "composer-send")!.isEnabled)
  }

  func testEditedConfigureRetryDoesNotRefillOriginalPrompt() async throws {
    let c = try makeComposer(
      gateFirstPrompt: false,
      gatedBootstrapFailure: .configureDefinitive
    )
    defer { c.model.teardown() }

    type("original configure prompt", into: c.tv)
    c.bar.button(id: "composer-send")!.performClick(nil)
    try await c.wire.waitForBootstrapFailureGate()
    await c.wire.releaseBootstrapFailure()
    try await waitUntil { c.model.retryableConversationDraft != nil }
    c.bar.refreshPromptStatus()

    type("edited configure retry", into: c.tv)
    c.bar.button(id: "composer-send")!.performClick(nil)

    XCTAssertEqual(
      c.tv.string,
      "",
      "Configure retry 已提交编辑后的 prompt 时，不得重新填入旧 prompt"
    )
    try await c.wire.waitForPrompt("edited configure retry")
  }

  func testPromptlessOutcomeUnknownHasDiscoverableExactRetryForStartAndConfigure()
    async throws
  {
    for failure in [ComposerBootstrapFailure.startTransport, .configureTransport] {
      let c = try makeComposer(
        gateFirstPrompt: false,
        gatedBootstrapFailure: failure
      )
      let draft = try composerDraft(
        prompt: nil,
        keySuffix: "promptless-\(failure.rawValue)"
      )
      XCTAssertTrue(c.model.startConversation(draft))
      c.bar.refreshPromptStatus()
      try await c.wire.waitForBootstrapFailureGate()

      type("later draft must survive", into: c.tv)
      c.bar.refreshPromptStatus()
      XCTAssertFalse(c.bar.button(id: "composer-send")!.isEnabled)
      XCTAssertEqual(
        InputBarView.promptStatusText(
          sendingCount: c.model.sendingPrompts.count,
          queuedCount: c.model.queuedPrompts.count,
          retryRequired: false,
          bootstrapInFlight: true
        ),
        "starting conversation"
      )

      await c.wire.releaseBootstrapFailure()
      try await waitUntil { c.model.canRetryPromptlessConversationStart }
      c.bar.refreshPromptStatus()
      let retry = try XCTUnwrap(c.bar.button(id: "composer-retry-start"))
      XCTAssertFalse(retry.isHidden)
      XCTAssertTrue(retry.isEnabled)
      XCTAssertFalse(
        c.bar.button(id: "composer-send")!.isEnabled,
        "promptless exact retry 未处理前，普通 composer submit 不是合法入口"
      )

      retry.performClick(nil)
      XCTAssertEqual(c.tv.string, "later draft must survive")
      try await c.wire.waitForStartRequestCount(2)
      try await waitUntil {
        c.model.workbench.selectedConversationID
          == RuntimeConversationID(rawValue: "conversation-composer")
      }
      c.bar.refreshPromptStatus()
      XCTAssertEqual(c.tv.string, "later draft must survive")

      let keys = await c.wire.recordedBootstrapKeys()
      XCTAssertEqual(keys.start, [draft.idempotencyKeys.start, draft.idempotencyKeys.start])
      if failure == .configureTransport {
        XCTAssertEqual(
          keys.configure,
          [draft.idempotencyKeys.configure, draft.idempotencyKeys.configure]
        )
      }
      c.model.teardown()
    }
  }

  func testDialogNewIntentGetsIsolatedBootstrapOwner() async throws {
    let c = try makeComposer(
      gateFirstPrompt: false,
      gatedBootstrapFailure: .startDefinitive
    )
    defer { c.model.teardown() }

    type("old bootstrap", into: c.tv)
    c.bar.button(id: "composer-send")!.performClick(nil)
    try await c.wire.waitForBootstrapFailureGate()
    await c.wire.releaseBootstrapFailure()
    try await waitUntil { c.model.retryableConversationDraft != nil }
    c.bar.refreshPromptStatus()
    type("old composer draft", into: c.tv)
    let oldOwner = c.model.promptComposerOwner

    let dialogDraft = try composerDraft(
      prompt: "new dialog intent",
      keySuffix: "dialog-new-intent"
    )
    XCTAssertTrue(c.model.startConversation(dialogDraft))
    let dialogOwner = c.model.promptComposerOwner
    c.bar.refreshPromptStatus()

    XCTAssertNotEqual(dialogOwner, oldOwner)
    XCTAssertEqual(
      c.tv.string,
      "",
      "显式 Dialog 新意图不得继承旧 bootstrap composer 的未提交草稿"
    )
  }

  func testConversationComposerDraftsRoundTripAcrossAtoBtoA() throws {
    let c = try makeComposer()
    defer { c.model.teardown() }
    let ids = try installComposerCatalog(count: 2, in: c.model)

    try c.model.workbench.selectConversation(ids[0])
    c.bar.refreshPromptStatus()
    type("draft-a", into: c.tv)
    try c.model.workbench.selectConversation(ids[1])
    c.bar.refreshPromptStatus()
    XCTAssertEqual(c.tv.string, "")
    type("draft-b", into: c.tv)

    try c.model.workbench.selectConversation(ids[0])
    c.bar.refreshPromptStatus()
    XCTAssertEqual(c.tv.string, "draft-a")
    try c.model.workbench.selectConversation(ids[1])
    c.bar.refreshPromptStatus()
    XCTAssertEqual(c.tv.string, "draft-b")
  }

  func testComposerDraftCacheEnforcesProductionOwnerLRU() throws {
    XCTAssertEqual(InputBarDraftCacheLimits.production.maximumOwners, 32)
    let c = try makeComposer()
    defer { c.model.teardown() }
    let ids = try installComposerCatalog(count: 34, in: c.model)

    for (index, id) in ids.enumerated() {
      try c.model.workbench.selectConversation(id)
      c.bar.refreshPromptStatus()
      type("draft-\(index)", into: c.tv)
    }
    try c.model.workbench.selectConversation(ids[0])
    c.bar.refreshPromptStatus()
    XCTAssertEqual(c.tv.string, "", "第 33 个 inactive owner 必须淘汰最旧 draft")
    try c.model.workbench.selectConversation(ids[32])
    c.bar.refreshPromptStatus()
    XCTAssertEqual(c.tv.string, "draft-32", "近期 owner 必须按 LRU 保留")
  }

  func testComposerDraftCacheEnforcesPerDraftAndTotalByteLimits() throws {
    let limits = InputBarDraftCacheLimits(
      maximumOwners: 32,
      maximumDraftBytes: 8,
      maximumTotalDraftBytes: 10
    )
    let c = try makeComposer(
      gateFirstPrompt: false,
      draftCacheLimits: limits
    )
    defer { c.model.teardown() }
    let ids = try installComposerCatalog(count: 4, in: c.model)

    try c.model.workbench.selectConversation(ids[0])
    c.bar.refreshPromptStatus()
    type("aaaaaa", into: c.tv)
    try c.model.workbench.selectConversation(ids[1])
    c.bar.refreshPromptStatus()
    type("bbbbbb", into: c.tv)
    try c.model.workbench.selectConversation(ids[2])
    c.bar.refreshPromptStatus()
    try c.model.workbench.selectConversation(ids[0])
    c.bar.refreshPromptStatus()
    XCTAssertEqual(c.tv.string, "", "总 byte 超限必须淘汰最旧 draft")
    try c.model.workbench.selectConversation(ids[1])
    c.bar.refreshPromptStatus()
    XCTAssertEqual(c.tv.string, "bbbbbb")

    type("123456789", into: c.tv)
    try c.model.workbench.selectConversation(ids[3])
    c.bar.refreshPromptStatus()
    try c.model.workbench.selectConversation(ids[1])
    c.bar.refreshPromptStatus()
    XCTAssertEqual(c.tv.string, "", "单 draft byte 超限不得进入缓存")
  }

  private func assertCanonicalSequence(
    _ wire: ComposerRuntimeWire,
    prompt: String
  ) async {
    let conversationID = RuntimeConversationID(rawValue: "conversation-composer")
    let operations = await wire.recordedOperations()
    XCTAssertEqual(
      operations,
      [
        .describeAgents,
        .start(agentKind: .codex, cwd: "/tmp/agentdeck-composer"),
        .configure(conversationID: conversationID, expectedRevision: 0),
        .subscribe(conversationID: conversationID, cursor: .beforeFirst),
        .sendPrompt(
          conversationID: conversationID,
          expectedRevision: 1,
          prompt: prompt
        ),
      ]
    )
  }

  private func waitUntil(
    _ predicate: @MainActor () -> Bool
  ) async throws {
    for _ in 0..<400 {
      if predicate() { return }
      try await Task.sleep(for: .milliseconds(5))
    }
    throw ComposerRuntimeWireError.timeout
  }

  private func installComposerCatalog(
    count: Int,
    in model: SessionModel
  ) throws -> [RuntimeConversationID] {
    let entries = (0..<count).map { index in
      composerCatalogEntry("composer-owner-\(index)")
    }
    try model.workbench.installCatalog(
      snapshotPages: [
        try RuntimeCatalogSnapshotV2(
          baseCatalogCursor: .beforeFirst,
          entries: entries,
          nextPageCursor: nil
        )
      ]
    )
    return entries.map(\.conversationID)
  }
}

private enum ComposerRuntimeOperation: Equatable, Sendable {
  case describeAgents
  case start(agentKind: AgentKind, cwd: String)
  case configure(conversationID: RuntimeConversationID, expectedRevision: UInt64)
  case subscribe(conversationID: RuntimeConversationID, cursor: RuntimeStreamCursorV1)
  case sendPrompt(
    conversationID: RuntimeConversationID,
    expectedRevision: UInt64,
    prompt: String
  )
}

private enum ComposerRuntimeWireError: Error {
  case closed
  case timeout
  case unexpectedRequest
}

private enum ComposerBootstrapFailure: String, Equatable, Sendable {
  case startDefinitive
  case startTransport
  case configureDefinitive
  case configureTransport

  var gatesStart: Bool {
    self == .startDefinitive || self == .startTransport
  }
}

private struct ComposerBootstrapKeyCapture: Sendable {
  let start: [RuntimeIdempotencyKey]
  let configure: [RuntimeIdempotencyKey]
}

private actor ComposerRuntimeWire: AppRuntimeWireSession {
  private let conversationID: RuntimeConversationID
  private let descriptions: RuntimeAgentDescriptionsV2
  private let snapshot: ConversationSnapshotV2
  private let terminal: RuntimeSyncCompleteV1
  private var operations: [ComposerRuntimeOperation] = []
  private var startIdempotencyKeys: [RuntimeIdempotencyKey] = []
  private var configureIdempotencyKeys: [RuntimeIdempotencyKey] = []
  private var streamContinuation: CheckedContinuation<LocalRuntimeStreamFrame, Error>?
  private var shouldGateNextPrompt: Bool
  private let gatedBootstrapFailure: ComposerBootstrapFailure?
  private var didConsumeBootstrapFailure = false
  private var bootstrapFailureGateReached = false
  private var bootstrapFailureGateContinuation: CheckedContinuation<Void, Never>?
  private var promptContinuation: CheckedContinuation<RuntimeReplyV2, Error>?
  private var isClosed = false

  init(
    conversationID: RuntimeConversationID,
    gateFirstPrompt: Bool,
    gatedBootstrapFailure: ComposerBootstrapFailure? = nil
  ) throws {
    self.conversationID = conversationID
    shouldGateNextPrompt = gateFirstPrompt
    self.gatedBootstrapFailure = gatedBootstrapFailure
    let capabilities = try composerCodexCapabilities()
    let configuration = composerCodexConfiguration()
    descriptions = try RuntimeAgentDescriptionsV2(
      agents: [
        try RuntimeAgentDescriptionV2(
          agentKind: .codex,
          capabilities: capabilities,
          defaultConfiguration: configuration
        )
      ]
    )
    snapshot = try ConversationSnapshotV2(
      conversationID: conversationID,
      baseEventCursor: .beforeFirst,
      configurationState: try RuntimeConversationConfigurationStateV2(
        configurationRevision: 1,
        configuration: configuration
      ),
      items: [.capabilities(capabilities)]
    )
    terminal = try composerSyncComplete(conversationID: conversationID)
  }

  func start() async throws {}

  func request(_ request: RuntimeRequestV2) async throws -> RuntimeReplyV2 {
    switch request {
    case .describeAgents:
      operations.append(.describeAgents)
      return .agents(descriptions)
    case .start(let agentKind, let idempotencyKey, let cwd, _):
      operations.append(.start(agentKind: agentKind, cwd: cwd))
      startIdempotencyKeys.append(idempotencyKey)
      if let failure = claimBootstrapFailure(forStart: true) {
        await waitAtBootstrapFailureGate()
        switch failure {
        case .startDefinitive:
          return .failure(
            RuntimeFailureV1(
              code: "daemon.runtime.invalid_request",
              message: "Start rejected before commit"
            )
          )
        case .startTransport:
          throw RuntimeEnvelopeClientFailure(
            code: "test.start.transport",
            message: "Start outcome unknown"
          )
        case .configureDefinitive, .configureTransport:
          preconditionFailure("configure failure claimed by Start")
        }
      }
      return .conversationStart(
        ConversationStartReceiptV2(
          conversationID: conversationID,
          replayed: startIdempotencyKeys.count > 1
        )
      )
    case .configureConversation(let configuration):
      configureIdempotencyKeys.append(configuration.idempotencyKey)
      operations.append(
        .configure(
          conversationID: configuration.conversationID,
          expectedRevision: configuration.expectedConfigurationRevision
        )
      )
      if let failure = claimBootstrapFailure(forStart: false) {
        await waitAtBootstrapFailureGate()
        switch failure {
        case .configureDefinitive:
          return .failure(
            RuntimeFailureV1(
              code: "daemon.conversation.configuration_conflict",
              message: "Configure rejected before commit"
            )
          )
        case .configureTransport:
          throw RuntimeEnvelopeClientFailure(
            code: "test.configure.transport",
            message: "Configure outcome unknown"
          )
        case .startDefinitive, .startTransport:
          preconditionFailure("Start failure claimed by Configure")
        }
      }
      return .configuration(
        configureIdempotencyKeys.count > 1
          ? .replayed(conversationID: conversationID, configurationRevision: 1)
          : .applied(conversationID: conversationID, configurationRevision: 1)
      )
    case .sendPrompt(let requestID, _, let revision, let prompt):
      operations.append(
        .sendPrompt(
          conversationID: requestID,
          expectedRevision: revision,
          prompt: prompt.rawValue
        )
      )
      let reply = Self.acceptedPromptReply(configurationRevision: revision)
      if shouldGateNextPrompt {
        shouldGateNextPrompt = false
        return try await withCheckedThrowingContinuation { continuation in
          precondition(promptContinuation == nil)
          promptContinuation = continuation
        }
      }
      return reply
    default:
      throw ComposerRuntimeWireError.unexpectedRequest
    }
  }

  func beginAppSynchronizedRequest(
    _ request: RuntimeRequestV2
  ) async throws -> any AppRuntimeWireReplySequence {
    guard case .subscribe(let innerCursor) = request,
      case .conversation(let requestID, let cursor) = innerCursor
    else {
      throw ComposerRuntimeWireError.unexpectedRequest
    }
    operations.append(.subscribe(conversationID: requestID, cursor: cursor))
    return ComposerRuntimeReplySequence(
      replies: [
        .subscription(
          .subscribed(streamGeneration: RuntimeStreamGeneration(rawValue: "generation-composer"))
        ),
        .snapshot(snapshot),
        .syncComplete(terminal),
      ]
    )
  }

  func nextStream() async throws -> LocalRuntimeStreamFrame {
    guard !isClosed else { throw ComposerRuntimeWireError.closed }
    return try await withCheckedThrowingContinuation { continuation in
      precondition(streamContinuation == nil)
      streamContinuation = continuation
    }
  }

  func close() async {
    guard !isClosed else { return }
    isClosed = true
    promptContinuation?.resume(throwing: ComposerRuntimeWireError.closed)
    promptContinuation = nil
    bootstrapFailureGateContinuation?.resume()
    bootstrapFailureGateContinuation = nil
    streamContinuation?.resume(throwing: ComposerRuntimeWireError.closed)
    streamContinuation = nil
  }

  func recordedOperations() -> [ComposerRuntimeOperation] {
    operations
  }

  func recordedBootstrapKeys() -> ComposerBootstrapKeyCapture {
    ComposerBootstrapKeyCapture(
      start: startIdempotencyKeys,
      configure: configureIdempotencyKeys
    )
  }

  func waitForBootstrapFailureGate() async throws {
    for _ in 0..<400 {
      if bootstrapFailureGateReached { return }
      try await Task.sleep(for: .milliseconds(5))
    }
    throw ComposerRuntimeWireError.timeout
  }

  func waitForStartRequestCount(_ expected: Int) async throws {
    for _ in 0..<400 {
      if startIdempotencyKeys.count >= expected { return }
      try await Task.sleep(for: .milliseconds(5))
    }
    throw ComposerRuntimeWireError.timeout
  }

  func releaseBootstrapFailure() {
    bootstrapFailureGateContinuation?.resume()
    bootstrapFailureGateContinuation = nil
  }

  func waitForPrompt(_ prompt: String) async throws {
    for _ in 0..<400 {
      if operations.contains(where: { operation in
        guard case .sendPrompt(_, _, let value) = operation else { return false }
        return value == prompt
      }) {
        return
      }
      try await Task.sleep(for: .milliseconds(5))
    }
    throw ComposerRuntimeWireError.timeout
  }

  func releaseGatedPromptSuccess() {
    promptContinuation?.resume(
      returning: Self.acceptedPromptReply(configurationRevision: 1)
    )
    promptContinuation = nil
  }

  func releaseGatedPromptFailure() {
    promptContinuation?.resume(throwing: ComposerRuntimeWireError.closed)
    promptContinuation = nil
  }

  private static func acceptedPromptReply(
    configurationRevision: UInt64
  ) -> RuntimeReplyV2 {
    .command(
      .accepted(
        commandID: RuntimeCommandID(rawValue: "command-composer"),
        queuePosition: 0,
        configurationRevision: configurationRevision
      )
    )
  }

  private func claimBootstrapFailure(
    forStart: Bool
  ) -> ComposerBootstrapFailure? {
    guard !didConsumeBootstrapFailure, let gatedBootstrapFailure,
      gatedBootstrapFailure.gatesStart == forStart
    else {
      return nil
    }
    didConsumeBootstrapFailure = true
    bootstrapFailureGateReached = true
    return gatedBootstrapFailure
  }

  private func waitAtBootstrapFailureGate() async {
    await withCheckedContinuation { continuation in
      bootstrapFailureGateContinuation = continuation
    }
  }
}

private actor ComposerRuntimeReplySequence: AppRuntimeWireReplySequence {
  private var replies: [RuntimeReplyV2]

  init(replies: [RuntimeReplyV2]) {
    self.replies = replies
  }

  func next() async throws -> RuntimeReplyV2? {
    guard !replies.isEmpty else { return nil }
    return replies.removeFirst()
  }

  func cancel() async {}
}

private func composerCodexCapabilities() throws -> RuntimeSessionCapabilitiesV1 {
  try JSONDecoder().decode(
    RuntimeSessionCapabilitiesV1.self,
    from: Data(
      #"{"agentKind":"codex","agentVersion":"fixture","features":[],"vendor":{"agentKind":"codex","sandboxModes":[],"persistenceSupported":false,"reasoningEffortLevels":[]}}"#
        .utf8
    )
  )
}

private func composerCodexConfiguration() -> RuntimeConversationConfigurationV2 {
  RuntimeConversationConfigurationV2(
    vendorControl: .codex(
      RuntimeCodexConversationConfigurationV2(
        approvalPolicy: .onRequest,
        sandbox: .workspaceWrite,
        reasoningEffort: .medium
      )
    )
  )
}

private func composerDraft(
  prompt: String?,
  keySuffix: String
) throws -> RuntimeConversationDraft {
  try RuntimeConversationDraft(
    agentKind: .codex,
    cwd: "/tmp/agentdeck-composer",
    prompt: prompt,
    vendorOptions: .codex(
      CodexSessionOptions(
        approvalPolicy: .onRequest,
        sandbox: .workspaceWrite,
        persistApproval: false,
        reasoningEffort: .medium
      )
    ),
    idempotencyKeys: RuntimeConversationIdempotencyKeys(
      start: RuntimeIdempotencyKey(rawValue: "start:\(keySuffix)"),
      configure: RuntimeIdempotencyKey(rawValue: "configure:\(keySuffix)"),
      prompt: RuntimeIdempotencyKey(rawValue: "prompt:\(keySuffix)")
    )
  )
}

private func composerCatalogEntry(
  _ rawID: String
) -> RuntimeConversationEntryV2 {
  RuntimeConversationEntryV2(
    conversationID: RuntimeConversationID(rawValue: rawID),
    agentKind: .codex,
    title: rawID,
    cwd: "/tmp/agentdeck-composer",
    lastActiveMs: 1_000,
    archived: false,
    entryRevision: 1
  )
}

private func composerSyncComplete(
  conversationID: RuntimeConversationID
) throws -> RuntimeSyncCompleteV1 {
  let object: [String: Any] = [
    "streamGeneration": "generation-composer",
    "streamCursor": "beforeFirst",
    "innerCursor": [
      "scope": "conversation",
      "conversationId": conversationID.rawValue,
      "cursor": "beforeFirst",
    ],
    "keyDirectoryRevision": 0,
  ]
  return try JSONDecoder().decode(
    RuntimeSyncCompleteV1.self,
    from: JSONSerialization.data(withJSONObject: object)
  )
}
