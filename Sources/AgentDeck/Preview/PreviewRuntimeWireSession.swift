import AgentDeckCore
import Foundation

/// Preview-only Runtime v2 fixture wire。Synthetic identity 只存在于显式 `--preview`
/// composition；production SessionModel 不引用本类型，也没有 legacy stdio fallback。
actor PreviewRuntimeWireSession: AppRuntimeWireSession {
  private static let generation = RuntimeStreamGeneration(rawValue: "preview-generation")

  private var closed = false
  private var streamFrames: [LocalRuntimeStreamFrame] = []
  private var streamWaiter: CheckedContinuation<LocalRuntimeStreamFrame, Error>?
  private var nextEventSequence: [RuntimeConversationID: UInt64] = [:]

  func start() async throws {}

  func request(_ request: RuntimeRequestV2) async throws -> RuntimeReplyV2 {
    switch request {
    case .describeAgents:
      return .agents(try Self.agentDescriptions())
    case .catalog:
      return .catalog(try Self.catalogSnapshot())
    case .start:
      let id = RuntimeConversationID(rawValue: "preview-new-\(UUID().uuidString.lowercased())")
      return .conversationStart(ConversationStartReceiptV2(conversationID: id, replayed: false))
    case .configureConversation(let configuration):
      return .configuration(
        .applied(
          conversationID: configuration.conversationID,
          configurationRevision: configuration.expectedConfigurationRevision + 1
        )
      )
    case .sendPrompt(let conversationID, _, let revision, let prompt):
      let commandID = RuntimeCommandID(
        rawValue: "preview-command-\(UUID().uuidString.lowercased())"
      )
      try enqueuePromptTurn(
        conversationID: conversationID,
        commandID: commandID,
        prompt: prompt
      )
      return .command(
        .accepted(
          commandID: commandID,
          queuePosition: 0,
          configurationRevision: revision
        )
      )
    case .resolveApproval(_, _, let approvalID, _):
      return .approval(.applied(approvalID))
    case .updateConversationMetadata(let mutation):
      return .conversationMetadata(
        .applied(
          conversationID: mutation.conversationID,
          entryRevision: mutation.expectedEntryRevision + 1
        )
      )
    default:
      throw RuntimeEnvelopeClientFailure(
        code: "preview.request.unsupported",
        message: "preview fixture does not implement this Runtime request"
      )
    }
  }

  func beginAppSynchronizedRequest(
    _ request: RuntimeRequestV2
  ) async throws -> any AppRuntimeWireReplySequence {
    let replies: [RuntimeReplyV2]
    switch request {
    case .subscribe(let innerCursor):
      switch innerCursor {
      case .catalog(let cursor):
        replies = [
          .subscription(.subscribed(streamGeneration: Self.generation)),
          .syncComplete(try Self.syncComplete(innerCursor: .catalog(cursor: cursor))),
        ]
      case .conversation(let conversationID, _):
        let snapshot = try Self.conversationSnapshot(conversationID: conversationID)
        if nextEventSequence[conversationID] == nil {
          nextEventSequence[conversationID] = 0
        }
        replies = [
          .subscription(.subscribed(streamGeneration: Self.generation)),
          .snapshot(snapshot),
          .syncComplete(
            try Self.syncComplete(
              innerCursor: .conversation(
                conversationID: conversationID,
                cursor: snapshot.baseEventCursor
              )
            )
          ),
        ]
      }
    case .backfill(let target):
      switch target {
      case .catalog(let cursor):
        replies = [.syncComplete(try Self.syncComplete(innerCursor: .catalog(cursor: cursor)))]
      case .conversation(let conversationID, let cursor):
        replies = [
          .syncComplete(
            try Self.syncComplete(
              innerCursor: .conversation(conversationID: conversationID, cursor: cursor)
            )
          )
        ]
      }
    default:
      throw RuntimeEnvelopeClientFailure(
        code: "preview.sequence.unsupported",
        message: "preview fixture only sequences Subscribe/Backfill"
      )
    }
    return PreviewRuntimeReplySequence(replies: replies)
  }

  func nextStream() async throws -> LocalRuntimeStreamFrame {
    guard !closed else { throw Self.closedFailure() }
    if !streamFrames.isEmpty { return streamFrames.removeFirst() }
    return try await withCheckedThrowingContinuation { continuation in
      precondition(streamWaiter == nil)
      streamWaiter = continuation
    }
  }

  func close() async {
    guard !closed else { return }
    closed = true
    streamFrames.removeAll()
    streamWaiter?.resume(throwing: Self.closedFailure())
    streamWaiter = nil
  }

  private func enqueuePromptTurn(
    conversationID: RuntimeConversationID,
    commandID: RuntimeCommandID,
    prompt: RuntimePromptPayloadV1
  ) throws {
    let turnID = RuntimeTurnID(rawValue: "preview-turn-\(UUID().uuidString.lowercased())")
    var sequence = nextEventSequence[conversationID] ?? 0

    let bodies:
      [(
        itemID: RuntimeItemID?,
        entityID: RuntimeEntityID?,
        body: RuntimeEventBodyV2
      )] = [
        (nil, nil, .turnStarted(turnID: turnID)),
        (
          RuntimeItemID(rawValue: "preview-item-user-\(UUID().uuidString.lowercased())"),
          RuntimeEntityID(rawValue: "preview-entity-user-\(UUID().uuidString.lowercased())"),
          .item(.userMessage(text: prompt.rawValue, meta: RuntimeAgentItemMetaV1()))
        ),
        (
          RuntimeItemID(rawValue: "preview-item-assistant-\(UUID().uuidString.lowercased())"),
          RuntimeEntityID(rawValue: "preview-entity-assistant-\(UUID().uuidString.lowercased())"),
          .item(
            .assistantMessage(
              text: "Preview fixture 已完成这次 synthetic turn。",
              meta: RuntimeAgentItemMetaV1()
            )
          )
        ),
        (nil, nil, .turnCompleted(turnID: turnID, summary: try Self.turnSummary())),
      ]

    for payload in bodies {
      let event = try RuntimeEventV2(
        conversationID: conversationID,
        eventID: RuntimeEventID(
          rawValue: "preview-event-\(commandID.rawValue)-\(sequence)"
        ),
        eventSeq: sequence,
        commandID: commandID,
        itemID: payload.itemID,
        entityID: payload.entityID,
        body: payload.body
      )
      enqueue(event)
      sequence += 1
    }
    nextEventSequence[conversationID] = sequence
  }

  private func enqueue(_ event: RuntimeEventV2) {
    let frame = LocalRuntimeStreamFrame(
      messageID: RuntimeMessageID(rawValue: "preview-message-\(event.eventID.rawValue)"),
      item: .event(event)
    )
    if let streamWaiter {
      self.streamWaiter = nil
      streamWaiter.resume(returning: frame)
    } else {
      streamFrames.append(frame)
    }
  }

  private static func catalogSnapshot() throws -> RuntimeCatalogSnapshotV2 {
    try RuntimeCatalogSnapshotV2(
      baseCatalogCursor: .at(0),
      entries: MockDaemonScript.historyList().enumerated().map { index, item in
        RuntimeConversationEntryV2(
          conversationID: RuntimeConversationID(rawValue: item.threadId),
          agentKind: item.agentKind,
          title: item.title,
          cwd: item.cwd,
          lastActiveMs: item.lastActiveMs,
          archived: item.archived,
          entryRevision: UInt64(index + 1)
        )
      },
      nextPageCursor: nil
    )
  }

  private static func conversationSnapshot(
    conversationID: RuntimeConversationID
  ) throws -> ConversationSnapshotV2 {
    let commandID = RuntimeCommandID(rawValue: "preview-command-\(conversationID.rawValue)")
    return try ConversationSnapshotV2(
      conversationID: conversationID,
      baseEventCursor: .beforeFirst,
      configurationState: RuntimeConversationConfigurationStateV2(
        configurationRevision: 1,
        configuration: codexConfiguration()
      ),
      items: [
        .capabilities(try codexCapabilities()),
        .item(
          itemID: RuntimeItemID(rawValue: "preview-user-\(conversationID.rawValue)"),
          entityID: RuntimeEntityID(rawValue: "preview-user-entity-\(conversationID.rawValue)"),
          commandID: commandID,
          item: .userMessage(
            text: "把登录模块拆分成独立的 auth service，抽出 token 刷新逻辑，并补齐单元测试。",
            meta: RuntimeAgentItemMetaV1()
          )
        ),
        .item(
          itemID: RuntimeItemID(rawValue: "preview-assistant-\(conversationID.rawValue)"),
          entityID: RuntimeEntityID(
            rawValue: "preview-assistant-entity-\(conversationID.rawValue)"
          ),
          commandID: commandID,
          item: .assistantMessage(
            text: "已梳理 auth 依赖并完成服务拆分，下一步运行 focused tests。",
            meta: RuntimeAgentItemMetaV1()
          )
        ),
      ]
    )
  }

  private static func agentDescriptions() throws -> RuntimeAgentDescriptionsV2 {
    try RuntimeAgentDescriptionsV2(agents: [
      RuntimeAgentDescriptionV2(
        agentKind: .codex,
        capabilities: codexCapabilities(),
        defaultConfiguration: codexConfiguration()
      )
    ])
  }

  private static func codexCapabilities() throws -> RuntimeSessionCapabilitiesV1 {
    try JSONDecoder().decode(
      RuntimeSessionCapabilitiesV1.self,
      from: Data(
        #"{"agentKind":"codex","agentVersion":"preview","features":[],"vendor":{"agentKind":"codex","sandboxModes":["read-only","workspace-write"],"persistenceSupported":false,"reasoningEffortLevels":["low","medium","high"]}}"#
          .utf8
      )
    )
  }

  private static func codexConfiguration() -> RuntimeConversationConfigurationV2 {
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

  private static func syncComplete(
    innerCursor: RuntimeInnerCursorV1
  ) throws -> RuntimeSyncCompleteV1 {
    let fixture = PreviewSyncCompleteFixture(
      streamGeneration: generation,
      streamCursor: .at(0),
      innerCursor: innerCursor,
      keyDirectoryRevision: 0
    )
    return try JSONDecoder().decode(
      RuntimeSyncCompleteV1.self,
      from: JSONEncoder().encode(fixture)
    )
  }

  private static func turnSummary() throws -> RuntimeTurnSummaryV1 {
    try JSONDecoder().decode(
      RuntimeTurnSummaryV1.self,
      from: Data(
        #"{"elapsedMs":1200,"totalInputTokens":null,"totalOutputTokens":null}"#.utf8
      )
    )
  }

  private static func closedFailure() -> RuntimeEnvelopeClientFailure {
    RuntimeEnvelopeClientFailure(
      code: "preview.closed",
      message: "preview Runtime wire closed"
    )
  }
}

private actor PreviewRuntimeReplySequence: AppRuntimeWireReplySequence {
  private var replies: [RuntimeReplyV2]

  init(replies: [RuntimeReplyV2]) {
    self.replies = replies
  }

  func next() async throws -> RuntimeReplyV2? {
    guard !replies.isEmpty else { return nil }
    return replies.removeFirst()
  }

  func cancel() async {
    replies.removeAll()
  }
}

private struct PreviewSyncCompleteFixture: Encodable {
  let streamGeneration: RuntimeStreamGeneration
  let streamCursor: RuntimeStreamCursorV1
  let innerCursor: RuntimeInnerCursorV1
  let keyDirectoryRevision: UInt64
}
