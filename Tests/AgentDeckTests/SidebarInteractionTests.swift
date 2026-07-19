import AgentDeckCore
import AppKit
import XCTest

@testable import AgentDeck

/// 端到端交互：canonical catalog → 真实侧栏 VC → conversation snapshot barrier
/// → typed selection。测试 wire 只提供 Runtime v2 fixture，不建立真实 daemon 连接。
@MainActor
final class SidebarInteractionTests: XCTestCase {
  private func entry(
    _ id: String,
    _ title: String,
    cwd: String,
    archived: Bool = false,
    lastActiveMs: UInt64 = 1_000
  ) -> RuntimeConversationEntryV2 {
    RuntimeConversationEntryV2(
      conversationID: RuntimeConversationID(rawValue: id),
      agentKind: .codex,
      title: title,
      cwd: cwd,
      lastActiveMs: lastActiveMs,
      archived: archived,
      entryRevision: 1
    )
  }

  private func makeSidebar(
    _ entries: [RuntimeConversationEntryV2],
    failingConversationIDs: Set<RuntimeConversationID> = []
  ) async throws -> (HistorySidebarViewController, NSOutlineView, SessionModel) {
    let wire = try SidebarRuntimeFixtureWire(
      entries: entries,
      failingConversationIDs: failingConversationIDs
    )
    let model = SessionModel(runtimeWire: wire)
    model.loadHistory()
    try await waitUntil { !model.isLoadingHistory }
    if let historyErrorMessage = model.historyErrorMessage {
      throw SidebarRuntimeFixtureError.operationFailed(historyErrorMessage)
    }

    let vc = HistorySidebarViewController(model: model)
    _ = vc.view
    let outlineView = try XCTUnwrap(vc.view.firstDescendant(ofType: NSOutlineView.self))
    outlineView.reloadData()
    outlineView.expandItem(nil, expandChildren: true)
    return (vc, outlineView, model)
  }

  private func row(of conversationID: String, in outlineView: NSOutlineView) -> Int {
    for row in 0..<outlineView.numberOfRows
    where (outlineView.item(atRow: row) as? HistoryThreadSummary)?.id == conversationID {
      return row
    }
    return -1
  }

  func testHistoryThreadsPopulateGroups() async throws {
    let (_, outlineView, model) = try await makeSidebar([
      entry("conversation-1", "拆分登录", cwd: "/p/refactor-auth", lastActiveMs: 3_000),
      entry("conversation-2", "修复竞态", cwd: "/p/refactor-auth", lastActiveMs: 2_000),
      entry("conversation-3", "补文档", cwd: "/p/agentdeck-docs"),
    ])
    defer { model.teardown() }

    XCTAssertEqual(model.historyGroups.count, 2, "两个项目目录应分成两组")
    XCTAssertGreaterThanOrEqual(outlineView.numberOfRows, 5, "两组 + 三线程应至少 5 行")
    XCTAssertEqual(
      Set(model.workbench.catalogEntries.map(\.conversationID)),
      Set([
        RuntimeConversationID(rawValue: "conversation-1"),
        RuntimeConversationID(rawValue: "conversation-2"),
        RuntimeConversationID(rawValue: "conversation-3"),
      ])
    )
  }

  func testSelectingCatalogConversationSynchronizesCanonicalSnapshot() async throws {
    let targetID = RuntimeConversationID(rawValue: "conversation-select")
    let (vc, outlineView, model) = try await makeSidebar([
      entry(targetID.rawValue, "拆分登录", cwd: "/p/refactor-auth")
    ])
    defer { model.teardown() }

    let targetRow = row(of: targetID.rawValue, in: outlineView)
    XCTAssertGreaterThanOrEqual(targetRow, 0, "catalog conversation 应作为会话行出现在侧栏")
    XCTAssertNil(model.workbench.selectedConversationID)
    outlineView.selectRowIndexes(IndexSet(integer: targetRow), byExtendingSelection: false)
    if model.openingHistoryConversationID == nil {
      vc.outlineViewSelectionDidChange(
        Notification(name: NSOutlineView.selectionDidChangeNotification, object: outlineView)
      )
    }

    try await waitUntil { model.selectedSidebarConversationID == targetID.rawValue }
    XCTAssertEqual(model.workbench.selectedConversationID, targetID)
    XCTAssertEqual(model.selectedHistoryConversationID, targetID)
    XCTAssertEqual(model.selectedItems.map(\.id), ["item-\(targetID.rawValue)"])
    XCTAssertEqual(model.selectedItems.map(\.text), ["fixture \(targetID.rawValue)"])
  }

  func testConversationSynchronizationFailureKeepsSelectionFailClosed() async throws {
    let targetID = RuntimeConversationID(rawValue: "conversation-failing")
    let (vc, outlineView, model) = try await makeSidebar(
      [entry(targetID.rawValue, "拆分登录", cwd: "/p/refactor-auth")],
      failingConversationIDs: [targetID]
    )
    defer { model.teardown() }

    let targetRow = row(of: targetID.rawValue, in: outlineView)
    outlineView.selectRowIndexes(IndexSet(integer: targetRow), byExtendingSelection: false)
    if model.openingHistoryConversationID == nil {
      vc.outlineViewSelectionDidChange(
        Notification(name: NSOutlineView.selectionDidChangeNotification, object: outlineView)
      )
    }

    try await waitUntil {
      model.openingHistoryConversationID == nil && model.historyErrorMessage != nil
    }
    XCTAssertNil(model.workbench.selectedConversationID)
    XCTAssertNil(model.selectedSidebarConversationID)
    XCTAssertNotNil(model.historyErrorMessage)
  }

  func testGroupRowIsNotSelectable() async throws {
    let (vc, _, model) = try await makeSidebar([
      entry("conversation-group", "A", cwd: "/p/proj")
    ])
    defer { model.teardown() }

    let group = try XCTUnwrap(model.historyGroups.first)
    let conversation = try XCTUnwrap(model.historyThreads.first)
    XCTAssertFalse(vc.outlineView(NSOutlineView(), shouldSelectItem: group), "项目组行不应可选")
    XCTAssertTrue(vc.outlineView(NSOutlineView(), shouldSelectItem: conversation), "会话行应可选")
  }

  /// 渲染有数据的侧栏为 PNG，供人工核对真实呈现。
  func testRenderPopulatedSidebar() async throws {
    let (vc, _, model) = try await makeSidebar([
      entry(
        "conversation-render-1",
        "把登录模块拆分为独立的 service 并补齐测试",
        cwd: "/p/refactor-auth",
        lastActiveMs: 3_000
      ),
      entry(
        "conversation-render-2",
        "修复 token 刷新的竞态条件",
        cwd: "/p/refactor-auth",
        lastActiveMs: 2_000
      ),
      entry(
        "conversation-render-3",
        "补充 README 的部署章节",
        cwd: "/p/agentdeck-docs"
      ),
    ])
    defer { model.teardown() }

    vc.view.renderPNG(to: "/tmp/adk-sidebar.png", size: NSSize(width: 236, height: 640))
  }

  private func waitUntil(
    _ predicate: @escaping @MainActor () -> Bool,
    attempts: Int = 200
  ) async throws {
    for _ in 0..<attempts {
      if predicate() { return }
      try await Task.sleep(for: .milliseconds(5))
    }
    throw SidebarRuntimeFixtureError.timeout
  }
}

private enum SidebarRuntimeFixtureError: Error {
  case closed
  case missingSnapshot(RuntimeConversationID)
  case operationFailed(String)
  case synchronizationFailed(RuntimeConversationID)
  case timeout
  case unsupportedRequest
}

private actor SidebarRuntimeFixtureWire: AppRuntimeWireSession {
  private static let generation = RuntimeStreamGeneration(rawValue: "sidebar-generation")

  private let entries: [RuntimeConversationEntryV2]
  private let snapshots: [RuntimeConversationID: ConversationSnapshotV2]
  private let failingConversationIDs: Set<RuntimeConversationID>
  private var closed = false
  private var streamWaiter: CheckedContinuation<LocalRuntimeStreamFrame, Error>?

  init(
    entries: [RuntimeConversationEntryV2],
    failingConversationIDs: Set<RuntimeConversationID>
  ) throws {
    self.entries = entries
    self.failingConversationIDs = failingConversationIDs
    snapshots = try Dictionary(
      uniqueKeysWithValues: entries.map { entry in
        (entry.conversationID, try Self.snapshot(for: entry))
      }
    )
  }

  func start() async throws {}

  func request(_ request: RuntimeRequestV2) async throws -> RuntimeReplyV2 {
    guard !closed else { throw SidebarRuntimeFixtureError.closed }
    switch request {
    case .describeAgents:
      return .agents(try Self.agentDescriptions())
    case .catalog:
      return .catalog(
        try RuntimeCatalogSnapshotV2(
          baseCatalogCursor: .beforeFirst,
          entries: entries,
          nextPageCursor: nil
        )
      )
    default:
      throw SidebarRuntimeFixtureError.unsupportedRequest
    }
  }

  func beginAppSynchronizedRequest(
    _ request: RuntimeRequestV2
  ) async throws -> any AppRuntimeWireReplySequence {
    guard !closed else { throw SidebarRuntimeFixtureError.closed }
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
        guard !failingConversationIDs.contains(conversationID) else {
          throw SidebarRuntimeFixtureError.synchronizationFailed(conversationID)
        }
        guard let snapshot = snapshots[conversationID] else {
          throw SidebarRuntimeFixtureError.missingSnapshot(conversationID)
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
    default:
      throw SidebarRuntimeFixtureError.unsupportedRequest
    }
    return SidebarRuntimeFixtureReplySequence(replies: replies)
  }

  func nextStream() async throws -> LocalRuntimeStreamFrame {
    guard !closed else { throw SidebarRuntimeFixtureError.closed }
    return try await withCheckedThrowingContinuation { continuation in
      precondition(streamWaiter == nil)
      streamWaiter = continuation
    }
  }

  func close() async {
    guard !closed else { return }
    closed = true
    streamWaiter?.resume(throwing: SidebarRuntimeFixtureError.closed)
    streamWaiter = nil
  }

  private static func snapshot(
    for entry: RuntimeConversationEntryV2
  ) throws -> ConversationSnapshotV2 {
    let rawID = entry.conversationID.rawValue
    return try ConversationSnapshotV2(
      conversationID: entry.conversationID,
      baseEventCursor: .beforeFirst,
      configurationState: RuntimeConversationConfigurationStateV2(
        configurationRevision: 0,
        configuration: nil
      ),
      items: [
        .capabilities(try capabilities()),
        .item(
          itemID: RuntimeItemID(rawValue: "item-\(rawID)"),
          entityID: RuntimeEntityID(rawValue: "entity-\(rawID)"),
          commandID: RuntimeCommandID(rawValue: "command-\(rawID)"),
          item: .userMessage(
            text: "fixture \(rawID)",
            meta: RuntimeAgentItemMetaV1()
          )
        ),
      ]
    )
  }

  private static func agentDescriptions() throws -> RuntimeAgentDescriptionsV2 {
    let capabilities = try capabilities()
    return try RuntimeAgentDescriptionsV2(agents: [
      try RuntimeAgentDescriptionV2(
        agentKind: .codex,
        capabilities: capabilities,
        defaultConfiguration: RuntimeConversationConfigurationV2(
          vendorControl: .codex(
            RuntimeCodexConversationConfigurationV2(
              approvalPolicy: .onRequest,
              sandbox: .workspaceWrite,
              reasoningEffort: .medium
            )
          )
        )
      )
    ])
  }

  private static func capabilities() throws -> RuntimeSessionCapabilitiesV1 {
    try decode(
      RuntimeSessionCapabilitiesV1.self,
      [
        "agentKind": "codex",
        "agentVersion": "test",
        "features": ["streamingMessages"],
        "vendor": [
          "agentKind": "codex",
          "sandboxModes": ["workspace-write"],
          "persistenceSupported": false,
          "reasoningEffortLevels": ["medium"],
        ],
      ]
    )
  }

  private static func syncComplete(
    innerCursor: RuntimeInnerCursorV1
  ) throws -> RuntimeSyncCompleteV1 {
    try decode(
      RuntimeSyncCompleteV1.self,
      [
        "streamGeneration": generation.rawValue,
        "streamCursor": "beforeFirst",
        "innerCursor": innerCursorObject(innerCursor),
        "keyDirectoryRevision": 0,
      ]
    )
  }

  private static func innerCursorObject(_ cursor: RuntimeInnerCursorV1) -> Any {
    switch cursor {
    case .catalog(let value):
      return ["scope": "catalog", "cursor": cursorObject(value)]
    case .conversation(let conversationID, let value):
      return [
        "scope": "conversation",
        "conversationId": conversationID.rawValue,
        "cursor": cursorObject(value),
      ]
    }
  }

  private static func cursorObject(_ cursor: RuntimeStreamCursorV1) -> Any {
    switch cursor {
    case .beforeFirst: "beforeFirst"
    case .at(let value): ["at": value]
    }
  }

  private static func decode<Value: Decodable>(
    _ type: Value.Type,
    _ object: Any
  ) throws -> Value {
    let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    return try JSONDecoder().decode(type, from: data)
  }
}

private actor SidebarRuntimeFixtureReplySequence: AppRuntimeWireReplySequence {
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
