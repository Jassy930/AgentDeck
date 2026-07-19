import AgentDeckCore
import AppKit
import XCTest

@testable import AgentDeck

/// Covers C1: a fileEdit row the user expanded must stay expanded across the
/// streaming reconfigure path. The persisted expansion lives on the
/// controller (a `ConversationDisclosureStateStore`), survives cell reuse, and
/// drives the reserved row height.
@MainActor
final class ConversationDisclosurePersistenceTests: XCTestCase {
  private let conversationID = RuntimeConversationID(rawValue: "conversation-disclosure")

  private func makeModel(withDiff patch: String) throws -> SessionModel {
    let model = SessionModel()
    try model.workbench.installCatalog(
      snapshotPages: [
        try RuntimeCatalogSnapshotV2(
          baseCatalogCursor: .beforeFirst,
          entries: [
            RuntimeConversationEntryV2(
              conversationID: conversationID,
              agentKind: .codex,
              title: "Disclosure fixture",
              cwd: "/tmp/disclosure",
              lastActiveMs: 1_000,
              archived: false,
              entryRevision: 1
            )
          ],
          nextPageCursor: nil
        )
      ]
    )

    let snapshot = try ConversationSnapshotV2(
      conversationID: conversationID,
      baseEventCursor: .beforeFirst,
      configurationState: try RuntimeConversationConfigurationStateV2(
        configurationRevision: 0,
        configuration: nil
      ),
      items: [
        .capabilities(try capabilities()),
        .item(
          itemID: RuntimeItemID(rawValue: "item-user"),
          entityID: RuntimeEntityID(rawValue: "entity-user"),
          commandID: RuntimeCommandID(rawValue: "command-user"),
          item: .userMessage(text: "run it", meta: RuntimeAgentItemMetaV1())
        ),
        .item(
          itemID: RuntimeItemID(rawValue: "item-diff"),
          entityID: RuntimeEntityID(rawValue: "entity-diff"),
          commandID: RuntimeCommandID(rawValue: "command-user"),
          item: .diff(files: [try diffFile(patch: patch)], meta: RuntimeAgentItemMetaV1())
        ),
      ]
    )
    _ = try model.workbench.ingest(.synchronizedReply(.snapshot(snapshot)))
    _ = try model.workbench.ingest(
      .synchronizedReply(
        .syncComplete(try syncComplete(conversationID: conversationID))
      )
    )
    try model.workbench.selectConversation(conversationID)
    return model
  }

  /// The persisted set toggles and is queryable through the store contract.
  func testStoreTogglePersistsExpansion() throws {
    let model = try makeModel(withDiff: "line1\nline2\n")
    let vc = ConversationViewController(model: model)
    _ = vc.view  // loadView

    let store = vc as ConversationDisclosureStateStore
    XCTAssertFalse(store.isItemExpanded("item-diff"), "默认折叠")
    store.setItem("item-diff", expanded: true)
    XCTAssertTrue(store.isItemExpanded("item-diff"), "展开后持久化为 true")
    store.setItem("item-diff", expanded: false)
    XCTAssertFalse(store.isItemExpanded("item-diff"), "再次折叠后回到 false")
  }

  /// Expanding a fileEdit row makes the table reserve more height for its
  /// diff body, and a subsequent reconfigure must not lose that state.
  func testExpandedFileEditRowReservesMoreHeightAndSurvivesReconfigure() throws {
    let model = try makeModel(withDiff: String(repeating: "+output line\n", count: 12))
    let vc = ConversationViewController(model: model)
    _ = vc.view
    vc.view.frame = NSRect(x: 0, y: 0, width: 600, height: 800)
    vc.view.layoutSubtreeIfNeeded()

    guard let tableView = firstTableView(in: vc.view) else {
      return XCTFail("找不到 NSTableView")
    }
    // Rows: [userPrompt, fileEdit]. The fileEdit row is index 1.
    let fileEditRow = 1
    let collapsedHeight =
      tableView.delegate?.tableView?(tableView, heightOfRow: fileEditRow) ?? 0
    XCTAssertGreaterThan(collapsedHeight, 0)

    // Materialize the cell so the table has the row on screen, then expand.
    _ = tableView.delegate?.tableView?(
      tableView,
      viewFor: tableView.tableColumns.first,
      row: fileEditRow
    )
    (vc as ConversationDisclosureStateStore).setItem("item-diff", expanded: true)

    let expandedHeight =
      tableView.delegate?.tableView?(tableView, heightOfRow: fileEditRow) ?? 0
    XCTAssertGreaterThan(
      expandedHeight,
      collapsedHeight,
      "展开 fileEdit diff 后行高应增加（为 diff body 预留空间）"
    )

    // Re-fetch the cell — this is the streaming-reconfigure path. The
    // persisted flag must still be set, and the height must stay expanded.
    _ = tableView.delegate?.tableView?(
      tableView,
      viewFor: tableView.tableColumns.first,
      row: fileEditRow
    )
    XCTAssertTrue((vc as ConversationDisclosureStateStore).isItemExpanded("item-diff"))
    let afterReconfigure =
      tableView.delegate?.tableView?(tableView, heightOfRow: fileEditRow) ?? 0
    XCTAssertEqual(afterReconfigure, expandedHeight, accuracy: 0.5, "重配后行高保持展开高度")
  }

  private func capabilities() throws -> RuntimeSessionCapabilitiesV1 {
    try decode(
      RuntimeSessionCapabilitiesV1.self,
      [
        "agentKind": "codex",
        "agentVersion": "test",
        "features": ["diff"],
        "vendor": [
          "agentKind": "codex",
          "sandboxModes": ["workspace-write"],
          "persistenceSupported": false,
          "reasoningEffortLevels": ["medium"],
        ],
      ]
    )
  }

  private func diffFile(patch: String) throws -> RuntimeDiffFileV1 {
    try decode(
      RuntimeDiffFileV1.self,
      ["path": "Sources/Auth.swift", "status": "modified", "patch": patch]
    )
  }

  private func syncComplete(
    conversationID: RuntimeConversationID
  ) throws -> RuntimeSyncCompleteV1 {
    try decode(
      RuntimeSyncCompleteV1.self,
      [
        "streamGeneration": "fixture-generation",
        "streamCursor": "beforeFirst",
        "innerCursor": [
          "scope": "conversation",
          "conversationId": conversationID.rawValue,
          "cursor": "beforeFirst",
        ],
        "keyDirectoryRevision": 0,
      ]
    )
  }

  private func decode<Value: Decodable>(_ type: Value.Type, _ object: Any) throws -> Value {
    let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    return try JSONDecoder().decode(type, from: data)
  }

  private func firstTableView(in view: NSView) -> NSTableView? {
    if let table = view as? NSTableView { return table }
    for subview in view.subviews {
      if let found = firstTableView(in: subview) { return found }
    }
    return nil
  }
}
