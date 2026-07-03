import AppKit
import AgentDeckCore
import XCTest
@testable import AgentDeck

/// Covers C1: a shell/fileEdit row the user expanded must STAY expanded across
/// the streaming reconfigure path. The persisted expansion lives on the
/// controller (a `ConversationDisclosureStateStore`), survives cell reuse, and
/// drives the reserved row height.
@MainActor
final class ConversationDisclosurePersistenceTests: XCTestCase {

    private func makeModel(withShellOutput output: String) -> SessionModel {
        let model = SessionModel()
        var user = UIItem(id: "u1", lifecycle: "completed", kind: "user", text: "run it")
        user.textBuffer.replace(with: "run it")
        var shell = UIItem(id: "s1", lifecycle: "completed", kind: "shell")
        shell.command = "ls -la"
        shell.output = output
        shell.outputBuffer.replace(with: output)
        model.items = [user, shell]
        return model
    }

    /// The persisted set toggles and is queryable through the store contract.
    func testStoreTogglePersistsExpansion() {
        let model = makeModel(withShellOutput: "line1\nline2\n")
        let vc = ConversationViewController(model: model)
        _ = vc.view  // loadView

        let store = vc as ConversationDisclosureStateStore
        XCTAssertFalse(store.isItemExpanded("s1"), "默认折叠")
        store.setItem("s1", expanded: true)
        XCTAssertTrue(store.isItemExpanded("s1"), "展开后持久化为 true")
        store.setItem("s1", expanded: false)
        XCTAssertFalse(store.isItemExpanded("s1"), "再次折叠后回到 false")
    }

    /// Expanding a shell row makes the table reserve more height for it (the
    /// streamed output body), proving the persisted flag drives layout — and
    /// that a subsequent reconfigure does not lose it.
    func testExpandedShellRowReservesMoreHeightAndSurvivesReconfigure() {
        let model = makeModel(withShellOutput: String(repeating: "output line\n", count: 12))
        let vc = ConversationViewController(model: model)
        _ = vc.view
        vc.view.frame = NSRect(x: 0, y: 0, width: 600, height: 800)
        vc.view.layoutSubtreeIfNeeded()

        guard let tableView = firstTableView(in: vc.view) else {
            return XCTFail("找不到 NSTableView")
        }
        // Rows: [userPrompt, shell]. The shell row is index 1.
        let shellRow = 1
        let collapsedHeight = tableView.delegate?.tableView?(tableView, heightOfRow: shellRow) ?? 0
        XCTAssertGreaterThan(collapsedHeight, 0)

        // Materialize the cell so the table has the row on screen, then expand.
        _ = tableView.delegate?.tableView?(tableView, viewFor: tableView.tableColumns.first, row: shellRow)
        (vc as ConversationDisclosureStateStore).setItem("s1", expanded: true)

        let expandedHeight = tableView.delegate?.tableView?(tableView, heightOfRow: shellRow) ?? 0
        XCTAssertGreaterThan(
            expandedHeight, collapsedHeight,
            "展开 shell 输出后行高应增加（为输出体预留空间）"
        )

        // Re-fetch the cell — this is the streaming-reconfigure path. The
        // persisted flag must still be set, and the height must stay expanded.
        _ = tableView.delegate?.tableView?(tableView, viewFor: tableView.tableColumns.first, row: shellRow)
        XCTAssertTrue((vc as ConversationDisclosureStateStore).isItemExpanded("s1"))
        let afterReconfigure = tableView.delegate?.tableView?(tableView, heightOfRow: shellRow) ?? 0
        XCTAssertEqual(afterReconfigure, expandedHeight, accuracy: 0.5, "重配后行高保持展开高度")
    }

    private func firstTableView(in view: NSView) -> NSTableView? {
        if let table = view as? NSTableView { return table }
        for sub in view.subviews {
            if let found = firstTableView(in: sub) { return found }
        }
        return nil
    }
}
