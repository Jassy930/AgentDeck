import XCTest
import AppKit
import AgentDeckCore
@testable import AgentDeck

@MainActor
final class HistorySidebarSmokeTests: XCTestCase {
    /// Constructing the VC and accessing `.view` (which triggers `loadView`)
    /// must not crash and must NOT spawn `agentdeckd` — `SessionModel()`
    /// only builds a `DaemonClient` whose transport stays dormant until
    /// `start()` (never called here), exactly like the existing IpcTests /
    /// ConversationViewControllerSmokeTests.
    func testConstructsAndLoadsView() {
        let model = SessionModel()
        let vc = HistorySidebarViewController(model: model)
        XCTAssertNotNil(vc.view)
    }

    func testOutlineViewIsPresent() {
        let model = SessionModel()
        let vc = HistorySidebarViewController(model: model)
        _ = vc.view  // trigger loadView
        let hasOutline = Self.allViews(vc.view).contains { $0 is NSOutlineView }
        XCTAssertTrue(hasOutline, "Expected NSOutlineView in view hierarchy")
    }

    func testEmptyStateDoesNotPromiseUnsupportedPersistedHistory() throws {
        let vc = HistorySidebarViewController(model: SessionModel())
        _ = vc.view
        let label = try XCTUnwrap(vc.view.descendant(id: "sidebar-empty-history") as? NSTextField)

        XCTAssertTrue(label.stringValue.contains("当前支持的历史"))
        XCTAssertFalse(label.stringValue.contains("扫描已持久化"))
    }

    func testOutlineColumnFillsVisibleSidebarWidth() throws {
        let model = SessionModel(turnStarter: NoopRuntimeTurnStarter())
        model.setHistoryThreads([
            HistoryThreadSummary(
                id: "t1",
                name: "A complete thread title",
                preview: "preview",
                cwd: "/tmp/project",
                createdAt: 1,
                updatedAt: 2,
                status: "ready",
                modelProvider: "openai",
                source: "codex",
                agentKind: .codex
            ),
        ])
        let vc = HistorySidebarViewController(model: model)
        let window = NSWindow(contentViewController: vc)
        window.setContentSize(NSSize(width: 216, height: 640))
        window.makeKeyAndOrderFront(nil)
        defer { window.close() }
        RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.1))

        let scrollView = try XCTUnwrap(Self.allViews(vc.view).compactMap { $0 as? NSScrollView }.first)
        let outlineView = try XCTUnwrap(scrollView.documentView as? NSOutlineView)
        outlineView.reloadData()
        outlineView.expandItem(nil, expandChildren: true)
        let column = try XCTUnwrap(outlineView.tableColumns.first)
        let visibleWidth = scrollView.contentView.bounds.width

        XCTAssertGreaterThan(visibleWidth, 0)
        let threadRow = (0..<outlineView.numberOfRows).first {
            outlineView.item(atRow: $0) is HistoryThreadSummary
        }
        let row = try XCTUnwrap(threadRow)
        let cell = try XCTUnwrap(outlineView.view(atColumn: 0, row: row, makeIfNecessary: true))
        XCTAssertEqual(
            column.width + cell.frame.minX,
            visibleWidth,
            accuracy: 1,
            "The column must compensate for the source-list leading inset without leaving a trailing gutter"
        )
        XCTAssertEqual(
            cell.frame.maxX,
            visibleWidth,
            accuracy: 1,
            "Thread cells must reach the visible trailing edge"
        )

        window.setContentSize(NSSize(width: 250, height: 640))
        RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.1))
        let resizedVisibleWidth = scrollView.contentView.bounds.width
        let resizedCell = try XCTUnwrap(outlineView.view(atColumn: 0, row: row, makeIfNecessary: true))
        XCTAssertEqual(column.width + resizedCell.frame.minX, resizedVisibleWidth, accuracy: 1)
        XCTAssertEqual(resizedCell.frame.maxX, resizedVisibleWidth, accuracy: 1)
    }

    // MARK: - clickedRow → thread resolver

    /// Minimal data source mirroring the VC's two-level shape:
    /// top-level = groups, children = threads. Used to populate a real
    /// NSOutlineView so `thread(forClickedRow:in:)` can be exercised against
    /// a deterministic row layout (group at row 0, threads beneath it).
    private final class StubDataSource: NSObject, NSOutlineViewDataSource {
        let groups: [HistoryProjectGroup]
        init(_ groups: [HistoryProjectGroup]) { self.groups = groups }

        func outlineView(_ outlineView: NSOutlineView, numberOfChildrenOfItem item: Any?) -> Int {
            if item == nil { return groups.count }
            if let g = item as? HistoryProjectGroup { return g.threads.count }
            return 0
        }
        func outlineView(_ outlineView: NSOutlineView, child index: Int, ofItem item: Any?) -> Any {
            if item == nil { return groups[index] }
            return (item as! HistoryProjectGroup).threads[index]
        }
        func outlineView(_ outlineView: NSOutlineView, isItemExpandable item: Any) -> Bool {
            item is HistoryProjectGroup
        }
    }

    private func makePopulatedOutline() -> (NSOutlineView, StubDataSource) {
        let threads = [
            HistoryThreadSummary(id: "t1", name: "Alpha", preview: "a", cwd: "/tmp/proj",
                                 createdAt: 1, updatedAt: 2, status: "ready",
                                 modelProvider: "openai", source: "cli", agentKind: .codex),
            HistoryThreadSummary(id: "t2", name: "Beta", preview: "b", cwd: "/tmp/proj",
                                 createdAt: 3, updatedAt: 4, status: "ready",
                                 modelProvider: "openai", source: "cli", agentKind: .codex),
        ]
        let groups = HistoryProjectGroup.group(threads)
        let ds = StubDataSource(groups)
        let ov = NSOutlineView()
        let col = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("main"))
        ov.addTableColumn(col)
        ov.outlineTableColumn = col
        ov.dataSource = ds
        ov.reloadData()
        // Expand the single group so its threads materialize as rows 1..n.
        for g in groups { ov.expandItem(g) }
        // Row layout now: 0 = group row, rows 1..2 = thread rows.
        return (ov, ds)
    }

    func testClickedRowResolvesThread() {
        let (ov, ds) = makePopulatedOutline()
        XCTAssertEqual(ov.numberOfRows, 3, "Expected 1 group row + 2 thread rows")
        // Rows 1 and 2 are thread rows → resolve to HistoryThreadSummary.
        let row1 = HistorySidebarViewController.thread(forClickedRow: 1, in: ov)
        let row2 = HistorySidebarViewController.thread(forClickedRow: 2, in: ov)
        XCTAssertNotNil(row1)
        XCTAssertNotNil(row2)
        XCTAssertEqual(Set([row1!.id, row2!.id]), Set(["t1", "t2"]))
        _ = ds  // keep the data source alive for the duration of the test
    }

    func testClickedRowGroupRowReturnsNil() {
        let (ov, ds) = makePopulatedOutline()
        // Row 0 is the project group → not a thread.
        XCTAssertNil(HistorySidebarViewController.thread(forClickedRow: 0, in: ov),
                     "Group row must not resolve to a thread")
        _ = ds
    }

    func testClickedRowOutOfRangeReturnsNil() {
        let (ov, ds) = makePopulatedOutline()
        // -1 is NSOutlineView's "no row" sentinel; a too-large index is also safe.
        XCTAssertNil(HistorySidebarViewController.thread(forClickedRow: -1, in: ov))
        XCTAssertNil(HistorySidebarViewController.thread(forClickedRow: 999, in: ov))
        _ = ds
    }

    private static func allViews(_ root: NSView) -> [NSView] {
        var result = [root]
        for subview in root.subviews {
            result += allViews(subview)
        }
        if let scrollView = root as? NSScrollView, let documentView = scrollView.documentView {
            result += allViews(documentView)
        }
        return result
    }
}
