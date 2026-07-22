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
        let user = UIItem(id: "u1", lifecycle: "completed", kind: "user", text: "run it")
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

    /// 不同会话的历史回放都可能生成相同的 `ai-1` / `s1` item ID；切换
    /// viewport 时必须丢弃上一会话的 disclosure 状态，不能串到新会话。
    func testViewportChangeClearsDisclosureStateForCollidingItemIds() async {
        let model = makeModel(withShellOutput: "line1\nline2\n")
        let reasoning = UIItem(id: "r1", lifecycle: "completed", kind: "reasoning", text: "thinking")
        reasoning.textBuffer.replace(with: "thinking")
        model.items.append(reasoning)
        let vc = ConversationViewController(model: model)
        _ = vc.view
        let store = vc as ConversationDisclosureStateStore

        store.setItem("s1", expanded: true)
        store.setItem("r1", expanded: false)
        XCTAssertTrue(store.isItemExpanded("s1"))
        XCTAssertTrue(store.isItemCollapsed("r1"))

        model.conversationViewportIdentity = "history:codex:other-thread:1"
        for _ in 0..<50 {
            if !store.isItemExpanded("s1"), !store.isItemCollapsed("r1") { break }
            await Task.yield()
        }

        XCTAssertFalse(
            store.isItemExpanded("s1"),
            "切换会话后，同名 item 不应继承上一会话的展开状态"
        )
        XCTAssertFalse(
            store.isItemCollapsed("r1"),
            "切换会话后，同名 reasoning 不应继承上一会话的收起覆盖"
        )
    }

    /// 新建空会话也属于 viewport 切换。即使新 rows 为空，table 仍必须
    /// 显式 reload，不能把旧会话的 cell 留在屏幕上。
    func testViewportChangeFromPopulatedConversationReloadsToEmptyTable() async throws {
        let model = makeModel(withShellOutput: "line1\nline2\n")
        let vc = ConversationViewController(model: model)
        _ = vc.view
        let tableView = try XCTUnwrap(firstTableView(in: vc.view))
        tableView.reloadData()
        XCTAssertGreaterThan(tableView.numberOfRows, 0)

        model.startNewSessionFromCurrentProject()
        for _ in 0..<50 {
            if tableView.numberOfRows == 0 { break }
            await Task.yield()
        }

        XCTAssertEqual(tableView.numberOfRows, 0, "新建空会话后不应残留旧会话行")
    }

    func testToolActivityGroupDefaultsCollapsedAndExpansionRestoresOriginalRows() throws {
        let model = SessionModel(turnStarter: NoopRuntimeTurnStarter())
        let user = UIItem(id: "u-group", lifecycle: "completed", kind: "user", text: "执行检查")
        var first = UIItem(id: "tool-1", lifecycle: "completed", kind: "toolCall")
        first.tool = "Read"
        first.statusName = "completed"
        first.arguments = "{\"payload\":\"\(String(repeating: "long payload ", count: 80))\"}"
        let reasoning = UIItem(
            id: "reasoning-middle",
            lifecycle: "completed",
            kind: "reasoning",
            text: "继续检查"
        )
        var second = UIItem(id: "tool-2", lifecycle: "completed", kind: "toolCall")
        second.tool = "Grep"
        second.statusName = "completed"
        model.items = [user, first, reasoning, second]

        let controller = ConversationViewController(model: model)
        _ = controller.view
        let table = try XCTUnwrap(firstTableView(in: controller.view))
        let store = controller as ConversationDisclosureStateStore
        let groupId = "tool-group:u-group:tool-1"

        table.reloadData()
        XCTAssertEqual(table.numberOfRows, 2, "折叠态应只保留用户行和一个摘要行")
        XCTAssertFalse(store.isItemExpanded(groupId))
        let collapsedHeight = table.delegate?.tableView?(table, heightOfRow: 1) ?? 0

        store.setItem(groupId, expanded: true)
        XCTAssertTrue(store.isItemExpanded(groupId))
        XCTAssertEqual(
            table.numberOfRows,
            5,
            "展开后应恢复摘要 + 两个工具 + 中间 reasoning"
        )

        store.setItem("tool-1", expanded: true)
        let expandedMemberHeight = table.delegate?.tableView?(table, heightOfRow: 2) ?? 0
        XCTAssertGreaterThan(expandedMemberHeight, collapsedHeight)
        store.setItem(groupId, expanded: false)
        XCTAssertEqual(table.numberOfRows, 2)
        let recollapsedHeight = table.delegate?.tableView?(table, heightOfRow: 1) ?? 0
        XCTAssertEqual(
            recollapsedHeight,
            collapsedHeight,
            accuracy: 0.5,
            "组标题不能继承首个工具已展开 payload 的不可见高度"
        )
        store.setItem(groupId, expanded: true)
        XCTAssertTrue(store.isItemExpanded("tool-1"), "重新展开组后应保留单项 payload 状态")
    }

    func testExpandedToolGroupRowsReceiveDistinctNonOverlappingFrames() throws {
        let model = SessionModel(turnStarter: NoopRuntimeTurnStarter())
        let user = UIItem(
            id: "u-group-layout",
            lifecycle: "completed",
            kind: "user",
            text: "执行布局检查"
        )
        var first = UIItem(id: "layout-tool-1", lifecycle: "completed", kind: "toolCall")
        first.tool = "Read"
        first.statusName = "completed"
        first.arguments = #"{"file_path":"/tmp/first.swift"}"#
        let reasoning = UIItem(
            id: "layout-reasoning",
            lifecycle: "completed",
            kind: "reasoning",
            text: "继续检查"
        )
        var second = UIItem(id: "layout-tool-2", lifecycle: "completed", kind: "toolCall")
        second.tool = "Grep"
        second.statusName = "completed"
        second.arguments = #"{"pattern":"activity"}"#
        model.items = [user, first, reasoning, second]

        let controller = ConversationViewController(model: model)
        let window = NSWindow(contentViewController: controller)
        window.setContentSize(NSSize(width: 720, height: 560))
        window.makeKeyAndOrderFront(nil)
        defer { window.close() }
        RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.05))

        let table = try XCTUnwrap(firstTableView(in: controller.view))
        table.reloadData()
        table.layoutSubtreeIfNeeded()
        let store = controller as ConversationDisclosureStateStore
        store.setItem("tool-group:u-group-layout:layout-tool-1", expanded: true)
        table.layoutSubtreeIfNeeded()

        XCTAssertEqual(table.numberOfRows, 5)
        let frames = try (1..<5).map { row -> NSRect in
            let rowView = try XCTUnwrap(
                table.rowView(atRow: row, makeIfNecessary: true),
                "展开成员 row=\(row) 应有独立 row view"
            )
            XCTAssertGreaterThan(rowView.frame.height, 0)
            return rowView.frame
        }
        for (previous, next) in zip(frames, frames.dropFirst()) {
            XCTAssertLessThanOrEqual(
                previous.maxY,
                next.minY + 0.5,
                "展开后的行 frame 不得重叠"
            )
        }
    }

    func testHiddenExpandedToolPayloadGrowthInvalidatesHeightBeforeGroupReopens() throws {
        let model = SessionModel(turnStarter: NoopRuntimeTurnStarter())
        let user = UIItem(
            id: "u-hidden-payload",
            lifecycle: "completed",
            kind: "user",
            text: "执行缓存检查"
        )
        var first = UIItem(
            id: "hidden-tool-1",
            lifecycle: "completed",
            kind: "toolCall"
        )
        first.tool = "Read"
        first.statusName = "running"
        first.arguments = #"{"path":"/tmp/short.swift"}"#
        var second = UIItem(
            id: "hidden-tool-2",
            lifecycle: "completed",
            kind: "toolCall"
        )
        second.tool = "Grep"
        second.statusName = "completed"
        second.arguments = #"{"pattern":"cache"}"#
        model.items = [user, first, second]

        let controller = ConversationViewController(model: model)
        let window = NSWindow(contentViewController: controller)
        window.setContentSize(NSSize(width: 720, height: 560))
        window.makeKeyAndOrderFront(nil)
        defer { window.close() }
        RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.05))

        let table = try XCTUnwrap(firstTableView(in: controller.view))
        let store = controller as ConversationDisclosureStateStore
        let groupId = "tool-group:u-hidden-payload:hidden-tool-1"
        table.reloadData()

        store.setItem(groupId, expanded: true)
        store.setItem("hidden-tool-1", expanded: true)
        table.layoutSubtreeIfNeeded()
        XCTAssertEqual(table.numberOfRows, 4)
        let initialHeight = table.delegate?.tableView?(table, heightOfRow: 2) ?? 0

        store.setItem(groupId, expanded: false)
        XCTAssertEqual(table.numberOfRows, 2)

        var longerFirst = first
        longerFirst.arguments = "{\"paths\":[\n" + (0..<36)
            .map { "  \"/tmp/generated/very-long-path-\($0).swift\"" }
            .joined(separator: ",\n") + "\n]}"
        model.items = [user, longerFirst, second]
        RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.1))
        XCTAssertEqual(table.numberOfRows, 2, "payload flush 期间工具成员仍应保持隐藏")

        store.setItem(groupId, expanded: true)
        table.layoutSubtreeIfNeeded()
        XCTAssertEqual(table.numberOfRows, 4)
        XCTAssertTrue(store.isItemExpanded("hidden-tool-1"))

        let updatedHeight = table.delegate?.tableView?(table, heightOfRow: 2) ?? 0
        XCTAssertGreaterThan(
            updatedHeight,
            initialHeight + 20,
            "同 ID payload 在组折叠期间增长后，重新展开必须重新测量成员高度"
        )

        let frames = try (1..<4).map { row -> NSRect in
            let rowView = try XCTUnwrap(
                table.rowView(atRow: row, makeIfNecessary: true),
                "重新展开后的 row=\(row) 应有独立 row view"
            )
            XCTAssertGreaterThan(rowView.frame.height, 0)
            return rowView.frame
        }
        for (previous, next) in zip(frames, frames.dropFirst()) {
            XCTAssertLessThanOrEqual(
                previous.maxY,
                next.minY + 0.5,
                "payload 增长后重新展开的成员 frame 不得重叠"
            )
        }
    }

    private func firstTableView(in view: NSView) -> NSTableView? {
        if let table = view as? NSTableView { return table }
        for sub in view.subviews {
            if let found = firstTableView(in: sub) { return found }
        }
        return nil
    }
}
