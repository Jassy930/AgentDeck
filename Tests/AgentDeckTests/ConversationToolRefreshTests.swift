import AppKit
import AgentDeckCore
import XCTest
@testable import AgentDeck

@MainActor
final class ConversationToolRefreshTests: XCTestCase {
    private func readTool(_ id: String, status: String) -> UIItem {
        var item = UIItem(id: id, lifecycle: "completed", kind: "toolCall")
        item.tool = "Read"
        item.statusName = status
        return item
    }

    func testStableToolCallRowReconfiguresFromRunningToTerminalState() throws {
        let model = SessionModel(turnStarter: NoopRuntimeTurnStarter())
        let user = UIItem(
            id: "user-1",
            lifecycle: "completed",
            kind: "user",
            text: "检查窗口"
        )
        var running = UIItem(
            id: "tool-stable",
            lifecycle: "completed",
            kind: "toolCall"
        )
        running.server = "node_repl"
        running.tool = "js"
        running.arguments = #"{"title":"确认 AgentDeck 窗口"}"#
        running.statusName = "running"
        model.items = [user, running]

        let controller = ConversationViewController(model: model)
        let window = NSWindow(contentViewController: controller)
        window.setContentSize(NSSize(width: 720, height: 520))
        window.makeKeyAndOrderFront(nil)
        defer { window.close() }
        RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.05))

        let table = try XCTUnwrap(firstTableView(in: controller.view))
        table.reloadData()
        let initialCell = try XCTUnwrap(
            table.view(atColumn: 0, row: 1, makeIfNecessary: true) as? ToolCallCellView
        )
        XCTAssertTrue(visibleLabels(in: initialCell).contains("进行中"))

        var completed = running
        completed.statusName = "completed"
        completed.durationMs = 136
        completed.result = #"{"success":true}"#
        completed.success = true
        model.items = [user, completed]
        RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.1))

        let terminalCell = try XCTUnwrap(
            table.view(atColumn: 0, row: 1, makeIfNecessary: true) as? ToolCallCellView
        )
        let labels = visibleLabels(in: terminalCell)
        XCTAssertTrue(labels.contains("已完成 · 136ms"))
        XCTAssertFalse(labels.contains("进行中"), "同 ID 的终态不能残留旧状态")
    }

    func testCollaborationActivityRefreshesItsEventDescriptionInPlace() throws {
        let model = SessionModel(turnStarter: NoopRuntimeTurnStarter())
        let user = UIItem(
            id: "user-collaboration",
            lifecycle: "completed",
            kind: "user",
            text: "检查子任务"
        )
        var started = UIItem(
            id: "activity-stable",
            lifecycle: "completed",
            kind: "toolCall"
        )
        started.tool = "Tool ui trace"
        started.activityKind = "collaboration"
        started.activityEvent = "started"
        model.items = [user, started]

        let controller = ConversationViewController(model: model)
        let window = NSWindow(contentViewController: controller)
        window.setContentSize(NSSize(width: 720, height: 520))
        window.makeKeyAndOrderFront(nil)
        defer { window.close() }
        RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.05))

        let table = try XCTUnwrap(firstTableView(in: controller.view))
        table.reloadData()
        XCTAssertEqual(table.numberOfRows, 2)
        let initialCell = try XCTUnwrap(
            table.view(atColumn: 0, row: 1, makeIfNecessary: true) as? ToolCallCellView
        )
        XCTAssertTrue(visibleLabels(in: initialCell).contains("已开始工作"))

        var interacted = started
        interacted.activityEvent = "interacted"
        model.items = [user, interacted]
        RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.1))

        XCTAssertEqual(table.numberOfRows, 2)
        let updatedCell = try XCTUnwrap(
            table.view(atColumn: 0, row: 1, makeIfNecessary: true) as? ToolCallCellView
        )
        let labels = visibleLabels(in: updatedCell)
        XCTAssertTrue(labels.contains("已更新"))
        XCTAssertFalse(labels.contains("已开始工作"))
    }

    func testStableCollapsedGroupRefreshesCountAndFailureThenKeepsExpansionOnAppend() throws {
        let model = SessionModel(turnStarter: NoopRuntimeTurnStarter())
        let user = UIItem(
            id: "user-group-live",
            lifecycle: "completed",
            kind: "user",
            text: "检查文件"
        )
        let first = readTool("read-1", status: "completed")
        let second = readTool("read-2", status: "completed")
        model.items = [user, first, second]

        let controller = ConversationViewController(model: model)
        let window = NSWindow(contentViewController: controller)
        window.setContentSize(NSSize(width: 720, height: 520))
        window.makeKeyAndOrderFront(nil)
        defer { window.close() }
        RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.05))

        let table = try XCTUnwrap(firstTableView(in: controller.view))
        table.reloadData()
        XCTAssertEqual(table.numberOfRows, 2)
        let initial = try XCTUnwrap(
            table.view(atColumn: 0, row: 1, makeIfNecessary: true) as? ToolActivityGroupCellView
        )
        XCTAssertTrue(visibleLabels(in: initial).contains("2 项 · 已完成"))

        var failed = readTool("read-3", status: "failed")
        failed.errorText = "permission denied"
        model.items = [user, first, second, failed]
        RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.1))

        XCTAssertEqual(table.numberOfRows, 2, "折叠组追加成员时 row 序列应保持稳定")
        let updated = try XCTUnwrap(
            table.view(atColumn: 0, row: 1, makeIfNecessary: true) as? ToolActivityGroupCellView
        )
        let labels = visibleLabels(in: updated)
        XCTAssertTrue(labels.contains("读取 3 个文件"))
        XCTAssertTrue(labels.contains("3 项 · 1 项失败"))

        let groupId = "tool-group:user-group-live:read-1"
        let store = controller as ConversationDisclosureStateStore
        store.setItem(groupId, expanded: true)
        XCTAssertEqual(table.numberOfRows, 5)

        let fourth = readTool("read-4", status: "completed")
        model.items = [user, first, second, failed, fourth]
        RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.1))

        XCTAssertTrue(store.isItemExpanded(groupId))
        XCTAssertEqual(
            table.numberOfRows,
            6,
            "展开组追加成员时应结构化恢复新的原始行"
        )
    }

    private func firstTableView(in view: NSView) -> NSTableView? {
        if let table = view as? NSTableView { return table }
        for subview in view.subviews {
            if let table = firstTableView(in: subview) { return table }
        }
        return nil
    }

    private func visibleLabels(in view: NSView) -> [String] {
        view.allDescendants(ofType: NSTextField.self)
            .filter { !$0.isHidden }
            .map(\.stringValue)
    }
}
