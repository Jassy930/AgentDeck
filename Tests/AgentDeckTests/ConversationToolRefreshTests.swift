import AppKit
import AgentDeckCore
import XCTest
@testable import AgentDeck

@MainActor
final class ConversationToolRefreshTests: XCTestCase {
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
