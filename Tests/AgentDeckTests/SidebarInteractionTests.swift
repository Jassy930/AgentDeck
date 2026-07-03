import XCTest
import AppKit
import AgentDeckCore
@testable import AgentDeck

/// 端到端交互：侧栏选中 / 切换 / 历史。
/// 注入历史线程 → 组装真实侧栏 VC → 模拟选中行 → 断言模型选中态。
@MainActor
final class SidebarInteractionTests: XCTestCase {

    private func thread(_ id: String, _ name: String, cwd: String, status: String = "ready") -> HistoryThreadSummary {
        HistoryThreadSummary(id: id, name: name, preview: "preview \(name)", cwd: cwd,
                             createdAt: 0, updatedAt: 0, status: status,
                             modelProvider: "openai", source: "codex", agentKind: .codex)
    }

    private func makeSidebar(_ threads: [HistoryThreadSummary]) -> (HistorySidebarViewController, NSOutlineView, SessionModel) {
        let model = SessionModel()
        model.setHistoryThreads(threads)
        let vc = HistorySidebarViewController(model: model)
        _ = vc.view
        let ov = vc.view.firstDescendant(ofType: NSOutlineView.self)!
        ov.reloadData()
        ov.expandItem(nil, expandChildren: true)
        return (vc, ov, model)
    }

    private func row(of threadId: String, in ov: NSOutlineView) -> Int {
        for r in 0..<ov.numberOfRows where (ov.item(atRow: r) as? HistoryThreadSummary)?.id == threadId { return r }
        return -1
    }

    func testHistoryThreadsPopulateGroups() {
        let (_, ov, model) = makeSidebar([
            thread("t1", "拆分登录", cwd: "/p/refactor-auth"),
            thread("t2", "修复竞态", cwd: "/p/refactor-auth"),
            thread("t3", "补文档", cwd: "/p/agentdeck-docs"),
        ])
        XCTAssertEqual(model.historyGroups.count, 2, "两个项目目录应分成两组")
        XCTAssertGreaterThanOrEqual(ov.numberOfRows, 5, "两组 + 三线程应至少 5 行")
    }

    func testSelectingLiveThreadUpdatesSelection() {
        // live 运行时是同步选中路径（持久化历史线程走 daemon 异步打开）
        let model = SessionModel()
        model.workbench.ensureRuntime(sessionId: "live-1", agentKind: .codex, threadId: nil,
                                      cwd: URL(fileURLWithPath: "/p/refactor-auth"))
        let vc = HistorySidebarViewController(model: model)
        _ = vc.view
        let ov = vc.view.firstDescendant(ofType: NSOutlineView.self)!
        ov.reloadData(); ov.expandItem(nil, expandChildren: true)
        let r = row(of: "live-1", in: ov)
        XCTAssertGreaterThanOrEqual(r, 0, "live 运行时应作为会话行出现在侧栏")
        ov.selectRowIndexes(IndexSet(integer: r), byExtendingSelection: false)
        vc.outlineViewSelectionDidChange(Notification(name: NSOutlineView.selectionDidChangeNotification, object: ov))
        XCTAssertEqual(model.selectedSidebarThreadId, "live-1", "选中 live 会话行应同步更新模型选中态")
    }

    func testSelectingPersistedThreadWithoutDaemonIsSafeNoop() {
        // 记录行为：无 daemon 连接时点持久化历史线程是安全 no-op（不崩、选中不变）。
        // 生产有 daemon 时走异步 read 打开。
        let (vc, ov, model) = makeSidebar([thread("t1", "拆分登录", cwd: "/p/refactor-auth")])
        let r = row(of: "t1", in: ov)
        ov.selectRowIndexes(IndexSet(integer: r), byExtendingSelection: false)
        vc.outlineViewSelectionDidChange(Notification(name: NSOutlineView.selectionDidChangeNotification, object: ov))
        XCTAssertNil(model.selectedSidebarThreadId, "无 daemon 时持久线程点击不同步选中（异步打开待 daemon 返回）")
    }

    func testGroupRowIsNotSelectable() {
        let (vc, _, model) = makeSidebar([thread("t1", "A", cwd: "/p/proj")])
        let group = model.historyGroups.first!
        XCTAssertFalse(vc.outlineView(NSOutlineView(), shouldSelectItem: group), "项目组行不应可选")
        let t = thread("t1", "A", cwd: "/p/proj")
        XCTAssertTrue(vc.outlineView(NSOutlineView(), shouldSelectItem: t), "会话行应可选")
    }

    /// 渲染有数据的侧栏为 PNG，供人工核对真实呈现。
    func testRenderPopulatedSidebar() {
        let (vc, _, _) = makeSidebar([
            thread("t1", "把登录模块拆分为独立的 service 并补齐测试", cwd: "/p/refactor-auth", status: "running"),
            thread("t2", "修复 token 刷新的竞态条件", cwd: "/p/refactor-auth", status: "waiting"),
            thread("t3", "补充 README 的部署章节", cwd: "/p/agentdeck-docs", status: "done"),
        ])
        vc.view.renderPNG(to: "/tmp/adk-sidebar.png", size: NSSize(width: 236, height: 640))
    }
}
