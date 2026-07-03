import XCTest
import AgentDeckCore
@testable import AgentDeckMobile

@MainActor
final class SessionDetailViewModelTests: XCTestCase {
    private func makeVM(_ sessionID: String) -> SessionDetailViewModel {
        let source = FixtureSessionSource(bundle: Bundle(for: MachineListViewController.self), tickScale: 0)
        return SessionDetailViewModel(source: source, sessionID: sessionID)
    }

    func testCodexStreamProducesRows() async {
        let vm = makeVM("sess-codex-01")
        let done = expectation(description: "stream done")
        vm.onUpdate = { if !vm.isStreaming { done.fulfill() } }
        vm.start()
        await fulfillment(of: [done], timeout: 3)
        // i1 user + i2 reasoning + i3 shell + i4 assistant(累积成 1 行) + i5 diff = 5 行
        XCTAssertEqual(vm.rows.count, 5)
        XCTAssertEqual(vm.rows.first?.role, .userPrompt)
        // 三次 i4 事件应累积在同一行（cumulative 语义）
        let messageRows = vm.rows.filter { $0.item.kind == "message" }
        XCTAssertEqual(messageRows.count, 1)
        XCTAssertTrue(messageRows[0].item.text.hasSuffix("避免雪崩重连。"))
    }

    func testApprovalSurfacesAndResolves() async {
        let vm = makeVM("sess-approval-01")
        let pending = expectation(description: "pending approval")
        vm.onUpdate = { if vm.approvalState == .pending { pending.fulfill() } }
        vm.start()
        await fulfillment(of: [pending], timeout: 3)
        XCTAssertEqual(vm.pendingApproval?.summary, "uv run alembic upgrade head")
        let done = expectation(description: "stream done after approve")
        vm.onUpdate = { if !vm.isStreaming { done.fulfill() } }
        vm.resolveApproval(approve: true)
        await fulfillment(of: [done], timeout: 3)
        XCTAssertEqual(vm.approvalState, .approved)
        XCTAssertEqual(vm.rows.count, 3) // user + shell + assistant
    }

    func testErrorSurfaces() async {
        let vm = makeVM("sess-failed-01")
        let errored = expectation(description: "error surfaced")
        vm.onUpdate = { if vm.errorText != nil { errored.fulfill() } }
        vm.start()
        await fulfillment(of: [errored], timeout: 3)
        XCTAssertTrue(vm.errorText?.contains("peer dependency") == true)
    }
}
