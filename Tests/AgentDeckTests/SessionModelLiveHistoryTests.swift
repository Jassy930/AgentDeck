import XCTest
@testable import AgentDeck

@MainActor
final class SessionModelLiveHistoryTests: XCTestCase {
    func testSubmittingNewLiveSessionAddsCurrentSessionToHistoryGroups() throws {
        let model = SessionModel(turnStarter: NoopRuntimeTurnStarter())
        let cwd = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("agentdeck-live-history")
        try FileManager.default.createDirectory(at: cwd, withIntermediateDirectories: true)
        XCTAssertNil(model.chooseCwd(cwd))

        model.submit("hello from current session", agentKind: .codex)

        let threads = model.historyGroups.flatMap(\.threads)
        XCTAssertEqual(threads.count, 1)
        XCTAssertEqual(threads.first?.preview, "hello from current session")
        XCTAssertEqual(threads.first?.cwd, cwd.path)
        XCTAssertEqual(threads.first?.source, "live")
        XCTAssertEqual(threads.first?.agentKind, .codex)
        XCTAssertEqual(threads.first?.status, "starting")
        XCTAssertEqual(threads.first?.id, model.workbench.selectedSessionId)
    }
}
