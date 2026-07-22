import XCTest
@testable import AgentDeck

@MainActor
final class PreviewBootstrapTests: XCTestCase {
    func testPreviewModelHasEnvironmentInfoAndLoadsMockHistory() async {
        let model = PreviewBootstrap.makeSessionModel()
        XCTAssertEqual(model.environmentInfo?.branch, "main")
        // 走真实 loadHistory → 真实 DaemonClient → MockDaemonTransport → 真实解码。
        model.loadHistory()
        XCTAssertTrue(model.isLoadingHistory)
        let didFinish = await waitUntil { !model.isLoadingHistory }
        XCTAssertTrue(didFinish, "preview 历史异步加载应在超时前完成")
        XCTAssertFalse(model.historyGroups.isEmpty, "preview 应通过真实链路加载到 mock 历史")
        XCTAssertNil(model.historyErrorMessage)
    }
}
