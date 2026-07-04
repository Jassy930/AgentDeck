import XCTest
@testable import AgentDeck

@MainActor
final class PreviewBootstrapTests: XCTestCase {
    func testPreviewModelHasEnvironmentInfoAndLoadsMockHistory() {
        let model = PreviewBootstrap.makeSessionModel()
        XCTAssertEqual(model.environmentInfo?.branch, "main")
        // 走真实 loadHistory → 真实 DaemonClient → MockDaemonTransport → 真实解码。
        model.loadHistory()
        XCTAssertFalse(model.historyGroups.isEmpty, "preview 应通过真实链路加载到 mock 历史")
        XCTAssertNil(model.historyErrorMessage)
    }
}
