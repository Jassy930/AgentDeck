import XCTest
import AppKit
@testable import AgentDeck

@MainActor
final class EnvironmentPanelSmokeTests: XCTestCase {
    func testConstructsWithModelAndRendersChanges() {
        let model = SessionModel(turnStarter: NoopRuntimeTurnStarter())
        model.environmentInfo = EnvironmentInfo(added: 128, removed: 34, fileCount: 3, branch: "main", commit: "a1b2c3d")
        let panel = CodexEnvironmentPanelView(model: model)
        panel.layoutSubtreeIfNeeded()
        // 面板把 changesSummary 暴露给测试断言（accessibilityIdentifier 承载）。
        let labels = panel.allLabelsForTest()
        XCTAssertTrue(labels.contains("+128 -34"), "应渲染带符号的变更统计")
        XCTAssertTrue(labels.contains("main"), "应渲染分支名")
        XCTAssertTrue(labels.contains("a1b2c3d"), "应渲染提交短哈希")
    }
}
