import XCTest
@testable import AgentDeck

@MainActor
final class InputBarPlanModeBadgeTests: XCTestCase {

    func testHiddenWhenCapabilitiesNil() {
        XCTAssertFalse(InputBarView.shouldShowPlanModeBadge(
            capabilities: nil, permissionMode: .plan))
    }

    func testHiddenWhenFeatureMissing() {
        // CC caps但去掉 planMode feature
        let caps = SessionCapabilities(
            agentKind: .claudeCode,
            agentVersion: "x",
            features: [.claudeCodePermissionMode],
            vendor: .claudeCode(ClaudeCodeCapabilities(
                permissionModes: [.default, .plan], outputStyles: [], hooksSupported: [], cliVersion: "1"
            ))
        )
        XCTAssertFalse(InputBarView.shouldShowPlanModeBadge(
            capabilities: caps, permissionMode: .plan))
    }

    func testHiddenWhenPermissionModeNotPlan() {
        XCTAssertFalse(InputBarView.shouldShowPlanModeBadge(
            capabilities: .ccStub(), permissionMode: .default))
        XCTAssertFalse(InputBarView.shouldShowPlanModeBadge(
            capabilities: .ccStub(), permissionMode: nil))
    }

    func testShownWhenFeatureAndPlanMode() {
        XCTAssertTrue(InputBarView.shouldShowPlanModeBadge(
            capabilities: .ccStub(), permissionMode: .plan))
    }

    func testHiddenForCodexCaps() {
        XCTAssertFalse(InputBarView.shouldShowPlanModeBadge(
            capabilities: .codexStub(), permissionMode: .plan))
    }
}
