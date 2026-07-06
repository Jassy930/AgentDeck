import XCTest
@testable import AgentDeck

/// `AGENTDECK_PREVIEW_SCREEN`（1-based）→ 0-based 屏下标的解析。
@MainActor
final class PreviewScreenConfigTests: XCTestCase {
    func testValidIndexWithinRange() {
        XCTAssertEqual(AppDelegate.previewScreenIndex("2", screenCount: 2), 1)
        XCTAssertEqual(AppDelegate.previewScreenIndex("1", screenCount: 2), 0)
        XCTAssertEqual(AppDelegate.previewScreenIndex(" 2 ", screenCount: 3), 1)
    }

    func testUnsetOrInvalidReturnsNil() {
        XCTAssertNil(AppDelegate.previewScreenIndex(nil, screenCount: 2))
        XCTAssertNil(AppDelegate.previewScreenIndex("", screenCount: 2))
        XCTAssertNil(AppDelegate.previewScreenIndex("0", screenCount: 2))
        XCTAssertNil(AppDelegate.previewScreenIndex("abc", screenCount: 2))
    }

    func testOutOfRangeReturnsNil() {
        // 只有 1 块屏时请求第 2 块 → nil（回落主屏居中）。
        XCTAssertNil(AppDelegate.previewScreenIndex("2", screenCount: 1))
    }
}
