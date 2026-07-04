import XCTest
@testable import AgentDeck

final class EnvironmentInfoTests: XCTestCase {
    func testChangesSummaryFormatsSignedCounts() {
        let info = EnvironmentInfo(added: 128, removed: 34, fileCount: 3, branch: "main", commit: "a1b2c3d")
        XCTAssertEqual(info.changesSummary, "+128 -34")
        XCTAssertEqual(info.fileCountSummary, "3 文件")
    }

    func testZeroChangesStillSigned() {
        let info = EnvironmentInfo(added: 0, removed: 0, fileCount: 0, branch: nil, commit: nil)
        XCTAssertEqual(info.changesSummary, "+0 -0")
        XCTAssertEqual(info.fileCountSummary, "0 文件")
    }
}
