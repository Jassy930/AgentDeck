import XCTest
import AppKit
@testable import AgentDeck

final class RowHeightCacheTests: XCTestCase {
    func testMeasuredHeightGrowsWithMoreText() {
        let short = NSAttributedString(string: "one line")
        let long = NSAttributedString(string: String(repeating: "wrap this text many times ", count: 50))
        let hShort = measuredTextHeight(short, width: 200)
        let hLong = measuredTextHeight(long, width: 200)
        XCTAssertGreaterThan(hLong, hShort)
    }

    func testCacheReturnsStoredValueUntilVersionOrWidthChanges() {
        let cache = RowHeightCache()
        var computeCount = 0
        let compute: () -> CGFloat = { computeCount += 1; return 42 }

        _ = cache.height(rowId: "r1", version: 1, width: 300, compute: compute)
        _ = cache.height(rowId: "r1", version: 1, width: 300, compute: compute)
        XCTAssertEqual(computeCount, 1, "同键应命中缓存")

        _ = cache.height(rowId: "r1", version: 2, width: 300, compute: compute) // version 变
        _ = cache.height(rowId: "r1", version: 2, width: 320, compute: compute) // width 变
        XCTAssertEqual(computeCount, 3)
    }

    func testInvalidateForcesRecompute() {
        let cache = RowHeightCache()
        var n = 0
        _ = cache.height(rowId: "r", version: 1, width: 10) { n += 1; return 1 }
        cache.invalidate(rowId: "r")
        _ = cache.height(rowId: "r", version: 1, width: 10) { n += 1; return 1 }
        XCTAssertEqual(n, 2)
    }
}
