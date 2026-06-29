import XCTest
@testable import AgentDeck

/// Covers the reload-strategy decision (root-cause fix for C1/C2): a pure
/// streaming-text growth must NOT trigger a full reload, only height
/// re-measurement; structural changes fall back to a reload.
final class ConversationReloadStrategyTests: XCTestCase {

    // MARK: - Pure diff decision

    func testIdenticalSignaturesReportNoChange() {
        let prev = [(id: "a", version: 1), (id: "b", version: 2)]
        let diff = ConversationRowsDiff.decide(previous: prev, next: prev)
        XCTAssertEqual(diff, .sameRows(changedIndexes: []))
    }

    func testPureTextGrowthIsSameRowsWithOnlyChangedIndexes() {
        // Same ids; the second row's text grew (version bumped) → only that row
        // needs re-measuring, and NO full reload. This is the streaming flush
        // case that previously collapsed disclosures (C1) and wiped selection (C2).
        let prev = [(id: "a", version: 1), (id: "b", version: 2)]
        let next = [(id: "a", version: 1), (id: "b", version: 9)]
        let diff = ConversationRowsDiff.decide(previous: prev, next: next)
        XCTAssertEqual(diff, .sameRows(changedIndexes: [1]))
    }

    func testMultipleVersionBumpsReportAllChangedIndexes() {
        let prev = [(id: "a", version: 1), (id: "b", version: 2), (id: "c", version: 3)]
        let next = [(id: "a", version: 5), (id: "b", version: 2), (id: "c", version: 7)]
        let diff = ConversationRowsDiff.decide(previous: prev, next: next)
        XCTAssertEqual(diff, .sameRows(changedIndexes: [0, 2]))
    }

    func testAppendedRowIsStructural() {
        let prev = [(id: "a", version: 1)]
        let next = [(id: "a", version: 1), (id: "b", version: 1)]
        XCTAssertEqual(ConversationRowsDiff.decide(previous: prev, next: next), .structural)
    }

    func testRemovedRowIsStructural() {
        let prev = [(id: "a", version: 1), (id: "b", version: 1)]
        let next = [(id: "a", version: 1)]
        XCTAssertEqual(ConversationRowsDiff.decide(previous: prev, next: next), .structural)
    }

    func testReorderedRowsAreStructural() {
        let prev = [(id: "a", version: 1), (id: "b", version: 1)]
        let next = [(id: "b", version: 1), (id: "a", version: 1)]
        XCTAssertEqual(ConversationRowsDiff.decide(previous: prev, next: next), .structural)
    }

    func testEmptyToEmptyIsSameRows() {
        let diff = ConversationRowsDiff.decide(previous: [], next: [])
        XCTAssertEqual(diff, .sameRows(changedIndexes: []))
    }
}
