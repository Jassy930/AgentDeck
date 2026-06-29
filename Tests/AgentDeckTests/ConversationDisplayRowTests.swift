import XCTest
@testable import AgentDeck

// MARK: - Test support

enum ConversationDisplayRowTestSupport {
    /// One turn: 1 user item + 2 assistant items → 3 rows total.
    static func sampleTurns() -> [ConversationTurn] {
        let userItem = UIItem(
            id: "item-user-1",
            lifecycle: "completed",
            kind: "user",
            text: "Hello, agent"
        )
        let assistantItem1 = UIItem(
            id: "item-assistant-1",
            lifecycle: "completed",
            kind: "reasoning",
            text: "Thinking..."
        )
        let assistantItem2 = UIItem(
            id: "item-assistant-2",
            lifecycle: "completed",
            kind: "shell",
            command: "ls -la"
        )
        // makeConversationTurns groups by "user" kind boundary.
        let items: [UIItem] = [userItem, assistantItem1, assistantItem2]
        return makeConversationTurns(from: items)
    }
}

// MARK: - Tests

final class ConversationDisplayRowTests: XCTestCase {

    func testUserThenAssistantItemsFlattenInOrderWithBoundaries() {
        let turns = ConversationDisplayRowTestSupport.sampleTurns()
        let rows = ConversationDisplayRowBuilder.rows(from: turns)

        XCTAssertEqual(rows.count, 3)
        XCTAssertTrue(rows[0].firstInTurn)
        XCTAssertTrue(rows[2].lastInTurn)
        XCTAssertEqual(
            rows.map(\.turnId).filter { $0 == rows[0].turnId }.count,
            3,
            "同一 turn 的行 turnId 一致"
        )
        // id 唯一
        XCTAssertEqual(Set(rows.map(\.id)).count, rows.count)
    }

    func testUserPromptRoleIsFirst() {
        let turns = ConversationDisplayRowTestSupport.sampleTurns()
        let rows = ConversationDisplayRowBuilder.rows(from: turns)

        XCTAssertEqual(rows[0].role, .userPrompt)
    }

    func testAssistantItemsFollowUserPrompt() {
        let turns = ConversationDisplayRowTestSupport.sampleTurns()
        let rows = ConversationDisplayRowBuilder.rows(from: turns)

        XCTAssertEqual(rows[1].role, .assistantItem)
        XCTAssertEqual(rows[2].role, .assistantItem)
    }

    func testMiddleRowIsNeitherFirstNorLast() {
        let turns = ConversationDisplayRowTestSupport.sampleTurns()
        let rows = ConversationDisplayRowBuilder.rows(from: turns)

        XCTAssertFalse(rows[1].firstInTurn)
        XCTAssertFalse(rows[1].lastInTurn)
    }

    func testFirstRowIsNotLast() {
        let turns = ConversationDisplayRowTestSupport.sampleTurns()
        let rows = ConversationDisplayRowBuilder.rows(from: turns)

        XCTAssertFalse(rows[0].lastInTurn)
    }

    func testLastRowIsNotFirst() {
        let turns = ConversationDisplayRowTestSupport.sampleTurns()
        let rows = ConversationDisplayRowBuilder.rows(from: turns)

        XCTAssertFalse(rows[2].firstInTurn)
    }

    func testEmptyTurnsProducesNoRows() {
        let rows = ConversationDisplayRowBuilder.rows(from: [])
        XCTAssertTrue(rows.isEmpty)
    }

    func testTurnWithOnlyAssistantItemsNoUserPrompt() {
        // A turn that has no user item (assistant-only).
        let assistantItem = UIItem(
            id: "item-a1",
            lifecycle: "completed",
            kind: "reasoning",
            text: "autonomous reasoning"
        )
        // Construct directly without going through makeConversationTurns
        // (which would create a turn with no user).
        let turn = ConversationTurn(id: "turn-x", user: nil, assistantItems: [assistantItem])
        let rows = ConversationDisplayRowBuilder.rows(from: [turn])

        XCTAssertEqual(rows.count, 1)
        XCTAssertEqual(rows[0].role, .assistantItem)
        XCTAssertTrue(rows[0].firstInTurn)
        XCTAssertTrue(rows[0].lastInTurn)
    }

    func testMultipleTurnsEachHaveIndependentBoundaries() {
        let turn1 = ConversationTurn(
            id: "turn-1",
            user: UIItem(id: "u1", lifecycle: "completed", kind: "user", text: "Q1"),
            assistantItems: [
                UIItem(id: "a1", lifecycle: "completed", kind: "reasoning", text: "A1")
            ]
        )
        let turn2 = ConversationTurn(
            id: "turn-2",
            user: UIItem(id: "u2", lifecycle: "completed", kind: "user", text: "Q2"),
            assistantItems: [
                UIItem(id: "a2", lifecycle: "completed", kind: "reasoning", text: "A2")
            ]
        )
        let rows = ConversationDisplayRowBuilder.rows(from: [turn1, turn2])

        XCTAssertEqual(rows.count, 4)

        // turn1 boundaries
        XCTAssertTrue(rows[0].firstInTurn)
        XCTAssertFalse(rows[0].lastInTurn)
        XCTAssertFalse(rows[1].firstInTurn)
        XCTAssertTrue(rows[1].lastInTurn)

        // turn2 boundaries
        XCTAssertTrue(rows[2].firstInTurn)
        XCTAssertFalse(rows[2].lastInTurn)
        XCTAssertFalse(rows[3].firstInTurn)
        XCTAssertTrue(rows[3].lastInTurn)

        // turnIds are isolated per turn
        XCTAssertEqual(rows[0].turnId, rows[1].turnId)
        XCTAssertEqual(rows[2].turnId, rows[3].turnId)
        XCTAssertNotEqual(rows[0].turnId, rows[2].turnId)
    }
}
