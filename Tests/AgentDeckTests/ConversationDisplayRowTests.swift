import XCTest
import AgentDeckCore
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
        var assistantItem2 = UIItem(
            id: "item-assistant-2",
            lifecycle: "completed",
            kind: "shell"
        )
        assistantItem2.command = "ls -la"
        // makeConversationTurns groups by "user" kind boundary.
        let items: [UIItem] = [userItem, assistantItem1, assistantItem2]
        return makeConversationTurns(from: items)
    }
}

// MARK: - Tests

final class ConversationDisplayRowTests: XCTestCase {

    private func tool(_ id: String, name: String = "Read") -> UIItem {
        var item = UIItem(id: id, lifecycle: "completed", kind: "toolCall")
        item.tool = name
        item.statusName = "completed"
        return item
    }

    private func collaboration(
        _ id: String,
        task: String,
        event: String = "interacted"
    ) -> UIItem {
        var item = UIItem(id: id, lifecycle: "completed", kind: "toolCall")
        item.tool = task
        item.activityKind = "collaboration"
        item.activityEvent = event
        return item
    }

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

    func testToolGroupingDefaultsOffForSharedAndIOSCallers() {
        let turn = ConversationTurn(
            id: "turn-default",
            user: nil,
            assistantItems: [tool("t1"), tool("t2")]
        )

        let rows = ConversationDisplayRowBuilder.rows(from: [turn])

        XCTAssertEqual(rows.map(\.item.id), ["t1", "t2"])
        XCTAssertTrue(rows.allSatisfy { $0.toolActivityGroup == nil })
    }

    func testTwoConsecutiveToolActivitiesCollapseIntoOneStableSummaryRow() throws {
        let turn = ConversationTurn(
            id: "turn-group",
            user: nil,
            assistantItems: [tool("t1"), tool("t2", name: "Grep")]
        )

        let rows = ConversationDisplayRowBuilder.rows(
            from: [turn],
            toolGrouping: .consecutiveActivity
        )

        XCTAssertEqual(rows.count, 1)
        let group = try XCTUnwrap(rows[0].toolActivityGroup)
        XCTAssertEqual(group.activityItems.map(\.id), ["t1", "t2"])
        XCTAssertEqual(group.disclosureId, "tool-group:turn-group:t1")
        XCTAssertEqual(rows[0].presentationKind, "toolActivityGroup")
        XCTAssertTrue(rows[0].firstInTurn)
        XCTAssertTrue(rows[0].lastInTurn)
    }

    func testReasoningBetweenToolActivitiesIsPreservedInsideGroup() throws {
        let reasoning = UIItem(
            id: "r-middle",
            lifecycle: "completed",
            kind: "reasoning",
            text: "检查下一步"
        )
        let turn = ConversationTurn(
            id: "turn-reasoning",
            user: nil,
            assistantItems: [tool("t1"), reasoning, tool("t2")]
        )

        let rows = ConversationDisplayRowBuilder.rows(
            from: [turn],
            toolGrouping: .consecutiveActivity
        )

        let group = try XCTUnwrap(rows.first?.toolActivityGroup)
        XCTAssertEqual(group.members.map(\.id), ["t1", "r-middle", "t2"])
        XCTAssertEqual(group.activityItems.map(\.id), ["t1", "t2"])
    }

    func testLeadingAndTrailingReasoningRemainOutsideCollapsedGroup() throws {
        let leading = UIItem(id: "r-leading", lifecycle: "completed", kind: "reasoning")
        let middle = UIItem(id: "r-middle", lifecycle: "completed", kind: "reasoning")
        let trailing = UIItem(id: "r-trailing", lifecycle: "completed", kind: "reasoning")
        let turn = ConversationTurn(
            id: "turn-trim",
            user: nil,
            assistantItems: [leading, tool("t1"), middle, tool("t2"), trailing]
        )

        let rows = ConversationDisplayRowBuilder.rows(
            from: [turn],
            toolGrouping: .consecutiveActivity
        )

        XCTAssertEqual(rows.count, 3)
        XCTAssertEqual(rows[0].item.id, "r-leading")
        XCTAssertNotNil(rows[1].toolActivityGroup)
        XCTAssertEqual(rows[2].item.id, "r-trailing")
        XCTAssertEqual(try XCTUnwrap(rows[1].toolActivityGroup).members.map(\.id), ["t1", "r-middle", "t2"])
    }

    func testMessageAndTurnBoundariesPreventGrouping() {
        let message = UIItem(
            id: "message",
            lifecycle: "completed",
            kind: "message",
            text: "阶段说明"
        )
        let firstTurn = ConversationTurn(
            id: "turn-boundary-1",
            user: nil,
            assistantItems: [tool("t1"), message, tool("t2")]
        )
        let secondTurn = ConversationTurn(
            id: "turn-boundary-2",
            user: nil,
            assistantItems: [tool("t3")]
        )

        let rows = ConversationDisplayRowBuilder.rows(
            from: [firstTurn, secondTurn],
            toolGrouping: .consecutiveActivity
        )

        XCTAssertEqual(rows.map(\.item.id), ["t1", "message", "t2", "t3"])
        XCTAssertTrue(rows.allSatisfy { $0.toolActivityGroup == nil })
    }

    func testNeutralCollaborationActivityPreventsCrossBoundaryGrouping() {
        var collaboration = tool("collab", name: "spawnAgent")
        collaboration.activityKind = "collaboration"
        let turn = ConversationTurn(
            id: "turn-collaboration-boundary",
            user: nil,
            assistantItems: [tool("t1"), collaboration, tool("t2")]
        )

        let rows = ConversationDisplayRowBuilder.rows(
            from: [turn],
            toolGrouping: .consecutiveActivity
        )

        XCTAssertEqual(rows.map(\.item.id), ["t1", "collab", "t2"])
        XCTAssertTrue(rows.allSatisfy { $0.toolActivityGroup == nil })
    }

    func testSameTaskCollaborationEventsFoldInterveningReasoningIntoOneGroup() throws {
        let firstReasoning = UIItem(
            id: "r-1", lifecycle: "completed", kind: "reasoning", text: "检查实现"
        )
        let secondReasoning = UIItem(
            id: "r-2", lifecycle: "completed", kind: "reasoning", text: "继续复核"
        )
        let turn = ConversationTurn(
            id: "turn-collaboration-group",
            user: nil,
            assistantItems: [
                collaboration("c-1", task: "B3a2a implement", event: "started"),
                firstReasoning,
                collaboration("c-2", task: "B3a2a implement"),
                secondReasoning,
                collaboration("c-3", task: "B3a2a implement"),
            ]
        )

        let rows = ConversationDisplayRowBuilder.rows(
            from: [turn],
            toolGrouping: .consecutiveActivity
        )

        XCTAssertEqual(rows.count, 1)
        let group = try XCTUnwrap(rows[0].toolActivityGroup)
        XCTAssertEqual(group.members.map(\.id), ["c-1", "r-1", "c-2", "r-2", "c-3"])
        XCTAssertEqual(group.activityItems.map(\.id), ["c-1", "c-2", "c-3"])
    }

    func testDifferentCollaborationTasksRemainVisibleBoundaries() throws {
        let between = UIItem(
            id: "r-between", lifecycle: "completed", kind: "reasoning", text: "切换审计"
        )
        let turn = ConversationTurn(
            id: "turn-collaboration-boundaries",
            user: nil,
            assistantItems: [
                collaboration("b-1", task: "B3a2a implement"),
                collaboration("b-2", task: "B3a2a implement"),
                between,
                collaboration("relay", task: "Relay plan audit", event: "interrupted"),
                collaboration("b-3", task: "B3a2a implement"),
                collaboration("b-4", task: "B3a2a implement"),
            ]
        )

        let rows = ConversationDisplayRowBuilder.rows(
            from: [turn],
            toolGrouping: .consecutiveActivity
        )

        XCTAssertEqual(rows.count, 4)
        XCTAssertEqual(try XCTUnwrap(rows[0].toolActivityGroup).activityItems.map(\.id), ["b-1", "b-2"])
        XCTAssertEqual(rows[1].item.id, "r-between")
        XCTAssertEqual(rows[2].item.id, "relay")
        XCTAssertNil(rows[2].toolActivityGroup)
        XCTAssertEqual(try XCTUnwrap(rows[3].toolActivityGroup).activityItems.map(\.id), ["b-3", "b-4"])
    }

    func testExpandingGroupRestoresOriginalRowsInOrderAndBoundaries() throws {
        let reasoning = UIItem(id: "r1", lifecycle: "completed", kind: "reasoning")
        let turn = ConversationTurn(
            id: "turn-expanded",
            user: nil,
            assistantItems: [tool("t1"), reasoning, tool("t2")]
        )
        let disclosureId = "tool-group:turn-expanded:t1"

        let rows = ConversationDisplayRowBuilder.rows(
            from: [turn],
            toolGrouping: .consecutiveActivity,
            expandedToolGroupIds: [disclosureId]
        )

        XCTAssertEqual(rows.count, 4)
        XCTAssertEqual(try XCTUnwrap(rows[0].toolActivityGroup).disclosureId, disclosureId)
        XCTAssertEqual(rows.dropFirst().map(\.item.id), ["t1", "r1", "t2"])
        XCTAssertEqual(Set(rows.map(\.id)).count, rows.count)
        XCTAssertTrue(rows[0].firstInTurn)
        XCTAssertFalse(rows[0].lastInTurn)
        XCTAssertTrue(rows[3].lastInTurn)
    }

    func testAppendingActivityKeepsGroupAndDisclosureIdentityStable() throws {
        let first = ConversationTurn(
            id: "turn-live",
            user: nil,
            assistantItems: [tool("t1"), tool("t2")]
        )
        let appended = ConversationTurn(
            id: "turn-live",
            user: nil,
            assistantItems: [tool("t1"), tool("t2"), tool("t3")]
        )

        let before = try XCTUnwrap(ConversationDisplayRowBuilder.rows(
            from: [first], toolGrouping: .consecutiveActivity
        ).first)
        let after = try XCTUnwrap(ConversationDisplayRowBuilder.rows(
            from: [appended], toolGrouping: .consecutiveActivity
        ).first)

        XCTAssertEqual(before.id, after.id)
        XCTAssertEqual(before.toolActivityGroup?.disclosureId, after.toolActivityGroup?.disclosureId)
        XCTAssertEqual(after.toolActivityGroup?.activityItems.count, 3)
    }
}
