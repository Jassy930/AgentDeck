import XCTest
import AppKit
@testable import AgentDeck

// MARK: - Test support
//
// `ConversationDisplayRowTestSupport` already exists (ConversationDisplayRowTests.swift).
// Extend it here with row builders tailored to the factory's dispatch surface:
// one real `ConversationDisplayRow` per role, plus per-kind assistant rows.

extension ConversationDisplayRowTestSupport {

    /// A single user-prompt row.
    static func userPromptRow(text: String = "Hello, agent") -> ConversationDisplayRow {
        let item = UIItem(id: "u-1", lifecycle: "completed", kind: "user", text: text)
        let turn = ConversationTurn(id: "turn-u", user: item, assistantItems: [])
        return ConversationDisplayRowBuilder.rows(from: [turn])[0]
    }

    /// A single assistant "message" row.
    static func messageRow(text: String = "hi") -> ConversationDisplayRow {
        assistantRow(kind: "message", text: text)
    }

    /// A single assistant row for an arbitrary kind. `configure*` closure lets
    /// callers populate kind-specific fields.
    static func assistantRow(
        kind: String,
        text: String = "",
        configure: (inout UIItem) -> Void = { _ in }
    ) -> ConversationDisplayRow {
        var item = UIItem(id: "a-\(kind)", lifecycle: "completed", kind: kind, text: text)
        item.textBuffer.replace(with: text)
        configure(&item)
        let turn = ConversationTurn(id: "turn-\(kind)", user: nil, assistantItems: [item])
        return ConversationDisplayRowBuilder.rows(from: [turn])[0]
    }

    /// One real row for the userPrompt role and one for the assistantItem role.
    static func oneOfEachRole() -> [ConversationDisplayRow] {
        [userPromptRow(), messageRow(text: "hi")]
    }

    /// One row per distinct assistant kind the factory dispatches on (excludes
    /// approval — that's Task 8 and not a DisplayRow kind).
    static func oneOfEachAssistantKind() -> [ConversationDisplayRow] {
        let kinds = [
            "message", "reasoning", "shell", "fileEdit", "webSearch",
            "plan", "hookPrompt", "toolCall", "collabAgentToolCall",
            "media", "reviewMode", "contextCompaction", "raw",
        ]
        return kinds.map { assistantRow(kind: $0, text: "text") }
    }
}

// MARK: - Tests

@MainActor
final class ConversationRowFactoryTests: XCTestCase {

    func testReuseIdentifierDiffersByRole() {
        let rows = ConversationDisplayRowTestSupport.oneOfEachRole()
        let ids = Set(rows.map { ConversationRowFactory.reuseIdentifier(for: $0).rawValue })
        XCTAssertEqual(ids.count, rows.count, "不同 role 的 reuse id 应不同")
    }

    func testReuseIdentifierDiffersByAssistantKind() {
        let rows = ConversationDisplayRowTestSupport.oneOfEachAssistantKind()
        let ids = Set(rows.map { ConversationRowFactory.reuseIdentifier(for: $0).rawValue })
        XCTAssertEqual(ids.count, rows.count, "不同 assistant kind 的 reuse id 应不同")
    }

    func testUserPromptIdentifierDiffersFromAssistantMessage() {
        let user = ConversationDisplayRowTestSupport.userPromptRow()
        let message = ConversationDisplayRowTestSupport.messageRow()
        XCTAssertNotEqual(
            ConversationRowFactory.reuseIdentifier(for: user),
            ConversationRowFactory.reuseIdentifier(for: message)
        )
    }

    func testMakeCellMatchesIdentifierType() {
        let row = ConversationDisplayRowTestSupport.messageRow(text: "hi")
        let cell = ConversationRowFactory.makeCell(for: row)
        XCTAssertEqual(cell.identifier, ConversationRowFactory.reuseIdentifier(for: row))
    }

    func testMakeCellSetsIdentifierForEveryAssistantKind() {
        for row in ConversationDisplayRowTestSupport.oneOfEachAssistantKind() {
            let cell = ConversationRowFactory.makeCell(for: row)
            XCTAssertEqual(
                cell.identifier,
                ConversationRowFactory.reuseIdentifier(for: row),
                "kind=\(row.item.kind) 的 cell identifier 应与 reuseIdentifier 一致"
            )
        }
    }

    func testMakeUserPromptCellIsUserPromptCellView() {
        let row = ConversationDisplayRowTestSupport.userPromptRow()
        let cell = ConversationRowFactory.makeCell(for: row)
        XCTAssertTrue(cell is UserPromptCellView)
    }

    func testHeightIsPositiveForMessage() {
        let row = ConversationDisplayRowTestSupport.messageRow(text: "hello world")
        XCTAssertGreaterThan(ConversationRowFactory.height(for: row, width: 400), 0)
    }

    func testHeightIsPositiveForEveryAssistantKind() {
        for row in ConversationDisplayRowTestSupport.oneOfEachAssistantKind() {
            XCTAssertGreaterThan(
                ConversationRowFactory.height(for: row, width: 400),
                0,
                "kind=\(row.item.kind) 的高度应为正"
            )
        }
    }

    func testHeightGrowsWithLongerMessage() {
        let shortRow = ConversationDisplayRowTestSupport.messageRow(text: "short")
        let longRow = ConversationDisplayRowTestSupport.messageRow(
            text: String(repeating: "wrap this text many times ", count: 60)
        )
        let shortHeight = ConversationRowFactory.height(for: shortRow, width: 300)
        let longHeight = ConversationRowFactory.height(for: longRow, width: 300)
        XCTAssertGreaterThan(longHeight, shortHeight, "更长的 message 应占更高的行")
    }

    func testCollapsedShellHeightAccountsForHeaderOnly() {
        // Shell output collapses by default: a huge output must NOT inflate the
        // collapsed row height (header + metadata only).
        let row = ConversationDisplayRowTestSupport.assistantRow(kind: "shell") { item in
            item.command = "ls -la"
            item.output = String(repeating: "line of output\n", count: 200)
            item.outputBuffer.replace(with: item.output)
        }
        let height = ConversationRowFactory.height(for: row, width: 400)
        XCTAssertGreaterThan(height, 0)
        // The collapsed height must be far smaller than the full output would be.
        XCTAssertLessThan(height, 400, "折叠态 shell 行高应只计 header，不随 output 行数膨胀")
    }
}
