import XCTest
import AppKit
import AgentDeckCore
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

    static func toolActivityGroupRow(count: Int = 2) -> ConversationDisplayRow {
        let tools = (0..<count).map { index -> UIItem in
            var item = UIItem(
                id: "group-tool-\(index)",
                lifecycle: "completed",
                kind: "toolCall"
            )
            item.tool = "Read"
            item.statusName = "completed"
            item.arguments = #"{"file_path":"/tmp/file.swift"}"#
            return item
        }
        let turn = ConversationTurn(id: "turn-group", user: nil, assistantItems: tools)
        return ConversationDisplayRowBuilder.rows(
            from: [turn],
            toolGrouping: .consecutiveActivity
        )[0]
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

    func testToolActivityGroupUsesDedicatedReuseIdentifierAndCell() {
        let row = ConversationDisplayRowTestSupport.toolActivityGroupRow()
        let cell = ConversationRowFactory.makeCell(for: row)

        XCTAssertEqual(
            ConversationRowFactory.reuseIdentifier(for: row).rawValue,
            "assistant.toolActivityGroup"
        )
        XCTAssertTrue(cell is ToolActivityGroupCellView)
    }

    func testNeutralContextMaintenanceUsesExistingCompactSystemCell() throws {
        var item = UIItem(
            id: "maintenance-1",
            lifecycle: "completed",
            kind: "toolCall"
        )
        item.activityKind = "contextMaintenance"
        let row = ConversationDisplayRow(
            role: .assistantItem,
            turnId: "turn-maintenance",
            item: item,
            firstInTurn: true,
            lastInTurn: true
        )

        let cell = ConversationRowFactory.makeCell(for: row)
        XCTAssertEqual(
            ConversationRowFactory.reuseIdentifier(for: row).rawValue,
            "assistant.contextCompaction"
        )
        let contextCell = try XCTUnwrap(cell as? ContextCompactionCellView)
        contextCell.configure(
            row: row,
            width: 620,
            model: SessionModel(turnStarter: NoopRuntimeTurnStarter())
        )
        XCTAssertTrue(
            contextCell.allDescendants(ofType: NSTextField.self)
                .contains { $0.stringValue == "上下文已压缩" }
        )
    }

    func testFileEditCellUsesAvailableTranscriptWidth() throws {
        let row = ConversationDisplayRowTestSupport.assistantRow(kind: "fileEdit") { item in
            item.path = "/tmp/agentdeck-worktree/Sources/AgentDeck/ConversationRowViews.swift"
            item.statusName = "modified"
        }
        let width: CGFloat = 720
        let cell = try XCTUnwrap(
            ConversationRowFactory.makeCell(for: row) as? FileEditCellView
        )
        cell.frame = NSRect(
            x: 0,
            y: 0,
            width: width,
            height: ConversationRowFactory.height(for: row, width: width)
        )
        cell.configure(
            row: row,
            width: width,
            model: SessionModel(turnStarter: NoopRuntimeTurnStarter())
        )
        cell.layoutSubtreeIfNeeded()

        XCTAssertGreaterThan(
            cell.contentStack.frame.width,
            width - 60,
            "文件路径行应占用正文可用宽度，不能退化成按路径分隔符竖排"
        )
        let pathLabel = try XCTUnwrap(
            cell.contentStack.arrangedSubviews.first as? NSTextField
        )
        XCTAssertGreaterThan(pathLabel.frame.width, width - 60)
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

    func testCollapsedToolCallUsesCompactSingleLineHeight() {
        let row = ConversationDisplayRowTestSupport.assistantRow(kind: "toolCall") { item in
            item.tool = "Read"
            item.arguments = #"{"file_path":"/tmp/compact.swift"}"#
            item.result = String(repeating: "payload line\n", count: 200)
            item.statusName = "completed"
        }

        let height = ConversationRowFactory.height(for: row, width: 400)

        XCTAssertLessThanOrEqual(height, 32, "折叠态 toolCall 应保持为紧凑单行")
    }

    func testCollapsedToolCallHeightDoesNotGrowWithPayload() {
        let short = ConversationDisplayRowTestSupport.assistantRow(kind: "toolCall") { item in
            item.tool = "Read"
            item.arguments = #"{"file_path":"/tmp/short.swift"}"#
        }
        let long = ConversationDisplayRowTestSupport.assistantRow(kind: "toolCall") { item in
            item.tool = "Read"
            item.arguments = #"{"file_path":"/tmp/long.swift"}"#
            item.result = String(repeating: "result\n", count: 500)
        }

        XCTAssertEqual(
            ConversationRowFactory.height(for: short, width: 400),
            ConversationRowFactory.height(for: long, width: 400),
            accuracy: 0.1,
            "payload 只应影响展开态高度"
        )
    }

    func testCollapsedToolActivityGroupHeightDoesNotGrowWithMemberCount() {
        let two = ConversationDisplayRowTestSupport.toolActivityGroupRow(count: 2)
        let twenty = ConversationDisplayRowTestSupport.toolActivityGroupRow(count: 20)

        XCTAssertEqual(
            ConversationRowFactory.height(for: two, width: 400),
            ConversationRowFactory.height(for: twenty, width: 400),
            accuracy: 0.1
        )
        XCTAssertLessThanOrEqual(
            ConversationRowFactory.height(for: twenty, width: 400),
            32,
            "折叠组只能占一个紧凑摘要行"
        )
    }
}
