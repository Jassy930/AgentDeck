import AgentDeckMobileCore
import Foundation
import XCTest

final class AgentItemReducerTests: XCTestCase {
    func testToolReducerPreservesNeutralPresentationMetadata() throws {
        let meta = AgentItemMeta(vendorExtensions: [
            "server": AnyCodable("node_repl"),
            "status": AnyCodable("failed"),
            "durationMs": AnyCodable(Int64(136)),
            "mcpAppResourceUri": AnyCodable("app://agentdeck"),
        ])
        let agentItem = AgentItem.toolCall(
            name: "js",
            args: AnyCodable(["title": "确认 AgentDeck 窗口"]),
            result: AnyCodable(["success": false]),
            meta: meta
        )
        var store = AgentItemStore()

        AgentItemReducer.apply(agentItem, itemId: "tool-1", state: .completed, into: &store)

        let item = try XCTUnwrap(store.items.first)
        XCTAssertEqual(item.server, "node_repl")
        XCTAssertEqual(item.tool, "js")
        XCTAssertEqual(item.toolKind, "mcp")
        XCTAssertEqual(item.statusName, "failed")
        XCTAssertEqual(item.durationMs, 136)
        XCTAssertEqual(item.resourceUri, "app://agentdeck")
        XCTAssertEqual(item.success, false)
    }

    func testToolReducerPreservesNeutralCollaborationActivityGroupingIdentity() throws {
        let meta = AgentItemMeta(vendorExtensions: [
            "activityKind": AnyCodable("collaboration"),
            "activityEvent": AnyCodable("interacted"),
            "status": AnyCodable("completed"),
        ])
        let agentItem = AgentItem.toolCall(
            name: "spawnAgent",
            args: AnyCodable([
                "prompt": "审查工具展示",
                "model": "gpt-5",
                "reasoningEffort": "high",
                "senderThreadId": "parent-1",
                "receiverThreadIds": ["child-1"],
            ] as [String: Any]),
            result: AnyCodable([
                "agentsStates": [
                    "child-1": ["status": "completed"],
                ],
            ] as [String: Any]),
            meta: meta
        )
        var store = AgentItemStore()

        AgentItemReducer.apply(agentItem, itemId: "collab-1", state: .completed, into: &store)

        let item = try XCTUnwrap(store.items.first)
        XCTAssertEqual(item.activityKind, "collaboration")
        XCTAssertEqual(item.activityEvent, "interacted")
        XCTAssertEqual(ToolPresentation.toolStatusSummary(item), "已更新")
        XCTAssertTrue(ToolActivityGroupPresentation.isGroupable(item))
        XCTAssertEqual(
            ToolActivityGroupPresentation.groupingKey(for: item),
            .collaboration(taskName: "spawnagent")
        )
    }

    func testToolReducerRoutesContextMaintenanceToCompactSystemRow() throws {
        let meta = AgentItemMeta(vendorExtensions: [
            "activityKind": AnyCodable("contextMaintenance"),
        ])
        let agentItem = AgentItem.toolCall(
            name: "contextCompaction",
            args: AnyCodable(NSNull()),
            result: nil,
            meta: meta
        )
        var store = AgentItemStore()

        AgentItemReducer.apply(agentItem, itemId: "compact-1", state: .completed, into: &store)

        let item = try XCTUnwrap(store.items.first)
        let row = ConversationDisplayRow(
            role: .assistantItem,
            turnId: "turn-maintenance",
            item: item,
            firstInTurn: true,
            lastInTurn: true
        )
        XCTAssertEqual(item.activityKind, "contextMaintenance")
        XCTAssertEqual(row.presentationKind, "contextCompaction")
        XCTAssertFalse(ToolActivityGroupPresentation.isGroupable(item))
    }

    func testToolReducerPreservesClaudeCodeFailureMetadata() throws {
        let meta = AgentItemMeta(vendorExtensions: [
            "toolUseId": AnyCodable("tool-use-1"),
            "isError": AnyCodable(true),
        ])
        let agentItem = AgentItem.toolCall(
            name: "Read",
            args: AnyCodable(["file_path": "/tmp/missing"]),
            result: AnyCodable("file not found"),
            meta: meta
        )
        var store = AgentItemStore()

        AgentItemReducer.apply(agentItem, itemId: "tool-cc-1", state: .completed, into: &store)

        let item = try XCTUnwrap(store.items.first)
        XCTAssertEqual(item.success, false)
        XCTAssertEqual(ToolPresentation.toolStatus(item), "failed")
    }

    func testToolReducerPrefersCanonicalMCPAppContextMetadata() throws {
        let meta = AgentItemMeta(vendorExtensions: [
            "server": AnyCodable("node_repl"),
            "status": AnyCodable("completed"),
            "resourceUri": AnyCodable("app://canonical-agentdeck"),
            "actionName": AnyCodable("确认 AgentDeck 窗口"),
            "mcpAppResourceUri": AnyCodable("app://deprecated-agentdeck"),
        ])
        let agentItem = AgentItem.toolCall(
            name: "js",
            args: AnyCodable(["code": "..."]),
            result: AnyCodable(["success": true]),
            meta: meta
        )
        var store = AgentItemStore()

        AgentItemReducer.apply(agentItem, itemId: "tool-canonical", state: .completed, into: &store)

        let item = try XCTUnwrap(store.items.first)
        XCTAssertEqual(item.resourceUri, "app://canonical-agentdeck")
        XCTAssertEqual(item.action, "确认 AgentDeck 窗口")
        XCTAssertEqual(ToolPresentation.toolContextSummary(item), "确认 AgentDeck 窗口")
    }

    func testCumulativeSnapshotsReplaceByEnvelopeIdentityAndState() throws {
        var store = AgentItemStore()

        AgentItemReducer.apply(
            .assistantMessage(text: "Hel", meta: AgentItemMeta()),
            itemId: "message-1",
            state: .streaming,
            into: &store
        )
        AgentItemReducer.apply(
            .assistantMessage(text: "Hello", meta: AgentItemMeta()),
            itemId: "message-1",
            state: .completed,
            into: &store
        )

        let item = try XCTUnwrap(store.items.first)
        XCTAssertEqual(store.items.count, 1)
        XCTAssertEqual(item.id, "message-1")
        XCTAssertEqual(item.text, "Hello")
        XCTAssertEqual(item.lifecycle, "completed")
    }
}
