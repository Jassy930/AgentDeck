import Foundation
import XCTest
@testable import AgentDeckCore

final class RuntimeV2StreamProtocolTests: XCTestCase {
    func testEntryAndCatalogRequiredNullRowsAndRevisionZeroContract() throws {
        let missing = entry(title: nil, cwd: nil, includeOptionals: false)
        let explicitNull = entry(title: nil, cwd: nil, includeOptionals: true)
        for wire in [missing, explicitNull] {
            let decoded = try decode(RuntimeConversationEntryV2.self, wire)
            XCTAssertNil(decoded.title)
            XCTAssertNil(decoded.cwd)
            XCTAssertEqual(decoded.entryRevision, 0)
            let encoded = try object(decoded)
            XCTAssertTrue(encoded["title"] is NSNull)
            XCTAssertTrue(encoded["cwd"] is NSNull)
            XCTAssertNil(encoded["adapterStateKey"])
        }
        var leaked = explicitNull
        leaked["adapterStateKey"] = "private"
        try assertDecodeFails(RuntimeConversationEntryV2.self, leaked)

        let richEntry: [String: Any] = [
            "conversationId": "conversation-rich", "agentKind": "claude_code",
            "title": "标题", "cwd": "/tmp/project", "lastActiveMs": 42,
            "archived": true, "entryRevision": 7,
        ]
        let decodedRichEntry = try decode(RuntimeConversationEntryV2.self, richEntry)
        XCTAssertEqual(try bytes(try object(decodedRichEntry)), try bytes(richEntry))

        let fiveHundred = catalog(entries: Array(repeating: explicitNull, count: 500))
        XCTAssertNoThrow(try decode(RuntimeCatalogSnapshotV2.self, fiveHundred))
        try assertDecodeFails(
            RuntimeCatalogSnapshotV2.self,
            catalog(entries: Array(repeating: explicitNull, count: 501))
        )
        var missingCursor = catalog(entries: [])
        missingCursor.removeValue(forKey: "nextPageCursor")
        try assertDecodeFails(RuntimeCatalogSnapshotV2.self, missingCursor)
        var missingCurrentCursor = catalog(entries: [])
        missingCurrentCursor.removeValue(forKey: "currentPageCursor")
        try assertDecodeFails(RuntimeCatalogSnapshotV2.self, missingCurrentCursor)
        let decoded = try decode(RuntimeCatalogSnapshotV2.self, catalog(entries: []))
        XCTAssertNil(decoded.currentPageCursor)
        XCTAssertNil(decoded.nextPageCursor)
        XCTAssertTrue(try object(decoded)["currentPageCursor"] is NSNull)
        XCTAssertTrue(try object(decoded)["nextPageCursor"] is NSNull)

        let richCatalog: [String: Any] = [
            "baseCatalogCursor": ["at": 9], "entries": [richEntry],
            "currentPageCursor": "page-1",
            "nextPageCursor": "page-2",
        ]
        XCTAssertEqual(
            try bytes(try object(try decode(RuntimeCatalogSnapshotV2.self, richCatalog))),
            try bytes(richCatalog)
        )
        var unknownCatalog = richCatalog
        unknownCatalog["future"] = true
        try assertDecodeFails(RuntimeCatalogSnapshotV2.self, unknownCatalog)
        XCTAssertThrowsError(
            try RuntimeCatalogSnapshotV2(
                baseCatalogCursor: .beforeFirst,
                entries: Array(repeating: decodedRichEntry, count: 501),
                currentPageCursor: nil,
                nextPageCursor: nil
            )
        )
    }

    func testCatalogEncodedLimitIsSymmetricAtExact64MiB() throws {
        let maximum = RuntimeCatalogSnapshotV2.maxEncodedBytes
        let empty = catalog(entries: [entry(title: "", cwd: nil)])
        let fixedBytes = try bytes(empty).count
        let exactTitle = String(repeating: "a", count: maximum - fixedBytes)
        let exact = catalog(entries: [entry(title: exactTitle, cwd: nil)])
        XCTAssertEqual(try bytes(exact).count, maximum)
        let decodedExact = try decode(RuntimeCatalogSnapshotV2.self, exact)
        XCTAssertEqual(try JSONEncoder().encode(decodedExact).count, maximum)

        let oversized = catalog(entries: [entry(title: exactTitle + "a", cwd: nil)])
        XCTAssertEqual(try bytes(oversized).count, maximum + 1)
        try assertDecodeFails(RuntimeCatalogSnapshotV2.self, oversized)
        let oversizedEntry = RuntimeConversationEntryV2(
            conversationID: RuntimeConversationID(rawValue: "conversation-1"),
            agentKind: .codex,
            title: exactTitle + "a",
            cwd: nil,
            lastActiveMs: 0,
            archived: false,
            entryRevision: 0
        )
        XCTAssertThrowsError(
            try RuntimeCatalogSnapshotV2(
                baseCatalogCursor: .beforeFirst,
                entries: [oversizedEntry],
                currentPageCursor: nil,
                nextPageCursor: nil
            )
        )
    }

    func testCatalogRemovedKeyAndDeltaRevisionZeroStayRustExact() throws {
        let upserted: [String: Any] = [
            "kind": "upserted", "entry": entry(title: "hello", cwd: "/tmp"),
        ]
        XCTAssertEqual(
            try bytes(try object(try decode(RuntimeCatalogChangeV2.self, upserted))),
            try bytes(upserted)
        )
        var unknownUpserted = upserted
        unknownUpserted["future"] = true
        try assertDecodeFails(RuntimeCatalogChangeV2.self, unknownUpserted)

        let removed: [String: Any] = [
            "kind": "removed", "conversation_id": "conversation-removed",
        ]
        let change = try decode(RuntimeCatalogChangeV2.self, removed)
        XCTAssertEqual(Set(try object(change).keys), ["kind", "conversation_id"])
        var unknownRemoved = removed
        unknownRemoved["future"] = true
        try assertDecodeFails(RuntimeCatalogChangeV2.self, unknownRemoved)
        try assertDecodeFails(
            RuntimeCatalogChangeV2.self,
            ["kind": "removed", "conversationId": "conversation-removed"]
        )
        let delta: [String: Any] = ["catalogRevision": 0, "changes": [removed]]
        let decodedDelta = try decode(RuntimeCatalogDeltaV2.self, delta)
        XCTAssertEqual(decodedDelta.catalogRevision, 0)
        XCTAssertEqual(try bytes(try object(decodedDelta)), try bytes(delta))
        var unknownDelta = delta
        unknownDelta["future"] = true
        try assertDecodeFails(RuntimeCatalogDeltaV2.self, unknownDelta)
    }

    func testRuntimeVendorPanelIsStrictAtEveryLayerAndEmitsNullOptionals() throws {
        let missing: [String: Any] = [
            "agentKind": "claude_code",
            "event": ["kind": "systemStatus", "subtype": "ready"],
        ]
        let null: [String: Any] = [
            "agentKind": "claude_code",
            "event": [
                "kind": "systemStatus", "subtype": "ready", "status": NSNull(),
                "message": NSNull(), "attempt": NSNull(), "error": NSNull(),
                "errorStatus": NSNull(), "maxRetries": NSNull(), "retryDelayMs": NSNull(),
            ],
        ]
        for wire in [missing, null] {
            let encoded = try object(try decode(RuntimeVendorPanelPayloadV2.self, wire))
            let event = try XCTUnwrap(encoded["event"] as? [String: Any])
            for key in [
                "status", "message", "attempt", "error", "errorStatus", "maxRetries",
                "retryDelayMs",
            ] {
                XCTAssertTrue(event[key] is NSNull)
            }
        }
        let systemValues: [String: Any] = [
            "agentKind": "claude_code",
            "event": [
                "kind": "systemStatus", "subtype": "api_retry", "status": "retrying",
                "message": "later", "attempt": 2, "error": "timeout", "errorStatus": 503,
                "maxRetries": 4, "retryDelayMs": 1.5,
            ],
        ]
        XCTAssertEqual(
            try bytes(try object(try decode(RuntimeVendorPanelPayloadV2.self, systemValues))),
            try bytes(systemValues)
        )

        let hookMissing: [String: Any] = [
            "agentKind": "claude_code",
            "event": ["kind": "hookFired", "matcher": "Bash"],
        ]
        let hookNull: [String: Any] = [
            "agentKind": "claude_code",
            "event": [
                "kind": "hookFired", "matcher": "Bash", "toolUseId": NSNull(),
                "elapsedMs": NSNull(),
            ],
        ]
        for wire in [hookMissing, hookNull] {
            let encoded = try object(try decode(RuntimeVendorPanelPayloadV2.self, wire))
            let event = try XCTUnwrap(encoded["event"] as? [String: Any])
            XCTAssertEqual(event["kind"] as? String, "hookFired")
            XCTAssertEqual(event["matcher"] as? String, "Bash")
            XCTAssertTrue(event["toolUseId"] is NSNull)
            XCTAssertTrue(event["elapsedMs"] is NSNull)
        }
        let hookValues: [String: Any] = [
            "agentKind": "claude_code",
            "event": [
                "kind": "hookFired", "matcher": "Bash", "toolUseId": "tool-1",
                "elapsedMs": 7,
            ],
        ]
        XCTAssertEqual(
            try bytes(try object(try decode(RuntimeVendorPanelPayloadV2.self, hookValues))),
            try bytes(hookValues)
        )

        var outerUnknown = missing
        outerUnknown["future"] = true
        try assertDecodeFails(RuntimeVendorPanelPayloadV2.self, outerUnknown)
        var eventUnknown = missing
        var nested = try XCTUnwrap(eventUnknown["event"] as? [String: Any])
        nested["future"] = true
        eventUnknown["event"] = nested
        try assertDecodeFails(RuntimeVendorPanelPayloadV2.self, eventUnknown)
        var hookUnknown = hookMissing
        var hookEvent = try XCTUnwrap(hookUnknown["event"] as? [String: Any])
        hookEvent["future"] = true
        hookUnknown["event"] = hookEvent
        try assertDecodeFails(RuntimeVendorPanelPayloadV2.self, hookUnknown)
        try assertDecodeFails(
            RuntimeVendorPanelPayloadV2.self,
            [
                "agentKind": "codex",
                "event": ["kind": "placeholder", "future": true],
            ]
        )
        try assertDecodeFails(
            RuntimeVendorPanelPayloadV2.self,
            ["agentKind": "codex", "event": ["kind": "future"]]
        )
        XCTAssertNoThrow(
            try decode(
                RuntimeVendorPanelPayloadV2.self,
                ["agentKind": "codex", "event": ["kind": "placeholder"]]
            )
        )
    }

    func testEventRequiredNullableIdentityBodyMatrixAndApprovalDecision() throws {
        let cases: [([String: Any], Any, Any, Any)] = [
            (["kind": "capabilities", "capabilities": capabilities("codex")], NSNull(), NSNull(), NSNull()),
            (["kind": "configurationChanged", "state": unconfiguredState()], NSNull(), NSNull(), NSNull()),
            (["kind": "configurationChanged", "state": configuredState("claude_code")], NSNull(), NSNull(), NSNull()),
            (["kind": "vendorPanelEvent", "vendorPanel": codexPanel()], NSNull(), NSNull(), NSNull()),
            (["kind": "item", "item": userMessage()], "command-1", "item-1", "entity-1"),
            (["kind": "item", "item": assistantMessage()], NSNull(), "item-2", "entity-2"),
            (["kind": "item", "item": assistantMessage()], "command-2", "item-3", "entity-3"),
            (["kind": "turnStarted", "turn_id": "turn-1"], "command-1", NSNull(), NSNull()),
            (["kind": "actionRequest", "turn_id": "turn-1", "approval_id": "approval-1", "request": actionRequest()], "command-1", NSNull(), NSNull()),
            (["kind": "approvalResolved", "turn_id": "turn-1", "approval_id": "approval-1", "decision": "approve", "state": "expired"], "command-1", NSNull(), NSNull()),
            (["kind": "turnCompleted", "turn_id": "turn-1", "summary": turnSummary()], "command-1", NSNull(), NSNull()),
            (["kind": "turnInterrupted", "turn_id": "turn-1"], "command-1", NSNull(), NSNull()),
            (["kind": "error", "failure": failure()], NSNull(), NSNull(), NSNull()),
            (["kind": "error", "failure": terminalFailure()], "command-error", NSNull(), NSNull()),
        ]
        for (index, value) in cases.enumerated() {
            let wire = event(
                body: value.0,
                commandID: value.1,
                itemID: value.2,
                entityID: value.3,
                sequence: 0,
                suffix: "\(index)"
            )
            let decoded = try decode(RuntimeEventV2.self, wire)
            XCTAssertEqual(try bytes(try object(decoded)), try bytes(wire))

            var unknownBody = value.0
            unknownBody["future"] = true
            try assertDecodeFails(RuntimeEventBodyV2.self, unknownBody)

            var invalid = wire
            switch value.0["kind"] as? String {
            case "capabilities", "configurationChanged", "vendorPanelEvent":
                invalid["commandId"] = "unexpected-command"
            case "item":
                invalid["entityId"] = NSNull()
            case "error":
                invalid["itemId"] = "unexpected-item"
            default:
                invalid["commandId"] = NSNull()
            }
            try assertDecodeFails(RuntimeEventV2.self, invalid)

            let decodedBody = try decode(RuntimeEventBodyV2.self, value.0)
            let invalidIDs = invalidIdentity(for: decodedBody)
            XCTAssertThrowsError(
                try RuntimeEventV2(
                    conversationID: RuntimeConversationID(rawValue: "conversation-constructor"),
                    eventID: RuntimeEventID(rawValue: "event-constructor-\(index)"),
                    eventSeq: 0,
                    commandID: invalidIDs.command,
                    itemID: invalidIDs.item,
                    entityID: invalidIDs.entity,
                    body: decodedBody
                )
            )
        }

        let base = event(body: cases[0].0)
        for identity in ["commandId", "itemId", "entityId"] {
            var missing = base
            missing.removeValue(forKey: identity)
            try assertDecodeFails(RuntimeEventV2.self, missing)
        }
        try assertDecodeFails(
            RuntimeEventV2.self,
            event(body: ["kind": "turnStarted", "turn_id": "turn-1"])
        )
        try assertDecodeFails(
            RuntimeEventV2.self,
            event(body: ["kind": "item", "item": userMessage()], itemID: "i", entityID: "e")
        )
        var missingDecision: [String: Any] = [
            "kind": "approvalResolved", "turn_id": "turn-1", "approval_id": "approval-1",
            "state": "expired",
        ]
        missingDecision.removeValue(forKey: "decision")
        try assertDecodeFails(RuntimeEventBodyV2.self, missingDecision)
        var unknownOuter = base
        unknownOuter["future"] = true
        try assertDecodeFails(RuntimeEventV2.self, unknownOuter)

        let approval = RuntimeEventBodyV2.approvalResolved(
            turnID: RuntimeTurnID(rawValue: "turn-1"),
            approvalID: RuntimeApprovalID(rawValue: "approval-1"),
            decision: nil,
            state: .expired
        )
        XCTAssertTrue(try object(approval)["decision"] is NSNull)
        XCTAssertThrowsError(
            try RuntimeEventV2(
                conversationID: RuntimeConversationID(rawValue: "conversation-1"),
                eventID: RuntimeEventID(rawValue: "event-1"),
                eventSeq: 0,
                commandID: nil,
                itemID: nil,
                entityID: nil,
                body: .turnStarted(turnID: RuntimeTurnID(rawValue: "turn-1"))
            )
        )
    }

    func testCommandBoundErrorRequiresFixedDaemonFailureTuple() throws {
        let invalidFailures: [[String: Any]] = [
            failure(),
            [
                "code": "daemon.runtime.execution_failed", "message": "wrong message",
                "diagnosticRef": NSNull(),
            ],
            [
                "code": "daemon.runtime.execution_failed", "message": "agent execution failed",
                "diagnosticRef": "diag-not-allowed",
            ],
        ]
        for invalidFailure in invalidFailures {
            let wire = event(
                body: ["kind": "error", "failure": invalidFailure],
                commandID: "command-invalid"
            )
            try assertDecodeFails(RuntimeEventV2.self, wire)
        }

        XCTAssertThrowsError(
            try RuntimeEventV2(
                conversationID: RuntimeConversationID(rawValue: "conversation-1"),
                eventID: RuntimeEventID(rawValue: "event-invalid-terminal-failure"),
                eventSeq: 0,
                commandID: RuntimeCommandID(rawValue: "command-1"),
                itemID: nil,
                entityID: nil,
                body: .error(RuntimeFailureV1(code: "daemon.test", message: "failure"))
            )
        )
    }

    func testCatalogAndEventFlattenedSurfacesPreserveAndRejectDiscriminators() throws {
        requireFlattened(RuntimeCatalogSnapshotV2.self)
        requireFlattened(RuntimeCatalogDeltaV2.self)
        requireFlattened(RuntimeEventV2.self)
        var catalogReply = catalog(entries: [])
        catalogReply["reply"] = "catalog"
        let reply = try decode(
            RuntimeV2StreamFlattenedProbe<RuntimeCatalogSnapshotV2>.self,
            catalogReply
        )
        XCTAssertEqual(try bytes(try object(reply)), try bytes(catalogReply))
        try assertDecodeFails(RuntimeCatalogSnapshotV2.self, catalogReply)
        catalogReply["reply"] = "future"
        try assertDecodeFails(
            RuntimeV2StreamFlattenedProbe<RuntimeCatalogSnapshotV2>.self,
            catalogReply
        )

        var delta = catalogDelta(0)
        delta["stream"] = "catalogDelta"
        let decodedDelta = try decode(
            RuntimeV2StreamFlattenedProbe<RuntimeCatalogDeltaV2>.self,
            delta
        )
        XCTAssertEqual(try bytes(try object(decodedDelta)), try bytes(delta))
        try assertDecodeFails(RuntimeCatalogDeltaV2.self, delta)
        delta["stream"] = "future"
        try assertDecodeFails(RuntimeV2StreamFlattenedProbe<RuntimeCatalogDeltaV2>.self, delta)

        var stream = event(body: ["kind": "error", "failure": failure()])
        stream["stream"] = "event"
        let decodedEvent = try decode(
            RuntimeV2StreamFlattenedProbe<RuntimeEventV2>.self,
            stream
        )
        XCTAssertEqual(try bytes(try object(decodedEvent)), try bytes(stream))
        try assertDecodeFails(RuntimeEventV2.self, stream)
        stream["stream"] = "future"
        try assertDecodeFails(RuntimeV2StreamFlattenedProbe<RuntimeEventV2>.self, stream)
    }

    private func requireFlattened<T: RuntimeV2FlattenedPayload>(_ type: T.Type) {}

    private func invalidIdentity(
        for body: RuntimeEventBodyV2
    ) -> (command: RuntimeCommandID?, item: RuntimeItemID?, entity: RuntimeEntityID?) {
        switch body {
        case .capabilities, .configurationChanged, .vendorPanelEvent:
            return (RuntimeCommandID(rawValue: "unexpected-command"), nil, nil)
        case .item:
            return (RuntimeCommandID(rawValue: "command"), RuntimeItemID(rawValue: "item"), nil)
        case .turnStarted, .actionRequest, .approvalResolved, .turnCompleted, .turnInterrupted:
            return (nil, nil, nil)
        case .error:
            return (nil, RuntimeItemID(rawValue: "unexpected-item"), nil)
        }
    }

    private func decode<T: Decodable>(_ type: T.Type, _ value: Any) throws -> T {
        try JSONDecoder().decode(type, from: try bytes(value))
    }

    private func assertDecodeFails<T: Decodable>(
        _ type: T.Type,
        _ value: Any,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        let data = try bytes(value)
        XCTAssertThrowsError(try JSONDecoder().decode(type, from: data), file: file, line: line)
    }

    private func object<T: Encodable>(_ value: T) throws -> [String: Any] {
        try XCTUnwrap(
            JSONSerialization.jsonObject(with: JSONEncoder().encode(value)) as? [String: Any]
        )
    }

    private func bytes(_ value: Any) throws -> Data {
        try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys, .fragmentsAllowed])
    }

    private func entry(
        title: String?,
        cwd: String?,
        includeOptionals: Bool = true
    ) -> [String: Any] {
        var value: [String: Any] = [
            "conversationId": "conversation-1", "agentKind": "codex",
            "lastActiveMs": 0, "archived": false, "entryRevision": 0,
        ]
        if includeOptionals {
            value["title"] = title ?? NSNull()
            value["cwd"] = cwd ?? NSNull()
        }
        return value
    }

    private func catalog(entries: [[String: Any]]) -> [String: Any] {
        [
            "baseCatalogCursor": "beforeFirst", "entries": entries,
            "currentPageCursor": NSNull(), "nextPageCursor": NSNull(),
        ]
    }

    private func catalogDelta(_ revision: UInt64) -> [String: Any] {
        [
            "catalogRevision": revision,
            "changes": [["kind": "removed", "conversation_id": "conversation-\(revision)"]],
        ]
    }

    private func capabilities(_ kind: String) -> [String: Any] {
        let vendor: [String: Any] = kind == "codex"
            ? [
                "agentKind": "codex", "sandboxModes": [], "persistenceSupported": false,
                "reasoningEffortLevels": [],
            ]
            : [
                "agentKind": "claude_code", "permissionModes": [], "outputStyles": [],
                "hooksSupported": [], "cliVersion": "fixture",
            ]
        return ["agentKind": kind, "agentVersion": "fixture", "features": [], "vendor": vendor]
    }

    private func codexPanel() -> [String: Any] {
        ["agentKind": "codex", "event": ["kind": "placeholder"]]
    }

    private func unconfiguredState() -> [String: Any] {
        ["configurationRevision": 0, "configuration": NSNull()]
    }

    private func configuredState(_ kind: String) -> [String: Any] {
        let configuration: [String: Any] = kind == "codex"
            ? ["approvalPolicy": "on-request", "sandbox": "workspace-write", "reasoningEffort": "high"]
            : ["permissionMode": "default", "model": NSNull(), "effort": NSNull(), "outputStyle": NSNull()]
        return [
            "configurationRevision": 1,
            "configuration": [
                "vendorControl": ["agentKind": kind, "configuration": configuration],
            ],
        ]
    }

    private func event(
        body: [String: Any],
        commandID: Any = NSNull(),
        itemID: Any = NSNull(),
        entityID: Any = NSNull(),
        sequence: UInt64 = 0,
        suffix: String = "0"
    ) -> [String: Any] {
        [
            "conversationId": "conversation-1", "eventId": "event-\(suffix)",
            "eventSeq": sequence, "commandId": commandID, "itemId": itemID,
            "entityId": entityID, "body": body,
        ]
    }

    private func userMessage() -> [String: Any] {
        ["kind": "userMessage", "text": "hello", "meta": ["vendorExtensions": [:]]]
    }

    private func assistantMessage() -> [String: Any] {
        ["kind": "assistantMessage", "text": "hello", "meta": ["vendorExtensions": [:]]]
    }

    private func actionRequest() -> [String: Any] {
        [
            "kind": "executeCommand", "requestId": "request-1", "summary": "run",
            "vendor": [
                "agentKind": "codex", "sandboxAtDecision": "workspace-write",
                "approvalPolicyAtDecision": "on-request", "canPersist": false,
            ],
        ]
    }

    private func turnSummary() -> [String: Any] {
        ["elapsedMs": 1, "totalInputTokens": NSNull(), "totalOutputTokens": NSNull()]
    }

    private func failure(_ message: String = "failure") -> [String: Any] {
        ["code": "daemon.test", "message": message, "diagnosticRef": NSNull()]
    }

    private func terminalFailure() -> [String: Any] {
        [
            "code": "daemon.runtime.execution_failed", "message": "agent execution failed",
            "diagnosticRef": NSNull(),
        ]
    }

}

private struct RuntimeV2StreamFlattenedProbe<Value: RuntimeV2FlattenedPayload>: Codable {
    let value: Value
    init(from decoder: Decoder) throws { value = try Value(flattenedFrom: decoder) }
    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: RuntimeV2CodingKey.self)
        try value.encodeFlattenedFields(into: &container)
    }
}
