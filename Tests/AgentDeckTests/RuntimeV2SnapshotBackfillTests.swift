import Foundation
import XCTest
@testable import AgentDeckCore

final class RuntimeV2SnapshotBackfillTests: XCTestCase {
    func testRustProducedSnapshotAndBackfillPayloadsReadBackWithoutOuterCodec() throws {
        requireFlattened(ConversationSnapshotV2.self)
        requireFlattened(RuntimeBackfillChunkV2.self)
        for name in ["capabilitiesFirstSnapshot", "unconfiguredSnapshot"] {
            let payload = try rustProducedReplyPayload(named: name)
            let flattened = try decode(
                RuntimeV2SnapshotBackfillFlattenedProbe<ConversationSnapshotV2>.self,
                payload
            )
            XCTAssertEqual(try bytes(try object(flattened)), try bytes(payload), name)
            try assertDecodeFails(ConversationSnapshotV2.self, payload)

            var standalone = payload
            standalone.removeValue(forKey: "reply")
            XCTAssertEqual(
                try bytes(try object(try decode(ConversationSnapshotV2.self, standalone))),
                try bytes(standalone),
                name
            )
        }

        let backfill = try rustProducedReplyPayload(named: "replyBackfill")
        let flattened = try decode(
            RuntimeV2SnapshotBackfillFlattenedProbe<RuntimeBackfillChunkV2>.self,
            backfill
        )
        XCTAssertEqual(try bytes(try object(flattened)), try bytes(backfill))
        try assertDecodeFails(RuntimeBackfillChunkV2.self, backfill)
        var standalone = backfill
        standalone.removeValue(forKey: "reply")
        XCTAssertEqual(
            try bytes(try object(try decode(RuntimeBackfillChunkV2.self, standalone))),
            try bytes(standalone)
        )
        var wrongTag = backfill
        wrongTag["reply"] = "future"
        try assertDecodeFails(
            RuntimeV2SnapshotBackfillFlattenedProbe<RuntimeBackfillChunkV2>.self,
            wrongTag
        )
    }

    func testSnapshotRequiresExactlyOneCapabilitiesFirstAndMatchingConfiguration() throws {
        let capabilities = snapshotCapabilitiesItem("codex")
        let item = snapshotItem(kind: "assistantMessage", commandID: NSNull())
        let valid = snapshot(
            configurationState: configuredState("codex"),
            items: [capabilities, item]
        )
        XCTAssertEqual(
            try bytes(try object(try decode(ConversationSnapshotV2.self, valid))),
            try bytes(valid)
        )

        let invalidItems = [
            [],
            [item],
            [item, capabilities],
            [capabilities, capabilities],
        ]
        for items in invalidItems {
            try assertDecodeFails(
                ConversationSnapshotV2.self,
                snapshot(configurationState: unconfiguredState(), items: items)
            )
        }
        try assertDecodeFails(
            ConversationSnapshotV2.self,
            snapshot(configurationState: configuredState("claude_code"), items: [capabilities])
        )

        var unknown = valid
        unknown["future"] = true
        try assertDecodeFails(ConversationSnapshotV2.self, unknown)
        for identity in ["commandId", "itemId", "entityId"] {
            var missingIdentity = capabilities
            missingIdentity.removeValue(forKey: identity)
            try assertDecodeFails(SnapshotItemV1.self, missingIdentity)
        }
        try assertDecodeFails(
            SnapshotItemV1.self,
            snapshotItem(kind: "userMessage", commandID: NSNull())
        )

        let decodedCapabilities = try decode(SnapshotItemV1.self, capabilities)
        let decodedItem = try decode(SnapshotItemV1.self, item)
        let codexState = try decode(
            RuntimeConversationConfigurationStateV2.self,
            configuredState("codex")
        )
        let claudeState = try decode(
            RuntimeConversationConfigurationStateV2.self,
            configuredState("claude_code")
        )
        XCTAssertNoThrow(
            try ConversationSnapshotV2(
                conversationID: RuntimeConversationID(rawValue: "conversation-snapshot"),
                baseEventCursor: .at(0),
                configurationState: codexState,
                items: [decodedCapabilities, decodedItem]
            )
        )
        XCTAssertThrowsError(
            try ConversationSnapshotV2(
                conversationID: RuntimeConversationID(rawValue: "conversation-snapshot"),
                baseEventCursor: .beforeFirst,
                configurationState: claudeState,
                items: [decodedCapabilities]
            )
        )
    }

    func testBackfillRangeIsAfterExclusiveThroughInclusiveAndCappedAt512() throws {
        let validWires: [[String: Any]] = [
            ["after": "beforeFirst", "through": ["at": 0]],
            ["after": ["at": 0], "through": ["at": 1]],
            ["after": "beforeFirst", "through": ["at": 511]],
        ]
        for wire in validWires {
            XCTAssertEqual(
                try bytes(try object(try decode(RuntimeBackfillRangeV1.self, wire))),
                try bytes(wire)
            )
        }

        let invalidWires: [[String: Any]] = [
            ["after": "beforeFirst", "through": "beforeFirst"],
            ["after": ["at": 0], "through": ["at": 0]],
            ["after": ["at": 2], "through": ["at": 1]],
            ["after": "beforeFirst", "through": ["at": 512]],
            ["after": ["at": UInt64.max], "through": ["at": UInt64.max]],
            ["after": "beforeFirst", "through": ["at": 0], "future": true],
        ]
        for wire in invalidWires {
            try assertDecodeFails(RuntimeBackfillRangeV1.self, wire)
        }
        XCTAssertNoThrow(
            try RuntimeBackfillRangeV1(after: .beforeFirst, through: .at(511))
        )
        XCTAssertThrowsError(
            try RuntimeBackfillRangeV1(after: .beforeFirst, through: .at(512))
        )
    }

    func testCatalogBackfillRequiresExactCountAndContiguousRevision() throws {
        let valid = catalogBackfill(revisions: [0, 1], after: "beforeFirst", through: 1)
        XCTAssertEqual(
            try bytes(try object(try decode(RuntimeBackfillChunkV2.self, valid))),
            try bytes(valid)
        )

        let invalid: [[String: Any]] = [
            catalogBackfill(revisions: [], after: "beforeFirst", through: 0),
            catalogBackfill(revisions: [0], after: "beforeFirst", through: 1),
            catalogBackfill(revisions: [0, 2], after: "beforeFirst", through: 1),
            catalogBackfill(revisions: [1], after: "beforeFirst", through: 0),
        ]
        for wire in invalid {
            try assertDecodeFails(RuntimeBackfillChunkV2.self, wire)
        }
        var unknown = valid
        unknown["future"] = true
        try assertDecodeFails(RuntimeBackfillChunkV2.self, unknown)

        let range = try RuntimeBackfillRangeV1(after: .beforeFirst, through: .at(0))
        let empty = RuntimeBackfillChunkV2.catalog(range: range, deltas: [])
        XCTAssertThrowsError(try JSONEncoder().encode(empty))
        let discontinuous = RuntimeBackfillChunkV2.catalog(
            range: try RuntimeBackfillRangeV1(after: .beforeFirst, through: .at(1)),
            deltas: [catalogDelta(0), catalogDelta(2)]
        )
        XCTAssertThrowsError(try JSONEncoder().encode(discontinuous))
    }

    func testConversationBackfillRequiresExactSequenceAndConversationScope() throws {
        let valid = conversationBackfill(
            conversationID: "conversation-backfill",
            eventConversationIDs: ["conversation-backfill", "conversation-backfill"],
            sequences: [0, 1],
            through: 1
        )
        XCTAssertEqual(
            try bytes(try object(try decode(RuntimeBackfillChunkV2.self, valid))),
            try bytes(valid)
        )

        let invalid: [[String: Any]] = [
            conversationBackfill(
                conversationID: "conversation-backfill",
                eventConversationIDs: [], sequences: [], through: 0
            ),
            conversationBackfill(
                conversationID: "conversation-backfill",
                eventConversationIDs: ["conversation-backfill"], sequences: [0], through: 1
            ),
            conversationBackfill(
                conversationID: "conversation-backfill",
                eventConversationIDs: ["conversation-backfill", "conversation-backfill"],
                sequences: [0, 2], through: 1
            ),
            conversationBackfill(
                conversationID: "conversation-backfill",
                eventConversationIDs: ["other"], sequences: [0], through: 0
            ),
        ]
        for wire in invalid {
            try assertDecodeFails(RuntimeBackfillChunkV2.self, wire)
        }

        let range = try RuntimeBackfillRangeV1(after: .beforeFirst, through: .at(0))
        let event = try decode(
            RuntimeEventV2.self,
            runtimeEvent(conversationID: "other", sequence: 0)
        )
        let capabilities = try decode(RuntimeSessionCapabilitiesV1.self, capabilities("codex"))
        let mismatched = RuntimeBackfillChunkV2.conversation(
            conversationID: RuntimeConversationID(rawValue: "conversation-backfill"),
            capabilitiesPreamble: capabilities,
            range: range,
            events: [event]
        )
        XCTAssertThrowsError(try JSONEncoder().encode(mismatched))
    }

    func testBackfillAllows512Rejects513AndEnforcesExact64MiBBareBytes() throws {
        let fiveTwelve = catalogBackfill(
            revisions: Array(0...511),
            after: "beforeFirst",
            through: 511
        )
        XCTAssertNoThrow(try decode(RuntimeBackfillChunkV2.self, fiveTwelve))
        let fiveThirteen = catalogBackfill(
            revisions: Array(0...512),
            after: "beforeFirst",
            through: 511
        )
        try assertDecodeFails(RuntimeBackfillChunkV2.self, fiveThirteen)

        let maximum = RuntimeBackfillChunkV2.maxEncodedBytes
        let base = catalogBackfill(
            revisions: [0], after: "beforeFirst", through: 0, removedID: ""
        )
        let fixedBytes = try bytes(base).count
        let exactID = String(repeating: "x", count: maximum - fixedBytes)
        let exact = catalogBackfill(
            revisions: [0], after: "beforeFirst", through: 0, removedID: exactID
        )
        XCTAssertEqual(try bytes(exact).count, maximum)
        let decoded = try decode(RuntimeBackfillChunkV2.self, exact)
        XCTAssertEqual(try JSONEncoder().encode(decoded).count, maximum)

        let oversized = catalogBackfill(
            revisions: [0], after: "beforeFirst", through: 0, removedID: exactID + "x"
        )
        XCTAssertEqual(try bytes(oversized).count, maximum + 1)
        try assertDecodeFails(RuntimeBackfillChunkV2.self, oversized)

        let direct = RuntimeBackfillChunkV2.catalog(
            range: try RuntimeBackfillRangeV1(after: .beforeFirst, through: .at(0)),
            deltas: [
                RuntimeCatalogDeltaV2(
                    catalogRevision: 0,
                    changes: [
                        .removed(
                            conversationID: RuntimeConversationID(rawValue: exactID + "x")
                        ),
                    ]
                ),
            ]
        )
        XCTAssertThrowsError(try JSONEncoder().encode(direct))
    }

    func testCompatibilityAdapterKeyRenameHasExactSourceBoundary() throws {
        let root = repositoryRoot
        let wireURL = root.appendingPathComponent(
            "Sources/AgentDeckCore/Protocol/RuntimeWireTypes.swift"
        )
        let compatibilityTestURL = root.appendingPathComponent(
            "Tests/AgentDeckTests/RuntimeProtocolCompatibilityTests.swift"
        )
        let wireSource = try String(contentsOf: wireURL, encoding: .utf8)

        let legacy = ["Runtime", "Adapter", "State", "Key"].joined()
        let legacyKind = legacy + "Kind"
        let compatibility = legacy + "V1Compatibility"
        let compatibilityKind = compatibility + "Kind"
        let wireTokens = identifierCounts(in: wireSource)
        XCTAssertEqual(wireTokens[legacy, default: 0], 0)
        XCTAssertEqual(wireTokens[legacyKind, default: 0], 0)
        XCTAssertEqual(wireTokens[compatibilityKind, default: 0], 2)
        XCTAssertEqual(wireTokens[compatibility, default: 0], 6)
        let definitions = try sourceSlice(
            wireSource,
            from: "public enum " + compatibilityKind,
            before: "public struct RuntimeGrantSerial"
        )
        let catalogEntry = try sourceSlice(
            wireSource,
            from: "public struct RuntimeConversationEntryV1",
            before: "public struct RuntimeCatalogSnapshotV1"
        )
        let startReceipt = try sourceSlice(
            wireSource,
            from: "public struct ConversationStartReceiptV1",
            before: "public enum CancellationReceiptV1"
        )
        XCTAssertEqual(identifierCounts(in: definitions)[compatibilityKind, default: 0], 2)
        XCTAssertEqual(identifierCounts(in: definitions)[compatibility, default: 0], 1)
        XCTAssertEqual(identifierCounts(in: catalogEntry)[compatibility, default: 0], 2)
        XCTAssertEqual(identifierCounts(in: startReceipt)[compatibility, default: 0], 3)

        let allowedCompatibilityFiles = Set([
            wireURL.standardizedFileURL.path,
            compatibilityTestURL.standardizedFileURL.path,
        ])
        var legacyLeaks: [String] = []
        var compatibilityLeaks: [String] = []
        for url in try allSwiftSourceFiles() {
            let counts = identifierCounts(in: try String(contentsOf: url, encoding: .utf8))
            if counts[legacy, default: 0] > 0 || counts[legacyKind, default: 0] > 0 {
                legacyLeaks.append(url.path)
            }
            if !allowedCompatibilityFiles.contains(url.standardizedFileURL.path),
               counts[compatibility, default: 0] > 0
                || counts[compatibilityKind, default: 0] > 0
            {
                compatibilityLeaks.append(url.path)
            }
        }
        XCTAssertEqual(legacyLeaks, [])
        XCTAssertEqual(compatibilityLeaks, [])
    }

    private func requireFlattened<T: RuntimeV2FlattenedPayload>(_ type: T.Type) {}

    private func decode<T: Decodable>(_ type: T.Type, _ value: Any) throws -> T {
        try JSONDecoder().decode(type, from: try bytes(value))
    }

    private func assertDecodeFails<T: Decodable>(
        _ type: T.Type,
        _ value: Any,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        XCTAssertThrowsError(
            try JSONDecoder().decode(type, from: try bytes(value)),
            file: file,
            line: line
        )
    }

    private func object<T: Encodable>(_ value: T) throws -> [String: Any] {
        try XCTUnwrap(
            JSONSerialization.jsonObject(with: JSONEncoder().encode(value)) as? [String: Any]
        )
    }

    private func bytes(_ value: Any) throws -> Data {
        try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys, .fragmentsAllowed])
    }

    private func snapshot(
        configurationState: [String: Any],
        items: [[String: Any]]
    ) -> [String: Any] {
        [
            "conversationId": "conversation-snapshot",
            "baseEventCursor": "beforeFirst",
            "configurationState": configurationState,
            "items": items,
        ]
    }

    private func snapshotCapabilitiesItem(_ kind: String) -> [String: Any] {
        [
            "kind": "capabilities", "commandId": NSNull(), "itemId": NSNull(),
            "entityId": NSNull(), "capabilities": capabilities(kind),
        ]
    }

    private func snapshotItem(kind: String, commandID: Any) -> [String: Any] {
        [
            "kind": "item", "commandId": commandID, "itemId": "item-1",
            "entityId": "entity-1", "item": agentItem(kind),
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

    private func configuredState(_ kind: String) -> [String: Any] {
        let configuration: [String: Any] = kind == "codex"
            ? [
                "approvalPolicy": "on-request", "sandbox": "workspace-write",
                "reasoningEffort": "high",
            ]
            : [
                "permissionMode": "default", "model": NSNull(), "effort": NSNull(),
                "outputStyle": NSNull(),
            ]
        return [
            "configurationRevision": 1,
            "configuration": [
                "vendorControl": ["agentKind": kind, "configuration": configuration],
            ],
        ]
    }

    private func unconfiguredState() -> [String: Any] {
        ["configurationRevision": 0, "configuration": NSNull()]
    }

    private func agentItem(_ kind: String) -> [String: Any] {
        ["kind": kind, "text": "hello", "meta": ["vendorExtensions": [:]]]
    }

    private func catalogDelta(_ revision: UInt64, removedID: String? = nil) -> RuntimeCatalogDeltaV2 {
        RuntimeCatalogDeltaV2(
            catalogRevision: revision,
            changes: [
                .removed(
                    conversationID: RuntimeConversationID(
                        rawValue: removedID ?? "conversation-\(revision)"
                    )
                ),
            ]
        )
    }

    private func catalogBackfill(
        revisions: [Int],
        after: Any,
        through: UInt64,
        removedID: String? = nil
    ) -> [String: Any] {
        [
            "scope": "catalog",
            "range": ["after": after, "through": ["at": through]],
            "deltas": revisions.map { revision in
                [
                    "catalogRevision": revision,
                    "changes": [[
                        "kind": "removed",
                        "conversation_id": removedID ?? "conversation-\(revision)",
                    ]],
                ]
            },
        ]
    }

    private func conversationBackfill(
        conversationID: String,
        eventConversationIDs: [String],
        sequences: [UInt64],
        through: UInt64
    ) -> [String: Any] {
        [
            "scope": "conversation",
            "conversationId": conversationID,
            "capabilitiesPreamble": capabilities("codex"),
            "range": ["after": "beforeFirst", "through": ["at": through]],
            "events": zip(eventConversationIDs, sequences).map {
                runtimeEvent(conversationID: $0.0, sequence: $0.1)
            },
        ]
    }

    private func runtimeEvent(conversationID: String, sequence: UInt64) -> [String: Any] {
        [
            "conversationId": conversationID,
            "eventId": "event-\(sequence)",
            "eventSeq": sequence,
            "commandId": NSNull(),
            "itemId": NSNull(),
            "entityId": NSNull(),
            "body": [
                "kind": "error",
                "failure": [
                    "code": "daemon.test", "message": "failure", "diagnosticRef": NSNull(),
                ],
            ],
        ]
    }

    private func rustProducedReplyPayload(named name: String) throws -> [String: Any] {
        let text = try String(contentsOf: rustFixtureURL, encoding: .utf8)
        let matches = try text.split(whereSeparator: \.isNewline).compactMap { line -> [String: Any]? in
            let object = try XCTUnwrap(
                JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any]
            )
            return object["case"] as? String == name ? object : nil
        }
        let fixture = try XCTUnwrap(matches.only)
        XCTAssertEqual(fixture["wireType"] as? String, "runtimeEnvelope")
        let value = try XCTUnwrap(fixture["value"] as? [String: Any])
        let body = try XCTUnwrap(value["body"] as? [String: Any])
        XCTAssertEqual(body["message"] as? String, "reply")
        return try XCTUnwrap(body["payload"] as? [String: Any])
    }

    private var repositoryRoot: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }

    private var rustFixtureURL: URL {
        repositoryRoot.appendingPathComponent("protocol/agentdeck/fixtures/runtime-v5-wire.jsonl")
    }

    private func allSwiftSourceFiles() throws -> [URL] {
        var result: [URL] = []
        let package = repositoryRoot.appendingPathComponent("Package.swift")
        if FileManager.default.fileExists(atPath: package.path) {
            result.append(package.standardizedFileURL)
        }
        for directory in ["Sources", "Tests", "ios", "designs"] {
            let root = repositoryRoot.appendingPathComponent(directory)
            guard FileManager.default.fileExists(atPath: root.path) else { continue }
            guard let enumerator = FileManager.default.enumerator(
                at: root,
                includingPropertiesForKeys: [.isRegularFileKey],
                options: [.skipsHiddenFiles]
            ) else {
                throw CocoaError(.fileReadUnknown)
            }
            for case let url as URL in enumerator where url.pathExtension == "swift" {
                result.append(url.standardizedFileURL)
            }
        }
        return result.sorted { $0.path < $1.path }
    }

    private func sourceSlice(
        _ source: String,
        from start: String,
        before end: String
    ) throws -> String {
        guard let startRange = source.range(of: start),
              let endRange = source.range(
                  of: end,
                  range: startRange.upperBound..<source.endIndex
              )
        else {
            throw CocoaError(.fileReadCorruptFile)
        }
        return String(source[startRange.lowerBound..<endRange.lowerBound])
    }

    private func identifierCounts(in source: String) -> [String: Int] {
        source.split { !$0.isLetter && !$0.isNumber && $0 != "_" }
            .reduce(into: [:]) { counts, token in
                counts[String(token), default: 0] += 1
            }
    }
}

private struct RuntimeV2SnapshotBackfillFlattenedProbe<Value: RuntimeV2FlattenedPayload>: Codable {
    let value: Value
    init(from decoder: Decoder) throws {
        value = try Value(flattenedFrom: decoder)
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: RuntimeV2CodingKey.self)
        try value.encodeFlattenedFields(into: &container)
    }
}

private extension Array {
    var only: Element? { count == 1 ? self[0] : nil }
}
