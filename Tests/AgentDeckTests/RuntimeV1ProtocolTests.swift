import Foundation
import XCTest
@testable import AgentDeckCore

final class RuntimeV1ProtocolTests: XCTestCase {
    func testRustJSONLDecodesAndReencodesWithEquivalentJSON() throws {
        let fixtures = try loadFixtures()
        XCTAssertEqual(fixtures.count, 16)
        XCTAssertEqual(
            Set(fixtures.map(\.name)),
            [
                "stableIds",
                "commandAccepted", "commandReplayed", "commandFailed",
                "approvalClaimed", "approvalApplied", "approvalDeliveryFailed",
                "approvalExpired",
                "approvalAlreadyHandled-claimed", "approvalAlreadyHandled-applying",
                "approvalAlreadyHandled-applied", "approvalAlreadyHandled-deliveryFailed",
                "approvalAlreadyHandled-expired",
                "revocationCommitted", "capabilitiesFirstSnapshot", "transferEnvelope",
            ]
        )

        for fixture in fixtures {
            let encoded: Data
            switch fixture.wireType {
            case "runtimeEnvelope":
                encoded = try RuntimeV1WireCodec.encode(
                    RuntimeV1WireCodec.decodeEnvelope(fixture.value)
                )
            case "transferEnvelope":
                encoded = try RuntimeV1WireCodec.encode(
                    RuntimeV1WireCodec.decodeTransferEnvelope(fixture.value)
                )
            default:
                return XCTFail("unknown fixture wire type \(fixture.wireType)")
            }
            XCTAssertEqual(
                try normalizedJSON(encoded),
                try normalizedJSON(fixture.value),
                "Rust/Swift semantic JSON drift for \(fixture.name)"
            )
        }
    }

    func testStableIDsAndCapabilitiesFirstSnapshotAreTyped() throws {
        let fixtures = try loadFixtures()
        let stable = try XCTUnwrap(fixtures.first { $0.name == "stableIds" })
        let envelope = try RuntimeV1WireCodec.decodeEnvelope(stable.value)
        XCTAssertEqual(envelope.messageID.rawValue, "message-stable-1")
        guard case let .stream(.event(event)) = envelope.body,
              case let .turnStarted(turnID, commandID) = event.body
        else {
            return XCTFail("stableIds must be a typed turnStarted stream event")
        }
        XCTAssertEqual(event.conversationID.rawValue, "conversation-stable-1")
        XCTAssertEqual(event.eventID.rawValue, "event-stable-1")
        XCTAssertEqual(event.itemID?.rawValue, "item-stable-1")
        XCTAssertEqual(event.entityID?.rawValue, "entity-stable-1")
        XCTAssertEqual(turnID.rawValue, "turn-stable-1")
        XCTAssertEqual(commandID.rawValue, "command-stable-1")

        let snapshotFixture = try XCTUnwrap(
            fixtures.first { $0.name == "capabilitiesFirstSnapshot" }
        )
        let snapshotEnvelope = try RuntimeV1WireCodec.decodeEnvelope(snapshotFixture.value)
        guard case let .reply(.snapshot(snapshot)) = snapshotEnvelope.body else {
            return XCTFail("snapshot fixture must decode as RuntimeReply.snapshot")
        }
        guard case .capabilities = snapshot.items.first else {
            return XCTFail("snapshot must expose capabilities as its first typed item")
        }
        guard snapshot.items.count == 2, case .item = snapshot.items[1] else {
            return XCTFail("snapshot must expose the following agent item")
        }
    }

    func testRealDecodeEntryRejectsUnknownFieldsAndInvalidSnapshotOrder() throws {
        let fixtures = try loadRawFixtureObjects()
        let stable = try XCTUnwrap(fixtures.first { ($0["case"] as? String) == "stableIds" })
        var stableValue = try XCTUnwrap(stable["value"] as? [String: Any])
        stableValue["unexpected"] = true
        XCTAssertThrowsError(
            try RuntimeV1WireCodec.decodeEnvelope(try JSONSerialization.data(withJSONObject: stableValue))
        )

        let command = try XCTUnwrap(
            fixtures.first { ($0["case"] as? String) == "commandAccepted" }
        )
        var commandValue = try XCTUnwrap(command["value"] as? [String: Any])
        var body = try XCTUnwrap(commandValue["body"] as? [String: Any])
        var payload = try XCTUnwrap(body["payload"] as? [String: Any])
        payload["unexpected"] = true
        body["payload"] = payload
        commandValue["body"] = body
        XCTAssertThrowsError(
            try RuntimeV1WireCodec.decodeEnvelope(
                try JSONSerialization.data(withJSONObject: commandValue)
            )
        )

        let snapshot = try XCTUnwrap(
            fixtures.first { ($0["case"] as? String) == "capabilitiesFirstSnapshot" }
        )
        var snapshotValue = try XCTUnwrap(snapshot["value"] as? [String: Any])
        var snapshotBody = try XCTUnwrap(snapshotValue["body"] as? [String: Any])
        var snapshotPayload = try XCTUnwrap(snapshotBody["payload"] as? [String: Any])
        var items = try XCTUnwrap(snapshotPayload["items"] as? [[String: Any]])
        items.swapAt(0, 1)
        snapshotPayload["items"] = items
        snapshotBody["payload"] = snapshotPayload
        snapshotValue["body"] = snapshotBody
        XCTAssertThrowsError(
            try RuntimeV1WireCodec.decodeEnvelope(
                try JSONSerialization.data(withJSONObject: snapshotValue)
            )
        )

        let transfer = try XCTUnwrap(
            fixtures.first { ($0["case"] as? String) == "transferEnvelope" }
        )
        var transferValue = try XCTUnwrap(transfer["value"] as? [String: Any])
        transferValue["unexpected"] = true
        XCTAssertThrowsError(
            try RuntimeV1WireCodec.decodeTransferEnvelope(
                try JSONSerialization.data(withJSONObject: transferValue)
            )
        )
    }

    func testRealDecodeEntryRejectsUnknownFieldsInsideNestedAgentItems() throws {
        let fixtures = try loadRawFixtureObjects()
        let snapshot = try XCTUnwrap(
            fixtures.first { ($0["case"] as? String) == "capabilitiesFirstSnapshot" }
        )
        let nestedCases: [(name: String, item: [String: Any])] = [
            (
                "diff file",
                [
                    "kind": "diff",
                    "files": [[
                        "path": "README.md",
                        "status": "modified",
                        "unexpected": true,
                    ]],
                ]
            ),
            (
                "plan step",
                [
                    "kind": "plan",
                    "steps": [[
                        "title": "ship Runtime v1",
                        "status": "pending",
                        "unexpected": true,
                    ]],
                ]
            ),
        ]

        for nestedCase in nestedCases {
            var snapshotValue = try XCTUnwrap(snapshot["value"] as? [String: Any])
            var body = try XCTUnwrap(snapshotValue["body"] as? [String: Any])
            var payload = try XCTUnwrap(body["payload"] as? [String: Any])
            var items = try XCTUnwrap(payload["items"] as? [[String: Any]])
            items[1]["item"] = nestedCase.item
            payload["items"] = items
            body["payload"] = payload
            snapshotValue["body"] = body

            XCTAssertThrowsError(
                try RuntimeV1WireCodec.decodeEnvelope(
                    try JSONSerialization.data(withJSONObject: snapshotValue)
                ),
                "nested unknown field must fail closed for \(nestedCase.name)"
            )
        }
    }

    private struct Fixture {
        let name: String
        let wireType: String
        let value: Data
    }

    private func loadFixtures() throws -> [Fixture] {
        try loadRawFixtureObjects().map { object in
            Fixture(
                name: try XCTUnwrap(object["case"] as? String),
                wireType: try XCTUnwrap(object["wireType"] as? String),
                value: try JSONSerialization.data(
                    withJSONObject: XCTUnwrap(object["value"])
                )
            )
        }
    }

    private func loadRawFixtureObjects() throws -> [[String: Any]] {
        let data = try Data(contentsOf: fixtureURL)
        let text = try XCTUnwrap(String(data: data, encoding: .utf8))
        return try text.split(separator: "\n").map { line in
            try XCTUnwrap(
                JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any]
            )
        }
    }

    private func normalizedJSON(_ data: Data) throws -> Data {
        let object = try JSONSerialization.jsonObject(with: data)
        return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    }

    private var fixtureURL: URL {
        repoRoot
            .appendingPathComponent("protocol")
            .appendingPathComponent("agentdeck")
            .appendingPathComponent("fixtures")
            .appendingPathComponent("runtime-v1-wire.jsonl")
    }

    private var repoRoot: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }
}
