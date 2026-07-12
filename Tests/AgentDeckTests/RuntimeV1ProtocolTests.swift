import Foundation
import XCTest
@testable import AgentDeckCore

final class RuntimeV1ProtocolTests: XCTestCase {
    func testApprovalResolvedRequiresExplicitDecisionEvenWhenWinnerIsAbsent() throws {
        func event(_ decision: Any?) throws -> Data {
            var body: [String: Any] = [
                "kind": "approvalResolved",
                "turn_id": "turn-expired-without-winner",
                "approval_id": "approval-expired-without-winner",
                "state": "expired",
            ]
            if let decision {
                body["decision"] = decision
            }
            return try JSONSerialization.data(withJSONObject: [
                "version": 1,
                "messageId": "message-expired-without-winner",
                "body": [
                    "message": "stream",
                    "payload": [
                        "stream": "event",
                        "conversationId": "conversation-expired-without-winner",
                        "eventId": "event-expired-without-winner",
                        "eventSeq": 1,
                        "itemId": NSNull(),
                        "entityId": NSNull(),
                        "body": body,
                    ],
                ],
            ])
        }

        guard case let .stream(.event(runtimeEvent)) = try RuntimeV1WireCodec.decodeEnvelope(
            event(NSNull())
        ).body,
            case let .approvalResolved(_, _, decision, .expired) = runtimeEvent.body
        else {
            return XCTFail("expected explicit null decision to decode as a winner-less expiry")
        }
        XCTAssertNil(decision)
        XCTAssertThrowsError(try RuntimeV1WireCodec.decodeEnvelope(event(nil)))
    }

    func testRuntimeCoreContractUsesPureStartAndExactCancelAndReceiptTargets() throws {
        let fixtures = try loadFixtures()

        let start = try XCTUnwrap(fixtures.first { $0.name == "requestStart" })
        guard case let .request(.start(agentKind, idempotencyKey, cwd, title)) =
            try RuntimeV1WireCodec.decodeEnvelope(start.value).body
        else {
            return XCTFail("expected pure conversation start request")
        }
        XCTAssertEqual(agentKind, .codex)
        XCTAssertEqual(idempotencyKey.rawValue, "start-key-request-1")
        XCTAssertEqual(cwd, "/tmp/runtime-request-1")
        XCTAssertEqual(title, "fixture conversation")

        let queued = try XCTUnwrap(fixtures.first { $0.name == "requestCancelQueued" })
        guard case let .request(.cancelQueued(conversationID, commandID)) =
            try RuntimeV1WireCodec.decodeEnvelope(queued.value).body
        else {
            return XCTFail("expected queued cancellation request")
        }
        XCTAssertEqual(conversationID.rawValue, "conversation-request-1")
        XCTAssertEqual(commandID.rawValue, "command-request-queued-1")

        let active = try XCTUnwrap(fixtures.first { $0.name == "requestCancelActive" })
        guard case let .request(.cancelActive(_, turnID)) =
            try RuntimeV1WireCodec.decodeEnvelope(active.value).body
        else {
            return XCTFail("expected active cancellation request")
        }
        XCTAssertEqual(turnID.rawValue, "turn-request-active-1")

        let query = try XCTUnwrap(fixtures.first { $0.name == "requestQueryReceiptCommand" })
        guard case let .request(.queryReceipt(.command(_, commandID))) =
            try RuntimeV1WireCodec.decodeEnvelope(query.value).body
        else {
            return XCTFail("expected command receipt selector")
        }
        XCTAssertEqual(commandID.rawValue, "command-query-1")

        let created = try XCTUnwrap(fixtures.first { $0.name == "conversationStartCreated" })
        guard case let .reply(.conversationStart(receipt)) =
            try RuntimeV1WireCodec.decodeEnvelope(created.value).body
        else {
            return XCTFail("expected conversation start receipt")
        }
        XCTAssertEqual(receipt.conversationID.rawValue, "conversation-created-1")
        XCTAssertEqual(receipt.adapterStateKey.rawValue, "adapter-state-created-1")
        XCTAssertFalse(receipt.replayed)

        let cancellation = try XCTUnwrap(
            fixtures.first { $0.name == "cancellationActiveCancelRequested" }
        )
        guard case let .reply(.cancellation(.activeCancelRequested(_, turnID))) =
            try RuntimeV1WireCodec.decodeEnvelope(cancellation.value).body
        else {
            return XCTFail("expected active cancel requested receipt")
        }
        XCTAssertEqual(turnID.rawValue, "turn-cancel-1")
    }

    func testRuntimeCoreContractRejectsLegacyAmbiguousCancelAndReceiptSelectors() throws {
        let invalidPayloads: [[String: Any]] = [
            ["request": "cancel", "conversationId": "c1", "turnId": NSNull()],
            ["request": "cancelQueued", "conversationId": "c1"],
            ["request": "cancelActive", "conversationId": "c1"],
            ["request": "queryReceipt", "conversationId": "c1"],
            [
                "request": "queryReceipt", "selector": "command",
                "conversationId": "c1", "commandId": "cmd1", "idempotencyKey": "k1",
            ],
        ]
        for payload in invalidPayloads {
            let value: [String: Any] = [
                "version": 1,
                "messageId": "invalid-contract",
                "body": ["message": "request", "payload": payload],
            ]
            XCTAssertThrowsError(
                try RuntimeV1WireCodec.decodeEnvelope(
                    JSONSerialization.data(withJSONObject: value)
                )
            )
        }
    }

    func testCommandStatusReplyPreservesExactJournalStateAndOptionalTurn() throws {
        func envelopeData(_ payload: [String: Any]) throws -> Data {
            try JSONSerialization.data(withJSONObject: [
                "version": 1,
                "messageId": "message-command-status",
                "body": ["message": "reply", "payload": payload],
            ])
        }

        let accepted = try envelopeData([
            "reply": "commandStatus",
            "conversationId": "conversation-status-1",
            "commandId": "command-status-accepted-1",
            "status": "accepted",
            "turnId": NSNull(),
        ])
        guard case let .reply(.commandStatus(receipt)) =
            try RuntimeV1WireCodec.decodeEnvelope(accepted).body
        else {
            return XCTFail("expected exact command status receipt")
        }
        XCTAssertEqual(receipt.conversationID.rawValue, "conversation-status-1")
        XCTAssertEqual(receipt.commandID.rawValue, "command-status-accepted-1")
        XCTAssertEqual(receipt.status, .accepted)
        XCTAssertNil(receipt.turnID)

        for status in CommandStatusV1.allCases {
            let turnID = status == .accepted ? nil : "turn-\(status.rawValue)"
            let data = try envelopeData([
                "reply": "commandStatus",
                "conversationId": "conversation-status-1",
                "commandId": "command-\(status.rawValue)",
                "status": status.rawValue,
                "turnId": turnID ?? NSNull(),
            ])
            let envelope = try RuntimeV1WireCodec.decodeEnvelope(data)
            let encoded = try RuntimeV1WireCodec.encode(envelope)
            XCTAssertEqual(try normalizedJSON(encoded), try normalizedJSON(data))
        }
    }

    func testBackfillBareEventRejectsInjectedStreamContextTag() throws {
        let fixtures = try loadRawFixtureObjects()
        var backfill = try fixtureValue(named: "replyBackfill", in: fixtures)
        let stable = try fixtureValue(named: "stableIds", in: fixtures)
        let stableBody = try XCTUnwrap(stable["body"] as? [String: Any])
        let injectedEvent = try XCTUnwrap(stableBody["payload"] as? [String: Any])
        XCTAssertEqual(injectedEvent["stream"] as? String, "event")

        var backfillBody = try XCTUnwrap(backfill["body"] as? [String: Any])
        var backfillPayload = try XCTUnwrap(backfillBody["payload"] as? [String: Any])
        backfillPayload["events"] = [injectedEvent]
        backfillBody["payload"] = backfillPayload
        backfill["body"] = backfillBody

        XCTAssertThrowsError(
            try RuntimeV1WireCodec.decodeEnvelope(
                JSONSerialization.data(withJSONObject: backfill)
            )
        )
    }

    func testStreamSyncCompleteRejectsInjectedReplyContextTag() throws {
        let fixtures = try loadRawFixtureObjects()
        var value = try fixtureValue(named: "streamSyncComplete", in: fixtures)
        var body = try XCTUnwrap(value["body"] as? [String: Any])
        var payload = try XCTUnwrap(body["payload"] as? [String: Any])
        payload["reply"] = "syncComplete"
        body["payload"] = payload
        value["body"] = body

        XCTAssertThrowsError(
            try RuntimeV1WireCodec.decodeEnvelope(
                JSONSerialization.data(withJSONObject: value)
            )
        )
    }

    func testAgentItemMetaNullIsRejectedInsteadOfDefaulted() throws {
        let fixtures = try loadRawFixtureObjects()
        var value = try fixtureValue(named: "agentItemAssistantMessage", in: fixtures)
        var envelopeBody = try XCTUnwrap(value["body"] as? [String: Any])
        var payload = try XCTUnwrap(envelopeBody["payload"] as? [String: Any])
        var body = try XCTUnwrap(payload["body"] as? [String: Any])
        var item = try XCTUnwrap(body["item"] as? [String: Any])
        item["meta"] = NSNull()
        body["item"] = item
        payload["body"] = body
        envelopeBody["payload"] = payload
        value["body"] = envelopeBody

        XCTAssertThrowsError(
            try RuntimeV1WireCodec.decodeEnvelope(
                JSONSerialization.data(withJSONObject: value)
            )
        )
    }

    func testVendorExtensionsNullIsRejectedInsteadOfDefaulted() throws {
        let fixtures = try loadRawFixtureObjects()
        var value = try fixtureValue(named: "agentItemAssistantMessage", in: fixtures)
        var envelopeBody = try XCTUnwrap(value["body"] as? [String: Any])
        var payload = try XCTUnwrap(envelopeBody["payload"] as? [String: Any])
        var body = try XCTUnwrap(payload["body"] as? [String: Any])
        var item = try XCTUnwrap(body["item"] as? [String: Any])
        item["meta"] = ["vendorExtensions": NSNull()]
        body["item"] = item
        payload["body"] = body
        envelopeBody["payload"] = payload
        value["body"] = envelopeBody

        XCTAssertThrowsError(
            try RuntimeV1WireCodec.decodeEnvelope(
                JSONSerialization.data(withJSONObject: value)
            )
        )
    }

    func testCreatePairInviteTTLDefaultsWhenMissingButRejectsNull() throws {
        let fixtures = try loadRawFixtureObjects()
        let source = try fixtureValue(named: "requestCreatePairInvite", in: fixtures)

        var missing = source
        var missingBody = try XCTUnwrap(missing["body"] as? [String: Any])
        var missingPayload = try XCTUnwrap(missingBody["payload"] as? [String: Any])
        missingPayload.removeValue(forKey: "ttlSecs")
        missingBody["payload"] = missingPayload
        missing["body"] = missingBody

        let decoded = try RuntimeV1WireCodec.decodeEnvelope(
            JSONSerialization.data(withJSONObject: missing)
        )
        guard case .request(.createPairInvite(_, let ttlSecs, _)) = decoded.body else {
            return XCTFail("expected createPairInvite request")
        }
        XCTAssertEqual(ttlSecs, 300)

        var explicitNull = source
        var nullBody = try XCTUnwrap(explicitNull["body"] as? [String: Any])
        var nullPayload = try XCTUnwrap(nullBody["payload"] as? [String: Any])
        nullPayload["ttlSecs"] = NSNull()
        nullBody["payload"] = nullPayload
        explicitNull["body"] = nullBody

        XCTAssertThrowsError(
            try RuntimeV1WireCodec.decodeEnvelope(
                JSONSerialization.data(withJSONObject: explicitNull)
            )
        )
    }

    func testRustJSONLDecodesAndReencodesWithEquivalentJSON() throws {
        let fixtures = try loadFixtures()
        XCTAssertGreaterThan(fixtures.count, 16)

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

    func testRustFixtureCoversEveryTopLevelRuntimeVariant() throws {
        let fixtures = try loadRawFixtureObjects()
        let payloads = fixtures.compactMap { fixture -> [String: Any]? in
            guard fixture["wireType"] as? String == "runtimeEnvelope",
                  let value = fixture["value"] as? [String: Any],
                  let body = value["body"] as? [String: Any]
            else {
                return nil
            }
            return body
        }

        XCTAssertEqual(
            Set(payloads.compactMap { $0["message"] as? String }),
            ["request", "reply", "stream"]
        )
        XCTAssertEqual(
            Set(payloads.compactMap { body in
                (body["payload"] as? [String: Any])?["request"] as? String
            }),
            [
                "hello", "catalog", "subscribe", "start", "sendPrompt",
                "resolveApproval", "retryApproval", "cancelQueued", "cancelActive",
                "queryReceipt",
                "createPairInvite", "listPendingPairings", "confirmPairing",
                "cancelPairing", "revoke", "trustReset",
            ]
        )
        XCTAssertEqual(
            Set(payloads.compactMap { body in
                (body["payload"] as? [String: Any])?["reply"] as? String
            }),
            [
                "hello", "command", "commandStatus", "conversationStart", "cancellation", "approval",
                "revocation", "catalog", "snapshot", "backfill", "syncComplete",
                "pairInvite", "pendingPairings", "failure",
            ]
        )
        XCTAssertEqual(
            Set(payloads.compactMap { body in
                (body["payload"] as? [String: Any])?["stream"] as? String
            }),
            ["event", "catalogDelta", "syncComplete"]
        )
    }

    func testRustFixtureCoversEveryRuntimeEventAndAgentItemVariant() throws {
        let events = try loadRawFixtureObjects().compactMap { fixture -> [String: Any]? in
            guard fixture["wireType"] as? String == "runtimeEnvelope",
                  let value = fixture["value"] as? [String: Any],
                  let envelopeBody = value["body"] as? [String: Any],
                  envelopeBody["message"] as? String == "stream",
                  let payload = envelopeBody["payload"] as? [String: Any],
                  payload["stream"] as? String == "event"
            else {
                return nil
            }
            return payload
        }
        let eventBodies = events.compactMap { $0["body"] as? [String: Any] }
        XCTAssertEqual(
            Set(eventBodies.compactMap { $0["kind"] as? String }),
            [
                "capabilities", "item", "turnStarted", "actionRequest",
                "approvalResolved", "turnCompleted", "turnInterrupted", "error",
            ]
        )
        XCTAssertEqual(
            Set(eventBodies.compactMap { body in
                (body["item"] as? [String: Any])?["kind"] as? String
            }),
            [
                "userMessage", "assistantMessage", "reasoning", "shell", "diff", "plan",
                "imageReference", "toolCall", "raw",
            ]
        )
    }

    func testRustOptionalNullsAndBTreeSetOrderArePreserved() throws {
        let fixtures = try loadRawFixtureObjects()
        let capabilities = try fixtureValue(named: "eventCapabilitiesMulti", in: fixtures)
        let capabilitiesBody = try eventBody(in: capabilities)
        let capabilitiesValue = try XCTUnwrap(capabilitiesBody["capabilities"] as? [String: Any])
        XCTAssertEqual(
            capabilitiesValue["features"] as? [String],
            ["streamingMessages", "approval", "worktree", "codexSkills"]
        )

        let shell = try eventItem(
            in: fixtureValue(named: "agentItemShellNullOptionals", in: fixtures)
        )
        XCTAssertTrue(shell["exitCode"] is NSNull)
        XCTAssertTrue(shell["durationMs"] is NSNull)

        let image = try eventItem(
            in: fixtureValue(named: "agentItemImageReferenceNullPaths", in: fixtures)
        )
        XCTAssertTrue(image["savedPath"] is NSNull)
        XCTAssertTrue(image["originalPath"] is NSNull)

        let tool = try eventItem(
            in: fixtureValue(named: "agentItemToolCallNullResult", in: fixtures)
        )
        XCTAssertTrue(tool["result"] is NSNull)
    }

    func testShellExitCodeUsesRustI32Bounds() throws {
        let fixtures = try loadRawFixtureObjects()
        for name in ["agentItemShellMinExit", "agentItemShellMaxExit"] {
            let value = try fixtureValue(named: name, in: fixtures)
            XCTAssertNoThrow(
                try RuntimeV1WireCodec.decodeEnvelope(
                    JSONSerialization.data(withJSONObject: value)
                ),
                name
            )
        }

        let source = try fixtureValue(named: "agentItemShellMaxExit", in: fixtures)
        for overflow in [Int64(Int32.max) + 1, Int64(Int32.min) - 1] {
            var value = source
            var envelopeBody = try XCTUnwrap(value["body"] as? [String: Any])
            var payload = try XCTUnwrap(envelopeBody["payload"] as? [String: Any])
            var body = try XCTUnwrap(payload["body"] as? [String: Any])
            var item = try XCTUnwrap(body["item"] as? [String: Any])
            item["exitCode"] = overflow
            body["item"] = item
            payload["body"] = body
            envelopeBody["payload"] = payload
            value["body"] = envelopeBody
            XCTAssertThrowsError(
                try RuntimeV1WireCodec.decodeEnvelope(
                    JSONSerialization.data(withJSONObject: value)
                ),
                "Rust i32 overflow must fail closed"
            )
        }
    }

    func testExpandedRuntimeDTOsRejectNestedUnknownFieldsAtRealEntry() throws {
        let fixtures = try loadRawFixtureObjects()
        let mutations: [(String, (inout [String: Any]) throws -> Void)] = [
            ("requestResolveApproval", { value in
                var envelopeBody = try XCTUnwrap(value["body"] as? [String: Any])
                var payload = try XCTUnwrap(envelopeBody["payload"] as? [String: Any])
                var decision = try XCTUnwrap(payload["decision"] as? [String: Any])
                decision["unexpected"] = true
                payload["decision"] = decision
                envelopeBody["payload"] = payload
                value["body"] = envelopeBody
            }),
            ("replyCatalog", { value in
                var envelopeBody = try XCTUnwrap(value["body"] as? [String: Any])
                var payload = try XCTUnwrap(envelopeBody["payload"] as? [String: Any])
                var entries = try XCTUnwrap(payload["entries"] as? [[String: Any]])
                entries[0]["unexpected"] = true
                payload["entries"] = entries
                envelopeBody["payload"] = payload
                value["body"] = envelopeBody
            }),
            ("eventActionRequest", { value in
                var envelopeBody = try XCTUnwrap(value["body"] as? [String: Any])
                var payload = try XCTUnwrap(envelopeBody["payload"] as? [String: Any])
                var body = try XCTUnwrap(payload["body"] as? [String: Any])
                var request = try XCTUnwrap(body["request"] as? [String: Any])
                var vendor = try XCTUnwrap(request["vendor"] as? [String: Any])
                vendor["unexpected"] = true
                request["vendor"] = vendor
                body["request"] = request
                payload["body"] = body
                envelopeBody["payload"] = payload
                value["body"] = envelopeBody
            }),
            ("eventTurnCompleted", { value in
                var envelopeBody = try XCTUnwrap(value["body"] as? [String: Any])
                var payload = try XCTUnwrap(envelopeBody["payload"] as? [String: Any])
                var body = try XCTUnwrap(payload["body"] as? [String: Any])
                var summary = try XCTUnwrap(body["summary"] as? [String: Any])
                summary["unexpected"] = true
                body["summary"] = summary
                payload["body"] = body
                envelopeBody["payload"] = payload
                value["body"] = envelopeBody
            }),
        ]

        for (name, mutate) in mutations {
            var value = try fixtureValue(named: name, in: fixtures)
            try mutate(&value)
            try assertEnvelopeDecodeRejects(value, at: "unexpected")
        }
    }

    func testTransferEnvelopeEnforcesRustBoundsAtRealCodecEntry() throws {
        let fixtures = try loadRawFixtureObjects()
        let source = try fixtureValue(named: "transferEnvelope", in: fixtures)

        var maximums = source
        maximums["partIndex"] = Int(TransferEnvelopeV1.maxPartCount - 1)
        maximums["partCount"] = Int(TransferEnvelopeV1.maxPartCount)
        maximums["totalBytes"] = Int(TransferEnvelopeV1.maxTotalBytes)
        XCTAssertNoThrow(
            try RuntimeV1WireCodec.decodeTransferEnvelope(
                JSONSerialization.data(withJSONObject: maximums)
            )
        )

        var maximumPart = source
        maximumPart["part"] = Data(repeating: 0xA5, count: TransferEnvelopeV1.maxPartBytes)
            .base64EncodedString()
        XCTAssertNoThrow(
            try RuntimeV1WireCodec.decodeTransferEnvelope(
                JSONSerialization.data(withJSONObject: maximumPart)
            )
        )

        let invalidMutations: [(String, Any)] = [
            ("partCount", 0),
            ("partCount", Int(TransferEnvelopeV1.maxPartCount) + 1),
            ("partIndex", 1),
            ("totalBytes", Int(TransferEnvelopeV1.maxTotalBytes) + 1),
            ("totalSha256", Data(repeating: 0, count: 31).base64EncodedString()),
            (
                "part",
                Data(repeating: 0, count: TransferEnvelopeV1.maxPartBytes + 1)
                    .base64EncodedString()
            ),
        ]
        for (field, value) in invalidMutations {
            var invalid = source
            invalid[field] = value
            XCTAssertThrowsError(
                try RuntimeV1WireCodec.decodeTransferEnvelope(
                    JSONSerialization.data(withJSONObject: invalid)
                ),
                field
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

        var missingValue = try XCTUnwrap(snapshot["value"] as? [String: Any])
        var missingBody = try XCTUnwrap(missingValue["body"] as? [String: Any])
        var missingPayload = try XCTUnwrap(missingBody["payload"] as? [String: Any])
        let originalItems = try XCTUnwrap(missingPayload["items"] as? [[String: Any]])
        missingPayload["items"] = Array(originalItems.dropFirst())
        missingBody["payload"] = missingPayload
        missingValue["body"] = missingBody
        XCTAssertThrowsError(
            try RuntimeV1WireCodec.decodeEnvelope(
                JSONSerialization.data(withJSONObject: missingValue)
            )
        )

        var duplicateValue = try XCTUnwrap(snapshot["value"] as? [String: Any])
        var duplicateBody = try XCTUnwrap(duplicateValue["body"] as? [String: Any])
        var duplicatePayload = try XCTUnwrap(duplicateBody["payload"] as? [String: Any])
        var duplicateItems = try XCTUnwrap(duplicatePayload["items"] as? [[String: Any]])
        duplicateItems.append(originalItems[0])
        duplicatePayload["items"] = duplicateItems
        duplicateBody["payload"] = duplicatePayload
        duplicateValue["body"] = duplicateBody
        XCTAssertThrowsError(
            try RuntimeV1WireCodec.decodeEnvelope(
                JSONSerialization.data(withJSONObject: duplicateValue)
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

    private func fixtureValue(
        named name: String,
        in fixtures: [[String: Any]]
    ) throws -> [String: Any] {
        let fixture = try XCTUnwrap(fixtures.first { ($0["case"] as? String) == name })
        return try XCTUnwrap(fixture["value"] as? [String: Any])
    }

    private func eventBody(in value: [String: Any]) throws -> [String: Any] {
        let envelopeBody = try XCTUnwrap(value["body"] as? [String: Any])
        let payload = try XCTUnwrap(envelopeBody["payload"] as? [String: Any])
        return try XCTUnwrap(payload["body"] as? [String: Any])
    }

    private func eventItem(in value: [String: Any]) throws -> [String: Any] {
        try XCTUnwrap(eventBody(in: value)["item"] as? [String: Any])
    }

    private func assertEnvelopeDecodeRejects(
        _ value: [String: Any],
        at expectedKey: String,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        do {
            _ = try RuntimeV1WireCodec.decodeEnvelope(
                JSONSerialization.data(withJSONObject: value)
            )
            XCTFail("decode unexpectedly accepted invalid (expectedKey)", file: file, line: line)
        } catch let DecodingError.typeMismatch(_, context),
                let DecodingError.valueNotFound(_, context),
                let DecodingError.dataCorrupted(context) {
            XCTAssertEqual(context.codingPath.last?.stringValue, expectedKey, file: file, line: line)
        } catch let DecodingError.keyNotFound(key, _) {
            XCTAssertEqual(key.stringValue, expectedKey, file: file, line: line)
        } catch {
            XCTFail("unexpected decode error (error)", file: file, line: line)
        }
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
