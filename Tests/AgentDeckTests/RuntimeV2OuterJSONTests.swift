import Foundation
import XCTest
@testable import AgentDeckCore

final class RuntimeV2OuterJSONTests: XCTestCase {
    func testRustJSONFixturesDecodeAndReencodeSemantically() throws {
        let fixtures = try loadFixtures()
        XCTAssertEqual(fixtures.count, 103)
        XCTAssertEqual(Set(fixtures.map(\.name)).count, 103)

        let envelopes = fixtures.filter { $0.wireType == "runtimeEnvelope" }
        let transfers = fixtures.filter { $0.wireType == "transferEnvelope" }
        let compact = fixtures.filter { $0.wireType == "runtimeTransferCarrierV1" }
        XCTAssertEqual(envelopes.count, 101)
        XCTAssertEqual(transfers.count, 1)
        XCTAssertEqual(compact.count, 1)
        XCTAssertEqual(Set(fixtures.filter { $0.wireType != "runtimeTransferCarrierV1" }.map(\.name)), Set(Self.expectedTypedPaths.keys))

        var outerCounts = ["request": 0, "reply": 0, "stream": 0]
        for fixture in envelopes {
            let input = try jsonData(fixture.value)
            let decoded = try JSONDecoder().decode(RuntimeEnvelopeV2.self, from: input)
            let actualPath = try typedPath(decoded, outerCounts: &outerCounts)
            XCTAssertEqual(actualPath, Self.expectedTypedPaths[fixture.name], "typed path for \(fixture.name)")
            let output = try JSONEncoder().encode(decoded)
            try assertJSONSemanticallyEqual(input, output, caseName: fixture.name)
        }
        XCTAssertEqual(outerCounts, ["request": 29, "reply": 46, "stream": 26])

        let transfer = try XCTUnwrap(transfers.first)
        let input = try jsonData(transfer.value)
        let decoded = try JSONDecoder().decode(TransferEnvelopeV2.self, from: input)
        XCTAssertEqual(Self.expectedTypedPaths[transfer.name], "transferEnvelope")
        let output = try JSONEncoder().encode(decoded)
        try assertJSONSemanticallyEqual(input, output, caseName: transfer.name)
    }

    func testEnvelopeMessageAndTagsRejectUnknownOrWrongVersion() throws {
        let helloFixture = try fixture(named: "requestHello")
        let valid = try objectValue(helloFixture.value)
        _ = try decodeEnvelope(valid)

        for path in ["envelope", "message", "request"] {
            var changed = valid
            switch path {
            case "envelope":
                changed["future"] = true
            case "message":
                var body = try dictionary(changed["body"])
                body["future"] = true
                changed["body"] = body
            default:
                var body = try dictionary(changed["body"])
                var payload = try dictionary(body["payload"])
                payload["future"] = true
                body["payload"] = payload
                changed["body"] = body
            }
            XCTAssertThrowsError(try decodeEnvelope(changed), "\(path) must deny unknown fields")
        }

        var wrongVersion = valid
        wrongVersion["version"] = 1
        XCTAssertThrowsError(try decodeEnvelope(wrongVersion))

        var wrongMessage = valid
        var body = try dictionary(wrongMessage["body"])
        body["message"] = "future"
        wrongMessage["body"] = body
        XCTAssertThrowsError(try decodeEnvelope(wrongMessage))

        for caseName in ["replyHello", "streamTransferPart"] {
            var branch = try objectValue(try fixture(named: caseName).value)
            var branchBody = try dictionary(branch["body"])
            var branchPayload = try dictionary(branchBody["payload"])
            branchPayload["future"] = true
            branchBody["payload"] = branchPayload
            branch["body"] = branchBody
            XCTAssertThrowsError(try decodeEnvelope(branch), "\(caseName) must deny unknown fields")
        }

        let v1Egress = RuntimeEnvelopeV2(
            version: 1,
            messageID: RuntimeMessageID(rawValue: "version-one-egress"),
      body: .request(.hello(runtimeProtocolVersion: runtimeProtocolVersionCurrent))
        )
        XCTAssertThrowsError(try JSONEncoder().encode(v1Egress)) { error in
            XCTAssertTrue(error is EncodingError)
        }
    }

    func testCatalogPageCursorIsRequiredNullableAndPairTTLDefaultsOnlyWhenMissing() throws {
        var catalog = try objectValue(try fixture(named: "requestCatalog").value)
        var body = try dictionary(catalog["body"])
        var payload = try dictionary(body["payload"])

        payload.removeValue(forKey: "pageCursor")
        body["payload"] = payload
        catalog["body"] = body
        XCTAssertThrowsError(try decodeEnvelope(catalog))

        payload["pageCursor"] = NSNull()
        body["payload"] = payload
        catalog["body"] = body
        let catalogRoundTrip = try encodedObject(try decodeEnvelope(catalog))
        let catalogPayload = try payloadObject(catalogRoundTrip)
        XCTAssertTrue(catalogPayload.keys.contains("pageCursor"))
        XCTAssertTrue(catalogPayload["pageCursor"] is NSNull)

        var invite = try objectValue(try fixture(named: "requestCreatePairInvite").value)
        body = try dictionary(invite["body"])
        payload = try dictionary(body["payload"])
        payload.removeValue(forKey: "ttlSecs")
        body["payload"] = payload
        invite["body"] = body
        let defaulted = try encodedObject(try decodeEnvelope(invite))
        XCTAssertEqual(try payloadObject(defaulted)["ttlSecs"] as? Int, 300)

        payload["ttlSecs"] = NSNull()
        body["payload"] = payload
        invite["body"] = body
        XCTAssertThrowsError(try decodeEnvelope(invite))
    }

    func testSendPromptRequiresConfigurationRevision() throws {
        var wire = try objectValue(try fixture(named: "requestSendPrompt").value)
        var body = try dictionary(wire["body"])
        var payload = try dictionary(body["payload"])
        XCTAssertNotNil(payload["expectedConfigurationRevision"])

        payload.removeValue(forKey: "expectedConfigurationRevision")
        body["payload"] = payload
        wire["body"] = body
        XCTAssertThrowsError(try decodeEnvelope(wire))

        payload["expectedConfigurationRevision"] = NSNull()
        body["payload"] = payload
        wire["body"] = body
        XCTAssertThrowsError(try decodeEnvelope(wire))
    }

    func testMessageAndTransferIdentifiersUseOneTo1024UTF8Bytes() throws {
        let fixture = try fixture(named: "requestHello")
        var wire = try objectValue(fixture.value)
        for invalid in ["", String(repeating: "x", count: 1025), String(repeating: "中", count: 342)] {
            wire["messageId"] = invalid
            XCTAssertThrowsError(try decodeEnvelope(wire)) { error in
                guard case let DecodingError.dataCorrupted(context) = error else {
                    return XCTFail("expected DecodingError.dataCorrupted, got \(error)")
                }
                XCTAssertEqual(context.codingPath.last?.stringValue, "messageId")
            }
        }
        wire["messageId"] = String(repeating: "x", count: 1024)
        _ = try decodeEnvelope(wire)
        wire["messageId"] = String(repeating: "中", count: 341)
        _ = try decodeEnvelope(wire)

        let invalidMessageEgress = RuntimeEnvelopeV2(
            version: runtimeProtocolVersionCurrent,
            messageID: RuntimeMessageID(rawValue: String(repeating: "中", count: 342)),
      body: .request(.hello(runtimeProtocolVersion: runtimeProtocolVersionCurrent))
        )
        XCTAssertThrowsError(try JSONEncoder().encode(invalidMessageEgress)) { error in
            XCTAssertTrue(error is EncodingError)
        }

        let hash = Data(repeating: 7, count: 32)
        XCTAssertThrowsError(
            try TransferEnvelopeV2(
                transferID: RuntimeTransferID(rawValue: ""),
                partIndex: 0,
                partCount: 1,
                totalSHA256: hash,
                totalBytes: 1,
                part: Data([1])
            )
        ) { error in
            XCTAssertEqual(error as? RuntimeV2WireError, .invalidTransferBounds)
        }
        XCTAssertNoThrow(
            try TransferEnvelopeV2(
                transferID: RuntimeTransferID(rawValue: String(repeating: "y", count: 1024)),
                partIndex: 0,
                partCount: 1,
                totalSHA256: hash,
                totalBytes: 1,
                part: Data([1])
            )
        )
        XCTAssertNoThrow(
            try TransferEnvelopeV2(
                transferID: RuntimeTransferID(rawValue: String(repeating: "中", count: 341)),
                partIndex: 0,
                partCount: 1,
                totalSHA256: hash,
                totalBytes: 1,
                part: Data([1])
            )
        )
        XCTAssertThrowsError(
            try TransferEnvelopeV2(
                transferID: RuntimeTransferID(rawValue: String(repeating: "y", count: 1025)),
                partIndex: 0,
                partCount: 1,
                totalSHA256: hash,
                totalBytes: 1,
                part: Data([1])
            )
        ) { error in
            XCTAssertEqual(error as? RuntimeV2WireError, .invalidTransferBounds)
        }
        XCTAssertThrowsError(
            try TransferEnvelopeV2(
                transferID: RuntimeTransferID(rawValue: String(repeating: "中", count: 342)),
                partIndex: 0,
                partCount: 1,
                totalSHA256: hash,
                totalBytes: 1,
                part: Data([1])
            )
        ) { error in
            XCTAssertEqual(error as? RuntimeV2WireError, .invalidTransferBounds)
        }
    }

    func testJSONTransferProfileRepresents64MiBOnlyWith94Parts() throws {
        XCTAssertEqual(TransferEnvelopeV2.maxJSONPartBytes, 700 * 1024)
        XCTAssertEqual(TransferEnvelopeV2.maxJSONPartCount, 94)
        XCTAssertEqual(TransferEnvelopeV2.maxCompactPartBytes, 3_670_016)
        XCTAssertEqual(TransferEnvelopeV2.maxCompactPartCount, 64)
        XCTAssertEqual(TransferEnvelopeV2.maxTotalBytes, 64 * 1024 * 1024)

        let transferID = RuntimeTransferID(rawValue: "profile-transfer")
        let hash = Data(repeating: 9, count: 32)
        let total = TransferEnvelopeV2.maxTotalBytes
        XCTAssertThrowsError(
            try TransferEnvelopeV2(
                transferID: transferID,
                partIndex: 0,
                partCount: 64,
                totalSHA256: hash,
                totalBytes: total,
                part: Data([1])
            )
        )
        XCTAssertNoThrow(
            try TransferEnvelopeV2(
                transferID: transferID,
                partIndex: 0,
                partCount: 94,
                totalSHA256: hash,
                totalBytes: total,
                part: Data([1])
            )
        )
        XCTAssertThrowsError(
            try TransferEnvelopeV2(
                transferID: transferID,
                partIndex: 0,
                partCount: 93,
                totalSHA256: hash,
                totalBytes: total,
                part: Data([1])
            )
        )

        let invalidCases: [(UInt32, UInt32, Data, UInt64, Data)] = [
            (0, 0, hash, 0, Data()),
            (94, 94, hash, total, Data([1])),
            (0, 95, hash, total, Data([1])),
            (0, 94, Data(repeating: 0, count: 31), total, Data([1])),
            (0, 94, Data(repeating: 0, count: 33), total, Data([1])),
            (0, 94, hash, total + 1, Data([1])),
            (0, 1, hash, 0, Data([1])),
            (0, 2, hash, UInt64(2 * 700 * 1024), Data(repeating: 0, count: 700 * 1024 + 1)),
            (UInt32.max, 1, hash, 1, Data([1])),
            (0, UInt32.max, hash, 1, Data([1])),
        ]
        for (index, count, candidateHash, bytes, part) in invalidCases {
            XCTAssertThrowsError(
                try TransferEnvelopeV2(
                    transferID: transferID,
                    partIndex: index,
                    partCount: count,
                    totalSHA256: candidateHash,
                    totalBytes: bytes,
                    part: part
                )
            ) { error in
                XCTAssertEqual(error as? RuntimeV2WireError, .invalidTransferBounds)
            }
        }
    }

    func testTransferInvalidMatrixRejectsStandaloneReplyAndStreamIngress() throws {
        let baseline = try objectValue(try fixture(named: "transferEnvelope").value)
        let max = TransferEnvelopeV2.maxJSONPartBytes
        var candidates: [(String, [String: Any])] = []

        func mutated(_ name: String, _ key: String, _ value: Any) {
            var candidate = baseline
            candidate[key] = value
            candidates.append((name, candidate))
        }

        mutated("empty-id", "transferId", "")
        mutated("long-id", "transferId", String(repeating: "x", count: 1025))
        mutated("utf8-id", "transferId", String(repeating: "中", count: 342))
        mutated("zero-count", "partCount", 0)
        mutated("index-equals-count", "partIndex", 1)
        mutated("count-over-profile", "partCount", 95)
        mutated("hash-31", "totalSha256", Data(repeating: 0, count: 31).base64EncodedString())
        mutated("hash-33", "totalSha256", Data(repeating: 0, count: 33).base64EncodedString())
        mutated("total-over-cap", "totalBytes", TransferEnvelopeV2.maxTotalBytes + 1)
        mutated("part-over-total", "totalBytes", 23)
        mutated("max-index", "partIndex", UInt32.max)
        mutated("max-count", "partCount", UInt32.max)

        var unrepresentable = baseline
        unrepresentable["partCount"] = 93
        unrepresentable["totalBytes"] = TransferEnvelopeV2.maxTotalBytes
        candidates.append(("unrepresentable", unrepresentable))

        var oversizedPart = baseline
        oversizedPart["partCount"] = 2
        oversizedPart["totalBytes"] = UInt64(2 * max)
        oversizedPart["part"] = Data(repeating: 1, count: max + 1).base64EncodedString()
        candidates.append(("oversized-part", oversizedPart))

        var unknown = baseline
        unknown["future"] = true
        candidates.append(("unknown", unknown))

        let flattenedCases = [
            (fixture: "replyTransferPart", tag: "reply"),
            (fixture: "streamTransferPart", tag: "stream"),
        ]
        for (name, candidate) in candidates {
            assertTransferDecodeFails(candidate, label: "standalone \(name)")
            for flattened in flattenedCases {
                var envelope = try objectValue(try fixture(named: flattened.fixture).value)
                var body = try dictionary(envelope["body"])
                var payload = candidate
                payload[flattened.tag] = "transferPart"
                body["payload"] = payload
                envelope["body"] = body
                XCTAssertThrowsError(try decodeEnvelope(envelope), "\(flattened.fixture) \(name)") {
                    XCTAssertTrue($0 is DecodingError, "expected DecodingError, got \($0)")
                }
            }
        }
    }

    func testMaximumJSONPartFitsStrictOneMiBEnvelopeWithMaximumIDs() throws {
        let transfer = try TransferEnvelopeV2(
            transferID: RuntimeTransferID(rawValue: String(repeating: "t", count: 1024)),
            partIndex: 0,
            partCount: 94,
            totalSHA256: Data(repeating: 5, count: 32),
            totalBytes: TransferEnvelopeV2.maxTotalBytes,
            part: Data(repeating: 0x5a, count: TransferEnvelopeV2.maxJSONPartBytes)
        )
        let envelope = RuntimeEnvelopeV2(
            version: runtimeProtocolVersionCurrent,
            messageID: RuntimeMessageID(rawValue: String(repeating: "m", count: 1024)),
            body: .reply(.transferPart(transfer))
        )
        let encoded = try JSONEncoder().encode(envelope)
        XCTAssertLessThan(encoded.count, 1024 * 1024)
    }

    // MARK: - Fixture helpers

    private static let expectedTypedPaths: [String: String] = [
        "stableIds": "stream.event.item.userMessage",
        "requestHello": "request.hello",
        "requestDescribeAgents": "request.describeAgents",
        "requestCatalog": "request.catalog",
        "requestSubscribe": "request.subscribe",
        "requestUnsubscribe": "request.unsubscribe",
        "requestBackfillCatalog": "request.backfill.catalog",
        "requestStart": "request.start",
        "requestConfigureCodex": "request.configureConversation.codex",
        "requestConfigureClaudeCode": "request.configureConversation.claudeCode",
        "requestUpdateMetadataRename": "request.updateConversationMetadata.rename",
        "requestUpdateMetadataArchive": "request.updateConversationMetadata.setArchived",
        "requestSendPrompt": "request.sendPrompt",
        "requestResolveApproval": "request.resolveApproval",
        "requestRetryApproval": "request.retryApproval",
        "requestCancelQueued": "request.cancelQueued",
        "requestCancelActive": "request.cancelActive",
        "requestQueryReceiptCommand": "request.queryReceipt.command",
        "requestQueryReceiptIdempotency": "request.queryReceipt.idempotency",
        "requestCreatePairInvite": "request.createPairInvite",
        "requestListPendingPairings": "request.listPendingPairings",
        "requestConfirmPairing": "request.confirmPairing",
        "requestCancelPairing": "request.cancelPairing",
        "requestRevoke": "request.revoke.selfDevice",
        "requestTrustReset": "request.trustReset",
        "requestTrustResetWithAdminPurgeReceipt": "request.trustReset",
        "requestTrustResetForUninstallPurge": "request.trustReset",
        "requestMachineEnroll": "request.machineEnroll",
        "requestMachineRemoteStatus": "request.machineRemoteStatus",
        "requestStageUpgrade": "request.stageUpgrade",
        "replyHello": "reply.hello",
        "replyAgents": "reply.agents",
        "configurationApplied": "reply.configuration.applied",
        "configurationReplayed": "reply.configuration.replayed",
        "configurationConflict": "reply.configuration.conflict",
        "configurationFailed": "reply.configuration.failed",
        "metadataApplied": "reply.conversationMetadata.applied",
        "metadataReplayed": "reply.conversationMetadata.replayed",
        "metadataConflict": "reply.conversationMetadata.conflict",
        "metadataFailed": "reply.conversationMetadata.failed",
        "stageUpgradeStaged": "reply.stageUpgrade.staged",
        "stageUpgradeAwaitingIdle": "reply.stageUpgrade.awaitingIdle",
        "stageUpgradeReplayed": "reply.stageUpgrade.replayed",
        "stageUpgradeFailed": "reply.stageUpgrade.failed",
        "replyCatalog": "reply.catalog",
        "replySubscriptionSubscribed": "reply.subscription.subscribed",
        "replySubscriptionUnsubscribed": "reply.subscription.unsubscribed",
        "replyBackfill": "reply.backfill.conversation",
        "replySyncComplete": "reply.syncComplete",
        "replyPairInvite": "reply.pairInvite",
        "replyPendingPairings": "reply.pendingPairings",
        "replyMachineRemoteStatus": "reply.machineRemoteStatus.active",
        "replyFailure": "reply.failure",
        "streamCatalogDelta": "stream.catalogDelta.removed",
        "streamCatalogUpsert": "stream.catalogDelta.upserted",
        "eventCapabilitiesMulti": "stream.event.capabilities",
        "eventConfigurationChanged": "stream.event.configurationChanged",
        "eventCodexVendorPanel": "stream.event.vendorPanel.codex.placeholder",
        "eventClaudeCodeVendorPanel": "stream.event.vendorPanel.claudeCode.systemStatus",
        "eventTurnStarted": "stream.event.turnStarted",
        "eventActionRequest": "stream.event.actionRequest.executeCommand",
        "eventApprovalResolved": "stream.event.approvalResolved.applied",
        "eventApprovalExpiredWithoutWinner": "stream.event.approvalResolved.expired.nullDecision",
        "eventTurnCompleted": "stream.event.turnCompleted",
        "eventTurnInterrupted": "stream.event.turnInterrupted",
        "eventError": "stream.event.error",
        "agentItemUserMessage": "stream.event.item.userMessage",
        "agentItemAssistantMessage": "stream.event.item.assistantMessage",
        "agentItemReasoning": "stream.event.item.reasoning",
        "agentItemShellMinExit": "stream.event.item.shell",
        "agentItemDiffNullPatch": "stream.event.item.diff",
        "agentItemPlanNullDetail": "stream.event.item.plan",
        "agentItemImageReferenceNullPaths": "stream.event.item.imageReference",
        "agentItemToolCallNullResult": "stream.event.item.toolCall",
        "agentItemRaw": "stream.event.item.raw",
        "agentItemShellMaxExit": "stream.event.item.shell",
        "agentItemShellNullOptionals": "stream.event.item.shell",
        "commandAccepted": "reply.command.accepted",
        "commandReplayed": "reply.command.replayed",
        "commandFailed": "reply.command.failed",
        "commandStatusAccepted": "reply.commandStatus.accepted",
        "commandStatusStarted": "reply.commandStatus.started",
        "conversationStartCreated": "reply.conversationStart.created",
        "conversationStartReplayed": "reply.conversationStart.replayed",
        "cancellationQueuedCanceled": "reply.cancellation.queuedCanceled",
        "cancellationActiveCancelRequested": "reply.cancellation.activeCancelRequested",
        "approvalClaimed": "reply.approval.claimed",
        "approvalApplied": "reply.approval.applied",
        "approvalDeliveryFailed": "reply.approval.deliveryFailed",
        "approvalExpired": "reply.approval.expired",
        "approvalAlreadyHandled-claimed": "reply.approval.alreadyHandled.claimed",
        "approvalAlreadyHandled-applying": "reply.approval.alreadyHandled.applying",
        "approvalAlreadyHandled-applied": "reply.approval.alreadyHandled.applied",
        "approvalAlreadyHandled-deliveryFailed": "reply.approval.alreadyHandled.deliveryFailed",
        "approvalAlreadyHandled-expired": "reply.approval.alreadyHandled.expired",
        "revocationCommitted": "reply.revocation.committed",
        "revocationFailed": "reply.revocation.failed",
        "capabilitiesFirstSnapshot": "reply.snapshot.configured",
        "unconfiguredSnapshot": "reply.snapshot.unconfigured",
        "transferEnvelope": "transferEnvelope",
        "replyTransferPart": "reply.transferPart",
        "streamTransferPart": "stream.transferPart",
    ]

    private func typedPath(
        _ envelope: RuntimeEnvelopeV2,
        outerCounts: inout [String: Int]
    ) throws -> String {
        switch envelope.body {
        case .request(let request):
            outerCounts["request", default: 0] += 1
            return requestPath(request)
        case .reply(let reply):
            outerCounts["reply", default: 0] += 1
            return replyPath(reply)
        case .stream(let stream):
            outerCounts["stream", default: 0] += 1
            return try streamPath(stream)
        }
    }

    private func requestPath(_ request: RuntimeRequestV2) -> String {
        switch request {
        case .hello: "request.hello"
        case .describeAgents: "request.describeAgents"
        case .catalog: "request.catalog"
        case .subscribe: "request.subscribe"
        case .unsubscribe: "request.unsubscribe"
        case .backfill(let value):
            switch value {
            case .catalog: "request.backfill.catalog"
            case .conversation: "request.backfill.conversation"
            }
        case .start: "request.start"
        case .configureConversation(let value):
            switch value.configuration.vendorControl {
            case .codex: "request.configureConversation.codex"
            case .claudeCode: "request.configureConversation.claudeCode"
            }
        case .updateConversationMetadata(let value):
            switch value.mutation {
            case .rename: "request.updateConversationMetadata.rename"
            case .setArchived: "request.updateConversationMetadata.setArchived"
            }
        case .sendPrompt: "request.sendPrompt"
        case .resolveApproval: "request.resolveApproval"
        case .retryApproval: "request.retryApproval"
        case .cancelQueued: "request.cancelQueued"
        case .cancelActive: "request.cancelActive"
        case .queryReceipt(let value):
            switch value {
            case .command: "request.queryReceipt.command"
            case .idempotency: "request.queryReceipt.idempotency"
            }
        case .createPairInvite: "request.createPairInvite"
        case .listPendingPairings: "request.listPendingPairings"
        case .confirmPairing: "request.confirmPairing"
        case .cancelPairing: "request.cancelPairing"
        case .revoke(let target):
            switch target {
            case .selfDevice: "request.revoke.selfDevice"
            case .device: "request.revoke.device"
            }
        case .machineEnroll: "request.machineEnroll"
        case .machineRemoteStatus: "request.machineRemoteStatus"
        case .trustReset: "request.trustReset"
        case .stageUpgrade: "request.stageUpgrade"
        }
    }

    private func replyPath(_ reply: RuntimeReplyV2) -> String {
        switch reply {
        case .hello: "reply.hello"
        case .agents: "reply.agents"
        case .configuration(let value):
            switch value {
            case .applied: "reply.configuration.applied"
            case .replayed: "reply.configuration.replayed"
            case .conflict: "reply.configuration.conflict"
            case .failed: "reply.configuration.failed"
            }
        case .conversationMetadata(let value):
            switch value {
            case .applied: "reply.conversationMetadata.applied"
            case .replayed: "reply.conversationMetadata.replayed"
            case .conflict: "reply.conversationMetadata.conflict"
            case .failed: "reply.conversationMetadata.failed"
            }
        case .stageUpgrade(let value):
            switch value {
            case .staged: "reply.stageUpgrade.staged"
            case .awaitingIdle: "reply.stageUpgrade.awaitingIdle"
            case .replayed: "reply.stageUpgrade.replayed"
            case .failed: "reply.stageUpgrade.failed"
            }
        case .command(let value):
            switch value {
            case .accepted: "reply.command.accepted"
            case .replayed: "reply.command.replayed"
            case .failed: "reply.command.failed"
            }
        case .commandStatus(let value): "reply.commandStatus.\(value.status.rawValue)"
        case .conversationStart(let value):
            value.replayed ? "reply.conversationStart.replayed" : "reply.conversationStart.created"
        case .cancellation(let value):
            switch value {
            case .queuedCanceled: "reply.cancellation.queuedCanceled"
            case .activeCancelRequested: "reply.cancellation.activeCancelRequested"
            }
        case .approval(let value):
            switch value {
            case .claimed: "reply.approval.claimed"
            case .applied: "reply.approval.applied"
            case .alreadyHandled(_, _, let state): "reply.approval.alreadyHandled.\(state.rawValue)"
            case .deliveryFailed: "reply.approval.deliveryFailed"
            case .expired: "reply.approval.expired"
            }
        case .revocation(let value):
            switch value {
            case .committed: "reply.revocation.committed"
            case .failed: "reply.revocation.failed"
            }
        case .subscription(let value):
            switch value {
            case .subscribed: "reply.subscription.subscribed"
            case .unsubscribed: "reply.subscription.unsubscribed"
            }
        case .catalog: "reply.catalog"
        case .snapshot(let value):
            value.configurationState.configuration == nil
                ? "reply.snapshot.unconfigured" : "reply.snapshot.configured"
        case .backfill(let value):
            switch value {
            case .catalog: "reply.backfill.catalog"
            case .conversation: "reply.backfill.conversation"
            }
        case .syncComplete: "reply.syncComplete"
        case .transferPart: "reply.transferPart"
        case .pairInvite: "reply.pairInvite"
        case .pendingPairings: "reply.pendingPairings"
    case .machineRemoteStatus(let status):
      "reply.machineRemoteStatus.\(status.lifecycle.rawValue)"
        case .failure: "reply.failure"
        }
    }

    private func streamPath(_ stream: RuntimeStreamItemV2) throws -> String {
        switch stream {
        case .catalogDelta(let delta):
            switch try XCTUnwrap(delta.changes.first) {
            case .upserted: "stream.catalogDelta.upserted"
            case .removed: "stream.catalogDelta.removed"
            }
        case .event(let event): try eventPath(event.body)
        case .transferPart: "stream.transferPart"
        }
    }

    private func eventPath(_ body: RuntimeEventBodyV2) throws -> String {
        switch body {
        case .capabilities:
            return "stream.event.capabilities"
        case .configurationChanged:
            return "stream.event.configurationChanged"
        case .vendorPanelEvent(let panel):
            switch panel {
            case .codex(let event):
                switch event {
                case .placeholder:
                    return "stream.event.vendorPanel.codex.placeholder"
                }
            case .claudeCode(let event):
                switch event {
                case .hookFired:
                    return "stream.event.vendorPanel.claudeCode.hookFired"
                case .systemStatus:
                    return "stream.event.vendorPanel.claudeCode.systemStatus"
                }
            }
        case .item(let item):
            return "stream.event.item.\(itemPath(item))"
        case .turnStarted:
            return "stream.event.turnStarted"
        case .actionRequest(_, _, let request):
            return "stream.event.actionRequest.\(request.kind.rawValue)"
        case .approvalResolved(_, _, let decision, let state):
            let suffix = decision == nil ? ".nullDecision" : ""
            return "stream.event.approvalResolved.\(state.rawValue)\(suffix)"
        case .turnCompleted:
            return "stream.event.turnCompleted"
        case .turnInterrupted:
            return "stream.event.turnInterrupted"
        case .error:
            return "stream.event.error"
        }
    }

    private func itemPath(_ item: RuntimeAgentItemV1) -> String {
        switch item {
        case .userMessage: "userMessage"
        case .assistantMessage: "assistantMessage"
        case .reasoning: "reasoning"
        case .shell: "shell"
        case .diff: "diff"
        case .plan: "plan"
        case .imageReference: "imageReference"
        case .toolCall: "toolCall"
        case .raw: "raw"
        }
    }

    private struct Fixture {
        let name: String
        let wireType: String
        let value: Any
    }

    private func fixture(named name: String) throws -> Fixture {
        try XCTUnwrap(loadFixtures().first { $0.name == name })
    }

    private func loadFixtures() throws -> [Fixture] {
        let data = try Data(contentsOf: repositoryRoot
            .appendingPathComponent("protocol/agentdeck/fixtures/runtime-v3-wire.jsonl"))
        let text = try XCTUnwrap(String(data: data, encoding: .utf8))
        return try text.split(separator: "\n").map { line in
            let object = try XCTUnwrap(
                JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any]
            )
            return Fixture(
                name: try XCTUnwrap(object["case"] as? String),
                wireType: try XCTUnwrap(object["wireType"] as? String),
                value: try XCTUnwrap(object["value"])
            )
        }
    }

    private var repositoryRoot: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }

    private func decodeEnvelope(_ object: [String: Any]) throws -> RuntimeEnvelopeV2 {
        try JSONDecoder().decode(RuntimeEnvelopeV2.self, from: jsonData(object))
    }

    private func assertTransferDecodeFails(
        _ object: [String: Any],
        label: String,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertThrowsError(
            try JSONDecoder().decode(TransferEnvelopeV2.self, from: jsonData(object)),
            label,
            file: file,
            line: line
        ) { error in
            XCTAssertTrue(
                error is DecodingError,
                "expected DecodingError for \(label), got \(error)",
                file: file,
                line: line
            )
        }
    }

    private func encodedObject(_ envelope: RuntimeEnvelopeV2) throws -> [String: Any] {
        try objectValue(JSONSerialization.jsonObject(with: JSONEncoder().encode(envelope)))
    }

    private func payloadObject(_ envelope: [String: Any]) throws -> [String: Any] {
        let body = try dictionary(envelope["body"])
        return try dictionary(body["payload"])
    }

    private func objectValue(_ value: Any) throws -> [String: Any] {
        try XCTUnwrap(value as? [String: Any])
    }

    private func dictionary(_ value: Any?) throws -> [String: Any] {
        try XCTUnwrap(value as? [String: Any])
    }

    private func jsonData(_ value: Any) throws -> Data {
        try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
    }

    private func assertJSONSemanticallyEqual(
        _ lhs: Data,
        _ rhs: Data,
        caseName: String,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        let left = try JSONSerialization.jsonObject(with: lhs) as AnyObject
        let right = try JSONSerialization.jsonObject(with: rhs) as AnyObject
        XCTAssertEqual(left as? NSObject, right as? NSObject, "fixture \(caseName)", file: file, line: line)
    }
}
