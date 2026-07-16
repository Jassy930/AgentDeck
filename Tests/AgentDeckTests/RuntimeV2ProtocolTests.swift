import Foundation
import XCTest
@testable import AgentDeckCore

final class RuntimeV2ProtocolTests: XCTestCase {
    func testCodexConfigurationRequiresExactKeysAndRequiredValues() throws {
        let valid: [String: Any] = [
            "approvalPolicy": "on-request",
            "sandbox": "workspace-write",
            "reasoningEffort": "high",
        ]
        let decoded = try decode(RuntimeCodexConversationConfigurationV2.self, valid)
        XCTAssertEqual(decoded.approvalPolicy, .onRequest)
        XCTAssertEqual(decoded.sandbox, .workspaceWrite)
        XCTAssertEqual(decoded.reasoningEffort, .high)

        for key in valid.keys {
            var missing = valid
            missing.removeValue(forKey: key)
            try assertDecodeFails(RuntimeCodexConversationConfigurationV2.self, missing)

            var null = valid
            null[key] = NSNull()
            try assertDecodeFails(RuntimeCodexConversationConfigurationV2.self, null)
        }
        var unknown = valid
        unknown["futurePolicy"] = true
        try assertDecodeFails(RuntimeCodexConversationConfigurationV2.self, unknown)

        let encoded = try object(
            RuntimeCodexConversationConfigurationV2(
                approvalPolicy: .onRequest,
                sandbox: .workspaceWrite,
                reasoningEffort: .high
            )
        )
        XCTAssertEqual(Set(encoded.keys), Set(valid.keys))
    }

    func testClaudeCodeOptionalsNormalizeMissingAndNullAndEncodeExplicitNull() throws {
        let missing: [String: Any] = ["permissionMode": "default"]
        let explicitNull: [String: Any] = [
            "permissionMode": "default",
            "model": NSNull(),
            "effort": NSNull(),
            "outputStyle": NSNull(),
        ]
        for wire in [missing, explicitNull] {
            let decoded = try decode(RuntimeClaudeCodeConversationConfigurationV2.self, wire)
            XCTAssertEqual(decoded.permissionMode, .default)
            XCTAssertNil(decoded.model)
            XCTAssertNil(decoded.effort)
            XCTAssertNil(decoded.outputStyle)
        }

        let value = try RuntimeClaudeCodeConversationConfigurationV2(
            permissionMode: .default,
            model: nil,
            effort: nil,
            outputStyle: nil
        )
        let encoded = try object(value)
        XCTAssertEqual(
            Set(encoded.keys),
            ["permissionMode", "model", "effort", "outputStyle"]
        )
        XCTAssertTrue(encoded["model"] is NSNull)
        XCTAssertTrue(encoded["effort"] is NSNull)
        XCTAssertTrue(encoded["outputStyle"] is NSNull)

        try assertDecodeFails(
            RuntimeClaudeCodeConversationConfigurationV2.self,
            ["model": NSNull(), "effort": NSNull(), "outputStyle": NSNull()]
        )
        try assertDecodeFails(
            RuntimeClaudeCodeConversationConfigurationV2.self,
            ["permissionMode": NSNull()]
        )
        try assertDecodeFails(
            RuntimeClaudeCodeConversationConfigurationV2.self,
            ["permissionMode": "default", "unknown": true]
        )

        let validUTF8 = String(repeating: "中", count: 341)
        XCTAssertNoThrow(
            try RuntimeClaudeCodeConversationConfigurationV2(
                permissionMode: .default,
                model: validUTF8,
                effort: "high",
                outputStyle: "concise"
            )
        )
        for invalid in ["", "bad\0value", String(repeating: "中", count: 342)] {
            var ingress = explicitNull
            ingress["model"] = invalid
            try assertDecodeFails(RuntimeClaudeCodeConversationConfigurationV2.self, ingress)
            XCTAssertThrowsError(
                try RuntimeClaudeCodeConversationConfigurationV2(
                    permissionMode: .default,
                    model: invalid,
                    effort: nil,
                    outputStyle: nil
                )
            )
        }
    }

    func testConfigurationVendorTagAndStateAreStrictAndRequiredNullable() throws {
        let configured = codexConfiguration()
        let state0: [String: Any] = [
            "configurationRevision": 0,
            "configuration": NSNull(),
        ]
        let state1: [String: Any] = [
            "configurationRevision": 1,
            "configuration": configured,
        ]
        XCTAssertNoThrow(try decode(RuntimeConversationConfigurationStateV2.self, state0))
        XCTAssertNoThrow(try decode(RuntimeConversationConfigurationStateV2.self, state1))

        try assertDecodeFails(
            RuntimeConversationConfigurationStateV2.self,
            ["configurationRevision": 0]
        )
        try assertDecodeFails(
            RuntimeConversationConfigurationStateV2.self,
            ["configurationRevision": 1, "configuration": NSNull()]
        )
        try assertDecodeFails(
            RuntimeConversationConfigurationStateV2.self,
            ["configurationRevision": 0, "configuration": configured]
        )
        try assertDecodeFails(
            RuntimeConversationConfigurationStateV2.self,
            ["configurationRevision": 0, "configuration": NSNull(), "future": 1]
        )

        var unknownTag = configured
        var vendor = try XCTUnwrap(unknownTag["vendorControl"] as? [String: Any])
        vendor["agentKind"] = "future_agent"
        unknownTag["vendorControl"] = vendor
        try assertDecodeFails(RuntimeConversationConfigurationV2.self, unknownTag)

        let codex = RuntimeConversationConfigurationV2(
            vendorControl: .codex(
                RuntimeCodexConversationConfigurationV2(
                    approvalPolicy: .never,
                    sandbox: .readOnly,
                    reasoningEffort: .low
                )
            )
        )
        XCTAssertThrowsError(
            try RuntimeConversationConfigurationStateV2(
                configurationRevision: 0,
                configuration: codex
            )
        )
        XCTAssertThrowsError(
            try RuntimeConversationConfigurationStateV2(
                configurationRevision: 1,
                configuration: nil
            )
        )
        let unconfigured = try RuntimeConversationConfigurationStateV2(
            configurationRevision: 0,
            configuration: nil
        )
        XCTAssertTrue(try object(unconfigured)["configuration"] is NSNull)
    }

    func testConfigurationRequestAndReceiptUseTheRevisionZeroAllowlist() throws {
        let request: [String: Any] = [
            "conversationId": "conversation-1",
            "idempotencyKey": "configure-1",
            "expectedConfigurationRevision": 0,
            "configuration": codexConfiguration(),
        ]
        let decodedRequest = try decode(RuntimeConfigureConversationRequestV2.self, request)
        XCTAssertEqual(decodedRequest.expectedConfigurationRevision, 0)
        XCTAssertEqual(Set(try object(decodedRequest).keys), Set(request.keys))
        var unknownRequest = request
        unknownRequest["unexpected"] = true
        try assertDecodeFails(RuntimeConfigureConversationRequestV2.self, unknownRequest)

        for status in ["applied", "replayed"] {
            var receipt: [String: Any] = [
                "status": status,
                "conversationId": "conversation-1",
                "configurationRevision": 0,
            ]
            try assertDecodeFails(RuntimeConfigurationReceiptV2.self, receipt)
            receipt["configurationRevision"] = 1
            XCTAssertNoThrow(try object(try decode(RuntimeConfigurationReceiptV2.self, receipt)))
        }
        let conflict: [String: Any] = [
            "status": "conflict",
            "conversationId": "conversation-1",
            "currentConfigurationRevision": 0,
        ]
        XCTAssertNoThrow(try decode(RuntimeConfigurationReceiptV2.self, conflict))

        let conversationID = RuntimeConversationID(rawValue: "conversation-1")
        XCTAssertThrowsError(
            try JSONEncoder().encode(
                RuntimeConfigurationReceiptV2.applied(
                    conversationID: conversationID,
                    configurationRevision: 0
                )
            )
        )
        XCTAssertNoThrow(
            try JSONEncoder().encode(
                RuntimeConfigurationReceiptV2.conflict(
                    conversationID: conversationID,
                    currentConfigurationRevision: 0
                )
            )
        )
        try assertDecodeFails(
            RuntimeConfigurationReceiptV2.self,
            ["status": "future", "conversationId": "conversation-1"]
        )
    }

    func testMetadataRenameRequiresTitleKeyAndValidatesUTF8OnBothBoundaries() throws {
        let nullRename: [String: Any] = ["kind": "rename", "title": NSNull()]
        let emptyRename: [String: Any] = ["kind": "rename", "title": ""]
        XCTAssertNoThrow(try decode(RuntimeConversationMetadataMutationV2.self, nullRename))
        XCTAssertNoThrow(try decode(RuntimeConversationMetadataMutationV2.self, emptyRename))
        try assertDecodeFails(
            RuntimeConversationMetadataMutationV2.self,
            ["kind": "rename"]
        )
        try assertDecodeFails(
            RuntimeConversationMetadataMutationV2.self,
            ["kind": "rename", "title": NSNull(), "future": true]
        )

        let encodedNull = try object(RuntimeConversationMetadataMutationV2.rename(title: nil))
        XCTAssertEqual(Set(encodedNull.keys), ["kind", "title"])
        XCTAssertTrue(encodedNull["title"] is NSNull)

        for invalid in ["bad\0title", String(repeating: "中", count: 1366)] {
            try assertDecodeFails(
                RuntimeConversationMetadataMutationV2.self,
                ["kind": "rename", "title": invalid]
            )
            XCTAssertThrowsError(
                try JSONEncoder().encode(
                    RuntimeConversationMetadataMutationV2.rename(title: invalid)
                )
            )
        }
    }

    func testMetadataRequestAndReceiptUseTheRevisionZeroAllowlist() throws {
        let request: [String: Any] = [
            "conversationId": "conversation-1",
            "idempotencyKey": "metadata-1",
            "expectedEntryRevision": 0,
            "mutation": ["kind": "setArchived", "archived": true],
        ]
        let decoded = try decode(RuntimeConversationMetadataMutationRequestV2.self, request)
        XCTAssertEqual(decoded.expectedEntryRevision, 0)
        var unknown = request
        unknown["future"] = true
        try assertDecodeFails(RuntimeConversationMetadataMutationRequestV2.self, unknown)

        for status in ["applied", "replayed"] {
            var receipt: [String: Any] = [
                "status": status, "conversationId": "conversation-1", "entryRevision": 0,
            ]
            try assertDecodeFails(RuntimeConversationMetadataReceiptV2.self, receipt)
            receipt["entryRevision"] = 1
            XCTAssertNoThrow(try object(try decode(RuntimeConversationMetadataReceiptV2.self, receipt)))
        }
        let conflict: [String: Any] = [
            "status": "conflict",
            "conversationId": "conversation-1",
            "currentEntryRevision": 0,
        ]
        XCTAssertNoThrow(try decode(RuntimeConversationMetadataReceiptV2.self, conflict))

        let conversationID = RuntimeConversationID(rawValue: "conversation-1")
        XCTAssertThrowsError(
            try JSONEncoder().encode(
                RuntimeConversationMetadataReceiptV2.replayed(
                    conversationID: conversationID,
                    entryRevision: 0
                )
            )
        )
        XCTAssertNoThrow(
            try JSONEncoder().encode(
                RuntimeConversationMetadataReceiptV2.conflict(
                    conversationID: conversationID,
                    currentEntryRevision: 0
                )
            )
        )
    }

    func testAgentDescriptionEnforcesFourWayAgentMatching() throws {
        let validCodex = agentDescription(
            outer: "codex",
            capabilities: "codex",
            vendor: "codex",
            configuration: "codex"
        )
        XCTAssertNoThrow(try decode(RuntimeAgentDescriptionV2.self, validCodex))

        let mismatches = [
            ("claude_code", "codex", "codex", "codex"),
            ("codex", "claude_code", "claude_code", "codex"),
            ("codex", "codex", "claude_code", "codex"),
            ("codex", "codex", "codex", "claude_code"),
        ]
        for (outer, capabilities, vendor, configuration) in mismatches {
            let wire = agentDescription(
                outer: outer,
                capabilities: capabilities,
                vendor: vendor,
                configuration: configuration
            )
            try assertDecodeFails(RuntimeAgentDescriptionV2.self, wire)

            let decodedCapabilities = try decode(
                RuntimeSessionCapabilitiesV1.self,
                capabilitiesObject(agentKind: capabilities, vendorKind: vendor)
            )
            let decodedConfiguration = try decode(
                RuntimeConversationConfigurationV2.self,
                configurationObject(agentKind: configuration)
            )
            XCTAssertThrowsError(
                try RuntimeAgentDescriptionV2(
                    agentKind: try XCTUnwrap(AgentKind(rawValue: outer)),
                    capabilities: decodedCapabilities,
                    defaultConfiguration: decodedConfiguration
                )
            )
        }
    }

    func testAgentDescriptionsAllowEmptyAndRejectDuplicatesAndSeventeenthRow() throws {
        let codex = try decode(
            RuntimeAgentDescriptionV2.self,
            agentDescription(
                outer: "codex",
                capabilities: "codex",
                vendor: "codex",
                configuration: "codex"
            )
        )
        let claudeCode = try decode(
            RuntimeAgentDescriptionV2.self,
            agentDescription(
                outer: "claude_code",
                capabilities: "claude_code",
                vendor: "claude_code",
                configuration: "claude_code"
            )
        )
        XCTAssertNoThrow(try RuntimeAgentDescriptionsV2(agents: []))
        XCTAssertNoThrow(try RuntimeAgentDescriptionsV2(agents: [codex, claudeCode]))
        XCTAssertThrowsError(try RuntimeAgentDescriptionsV2(agents: [codex, codex]))
        XCTAssertThrowsError(
            try RuntimeAgentDescriptionsV2(agents: Array(repeating: codex, count: 17))
        ) { XCTAssertEqual($0 as? RuntimeV2MirrorError, .tooManyAgentDescriptions) }

        XCTAssertNoThrow(try decode(RuntimeAgentDescriptionsV2.self, ["agents": []]))
        try assertDecodeFails(
            RuntimeAgentDescriptionsV2.self,
            ["agents": Array(repeating: agentDescription(
                outer: "codex",
                capabilities: "codex",
                vendor: "codex",
                configuration: "codex"
            ), count: 17)]
        )
    }

    func testStageUpgradeHashAndRequestAreStrictAndSymmetric() throws {
        let valid = String(repeating: "ab", count: 32)
        let hash = try RuntimeArtifactSHA256V2(rawValue: valid)
        XCTAssertEqual(hash.rawValue, valid)
        XCTAssertEqual(try decode(RuntimeArtifactSHA256V2.self, valid).rawValue, valid)

        for invalid in [
            String(repeating: "AB", count: 32),
            String(repeating: "a", count: 63),
            String(repeating: "a", count: 65),
            String(repeating: "g", count: 64),
        ] {
            XCTAssertThrowsError(try RuntimeArtifactSHA256V2(rawValue: invalid))
            try assertDecodeFails(RuntimeArtifactSHA256V2.self, invalid)
        }

        let request: [String: Any] = [
            "targetVersion": "1.2.3-rc_1+local",
            "candidateSha256": valid,
            "idempotencyKey": "upgrade-1",
            "scope": "localOnly",
        ]
        let decoded = try decode(RuntimeStageUpgradeRequestV2.self, request)
        XCTAssertEqual(decoded.targetVersion, "1.2.3-rc_1+local")
        XCTAssertEqual(Set(try object(decoded).keys), Set(request.keys))

        var unknown = request
        unknown["future"] = true
        try assertDecodeFails(RuntimeStageUpgradeRequestV2.self, unknown)
        var remote = request
        remote["scope"] = "remote"
        try assertDecodeFails(RuntimeStageUpgradeRequestV2.self, remote)

        let artifact = try RuntimeArtifactSHA256V2(rawValue: valid)
        for invalid in ["", ".", "..", "v/2", "版本2", String(repeating: "a", count: 129)] {
            var wire = request
            wire["targetVersion"] = invalid
            try assertDecodeFails(RuntimeStageUpgradeRequestV2.self, wire)
            XCTAssertThrowsError(
                try RuntimeStageUpgradeRequestV2(
                    targetVersion: invalid,
                    candidateSHA256: artifact,
                    idempotencyKey: RuntimeIdempotencyKey(rawValue: "upgrade-1"),
                    scope: .localOnly
                )
            )
        }
    }

    func testStageUpgradeReceiptRequiresPositiveActiveTurnsAndValidTargetOnEgress() throws {
        let valid: [String: Any] = [
            "status": "awaitingIdle",
            "targetVersion": "2.0.0",
            "activeTurns": 1,
        ]
        XCTAssertNoThrow(try decode(RuntimeStageUpgradeReceiptV2.self, valid))
        var zero = valid
        zero["activeTurns"] = 0
        try assertDecodeFails(RuntimeStageUpgradeReceiptV2.self, zero)
        var unknown = valid
        unknown["future"] = true
        try assertDecodeFails(RuntimeStageUpgradeReceiptV2.self, unknown)

        XCTAssertThrowsError(
            try JSONEncoder().encode(
                RuntimeStageUpgradeReceiptV2.awaitingIdle(
                    targetVersion: "2.0.0",
                    activeTurns: 0
                )
            )
        )
        XCTAssertThrowsError(
            try JSONEncoder().encode(
                RuntimeStageUpgradeReceiptV2.staged(targetVersion: "..")
            )
        )
    }

    func testChangedCommandReceiptsAllowRevisionZeroAndRemainStrict() throws {
        let accepted: [String: Any] = [
            "status": "accepted",
            "commandId": "command-1",
            "queuePosition": 0,
            "configurationRevision": 0,
        ]
        let replayed: [String: Any] = [
            "status": "replayed",
            "commandId": "command-1",
            "configurationRevision": 0,
        ]
        XCTAssertNoThrow(try decode(CommandReceiptV2.self, accepted))
        XCTAssertNoThrow(try decode(CommandReceiptV2.self, replayed))
        XCTAssertNoThrow(
            try JSONEncoder().encode(
                CommandReceiptV2.accepted(
                    commandID: RuntimeCommandID(rawValue: "command-1"),
                    queuePosition: 0,
                    configurationRevision: 0
                )
            )
        )
        var unknown = accepted
        unknown["legacyField"] = true
        try assertDecodeFails(CommandReceiptV2.self, unknown)
        try assertDecodeFails(CommandReceiptV2.self, ["status": "future"])

        let base: [String: Any] = [
            "conversationId": "conversation-1",
            "commandId": "command-1",
            "configurationRevision": 0,
            "status": "accepted",
        ]
        let missing = try decode(CommandStatusReceiptV2.self, base)
        XCTAssertNil(missing.turnID)
        var explicitNull = base
        explicitNull["turnId"] = NSNull()
        XCTAssertNil(try decode(CommandStatusReceiptV2.self, explicitNull).turnID)

        let value = CommandStatusReceiptV2(
            conversationID: RuntimeConversationID(rawValue: "conversation-1"),
            commandID: RuntimeCommandID(rawValue: "command-1"),
            configurationRevision: 0,
            status: .accepted,
            turnID: nil
        )
        let encoded = try object(value)
        XCTAssertEqual((encoded["configurationRevision"] as? NSNumber)?.uint64Value, 0)
        XCTAssertTrue(encoded["turnId"] is NSNull)
        var statusUnknown = explicitNull
        statusUnknown["future"] = true
        try assertDecodeFails(CommandStatusReceiptV2.self, statusUnknown)
    }

    func testConversationStartReceiptNeverAcceptsOrEmitsPrivateAdapterHandle() throws {
        let valid: [String: Any] = [
            "conversationId": "conversation-1",
            "replayed": false,
        ]
        let decoded = try decode(ConversationStartReceiptV2.self, valid)
        XCTAssertEqual(decoded.conversationID.rawValue, "conversation-1")
        var leaked = valid
        leaked["adapterStateKey"] = "private-handle"
        try assertDecodeFails(ConversationStartReceiptV2.self, leaked)

        let encoded = try object(
            ConversationStartReceiptV2(
                conversationID: RuntimeConversationID(rawValue: "conversation-1"),
                replayed: false
            )
        )
        XCTAssertEqual(Set(encoded.keys), ["conversationId", "replayed"])
        XCTAssertNil(encoded["adapterStateKey"])
        XCTAssertFalse(Mirror(reflecting: decoded).children.contains { child in
            child.label == "adapterStateKey"
        })
    }

    func testA2cFlattenedPayloadSurfaceValidatesAndPreservesDiscriminator() throws {
        requireFlattened(RuntimeConfigureConversationRequestV2.self)
        requireFlattened(RuntimeConversationMetadataMutationRequestV2.self)
        requireFlattened(RuntimeStageUpgradeRequestV2.self)
        requireFlattened(RuntimeAgentDescriptionsV2.self)
        requireFlattened(RuntimeConfigurationReceiptV2.self)
        requireFlattened(RuntimeConversationMetadataReceiptV2.self)
        requireFlattened(RuntimeStageUpgradeReceiptV2.self)
        requireFlattened(CommandReceiptV2.self)
        requireFlattened(CommandStatusReceiptV2.self)
        requireFlattened(ConversationStartReceiptV2.self)
        var wire: [String: Any] = [
            "request": "configureConversation", "conversationId": "conversation-1",
            "idempotencyKey": "configure-1", "expectedConfigurationRevision": 0,
            "configuration": codexConfiguration(),
        ]
        let decoded = try decode(
            RuntimeV2FlattenedProbe<RuntimeConfigureConversationRequestV2>.self, wire
        )
        XCTAssertEqual(try bytes(try object(decoded)), try bytes(wire))
        wire["request"] = "future"
        try assertDecodeFails(
            RuntimeV2FlattenedProbe<RuntimeConfigureConversationRequestV2>.self, wire
        )
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
        let data = try bytes(value)
        XCTAssertThrowsError(
            try JSONDecoder().decode(type, from: data),
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
        try JSONSerialization.data(
            withJSONObject: value,
            options: [.sortedKeys, .fragmentsAllowed]
        )
    }

    private func codexConfiguration() -> [String: Any] {
        configurationObject(agentKind: "codex")
    }

    private func configurationObject(agentKind: String) -> [String: Any] {
        let configuration: [String: Any]
        if agentKind == "codex" {
            configuration = [
                "approvalPolicy": "on-request",
                "sandbox": "workspace-write",
                "reasoningEffort": "high",
            ]
        } else {
            configuration = [
                "permissionMode": "default",
                "model": NSNull(),
                "effort": NSNull(),
                "outputStyle": NSNull(),
            ]
        }
        return [
            "vendorControl": [
                "agentKind": agentKind,
                "configuration": configuration,
            ],
        ]
    }

    private func capabilitiesObject(agentKind: String, vendorKind: String) -> [String: Any] {
        let vendor: [String: Any]
        if vendorKind == "codex" {
            vendor = [
                "agentKind": "codex",
                "sandboxModes": [],
                "persistenceSupported": false,
                "reasoningEffortLevels": [],
            ]
        } else {
            vendor = [
                "agentKind": "claude_code",
                "permissionModes": [],
                "outputStyles": [],
                "hooksSupported": [],
                "cliVersion": "fixture",
            ]
        }
        return [
            "agentKind": agentKind,
            "agentVersion": "fixture",
            "features": [],
            "vendor": vendor,
        ]
    }

    private func agentDescription(
        outer: String,
        capabilities: String,
        vendor: String,
        configuration: String
    ) -> [String: Any] {
        [
            "agentKind": outer,
            "capabilities": capabilitiesObject(agentKind: capabilities, vendorKind: vendor),
            "defaultConfiguration": configurationObject(agentKind: configuration),
        ]
    }
}

private struct RuntimeV2FlattenedProbe<Value: RuntimeV2FlattenedPayload>: Codable {
    let value: Value
    init(from decoder: Decoder) throws { value = try Value(flattenedFrom: decoder) }
    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: RuntimeV2CodingKey.self)
        try value.encodeFlattenedFields(into: &container)
    }
}
