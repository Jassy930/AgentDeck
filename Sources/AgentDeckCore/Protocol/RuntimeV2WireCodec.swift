import Foundation

// Runtime v2 changed outer 与 JSON transfer model。稳定且 wire 未变化的 leaf DTO
// 继续复用 RuntimeWireTypes.swift；current facade 与 compact codec 在 A2c2 收口。

public enum RuntimeV2WireError: Error, Equatable, Sendable {
    case invalidIdentity
    case invalidTransferBounds
    case invalidTransferCarrier
    case unsupportedVersion
    case frameTooLarge
    case transferTooLarge
}

public let runtimeProtocolVersionV2: UInt16 = 2
public let runtimeProtocolVersionCurrent: UInt16 = runtimeProtocolVersionV2
public typealias RuntimeWireCodec = RuntimeV2WireCodec

private func runtimeV2ValidateIdentity(_ value: String) throws {
    guard !value.isEmpty, value.utf8.count <= 1024 else {
        throw RuntimeV2WireError.invalidIdentity
    }
}

private func runtimeV2InvalidTag(
    _ value: String,
    field: String,
    container: KeyedDecodingContainer<RuntimeV2CodingKey>
) -> DecodingError {
    .dataCorruptedError(
        forKey: runtimeV2Key(field),
        in: container,
        debugDescription: "unsupported Runtime v2 \(field) \(value)"
    )
}

// MARK: - Transfer JSON model

enum RuntimeTransferProfileV2 {
    case json
    case compact

    var maximumPartBytes: Int {
        switch self {
        case .json: TransferEnvelopeV2.maxJSONPartBytes
        case .compact: TransferEnvelopeV2.maxCompactPartBytes
        }
    }

    var maximumPartCount: UInt32 {
        switch self {
        case .json: TransferEnvelopeV2.maxJSONPartCount
        case .compact: TransferEnvelopeV2.maxCompactPartCount
        }
    }
}

public struct TransferEnvelopeV2: Codable, Sendable {
    public static let maxJSONPartBytes = 700 * 1024
    public static let maxJSONPartCount: UInt32 = 94
    public static let maxCompactPartBytes = 3_670_016
    public static let maxCompactPartCount: UInt32 = 64
    public static let maxTotalBytes: UInt64 = 64 * 1024 * 1024

    public let transferID: RuntimeTransferID
    public let partIndex: UInt32
    public let partCount: UInt32
    public let totalSHA256: Data
    public let totalBytes: UInt64
    public let part: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case transferID = "transferId"
        case partIndex, partCount
        case totalSHA256 = "totalSha256"
        case totalBytes, part
    }

    public init(
        transferID: RuntimeTransferID,
        partIndex: UInt32,
        partCount: UInt32,
        totalSHA256: Data,
        totalBytes: UInt64,
        part: Data
    ) throws {
        self.transferID = transferID
        self.partIndex = partIndex
        self.partCount = partCount
        self.totalSHA256 = totalSHA256
        self.totalBytes = totalBytes
        self.part = part
        try validate(profile: .json)
    }

    init(
        transferID: RuntimeTransferID,
        partIndex: UInt32,
        partCount: UInt32,
        totalSHA256: Data,
        totalBytes: UInt64,
        part: Data,
        profile: RuntimeTransferProfileV2
    ) throws {
        self.transferID = transferID
        self.partIndex = partIndex
        self.partCount = partCount
        self.totalSHA256 = totalSHA256
        self.totalBytes = totalBytes
        self.part = part
        try validate(profile: profile)
    }

    public init(from decoder: Decoder) throws {
        try runtimeV2RejectUnknownKeys(
            decoder,
            allowed: Set(CodingKeys.allCases.map(\.rawValue))
        )
        try self.init(decodingFieldsFrom: decoder, profile: .json)
    }

    init(
        flattenedFrom decoder: Decoder,
        discriminator: String,
        expected: String
    ) throws {
        let fields = Set(CodingKeys.allCases.map(\.rawValue)).union([discriminator])
        try runtimeV2RejectUnknownKeys(decoder, allowed: fields)
        try runtimeV2ValidateDiscriminator(decoder, key: discriminator, expected: expected)
        try self.init(decodingFieldsFrom: decoder, profile: .json)
    }

    private init(
        decodingFieldsFrom decoder: Decoder,
        profile: RuntimeTransferProfileV2
    ) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let rawTransferID = try container.decode(String.self, forKey: .transferID)
        do {
            try runtimeV2ValidateIdentity(rawTransferID)
        } catch {
            throw DecodingError.dataCorruptedError(
                forKey: .transferID,
                in: container,
                debugDescription: "Runtime v2 transferId must contain 1...1024 UTF-8 bytes"
            )
        }
        transferID = RuntimeTransferID(rawValue: rawTransferID)
        partIndex = try container.decode(UInt32.self, forKey: .partIndex)
        partCount = try container.decode(UInt32.self, forKey: .partCount)
        totalSHA256 = try container.decode(Data.self, forKey: .totalSHA256)
        totalBytes = try container.decode(UInt64.self, forKey: .totalBytes)
        part = try container.decode(Data.self, forKey: .part)
        do {
            try validate(profile: profile)
        } catch {
            throw DecodingError.dataCorrupted(
                .init(
                    codingPath: decoder.codingPath,
                    debugDescription: "invalid Runtime v2 transfer bounds",
                    underlyingError: error
                )
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        do {
            try validate(profile: .json)
        } catch {
            throw EncodingError.invalidValue(
                self,
                .init(
                    codingPath: encoder.codingPath,
                    debugDescription: "invalid Runtime v2 transfer bounds",
                    underlyingError: error
                )
            )
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(transferID, forKey: .transferID)
        try container.encode(partIndex, forKey: .partIndex)
        try container.encode(partCount, forKey: .partCount)
        try container.encode(totalSHA256, forKey: .totalSHA256)
        try container.encode(totalBytes, forKey: .totalBytes)
        try container.encode(part, forKey: .part)
    }

    func encodeFlattenedFields(
        discriminator: String,
        value: String,
        into container: inout KeyedEncodingContainer<RuntimeV2CodingKey>
    ) throws {
        do {
            try validate(profile: .json)
        } catch {
            throw EncodingError.invalidValue(
                self,
                .init(
                    codingPath: container.codingPath,
                    debugDescription: "invalid Runtime v2 transfer bounds",
                    underlyingError: error
                )
            )
        }
        try container.encode(value, forKey: runtimeV2Key(discriminator))
        try container.encode(transferID, forKey: runtimeV2Key("transferId"))
        try container.encode(partIndex, forKey: runtimeV2Key("partIndex"))
        try container.encode(partCount, forKey: runtimeV2Key("partCount"))
        try container.encode(totalSHA256, forKey: runtimeV2Key("totalSha256"))
        try container.encode(totalBytes, forKey: runtimeV2Key("totalBytes"))
        try container.encode(part, forKey: runtimeV2Key("part"))
    }

    func validate(profile: RuntimeTransferProfileV2) throws {
        do {
            try runtimeV2ValidateIdentity(transferID.rawValue)
        } catch {
            throw RuntimeV2WireError.invalidTransferBounds
        }
        let (maximumRepresentable, overflow) = UInt64(partCount).multipliedReportingOverflow(
            by: UInt64(profile.maximumPartBytes)
        )
        guard !overflow,
              partCount > 0,
              partCount <= profile.maximumPartCount,
              partIndex < partCount,
              totalSHA256.count == 32,
              totalBytes <= Self.maxTotalBytes,
              totalBytes <= maximumRepresentable,
              part.count <= profile.maximumPartBytes,
              UInt64(part.count) <= totalBytes
        else {
            throw RuntimeV2WireError.invalidTransferBounds
        }
    }
}

// MARK: - Compact transfer carrier

public enum RuntimeTransferChannelV2: UInt8, Sendable {
    case reply = 0
    case stream = 1
}

public struct RuntimeTransferCarrierV2: Sendable {
    public static let maxBytes = 4 * 1024 * 1024

    public let runtimeVersion: UInt16
    public let messageID: RuntimeMessageID
    public let channel: RuntimeTransferChannelV2
    public let transfer: TransferEnvelopeV2

    public init(
        messageID: RuntimeMessageID,
        channel: RuntimeTransferChannelV2,
        transfer: TransferEnvelopeV2
    ) {
        runtimeVersion = runtimeProtocolVersionV2
        self.messageID = messageID
        self.channel = channel
        self.transfer = transfer
    }

    public init(
        messageID: RuntimeMessageID,
        channel: RuntimeTransferChannelV2,
        transferID: RuntimeTransferID,
        partIndex: UInt32,
        partCount: UInt32,
        totalSHA256: Data,
        totalBytes: UInt64,
        part: Data
    ) throws {
        try runtimeV2ValidateIdentity(messageID.rawValue)
        runtimeVersion = runtimeProtocolVersionV2
        self.messageID = messageID
        self.channel = channel
        transfer = try TransferEnvelopeV2(
            transferID: transferID,
            partIndex: partIndex,
            partCount: partCount,
            totalSHA256: totalSHA256,
            totalBytes: totalBytes,
            part: part,
            profile: .compact
        )
    }

    init(
        runtimeVersion: UInt16,
        messageID: RuntimeMessageID,
        channel: RuntimeTransferChannelV2,
        transfer: TransferEnvelopeV2
    ) {
        self.runtimeVersion = runtimeVersion
        self.messageID = messageID
        self.channel = channel
        self.transfer = transfer
    }
}

// MARK: - Requests

public enum RuntimeRequestV2: Codable, Sendable {
    case hello(runtimeProtocolVersion: UInt16)
    case describeAgents
    case catalog(pageCursor: RuntimeCatalogPageCursor?)
    case subscribe(innerCursor: RuntimeInnerCursorV1)
    case unsubscribe(target: RuntimeSubscriptionTargetV1)
    case backfill(RuntimeBackfillRequestV1)
    case start(
        agentKind: AgentKind,
        idempotencyKey: RuntimeIdempotencyKey,
        cwd: String,
        title: String?
    )
    case configureConversation(RuntimeConfigureConversationRequestV2)
    case updateConversationMetadata(RuntimeConversationMetadataMutationRequestV2)
    case sendPrompt(
        conversationID: RuntimeConversationID,
        idempotencyKey: RuntimeIdempotencyKey,
        expectedConfigurationRevision: UInt64,
        prompt: RuntimePromptPayloadV1
    )
    case resolveApproval(
        conversationID: RuntimeConversationID,
        turnID: RuntimeTurnID,
        approvalID: RuntimeApprovalID,
        decision: RuntimeActionDecisionV1
    )
    case retryApproval(conversationID: RuntimeConversationID, approvalID: RuntimeApprovalID)
    case cancelQueued(conversationID: RuntimeConversationID, commandID: RuntimeCommandID)
    case cancelActive(conversationID: RuntimeConversationID, turnID: RuntimeTurnID)
    case queryReceipt(RuntimeReceiptSelectorV1)
    case createPairInvite(
        displayName: String,
        ttlSecs: UInt32,
        scope: RuntimeLocalOnlyAdministrationV1
    )
    case listPendingPairings(scope: RuntimeLocalOnlyAdministrationV1)
    case confirmPairing(pairingID: RuntimePairingID, scope: RuntimeLocalOnlyAdministrationV1)
    case cancelPairing(pairingID: RuntimePairingID, scope: RuntimeLocalOnlyAdministrationV1)
    case revoke(target: RuntimeRevokeTargetV1)
    case trustReset(scope: RuntimeLocalOnlyAdministrationV1)
    case stageUpgrade(RuntimeStageUpgradeRequestV2)

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: RuntimeV2CodingKey.self)
        let request = try container.decode(String.self, forKey: runtimeV2Key("request"))
        switch request {
        case "hello":
            try runtimeV2RejectUnknownKeys(
                decoder,
                allowed: ["request", "runtimeProtocolVersion"]
            )
            self = .hello(
                runtimeProtocolVersion: try container.decode(
                    UInt16.self,
                    forKey: runtimeV2Key("runtimeProtocolVersion")
                )
            )
        case "describeAgents":
            try runtimeV2RejectUnknownKeys(decoder, allowed: ["request"])
            self = .describeAgents
        case "catalog":
            try runtimeV2RejectUnknownKeys(decoder, allowed: ["request", "pageCursor"])
            let cursor = try runtimeV2DecodeRequiredNullable(
                RuntimeCatalogPageCursor.self,
                from: container,
                forKey: runtimeV2Key("pageCursor")
            )
            self = .catalog(pageCursor: cursor)
        case "subscribe":
            try runtimeV2RejectUnknownKeys(decoder, allowed: ["request", "innerCursor"])
            self = .subscribe(
                innerCursor: try container.decode(
                    RuntimeInnerCursorV1.self,
                    forKey: runtimeV2Key("innerCursor")
                )
            )
        case "unsubscribe":
            try runtimeV2RejectUnknownKeys(decoder, allowed: ["request", "target"])
            self = .unsubscribe(
                target: try container.decode(
                    RuntimeSubscriptionTargetV1.self,
                    forKey: runtimeV2Key("target")
                )
            )
        case "backfill":
            self = .backfill(try RuntimeBackfillRequestV1(from: decoder))
        case "start":
            try runtimeV2RejectUnknownKeys(
                decoder,
                allowed: ["request", "agentKind", "idempotencyKey", "cwd", "title"]
            )
            self = .start(
                agentKind: try container.decode(AgentKind.self, forKey: runtimeV2Key("agentKind")),
                idempotencyKey: try container.decode(
                    RuntimeIdempotencyKey.self,
                    forKey: runtimeV2Key("idempotencyKey")
                ),
                cwd: try container.decode(String.self, forKey: runtimeV2Key("cwd")),
                title: try container.decodeIfPresent(String.self, forKey: runtimeV2Key("title"))
            )
        case "configureConversation":
            self = .configureConversation(
                try RuntimeConfigureConversationRequestV2(flattenedFrom: decoder)
            )
        case "updateConversationMetadata":
            self = .updateConversationMetadata(
                try RuntimeConversationMetadataMutationRequestV2(flattenedFrom: decoder)
            )
        case "sendPrompt":
            try runtimeV2RejectUnknownKeys(
                decoder,
                allowed: [
                    "request", "conversationId", "idempotencyKey",
                    "expectedConfigurationRevision", "prompt",
                ]
            )
            self = .sendPrompt(
                conversationID: try container.decode(
                    RuntimeConversationID.self,
                    forKey: runtimeV2Key("conversationId")
                ),
                idempotencyKey: try container.decode(
                    RuntimeIdempotencyKey.self,
                    forKey: runtimeV2Key("idempotencyKey")
                ),
                expectedConfigurationRevision: try container.decode(
                    UInt64.self,
                    forKey: runtimeV2Key("expectedConfigurationRevision")
                ),
                prompt: try container.decode(
                    RuntimePromptPayloadV1.self,
                    forKey: runtimeV2Key("prompt")
                )
            )
        case "resolveApproval":
            try runtimeV2RejectUnknownKeys(
                decoder,
                allowed: ["request", "conversation_id", "turn_id", "approval_id", "decision"]
            )
            self = .resolveApproval(
                conversationID: try container.decode(
                    RuntimeConversationID.self,
                    forKey: runtimeV2Key("conversation_id")
                ),
                turnID: try container.decode(RuntimeTurnID.self, forKey: runtimeV2Key("turn_id")),
                approvalID: try container.decode(
                    RuntimeApprovalID.self,
                    forKey: runtimeV2Key("approval_id")
                ),
                decision: try container.decode(
                    RuntimeActionDecisionV1.self,
                    forKey: runtimeV2Key("decision")
                )
            )
        case "retryApproval":
            try runtimeV2RejectUnknownKeys(
                decoder,
                allowed: ["request", "conversation_id", "approval_id"]
            )
            self = .retryApproval(
                conversationID: try container.decode(
                    RuntimeConversationID.self,
                    forKey: runtimeV2Key("conversation_id")
                ),
                approvalID: try container.decode(
                    RuntimeApprovalID.self,
                    forKey: runtimeV2Key("approval_id")
                )
            )
        case "cancelQueued":
            try runtimeV2RejectUnknownKeys(
                decoder,
                allowed: ["request", "conversationId", "commandId"]
            )
            self = .cancelQueued(
                conversationID: try container.decode(
                    RuntimeConversationID.self,
                    forKey: runtimeV2Key("conversationId")
                ),
                commandID: try container.decode(
                    RuntimeCommandID.self,
                    forKey: runtimeV2Key("commandId")
                )
            )
        case "cancelActive":
            try runtimeV2RejectUnknownKeys(
                decoder,
                allowed: ["request", "conversationId", "turnId"]
            )
            self = .cancelActive(
                conversationID: try container.decode(
                    RuntimeConversationID.self,
                    forKey: runtimeV2Key("conversationId")
                ),
                turnID: try container.decode(RuntimeTurnID.self, forKey: runtimeV2Key("turnId"))
            )
        case "queryReceipt":
            self = .queryReceipt(try RuntimeReceiptSelectorV1(from: decoder))
        case "createPairInvite":
            try runtimeV2RejectUnknownKeys(
                decoder,
                allowed: ["request", "displayName", "ttlSecs", "scope"]
            )
            let ttlSecs: UInt32
            if container.contains(runtimeV2Key("ttlSecs")) {
                ttlSecs = try container.decode(UInt32.self, forKey: runtimeV2Key("ttlSecs"))
            } else {
                ttlSecs = 300
            }
            self = .createPairInvite(
                displayName: try container.decode(String.self, forKey: runtimeV2Key("displayName")),
                ttlSecs: ttlSecs,
                scope: try container.decode(
                    RuntimeLocalOnlyAdministrationV1.self,
                    forKey: runtimeV2Key("scope")
                )
            )
        case "listPendingPairings":
            try runtimeV2RejectUnknownKeys(decoder, allowed: ["request", "scope"])
            self = .listPendingPairings(
                scope: try container.decode(
                    RuntimeLocalOnlyAdministrationV1.self,
                    forKey: runtimeV2Key("scope")
                )
            )
        case "confirmPairing", "cancelPairing":
            try runtimeV2RejectUnknownKeys(
                decoder,
                allowed: ["request", "pairing_id", "scope"]
            )
            let pairingID = try container.decode(
                RuntimePairingID.self,
                forKey: runtimeV2Key("pairing_id")
            )
            let scope = try container.decode(
                RuntimeLocalOnlyAdministrationV1.self,
                forKey: runtimeV2Key("scope")
            )
            self = request == "confirmPairing"
                ? .confirmPairing(pairingID: pairingID, scope: scope)
                : .cancelPairing(pairingID: pairingID, scope: scope)
        case "revoke":
            try runtimeV2RejectUnknownKeys(decoder, allowed: ["request", "target"])
            self = .revoke(
                target: try container.decode(
                    RuntimeRevokeTargetV1.self,
                    forKey: runtimeV2Key("target")
                )
            )
        case "trustReset":
            try runtimeV2RejectUnknownKeys(decoder, allowed: ["request", "scope"])
            self = .trustReset(
                scope: try container.decode(
                    RuntimeLocalOnlyAdministrationV1.self,
                    forKey: runtimeV2Key("scope")
                )
            )
        case "stageUpgrade":
            self = .stageUpgrade(try RuntimeStageUpgradeRequestV2(flattenedFrom: decoder))
        default:
            throw runtimeV2InvalidTag(request, field: "request", container: container)
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: RuntimeV2CodingKey.self)
        switch self {
        case .hello(let version):
            try container.encode("hello", forKey: runtimeV2Key("request"))
            try container.encode(version, forKey: runtimeV2Key("runtimeProtocolVersion"))
        case .describeAgents:
            try container.encode("describeAgents", forKey: runtimeV2Key("request"))
        case .catalog(let pageCursor):
            try container.encode("catalog", forKey: runtimeV2Key("request"))
            try container.encode(pageCursor, forKey: runtimeV2Key("pageCursor"))
        case .subscribe(let innerCursor):
            try container.encode("subscribe", forKey: runtimeV2Key("request"))
            try container.encode(innerCursor, forKey: runtimeV2Key("innerCursor"))
        case .unsubscribe(let target):
            try container.encode("unsubscribe", forKey: runtimeV2Key("request"))
            try container.encode(target, forKey: runtimeV2Key("target"))
        case .backfill(let request):
            try container.encode("backfill", forKey: runtimeV2Key("request"))
            switch request {
            case .catalog(let after):
                try container.encode("catalog", forKey: runtimeV2Key("scope"))
                try container.encode(after, forKey: runtimeV2Key("after"))
            case .conversation(let conversationID, let after):
                try container.encode("conversation", forKey: runtimeV2Key("scope"))
                try container.encode(conversationID, forKey: runtimeV2Key("conversationId"))
                try container.encode(after, forKey: runtimeV2Key("after"))
            }
        case .start(let agentKind, let idempotencyKey, let cwd, let title):
            try container.encode("start", forKey: runtimeV2Key("request"))
            try container.encode(agentKind, forKey: runtimeV2Key("agentKind"))
            try container.encode(idempotencyKey, forKey: runtimeV2Key("idempotencyKey"))
            try container.encode(cwd, forKey: runtimeV2Key("cwd"))
            try container.encode(title, forKey: runtimeV2Key("title"))
        case .configureConversation(let request):
            try request.encodeFlattenedFields(into: &container)
        case .updateConversationMetadata(let request):
            try request.encodeFlattenedFields(into: &container)
        case .sendPrompt(
            let conversationID,
            let idempotencyKey,
            let expectedConfigurationRevision,
            let prompt
        ):
            try container.encode("sendPrompt", forKey: runtimeV2Key("request"))
            try container.encode(conversationID, forKey: runtimeV2Key("conversationId"))
            try container.encode(idempotencyKey, forKey: runtimeV2Key("idempotencyKey"))
            try container.encode(
                expectedConfigurationRevision,
                forKey: runtimeV2Key("expectedConfigurationRevision")
            )
            try container.encode(prompt, forKey: runtimeV2Key("prompt"))
        case .resolveApproval(let conversationID, let turnID, let approvalID, let decision):
            try container.encode("resolveApproval", forKey: runtimeV2Key("request"))
            try container.encode(conversationID, forKey: runtimeV2Key("conversation_id"))
            try container.encode(turnID, forKey: runtimeV2Key("turn_id"))
            try container.encode(approvalID, forKey: runtimeV2Key("approval_id"))
            try container.encode(decision, forKey: runtimeV2Key("decision"))
        case .retryApproval(let conversationID, let approvalID):
            try container.encode("retryApproval", forKey: runtimeV2Key("request"))
            try container.encode(conversationID, forKey: runtimeV2Key("conversation_id"))
            try container.encode(approvalID, forKey: runtimeV2Key("approval_id"))
        case .cancelQueued(let conversationID, let commandID):
            try container.encode("cancelQueued", forKey: runtimeV2Key("request"))
            try container.encode(conversationID, forKey: runtimeV2Key("conversationId"))
            try container.encode(commandID, forKey: runtimeV2Key("commandId"))
        case .cancelActive(let conversationID, let turnID):
            try container.encode("cancelActive", forKey: runtimeV2Key("request"))
            try container.encode(conversationID, forKey: runtimeV2Key("conversationId"))
            try container.encode(turnID, forKey: runtimeV2Key("turnId"))
        case .queryReceipt(let selector):
            try container.encode("queryReceipt", forKey: runtimeV2Key("request"))
            switch selector {
            case .command(let conversationID, let commandID):
                try container.encode("command", forKey: runtimeV2Key("selector"))
                try container.encode(conversationID, forKey: runtimeV2Key("conversationId"))
                try container.encode(commandID, forKey: runtimeV2Key("commandId"))
            case .idempotency(let conversationID, let idempotencyKey):
                try container.encode("idempotency", forKey: runtimeV2Key("selector"))
                try container.encode(conversationID, forKey: runtimeV2Key("conversationId"))
                try container.encode(idempotencyKey, forKey: runtimeV2Key("idempotencyKey"))
            }
        case .createPairInvite(let displayName, let ttlSecs, let scope):
            try container.encode("createPairInvite", forKey: runtimeV2Key("request"))
            try container.encode(displayName, forKey: runtimeV2Key("displayName"))
            try container.encode(ttlSecs, forKey: runtimeV2Key("ttlSecs"))
            try container.encode(scope, forKey: runtimeV2Key("scope"))
        case .listPendingPairings(let scope):
            try container.encode("listPendingPairings", forKey: runtimeV2Key("request"))
            try container.encode(scope, forKey: runtimeV2Key("scope"))
        case .confirmPairing(let pairingID, let scope):
            try container.encode("confirmPairing", forKey: runtimeV2Key("request"))
            try container.encode(pairingID, forKey: runtimeV2Key("pairing_id"))
            try container.encode(scope, forKey: runtimeV2Key("scope"))
        case .cancelPairing(let pairingID, let scope):
            try container.encode("cancelPairing", forKey: runtimeV2Key("request"))
            try container.encode(pairingID, forKey: runtimeV2Key("pairing_id"))
            try container.encode(scope, forKey: runtimeV2Key("scope"))
        case .revoke(let target):
            try container.encode("revoke", forKey: runtimeV2Key("request"))
            try container.encode(target, forKey: runtimeV2Key("target"))
        case .trustReset(let scope):
            try container.encode("trustReset", forKey: runtimeV2Key("request"))
            try container.encode(scope, forKey: runtimeV2Key("scope"))
        case .stageUpgrade(let request):
            try request.encodeFlattenedFields(into: &container)
        }
    }
}

// MARK: - Replies

public enum RuntimeReplyV2: Codable, Sendable {
    case hello(runtimeProtocolVersion: UInt16)
    case agents(RuntimeAgentDescriptionsV2)
    case configuration(RuntimeConfigurationReceiptV2)
    case conversationMetadata(RuntimeConversationMetadataReceiptV2)
    case stageUpgrade(RuntimeStageUpgradeReceiptV2)
    case command(CommandReceiptV2)
    case commandStatus(CommandStatusReceiptV2)
    case conversationStart(ConversationStartReceiptV2)
    case cancellation(CancellationReceiptV1)
    case approval(ApprovalReceiptV1)
    case revocation(RevocationReceiptV1)
    case subscription(RuntimeSubscriptionReceiptV1)
    case catalog(RuntimeCatalogSnapshotV2)
    case snapshot(ConversationSnapshotV2)
    case backfill(RuntimeBackfillChunkV2)
    case syncComplete(RuntimeSyncCompleteV1)
    case transferPart(TransferEnvelopeV2)
    case pairInvite(RuntimePairInviteV1)
    case pendingPairings([RuntimePendingPairingV1])
    case failure(RuntimeFailureV1)

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: RuntimeV2CodingKey.self)
        let reply = try container.decode(String.self, forKey: runtimeV2Key("reply"))
        switch reply {
        case "hello":
            try runtimeV2RejectUnknownKeys(
                decoder,
                allowed: ["reply", "runtimeProtocolVersion"]
            )
            self = .hello(
                runtimeProtocolVersion: try container.decode(
                    UInt16.self,
                    forKey: runtimeV2Key("runtimeProtocolVersion")
                )
            )
        case "agents":
            self = .agents(try RuntimeAgentDescriptionsV2(flattenedFrom: decoder))
        case "configuration":
            self = .configuration(try RuntimeConfigurationReceiptV2(flattenedFrom: decoder))
        case "conversationMetadata":
            self = .conversationMetadata(
                try RuntimeConversationMetadataReceiptV2(flattenedFrom: decoder)
            )
        case "stageUpgrade":
            self = .stageUpgrade(try RuntimeStageUpgradeReceiptV2(flattenedFrom: decoder))
        case "command":
            self = .command(try CommandReceiptV2(flattenedFrom: decoder))
        case "commandStatus":
            self = .commandStatus(try CommandStatusReceiptV2(flattenedFrom: decoder))
        case "conversationStart":
            self = .conversationStart(try ConversationStartReceiptV2(flattenedFrom: decoder))
        case "cancellation":
            self = .cancellation(try CancellationReceiptV1(from: decoder))
        case "approval":
            self = .approval(try ApprovalReceiptV1(from: decoder))
        case "revocation":
            self = .revocation(try RevocationReceiptV1(from: decoder))
        case "subscription":
            self = .subscription(try RuntimeSubscriptionReceiptV1(from: decoder))
        case "catalog":
            self = .catalog(try RuntimeCatalogSnapshotV2(flattenedFrom: decoder))
        case "snapshot":
            self = .snapshot(try ConversationSnapshotV2(flattenedFrom: decoder))
        case "backfill":
            self = .backfill(try RuntimeBackfillChunkV2(flattenedFrom: decoder))
        case "syncComplete":
            self = .syncComplete(try RuntimeSyncCompleteV1(runtimeV2FlattenedFrom: decoder))
        case "transferPart":
            self = .transferPart(
                try TransferEnvelopeV2(
                    flattenedFrom: decoder,
                    discriminator: "reply",
                    expected: "transferPart"
                )
            )
        case "pairInvite":
            self = .pairInvite(try RuntimePairInviteV1(from: decoder))
        case "pendingPairings":
            try runtimeV2RejectUnknownKeys(decoder, allowed: ["reply", "pairings"])
            self = .pendingPairings(
                try container.decode(
                    [RuntimePendingPairingV1].self,
                    forKey: runtimeV2Key("pairings")
                )
            )
        case "failure":
            try runtimeV2RejectUnknownKeys(
                decoder,
                allowed: ["reply", "code", "message", "diagnosticRef"]
            )
            self = .failure(
                RuntimeFailureV1(
                    code: try container.decode(String.self, forKey: runtimeV2Key("code")),
                    message: try container.decode(String.self, forKey: runtimeV2Key("message")),
                    diagnosticRef: try container.decodeIfPresent(
                        String.self,
                        forKey: runtimeV2Key("diagnosticRef")
                    )
                )
            )
        default:
            throw runtimeV2InvalidTag(reply, field: "reply", container: container)
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: RuntimeV2CodingKey.self)
        switch self {
        case .hello(let version):
            try container.encode("hello", forKey: runtimeV2Key("reply"))
            try container.encode(version, forKey: runtimeV2Key("runtimeProtocolVersion"))
        case .agents(let descriptions):
            try descriptions.encodeFlattenedFields(into: &container)
        case .configuration(let receipt):
            try receipt.encodeFlattenedFields(into: &container)
        case .conversationMetadata(let receipt):
            try receipt.encodeFlattenedFields(into: &container)
        case .stageUpgrade(let receipt):
            try receipt.encodeFlattenedFields(into: &container)
        case .command(let receipt):
            try receipt.encodeFlattenedFields(into: &container)
        case .commandStatus(let receipt):
            try receipt.encodeFlattenedFields(into: &container)
        case .conversationStart(let receipt):
            try receipt.encodeFlattenedFields(into: &container)
        case .cancellation(let receipt):
            try container.encode("cancellation", forKey: runtimeV2Key("reply"))
            switch receipt {
            case .queuedCanceled(let conversationID, let commandID):
                try container.encode("queuedCanceled", forKey: runtimeV2Key("status"))
                try container.encode(conversationID, forKey: runtimeV2Key("conversationId"))
                try container.encode(commandID, forKey: runtimeV2Key("commandId"))
            case .activeCancelRequested(let conversationID, let turnID):
                try container.encode("activeCancelRequested", forKey: runtimeV2Key("status"))
                try container.encode(conversationID, forKey: runtimeV2Key("conversationId"))
                try container.encode(turnID, forKey: runtimeV2Key("turnId"))
            }
        case .approval(let receipt):
            try container.encode("approval", forKey: runtimeV2Key("reply"))
            switch receipt {
            case .claimed(let approvalID):
                try encodeApproval("claimed", approvalID: approvalID, into: &container)
            case .applied(let approvalID):
                try encodeApproval("applied", approvalID: approvalID, into: &container)
            case .alreadyHandled(let approvalID, let decision, let state):
                try container.encode("alreadyHandled", forKey: runtimeV2Key("status"))
                try container.encode(approvalID, forKey: runtimeV2Key("approval_id"))
                try container.encode(decision, forKey: runtimeV2Key("decision"))
                try container.encode(state, forKey: runtimeV2Key("state"))
            case .deliveryFailed(let approvalID):
                try encodeApproval("deliveryFailed", approvalID: approvalID, into: &container)
            case .expired(let approvalID):
                try encodeApproval("expired", approvalID: approvalID, into: &container)
            }
        case .revocation(let receipt):
            try container.encode("revocation", forKey: runtimeV2Key("reply"))
            switch receipt {
            case .committed(let serial):
                try container.encode("committed", forKey: runtimeV2Key("status"))
                try container.encode(serial, forKey: runtimeV2Key("grant_serial"))
            case .failed(let failure):
                try container.encode("failed", forKey: runtimeV2Key("status"))
                try container.encode(failure, forKey: runtimeV2Key("failure"))
            }
        case .subscription(let receipt):
            try container.encode("subscription", forKey: runtimeV2Key("reply"))
            switch receipt {
            case .subscribed(let generation):
                try container.encode("subscribed", forKey: runtimeV2Key("status"))
                try container.encode(generation, forKey: runtimeV2Key("streamGeneration"))
            case .unsubscribed:
                try container.encode("unsubscribed", forKey: runtimeV2Key("status"))
            }
        case .catalog(let catalog):
            try catalog.encodeFlattenedFields(into: &container)
        case .snapshot(let snapshot):
            try snapshot.encodeFlattenedFields(into: &container)
        case .backfill(let backfill):
            try backfill.encodeFlattenedFields(into: &container)
        case .syncComplete(let value):
            try container.encode("syncComplete", forKey: runtimeV2Key("reply"))
            try container.encode(value.streamGeneration, forKey: runtimeV2Key("streamGeneration"))
            try container.encode(value.streamCursor, forKey: runtimeV2Key("streamCursor"))
            try container.encode(value.innerCursor, forKey: runtimeV2Key("innerCursor"))
            try container.encode(
                value.keyDirectoryRevision,
                forKey: runtimeV2Key("keyDirectoryRevision")
            )
        case .transferPart(let transfer):
            try transfer.encodeFlattenedFields(
                discriminator: "reply",
                value: "transferPart",
                into: &container
            )
        case .pairInvite(let invite):
            try container.encode("pairInvite", forKey: runtimeV2Key("reply"))
            try container.encode(invite.pairingID, forKey: runtimeV2Key("pairingId"))
            try container.encode(invite.displayName, forKey: runtimeV2Key("displayName"))
            try container.encode(invite.expiresAtMs, forKey: runtimeV2Key("expiresAtMs"))
        case .pendingPairings(let pairings):
            try container.encode("pendingPairings", forKey: runtimeV2Key("reply"))
            try container.encode(pairings, forKey: runtimeV2Key("pairings"))
        case .failure(let failure):
            try container.encode("failure", forKey: runtimeV2Key("reply"))
            try container.encode(failure.code, forKey: runtimeV2Key("code"))
            try container.encode(failure.message, forKey: runtimeV2Key("message"))
            try container.encode(failure.diagnosticRef, forKey: runtimeV2Key("diagnosticRef"))
        }
    }

    private func encodeApproval(
        _ status: String,
        approvalID: RuntimeApprovalID,
        into container: inout KeyedEncodingContainer<RuntimeV2CodingKey>
    ) throws {
        try container.encode(status, forKey: runtimeV2Key("status"))
        try container.encode(approvalID, forKey: runtimeV2Key("approval_id"))
    }
}

private extension RuntimeSyncCompleteV1 {
    init(runtimeV2FlattenedFrom decoder: Decoder) throws {
        try runtimeV2RejectUnknownKeys(
            decoder,
            allowed: [
                "reply", "streamGeneration", "streamCursor", "innerCursor",
                "keyDirectoryRevision",
            ]
        )
        try runtimeV2ValidateDiscriminator(decoder, key: "reply", expected: "syncComplete")
        let container = try decoder.container(keyedBy: RuntimeV2CodingKey.self)
        streamGeneration = try container.decode(
            RuntimeStreamGeneration.self,
            forKey: runtimeV2Key("streamGeneration")
        )
        streamCursor = try container.decode(
            RuntimeStreamCursorV1.self,
            forKey: runtimeV2Key("streamCursor")
        )
        innerCursor = try container.decode(
            RuntimeInnerCursorV1.self,
            forKey: runtimeV2Key("innerCursor")
        )
        keyDirectoryRevision = try container.decode(
            UInt64.self,
            forKey: runtimeV2Key("keyDirectoryRevision")
        )
    }
}

// MARK: - Stream and outer envelope

public enum RuntimeStreamItemV2: Codable, Sendable {
    case event(RuntimeEventV2)
    case catalogDelta(RuntimeCatalogDeltaV2)
    case transferPart(TransferEnvelopeV2)

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: RuntimeV2CodingKey.self)
        let stream = try container.decode(String.self, forKey: runtimeV2Key("stream"))
        switch stream {
        case "event":
            self = .event(try RuntimeEventV2(flattenedFrom: decoder))
        case "catalogDelta":
            self = .catalogDelta(try RuntimeCatalogDeltaV2(flattenedFrom: decoder))
        case "transferPart":
            self = .transferPart(
                try TransferEnvelopeV2(
                    flattenedFrom: decoder,
                    discriminator: "stream",
                    expected: "transferPart"
                )
            )
        default:
            throw runtimeV2InvalidTag(stream, field: "stream", container: container)
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: RuntimeV2CodingKey.self)
        switch self {
        case .event(let event):
            try event.encodeFlattenedFields(into: &container)
        case .catalogDelta(let delta):
            try delta.encodeFlattenedFields(into: &container)
        case .transferPart(let transfer):
            try transfer.encodeFlattenedFields(
                discriminator: "stream",
                value: "transferPart",
                into: &container
            )
        }
    }
}

public enum RuntimeMessageV2: Codable, Sendable {
    case request(RuntimeRequestV2)
    case reply(RuntimeReplyV2)
    case stream(RuntimeStreamItemV2)

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case message, payload
    }

    public init(from decoder: Decoder) throws {
        try runtimeV2RejectUnknownKeys(
            decoder,
            allowed: Set(CodingKeys.allCases.map(\.rawValue))
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        switch try container.decode(String.self, forKey: .message) {
        case "request":
            self = .request(try container.decode(RuntimeRequestV2.self, forKey: .payload))
        case "reply":
            self = .reply(try container.decode(RuntimeReplyV2.self, forKey: .payload))
        case "stream":
            self = .stream(try container.decode(RuntimeStreamItemV2.self, forKey: .payload))
        case let value:
            throw DecodingError.dataCorruptedError(
                forKey: .message,
                in: container,
                debugDescription: "unsupported Runtime v2 message \(value)"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .request(let value):
            try container.encode("request", forKey: .message)
            try container.encode(value, forKey: .payload)
        case .reply(let value):
            try container.encode("reply", forKey: .message)
            try container.encode(value, forKey: .payload)
        case .stream(let value):
            try container.encode("stream", forKey: .message)
            try container.encode(value, forKey: .payload)
        }
    }
}

public struct RuntimeEnvelopeV2: Codable, Sendable {
    public let version: UInt16
    public let messageID: RuntimeMessageID
    public let body: RuntimeMessageV2

    public init(version: UInt16, messageID: RuntimeMessageID, body: RuntimeMessageV2) {
        self.version = version
        self.messageID = messageID
        self.body = body
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case messageID = "messageId"
        case body
    }

    public init(from decoder: Decoder) throws {
        try runtimeV2RejectUnknownKeys(
            decoder,
            allowed: Set(CodingKeys.allCases.map(\.rawValue))
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        version = try container.decode(UInt16.self, forKey: .version)
        guard version == runtimeProtocolVersionV2 else {
            throw DecodingError.dataCorruptedError(
                forKey: .version,
                in: container,
                debugDescription: "unsupported Runtime protocol version \(version)"
            )
        }
        let rawMessageID = try container.decode(String.self, forKey: .messageID)
        do {
            try runtimeV2ValidateIdentity(rawMessageID)
        } catch {
            throw DecodingError.dataCorruptedError(
                forKey: .messageID,
                in: container,
                debugDescription: "Runtime v2 messageId must contain 1...1024 UTF-8 bytes"
            )
        }
        messageID = RuntimeMessageID(rawValue: rawMessageID)
        body = try container.decode(RuntimeMessageV2.self, forKey: .body)
    }

    public func encode(to encoder: Encoder) throws {
        guard version == runtimeProtocolVersionV2 else {
            throw EncodingError.invalidValue(
                version,
                .init(
                    codingPath: encoder.codingPath,
                    debugDescription: "unsupported Runtime protocol version \(version)"
                )
            )
        }
        do {
            try runtimeV2ValidateIdentity(messageID.rawValue)
        } catch {
            throw EncodingError.invalidValue(
                messageID.rawValue,
                .init(
                    codingPath: encoder.codingPath + [CodingKeys.messageID],
                    debugDescription: "Runtime v2 messageId must contain 1...1024 UTF-8 bytes"
                )
            )
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(version, forKey: .version)
        try container.encode(messageID, forKey: .messageID)
        try container.encode(body, forKey: .body)
    }
}

// MARK: - Current Runtime v2 wire entry points

public enum RuntimeV2WireCodec {
    public static let maxRequestBytes = 1024 * 1024
    public static let maxJSONFrameBytes = 1024 * 1024

    public static func decodeEnvelope(_ data: Data) throws -> RuntimeEnvelopeV2 {
        guard data.count < maxJSONFrameBytes else {
            throw RuntimeV2WireError.frameTooLarge
        }
        let value = try JSONDecoder().decode(RuntimeEnvelopeV2.self, from: data)
        if case .request = value.body, data.count >= maxRequestBytes {
            throw RuntimeV2WireError.frameTooLarge
        }
        return value
    }

    public static func decodeTransferEnvelope(_ data: Data) throws -> TransferEnvelopeV2 {
        guard data.count < maxJSONFrameBytes else {
            throw RuntimeV2WireError.frameTooLarge
        }
        return try JSONDecoder().decode(TransferEnvelopeV2.self, from: data)
    }

    public static func encode(_ value: RuntimeEnvelopeV2) throws -> Data {
        let data = try JSONEncoder().encode(value)
        guard data.count < maxJSONFrameBytes else {
            throw RuntimeV2WireError.frameTooLarge
        }
        if case .request = value.body, data.count >= maxRequestBytes {
            throw RuntimeV2WireError.frameTooLarge
        }
        return data
    }

    public static func encode(_ value: TransferEnvelopeV2) throws -> Data {
        let data = try JSONEncoder().encode(value)
        guard data.count < maxJSONFrameBytes else {
            throw RuntimeV2WireError.frameTooLarge
        }
        return data
    }

    public static func decodeTransferCarrier(_ data: Data) throws -> RuntimeTransferCarrierV2 {
        guard data.count < RuntimeTransferCarrierV2.maxBytes else {
            throw RuntimeV2WireError.transferTooLarge
        }

        var reader = RuntimeV2TransferCarrierReader(data: data)
        guard try reader.take(5) == Data("ADRT1".utf8) else {
            throw RuntimeV2WireError.invalidTransferCarrier
        }
        let version = try reader.readUInt16()
        guard version == runtimeProtocolVersionV2 else {
            throw RuntimeV2WireError.unsupportedVersion
        }
        guard let channel = RuntimeTransferChannelV2(rawValue: try reader.readUInt8()) else {
            throw RuntimeV2WireError.invalidTransferCarrier
        }

        let messageID = try reader.readUTF8UInt16()
        let transferID = try reader.readUTF8UInt16()
        do {
            try runtimeV2ValidateIdentity(messageID)
            try runtimeV2ValidateIdentity(transferID)
        } catch {
            throw RuntimeV2WireError.invalidTransferCarrier
        }

        let partIndex = try reader.readUInt32()
        let partCount = try reader.readUInt32()
        let totalSHA256 = try reader.take(32)
        let totalBytes = try reader.readUInt64()
        let partLength = Int(try reader.readUInt32())
        let part = try reader.take(partLength)
        guard reader.isAtEnd else {
            throw RuntimeV2WireError.invalidTransferCarrier
        }

        let transfer = try TransferEnvelopeV2(
            transferID: RuntimeTransferID(rawValue: transferID),
            partIndex: partIndex,
            partCount: partCount,
            totalSHA256: totalSHA256,
            totalBytes: totalBytes,
            part: part,
            profile: .compact
        )
        return RuntimeTransferCarrierV2(
            runtimeVersion: version,
            messageID: RuntimeMessageID(rawValue: messageID),
            channel: channel,
            transfer: transfer
        )
    }

    public static func encode(_ value: RuntimeTransferCarrierV2) throws -> Data {
        guard value.runtimeVersion == runtimeProtocolVersionV2 else {
            throw RuntimeV2WireError.unsupportedVersion
        }
        try value.transfer.validate(profile: .compact)

        let message = Data(value.messageID.rawValue.utf8)
        let transferID = Data(value.transfer.transferID.rawValue.utf8)
        guard !message.isEmpty,
              !transferID.isEmpty,
              message.count <= 1024,
              transferID.count <= 1024,
              value.transfer.part.count <= Int(UInt32.max)
        else {
            throw RuntimeV2WireError.invalidTransferCarrier
        }

        var data = Data("ADRT1".utf8)
        appendBigEndian(value.runtimeVersion, to: &data)
        data.append(value.channel.rawValue)
        appendBigEndian(UInt16(message.count), to: &data)
        data.append(message)
        appendBigEndian(UInt16(transferID.count), to: &data)
        data.append(transferID)
        appendBigEndian(value.transfer.partIndex, to: &data)
        appendBigEndian(value.transfer.partCount, to: &data)
        data.append(value.transfer.totalSHA256)
        appendBigEndian(value.transfer.totalBytes, to: &data)
        appendBigEndian(UInt32(value.transfer.part.count), to: &data)
        data.append(value.transfer.part)
        guard data.count < RuntimeTransferCarrierV2.maxBytes else {
            throw RuntimeV2WireError.transferTooLarge
        }
        return data
    }

    private static func appendBigEndian<T: FixedWidthInteger>(_ value: T, to data: inout Data) {
        var bigEndian = value.bigEndian
        withUnsafeBytes(of: &bigEndian) { data.append(contentsOf: $0) }
    }
}

private struct RuntimeV2TransferCarrierReader {
    let data: Data
    var offset = 0

    var isAtEnd: Bool { offset == data.count }

    mutating func take(_ count: Int) throws -> Data {
        guard count >= 0, offset <= data.count, count <= data.count - offset else {
            throw RuntimeV2WireError.invalidTransferCarrier
        }
        defer { offset += count }
        return data.subdata(in: offset..<(offset + count))
    }

    mutating func readUInt8() throws -> UInt8 {
        guard let value = try take(1).first else {
            throw RuntimeV2WireError.invalidTransferCarrier
        }
        return value
    }

    mutating func readUInt16() throws -> UInt16 {
        let bytes = [UInt8](try take(2))
        return (UInt16(bytes[0]) << 8) | UInt16(bytes[1])
    }

    mutating func readUInt32() throws -> UInt32 {
        let bytes = [UInt8](try take(4))
        return bytes.reduce(0) { ($0 << 8) | UInt32($1) }
    }

    mutating func readUInt64() throws -> UInt64 {
        let bytes = [UInt8](try take(8))
        return bytes.reduce(0) { ($0 << 8) | UInt64($1) }
    }

    mutating func readUTF8UInt16() throws -> String {
        let length = Int(try readUInt16())
        guard let value = String(data: try take(length), encoding: .utf8) else {
            throw RuntimeV2WireError.invalidTransferCarrier
        }
        return value
    }
}
