import Foundation

public let runtimeProtocolVersionV1: UInt16 = 1

// MARK: - Stable IDs

public protocol RuntimeV1IDKind: Sendable {}

public struct RuntimeV1ID<Kind: RuntimeV1IDKind>: RawRepresentable, Codable, Hashable, Sendable {
    public let rawValue: String

    public init(rawValue: String) {
        self.rawValue = rawValue
    }

    public init(from decoder: Decoder) throws {
        rawValue = try decoder.singleValueContainer().decode(String.self)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}

public enum RuntimeMessageIDKind: RuntimeV1IDKind {}
public enum RuntimeConversationIDKind: RuntimeV1IDKind {}
public enum RuntimeTurnIDKind: RuntimeV1IDKind {}
public enum RuntimeEventIDKind: RuntimeV1IDKind {}
public enum RuntimeItemIDKind: RuntimeV1IDKind {}
public enum RuntimeEntityIDKind: RuntimeV1IDKind {}
public enum RuntimeCommandIDKind: RuntimeV1IDKind {}
public enum RuntimeApprovalIDKind: RuntimeV1IDKind {}
public enum RuntimeTransferIDKind: RuntimeV1IDKind {}

public typealias RuntimeMessageID = RuntimeV1ID<RuntimeMessageIDKind>
public typealias RuntimeConversationID = RuntimeV1ID<RuntimeConversationIDKind>
public typealias RuntimeTurnID = RuntimeV1ID<RuntimeTurnIDKind>
public typealias RuntimeEventID = RuntimeV1ID<RuntimeEventIDKind>
public typealias RuntimeItemID = RuntimeV1ID<RuntimeItemIDKind>
public typealias RuntimeEntityID = RuntimeV1ID<RuntimeEntityIDKind>
public typealias RuntimeCommandID = RuntimeV1ID<RuntimeCommandIDKind>
public typealias RuntimeApprovalID = RuntimeV1ID<RuntimeApprovalIDKind>
public typealias RuntimeTransferID = RuntimeV1ID<RuntimeTransferIDKind>

public struct RuntimeGrantSerial: RawRepresentable, Codable, Hashable, Sendable {
    public let rawValue: UInt64

    public init(rawValue: UInt64) {
        self.rawValue = rawValue
    }

    public init(from decoder: Decoder) throws {
        rawValue = try decoder.singleValueContainer().decode(UInt64.self)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}

// MARK: - Runtime envelope

public struct RuntimeEnvelopeV1: Codable, Sendable {
    public let version: UInt16
    public let messageID: RuntimeMessageID
    public let body: RuntimeMessageV1

    public init(version: UInt16, messageID: RuntimeMessageID, body: RuntimeMessageV1) {
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
        try rejectUnknownKeys(decoder, allowed: CodingKeys.all)
        let container = try decoder.container(keyedBy: CodingKeys.self)
        version = try container.decode(UInt16.self, forKey: .version)
        guard version == runtimeProtocolVersionV1 else {
            throw DecodingError.dataCorruptedError(
                forKey: .version,
                in: container,
                debugDescription: "unsupported Runtime protocol version \(version)"
            )
        }
        messageID = try container.decode(RuntimeMessageID.self, forKey: .messageID)
        body = try container.decode(RuntimeMessageV1.self, forKey: .body)
    }
}

public enum RuntimeMessageV1: Codable, Sendable {
    case reply(RuntimeReplyV1)
    case stream(RuntimeStreamItemV1)

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case message
        case payload
    }

    public init(from decoder: Decoder) throws {
        try rejectUnknownKeys(decoder, allowed: CodingKeys.all)
        let container = try decoder.container(keyedBy: CodingKeys.self)
        switch try container.decode(String.self, forKey: .message) {
        case "reply":
            self = .reply(try container.decode(RuntimeReplyV1.self, forKey: .payload))
        case "stream":
            self = .stream(try container.decode(RuntimeStreamItemV1.self, forKey: .payload))
        case let value:
            throw DecodingError.dataCorruptedError(
                forKey: .message,
                in: container,
                debugDescription: "unsupported Runtime message \(value)"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .reply(let value):
            try container.encode("reply", forKey: .message)
            try container.encode(value, forKey: .payload)
        case .stream(let value):
            try container.encode("stream", forKey: .message)
            try container.encode(value, forKey: .payload)
        }
    }
}

public enum RuntimeReplyV1: Codable, Sendable {
    case command(CommandReceiptV1)
    case approval(ApprovalReceiptV1)
    case revocation(RevocationReceiptV1)
    case snapshot(ConversationSnapshotV1)

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: RuntimeV1CodingKey.self)
        let reply = try container.decode(String.self, forKey: key("reply"))
        switch reply {
        case "command": self = .command(try CommandReceiptV1(from: decoder))
        case "approval": self = .approval(try ApprovalReceiptV1(from: decoder))
        case "revocation": self = .revocation(try RevocationReceiptV1(from: decoder))
        case "snapshot": self = .snapshot(try ConversationSnapshotV1(from: decoder))
        default:
            throw DecodingError.dataCorruptedError(
                forKey: key("reply"),
                in: container,
                debugDescription: "unsupported Runtime reply \(reply)"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: RuntimeV1CodingKey.self)
        switch self {
        case .command(let receipt):
            try container.encode("command", forKey: key("reply"))
            try receipt.encodeFields(into: &container)
        case .approval(let receipt):
            try container.encode("approval", forKey: key("reply"))
            try receipt.encodeFields(into: &container)
        case .revocation(let receipt):
            try container.encode("revocation", forKey: key("reply"))
            try receipt.encodeFields(into: &container)
        case .snapshot(let snapshot):
            try container.encode("snapshot", forKey: key("reply"))
            try snapshot.encodeFields(into: &container)
        }
    }
}

// MARK: - Receipts

public struct RuntimeFailureV1: Codable, Sendable {
    public let code: String
    public let message: String
    public let diagnosticRef: String?

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case code, message, diagnosticRef
    }

    public init(from decoder: Decoder) throws {
        try rejectUnknownKeys(decoder, allowed: CodingKeys.all)
        let container = try decoder.container(keyedBy: CodingKeys.self)
        code = try container.decode(String.self, forKey: .code)
        message = try container.decode(String.self, forKey: .message)
        diagnosticRef = try container.decodeIfPresent(String.self, forKey: .diagnosticRef)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(code, forKey: .code)
        try container.encode(message, forKey: .message)
        try container.encode(diagnosticRef, forKey: .diagnosticRef)
    }
}

public enum CommandReceiptV1: Codable, Sendable {
    case accepted(commandID: RuntimeCommandID, queuePosition: UInt32)
    case replayed(commandID: RuntimeCommandID)
    case failed(RuntimeFailureV1)

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: RuntimeV1CodingKey.self)
        let status = try container.decode(String.self, forKey: key("status"))
        switch status {
        case "accepted":
            try rejectUnknownKeys(decoder, allowed: ["reply", "status", "command_id", "queue_position"])
            self = .accepted(
                commandID: try container.decode(RuntimeCommandID.self, forKey: key("command_id")),
                queuePosition: try container.decode(UInt32.self, forKey: key("queue_position"))
            )
        case "replayed":
            try rejectUnknownKeys(decoder, allowed: ["reply", "status", "command_id"])
            self = .replayed(
                commandID: try container.decode(RuntimeCommandID.self, forKey: key("command_id"))
            )
        case "failed":
            try rejectUnknownKeys(decoder, allowed: ["reply", "status", "failure"])
            self = .failed(try container.decode(RuntimeFailureV1.self, forKey: key("failure")))
        default:
            throw invalidTag(status, field: "status", in: container)
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: RuntimeV1CodingKey.self)
        try encodeFields(into: &container)
    }

    fileprivate func encodeFields(
        into container: inout KeyedEncodingContainer<RuntimeV1CodingKey>
    ) throws {
        switch self {
        case .accepted(let commandID, let queuePosition):
            try container.encode("accepted", forKey: key("status"))
            try container.encode(commandID, forKey: key("command_id"))
            try container.encode(queuePosition, forKey: key("queue_position"))
        case .replayed(let commandID):
            try container.encode("replayed", forKey: key("status"))
            try container.encode(commandID, forKey: key("command_id"))
        case .failed(let failure):
            try container.encode("failed", forKey: key("status"))
            try container.encode(failure, forKey: key("failure"))
        }
    }
}

public enum ApprovalDeliveryStateV1: String, Codable, Sendable {
    case claimed
    case applying
    case applied
    case deliveryFailed
    case expired
}

public enum ApprovalReceiptV1: Codable, Sendable {
    case claimed(RuntimeApprovalID)
    case applied(RuntimeApprovalID)
    case alreadyHandled(
        approvalID: RuntimeApprovalID,
        decision: ActionDecisionKind,
        state: ApprovalDeliveryStateV1
    )
    case deliveryFailed(RuntimeApprovalID)
    case expired(RuntimeApprovalID)

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: RuntimeV1CodingKey.self)
        let status = try container.decode(String.self, forKey: key("status"))
        switch status {
        case "claimed":
            try rejectUnknownKeys(decoder, allowed: ["reply", "status", "approval_id"])
            self = .claimed(try container.decode(RuntimeApprovalID.self, forKey: key("approval_id")))
        case "applied":
            try rejectUnknownKeys(decoder, allowed: ["reply", "status", "approval_id"])
            self = .applied(try container.decode(RuntimeApprovalID.self, forKey: key("approval_id")))
        case "alreadyHandled":
            try rejectUnknownKeys(
                decoder,
                allowed: ["reply", "status", "approval_id", "decision", "state"]
            )
            self = .alreadyHandled(
                approvalID: try container.decode(RuntimeApprovalID.self, forKey: key("approval_id")),
                decision: try container.decode(ActionDecisionKind.self, forKey: key("decision")),
                state: try container.decode(ApprovalDeliveryStateV1.self, forKey: key("state"))
            )
        case "deliveryFailed":
            try rejectUnknownKeys(decoder, allowed: ["reply", "status", "approval_id"])
            self = .deliveryFailed(
                try container.decode(RuntimeApprovalID.self, forKey: key("approval_id"))
            )
        case "expired":
            try rejectUnknownKeys(decoder, allowed: ["reply", "status", "approval_id"])
            self = .expired(try container.decode(RuntimeApprovalID.self, forKey: key("approval_id")))
        default:
            throw invalidTag(status, field: "status", in: container)
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: RuntimeV1CodingKey.self)
        try encodeFields(into: &container)
    }

    fileprivate func encodeFields(
        into container: inout KeyedEncodingContainer<RuntimeV1CodingKey>
    ) throws {
        switch self {
        case .claimed(let approvalID):
            try encodeSimple("claimed", approvalID: approvalID, into: &container)
        case .applied(let approvalID):
            try encodeSimple("applied", approvalID: approvalID, into: &container)
        case .alreadyHandled(let approvalID, let decision, let state):
            try container.encode("alreadyHandled", forKey: key("status"))
            try container.encode(approvalID, forKey: key("approval_id"))
            try container.encode(decision, forKey: key("decision"))
            try container.encode(state, forKey: key("state"))
        case .deliveryFailed(let approvalID):
            try encodeSimple("deliveryFailed", approvalID: approvalID, into: &container)
        case .expired(let approvalID):
            try encodeSimple("expired", approvalID: approvalID, into: &container)
        }
    }

    private func encodeSimple(
        _ status: String,
        approvalID: RuntimeApprovalID,
        into container: inout KeyedEncodingContainer<RuntimeV1CodingKey>
    ) throws {
        try container.encode(status, forKey: key("status"))
        try container.encode(approvalID, forKey: key("approval_id"))
    }
}

public enum RevocationReceiptV1: Codable, Sendable {
    case committed(RuntimeGrantSerial)
    case failed(RuntimeFailureV1)

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: RuntimeV1CodingKey.self)
        let status = try container.decode(String.self, forKey: key("status"))
        switch status {
        case "committed":
            try rejectUnknownKeys(decoder, allowed: ["reply", "status", "grant_serial"])
            self = .committed(
                try container.decode(RuntimeGrantSerial.self, forKey: key("grant_serial"))
            )
        case "failed":
            try rejectUnknownKeys(decoder, allowed: ["reply", "status", "failure"])
            self = .failed(try container.decode(RuntimeFailureV1.self, forKey: key("failure")))
        default:
            throw invalidTag(status, field: "status", in: container)
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: RuntimeV1CodingKey.self)
        try encodeFields(into: &container)
    }

    fileprivate func encodeFields(
        into container: inout KeyedEncodingContainer<RuntimeV1CodingKey>
    ) throws {
        switch self {
        case .committed(let serial):
            try container.encode("committed", forKey: key("status"))
            try container.encode(serial, forKey: key("grant_serial"))
        case .failed(let failure):
            try container.encode("failed", forKey: key("status"))
            try container.encode(failure, forKey: key("failure"))
        }
    }
}

// MARK: - Stream events

public enum RuntimeStreamItemV1: Codable, Sendable {
    case event(RuntimeEventV1)

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case stream
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        switch try container.decode(String.self, forKey: .stream) {
        case "event": self = .event(try RuntimeEventV1(from: decoder))
        case let value:
            throw DecodingError.dataCorruptedError(
                forKey: .stream,
                in: container,
                debugDescription: "unsupported Runtime stream item \(value)"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        switch self {
        case .event(let event):
            var container = encoder.container(keyedBy: RuntimeV1CodingKey.self)
            try container.encode("event", forKey: key("stream"))
            try event.encodeFields(into: &container)
        }
    }
}

public struct RuntimeEventV1: Codable, Sendable {
    public let conversationID: RuntimeConversationID
    public let eventID: RuntimeEventID
    public let eventSeq: UInt64
    public let itemID: RuntimeItemID?
    public let entityID: RuntimeEntityID?
    public let body: RuntimeEventBodyV1

    public init(from decoder: Decoder) throws {
        try rejectUnknownKeys(
            decoder,
            allowed: ["stream", "conversationId", "eventId", "eventSeq", "itemId", "entityId", "body"]
        )
        let container = try decoder.container(keyedBy: RuntimeV1CodingKey.self)
        conversationID = try container.decode(RuntimeConversationID.self, forKey: key("conversationId"))
        eventID = try container.decode(RuntimeEventID.self, forKey: key("eventId"))
        eventSeq = try container.decode(UInt64.self, forKey: key("eventSeq"))
        itemID = try container.decodeIfPresent(RuntimeItemID.self, forKey: key("itemId"))
        entityID = try container.decodeIfPresent(RuntimeEntityID.self, forKey: key("entityId"))
        body = try container.decode(RuntimeEventBodyV1.self, forKey: key("body"))
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: RuntimeV1CodingKey.self)
        try encodeFields(into: &container)
    }

    fileprivate func encodeFields(
        into container: inout KeyedEncodingContainer<RuntimeV1CodingKey>
    ) throws {
        try container.encode(conversationID, forKey: key("conversationId"))
        try container.encode(eventID, forKey: key("eventId"))
        try container.encode(eventSeq, forKey: key("eventSeq"))
        try container.encode(itemID, forKey: key("itemId"))
        try container.encode(entityID, forKey: key("entityId"))
        try container.encode(body, forKey: key("body"))
    }
}

public enum RuntimeEventBodyV1: Codable, Sendable {
    case turnStarted(turnID: RuntimeTurnID, commandID: RuntimeCommandID)

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: RuntimeV1CodingKey.self)
        let kindValue = try container.decode(String.self, forKey: key("kind"))
        switch kindValue {
        case "turnStarted":
            try rejectUnknownKeys(decoder, allowed: ["kind", "turn_id", "command_id"])
            self = .turnStarted(
                turnID: try container.decode(RuntimeTurnID.self, forKey: key("turn_id")),
                commandID: try container.decode(RuntimeCommandID.self, forKey: key("command_id"))
            )
        default:
            throw invalidTag(kindValue, field: "kind", in: container)
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: RuntimeV1CodingKey.self)
        switch self {
        case .turnStarted(let turnID, let commandID):
            try container.encode("turnStarted", forKey: key("kind"))
            try container.encode(turnID, forKey: key("turn_id"))
            try container.encode(commandID, forKey: key("command_id"))
        }
    }
}

// MARK: - Snapshot barrier

public enum SnapshotItemV1: Codable, Sendable {
    case capabilities(SessionCapabilities)
    case item(itemID: RuntimeItemID, item: AgentItem)

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: RuntimeV1CodingKey.self)
        let kindValue = try container.decode(String.self, forKey: key("kind"))
        switch kindValue {
        case "capabilities":
            try rejectUnknownKeys(decoder, allowed: ["kind", "capabilities"])
            self = .capabilities(
                try container.decode(StrictSessionCapabilities.self, forKey: key("capabilities")).value
            )
        case "item":
            try rejectUnknownKeys(decoder, allowed: ["kind", "item_id", "item"])
            self = .item(
                itemID: try container.decode(RuntimeItemID.self, forKey: key("item_id")),
                item: try container.decode(StrictAgentItem.self, forKey: key("item")).value
            )
        default:
            throw invalidTag(kindValue, field: "kind", in: container)
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: RuntimeV1CodingKey.self)
        switch self {
        case .capabilities(let capabilities):
            try container.encode("capabilities", forKey: key("kind"))
            try container.encode(capabilities, forKey: key("capabilities"))
        case .item(let itemID, let item):
            try container.encode("item", forKey: key("kind"))
            try container.encode(itemID, forKey: key("item_id"))
            try container.encode(item, forKey: key("item"))
        }
    }
}

public struct ConversationSnapshotV1: Codable, Sendable {
    public let conversationID: RuntimeConversationID
    public let baseEventSeq: UInt64
    public let items: [SnapshotItemV1]

    public init(from decoder: Decoder) throws {
        try rejectUnknownKeys(
            decoder,
            allowed: ["reply", "conversationId", "baseEventSeq", "items"]
        )
        let container = try decoder.container(keyedBy: RuntimeV1CodingKey.self)
        conversationID = try container.decode(RuntimeConversationID.self, forKey: key("conversationId"))
        baseEventSeq = try container.decode(UInt64.self, forKey: key("baseEventSeq"))
        items = try container.decode([SnapshotItemV1].self, forKey: key("items"))
        try Self.validate(items, codingPath: decoder.codingPath)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: RuntimeV1CodingKey.self)
        try encodeFields(into: &container)
    }

    fileprivate func encodeFields(
        into container: inout KeyedEncodingContainer<RuntimeV1CodingKey>
    ) throws {
        try container.encode(conversationID, forKey: key("conversationId"))
        try container.encode(baseEventSeq, forKey: key("baseEventSeq"))
        try container.encode(items, forKey: key("items"))
    }

    private static func validate(_ items: [SnapshotItemV1], codingPath: [CodingKey]) throws {
        guard case .capabilities? = items.first else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: codingPath, debugDescription: "snapshot capabilities must be first")
            )
        }
        let capabilityCount = items.reduce(into: 0) { count, item in
            if case .capabilities = item { count += 1 }
        }
        guard capabilityCount == 1 else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: codingPath, debugDescription: "snapshot must contain capabilities exactly once")
            )
        }
    }
}

// MARK: - Transfer envelope

public struct TransferEnvelopeV1: Codable, Sendable {
    public static let maxPartBytes = 3_670_016
    public static let maxPartCount: UInt32 = 64
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

    public init(from decoder: Decoder) throws {
        try rejectUnknownKeys(decoder, allowed: CodingKeys.all)
        let container = try decoder.container(keyedBy: CodingKeys.self)
        transferID = try container.decode(RuntimeTransferID.self, forKey: .transferID)
        partIndex = try container.decode(UInt32.self, forKey: .partIndex)
        partCount = try container.decode(UInt32.self, forKey: .partCount)
        totalSHA256 = try container.decode(Data.self, forKey: .totalSHA256)
        totalBytes = try container.decode(UInt64.self, forKey: .totalBytes)
        part = try container.decode(Data.self, forKey: .part)
        guard partCount > 0,
              partCount <= Self.maxPartCount,
              partIndex < partCount,
              totalSHA256.count == 32,
              totalBytes <= Self.maxTotalBytes,
              part.count <= Self.maxPartBytes
        else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: decoder.codingPath, debugDescription: "invalid transfer bounds")
            )
        }
    }
}

// MARK: - Actual JSON entry points

public enum RuntimeV1WireCodec {
    public static func decodeEnvelope(_ data: Data) throws -> RuntimeEnvelopeV1 {
        try JSONDecoder().decode(RuntimeEnvelopeV1.self, from: data)
    }

    public static func decodeTransferEnvelope(_ data: Data) throws -> TransferEnvelopeV1 {
        try JSONDecoder().decode(TransferEnvelopeV1.self, from: data)
    }

    public static func encode(_ value: RuntimeEnvelopeV1) throws -> Data {
        try JSONEncoder().encode(value)
    }

    public static func encode(_ value: TransferEnvelopeV1) throws -> Data {
        try JSONEncoder().encode(value)
    }
}

// MARK: - Strict decoding support

private struct RuntimeV1CodingKey: CodingKey, Hashable {
    let stringValue: String
    let intValue: Int?

    init(_ stringValue: String) {
        self.stringValue = stringValue
        intValue = nil
    }

    init?(stringValue: String) {
        self.init(stringValue)
    }

    init?(intValue: Int) {
        stringValue = String(intValue)
        self.intValue = intValue
    }
}

private func key(_ value: String) -> RuntimeV1CodingKey {
    RuntimeV1CodingKey(value)
}

private func rejectUnknownKeys(_ decoder: Decoder, allowed: Set<String>) throws {
    let container = try decoder.container(keyedBy: RuntimeV1CodingKey.self)
    if let unknown = container.allKeys.first(where: { !allowed.contains($0.stringValue) }) {
        throw DecodingError.dataCorruptedError(
            forKey: unknown,
            in: container,
            debugDescription: "unknown field \(unknown.stringValue)"
        )
    }
}

private func rejectUnknownKeys(_ decoder: Decoder, allowed: [String]) throws {
    try rejectUnknownKeys(decoder, allowed: Set(allowed))
}

private func invalidTag<T>(
    _ value: String,
    field: String,
    in container: KeyedDecodingContainer<T>
) -> DecodingError where T: CodingKey {
    .dataCorrupted(
        .init(codingPath: container.codingPath, debugDescription: "unsupported \(field) \(value)")
    )
}

private extension CaseIterable where Self: CodingKey {
    static var all: Set<String> {
        Set(allCases.map(\.stringValue))
    }
}

private struct StrictSessionCapabilities: Decodable {
    let value: SessionCapabilities

    init(from decoder: Decoder) throws {
        try rejectUnknownKeys(
            decoder,
            allowed: ["agentKind", "agentVersion", "features", "vendor"]
        )
        let container = try decoder.container(keyedBy: RuntimeV1CodingKey.self)
        _ = try container.decode(StrictVendorCapabilities.self, forKey: key("vendor"))
        value = try SessionCapabilities(from: decoder)
    }
}

private struct StrictVendorCapabilities: Decodable {
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: RuntimeV1CodingKey.self)
        let kindValue = try container.decode(AgentKind.self, forKey: key("agentKind"))
        switch kindValue {
        case .codex:
            try rejectUnknownKeys(
                decoder,
                allowed: ["agentKind", "sandboxModes", "persistenceSupported", "reasoningEffortLevels"]
            )
        case .claudeCode:
            try rejectUnknownKeys(
                decoder,
                allowed: ["agentKind", "permissionModes", "outputStyles", "hooksSupported", "cliVersion"]
            )
        }
    }
}

private struct StrictAgentItem: Decodable {
    let value: AgentItem

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: RuntimeV1CodingKey.self)
        let kindValue = try container.decode(String.self, forKey: key("kind"))
        let common = ["kind", "meta"]
        let fields: [String]
        switch kindValue {
        case "userMessage", "assistantMessage", "reasoning": fields = common + ["text"]
        case "shell": fields = common + ["command", "status", "exitCode", "durationMs"]
        case "diff": fields = common + ["files"]
        case "plan": fields = common + ["steps"]
        case "imageReference": fields = common + ["savedPath", "originalPath"]
        case "toolCall": fields = common + ["name", "args", "result"]
        case "raw": fields = common + ["rawKind", "rawPayload"]
        default: throw invalidTag(kindValue, field: "AgentItem kind", in: container)
        }
        try rejectUnknownKeys(decoder, allowed: fields)
        if container.contains(key("meta")) {
            _ = try container.decode(StrictAgentItemMeta.self, forKey: key("meta"))
        }
        value = try AgentItem(from: decoder)
    }
}

private struct StrictAgentItemMeta: Decodable {
    init(from decoder: Decoder) throws {
        try rejectUnknownKeys(decoder, allowed: ["vendorExtensions"])
    }
}
