import Foundation

// Runtime 公共 wire 的兼容 leaf 与 v1 mirror。当前文件名保持 version-neutral；
// Runtime v2 的 changed/outer DTO 由独立 RuntimeV2Types.swift 承载，避免机械改写全部 leaf symbols。

public let runtimeProtocolVersionV1: UInt16 = 1

public enum RuntimeV1MirrorError: Error, Equatable, Sendable {
    case promptTooLarge
    case duplicateCapability
    case cursorExhausted
    case invalidIdentity
    case invalidTransferCarrier
    case transferTooLarge
    case frameTooLarge
    case backfillTooLarge
    case catalogTooLarge
}

// MARK: - Stable IDs

public protocol RuntimeV1IDKind: Sendable {
    static var maximumWireUTF8Bytes: Int? { get }
}

public extension RuntimeV1IDKind {
    static var maximumWireUTF8Bytes: Int? { nil }
}

public struct RuntimeV1ID<Kind: RuntimeV1IDKind>: RawRepresentable, Codable, Hashable, Sendable {
    public let rawValue: String

    public init(rawValue: String) {
        self.rawValue = rawValue
    }

    public init(from decoder: Decoder) throws {
        rawValue = try decoder.singleValueContainer().decode(String.self)
        try validateWireValue()
    }

    public func encode(to encoder: Encoder) throws {
        try validateWireValue()
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }

    private func validateWireValue() throws {
        guard let maximum = Kind.maximumWireUTF8Bytes else { return }
        let count = rawValue.utf8.count
        guard count > 0, count <= maximum else {
            throw RuntimeV1MirrorError.invalidIdentity
        }
    }
}

public enum RuntimeMessageIDKind: RuntimeV1IDKind {
    public static let maximumWireUTF8Bytes: Int? = 1024
}
public enum RuntimeConversationIDKind: RuntimeV1IDKind {}
public enum RuntimeTurnIDKind: RuntimeV1IDKind {}
public enum RuntimeEventIDKind: RuntimeV1IDKind {}
public enum RuntimeItemIDKind: RuntimeV1IDKind {}
public enum RuntimeEntityIDKind: RuntimeV1IDKind {}
public enum RuntimeCommandIDKind: RuntimeV1IDKind {}
public enum RuntimeApprovalIDKind: RuntimeV1IDKind {}
public enum RuntimeAdapterStateKeyKind: RuntimeV1IDKind {}
public enum RuntimeIdempotencyKeyKind: RuntimeV1IDKind {}
public enum RuntimeTransferIDKind: RuntimeV1IDKind {
    public static let maximumWireUTF8Bytes: Int? = 1024
}
public enum RuntimePairingIDKind: RuntimeV1IDKind {}
public enum RuntimeDeviceHandleKind: RuntimeV1IDKind {}
public enum RuntimeStreamGenerationKind: RuntimeV1IDKind {}
public enum RuntimeCatalogPageCursorKind: RuntimeV1IDKind {}

public typealias RuntimeMessageID = RuntimeV1ID<RuntimeMessageIDKind>
public typealias RuntimeConversationID = RuntimeV1ID<RuntimeConversationIDKind>
public typealias RuntimeTurnID = RuntimeV1ID<RuntimeTurnIDKind>
public typealias RuntimeEventID = RuntimeV1ID<RuntimeEventIDKind>
public typealias RuntimeItemID = RuntimeV1ID<RuntimeItemIDKind>
public typealias RuntimeEntityID = RuntimeV1ID<RuntimeEntityIDKind>
public typealias RuntimeCommandID = RuntimeV1ID<RuntimeCommandIDKind>
public typealias RuntimeApprovalID = RuntimeV1ID<RuntimeApprovalIDKind>
public typealias RuntimeAdapterStateKey = RuntimeV1ID<RuntimeAdapterStateKeyKind>
public typealias RuntimeIdempotencyKey = RuntimeV1ID<RuntimeIdempotencyKeyKind>
public typealias RuntimeTransferID = RuntimeV1ID<RuntimeTransferIDKind>
public typealias RuntimePairingID = RuntimeV1ID<RuntimePairingIDKind>
public typealias RuntimeDeviceHandle = RuntimeV1ID<RuntimeDeviceHandleKind>
public typealias RuntimeStreamGeneration = RuntimeV1ID<RuntimeStreamGenerationKind>
public typealias RuntimeCatalogPageCursor = RuntimeV1ID<RuntimeCatalogPageCursorKind>

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

// MARK: - Requests

public struct RuntimePromptPayloadV1: Codable, Hashable, Sendable {
    public static let maxUTF8Bytes = 256 * 1024
    public let rawValue: String

    public init(rawValue: String) throws {
        guard rawValue.utf8.count <= Self.maxUTF8Bytes else {
            throw RuntimeV1MirrorError.promptTooLarge
        }
        self.rawValue = rawValue
    }

    public init(from decoder: Decoder) throws {
        try self.init(rawValue: decoder.singleValueContainer().decode(String.self))
    }

    public func encode(to encoder: Encoder) throws {
        guard rawValue.utf8.count <= Self.maxUTF8Bytes else {
            throw RuntimeV1MirrorError.promptTooLarge
        }
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}

public enum RuntimeStreamCursorV1: Codable, Equatable, Sendable {
    case beforeFirst
    case at(UInt64)

    public init(from decoder: Decoder) throws {
        if let container = try? decoder.singleValueContainer(),
           let value = try? container.decode(String.self),
           value == "beforeFirst" {
            self = .beforeFirst
            return
        }
        try rejectUnknownKeys(decoder, allowed: ["at"])
        let container = try decoder.container(keyedBy: RuntimeV1CodingKey.self)
        self = .at(try container.decode(UInt64.self, forKey: key("at")))
    }

    public func encode(to encoder: Encoder) throws {
        switch self {
        case .beforeFirst:
            var container = encoder.singleValueContainer()
            try container.encode("beforeFirst")
        case .at(let value):
            var container = encoder.container(keyedBy: RuntimeV1CodingKey.self)
            try container.encode(value, forKey: key("at"))
        }
    }

    public func checkedNext() throws -> UInt64 {
        switch self {
        case .beforeFirst:
            return 0
        case .at(let value):
            guard value < UInt64.max else { throw RuntimeV1MirrorError.cursorExhausted }
            return value + 1
        }
    }
}

public enum RuntimeInnerCursorV1: Codable, Equatable, Sendable {
    case catalog(cursor: RuntimeStreamCursorV1)
    case conversation(conversationID: RuntimeConversationID, cursor: RuntimeStreamCursorV1)

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: RuntimeV1CodingKey.self)
        let scope = try container.decode(String.self, forKey: key("scope"))
        switch scope {
        case "catalog":
            try rejectUnknownKeys(decoder, allowed: ["scope", "cursor"])
            self = .catalog(
                cursor: try container.decode(RuntimeStreamCursorV1.self, forKey: key("cursor"))
            )
        case "conversation":
            try rejectUnknownKeys(decoder, allowed: ["scope", "conversationId", "cursor"])
            self = .conversation(
                conversationID: try container.decode(
                    RuntimeConversationID.self,
                    forKey: key("conversationId")
                ),
                cursor: try container.decode(RuntimeStreamCursorV1.self, forKey: key("cursor"))
            )
        default:
            throw invalidTag(scope, field: "scope", in: container)
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: RuntimeV1CodingKey.self)
        switch self {
        case .catalog(let cursor):
            try container.encode("catalog", forKey: key("scope"))
            try container.encode(cursor, forKey: key("cursor"))
        case .conversation(let conversationID, let cursor):
            try container.encode("conversation", forKey: key("scope"))
            try container.encode(conversationID, forKey: key("conversationId"))
            try container.encode(cursor, forKey: key("cursor"))
        }
    }
}

public enum RuntimeSubscriptionTargetV1: Codable, Sendable {
    case catalog
    case conversation(conversationID: RuntimeConversationID)

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: RuntimeV1CodingKey.self)
        let scope = try container.decode(String.self, forKey: key("scope"))
        switch scope {
        case "catalog":
            try rejectUnknownKeys(decoder, allowed: ["scope"])
            self = .catalog
        case "conversation":
            try rejectUnknownKeys(decoder, allowed: ["scope", "conversationId"])
            self = .conversation(
                conversationID: try container.decode(
                    RuntimeConversationID.self,
                    forKey: key("conversationId")
                )
            )
        default:
            throw invalidTag(scope, field: "scope", in: container)
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: RuntimeV1CodingKey.self)
        switch self {
        case .catalog:
            try container.encode("catalog", forKey: key("scope"))
        case .conversation(let conversationID):
            try container.encode("conversation", forKey: key("scope"))
            try container.encode(conversationID, forKey: key("conversationId"))
        }
    }
}

public enum RuntimeBackfillRequestV1: Codable, Sendable {
    case catalog(after: RuntimeStreamCursorV1)
    case conversation(conversationID: RuntimeConversationID, after: RuntimeStreamCursorV1)

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: RuntimeV1CodingKey.self)
        let scope = try container.decode(String.self, forKey: key("scope"))
        switch scope {
        case "catalog":
            try rejectUnknownKeys(decoder, allowed: ["request", "scope", "after"])
            self = .catalog(
                after: try container.decode(RuntimeStreamCursorV1.self, forKey: key("after"))
            )
        case "conversation":
            try rejectUnknownKeys(
                decoder,
                allowed: ["request", "scope", "conversationId", "after"]
            )
            self = .conversation(
                conversationID: try container.decode(
                    RuntimeConversationID.self,
                    forKey: key("conversationId")
                ),
                after: try container.decode(RuntimeStreamCursorV1.self, forKey: key("after"))
            )
        default:
            throw invalidTag(scope, field: "scope", in: container)
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
        case .catalog(let after):
            try container.encode("catalog", forKey: key("scope"))
            try container.encode(after, forKey: key("after"))
        case .conversation(let conversationID, let after):
            try container.encode("conversation", forKey: key("scope"))
            try container.encode(conversationID, forKey: key("conversationId"))
            try container.encode(after, forKey: key("after"))
        }
    }
}

public enum RuntimeLocalOnlyAdministrationV1: String, Codable, Sendable {
    case localOnly
}

public struct RuntimeActionDecisionV1: Codable, Sendable {
    public let requestID: String
    public let decision: ActionDecisionKind
    public let persist: Bool

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case requestID = "requestId"
        case decision, persist
    }

    public init(from decoder: Decoder) throws {
        try rejectUnknownKeys(decoder, allowed: CodingKeys.all)
        let container = try decoder.container(keyedBy: CodingKeys.self)
        requestID = try container.decode(String.self, forKey: .requestID)
        decision = try container.decode(ActionDecisionKind.self, forKey: .decision)
        persist = try container.decode(Bool.self, forKey: .persist)
    }
}

public enum RuntimeRevokeTargetV1: Codable, Sendable {
    case selfDevice
    case device(
        device: RuntimeDeviceHandle,
        grantSerial: RuntimeGrantSerial,
        scope: RuntimeLocalOnlyAdministrationV1
    )

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: RuntimeV1CodingKey.self)
        let kindValue = try container.decode(String.self, forKey: key("kind"))
        switch kindValue {
        case "selfDevice":
            try rejectUnknownKeys(decoder, allowed: ["kind"])
            self = .selfDevice
        case "device":
            try rejectUnknownKeys(
                decoder,
                allowed: ["kind", "device", "grant_serial", "scope"]
            )
            self = .device(
                device: try container.decode(RuntimeDeviceHandle.self, forKey: key("device")),
                grantSerial: try container.decode(
                    RuntimeGrantSerial.self,
                    forKey: key("grant_serial")
                ),
                scope: try container.decode(
                    RuntimeLocalOnlyAdministrationV1.self,
                    forKey: key("scope")
                )
            )
        default:
            throw invalidTag(kindValue, field: "kind", in: container)
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: RuntimeV1CodingKey.self)
        switch self {
        case .selfDevice:
            try container.encode("selfDevice", forKey: key("kind"))
        case .device(let device, let grantSerial, let scope):
            try container.encode("device", forKey: key("kind"))
            try container.encode(device, forKey: key("device"))
            try container.encode(grantSerial, forKey: key("grant_serial"))
            try container.encode(scope, forKey: key("scope"))
        }
    }
}

public enum RuntimeReceiptSelectorV1: Codable, Sendable {
    case command(conversationID: RuntimeConversationID, commandID: RuntimeCommandID)
    case idempotency(
        conversationID: RuntimeConversationID,
        idempotencyKey: RuntimeIdempotencyKey
    )

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: RuntimeV1CodingKey.self)
        let selector = try container.decode(String.self, forKey: key("selector"))
        switch selector {
        case "command":
            try rejectUnknownKeys(
                decoder,
                allowed: ["request", "selector", "conversationId", "commandId"]
            )
            self = .command(
                conversationID: try container.decode(
                    RuntimeConversationID.self,
                    forKey: key("conversationId")
                ),
                commandID: try container.decode(
                    RuntimeCommandID.self,
                    forKey: key("commandId")
                )
            )
        case "idempotency":
            try rejectUnknownKeys(
                decoder,
                allowed: ["request", "selector", "conversationId", "idempotencyKey"]
            )
            self = .idempotency(
                conversationID: try container.decode(
                    RuntimeConversationID.self,
                    forKey: key("conversationId")
                ),
                idempotencyKey: try container.decode(
                    RuntimeIdempotencyKey.self,
                    forKey: key("idempotencyKey")
                )
            )
        default:
            throw invalidTag(selector, field: "selector", in: container)
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
        case .command(let conversationID, let commandID):
            try container.encode("command", forKey: key("selector"))
            try container.encode(conversationID, forKey: key("conversationId"))
            try container.encode(commandID, forKey: key("commandId"))
        case .idempotency(let conversationID, let idempotencyKey):
            try container.encode("idempotency", forKey: key("selector"))
            try container.encode(conversationID, forKey: key("conversationId"))
            try container.encode(idempotencyKey, forKey: key("idempotencyKey"))
        }
    }
}

public enum RuntimeRequestV1: Codable, Sendable {
    case hello(runtimeProtocolVersion: UInt16)
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
    case sendPrompt(
        conversationID: RuntimeConversationID,
        idempotencyKey: RuntimeIdempotencyKey,
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

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: RuntimeV1CodingKey.self)
        let request = try container.decode(String.self, forKey: key("request"))
        switch request {
        case "hello":
            try rejectUnknownKeys(decoder, allowed: ["request", "runtimeProtocolVersion"])
            self = .hello(
                runtimeProtocolVersion: try container.decode(
                    UInt16.self,
                    forKey: key("runtimeProtocolVersion")
                )
            )
        case "catalog":
            try rejectUnknownKeys(decoder, allowed: ["request", "pageCursor"])
            guard container.contains(key("pageCursor")) else {
                throw DecodingError.keyNotFound(
                    key("pageCursor"),
                    .init(codingPath: decoder.codingPath, debugDescription: "pageCursor is required")
                )
            }
            self = .catalog(
                pageCursor: try container.decodeIfPresent(
                    RuntimeCatalogPageCursor.self,
                    forKey: key("pageCursor")
                )
            )
        case "subscribe":
            try rejectUnknownKeys(decoder, allowed: ["request", "innerCursor"])
            self = .subscribe(
                innerCursor: try container.decode(
                    RuntimeInnerCursorV1.self,
                    forKey: key("innerCursor")
                )
            )
        case "unsubscribe":
            try rejectUnknownKeys(decoder, allowed: ["request", "target"])
            self = .unsubscribe(
                target: try container.decode(
                    RuntimeSubscriptionTargetV1.self,
                    forKey: key("target")
                )
            )
        case "backfill":
            self = .backfill(try RuntimeBackfillRequestV1(from: decoder))
        case "start":
            try rejectUnknownKeys(
                decoder,
                allowed: ["request", "agentKind", "idempotencyKey", "cwd", "title"]
            )
            self = .start(
                agentKind: try container.decode(AgentKind.self, forKey: key("agentKind")),
                idempotencyKey: try container.decode(
                    RuntimeIdempotencyKey.self,
                    forKey: key("idempotencyKey")
                ),
                cwd: try container.decode(String.self, forKey: key("cwd")),
                title: try container.decodeIfPresent(String.self, forKey: key("title"))
            )
        case "sendPrompt":
            try rejectUnknownKeys(
                decoder,
                allowed: ["request", "conversationId", "idempotencyKey", "prompt"]
            )
            self = .sendPrompt(
                conversationID: try container.decode(
                    RuntimeConversationID.self,
                    forKey: key("conversationId")
                ),
                idempotencyKey: try container.decode(
                    RuntimeIdempotencyKey.self,
                    forKey: key("idempotencyKey")
                ),
                prompt: try container.decode(RuntimePromptPayloadV1.self, forKey: key("prompt"))
            )
        case "resolveApproval":
            try rejectUnknownKeys(
                decoder,
                allowed: [
                    "request", "conversation_id", "turn_id", "approval_id", "decision",
                ]
            )
            self = .resolveApproval(
                conversationID: try container.decode(
                    RuntimeConversationID.self,
                    forKey: key("conversation_id")
                ),
                turnID: try container.decode(RuntimeTurnID.self, forKey: key("turn_id")),
                approvalID: try container.decode(
                    RuntimeApprovalID.self,
                    forKey: key("approval_id")
                ),
                decision: try container.decode(
                    RuntimeActionDecisionV1.self,
                    forKey: key("decision")
                )
            )
        case "retryApproval":
            try rejectUnknownKeys(
                decoder,
                allowed: ["request", "conversation_id", "approval_id"]
            )
            self = .retryApproval(
                conversationID: try container.decode(
                    RuntimeConversationID.self,
                    forKey: key("conversation_id")
                ),
                approvalID: try container.decode(
                    RuntimeApprovalID.self,
                    forKey: key("approval_id")
                )
            )
        case "cancelQueued":
            try rejectUnknownKeys(
                decoder,
                allowed: ["request", "conversationId", "commandId"]
            )
            self = .cancelQueued(
                conversationID: try container.decode(
                    RuntimeConversationID.self,
                    forKey: key("conversationId")
                ),
                commandID: try container.decode(
                    RuntimeCommandID.self,
                    forKey: key("commandId")
                )
            )
        case "cancelActive":
            try rejectUnknownKeys(decoder, allowed: ["request", "conversationId", "turnId"])
            self = .cancelActive(
                conversationID: try container.decode(
                    RuntimeConversationID.self,
                    forKey: key("conversationId")
                ),
                turnID: try container.decode(RuntimeTurnID.self, forKey: key("turnId"))
            )
        case "queryReceipt":
            self = .queryReceipt(try RuntimeReceiptSelectorV1(from: decoder))
        case "createPairInvite":
            try rejectUnknownKeys(
                decoder,
                allowed: ["request", "displayName", "ttlSecs", "scope"]
            )
            let ttlSecs: UInt32
            if container.contains(key("ttlSecs")) {
                ttlSecs = try container.decode(UInt32.self, forKey: key("ttlSecs"))
            } else {
                ttlSecs = 300
            }
            self = .createPairInvite(
                displayName: try container.decode(String.self, forKey: key("displayName")),
                ttlSecs: ttlSecs,
                scope: try container.decode(
                    RuntimeLocalOnlyAdministrationV1.self,
                    forKey: key("scope")
                )
            )
        case "listPendingPairings":
            try rejectUnknownKeys(decoder, allowed: ["request", "scope"])
            self = .listPendingPairings(
                scope: try container.decode(
                    RuntimeLocalOnlyAdministrationV1.self,
                    forKey: key("scope")
                )
            )
        case "confirmPairing", "cancelPairing":
            try rejectUnknownKeys(decoder, allowed: ["request", "pairing_id", "scope"])
            let pairingID = try container.decode(RuntimePairingID.self, forKey: key("pairing_id"))
            let scope = try container.decode(
                RuntimeLocalOnlyAdministrationV1.self,
                forKey: key("scope")
            )
            self = request == "confirmPairing"
                ? .confirmPairing(pairingID: pairingID, scope: scope)
                : .cancelPairing(pairingID: pairingID, scope: scope)
        case "revoke":
            try rejectUnknownKeys(decoder, allowed: ["request", "target"])
            self = .revoke(
                target: try container.decode(RuntimeRevokeTargetV1.self, forKey: key("target"))
            )
        case "trustReset":
            try rejectUnknownKeys(decoder, allowed: ["request", "scope"])
            self = .trustReset(
                scope: try container.decode(
                    RuntimeLocalOnlyAdministrationV1.self,
                    forKey: key("scope")
                )
            )
        default:
            throw invalidTag(request, field: "request", in: container)
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: RuntimeV1CodingKey.self)
        switch self {
        case .hello(let version):
            try container.encode("hello", forKey: key("request"))
            try container.encode(version, forKey: key("runtimeProtocolVersion"))
        case .catalog(let pageCursor):
            try container.encode("catalog", forKey: key("request"))
            try container.encode(pageCursor, forKey: key("pageCursor"))
        case .subscribe(let innerCursor):
            try container.encode("subscribe", forKey: key("request"))
            try container.encode(innerCursor, forKey: key("innerCursor"))
        case .unsubscribe(let target):
            try container.encode("unsubscribe", forKey: key("request"))
            try container.encode(target, forKey: key("target"))
        case .backfill(let request):
            try container.encode("backfill", forKey: key("request"))
            try request.encodeFields(into: &container)
        case .start(let agentKind, let idempotencyKey, let cwd, let title):
            try container.encode("start", forKey: key("request"))
            try container.encode(agentKind, forKey: key("agentKind"))
            try container.encode(idempotencyKey, forKey: key("idempotencyKey"))
            try container.encode(cwd, forKey: key("cwd"))
            try container.encode(title, forKey: key("title"))
        case .sendPrompt(let conversationID, let idempotencyKey, let prompt):
            try container.encode("sendPrompt", forKey: key("request"))
            try container.encode(conversationID, forKey: key("conversationId"))
            try container.encode(idempotencyKey, forKey: key("idempotencyKey"))
            try container.encode(prompt, forKey: key("prompt"))
        case .resolveApproval(let conversationID, let turnID, let approvalID, let decision):
            try container.encode("resolveApproval", forKey: key("request"))
            try container.encode(conversationID, forKey: key("conversation_id"))
            try container.encode(turnID, forKey: key("turn_id"))
            try container.encode(approvalID, forKey: key("approval_id"))
            try container.encode(decision, forKey: key("decision"))
        case .retryApproval(let conversationID, let approvalID):
            try container.encode("retryApproval", forKey: key("request"))
            try container.encode(conversationID, forKey: key("conversation_id"))
            try container.encode(approvalID, forKey: key("approval_id"))
        case .cancelQueued(let conversationID, let commandID):
            try container.encode("cancelQueued", forKey: key("request"))
            try container.encode(conversationID, forKey: key("conversationId"))
            try container.encode(commandID, forKey: key("commandId"))
        case .cancelActive(let conversationID, let turnID):
            try container.encode("cancelActive", forKey: key("request"))
            try container.encode(conversationID, forKey: key("conversationId"))
            try container.encode(turnID, forKey: key("turnId"))
        case .queryReceipt(let selector):
            try container.encode("queryReceipt", forKey: key("request"))
            try selector.encodeFields(into: &container)
        case .createPairInvite(let displayName, let ttlSecs, let scope):
            try container.encode("createPairInvite", forKey: key("request"))
            try container.encode(displayName, forKey: key("displayName"))
            try container.encode(ttlSecs, forKey: key("ttlSecs"))
            try container.encode(scope, forKey: key("scope"))
        case .listPendingPairings(let scope):
            try container.encode("listPendingPairings", forKey: key("request"))
            try container.encode(scope, forKey: key("scope"))
        case .confirmPairing(let pairingID, let scope):
            try container.encode("confirmPairing", forKey: key("request"))
            try container.encode(pairingID, forKey: key("pairing_id"))
            try container.encode(scope, forKey: key("scope"))
        case .cancelPairing(let pairingID, let scope):
            try container.encode("cancelPairing", forKey: key("request"))
            try container.encode(pairingID, forKey: key("pairing_id"))
            try container.encode(scope, forKey: key("scope"))
        case .revoke(let target):
            try container.encode("revoke", forKey: key("request"))
            try container.encode(target, forKey: key("target"))
        case .trustReset(let scope):
            try container.encode("trustReset", forKey: key("request"))
            try container.encode(scope, forKey: key("scope"))
        }
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

    public func encode(to encoder: Encoder) throws {
        guard version == runtimeProtocolVersionV1 else {
            throw EncodingError.invalidValue(
                version,
                .init(
                    codingPath: encoder.codingPath,
                    debugDescription: "unsupported Runtime protocol version \(version)"
                )
            )
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(version, forKey: .version)
        try container.encode(messageID, forKey: .messageID)
        try container.encode(body, forKey: .body)
    }
}

public enum RuntimeMessageV1: Codable, Sendable {
    case request(RuntimeRequestV1)
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
        case "request":
            self = .request(try container.decode(RuntimeRequestV1.self, forKey: .payload))
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

public struct RuntimeConversationEntryV1: Codable, Sendable {
    public let conversationID: RuntimeConversationID
    public let adapterStateKey: RuntimeAdapterStateKey
    public let agentKind: AgentKind
    public let title: String?
    public let cwd: String?
    public let lastActiveMs: UInt64
    public let archived: Bool

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case conversationID = "conversationId"
        case adapterStateKey, agentKind, title, cwd, lastActiveMs, archived
    }

    public init(from decoder: Decoder) throws {
        try rejectUnknownKeys(decoder, allowed: CodingKeys.all)
        let container = try decoder.container(keyedBy: CodingKeys.self)
        conversationID = try container.decode(RuntimeConversationID.self, forKey: .conversationID)
        adapterStateKey = try container.decode(RuntimeAdapterStateKey.self, forKey: .adapterStateKey)
        agentKind = try container.decode(AgentKind.self, forKey: .agentKind)
        title = try container.decodeIfPresent(String.self, forKey: .title)
        cwd = try container.decodeIfPresent(String.self, forKey: .cwd)
        lastActiveMs = try container.decode(UInt64.self, forKey: .lastActiveMs)
        archived = try container.decode(Bool.self, forKey: .archived)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(conversationID, forKey: .conversationID)
        try container.encode(adapterStateKey, forKey: .adapterStateKey)
        try container.encode(agentKind, forKey: .agentKind)
        try container.encode(title, forKey: .title)
        try container.encode(cwd, forKey: .cwd)
        try container.encode(lastActiveMs, forKey: .lastActiveMs)
        try container.encode(archived, forKey: .archived)
    }
}

public struct RuntimeCatalogSnapshotV1: Codable, Sendable {
    public static let maxEntries = 500
    public static let maxEncodedBytes = 64 * 1024 * 1024
    public let baseCatalogCursor: RuntimeStreamCursorV1
    public let entries: [RuntimeConversationEntryV1]
    public let nextPageCursor: RuntimeCatalogPageCursor?

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case baseCatalogCursor, entries, nextPageCursor
    }

    init(
        baseCatalogCursor: RuntimeStreamCursorV1,
        entries: [RuntimeConversationEntryV1],
        nextPageCursor: RuntimeCatalogPageCursor?
    ) {
        self.baseCatalogCursor = baseCatalogCursor
        self.entries = entries
        self.nextPageCursor = nextPageCursor
    }

    public init(from decoder: Decoder) throws {
        try rejectUnknownKeys(decoder, allowed: CodingKeys.all.union(["reply"]))
        let container = try decoder.container(keyedBy: CodingKeys.self)
        baseCatalogCursor = try container.decode(
            RuntimeStreamCursorV1.self,
            forKey: .baseCatalogCursor
        )
        entries = try container.decode([RuntimeConversationEntryV1].self, forKey: .entries)
        guard container.contains(.nextPageCursor) else {
            throw DecodingError.keyNotFound(
                CodingKeys.nextPageCursor,
                .init(codingPath: decoder.codingPath, debugDescription: "nextPageCursor is required")
            )
        }
        nextPageCursor = try container.decodeIfPresent(
            RuntimeCatalogPageCursor.self,
            forKey: .nextPageCursor
        )
        try validate(codingPath: decoder.codingPath)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: RuntimeV1CodingKey.self)
        try encodeFields(into: &container)
    }

    fileprivate func encodeFields(
        into container: inout KeyedEncodingContainer<RuntimeV1CodingKey>
    ) throws {
        try validate(codingPath: container.codingPath)
        try encodeUncheckedFields(into: &container)
    }

    fileprivate func encodeUncheckedFields(
        into container: inout KeyedEncodingContainer<RuntimeV1CodingKey>
    ) throws {
        try container.encode(baseCatalogCursor, forKey: key("baseCatalogCursor"))
        try container.encode(entries, forKey: key("entries"))
        try container.encode(nextPageCursor, forKey: key("nextPageCursor"))
    }

    private func validate(codingPath: [CodingKey]) throws {
        guard entries.count <= Self.maxEntries else {
            throw RuntimeV1MirrorError.catalogTooLarge
        }
        let encoded = try JSONEncoder().encode(RuntimeCatalogSnapshotSizeProbe(value: self))
        guard encoded.count <= Self.maxEncodedBytes else {
            throw RuntimeV1MirrorError.catalogTooLarge
        }
    }
}

/// 避免 catalog snapshot 在 64 MiB egress gate 中递归调用自身 encoder。
/// probe 只编码与 direct/flatten wire 相同的 catalog fields。
private struct RuntimeCatalogSnapshotSizeProbe: Encodable {
    let value: RuntimeCatalogSnapshotV1

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: RuntimeV1CodingKey.self)
        try value.encodeUncheckedFields(into: &container)
    }
}

public enum RuntimeCatalogChangeV1: Codable, Sendable {
    case upserted(entry: RuntimeConversationEntryV1)
    case removed(conversationID: RuntimeConversationID)

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: RuntimeV1CodingKey.self)
        let kindValue = try container.decode(String.self, forKey: key("kind"))
        switch kindValue {
        case "upserted":
            try rejectUnknownKeys(decoder, allowed: ["kind", "entry"])
            self = .upserted(
                entry: try container.decode(RuntimeConversationEntryV1.self, forKey: key("entry"))
            )
        case "removed":
            try rejectUnknownKeys(decoder, allowed: ["kind", "conversation_id"])
            self = .removed(
                conversationID: try container.decode(
                    RuntimeConversationID.self,
                    forKey: key("conversation_id")
                )
            )
        default:
            throw invalidTag(kindValue, field: "kind", in: container)
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: RuntimeV1CodingKey.self)
        switch self {
        case .upserted(let entry):
            try container.encode("upserted", forKey: key("kind"))
            try container.encode(entry, forKey: key("entry"))
        case .removed(let conversationID):
            try container.encode("removed", forKey: key("kind"))
            try container.encode(conversationID, forKey: key("conversation_id"))
        }
    }
}

public struct RuntimeCatalogDeltaV1: Codable, Sendable {
    public let catalogRevision: UInt64
    public let changes: [RuntimeCatalogChangeV1]

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case catalogRevision, changes
    }

    public init(from decoder: Decoder) throws {
        try rejectUnknownKeys(decoder, allowed: CodingKeys.all.union(["stream"]))
        let container = try decoder.container(keyedBy: CodingKeys.self)
        catalogRevision = try container.decode(UInt64.self, forKey: .catalogRevision)
        changes = try container.decode([RuntimeCatalogChangeV1].self, forKey: .changes)
    }

    fileprivate func encodeFields(
        into container: inout KeyedEncodingContainer<RuntimeV1CodingKey>
    ) throws {
        try container.encode(catalogRevision, forKey: key("catalogRevision"))
        try container.encode(changes, forKey: key("changes"))
    }
}

public struct RuntimeSyncCompleteV1: Codable, Sendable {
    public let streamGeneration: RuntimeStreamGeneration
    public let streamCursor: RuntimeStreamCursorV1
    public let innerCursor: RuntimeInnerCursorV1
    public let keyDirectoryRevision: UInt64

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case streamGeneration, streamCursor, innerCursor, keyDirectoryRevision
    }

    public init(from decoder: Decoder) throws {
        try rejectUnknownKeys(decoder, allowed: CodingKeys.all)
        try self.init(decodingFieldsFrom: decoder)
    }

    fileprivate init(decodingFieldsFrom decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        streamGeneration = try container.decode(RuntimeStreamGeneration.self, forKey: .streamGeneration)
        streamCursor = try container.decode(RuntimeStreamCursorV1.self, forKey: .streamCursor)
        innerCursor = try container.decode(RuntimeInnerCursorV1.self, forKey: .innerCursor)
        keyDirectoryRevision = try container.decode(UInt64.self, forKey: .keyDirectoryRevision)
    }

    fileprivate func encodeFields(
        into container: inout KeyedEncodingContainer<RuntimeV1CodingKey>
    ) throws {
        try container.encode(streamGeneration, forKey: key("streamGeneration"))
        try container.encode(streamCursor, forKey: key("streamCursor"))
        try container.encode(innerCursor, forKey: key("innerCursor"))
        try container.encode(keyDirectoryRevision, forKey: key("keyDirectoryRevision"))
    }
}

public enum RuntimeSubscriptionReceiptV1: Codable, Sendable {
    case subscribed(streamGeneration: RuntimeStreamGeneration)
    case unsubscribed

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: RuntimeV1CodingKey.self)
        let status = try container.decode(String.self, forKey: key("status"))
        switch status {
        case "subscribed":
            try rejectUnknownKeys(decoder, allowed: ["reply", "status", "streamGeneration"])
            self = .subscribed(
                streamGeneration: try container.decode(
                    RuntimeStreamGeneration.self,
                    forKey: key("streamGeneration")
                )
            )
        case "unsubscribed":
            try rejectUnknownKeys(decoder, allowed: ["reply", "status"])
            self = .unsubscribed
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
        case .subscribed(let streamGeneration):
            try container.encode("subscribed", forKey: key("status"))
            try container.encode(streamGeneration, forKey: key("streamGeneration"))
        case .unsubscribed:
            try container.encode("unsubscribed", forKey: key("status"))
        }
    }
}

public struct RuntimeBackfillRangeV1: Codable, Sendable {
    public static let maxEntries = 512
    public let after: RuntimeStreamCursorV1
    public let through: RuntimeStreamCursorV1

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case after, through
    }

    public init(after: RuntimeStreamCursorV1, through: RuntimeStreamCursorV1) throws {
        self.after = after
        self.through = through
        try validate(codingPath: [])
    }

    public init(from decoder: Decoder) throws {
        try rejectUnknownKeys(decoder, allowed: CodingKeys.all)
        let container = try decoder.container(keyedBy: CodingKeys.self)
        after = try container.decode(RuntimeStreamCursorV1.self, forKey: .after)
        through = try container.decode(RuntimeStreamCursorV1.self, forKey: .through)
        try validate(codingPath: decoder.codingPath)
    }

    public func encode(to encoder: Encoder) throws {
        try validate(codingPath: encoder.codingPath)
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(after, forKey: .after)
        try container.encode(through, forKey: .through)
    }

    fileprivate func bounds(codingPath: [CodingKey]) throws -> (first: UInt64, last: UInt64, count: Int) {
        let first = try after.checkedNext()
        guard case .at(let last) = through, last >= first else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: codingPath, debugDescription: "backfill range must be non-empty")
            )
        }
        let distance = last - first
        guard distance < UInt64(Self.maxEntries) else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: codingPath, debugDescription: "backfill range exceeds 512 entries")
            )
        }
        return (first, last, Int(distance + 1))
    }

    private func validate(codingPath: [CodingKey]) throws {
        _ = try bounds(codingPath: codingPath)
    }
}

public enum RuntimeBackfillChunkV1: Codable, Sendable {
    public static let maxEncodedBytes = 64 * 1024 * 1024

    case catalog(range: RuntimeBackfillRangeV1, deltas: [RuntimeCatalogDeltaV1])
    case conversation(
        conversationID: RuntimeConversationID,
        capabilitiesPreamble: RuntimeSessionCapabilitiesV1,
        range: RuntimeBackfillRangeV1,
        events: [RuntimeEventV1]
    )

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: RuntimeV1CodingKey.self)
        let scope = try container.decode(String.self, forKey: key("scope"))
        switch scope {
        case "catalog":
            try rejectUnknownKeys(decoder, allowed: ["reply", "scope", "range", "deltas"])
            self = .catalog(
                range: try container.decode(RuntimeBackfillRangeV1.self, forKey: key("range")),
                deltas: try container.decode(
                    [RuntimeCatalogDeltaV1].self,
                    forKey: key("deltas")
                )
            )
        case "conversation":
            try rejectUnknownKeys(
                decoder,
                allowed: [
                    "reply", "scope", "conversationId", "capabilitiesPreamble", "range",
                    "events",
                ]
            )
            self = .conversation(
                conversationID: try container.decode(
                    RuntimeConversationID.self,
                    forKey: key("conversationId")
                ),
                capabilitiesPreamble: try container.decode(
                    RuntimeSessionCapabilitiesV1.self,
                    forKey: key("capabilitiesPreamble")
                ),
                range: try container.decode(RuntimeBackfillRangeV1.self, forKey: key("range")),
                events: try container.decode([RuntimeEventV1].self, forKey: key("events"))
            )
        default:
            throw invalidTag(scope, field: "scope", in: container)
        }
        try validate(codingPath: decoder.codingPath)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: RuntimeV1CodingKey.self)
        try encodeFields(into: &container)
    }

    fileprivate func encodeFields(
        into container: inout KeyedEncodingContainer<RuntimeV1CodingKey>
    ) throws {
        try validate(codingPath: container.codingPath)
        try encodeUncheckedFields(into: &container)
    }

    fileprivate func encodeUncheckedFields(
        into container: inout KeyedEncodingContainer<RuntimeV1CodingKey>
    ) throws {
        switch self {
        case .catalog(let range, let deltas):
            try container.encode("catalog", forKey: key("scope"))
            try container.encode(range, forKey: key("range"))
            try container.encode(deltas, forKey: key("deltas"))
        case .conversation(let conversationID, let capabilities, let range, let events):
            try container.encode("conversation", forKey: key("scope"))
            try container.encode(conversationID, forKey: key("conversationId"))
            try container.encode(capabilities, forKey: key("capabilitiesPreamble"))
            try container.encode(range, forKey: key("range"))
            try container.encode(events, forKey: key("events"))
        }
    }

    private func validate(codingPath: [CodingKey]) throws {
        switch self {
        case .catalog(let range, let deltas):
            let bounds = try range.bounds(codingPath: codingPath)
            guard deltas.count == bounds.count else {
                throw invalidBackfill(codingPath)
            }
            for (offset, delta) in deltas.enumerated()
            where delta.catalogRevision != bounds.first + UInt64(offset) {
                throw invalidBackfill(codingPath)
            }
        case .conversation(let conversationID, _, let range, let events):
            let bounds = try range.bounds(codingPath: codingPath)
            guard events.count == bounds.count else {
                throw invalidBackfill(codingPath)
            }
            for (offset, event) in events.enumerated()
            where event.conversationID != conversationID
                || event.eventSeq != bounds.first + UInt64(offset) {
                throw invalidBackfill(codingPath)
            }
        }

        let encoded = try JSONEncoder().encode(RuntimeBackfillChunkSizeProbe(value: self))
        guard encoded.count <= Self.maxEncodedBytes else {
            throw RuntimeV1MirrorError.backfillTooLarge
        }
    }

    private func invalidBackfill(_ codingPath: [CodingKey]) -> DecodingError {
        .dataCorrupted(
            .init(codingPath: codingPath, debugDescription: "backfill entries are not contiguous")
        )
    }
}

/// 避免 `RuntimeBackfillChunkV1.encode` 在执行 64 MiB egress gate 时递归调用自己。
/// probe 只编码同一组 wire fields，不重复执行 validate。
private struct RuntimeBackfillChunkSizeProbe: Encodable {
    let value: RuntimeBackfillChunkV1

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: RuntimeV1CodingKey.self)
        try value.encodeUncheckedFields(into: &container)
    }
}

public struct RuntimePairInviteV1: Codable, Sendable {
    public let pairingID: RuntimePairingID
    public let displayName: String
    public let expiresAtMs: UInt64

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case pairingID = "pairingId"
        case displayName, expiresAtMs
    }

    public init(from decoder: Decoder) throws {
        try rejectUnknownKeys(decoder, allowed: CodingKeys.all.union(["reply"]))
        let container = try decoder.container(keyedBy: CodingKeys.self)
        pairingID = try container.decode(RuntimePairingID.self, forKey: .pairingID)
        displayName = try container.decode(String.self, forKey: .displayName)
        expiresAtMs = try container.decode(UInt64.self, forKey: .expiresAtMs)
    }

    fileprivate func encodeFields(
        into container: inout KeyedEncodingContainer<RuntimeV1CodingKey>
    ) throws {
        try container.encode(pairingID, forKey: key("pairingId"))
        try container.encode(displayName, forKey: key("displayName"))
        try container.encode(expiresAtMs, forKey: key("expiresAtMs"))
    }
}

public struct RuntimePendingPairingV1: Codable, Sendable {
    public let pairingID: RuntimePairingID
    public let deviceFingerprint: String
    public let requestedAtMs: UInt64

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case pairingID = "pairingId"
        case deviceFingerprint, requestedAtMs
    }

    public init(from decoder: Decoder) throws {
        try rejectUnknownKeys(decoder, allowed: CodingKeys.all)
        let container = try decoder.container(keyedBy: CodingKeys.self)
        pairingID = try container.decode(RuntimePairingID.self, forKey: .pairingID)
        deviceFingerprint = try container.decode(String.self, forKey: .deviceFingerprint)
        requestedAtMs = try container.decode(UInt64.self, forKey: .requestedAtMs)
    }
}

public enum RuntimeReplyV1: Codable, Sendable {
    case hello(runtimeProtocolVersion: UInt16)
    case command(CommandReceiptV1)
    case commandStatus(CommandStatusReceiptV1)
    case conversationStart(ConversationStartReceiptV1)
    case cancellation(CancellationReceiptV1)
    case approval(ApprovalReceiptV1)
    case revocation(RevocationReceiptV1)
    case subscription(RuntimeSubscriptionReceiptV1)
    case snapshot(ConversationSnapshotV1)
    case catalog(RuntimeCatalogSnapshotV1)
    case backfill(RuntimeBackfillChunkV1)
    case syncComplete(RuntimeSyncCompleteV1)
    case transferPart(TransferEnvelopeV1)
    case pairInvite(RuntimePairInviteV1)
    case pendingPairings([RuntimePendingPairingV1])
    case failure(RuntimeFailureV1)

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: RuntimeV1CodingKey.self)
        let reply = try container.decode(String.self, forKey: key("reply"))
        switch reply {
        case "hello":
            try rejectUnknownKeys(decoder, allowed: ["reply", "runtimeProtocolVersion"])
            self = .hello(
                runtimeProtocolVersion: try container.decode(
                    UInt16.self,
                    forKey: key("runtimeProtocolVersion")
                )
            )
        case "command": self = .command(try CommandReceiptV1(from: decoder))
        case "commandStatus":
            self = .commandStatus(try CommandStatusReceiptV1(from: decoder))
        case "conversationStart":
            self = .conversationStart(try ConversationStartReceiptV1(from: decoder))
        case "cancellation":
            self = .cancellation(try CancellationReceiptV1(from: decoder))
        case "approval": self = .approval(try ApprovalReceiptV1(from: decoder))
        case "revocation": self = .revocation(try RevocationReceiptV1(from: decoder))
        case "subscription":
            self = .subscription(try RuntimeSubscriptionReceiptV1(from: decoder))
        case "snapshot": self = .snapshot(try ConversationSnapshotV1(from: decoder))
        case "catalog":
            try rejectUnknownKeys(
                decoder,
                allowed: ["reply", "baseCatalogCursor", "entries", "nextPageCursor"]
            )
            self = .catalog(try RuntimeCatalogSnapshotV1(from: decoder))
        case "backfill":
            self = .backfill(try RuntimeBackfillChunkV1(from: decoder))
        case "syncComplete":
            try rejectUnknownKeys(
                decoder,
                allowed: [
                    "reply", "streamGeneration", "streamCursor", "innerCursor",
                    "keyDirectoryRevision",
                ]
            )
            self = .syncComplete(try RuntimeReplySyncCompleteV1(from: decoder).value)
        case "transferPart":
            self = .transferPart(try RuntimeReplyTransferPartV1(from: decoder).value)
        case "pairInvite":
            try rejectUnknownKeys(
                decoder,
                allowed: ["reply", "pairingId", "displayName", "expiresAtMs"]
            )
            self = .pairInvite(try RuntimePairInviteV1(from: decoder))
        case "pendingPairings":
            try rejectUnknownKeys(decoder, allowed: ["reply", "pairings"])
            self = .pendingPairings(
                try container.decode([RuntimePendingPairingV1].self, forKey: key("pairings"))
            )
        case "failure":
            try rejectUnknownKeys(
                decoder,
                allowed: ["reply", "code", "message", "diagnosticRef"]
            )
            self = .failure(
                RuntimeFailureV1(
                    code: try container.decode(String.self, forKey: key("code")),
                    message: try container.decode(String.self, forKey: key("message")),
                    diagnosticRef: try container.decodeIfPresent(
                        String.self,
                        forKey: key("diagnosticRef")
                    )
                )
            )
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
        case .hello(let version):
            try container.encode("hello", forKey: key("reply"))
            try container.encode(version, forKey: key("runtimeProtocolVersion"))
        case .command(let receipt):
            try container.encode("command", forKey: key("reply"))
            try receipt.encodeFields(into: &container)
        case .commandStatus(let receipt):
            try container.encode("commandStatus", forKey: key("reply"))
            try receipt.encodeFields(into: &container)
        case .conversationStart(let receipt):
            try container.encode("conversationStart", forKey: key("reply"))
            try receipt.encodeFields(into: &container)
        case .cancellation(let receipt):
            try container.encode("cancellation", forKey: key("reply"))
            try receipt.encodeFields(into: &container)
        case .approval(let receipt):
            try container.encode("approval", forKey: key("reply"))
            try receipt.encodeFields(into: &container)
        case .revocation(let receipt):
            try container.encode("revocation", forKey: key("reply"))
            try receipt.encodeFields(into: &container)
        case .subscription(let receipt):
            try container.encode("subscription", forKey: key("reply"))
            try receipt.encodeFields(into: &container)
        case .snapshot(let snapshot):
            try container.encode("snapshot", forKey: key("reply"))
            try snapshot.encodeFields(into: &container)
        case .catalog(let catalog):
            try container.encode("catalog", forKey: key("reply"))
            try catalog.encodeFields(into: &container)
        case .backfill(let backfill):
            try container.encode("backfill", forKey: key("reply"))
            try backfill.encodeFields(into: &container)
        case .syncComplete(let value):
            try container.encode("syncComplete", forKey: key("reply"))
            try value.encodeFields(into: &container)
        case .transferPart(let transfer):
            try container.encode("transferPart", forKey: key("reply"))
            try transfer.encodeFields(into: &container)
        case .pairInvite(let value):
            try container.encode("pairInvite", forKey: key("reply"))
            try value.encodeFields(into: &container)
        case .pendingPairings(let pairings):
            try container.encode("pendingPairings", forKey: key("reply"))
            try container.encode(pairings, forKey: key("pairings"))
        case .failure(let failure):
            try container.encode("failure", forKey: key("reply"))
            try container.encode(failure.code, forKey: key("code"))
            try container.encode(failure.message, forKey: key("message"))
            try container.encode(failure.diagnosticRef, forKey: key("diagnosticRef"))
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

    public init(code: String, message: String, diagnosticRef: String? = nil) {
        self.code = code
        self.message = message
        self.diagnosticRef = diagnosticRef
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

public enum CommandStatusV1: String, Codable, Sendable, CaseIterable {
    case accepted
    case started
    case completed
    case failed
    case interrupted
    case expired
    case canceled
    case revokedBeforeStart
}

public struct CommandStatusReceiptV1: Codable, Sendable {
    public let conversationID: RuntimeConversationID
    public let commandID: RuntimeCommandID
    public let status: CommandStatusV1
    public let turnID: RuntimeTurnID?

    public init(
        conversationID: RuntimeConversationID,
        commandID: RuntimeCommandID,
        status: CommandStatusV1,
        turnID: RuntimeTurnID?
    ) {
        self.conversationID = conversationID
        self.commandID = commandID
        self.status = status
        self.turnID = turnID
    }

    public init(from decoder: Decoder) throws {
        try rejectUnknownKeys(
            decoder,
            allowed: ["reply", "conversationId", "commandId", "status", "turnId"]
        )
        let container = try decoder.container(keyedBy: RuntimeV1CodingKey.self)
        conversationID = try container.decode(
            RuntimeConversationID.self,
            forKey: key("conversationId")
        )
        commandID = try container.decode(RuntimeCommandID.self, forKey: key("commandId"))
        status = try container.decode(CommandStatusV1.self, forKey: key("status"))
        turnID = try container.decodeIfPresent(RuntimeTurnID.self, forKey: key("turnId"))
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: RuntimeV1CodingKey.self)
        try encodeFields(into: &container)
    }

    fileprivate func encodeFields(
        into container: inout KeyedEncodingContainer<RuntimeV1CodingKey>
    ) throws {
        try container.encode(conversationID, forKey: key("conversationId"))
        try container.encode(commandID, forKey: key("commandId"))
        try container.encode(status, forKey: key("status"))
        try container.encode(turnID, forKey: key("turnId"))
    }
}

public struct ConversationStartReceiptV1: Codable, Sendable {
    public let conversationID: RuntimeConversationID
    public let adapterStateKey: RuntimeAdapterStateKey
    public let replayed: Bool

    public init(
        conversationID: RuntimeConversationID,
        adapterStateKey: RuntimeAdapterStateKey,
        replayed: Bool
    ) {
        self.conversationID = conversationID
        self.adapterStateKey = adapterStateKey
        self.replayed = replayed
    }

    public init(from decoder: Decoder) throws {
        try rejectUnknownKeys(
            decoder,
            allowed: ["reply", "conversationId", "adapterStateKey", "replayed"]
        )
        let container = try decoder.container(keyedBy: RuntimeV1CodingKey.self)
        conversationID = try container.decode(
            RuntimeConversationID.self,
            forKey: key("conversationId")
        )
        adapterStateKey = try container.decode(
            RuntimeAdapterStateKey.self,
            forKey: key("adapterStateKey")
        )
        replayed = try container.decode(Bool.self, forKey: key("replayed"))
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: RuntimeV1CodingKey.self)
        try encodeFields(into: &container)
    }

    fileprivate func encodeFields(
        into container: inout KeyedEncodingContainer<RuntimeV1CodingKey>
    ) throws {
        try container.encode(conversationID, forKey: key("conversationId"))
        try container.encode(adapterStateKey, forKey: key("adapterStateKey"))
        try container.encode(replayed, forKey: key("replayed"))
    }
}

public enum CancellationReceiptV1: Codable, Sendable {
    case queuedCanceled(
        conversationID: RuntimeConversationID,
        commandID: RuntimeCommandID
    )
    case activeCancelRequested(
        conversationID: RuntimeConversationID,
        turnID: RuntimeTurnID
    )

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: RuntimeV1CodingKey.self)
        let status = try container.decode(String.self, forKey: key("status"))
        switch status {
        case "queuedCanceled":
            try rejectUnknownKeys(
                decoder,
                allowed: ["reply", "status", "conversationId", "commandId"]
            )
            self = .queuedCanceled(
                conversationID: try container.decode(
                    RuntimeConversationID.self,
                    forKey: key("conversationId")
                ),
                commandID: try container.decode(
                    RuntimeCommandID.self,
                    forKey: key("commandId")
                )
            )
        case "activeCancelRequested":
            try rejectUnknownKeys(
                decoder,
                allowed: ["reply", "status", "conversationId", "turnId"]
            )
            self = .activeCancelRequested(
                conversationID: try container.decode(
                    RuntimeConversationID.self,
                    forKey: key("conversationId")
                ),
                turnID: try container.decode(RuntimeTurnID.self, forKey: key("turnId"))
            )
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
        case .queuedCanceled(let conversationID, let commandID):
            try container.encode("queuedCanceled", forKey: key("status"))
            try container.encode(conversationID, forKey: key("conversationId"))
            try container.encode(commandID, forKey: key("commandId"))
        case .activeCancelRequested(let conversationID, let turnID):
            try container.encode("activeCancelRequested", forKey: key("status"))
            try container.encode(conversationID, forKey: key("conversationId"))
            try container.encode(turnID, forKey: key("turnId"))
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

// MARK: - Runtime capability, action, turn and item DTOs

public enum RuntimeVendorCapabilitiesV1: Codable, Sendable {
    case codex(
        sandboxModes: [CodexSandboxMode],
        persistenceSupported: Bool,
        reasoningEffortLevels: [CodexReasoningEffort]
    )
    case claudeCode(
        permissionModes: [ClaudeCodePermissionMode],
        outputStyles: [String],
        hooksSupported: [String],
        cliVersion: String
    )

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: RuntimeV1CodingKey.self)
        let agentKind = try container.decode(AgentKind.self, forKey: key("agentKind"))
        switch agentKind {
        case .codex:
            try rejectUnknownKeys(
                decoder,
                allowed: [
                    "agentKind", "sandboxModes", "persistenceSupported",
                    "reasoningEffortLevels",
                ]
            )
            self = .codex(
                sandboxModes: try container.decode(
                    [CodexSandboxMode].self,
                    forKey: key("sandboxModes")
                ),
                persistenceSupported: try container.decode(
                    Bool.self,
                    forKey: key("persistenceSupported")
                ),
                reasoningEffortLevels: try container.decode(
                    [CodexReasoningEffort].self,
                    forKey: key("reasoningEffortLevels")
                )
            )
        case .claudeCode:
            try rejectUnknownKeys(
                decoder,
                allowed: [
                    "agentKind", "permissionModes", "outputStyles", "hooksSupported",
                    "cliVersion",
                ]
            )
            self = .claudeCode(
                permissionModes: try container.decode(
                    [ClaudeCodePermissionMode].self,
                    forKey: key("permissionModes")
                ),
                outputStyles: try container.decode([String].self, forKey: key("outputStyles")),
                hooksSupported: try container.decode(
                    [String].self,
                    forKey: key("hooksSupported")
                ),
                cliVersion: try container.decode(String.self, forKey: key("cliVersion"))
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: RuntimeV1CodingKey.self)
        switch self {
        case .codex(let sandboxModes, let persistenceSupported, let reasoningEffortLevels):
            try container.encode(AgentKind.codex, forKey: key("agentKind"))
            try container.encode(sandboxModes, forKey: key("sandboxModes"))
            try container.encode(persistenceSupported, forKey: key("persistenceSupported"))
            try container.encode(reasoningEffortLevels, forKey: key("reasoningEffortLevels"))
        case .claudeCode(let permissionModes, let outputStyles, let hooksSupported, let cliVersion):
            try container.encode(AgentKind.claudeCode, forKey: key("agentKind"))
            try container.encode(permissionModes, forKey: key("permissionModes"))
            try container.encode(outputStyles, forKey: key("outputStyles"))
            try container.encode(hooksSupported, forKey: key("hooksSupported"))
            try container.encode(cliVersion, forKey: key("cliVersion"))
        }
    }
}

public struct RuntimeSessionCapabilitiesV1: Codable, Sendable {
    public let agentKind: AgentKind
    public let agentVersion: String
    public let features: Set<CapabilityId>
    public let vendor: RuntimeVendorCapabilitiesV1

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case agentKind, agentVersion, features, vendor
    }

    public init(from decoder: Decoder) throws {
        try rejectUnknownKeys(decoder, allowed: CodingKeys.all)
        let container = try decoder.container(keyedBy: CodingKeys.self)
        agentKind = try container.decode(AgentKind.self, forKey: .agentKind)
        agentVersion = try container.decode(String.self, forKey: .agentVersion)
        let decodedFeatures = try container.decode([CapabilityId].self, forKey: .features)
        guard Set(decodedFeatures).count == decodedFeatures.count else {
            throw RuntimeV1MirrorError.duplicateCapability
        }
        features = Set(decodedFeatures)
        vendor = try container.decode(RuntimeVendorCapabilitiesV1.self, forKey: .vendor)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(agentKind, forKey: .agentKind)
        try container.encode(agentVersion, forKey: .agentVersion)
        try container.encode(
            features.sorted { $0.runtimeV1BTreeOrder < $1.runtimeV1BTreeOrder },
            forKey: .features
        )
        try container.encode(vendor, forKey: .vendor)
    }
}

private extension CapabilityId {
    var runtimeV1BTreeOrder: Int {
        switch self {
        case .streamingMessages: 0
        case .streamingReasoning: 1
        case .shell: 2
        case .diff: 3
        case .approval: 4
        case .mcp: 5
        case .tokenCounters: 6
        case .authStatus: 7
        case .reasoningEffort: 8
        case .imageInput: 9
        case .worktree: 10
        case .codexSandboxMode: 11
        case .codexApprovalPersistence: 12
        case .codexSkills: 13
        case .codexCustomPrompts: 14
        case .claudeCodePermissionMode: 15
        case .claudeCodeHooks: 16
        case .claudeCodeOutputStyle: 17
        case .claudeCodeSlashCommands: 18
        case .claudeCodePlanMode: 19
        case .claudeCodeBackgroundAgents: 20
        case .claudeCodePluginDir: 21
        case .claudeCodeForkSession: 22
        }
    }
}

public struct RuntimeAgentItemMetaV1: Codable, Sendable {
    public let vendorExtensions: [String: AnyCodable]

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case vendorExtensions
    }

    public init(vendorExtensions: [String: AnyCodable] = [:]) {
        self.vendorExtensions = vendorExtensions
    }

    public init(from decoder: Decoder) throws {
        try rejectUnknownKeys(decoder, allowed: CodingKeys.all)
        let container = try decoder.container(keyedBy: CodingKeys.self)
        if container.contains(.vendorExtensions) {
            vendorExtensions = try container.decode(
                [String: AnyCodable].self,
                forKey: .vendorExtensions
            )
        } else {
            vendorExtensions = [:]
        }
    }
}

public struct RuntimeDiffFileV1: Codable, Sendable {
    public let path: String
    public let status: DiffStatus
    public let patch: String?

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case path, status, patch
    }

    public init(from decoder: Decoder) throws {
        try rejectUnknownKeys(decoder, allowed: CodingKeys.all)
        let container = try decoder.container(keyedBy: CodingKeys.self)
        path = try container.decode(String.self, forKey: .path)
        status = try container.decode(DiffStatus.self, forKey: .status)
        patch = try container.decodeIfPresent(String.self, forKey: .patch)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(path, forKey: .path)
        try container.encode(status, forKey: .status)
        try container.encode(patch, forKey: .patch)
    }
}

public struct RuntimePlanStepV1: Codable, Sendable {
    public let title: String
    public let status: PlanStepStatus
    public let detail: String?

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case title, status, detail
    }

    public init(from decoder: Decoder) throws {
        try rejectUnknownKeys(decoder, allowed: CodingKeys.all)
        let container = try decoder.container(keyedBy: CodingKeys.self)
        title = try container.decode(String.self, forKey: .title)
        status = try container.decode(PlanStepStatus.self, forKey: .status)
        detail = try container.decodeIfPresent(String.self, forKey: .detail)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(title, forKey: .title)
        try container.encode(status, forKey: .status)
        try container.encode(detail, forKey: .detail)
    }
}

public enum RuntimeAgentItemV1: Codable, Sendable {
    case userMessage(text: String, meta: RuntimeAgentItemMetaV1)
    case assistantMessage(text: String, meta: RuntimeAgentItemMetaV1)
    case reasoning(text: String, meta: RuntimeAgentItemMetaV1)
    case shell(
        command: String,
        status: ShellStatus,
        exitCode: Int32?,
        durationMs: UInt64?,
        meta: RuntimeAgentItemMetaV1
    )
    case diff(files: [RuntimeDiffFileV1], meta: RuntimeAgentItemMetaV1)
    case plan(steps: [RuntimePlanStepV1], meta: RuntimeAgentItemMetaV1)
    case imageReference(savedPath: String?, originalPath: String?, meta: RuntimeAgentItemMetaV1)
    case toolCall(
        name: String,
        args: AnyCodable,
        result: AnyCodable?,
        meta: RuntimeAgentItemMetaV1
    )
    case raw(rawKind: String, rawPayload: String, meta: RuntimeAgentItemMetaV1)

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: RuntimeV1CodingKey.self)
        let kindValue = try container.decode(String.self, forKey: key("kind"))
        let meta: RuntimeAgentItemMetaV1
        if container.contains(key("meta")) {
            meta = try container.decode(RuntimeAgentItemMetaV1.self, forKey: key("meta"))
        } else {
            meta = RuntimeAgentItemMetaV1()
        }
        switch kindValue {
        case "userMessage", "assistantMessage", "reasoning":
            try rejectUnknownKeys(decoder, allowed: ["kind", "text", "meta"])
            let text = try container.decode(String.self, forKey: key("text"))
            switch kindValue {
            case "userMessage": self = .userMessage(text: text, meta: meta)
            case "assistantMessage": self = .assistantMessage(text: text, meta: meta)
            default: self = .reasoning(text: text, meta: meta)
            }
        case "shell":
            try rejectUnknownKeys(
                decoder,
                allowed: ["kind", "command", "status", "exitCode", "durationMs", "meta"]
            )
            self = .shell(
                command: try container.decode(String.self, forKey: key("command")),
                status: try container.decode(ShellStatus.self, forKey: key("status")),
                exitCode: try container.decodeIfPresent(Int32.self, forKey: key("exitCode")),
                durationMs: try container.decodeIfPresent(UInt64.self, forKey: key("durationMs")),
                meta: meta
            )
        case "diff":
            try rejectUnknownKeys(decoder, allowed: ["kind", "files", "meta"])
            self = .diff(
                files: try container.decode([RuntimeDiffFileV1].self, forKey: key("files")),
                meta: meta
            )
        case "plan":
            try rejectUnknownKeys(decoder, allowed: ["kind", "steps", "meta"])
            self = .plan(
                steps: try container.decode([RuntimePlanStepV1].self, forKey: key("steps")),
                meta: meta
            )
        case "imageReference":
            try rejectUnknownKeys(
                decoder,
                allowed: ["kind", "savedPath", "originalPath", "meta"]
            )
            self = .imageReference(
                savedPath: try container.decodeIfPresent(String.self, forKey: key("savedPath")),
                originalPath: try container.decodeIfPresent(
                    String.self,
                    forKey: key("originalPath")
                ),
                meta: meta
            )
        case "toolCall":
            try rejectUnknownKeys(
                decoder,
                allowed: ["kind", "name", "args", "result", "meta"]
            )
            self = .toolCall(
                name: try container.decode(String.self, forKey: key("name")),
                args: try container.decode(AnyCodable.self, forKey: key("args")),
                result: try container.decodeIfPresent(AnyCodable.self, forKey: key("result")),
                meta: meta
            )
        case "raw":
            try rejectUnknownKeys(
                decoder,
                allowed: ["kind", "rawKind", "rawPayload", "meta"]
            )
            self = .raw(
                rawKind: try container.decode(String.self, forKey: key("rawKind")),
                rawPayload: try container.decode(String.self, forKey: key("rawPayload")),
                meta: meta
            )
        default:
            throw invalidTag(kindValue, field: "kind", in: container)
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: RuntimeV1CodingKey.self)
        switch self {
        case .userMessage(let text, let meta),
             .assistantMessage(let text, let meta),
             .reasoning(let text, let meta):
            let kindValue: String
            switch self {
            case .userMessage: kindValue = "userMessage"
            case .assistantMessage: kindValue = "assistantMessage"
            default: kindValue = "reasoning"
            }
            try container.encode(kindValue, forKey: key("kind"))
            try container.encode(text, forKey: key("text"))
            try container.encode(meta, forKey: key("meta"))
        case .shell(let command, let status, let exitCode, let durationMs, let meta):
            try container.encode("shell", forKey: key("kind"))
            try container.encode(command, forKey: key("command"))
            try container.encode(status, forKey: key("status"))
            try container.encode(exitCode, forKey: key("exitCode"))
            try container.encode(durationMs, forKey: key("durationMs"))
            try container.encode(meta, forKey: key("meta"))
        case .diff(let files, let meta):
            try container.encode("diff", forKey: key("kind"))
            try container.encode(files, forKey: key("files"))
            try container.encode(meta, forKey: key("meta"))
        case .plan(let steps, let meta):
            try container.encode("plan", forKey: key("kind"))
            try container.encode(steps, forKey: key("steps"))
            try container.encode(meta, forKey: key("meta"))
        case .imageReference(let savedPath, let originalPath, let meta):
            try container.encode("imageReference", forKey: key("kind"))
            try container.encode(savedPath, forKey: key("savedPath"))
            try container.encode(originalPath, forKey: key("originalPath"))
            try container.encode(meta, forKey: key("meta"))
        case .toolCall(let name, let args, let result, let meta):
            try container.encode("toolCall", forKey: key("kind"))
            try container.encode(name, forKey: key("name"))
            try container.encode(args, forKey: key("args"))
            try container.encode(result, forKey: key("result"))
            try container.encode(meta, forKey: key("meta"))
        case .raw(let rawKind, let rawPayload, let meta):
            try container.encode("raw", forKey: key("kind"))
            try container.encode(rawKind, forKey: key("rawKind"))
            try container.encode(rawPayload, forKey: key("rawPayload"))
            try container.encode(meta, forKey: key("meta"))
        }
    }
}

public enum RuntimeActionRequestVendorV1: Codable, Sendable {
    case codex(
        approvalPolicyAtDecision: CodexApprovalPolicy,
        sandboxAtDecision: CodexSandboxMode,
        canPersist: Bool
    )
    case claudeCode(permissionModeAtDecision: ClaudeCodePermissionMode, toolName: String)

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: RuntimeV1CodingKey.self)
        let kind = try container.decode(AgentKind.self, forKey: key("agentKind"))
        switch kind {
        case .codex:
            try rejectUnknownKeys(
                decoder,
                allowed: [
                    "agentKind", "approvalPolicyAtDecision", "sandboxAtDecision", "canPersist",
                ]
            )
            self = .codex(
                approvalPolicyAtDecision: try container.decode(
                    CodexApprovalPolicy.self,
                    forKey: key("approvalPolicyAtDecision")
                ),
                sandboxAtDecision: try container.decode(
                    CodexSandboxMode.self,
                    forKey: key("sandboxAtDecision")
                ),
                canPersist: try container.decode(Bool.self, forKey: key("canPersist"))
            )
        case .claudeCode:
            try rejectUnknownKeys(
                decoder,
                allowed: ["agentKind", "permissionModeAtDecision", "toolName"]
            )
            self = .claudeCode(
                permissionModeAtDecision: try container.decode(
                    ClaudeCodePermissionMode.self,
                    forKey: key("permissionModeAtDecision")
                ),
                toolName: try container.decode(String.self, forKey: key("toolName"))
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: RuntimeV1CodingKey.self)
        switch self {
        case .codex(let policy, let sandbox, let canPersist):
            try container.encode(AgentKind.codex, forKey: key("agentKind"))
            try container.encode(policy, forKey: key("approvalPolicyAtDecision"))
            try container.encode(sandbox, forKey: key("sandboxAtDecision"))
            try container.encode(canPersist, forKey: key("canPersist"))
        case .claudeCode(let mode, let toolName):
            try container.encode(AgentKind.claudeCode, forKey: key("agentKind"))
            try container.encode(mode, forKey: key("permissionModeAtDecision"))
            try container.encode(toolName, forKey: key("toolName"))
        }
    }
}

public struct RuntimeActionRequestV1: Codable, Sendable {
    public let requestID: String
    public let kind: ActionKind
    public let summary: String
    public let vendor: RuntimeActionRequestVendorV1

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case requestID = "requestId"
        case kind, summary, vendor
    }

    public init(from decoder: Decoder) throws {
        try rejectUnknownKeys(decoder, allowed: CodingKeys.all)
        let container = try decoder.container(keyedBy: CodingKeys.self)
        requestID = try container.decode(String.self, forKey: .requestID)
        kind = try container.decode(ActionKind.self, forKey: .kind)
        summary = try container.decode(String.self, forKey: .summary)
        vendor = try container.decode(RuntimeActionRequestVendorV1.self, forKey: .vendor)
    }
}

public struct RuntimeTurnSummaryV1: Codable, Sendable {
    public let totalInputTokens: UInt64?
    public let totalOutputTokens: UInt64?
    public let elapsedMs: UInt64

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case totalInputTokens, totalOutputTokens, elapsedMs
    }

    public init(from decoder: Decoder) throws {
        try rejectUnknownKeys(decoder, allowed: CodingKeys.all)
        let container = try decoder.container(keyedBy: CodingKeys.self)
        totalInputTokens = try container.decodeIfPresent(UInt64.self, forKey: .totalInputTokens)
        totalOutputTokens = try container.decodeIfPresent(UInt64.self, forKey: .totalOutputTokens)
        elapsedMs = try container.decode(UInt64.self, forKey: .elapsedMs)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(totalInputTokens, forKey: .totalInputTokens)
        try container.encode(totalOutputTokens, forKey: .totalOutputTokens)
        try container.encode(elapsedMs, forKey: .elapsedMs)
    }
}

// MARK: - Stream events

public enum RuntimeStreamItemV1: Codable, Sendable {
    case event(RuntimeEventV1)
    case catalogDelta(RuntimeCatalogDeltaV1)
    case transferPart(TransferEnvelopeV1)

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case stream
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        switch try container.decode(String.self, forKey: .stream) {
        case "event": self = .event(try RuntimeStreamEventV1(from: decoder).value)
        case "catalogDelta": self = .catalogDelta(try RuntimeCatalogDeltaV1(from: decoder))
        case "transferPart":
            self = .transferPart(try RuntimeStreamTransferPartV1(from: decoder).value)
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
        case .catalogDelta(let delta):
            var container = encoder.container(keyedBy: RuntimeV1CodingKey.self)
            try container.encode("catalogDelta", forKey: key("stream"))
            try delta.encodeFields(into: &container)
        case .transferPart(let value):
            var container = encoder.container(keyedBy: RuntimeV1CodingKey.self)
            try container.encode("transferPart", forKey: key("stream"))
            try value.encodeFields(into: &container)
        }
    }
}

public struct RuntimeEventV1: Codable, Sendable {
    public let conversationID: RuntimeConversationID
    public let eventID: RuntimeEventID
    public let eventSeq: UInt64
    public let commandID: RuntimeCommandID?
    public let itemID: RuntimeItemID?
    public let entityID: RuntimeEntityID?
    public let body: RuntimeEventBodyV1

    public init(from decoder: Decoder) throws {
        try rejectUnknownKeys(
            decoder,
            allowed: [
                "conversationId", "eventId", "eventSeq", "commandId", "itemId", "entityId",
                "body",
            ]
        )
        try self.init(decodingFieldsFrom: decoder)
    }

    fileprivate init(decodingFieldsFrom decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: RuntimeV1CodingKey.self)
        conversationID = try container.decode(RuntimeConversationID.self, forKey: key("conversationId"))
        eventID = try container.decode(RuntimeEventID.self, forKey: key("eventId"))
        eventSeq = try container.decode(UInt64.self, forKey: key("eventSeq"))
        for requiredNullable in ["commandId", "itemId", "entityId"]
        where !container.contains(key(requiredNullable)) {
            throw DecodingError.keyNotFound(
                key(requiredNullable),
                .init(
                    codingPath: decoder.codingPath,
                    debugDescription: "\(requiredNullable) is required even when null"
                )
            )
        }
        commandID = try container.decodeIfPresent(RuntimeCommandID.self, forKey: key("commandId"))
        itemID = try container.decodeIfPresent(RuntimeItemID.self, forKey: key("itemId"))
        entityID = try container.decodeIfPresent(RuntimeEntityID.self, forKey: key("entityId"))
        body = try container.decode(RuntimeEventBodyV1.self, forKey: key("body"))
        try validate(codingPath: decoder.codingPath)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: RuntimeV1CodingKey.self)
        try encodeFields(into: &container)
    }

    fileprivate func encodeFields(
        into container: inout KeyedEncodingContainer<RuntimeV1CodingKey>
    ) throws {
        try validate(codingPath: container.codingPath)
        try container.encode(conversationID, forKey: key("conversationId"))
        try container.encode(eventID, forKey: key("eventId"))
        try container.encode(eventSeq, forKey: key("eventSeq"))
        try container.encode(commandID, forKey: key("commandId"))
        try container.encode(itemID, forKey: key("itemId"))
        try container.encode(entityID, forKey: key("entityId"))
        try container.encode(body, forKey: key("body"))
    }

    private func validate(codingPath: [CodingKey]) throws {
        let hasItemIdentity = itemID != nil && entityID != nil
        let hasNoItemIdentity = itemID == nil && entityID == nil
        let valid: Bool
        switch body {
        case .capabilities:
            valid = commandID == nil && hasNoItemIdentity
        case .item(let item):
            let isUserMessage: Bool
            if case .userMessage = item { isUserMessage = true } else { isUserMessage = false }
            valid = hasItemIdentity && (!isUserMessage || commandID != nil)
        case .turnStarted, .actionRequest, .approvalResolved, .turnCompleted, .turnInterrupted:
            valid = commandID != nil && hasNoItemIdentity
        case .error:
            valid = hasNoItemIdentity
        }
        guard valid else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: codingPath, debugDescription: "runtime event identity mismatch")
            )
        }
    }
}

private struct RuntimeReplySyncCompleteV1: Decodable {
    let value: RuntimeSyncCompleteV1

    init(from decoder: Decoder) throws {
        try rejectUnknownKeys(
            decoder,
            allowed: [
                "reply", "streamGeneration", "streamCursor", "innerCursor",
                "keyDirectoryRevision",
            ]
        )
        let container = try decoder.container(keyedBy: RuntimeV1CodingKey.self)
        let tag = try container.decode(String.self, forKey: key("reply"))
        guard tag == "syncComplete" else {
            throw invalidTag(tag, field: "reply", in: container)
        }
        value = try RuntimeSyncCompleteV1(decodingFieldsFrom: decoder)
    }
}

private struct RuntimeStreamEventV1: Decodable {
    let value: RuntimeEventV1

    init(from decoder: Decoder) throws {
        try rejectUnknownKeys(
            decoder,
            allowed: [
                "stream", "conversationId", "eventId", "eventSeq", "commandId", "itemId",
                "entityId", "body",
            ]
        )
        let container = try decoder.container(keyedBy: RuntimeV1CodingKey.self)
        let tag = try container.decode(String.self, forKey: key("stream"))
        guard tag == "event" else {
            throw invalidTag(tag, field: "stream", in: container)
        }
        value = try RuntimeEventV1(decodingFieldsFrom: decoder)
    }
}

public enum RuntimeEventBodyV1: Codable, Sendable {
    case capabilities(RuntimeSessionCapabilitiesV1)
    case item(RuntimeAgentItemV1)
    case turnStarted(turnID: RuntimeTurnID)
    case actionRequest(
        turnID: RuntimeTurnID,
        approvalID: RuntimeApprovalID,
        request: RuntimeActionRequestV1
    )
    case approvalResolved(
        turnID: RuntimeTurnID,
        approvalID: RuntimeApprovalID,
        decision: ActionDecisionKind?,
        state: ApprovalDeliveryStateV1
    )
    case turnCompleted(turnID: RuntimeTurnID, summary: RuntimeTurnSummaryV1)
    case turnInterrupted(turnID: RuntimeTurnID)
    case error(RuntimeFailureV1)

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: RuntimeV1CodingKey.self)
        let kindValue = try container.decode(String.self, forKey: key("kind"))
        switch kindValue {
        case "capabilities":
            try rejectUnknownKeys(decoder, allowed: ["kind", "capabilities"])
            self = .capabilities(
                try container.decode(
                    RuntimeSessionCapabilitiesV1.self,
                    forKey: key("capabilities")
                )
            )
        case "item":
            try rejectUnknownKeys(decoder, allowed: ["kind", "item"])
            self = .item(
                try container.decode(RuntimeAgentItemV1.self, forKey: key("item"))
            )
        case "turnStarted":
            try rejectUnknownKeys(decoder, allowed: ["kind", "turn_id"])
            self = .turnStarted(
                turnID: try container.decode(RuntimeTurnID.self, forKey: key("turn_id"))
            )
        case "actionRequest":
            try rejectUnknownKeys(
                decoder,
                allowed: ["kind", "turn_id", "approval_id", "request"]
            )
            self = .actionRequest(
                turnID: try container.decode(RuntimeTurnID.self, forKey: key("turn_id")),
                approvalID: try container.decode(
                    RuntimeApprovalID.self,
                    forKey: key("approval_id")
                ),
                request: try container.decode(RuntimeActionRequestV1.self, forKey: key("request"))
            )
        case "approvalResolved":
            try rejectUnknownKeys(
                decoder,
                allowed: ["kind", "turn_id", "approval_id", "decision", "state"]
            )
            self = .approvalResolved(
                turnID: try container.decode(RuntimeTurnID.self, forKey: key("turn_id")),
                approvalID: try container.decode(
                    RuntimeApprovalID.self,
                    forKey: key("approval_id")
                ),
                decision: try container.decode(
                    ActionDecisionKind?.self,
                    forKey: key("decision")
                ),
                state: try container.decode(
                    ApprovalDeliveryStateV1.self,
                    forKey: key("state")
                )
            )
        case "turnCompleted":
            try rejectUnknownKeys(decoder, allowed: ["kind", "turn_id", "summary"])
            self = .turnCompleted(
                turnID: try container.decode(RuntimeTurnID.self, forKey: key("turn_id")),
                summary: try container.decode(RuntimeTurnSummaryV1.self, forKey: key("summary"))
            )
        case "turnInterrupted":
            try rejectUnknownKeys(decoder, allowed: ["kind", "turn_id"])
            self = .turnInterrupted(
                turnID: try container.decode(RuntimeTurnID.self, forKey: key("turn_id"))
            )
        case "error":
            try rejectUnknownKeys(decoder, allowed: ["kind", "failure"])
            self = .error(
                try container.decode(RuntimeFailureV1.self, forKey: key("failure"))
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
        case .item(let item):
            try container.encode("item", forKey: key("kind"))
            try container.encode(item, forKey: key("item"))
        case .turnStarted(let turnID):
            try container.encode("turnStarted", forKey: key("kind"))
            try container.encode(turnID, forKey: key("turn_id"))
        case .actionRequest(let turnID, let approvalID, let request):
            try container.encode("actionRequest", forKey: key("kind"))
            try container.encode(turnID, forKey: key("turn_id"))
            try container.encode(approvalID, forKey: key("approval_id"))
            try container.encode(request, forKey: key("request"))
        case .approvalResolved(let turnID, let approvalID, let decision, let state):
            try container.encode("approvalResolved", forKey: key("kind"))
            try container.encode(turnID, forKey: key("turn_id"))
            try container.encode(approvalID, forKey: key("approval_id"))
            try container.encode(decision, forKey: key("decision"))
            try container.encode(state, forKey: key("state"))
        case .turnCompleted(let turnID, let summary):
            try container.encode("turnCompleted", forKey: key("kind"))
            try container.encode(turnID, forKey: key("turn_id"))
            try container.encode(summary, forKey: key("summary"))
        case .turnInterrupted(let turnID):
            try container.encode("turnInterrupted", forKey: key("kind"))
            try container.encode(turnID, forKey: key("turn_id"))
        case .error(let failure):
            try container.encode("error", forKey: key("kind"))
            try container.encode(failure, forKey: key("failure"))
        }
    }
}

// MARK: - Snapshot barrier

public enum SnapshotItemV1: Codable, Sendable {
    case capabilities(RuntimeSessionCapabilitiesV1)
    case item(
        itemID: RuntimeItemID,
        entityID: RuntimeEntityID,
        commandID: RuntimeCommandID?,
        item: RuntimeAgentItemV1
    )

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: RuntimeV1CodingKey.self)
        let kindValue = try container.decode(String.self, forKey: key("kind"))
        switch kindValue {
        case "capabilities":
            try rejectUnknownKeys(
                decoder,
                allowed: ["kind", "commandId", "itemId", "entityId", "capabilities"]
            )
            for identity in ["commandId", "itemId", "entityId"] {
                guard container.contains(key(identity)), try container.decodeNil(forKey: key(identity)) else {
                    throw DecodingError.dataCorruptedError(
                        forKey: key(identity),
                        in: container,
                        debugDescription: "capabilities identity must be explicit null"
                    )
                }
            }
            self = .capabilities(
                try container.decode(
                    RuntimeSessionCapabilitiesV1.self,
                    forKey: key("capabilities")
                )
            )
        case "item":
            try rejectUnknownKeys(
                decoder,
                allowed: ["kind", "commandId", "itemId", "entityId", "item"]
            )
            guard container.contains(key("commandId")) else {
                throw DecodingError.keyNotFound(
                    key("commandId"),
                    .init(codingPath: decoder.codingPath, debugDescription: "commandId is required")
                )
            }
            let commandID = try container.decodeIfPresent(
                RuntimeCommandID.self,
                forKey: key("commandId")
            )
            let item = try container.decode(RuntimeAgentItemV1.self, forKey: key("item"))
            if case .userMessage = item, commandID == nil {
                throw DecodingError.dataCorruptedError(
                    forKey: key("commandId"),
                    in: container,
                    debugDescription: "snapshot UserMessage requires commandId"
                )
            }
            self = .item(
                itemID: try container.decode(RuntimeItemID.self, forKey: key("itemId")),
                entityID: try container.decode(RuntimeEntityID.self, forKey: key("entityId")),
                commandID: commandID,
                item: item
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
            try container.encodeNil(forKey: key("commandId"))
            try container.encodeNil(forKey: key("itemId"))
            try container.encodeNil(forKey: key("entityId"))
            try container.encode(capabilities, forKey: key("capabilities"))
        case .item(let itemID, let entityID, let commandID, let item):
            if case .userMessage = item, commandID == nil {
                throw EncodingError.invalidValue(
                    item,
                    .init(codingPath: encoder.codingPath, debugDescription: "UserMessage requires commandId")
                )
            }
            try container.encode("item", forKey: key("kind"))
            try container.encode(commandID, forKey: key("commandId"))
            try container.encode(itemID, forKey: key("itemId"))
            try container.encode(entityID, forKey: key("entityId"))
            try container.encode(item, forKey: key("item"))
        }
    }
}

public struct ConversationSnapshotV1: Codable, Sendable {
    public let conversationID: RuntimeConversationID
    public let baseEventCursor: RuntimeStreamCursorV1
    public let items: [SnapshotItemV1]

    public init(from decoder: Decoder) throws {
        try rejectUnknownKeys(
            decoder,
            allowed: ["reply", "conversationId", "baseEventCursor", "items"]
        )
        let container = try decoder.container(keyedBy: RuntimeV1CodingKey.self)
        conversationID = try container.decode(RuntimeConversationID.self, forKey: key("conversationId"))
        baseEventCursor = try container.decode(
            RuntimeStreamCursorV1.self,
            forKey: key("baseEventCursor")
        )
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
        try container.encode(baseEventCursor, forKey: key("baseEventCursor"))
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
    public static let maxRemotePartBytes = 3_670_016
    public static let maxJSONPartBytes = 700 * 1024
    public static let maxPartBytes = maxJSONPartBytes
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
        try self.init(decodingFieldsFrom: decoder, maximumPartBytes: Self.maxJSONPartBytes)
    }

    fileprivate init(
        decodingFieldsFrom decoder: Decoder,
        maximumPartBytes: Int
    ) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        transferID = try container.decode(RuntimeTransferID.self, forKey: .transferID)
        partIndex = try container.decode(UInt32.self, forKey: .partIndex)
        partCount = try container.decode(UInt32.self, forKey: .partCount)
        totalSHA256 = try container.decode(Data.self, forKey: .totalSHA256)
        totalBytes = try container.decode(UInt64.self, forKey: .totalBytes)
        part = try container.decode(Data.self, forKey: .part)
        try validate(maximumPartBytes: maximumPartBytes, codingPath: decoder.codingPath)
    }

    init(
        transferID: RuntimeTransferID,
        partIndex: UInt32,
        partCount: UInt32,
        totalSHA256: Data,
        totalBytes: UInt64,
        part: Data,
        maximumPartBytes: Int
    ) throws {
        self.transferID = transferID
        self.partIndex = partIndex
        self.partCount = partCount
        self.totalSHA256 = totalSHA256
        self.totalBytes = totalBytes
        self.part = part
        try validate(maximumPartBytes: maximumPartBytes, codingPath: [])
    }

    public func encode(to encoder: Encoder) throws {
        try validate(maximumPartBytes: Self.maxJSONPartBytes, codingPath: encoder.codingPath)
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(transferID, forKey: .transferID)
        try container.encode(partIndex, forKey: .partIndex)
        try container.encode(partCount, forKey: .partCount)
        try container.encode(totalSHA256, forKey: .totalSHA256)
        try container.encode(totalBytes, forKey: .totalBytes)
        try container.encode(part, forKey: .part)
    }

    fileprivate func encodeFields(
        into container: inout KeyedEncodingContainer<RuntimeV1CodingKey>
    ) throws {
        try validate(maximumPartBytes: Self.maxJSONPartBytes, codingPath: container.codingPath)
        try container.encode(transferID, forKey: key("transferId"))
        try container.encode(partIndex, forKey: key("partIndex"))
        try container.encode(partCount, forKey: key("partCount"))
        try container.encode(totalSHA256, forKey: key("totalSha256"))
        try container.encode(totalBytes, forKey: key("totalBytes"))
        try container.encode(part, forKey: key("part"))
    }

    fileprivate func validate(maximumPartBytes: Int, codingPath: [CodingKey]) throws {
        let maximumRepresentable = UInt64(partCount) * UInt64(maximumPartBytes)
        guard partCount > 0,
              partCount <= Self.maxPartCount,
              partIndex < partCount,
              totalSHA256.count == 32,
              totalBytes <= Self.maxTotalBytes,
              totalBytes <= maximumRepresentable,
              part.count <= maximumPartBytes,
              UInt64(part.count) <= totalBytes
        else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: codingPath, debugDescription: "invalid transfer bounds")
            )
        }
    }
}

private struct RuntimeReplyTransferPartV1: Decodable {
    let value: TransferEnvelopeV1

    init(from decoder: Decoder) throws {
        try rejectUnknownKeys(
            decoder,
            allowed: [
                "reply", "transferId", "partIndex", "partCount", "totalSha256", "totalBytes",
                "part",
            ]
        )
        let container = try decoder.container(keyedBy: RuntimeV1CodingKey.self)
        let tag = try container.decode(String.self, forKey: key("reply"))
        guard tag == "transferPart" else { throw invalidTag(tag, field: "reply", in: container) }
        value = try TransferEnvelopeV1(
            decodingFieldsFrom: decoder,
            maximumPartBytes: TransferEnvelopeV1.maxJSONPartBytes
        )
    }
}

private struct RuntimeStreamTransferPartV1: Decodable {
    let value: TransferEnvelopeV1

    init(from decoder: Decoder) throws {
        try rejectUnknownKeys(
            decoder,
            allowed: [
                "stream", "transferId", "partIndex", "partCount", "totalSha256", "totalBytes",
                "part",
            ]
        )
        let container = try decoder.container(keyedBy: RuntimeV1CodingKey.self)
        let tag = try container.decode(String.self, forKey: key("stream"))
        guard tag == "transferPart" else { throw invalidTag(tag, field: "stream", in: container) }
        value = try TransferEnvelopeV1(
            decodingFieldsFrom: decoder,
            maximumPartBytes: TransferEnvelopeV1.maxJSONPartBytes
        )
    }
}

public enum RuntimeTransferChannelV1: UInt8, Sendable {
    case reply = 0
    case stream = 1
}

public struct RuntimeTransferCarrierV1: Sendable {
    public static let maxBytes = 4 * 1024 * 1024
    public let runtimeVersion: UInt16
    public let messageID: RuntimeMessageID
    public let channel: RuntimeTransferChannelV1
    public let transfer: TransferEnvelopeV1

    public init(
        messageID: RuntimeMessageID,
        channel: RuntimeTransferChannelV1,
        transfer: TransferEnvelopeV1
    ) {
        runtimeVersion = runtimeProtocolVersionV1
        self.messageID = messageID
        self.channel = channel
        self.transfer = transfer
    }

    fileprivate init(
        runtimeVersion: UInt16,
        messageID: RuntimeMessageID,
        channel: RuntimeTransferChannelV1,
        transfer: TransferEnvelopeV1
    ) {
        self.runtimeVersion = runtimeVersion
        self.messageID = messageID
        self.channel = channel
        self.transfer = transfer
    }
}

// MARK: - Actual JSON entry points

public enum RuntimeV1WireCodec {
    public static let maxRequestBytes = 1024 * 1024
    public static let maxJSONFrameBytes = 1024 * 1024

    public static func decodeEnvelope(_ data: Data) throws -> RuntimeEnvelopeV1 {
        guard data.count < maxJSONFrameBytes else { throw RuntimeV1MirrorError.frameTooLarge }
        let value = try JSONDecoder().decode(RuntimeEnvelopeV1.self, from: data)
        if case .request = value.body, data.count >= maxRequestBytes {
            throw RuntimeV1MirrorError.frameTooLarge
        }
        return value
    }

    public static func decodeTransferEnvelope(_ data: Data) throws -> TransferEnvelopeV1 {
        guard data.count < maxJSONFrameBytes else { throw RuntimeV1MirrorError.frameTooLarge }
        return try JSONDecoder().decode(TransferEnvelopeV1.self, from: data)
    }

    public static func encode(_ value: RuntimeEnvelopeV1) throws -> Data {
        let data = try JSONEncoder().encode(value)
        guard data.count < maxJSONFrameBytes else { throw RuntimeV1MirrorError.frameTooLarge }
        if case .request = value.body, data.count >= maxRequestBytes {
            throw RuntimeV1MirrorError.frameTooLarge
        }
        return data
    }

    public static func encode(_ value: TransferEnvelopeV1) throws -> Data {
        let data = try JSONEncoder().encode(value)
        guard data.count < maxJSONFrameBytes else { throw RuntimeV1MirrorError.frameTooLarge }
        return data
    }

    public static func decodeTransferCarrier(_ data: Data) throws -> RuntimeTransferCarrierV1 {
        guard data.count < RuntimeTransferCarrierV1.maxBytes else {
            throw RuntimeV1MirrorError.transferTooLarge
        }
        var reader = RuntimeTransferCarrierReader(data: data)
        guard try reader.take(5) == Data("ADRT1".utf8) else {
            throw RuntimeV1MirrorError.invalidTransferCarrier
        }
        let version = try reader.readUInt16()
        guard version == runtimeProtocolVersionV1 else {
            throw RuntimeV1MirrorError.invalidTransferCarrier
        }
        guard let channel = RuntimeTransferChannelV1(rawValue: try reader.readUInt8()) else {
            throw RuntimeV1MirrorError.invalidTransferCarrier
        }
        let messageID = try reader.readUTF8UInt16()
        let transferID = try reader.readUTF8UInt16()
        guard !messageID.isEmpty,
              !transferID.isEmpty,
              messageID.utf8.count <= RuntimeMessageIDKind.maximumWireUTF8Bytes!,
              transferID.utf8.count <= RuntimeTransferIDKind.maximumWireUTF8Bytes!
        else {
            throw RuntimeV1MirrorError.invalidTransferCarrier
        }
        let partIndex = try reader.readUInt32()
        let partCount = try reader.readUInt32()
        let totalSHA256 = try reader.take(32)
        let totalBytes = try reader.readUInt64()
        let partLength = Int(try reader.readUInt32())
        let part = try reader.take(partLength)
        guard reader.isAtEnd else { throw RuntimeV1MirrorError.invalidTransferCarrier }
        let transfer = try TransferEnvelopeV1(
            transferID: RuntimeTransferID(rawValue: transferID),
            partIndex: partIndex,
            partCount: partCount,
            totalSHA256: totalSHA256,
            totalBytes: totalBytes,
            part: part,
            maximumPartBytes: TransferEnvelopeV1.maxRemotePartBytes
        )
        return RuntimeTransferCarrierV1(
            runtimeVersion: version,
            messageID: RuntimeMessageID(rawValue: messageID),
            channel: channel,
            transfer: transfer
        )
    }

    public static func encode(_ value: RuntimeTransferCarrierV1) throws -> Data {
        guard value.runtimeVersion == runtimeProtocolVersionV1 else {
            throw RuntimeV1MirrorError.invalidTransferCarrier
        }
        try value.transfer.validate(
            maximumPartBytes: TransferEnvelopeV1.maxRemotePartBytes,
            codingPath: []
        )
        let message = Data(value.messageID.rawValue.utf8)
        let transferID = Data(value.transfer.transferID.rawValue.utf8)
        guard !message.isEmpty,
              !transferID.isEmpty,
              message.count <= RuntimeMessageIDKind.maximumWireUTF8Bytes!,
              transferID.count <= RuntimeTransferIDKind.maximumWireUTF8Bytes!,
              value.transfer.part.count <= Int(UInt32.max)
        else {
            throw RuntimeV1MirrorError.invalidTransferCarrier
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
        guard data.count < RuntimeTransferCarrierV1.maxBytes else {
            throw RuntimeV1MirrorError.transferTooLarge
        }
        return data
    }

    private static func appendBigEndian<T: FixedWidthInteger>(_ value: T, to data: inout Data) {
        var bigEndian = value.bigEndian
        withUnsafeBytes(of: &bigEndian) { data.append(contentsOf: $0) }
    }
}

private struct RuntimeTransferCarrierReader {
    let data: Data
    var offset = 0

    var isAtEnd: Bool { offset == data.count }

    mutating func take(_ count: Int) throws -> Data {
        guard count >= 0, offset <= data.count, count <= data.count - offset else {
            throw RuntimeV1MirrorError.invalidTransferCarrier
        }
        defer { offset += count }
        return data.subdata(in: offset..<(offset + count))
    }

    mutating func readUInt8() throws -> UInt8 {
        guard let value = try take(1).first else {
            throw RuntimeV1MirrorError.invalidTransferCarrier
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
            throw RuntimeV1MirrorError.invalidTransferCarrier
        }
        return value
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
