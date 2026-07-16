import Foundation

// Runtime v2 catalog、vendor-panel 与 canonical event mirror。
// 稳定 leaf 继续复用 RuntimeWireTypes.swift；本文件只收紧 v2 changed stream DTO。

public enum RuntimeV2StreamMirrorError: Error, Equatable, Sendable {
    case catalogTooLarge
    case invalidEventIdentity
}

// MARK: - Catalog

public struct RuntimeConversationEntryV2: Codable, Sendable {
    public let conversationID: RuntimeConversationID
    public let agentKind: AgentKind
    public let title: String?
    public let cwd: String?
    public let lastActiveMs: UInt64
    public let archived: Bool
    public let entryRevision: UInt64

    public init(
        conversationID: RuntimeConversationID,
        agentKind: AgentKind,
        title: String?,
        cwd: String?,
        lastActiveMs: UInt64,
        archived: Bool,
        entryRevision: UInt64
    ) {
        self.conversationID = conversationID
        self.agentKind = agentKind
        self.title = title
        self.cwd = cwd
        self.lastActiveMs = lastActiveMs
        self.archived = archived
        self.entryRevision = entryRevision
    }

    public init(from decoder: Decoder) throws {
        try runtimeV2RejectUnknownKeys(decoder, allowed: Self.wireKeys)
        let container = try decoder.container(keyedBy: RuntimeV2CodingKey.self)
        self.init(
            conversationID: try container.decode(
                RuntimeConversationID.self,
                forKey: runtimeV2Key("conversationId")
            ),
            agentKind: try container.decode(AgentKind.self, forKey: runtimeV2Key("agentKind")),
            title: try container.decodeIfPresent(String.self, forKey: runtimeV2Key("title")),
            cwd: try container.decodeIfPresent(String.self, forKey: runtimeV2Key("cwd")),
            lastActiveMs: try container.decode(UInt64.self, forKey: runtimeV2Key("lastActiveMs")),
            archived: try container.decode(Bool.self, forKey: runtimeV2Key("archived")),
            entryRevision: try container.decode(UInt64.self, forKey: runtimeV2Key("entryRevision"))
        )
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: RuntimeV2CodingKey.self)
        try container.encode(conversationID, forKey: runtimeV2Key("conversationId"))
        try container.encode(agentKind, forKey: runtimeV2Key("agentKind"))
        try container.encode(title, forKey: runtimeV2Key("title"))
        try container.encode(cwd, forKey: runtimeV2Key("cwd"))
        try container.encode(lastActiveMs, forKey: runtimeV2Key("lastActiveMs"))
        try container.encode(archived, forKey: runtimeV2Key("archived"))
        try container.encode(entryRevision, forKey: runtimeV2Key("entryRevision"))
    }

    private static let wireKeys: Set<String> = [
        "conversationId", "agentKind", "title", "cwd", "lastActiveMs", "archived",
        "entryRevision",
    ]
}

public enum RuntimeCatalogChangeV2: Codable, Sendable {
    case upserted(entry: RuntimeConversationEntryV2)
    case removed(conversationID: RuntimeConversationID)

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: RuntimeV2CodingKey.self)
        let kind = try container.decode(String.self, forKey: runtimeV2Key("kind"))
        switch kind {
        case "upserted":
            try runtimeV2RejectUnknownKeys(decoder, allowed: ["kind", "entry"])
            self = .upserted(
                entry: try container.decode(
                    RuntimeConversationEntryV2.self,
                    forKey: runtimeV2Key("entry")
                )
            )
        case "removed":
            try runtimeV2RejectUnknownKeys(decoder, allowed: ["kind", "conversation_id"])
            self = .removed(
                conversationID: try container.decode(
                    RuntimeConversationID.self,
                    forKey: runtimeV2Key("conversation_id")
                )
            )
        default:
            throw DecodingError.dataCorruptedError(
                forKey: runtimeV2Key("kind"),
                in: container,
                debugDescription: "unknown Runtime v2 catalog change kind \(kind)"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: RuntimeV2CodingKey.self)
        switch self {
        case .upserted(let entry):
            try container.encode("upserted", forKey: runtimeV2Key("kind"))
            try container.encode(entry, forKey: runtimeV2Key("entry"))
        case .removed(let conversationID):
            try container.encode("removed", forKey: runtimeV2Key("kind"))
            try container.encode(conversationID, forKey: runtimeV2Key("conversation_id"))
        }
    }
}

public struct RuntimeCatalogDeltaV2: RuntimeV2FlattenedPayload {
    public let catalogRevision: UInt64
    public let changes: [RuntimeCatalogChangeV2]

    public init(catalogRevision: UInt64, changes: [RuntimeCatalogChangeV2]) {
        self.catalogRevision = catalogRevision
        self.changes = changes
    }

    public init(from decoder: Decoder) throws {
        try self.init(decodingFieldsFrom: decoder, allowed: Self.wireKeys)
    }

    init(flattenedFrom decoder: Decoder) throws {
        try runtimeV2ValidateDiscriminator(decoder, key: "stream", expected: "catalogDelta")
        try self.init(decodingFieldsFrom: decoder, allowed: Self.wireKeys.union(["stream"]))
    }

    private init(decodingFieldsFrom decoder: Decoder, allowed: Set<String>) throws {
        try runtimeV2RejectUnknownKeys(decoder, allowed: allowed)
        let container = try decoder.container(keyedBy: RuntimeV2CodingKey.self)
        self.init(
            catalogRevision: try container.decode(
                UInt64.self,
                forKey: runtimeV2Key("catalogRevision")
            ),
            changes: try container.decode(
                [RuntimeCatalogChangeV2].self,
                forKey: runtimeV2Key("changes")
            )
        )
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: RuntimeV2CodingKey.self)
        try encodeFields(into: &container)
    }

    func encodeFlattenedFields(
        into container: inout KeyedEncodingContainer<RuntimeV2CodingKey>
    ) throws {
        try container.encode("catalogDelta", forKey: runtimeV2Key("stream"))
        try encodeFields(into: &container)
    }

    private func encodeFields(
        into container: inout KeyedEncodingContainer<RuntimeV2CodingKey>
    ) throws {
        try container.encode(catalogRevision, forKey: runtimeV2Key("catalogRevision"))
        try container.encode(changes, forKey: runtimeV2Key("changes"))
    }

    private static let wireKeys: Set<String> = ["catalogRevision", "changes"]
}

public struct RuntimeCatalogSnapshotV2: RuntimeV2FlattenedPayload {
    public static let maxEntries = 500
    public static let maxEncodedBytes = 64 * 1024 * 1024

    public let baseCatalogCursor: RuntimeStreamCursorV1
    public let entries: [RuntimeConversationEntryV2]
    public let nextPageCursor: RuntimeCatalogPageCursor?

    public init(
        baseCatalogCursor: RuntimeStreamCursorV1,
        entries: [RuntimeConversationEntryV2],
        nextPageCursor: RuntimeCatalogPageCursor?
    ) throws {
        self.baseCatalogCursor = baseCatalogCursor
        self.entries = entries
        self.nextPageCursor = nextPageCursor
        try validate()
    }

    public init(from decoder: Decoder) throws {
        try self.init(decodingFieldsFrom: decoder, allowed: Self.wireKeys)
    }

    init(flattenedFrom decoder: Decoder) throws {
        try runtimeV2ValidateDiscriminator(decoder, key: "reply", expected: "catalog")
        try self.init(decodingFieldsFrom: decoder, allowed: Self.wireKeys.union(["reply"]))
    }

    private init(decodingFieldsFrom decoder: Decoder, allowed: Set<String>) throws {
        try runtimeV2RejectUnknownKeys(decoder, allowed: allowed)
        let container = try decoder.container(keyedBy: RuntimeV2CodingKey.self)
        try self.init(
            baseCatalogCursor: container.decode(
                RuntimeStreamCursorV1.self,
                forKey: runtimeV2Key("baseCatalogCursor")
            ),
            entries: container.decode(
                [RuntimeConversationEntryV2].self,
                forKey: runtimeV2Key("entries")
            ),
            nextPageCursor: runtimeV2DecodeRequiredNullable(
                RuntimeCatalogPageCursor.self,
                from: container,
                forKey: runtimeV2Key("nextPageCursor")
            )
        )
    }

    public func encode(to encoder: Encoder) throws {
        try validate()
        var container = encoder.container(keyedBy: RuntimeV2CodingKey.self)
        try encodeUncheckedFields(into: &container)
    }

    func encodeFlattenedFields(
        into container: inout KeyedEncodingContainer<RuntimeV2CodingKey>
    ) throws {
        try validate()
        try container.encode("catalog", forKey: runtimeV2Key("reply"))
        try encodeUncheckedFields(into: &container)
    }

    fileprivate func encodeUncheckedFields(
        into container: inout KeyedEncodingContainer<RuntimeV2CodingKey>
    ) throws {
        try container.encode(baseCatalogCursor, forKey: runtimeV2Key("baseCatalogCursor"))
        try container.encode(entries, forKey: runtimeV2Key("entries"))
        try container.encode(nextPageCursor, forKey: runtimeV2Key("nextPageCursor"))
    }

    private func validate() throws {
        guard entries.count <= Self.maxEntries else {
            throw RuntimeV2StreamMirrorError.catalogTooLarge
        }
        let bytes = try JSONEncoder().encode(RuntimeV2CatalogSnapshotSizeProbe(value: self)).count
        guard bytes <= Self.maxEncodedBytes else {
            throw RuntimeV2StreamMirrorError.catalogTooLarge
        }
    }

    private static let wireKeys: Set<String> = [
        "baseCatalogCursor", "entries", "nextPageCursor",
    ]
}

private struct RuntimeV2CatalogSnapshotSizeProbe: Encodable {
    let value: RuntimeCatalogSnapshotV2

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: RuntimeV2CodingKey.self)
        try value.encodeUncheckedFields(into: &container)
    }
}

// MARK: - Strict vendor panel

public enum RuntimeCodexVendorPanelEventV2: Codable, Sendable {
    case placeholder

    public init(from decoder: Decoder) throws {
        try runtimeV2RejectUnknownKeys(decoder, allowed: ["kind"])
        let container = try decoder.container(keyedBy: RuntimeV2CodingKey.self)
        let kind = try container.decode(String.self, forKey: runtimeV2Key("kind"))
        guard kind == "placeholder" else {
            throw DecodingError.dataCorruptedError(
                forKey: runtimeV2Key("kind"),
                in: container,
                debugDescription: "unknown Runtime v2 Codex panel event kind \(kind)"
            )
        }
        self = .placeholder
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: RuntimeV2CodingKey.self)
        try container.encode("placeholder", forKey: runtimeV2Key("kind"))
    }
}

public enum RuntimeClaudeCodeVendorPanelEventV2: Codable, Sendable {
    case hookFired(matcher: String, toolUseId: String?, elapsedMs: UInt64?)
    case systemStatus(
        subtype: String,
        status: String?,
        message: String?,
        attempt: UInt64?,
        error: String?,
        errorStatus: UInt64?,
        maxRetries: UInt64?,
        retryDelayMs: Double?
    )

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: RuntimeV2CodingKey.self)
        let kind = try container.decode(String.self, forKey: runtimeV2Key("kind"))
        switch kind {
        case "hookFired":
            try runtimeV2RejectUnknownKeys(
                decoder,
                allowed: ["kind", "matcher", "toolUseId", "elapsedMs"]
            )
            self = .hookFired(
                matcher: try container.decode(String.self, forKey: runtimeV2Key("matcher")),
                toolUseId: try container.decodeIfPresent(
                    String.self,
                    forKey: runtimeV2Key("toolUseId")
                ),
                elapsedMs: try container.decodeIfPresent(
                    UInt64.self,
                    forKey: runtimeV2Key("elapsedMs")
                )
            )
        case "systemStatus":
            try runtimeV2RejectUnknownKeys(
                decoder,
                allowed: [
                    "kind", "subtype", "status", "message", "attempt", "error",
                    "errorStatus", "maxRetries", "retryDelayMs",
                ]
            )
            self = .systemStatus(
                subtype: try container.decode(String.self, forKey: runtimeV2Key("subtype")),
                status: try container.decodeIfPresent(String.self, forKey: runtimeV2Key("status")),
                message: try container.decodeIfPresent(String.self, forKey: runtimeV2Key("message")),
                attempt: try container.decodeIfPresent(UInt64.self, forKey: runtimeV2Key("attempt")),
                error: try container.decodeIfPresent(String.self, forKey: runtimeV2Key("error")),
                errorStatus: try container.decodeIfPresent(
                    UInt64.self,
                    forKey: runtimeV2Key("errorStatus")
                ),
                maxRetries: try container.decodeIfPresent(
                    UInt64.self,
                    forKey: runtimeV2Key("maxRetries")
                ),
                retryDelayMs: try container.decodeIfPresent(
                    Double.self,
                    forKey: runtimeV2Key("retryDelayMs")
                )
            )
        default:
            throw DecodingError.dataCorruptedError(
                forKey: runtimeV2Key("kind"),
                in: container,
                debugDescription: "unknown Runtime v2 Claude Code panel event kind \(kind)"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: RuntimeV2CodingKey.self)
        switch self {
        case .hookFired(let matcher, let toolUseId, let elapsedMs):
            try container.encode("hookFired", forKey: runtimeV2Key("kind"))
            try container.encode(matcher, forKey: runtimeV2Key("matcher"))
            try container.encode(toolUseId, forKey: runtimeV2Key("toolUseId"))
            try container.encode(elapsedMs, forKey: runtimeV2Key("elapsedMs"))
        case .systemStatus(
            let subtype,
            let status,
            let message,
            let attempt,
            let error,
            let errorStatus,
            let maxRetries,
            let retryDelayMs
        ):
            try container.encode("systemStatus", forKey: runtimeV2Key("kind"))
            try container.encode(subtype, forKey: runtimeV2Key("subtype"))
            try container.encode(status, forKey: runtimeV2Key("status"))
            try container.encode(message, forKey: runtimeV2Key("message"))
            try container.encode(attempt, forKey: runtimeV2Key("attempt"))
            try container.encode(error, forKey: runtimeV2Key("error"))
            try container.encode(errorStatus, forKey: runtimeV2Key("errorStatus"))
            try container.encode(maxRetries, forKey: runtimeV2Key("maxRetries"))
            try container.encode(retryDelayMs, forKey: runtimeV2Key("retryDelayMs"))
        }
    }
}

public enum RuntimeVendorPanelPayloadV2: Codable, Sendable {
    case codex(RuntimeCodexVendorPanelEventV2)
    case claudeCode(RuntimeClaudeCodeVendorPanelEventV2)

    public var agentKind: AgentKind {
        switch self {
        case .codex: .codex
        case .claudeCode: .claudeCode
        }
    }

    public init(from decoder: Decoder) throws {
        try runtimeV2RejectUnknownKeys(decoder, allowed: ["agentKind", "event"])
        let container = try decoder.container(keyedBy: RuntimeV2CodingKey.self)
        switch try container.decode(AgentKind.self, forKey: runtimeV2Key("agentKind")) {
        case .codex:
            self = .codex(
                try container.decode(
                    RuntimeCodexVendorPanelEventV2.self,
                    forKey: runtimeV2Key("event")
                )
            )
        case .claudeCode:
            self = .claudeCode(
                try container.decode(
                    RuntimeClaudeCodeVendorPanelEventV2.self,
                    forKey: runtimeV2Key("event")
                )
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: RuntimeV2CodingKey.self)
        try container.encode(agentKind, forKey: runtimeV2Key("agentKind"))
        switch self {
        case .codex(let event):
            try container.encode(event, forKey: runtimeV2Key("event"))
        case .claudeCode(let event):
            try container.encode(event, forKey: runtimeV2Key("event"))
        }
    }
}

// MARK: - Canonical events

public enum RuntimeEventBodyV2: Codable, Sendable {
    case capabilities(RuntimeSessionCapabilitiesV1)
    case configurationChanged(RuntimeConversationConfigurationStateV2)
    case vendorPanelEvent(RuntimeVendorPanelPayloadV2)
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
        let container = try decoder.container(keyedBy: RuntimeV2CodingKey.self)
        let kind = try container.decode(String.self, forKey: runtimeV2Key("kind"))
        switch kind {
        case "capabilities":
            try runtimeV2RejectUnknownKeys(decoder, allowed: ["kind", "capabilities"])
            self = .capabilities(
                try container.decode(
                    RuntimeSessionCapabilitiesV1.self,
                    forKey: runtimeV2Key("capabilities")
                )
            )
        case "configurationChanged":
            try runtimeV2RejectUnknownKeys(decoder, allowed: ["kind", "state"])
            self = .configurationChanged(
                try container.decode(
                    RuntimeConversationConfigurationStateV2.self,
                    forKey: runtimeV2Key("state")
                )
            )
        case "vendorPanelEvent":
            try runtimeV2RejectUnknownKeys(decoder, allowed: ["kind", "vendorPanel"])
            self = .vendorPanelEvent(
                try container.decode(
                    RuntimeVendorPanelPayloadV2.self,
                    forKey: runtimeV2Key("vendorPanel")
                )
            )
        case "item":
            try runtimeV2RejectUnknownKeys(decoder, allowed: ["kind", "item"])
            self = .item(
                try container.decode(RuntimeAgentItemV1.self, forKey: runtimeV2Key("item"))
            )
        case "turnStarted":
            try runtimeV2RejectUnknownKeys(decoder, allowed: ["kind", "turn_id"])
            self = .turnStarted(
                turnID: try container.decode(RuntimeTurnID.self, forKey: runtimeV2Key("turn_id"))
            )
        case "actionRequest":
            try runtimeV2RejectUnknownKeys(
                decoder,
                allowed: ["kind", "turn_id", "approval_id", "request"]
            )
            self = .actionRequest(
                turnID: try container.decode(RuntimeTurnID.self, forKey: runtimeV2Key("turn_id")),
                approvalID: try container.decode(
                    RuntimeApprovalID.self,
                    forKey: runtimeV2Key("approval_id")
                ),
                request: try container.decode(
                    RuntimeActionRequestV1.self,
                    forKey: runtimeV2Key("request")
                )
            )
        case "approvalResolved":
            try runtimeV2RejectUnknownKeys(
                decoder,
                allowed: ["kind", "turn_id", "approval_id", "decision", "state"]
            )
            self = .approvalResolved(
                turnID: try container.decode(RuntimeTurnID.self, forKey: runtimeV2Key("turn_id")),
                approvalID: try container.decode(
                    RuntimeApprovalID.self,
                    forKey: runtimeV2Key("approval_id")
                ),
                decision: try runtimeV2DecodeRequiredNullable(
                    ActionDecisionKind.self,
                    from: container,
                    forKey: runtimeV2Key("decision")
                ),
                state: try container.decode(
                    ApprovalDeliveryStateV1.self,
                    forKey: runtimeV2Key("state")
                )
            )
        case "turnCompleted":
            try runtimeV2RejectUnknownKeys(decoder, allowed: ["kind", "turn_id", "summary"])
            self = .turnCompleted(
                turnID: try container.decode(RuntimeTurnID.self, forKey: runtimeV2Key("turn_id")),
                summary: try container.decode(
                    RuntimeTurnSummaryV1.self,
                    forKey: runtimeV2Key("summary")
                )
            )
        case "turnInterrupted":
            try runtimeV2RejectUnknownKeys(decoder, allowed: ["kind", "turn_id"])
            self = .turnInterrupted(
                turnID: try container.decode(RuntimeTurnID.self, forKey: runtimeV2Key("turn_id"))
            )
        case "error":
            try runtimeV2RejectUnknownKeys(decoder, allowed: ["kind", "failure"])
            self = .error(
                try container.decode(RuntimeFailureV1.self, forKey: runtimeV2Key("failure"))
            )
        default:
            throw DecodingError.dataCorruptedError(
                forKey: runtimeV2Key("kind"),
                in: container,
                debugDescription: "unknown Runtime v2 event body kind \(kind)"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: RuntimeV2CodingKey.self)
        switch self {
        case .capabilities(let capabilities):
            try container.encode("capabilities", forKey: runtimeV2Key("kind"))
            try container.encode(capabilities, forKey: runtimeV2Key("capabilities"))
        case .configurationChanged(let state):
            try container.encode("configurationChanged", forKey: runtimeV2Key("kind"))
            try container.encode(state, forKey: runtimeV2Key("state"))
        case .vendorPanelEvent(let panel):
            try container.encode("vendorPanelEvent", forKey: runtimeV2Key("kind"))
            try container.encode(panel, forKey: runtimeV2Key("vendorPanel"))
        case .item(let item):
            try container.encode("item", forKey: runtimeV2Key("kind"))
            try container.encode(item, forKey: runtimeV2Key("item"))
        case .turnStarted(let turnID):
            try container.encode("turnStarted", forKey: runtimeV2Key("kind"))
            try container.encode(turnID, forKey: runtimeV2Key("turn_id"))
        case .actionRequest(let turnID, let approvalID, let request):
            try container.encode("actionRequest", forKey: runtimeV2Key("kind"))
            try container.encode(turnID, forKey: runtimeV2Key("turn_id"))
            try container.encode(approvalID, forKey: runtimeV2Key("approval_id"))
            try container.encode(request, forKey: runtimeV2Key("request"))
        case .approvalResolved(let turnID, let approvalID, let decision, let state):
            try container.encode("approvalResolved", forKey: runtimeV2Key("kind"))
            try container.encode(turnID, forKey: runtimeV2Key("turn_id"))
            try container.encode(approvalID, forKey: runtimeV2Key("approval_id"))
            try container.encode(decision, forKey: runtimeV2Key("decision"))
            try container.encode(state, forKey: runtimeV2Key("state"))
        case .turnCompleted(let turnID, let summary):
            try container.encode("turnCompleted", forKey: runtimeV2Key("kind"))
            try container.encode(turnID, forKey: runtimeV2Key("turn_id"))
            try container.encode(summary, forKey: runtimeV2Key("summary"))
        case .turnInterrupted(let turnID):
            try container.encode("turnInterrupted", forKey: runtimeV2Key("kind"))
            try container.encode(turnID, forKey: runtimeV2Key("turn_id"))
        case .error(let failure):
            try container.encode("error", forKey: runtimeV2Key("kind"))
            try container.encode(failure, forKey: runtimeV2Key("failure"))
        }
    }
}

public struct RuntimeEventV2: RuntimeV2FlattenedPayload {
    public let conversationID: RuntimeConversationID
    public let eventID: RuntimeEventID
    public let eventSeq: UInt64
    public let commandID: RuntimeCommandID?
    public let itemID: RuntimeItemID?
    public let entityID: RuntimeEntityID?
    public let body: RuntimeEventBodyV2

    public init(
        conversationID: RuntimeConversationID,
        eventID: RuntimeEventID,
        eventSeq: UInt64,
        commandID: RuntimeCommandID?,
        itemID: RuntimeItemID?,
        entityID: RuntimeEntityID?,
        body: RuntimeEventBodyV2
    ) throws {
        self.conversationID = conversationID
        self.eventID = eventID
        self.eventSeq = eventSeq
        self.commandID = commandID
        self.itemID = itemID
        self.entityID = entityID
        self.body = body
        try validate()
    }

    public init(from decoder: Decoder) throws {
        try self.init(decodingFieldsFrom: decoder, allowed: Self.wireKeys)
    }

    init(flattenedFrom decoder: Decoder) throws {
        try runtimeV2ValidateDiscriminator(decoder, key: "stream", expected: "event")
        try self.init(decodingFieldsFrom: decoder, allowed: Self.wireKeys.union(["stream"]))
    }

    private init(decodingFieldsFrom decoder: Decoder, allowed: Set<String>) throws {
        try runtimeV2RejectUnknownKeys(decoder, allowed: allowed)
        let container = try decoder.container(keyedBy: RuntimeV2CodingKey.self)
        try self.init(
            conversationID: container.decode(
                RuntimeConversationID.self,
                forKey: runtimeV2Key("conversationId")
            ),
            eventID: container.decode(RuntimeEventID.self, forKey: runtimeV2Key("eventId")),
            eventSeq: container.decode(UInt64.self, forKey: runtimeV2Key("eventSeq")),
            commandID: runtimeV2DecodeRequiredNullable(
                RuntimeCommandID.self,
                from: container,
                forKey: runtimeV2Key("commandId")
            ),
            itemID: runtimeV2DecodeRequiredNullable(
                RuntimeItemID.self,
                from: container,
                forKey: runtimeV2Key("itemId")
            ),
            entityID: runtimeV2DecodeRequiredNullable(
                RuntimeEntityID.self,
                from: container,
                forKey: runtimeV2Key("entityId")
            ),
            body: container.decode(RuntimeEventBodyV2.self, forKey: runtimeV2Key("body"))
        )
    }

    public func encode(to encoder: Encoder) throws {
        try validate()
        var container = encoder.container(keyedBy: RuntimeV2CodingKey.self)
        try encodeFields(into: &container)
    }

    func encodeFlattenedFields(
        into container: inout KeyedEncodingContainer<RuntimeV2CodingKey>
    ) throws {
        try validate()
        try container.encode("event", forKey: runtimeV2Key("stream"))
        try encodeFields(into: &container)
    }

    private func encodeFields(
        into container: inout KeyedEncodingContainer<RuntimeV2CodingKey>
    ) throws {
        try container.encode(conversationID, forKey: runtimeV2Key("conversationId"))
        try container.encode(eventID, forKey: runtimeV2Key("eventId"))
        try container.encode(eventSeq, forKey: runtimeV2Key("eventSeq"))
        try container.encode(commandID, forKey: runtimeV2Key("commandId"))
        try container.encode(itemID, forKey: runtimeV2Key("itemId"))
        try container.encode(entityID, forKey: runtimeV2Key("entityId"))
        try container.encode(body, forKey: runtimeV2Key("body"))
    }

    private func validate() throws {
        let hasItemIdentity = itemID != nil && entityID != nil
        let hasNoItemIdentity = itemID == nil && entityID == nil
        let valid: Bool
        switch body {
        case .capabilities, .configurationChanged, .vendorPanelEvent:
            valid = commandID == nil && hasNoItemIdentity
        case .item(let item):
            let isUserMessage: Bool
            if case .userMessage = item {
                isUserMessage = true
            } else {
                isUserMessage = false
            }
            valid = hasItemIdentity && (!isUserMessage || commandID != nil)
        case .turnStarted, .actionRequest, .approvalResolved, .turnCompleted, .turnInterrupted:
            valid = commandID != nil && hasNoItemIdentity
        case .error:
            valid = hasNoItemIdentity
        }
        guard valid else {
            throw RuntimeV2StreamMirrorError.invalidEventIdentity
        }
    }

    private static let wireKeys: Set<String> = [
        "conversationId", "eventId", "eventSeq", "commandId", "itemId", "entityId", "body",
    ]
}
