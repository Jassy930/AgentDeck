import Foundation

// Runtime v2 changed DTO。稳定且 wire 未变化的 leaf 继续复用 RuntimeWireTypes.swift；
// 本文件只提供严格的 v2 configuration/metadata/upgrade/receipt mirror。

public enum RuntimeV2MirrorError: Error, Equatable, Sendable {
    case invalidConfigurationText
    case invalidConfigurationState
    case invalidAgentDescription
    case tooManyAgentDescriptions
    case duplicateAgentDescription
    case invalidMetadataTitle
    case invalidRevision
    case invalidArtifactSHA256
    case invalidTargetVersion
    case invalidActiveTurns
}

struct RuntimeV2CodingKey: CodingKey, Hashable {
    let stringValue: String
    let intValue: Int? = nil

    init(_ stringValue: String) {
        self.stringValue = stringValue
    }

    init?(stringValue: String) {
        self.init(stringValue)
    }

    init?(intValue: Int) {
        return nil
    }
}

func runtimeV2Key(_ value: String) -> RuntimeV2CodingKey {
    RuntimeV2CodingKey(value)
}

func runtimeV2RejectUnknownKeys(_ decoder: Decoder, allowed: Set<String>) throws {
    let container = try decoder.container(keyedBy: RuntimeV2CodingKey.self)
    if let unknown = container.allKeys.first(where: { !allowed.contains($0.stringValue) }) {
        throw DecodingError.dataCorruptedError(
            forKey: unknown,
            in: container,
            debugDescription: "unknown Runtime v2 field \(unknown.stringValue)"
        )
    }
}

func runtimeV2DecodeRequiredNullable<T: Decodable>(
    _ type: T.Type,
    from container: KeyedDecodingContainer<RuntimeV2CodingKey>,
    forKey key: RuntimeV2CodingKey
) throws -> T? {
    guard container.contains(key) else {
        throw DecodingError.keyNotFound(
            key,
            .init(codingPath: container.codingPath, debugDescription: "required nullable field")
        )
    }
    return try container.decodeIfPresent(type, forKey: key)
}

protocol RuntimeV2FlattenedPayload: Codable, Sendable {
    init(flattenedFrom decoder: Decoder) throws
    func encodeFlattenedFields(
        into container: inout KeyedEncodingContainer<RuntimeV2CodingKey>
    ) throws
}

func runtimeV2ValidateDiscriminator(
    _ decoder: Decoder,
    key: String,
    expected: String
) throws {
    let container = try decoder.container(keyedBy: RuntimeV2CodingKey.self)
    let received = try container.decode(String.self, forKey: runtimeV2Key(key))
    guard received == expected else {
        throw DecodingError.dataCorruptedError(
            forKey: runtimeV2Key(key),
            in: container,
            debugDescription: "unexpected Runtime v2 discriminator \(received)"
        )
    }
}

private func runtimeV2ValidateConfigurationText(_ value: String?) throws {
    guard let value else { return }
    guard !value.isEmpty, value.utf8.count <= 1024, !value.utf8.contains(0) else {
        throw RuntimeV2MirrorError.invalidConfigurationText
    }
}

private func runtimeV2ValidateTitle(_ value: String?) throws {
    guard let value else { return }
    guard value.utf8.count <= 4096, !value.utf8.contains(0) else {
        throw RuntimeV2MirrorError.invalidMetadataTitle
    }
}

private func runtimeV2RequireNonzeroRevision(_ value: UInt64) throws {
    guard value > 0 else { throw RuntimeV2MirrorError.invalidRevision }
}

// MARK: - Configuration

public struct RuntimeCodexConversationConfigurationV2: Codable, Sendable {
    public let approvalPolicy: CodexApprovalPolicy
    public let sandbox: CodexSandboxMode
    public let reasoningEffort: CodexReasoningEffort

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case approvalPolicy, sandbox, reasoningEffort
    }

    public init(
        approvalPolicy: CodexApprovalPolicy,
        sandbox: CodexSandboxMode,
        reasoningEffort: CodexReasoningEffort
    ) {
        self.approvalPolicy = approvalPolicy
        self.sandbox = sandbox
        self.reasoningEffort = reasoningEffort
    }

    public init(from decoder: Decoder) throws {
        try runtimeV2RejectUnknownKeys(
            decoder,
            allowed: Set(CodingKeys.allCases.map(\.rawValue))
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        approvalPolicy = try container.decode(CodexApprovalPolicy.self, forKey: .approvalPolicy)
        sandbox = try container.decode(CodexSandboxMode.self, forKey: .sandbox)
        reasoningEffort = try container.decode(CodexReasoningEffort.self, forKey: .reasoningEffort)
    }
}

public struct RuntimeClaudeCodeConversationConfigurationV2: Codable, Sendable {
    public let permissionMode: ClaudeCodePermissionMode
    public let model: String?
    public let effort: String?
    public let outputStyle: String?

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case permissionMode, model, effort, outputStyle
    }

    public init(
        permissionMode: ClaudeCodePermissionMode,
        model: String?,
        effort: String?,
        outputStyle: String?
    ) throws {
        try runtimeV2ValidateConfigurationText(model)
        try runtimeV2ValidateConfigurationText(effort)
        try runtimeV2ValidateConfigurationText(outputStyle)
        self.permissionMode = permissionMode
        self.model = model
        self.effort = effort
        self.outputStyle = outputStyle
    }

    public init(from decoder: Decoder) throws {
        try runtimeV2RejectUnknownKeys(
            decoder,
            allowed: Set(CodingKeys.allCases.map(\.rawValue))
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            permissionMode: container.decode(ClaudeCodePermissionMode.self, forKey: .permissionMode),
            model: container.decodeIfPresent(String.self, forKey: .model),
            effort: container.decodeIfPresent(String.self, forKey: .effort),
            outputStyle: container.decodeIfPresent(String.self, forKey: .outputStyle)
        )
    }

    public func encode(to encoder: Encoder) throws {
        try runtimeV2ValidateConfigurationText(model)
        try runtimeV2ValidateConfigurationText(effort)
        try runtimeV2ValidateConfigurationText(outputStyle)
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(permissionMode, forKey: .permissionMode)
        try container.encode(model, forKey: .model)
        try container.encode(effort, forKey: .effort)
        try container.encode(outputStyle, forKey: .outputStyle)
    }
}

public enum RuntimeVendorConfigurationSnapshotV2: Codable, Sendable {
    case codex(RuntimeCodexConversationConfigurationV2)
    case claudeCode(RuntimeClaudeCodeConversationConfigurationV2)

    public var agentKind: AgentKind {
        switch self {
        case .codex: .codex
        case .claudeCode: .claudeCode
        }
    }

    public init(from decoder: Decoder) throws {
        try runtimeV2RejectUnknownKeys(decoder, allowed: ["agentKind", "configuration"])
        let container = try decoder.container(keyedBy: RuntimeV2CodingKey.self)
        switch try container.decode(AgentKind.self, forKey: runtimeV2Key("agentKind")) {
        case .codex:
            self = .codex(
                try container.decode(
                    RuntimeCodexConversationConfigurationV2.self,
                    forKey: runtimeV2Key("configuration")
                )
            )
        case .claudeCode:
            self = .claudeCode(
                try container.decode(
                    RuntimeClaudeCodeConversationConfigurationV2.self,
                    forKey: runtimeV2Key("configuration")
                )
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: RuntimeV2CodingKey.self)
        try container.encode(agentKind, forKey: runtimeV2Key("agentKind"))
        switch self {
        case .codex(let value):
            try container.encode(value, forKey: runtimeV2Key("configuration"))
        case .claudeCode(let value):
            try container.encode(value, forKey: runtimeV2Key("configuration"))
        }
    }
}

public struct RuntimeConversationConfigurationV2: Codable, Sendable {
    public let vendorControl: RuntimeVendorConfigurationSnapshotV2
    public var agentKind: AgentKind { vendorControl.agentKind }

    private enum CodingKeys: String, CodingKey, CaseIterable { case vendorControl }

    public init(vendorControl: RuntimeVendorConfigurationSnapshotV2) {
        self.vendorControl = vendorControl
    }

    public init(from decoder: Decoder) throws {
        try runtimeV2RejectUnknownKeys(decoder, allowed: ["vendorControl"])
        let container = try decoder.container(keyedBy: CodingKeys.self)
        vendorControl = try container.decode(
            RuntimeVendorConfigurationSnapshotV2.self,
            forKey: .vendorControl
        )
    }
}

public struct RuntimeConversationConfigurationStateV2: Codable, Sendable {
    public let configurationRevision: UInt64
    public let configuration: RuntimeConversationConfigurationV2?

    public init(
        configurationRevision: UInt64,
        configuration: RuntimeConversationConfigurationV2?
    ) throws {
        guard (configurationRevision == 0) == (configuration == nil) else {
            throw RuntimeV2MirrorError.invalidConfigurationState
        }
        self.configurationRevision = configurationRevision
        self.configuration = configuration
    }

    public init(from decoder: Decoder) throws {
        try runtimeV2RejectUnknownKeys(
            decoder,
            allowed: ["configurationRevision", "configuration"]
        )
        let container = try decoder.container(keyedBy: RuntimeV2CodingKey.self)
        try self.init(
            configurationRevision: container.decode(
                UInt64.self,
                forKey: runtimeV2Key("configurationRevision")
            ),
            configuration: runtimeV2DecodeRequiredNullable(
                RuntimeConversationConfigurationV2.self,
                from: container,
                forKey: runtimeV2Key("configuration")
            )
        )
    }

    public func encode(to encoder: Encoder) throws {
        guard (configurationRevision == 0) == (configuration == nil) else {
            throw RuntimeV2MirrorError.invalidConfigurationState
        }
        var container = encoder.container(keyedBy: RuntimeV2CodingKey.self)
        try container.encode(
            configurationRevision,
            forKey: runtimeV2Key("configurationRevision")
        )
        try container.encode(configuration, forKey: runtimeV2Key("configuration"))
    }
}

public struct RuntimeConfigureConversationRequestV2: RuntimeV2FlattenedPayload {
    public let conversationID: RuntimeConversationID
    public let idempotencyKey: RuntimeIdempotencyKey
    public let expectedConfigurationRevision: UInt64
    public let configuration: RuntimeConversationConfigurationV2

    public init(
        conversationID: RuntimeConversationID,
        idempotencyKey: RuntimeIdempotencyKey,
        expectedConfigurationRevision: UInt64,
        configuration: RuntimeConversationConfigurationV2
    ) {
        self.conversationID = conversationID
        self.idempotencyKey = idempotencyKey
        self.expectedConfigurationRevision = expectedConfigurationRevision
        self.configuration = configuration
    }

    public init(from decoder: Decoder) throws {
        try self.init(decodingFieldsFrom: decoder, allowed: Self.wireKeys)
    }

    init(flattenedFrom decoder: Decoder) throws {
        try runtimeV2ValidateDiscriminator(
            decoder,
            key: "request",
            expected: "configureConversation"
        )
        try self.init(
            decodingFieldsFrom: decoder,
            allowed: Self.wireKeys.union(["request"])
        )
    }

    private init(decodingFieldsFrom decoder: Decoder, allowed: Set<String>) throws {
        try runtimeV2RejectUnknownKeys(decoder, allowed: allowed)
        let container = try decoder.container(keyedBy: RuntimeV2CodingKey.self)
        self.init(
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
            configuration: try container.decode(
                RuntimeConversationConfigurationV2.self,
                forKey: runtimeV2Key("configuration")
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
        try container.encode("configureConversation", forKey: runtimeV2Key("request"))
        try encodeFields(into: &container)
    }

    static let wireKeys: Set<String> = [
        "conversationId", "idempotencyKey", "expectedConfigurationRevision", "configuration",
    ]

    func encodeFields(
        into container: inout KeyedEncodingContainer<RuntimeV2CodingKey>
    ) throws {
        try container.encode(conversationID, forKey: runtimeV2Key("conversationId"))
        try container.encode(idempotencyKey, forKey: runtimeV2Key("idempotencyKey"))
        try container.encode(
            expectedConfigurationRevision,
            forKey: runtimeV2Key("expectedConfigurationRevision")
        )
        try container.encode(configuration, forKey: runtimeV2Key("configuration"))
    }
}

public enum RuntimeConfigurationReceiptV2: RuntimeV2FlattenedPayload {
    case applied(conversationID: RuntimeConversationID, configurationRevision: UInt64)
    case replayed(conversationID: RuntimeConversationID, configurationRevision: UInt64)
    case conflict(conversationID: RuntimeConversationID, currentConfigurationRevision: UInt64)
    case failed(RuntimeFailureV1)

    public init(from decoder: Decoder) throws {
        try self.init(decodingFieldsFrom: decoder, flattened: false)
    }

    init(flattenedFrom decoder: Decoder) throws {
        try self.init(decodingFieldsFrom: decoder, flattened: true)
    }

    private init(decodingFieldsFrom decoder: Decoder, flattened: Bool) throws {
        if flattened {
            try runtimeV2ValidateDiscriminator(decoder, key: "reply", expected: "configuration")
        }
        let outer: Set<String> = flattened ? ["reply"] : []
        let container = try decoder.container(keyedBy: RuntimeV2CodingKey.self)
        let status = try container.decode(String.self, forKey: runtimeV2Key("status"))
        switch status {
        case "applied", "replayed":
            try runtimeV2RejectUnknownKeys(
                decoder,
                allowed: Set([
                    "status", "conversationId", "configurationRevision",
                ]).union(outer)
            )
            let conversationID = try container.decode(
                RuntimeConversationID.self,
                forKey: runtimeV2Key("conversationId")
            )
            let revision = try container.decode(
                UInt64.self,
                forKey: runtimeV2Key("configurationRevision")
            )
            try runtimeV2RequireNonzeroRevision(revision)
            self = status == "applied"
                ? .applied(conversationID: conversationID, configurationRevision: revision)
                : .replayed(conversationID: conversationID, configurationRevision: revision)
        case "conflict":
            try runtimeV2RejectUnknownKeys(
                decoder,
                allowed: Set([
                    "status", "conversationId", "currentConfigurationRevision",
                ]).union(outer)
            )
            self = .conflict(
                conversationID: try container.decode(
                    RuntimeConversationID.self,
                    forKey: runtimeV2Key("conversationId")
                ),
                currentConfigurationRevision: try container.decode(
                    UInt64.self,
                    forKey: runtimeV2Key("currentConfigurationRevision")
                )
            )
        case "failed":
            try runtimeV2RejectUnknownKeys(
                decoder,
                allowed: Set(["status", "failure"]).union(outer)
            )
            self = .failed(
                try container.decode(RuntimeFailureV1.self, forKey: runtimeV2Key("failure"))
            )
        default:
            throw DecodingError.dataCorruptedError(
                forKey: runtimeV2Key("status"),
                in: container,
                debugDescription: "unknown configuration receipt status"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: RuntimeV2CodingKey.self)
        try encodeFields(into: &container, flattened: false)
    }

    func encodeFlattenedFields(
        into container: inout KeyedEncodingContainer<RuntimeV2CodingKey>
    ) throws {
        try encodeFields(into: &container, flattened: true)
    }

    private func encodeFields(
        into container: inout KeyedEncodingContainer<RuntimeV2CodingKey>,
        flattened: Bool
    ) throws {
        if flattened {
            try container.encode("configuration", forKey: runtimeV2Key("reply"))
        }
        switch self {
        case .applied(let conversationID, let revision),
             .replayed(let conversationID, let revision):
            try runtimeV2RequireNonzeroRevision(revision)
            let status = if case .applied = self { "applied" } else { "replayed" }
            try container.encode(status, forKey: runtimeV2Key("status"))
            try container.encode(conversationID, forKey: runtimeV2Key("conversationId"))
            try container.encode(revision, forKey: runtimeV2Key("configurationRevision"))
        case .conflict(let conversationID, let revision):
            try container.encode("conflict", forKey: runtimeV2Key("status"))
            try container.encode(conversationID, forKey: runtimeV2Key("conversationId"))
            try container.encode(revision, forKey: runtimeV2Key("currentConfigurationRevision"))
        case .failed(let failure):
            try container.encode("failed", forKey: runtimeV2Key("status"))
            try container.encode(failure, forKey: runtimeV2Key("failure"))
        }
    }
}

// MARK: - Metadata

public enum RuntimeConversationMetadataMutationV2: Codable, Sendable {
    case rename(title: String?)
    case setArchived(archived: Bool)

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: RuntimeV2CodingKey.self)
        let kind = try container.decode(String.self, forKey: runtimeV2Key("kind"))
        switch kind {
        case "rename":
            try runtimeV2RejectUnknownKeys(decoder, allowed: ["kind", "title"])
            let title = try runtimeV2DecodeRequiredNullable(
                String.self,
                from: container,
                forKey: runtimeV2Key("title")
            )
            try runtimeV2ValidateTitle(title)
            self = .rename(title: title)
        case "setArchived":
            try runtimeV2RejectUnknownKeys(decoder, allowed: ["kind", "archived"])
            self = .setArchived(
                archived: try container.decode(Bool.self, forKey: runtimeV2Key("archived"))
            )
        default:
            throw DecodingError.dataCorruptedError(
                forKey: runtimeV2Key("kind"),
                in: container,
                debugDescription: "unknown metadata mutation"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: RuntimeV2CodingKey.self)
        switch self {
        case .rename(let title):
            try runtimeV2ValidateTitle(title)
            try container.encode("rename", forKey: runtimeV2Key("kind"))
            try container.encode(title, forKey: runtimeV2Key("title"))
        case .setArchived(let archived):
            try container.encode("setArchived", forKey: runtimeV2Key("kind"))
            try container.encode(archived, forKey: runtimeV2Key("archived"))
        }
    }
}

public struct RuntimeConversationMetadataMutationRequestV2: RuntimeV2FlattenedPayload {
    public let conversationID: RuntimeConversationID
    public let idempotencyKey: RuntimeIdempotencyKey
    public let expectedEntryRevision: UInt64
    public let mutation: RuntimeConversationMetadataMutationV2

    public init(
        conversationID: RuntimeConversationID,
        idempotencyKey: RuntimeIdempotencyKey,
        expectedEntryRevision: UInt64,
        mutation: RuntimeConversationMetadataMutationV2
    ) {
        self.conversationID = conversationID
        self.idempotencyKey = idempotencyKey
        self.expectedEntryRevision = expectedEntryRevision
        self.mutation = mutation
    }

    public init(from decoder: Decoder) throws {
        try self.init(decodingFieldsFrom: decoder, allowed: Self.wireKeys)
    }

    init(flattenedFrom decoder: Decoder) throws {
        try runtimeV2ValidateDiscriminator(
            decoder,
            key: "request",
            expected: "updateConversationMetadata"
        )
        try self.init(
            decodingFieldsFrom: decoder,
            allowed: Self.wireKeys.union(["request"])
        )
    }

    private init(decodingFieldsFrom decoder: Decoder, allowed: Set<String>) throws {
        try runtimeV2RejectUnknownKeys(decoder, allowed: allowed)
        let container = try decoder.container(keyedBy: RuntimeV2CodingKey.self)
        self.init(
            conversationID: try container.decode(
                RuntimeConversationID.self,
                forKey: runtimeV2Key("conversationId")
            ),
            idempotencyKey: try container.decode(
                RuntimeIdempotencyKey.self,
                forKey: runtimeV2Key("idempotencyKey")
            ),
            expectedEntryRevision: try container.decode(
                UInt64.self,
                forKey: runtimeV2Key("expectedEntryRevision")
            ),
            mutation: try container.decode(
                RuntimeConversationMetadataMutationV2.self,
                forKey: runtimeV2Key("mutation")
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
        try container.encode("updateConversationMetadata", forKey: runtimeV2Key("request"))
        try encodeFields(into: &container)
    }

    static let wireKeys: Set<String> = [
        "conversationId", "idempotencyKey", "expectedEntryRevision", "mutation",
    ]

    private func encodeFields(
        into container: inout KeyedEncodingContainer<RuntimeV2CodingKey>
    ) throws {
        try container.encode(conversationID, forKey: runtimeV2Key("conversationId"))
        try container.encode(idempotencyKey, forKey: runtimeV2Key("idempotencyKey"))
        try container.encode(expectedEntryRevision, forKey: runtimeV2Key("expectedEntryRevision"))
        try container.encode(mutation, forKey: runtimeV2Key("mutation"))
    }
}

public enum RuntimeConversationMetadataReceiptV2: RuntimeV2FlattenedPayload {
    case applied(conversationID: RuntimeConversationID, entryRevision: UInt64)
    case replayed(conversationID: RuntimeConversationID, entryRevision: UInt64)
    case conflict(conversationID: RuntimeConversationID, currentEntryRevision: UInt64)
    case failed(RuntimeFailureV1)

    public init(from decoder: Decoder) throws {
        try self.init(decodingFieldsFrom: decoder, flattened: false)
    }

    init(flattenedFrom decoder: Decoder) throws {
        try self.init(decodingFieldsFrom: decoder, flattened: true)
    }

    private init(decodingFieldsFrom decoder: Decoder, flattened: Bool) throws {
        if flattened {
            try runtimeV2ValidateDiscriminator(
                decoder,
                key: "reply",
                expected: "conversationMetadata"
            )
        }
        let outer: Set<String> = flattened ? ["reply"] : []
        let container = try decoder.container(keyedBy: RuntimeV2CodingKey.self)
        let status = try container.decode(String.self, forKey: runtimeV2Key("status"))
        switch status {
        case "applied", "replayed":
            try runtimeV2RejectUnknownKeys(
                decoder,
                allowed: Set(["status", "conversationId", "entryRevision"]).union(outer)
            )
            let conversationID = try container.decode(
                RuntimeConversationID.self,
                forKey: runtimeV2Key("conversationId")
            )
            let revision = try container.decode(UInt64.self, forKey: runtimeV2Key("entryRevision"))
            try runtimeV2RequireNonzeroRevision(revision)
            self = status == "applied"
                ? .applied(conversationID: conversationID, entryRevision: revision)
                : .replayed(conversationID: conversationID, entryRevision: revision)
        case "conflict":
            try runtimeV2RejectUnknownKeys(
                decoder,
                allowed: Set(["status", "conversationId", "currentEntryRevision"]).union(outer)
            )
            self = .conflict(
                conversationID: try container.decode(
                    RuntimeConversationID.self,
                    forKey: runtimeV2Key("conversationId")
                ),
                currentEntryRevision: try container.decode(
                    UInt64.self,
                    forKey: runtimeV2Key("currentEntryRevision")
                )
            )
        case "failed":
            try runtimeV2RejectUnknownKeys(
                decoder,
                allowed: Set(["status", "failure"]).union(outer)
            )
            self = .failed(
                try container.decode(RuntimeFailureV1.self, forKey: runtimeV2Key("failure"))
            )
        default:
            throw DecodingError.dataCorruptedError(
                forKey: runtimeV2Key("status"),
                in: container,
                debugDescription: "unknown metadata receipt status"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: RuntimeV2CodingKey.self)
        try encodeFields(into: &container, flattened: false)
    }

    func encodeFlattenedFields(
        into container: inout KeyedEncodingContainer<RuntimeV2CodingKey>
    ) throws {
        try encodeFields(into: &container, flattened: true)
    }

    private func encodeFields(
        into container: inout KeyedEncodingContainer<RuntimeV2CodingKey>,
        flattened: Bool
    ) throws {
        if flattened {
            try container.encode("conversationMetadata", forKey: runtimeV2Key("reply"))
        }
        switch self {
        case .applied(let conversationID, let revision),
             .replayed(let conversationID, let revision):
            try runtimeV2RequireNonzeroRevision(revision)
            let status = if case .applied = self { "applied" } else { "replayed" }
            try container.encode(status, forKey: runtimeV2Key("status"))
            try container.encode(conversationID, forKey: runtimeV2Key("conversationId"))
            try container.encode(revision, forKey: runtimeV2Key("entryRevision"))
        case .conflict(let conversationID, let revision):
            try container.encode("conflict", forKey: runtimeV2Key("status"))
            try container.encode(conversationID, forKey: runtimeV2Key("conversationId"))
            try container.encode(revision, forKey: runtimeV2Key("currentEntryRevision"))
        case .failed(let failure):
            try container.encode("failed", forKey: runtimeV2Key("status"))
            try container.encode(failure, forKey: runtimeV2Key("failure"))
        }
    }
}

// MARK: - Agent discovery

private func runtimeV2VendorAgentKind(_ vendor: RuntimeVendorCapabilitiesV1) -> AgentKind {
    switch vendor {
    case .codex: .codex
    case .claudeCode: .claudeCode
    }
}

public struct RuntimeAgentDescriptionV2: Codable, Sendable {
    public let agentKind: AgentKind
    public let capabilities: RuntimeSessionCapabilitiesV1
    public let defaultConfiguration: RuntimeConversationConfigurationV2

    public init(
        agentKind: AgentKind,
        capabilities: RuntimeSessionCapabilitiesV1,
        defaultConfiguration: RuntimeConversationConfigurationV2
    ) throws {
        self.agentKind = agentKind
        self.capabilities = capabilities
        self.defaultConfiguration = defaultConfiguration
        try validate()
    }

    public init(from decoder: Decoder) throws {
        try runtimeV2RejectUnknownKeys(
            decoder,
            allowed: ["agentKind", "capabilities", "defaultConfiguration"]
        )
        let container = try decoder.container(keyedBy: RuntimeV2CodingKey.self)
        try self.init(
            agentKind: container.decode(AgentKind.self, forKey: runtimeV2Key("agentKind")),
            capabilities: container.decode(
                RuntimeSessionCapabilitiesV1.self,
                forKey: runtimeV2Key("capabilities")
            ),
            defaultConfiguration: container.decode(
                RuntimeConversationConfigurationV2.self,
                forKey: runtimeV2Key("defaultConfiguration")
            )
        )
    }

    public func encode(to encoder: Encoder) throws {
        try validate()
        var container = encoder.container(keyedBy: RuntimeV2CodingKey.self)
        try container.encode(agentKind, forKey: runtimeV2Key("agentKind"))
        try container.encode(capabilities, forKey: runtimeV2Key("capabilities"))
        try container.encode(defaultConfiguration, forKey: runtimeV2Key("defaultConfiguration"))
    }

    private func validate() throws {
        guard capabilities.agentKind == agentKind,
              runtimeV2VendorAgentKind(capabilities.vendor) == agentKind,
              defaultConfiguration.agentKind == agentKind
        else {
            throw RuntimeV2MirrorError.invalidAgentDescription
        }
    }
}

public struct RuntimeAgentDescriptionsV2: RuntimeV2FlattenedPayload {
    public static let maxAgents = 16
    public let agents: [RuntimeAgentDescriptionV2]

    public init(agents: [RuntimeAgentDescriptionV2]) throws {
        self.agents = agents
        try validate()
    }

    public init(from decoder: Decoder) throws {
        try self.init(decodingFieldsFrom: decoder, allowed: ["agents"])
    }

    init(flattenedFrom decoder: Decoder) throws {
        try runtimeV2ValidateDiscriminator(decoder, key: "reply", expected: "agents")
        try self.init(decodingFieldsFrom: decoder, allowed: ["reply", "agents"])
    }

    private init(decodingFieldsFrom decoder: Decoder, allowed: Set<String>) throws {
        try runtimeV2RejectUnknownKeys(decoder, allowed: allowed)
        let container = try decoder.container(keyedBy: RuntimeV2CodingKey.self)
        try self.init(
            agents: container.decode(
                [RuntimeAgentDescriptionV2].self,
                forKey: runtimeV2Key("agents")
            )
        )
    }

    public func encode(to encoder: Encoder) throws {
        try validate()
        var container = encoder.container(keyedBy: RuntimeV2CodingKey.self)
        try container.encode(agents, forKey: runtimeV2Key("agents"))
    }

    func encodeFlattenedFields(
        into container: inout KeyedEncodingContainer<RuntimeV2CodingKey>
    ) throws {
        try validate()
        try container.encode("agents", forKey: runtimeV2Key("reply"))
        try container.encode(agents, forKey: runtimeV2Key("agents"))
    }

    private func validate() throws {
        let kinds = Set(agents.map(\.agentKind))
        guard agents.count <= Self.maxAgents else {
            throw RuntimeV2MirrorError.tooManyAgentDescriptions
        }
        guard kinds.count == agents.count else {
            throw RuntimeV2MirrorError.duplicateAgentDescription
        }
    }
}

// MARK: - Upgrade

private func runtimeV2ValidateArtifactSHA256(_ value: String) throws {
    guard value.utf8.count == 64,
          value.utf8.allSatisfy({
              (48...57).contains($0) || (97...102).contains($0)
          })
    else {
        throw RuntimeV2MirrorError.invalidArtifactSHA256
    }
}

private func runtimeV2ValidateTargetVersion(_ value: String) throws {
    let bytes = value.utf8
    guard !value.isEmpty,
          value != ".",
          value != "..",
          bytes.count <= 128,
          bytes.allSatisfy({ byte in
              (byte >= 48 && byte <= 57)
                  || (byte >= 65 && byte <= 90)
                  || (byte >= 97 && byte <= 122)
                  || [46, 95, 43, 45].contains(byte)
          })
    else {
        throw RuntimeV2MirrorError.invalidTargetVersion
    }
}

public struct RuntimeArtifactSHA256V2: Codable, Hashable, Sendable {
    public let rawValue: String

    public init(rawValue: String) throws {
        try runtimeV2ValidateArtifactSHA256(rawValue)
        self.rawValue = rawValue
    }

    public init(from decoder: Decoder) throws {
        try self.init(rawValue: decoder.singleValueContainer().decode(String.self))
    }

    public func encode(to encoder: Encoder) throws {
        try runtimeV2ValidateArtifactSHA256(rawValue)
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}

public struct RuntimeStageUpgradeRequestV2: RuntimeV2FlattenedPayload {
    public let targetVersion: String
    public let candidateSHA256: RuntimeArtifactSHA256V2
    public let idempotencyKey: RuntimeIdempotencyKey
    public let scope: RuntimeLocalOnlyAdministrationV1

    public init(
        targetVersion: String,
        candidateSHA256: RuntimeArtifactSHA256V2,
        idempotencyKey: RuntimeIdempotencyKey,
        scope: RuntimeLocalOnlyAdministrationV1
    ) throws {
        try runtimeV2ValidateTargetVersion(targetVersion)
        self.targetVersion = targetVersion
        self.candidateSHA256 = candidateSHA256
        self.idempotencyKey = idempotencyKey
        self.scope = scope
    }

    public init(from decoder: Decoder) throws {
        try self.init(decodingFieldsFrom: decoder, allowed: Self.wireKeys)
    }

    init(flattenedFrom decoder: Decoder) throws {
        try runtimeV2ValidateDiscriminator(decoder, key: "request", expected: "stageUpgrade")
        try self.init(
            decodingFieldsFrom: decoder,
            allowed: Self.wireKeys.union(["request"])
        )
    }

    private init(decodingFieldsFrom decoder: Decoder, allowed: Set<String>) throws {
        try runtimeV2RejectUnknownKeys(decoder, allowed: allowed)
        let container = try decoder.container(keyedBy: RuntimeV2CodingKey.self)
        try self.init(
            targetVersion: container.decode(String.self, forKey: runtimeV2Key("targetVersion")),
            candidateSHA256: container.decode(
                RuntimeArtifactSHA256V2.self,
                forKey: runtimeV2Key("candidateSha256")
            ),
            idempotencyKey: container.decode(
                RuntimeIdempotencyKey.self,
                forKey: runtimeV2Key("idempotencyKey")
            ),
            scope: container.decode(
                RuntimeLocalOnlyAdministrationV1.self,
                forKey: runtimeV2Key("scope")
            )
        )
    }

    public func encode(to encoder: Encoder) throws {
        try runtimeV2ValidateTargetVersion(targetVersion)
        var container = encoder.container(keyedBy: RuntimeV2CodingKey.self)
        try encodeFields(into: &container)
    }

    func encodeFlattenedFields(
        into container: inout KeyedEncodingContainer<RuntimeV2CodingKey>
    ) throws {
        try runtimeV2ValidateTargetVersion(targetVersion)
        try container.encode("stageUpgrade", forKey: runtimeV2Key("request"))
        try encodeFields(into: &container)
    }

    private func encodeFields(
        into container: inout KeyedEncodingContainer<RuntimeV2CodingKey>
    ) throws {
        try container.encode(targetVersion, forKey: runtimeV2Key("targetVersion"))
        try container.encode(candidateSHA256, forKey: runtimeV2Key("candidateSha256"))
        try container.encode(idempotencyKey, forKey: runtimeV2Key("idempotencyKey"))
        try container.encode(scope, forKey: runtimeV2Key("scope"))
    }

    private static let wireKeys: Set<String> = [
        "targetVersion", "candidateSha256", "idempotencyKey", "scope",
    ]
}

public enum RuntimeStageUpgradeReceiptV2: RuntimeV2FlattenedPayload {
    case staged(targetVersion: String)
    case awaitingIdle(targetVersion: String, activeTurns: UInt32)
    case replayed(targetVersion: String)
    case failed(RuntimeFailureV1)

    public init(from decoder: Decoder) throws {
        try self.init(decodingFieldsFrom: decoder, flattened: false)
    }

    init(flattenedFrom decoder: Decoder) throws {
        try self.init(decodingFieldsFrom: decoder, flattened: true)
    }

    private init(decodingFieldsFrom decoder: Decoder, flattened: Bool) throws {
        if flattened {
            try runtimeV2ValidateDiscriminator(decoder, key: "reply", expected: "stageUpgrade")
        }
        let outer: Set<String> = flattened ? ["reply"] : []
        let container = try decoder.container(keyedBy: RuntimeV2CodingKey.self)
        let status = try container.decode(String.self, forKey: runtimeV2Key("status"))
        switch status {
        case "staged", "replayed":
            try runtimeV2RejectUnknownKeys(
                decoder,
                allowed: Set(["status", "targetVersion"]).union(outer)
            )
            let target = try container.decode(String.self, forKey: runtimeV2Key("targetVersion"))
            try runtimeV2ValidateTargetVersion(target)
            self = status == "staged" ? .staged(targetVersion: target) : .replayed(targetVersion: target)
        case "awaitingIdle":
            try runtimeV2RejectUnknownKeys(
                decoder,
                allowed: Set(["status", "targetVersion", "activeTurns"]).union(outer)
            )
            let target = try container.decode(String.self, forKey: runtimeV2Key("targetVersion"))
            let active = try container.decode(UInt32.self, forKey: runtimeV2Key("activeTurns"))
            try runtimeV2ValidateTargetVersion(target)
            guard active > 0 else { throw RuntimeV2MirrorError.invalidActiveTurns }
            self = .awaitingIdle(targetVersion: target, activeTurns: active)
        case "failed":
            try runtimeV2RejectUnknownKeys(
                decoder,
                allowed: Set(["status", "failure"]).union(outer)
            )
            self = .failed(
                try container.decode(RuntimeFailureV1.self, forKey: runtimeV2Key("failure"))
            )
        default:
            throw DecodingError.dataCorruptedError(
                forKey: runtimeV2Key("status"),
                in: container,
                debugDescription: "unknown stage-upgrade status"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: RuntimeV2CodingKey.self)
        try encodeFields(into: &container, flattened: false)
    }

    func encodeFlattenedFields(
        into container: inout KeyedEncodingContainer<RuntimeV2CodingKey>
    ) throws {
        try encodeFields(into: &container, flattened: true)
    }

    private func encodeFields(
        into container: inout KeyedEncodingContainer<RuntimeV2CodingKey>,
        flattened: Bool
    ) throws {
        if flattened {
            try container.encode("stageUpgrade", forKey: runtimeV2Key("reply"))
        }
        switch self {
        case .staged(let target), .replayed(let target):
            try runtimeV2ValidateTargetVersion(target)
            let status = if case .staged = self { "staged" } else { "replayed" }
            try container.encode(status, forKey: runtimeV2Key("status"))
            try container.encode(target, forKey: runtimeV2Key("targetVersion"))
        case .awaitingIdle(let target, let active):
            try runtimeV2ValidateTargetVersion(target)
            guard active > 0 else { throw RuntimeV2MirrorError.invalidActiveTurns }
            try container.encode("awaitingIdle", forKey: runtimeV2Key("status"))
            try container.encode(target, forKey: runtimeV2Key("targetVersion"))
            try container.encode(active, forKey: runtimeV2Key("activeTurns"))
        case .failed(let failure):
            try container.encode("failed", forKey: runtimeV2Key("status"))
            try container.encode(failure, forKey: runtimeV2Key("failure"))
        }
    }
}

// MARK: - Changed command receipts

public enum CommandReceiptV2: RuntimeV2FlattenedPayload {
    case accepted(
        commandID: RuntimeCommandID,
        queuePosition: UInt32,
        configurationRevision: UInt64
    )
    case replayed(commandID: RuntimeCommandID, configurationRevision: UInt64)
    case failed(RuntimeFailureV1)

    public init(from decoder: Decoder) throws {
        try self.init(decodingFieldsFrom: decoder, flattened: false)
    }

    init(flattenedFrom decoder: Decoder) throws {
        try self.init(decodingFieldsFrom: decoder, flattened: true)
    }

    private init(decodingFieldsFrom decoder: Decoder, flattened: Bool) throws {
        if flattened {
            try runtimeV2ValidateDiscriminator(decoder, key: "reply", expected: "command")
        }
        let outer: Set<String> = flattened ? ["reply"] : []
        let container = try decoder.container(keyedBy: RuntimeV2CodingKey.self)
        let status = try container.decode(String.self, forKey: runtimeV2Key("status"))
        switch status {
        case "accepted":
            try runtimeV2RejectUnknownKeys(
                decoder,
                allowed: Set([
                    "status", "commandId", "queuePosition", "configurationRevision",
                ]).union(outer)
            )
            self = .accepted(
                commandID: try container.decode(
                    RuntimeCommandID.self,
                    forKey: runtimeV2Key("commandId")
                ),
                queuePosition: try container.decode(UInt32.self, forKey: runtimeV2Key("queuePosition")),
                configurationRevision: try container.decode(
                    UInt64.self,
                    forKey: runtimeV2Key("configurationRevision")
                )
            )
        case "replayed":
            try runtimeV2RejectUnknownKeys(
                decoder,
                allowed: Set(["status", "commandId", "configurationRevision"]).union(outer)
            )
            self = .replayed(
                commandID: try container.decode(
                    RuntimeCommandID.self,
                    forKey: runtimeV2Key("commandId")
                ),
                configurationRevision: try container.decode(
                    UInt64.self,
                    forKey: runtimeV2Key("configurationRevision")
                )
            )
        case "failed":
            try runtimeV2RejectUnknownKeys(
                decoder,
                allowed: Set(["status", "failure"]).union(outer)
            )
            self = .failed(
                try container.decode(RuntimeFailureV1.self, forKey: runtimeV2Key("failure"))
            )
        default:
            throw DecodingError.dataCorruptedError(
                forKey: runtimeV2Key("status"),
                in: container,
                debugDescription: "unknown command receipt status"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: RuntimeV2CodingKey.self)
        try encodeFields(into: &container, flattened: false)
    }

    func encodeFlattenedFields(
        into container: inout KeyedEncodingContainer<RuntimeV2CodingKey>
    ) throws {
        try encodeFields(into: &container, flattened: true)
    }

    private func encodeFields(
        into container: inout KeyedEncodingContainer<RuntimeV2CodingKey>,
        flattened: Bool
    ) throws {
        if flattened {
            try container.encode("command", forKey: runtimeV2Key("reply"))
        }
        switch self {
        case .accepted(let commandID, let position, let revision):
            try container.encode("accepted", forKey: runtimeV2Key("status"))
            try container.encode(commandID, forKey: runtimeV2Key("commandId"))
            try container.encode(position, forKey: runtimeV2Key("queuePosition"))
            try container.encode(revision, forKey: runtimeV2Key("configurationRevision"))
        case .replayed(let commandID, let revision):
            try container.encode("replayed", forKey: runtimeV2Key("status"))
            try container.encode(commandID, forKey: runtimeV2Key("commandId"))
            try container.encode(revision, forKey: runtimeV2Key("configurationRevision"))
        case .failed(let failure):
            try container.encode("failed", forKey: runtimeV2Key("status"))
            try container.encode(failure, forKey: runtimeV2Key("failure"))
        }
    }
}

public struct CommandStatusReceiptV2: RuntimeV2FlattenedPayload {
    public let conversationID: RuntimeConversationID
    public let commandID: RuntimeCommandID
    public let configurationRevision: UInt64
    public let status: CommandStatusV1
    public let turnID: RuntimeTurnID?

    public init(
        conversationID: RuntimeConversationID,
        commandID: RuntimeCommandID,
        configurationRevision: UInt64,
        status: CommandStatusV1,
        turnID: RuntimeTurnID?
    ) {
        self.conversationID = conversationID
        self.commandID = commandID
        self.configurationRevision = configurationRevision
        self.status = status
        self.turnID = turnID
    }

    public init(from decoder: Decoder) throws {
        try self.init(decodingFieldsFrom: decoder, allowed: Self.wireKeys)
    }

    init(flattenedFrom decoder: Decoder) throws {
        try runtimeV2ValidateDiscriminator(decoder, key: "reply", expected: "commandStatus")
        try self.init(decodingFieldsFrom: decoder, allowed: Self.wireKeys.union(["reply"]))
    }

    private init(decodingFieldsFrom decoder: Decoder, allowed: Set<String>) throws {
        try runtimeV2RejectUnknownKeys(decoder, allowed: allowed)
        let container = try decoder.container(keyedBy: RuntimeV2CodingKey.self)
        self.init(
            conversationID: try container.decode(
                RuntimeConversationID.self,
                forKey: runtimeV2Key("conversationId")
            ),
            commandID: try container.decode(RuntimeCommandID.self, forKey: runtimeV2Key("commandId")),
            configurationRevision: try container.decode(
                UInt64.self,
                forKey: runtimeV2Key("configurationRevision")
            ),
            status: try container.decode(CommandStatusV1.self, forKey: runtimeV2Key("status")),
            turnID: try container.decodeIfPresent(RuntimeTurnID.self, forKey: runtimeV2Key("turnId"))
        )
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: RuntimeV2CodingKey.self)
        try encodeFields(into: &container)
    }

    func encodeFlattenedFields(
        into container: inout KeyedEncodingContainer<RuntimeV2CodingKey>
    ) throws {
        try container.encode("commandStatus", forKey: runtimeV2Key("reply"))
        try encodeFields(into: &container)
    }

    private func encodeFields(
        into container: inout KeyedEncodingContainer<RuntimeV2CodingKey>
    ) throws {
        try container.encode(conversationID, forKey: runtimeV2Key("conversationId"))
        try container.encode(commandID, forKey: runtimeV2Key("commandId"))
        try container.encode(configurationRevision, forKey: runtimeV2Key("configurationRevision"))
        try container.encode(status, forKey: runtimeV2Key("status"))
        try container.encode(turnID, forKey: runtimeV2Key("turnId"))
    }

    private static let wireKeys: Set<String> = [
        "conversationId", "commandId", "configurationRevision", "status", "turnId",
    ]
}

public struct ConversationStartReceiptV2: RuntimeV2FlattenedPayload {
    public let conversationID: RuntimeConversationID
    public let replayed: Bool

    public init(conversationID: RuntimeConversationID, replayed: Bool) {
        self.conversationID = conversationID
        self.replayed = replayed
    }

    public init(from decoder: Decoder) throws {
        try self.init(decodingFieldsFrom: decoder, allowed: ["conversationId", "replayed"])
    }

    init(flattenedFrom decoder: Decoder) throws {
        try runtimeV2ValidateDiscriminator(decoder, key: "reply", expected: "conversationStart")
        try self.init(
            decodingFieldsFrom: decoder,
            allowed: ["reply", "conversationId", "replayed"]
        )
    }

    private init(decodingFieldsFrom decoder: Decoder, allowed: Set<String>) throws {
        try runtimeV2RejectUnknownKeys(decoder, allowed: allowed)
        let container = try decoder.container(keyedBy: RuntimeV2CodingKey.self)
        self.init(
            conversationID: try container.decode(
                RuntimeConversationID.self,
                forKey: runtimeV2Key("conversationId")
            ),
            replayed: try container.decode(Bool.self, forKey: runtimeV2Key("replayed"))
        )
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: RuntimeV2CodingKey.self)
        try encodeFields(into: &container)
    }

    func encodeFlattenedFields(
        into container: inout KeyedEncodingContainer<RuntimeV2CodingKey>
    ) throws {
        try container.encode("conversationStart", forKey: runtimeV2Key("reply"))
        try encodeFields(into: &container)
    }

    private func encodeFields(
        into container: inout KeyedEncodingContainer<RuntimeV2CodingKey>
    ) throws {
        try container.encode(conversationID, forKey: runtimeV2Key("conversationId"))
        try container.encode(replayed, forKey: runtimeV2Key("replayed"))
    }
}
