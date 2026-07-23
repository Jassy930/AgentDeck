import Foundation

// Runtime v5 current DTO 保留 V2 类型名以维持源码兼容。稳定且 wire 未变化的 leaf 继续复用
// RuntimeWireTypes.swift；本文件提供严格的 configuration/metadata/upgrade/receipt/machine mirror。

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
            debugDescription: "unknown Runtime v5 field \(unknown.stringValue)"
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

func runtimeV4ValidatePairingDisplayName(_ value: String) throws {
    guard !value.isEmpty,
          value.utf8.count <= 128,
          value.trimmingCharacters(in: .whitespacesAndNewlines) == value,
          !value.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains)
    else {
        throw RuntimeV3MirrorError.invalidPairingPayload
    }
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
            debugDescription: "unexpected Runtime v5 discriminator \(received)"
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

// MARK: - Runtime v4 pairing administration

public enum RuntimePairingCertRoleV1: String, Codable, Sendable {
  case link
  case data
}

public struct RuntimePairingSignedCertificateV1: Codable, Sendable {
  public let subjectPubkey: Data
  public let certRole: RuntimePairingCertRoleV1
  public let generation: UInt64
  public let rootKeyID: Data
  public let trustEpoch: UInt64
  public let notAfterMs: UInt64?
  public let signature: Data

  private enum CodingKeys: String, CodingKey, CaseIterable {
    case subjectPubkey, certRole, generation
    case rootKeyID = "rootKeyId"
    case trustEpoch, notAfterMs, signature
  }

  public init(
    subjectPubkey: Data,
    certRole: RuntimePairingCertRoleV1,
    generation: UInt64,
    rootKeyID: Data,
    trustEpoch: UInt64,
    notAfterMs: UInt64?,
    signature: Data
  ) throws {
    try runtimeV3RequireData(subjectPubkey, count: 32)
    try runtimeV3RequireData(rootKeyID, count: 16)
    try runtimeV3RequireData(signature, count: 64)
    self.subjectPubkey = subjectPubkey
    self.certRole = certRole
    self.generation = generation
    self.rootKeyID = rootKeyID
    self.trustEpoch = trustEpoch
    self.notAfterMs = notAfterMs
    self.signature = signature
  }

  public init(from decoder: Decoder) throws {
    try runtimeV2RejectUnknownKeys(
      decoder,
      allowed: Set(CodingKeys.allCases.map(\.rawValue))
    )
    let container = try decoder.container(keyedBy: CodingKeys.self)
    try self.init(
      subjectPubkey: container.decode(Data.self, forKey: .subjectPubkey),
      certRole: container.decode(RuntimePairingCertRoleV1.self, forKey: .certRole),
      generation: container.decode(UInt64.self, forKey: .generation),
      rootKeyID: container.decode(Data.self, forKey: .rootKeyID),
      trustEpoch: container.decode(UInt64.self, forKey: .trustEpoch),
      notAfterMs: container.decodeIfPresent(UInt64.self, forKey: .notAfterMs),
      signature: container.decode(Data.self, forKey: .signature)
    )
  }

  public func encode(to encoder: Encoder) throws {
    _ = try RuntimePairingSignedCertificateV1(
      subjectPubkey: subjectPubkey,
      certRole: certRole,
      generation: generation,
      rootKeyID: rootKeyID,
      trustEpoch: trustEpoch,
      notAfterMs: notAfterMs,
      signature: signature
    )
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(subjectPubkey, forKey: .subjectPubkey)
    try container.encode(certRole, forKey: .certRole)
    try container.encode(generation, forKey: .generation)
    try container.encode(rootKeyID, forKey: .rootKeyID)
    try container.encode(trustEpoch, forKey: .trustEpoch)
    try container.encodeIfPresent(notAfterMs, forKey: .notAfterMs)
    try container.encode(signature, forKey: .signature)
  }
}

/// Runtime v4 经 same-UID UDS 返回的完整带外 PairInviteV1。
public struct RuntimePairInvitePayloadV1: Codable, Sendable {
  public let formatVersion: UInt16
  public let relayProtocolVersion: UInt16
  public let pairRoute: Data
  public let inviteSecret: Data
  public let inviteHPKEPubkey: Data
  public let wssURL: String
  public let relayServerID: Data
  public let currentSPKIPin: Data
  public let nextSPKIPin: Data
  public let expiresAtMs: UInt64
  public let machineRootPubkey: Data
  public let machineRootFingerprint: Data
  public let dataSignCert: RuntimePairingSignedCertificateV1
  public let machineDisplayName: String

  private enum CodingKeys: String, CodingKey, CaseIterable {
    case formatVersion, relayProtocolVersion, pairRoute, inviteSecret
    case inviteHPKEPubkey = "inviteHpkePubkey"
    case wssURL = "wssUrl"
    case relayServerID = "relayServerId"
    case currentSPKIPin = "currentSpkiPin"
    case nextSPKIPin = "nextSpkiPin"
    case expiresAtMs, machineRootPubkey, machineRootFingerprint, dataSignCert, machineDisplayName
  }

  public init(
    formatVersion: UInt16,
    relayProtocolVersion: UInt16,
    pairRoute: Data,
    inviteSecret: Data,
    inviteHPKEPubkey: Data,
    wssURL: String,
    relayServerID: Data,
    currentSPKIPin: Data,
    nextSPKIPin: Data,
    expiresAtMs: UInt64,
    machineRootPubkey: Data,
    machineRootFingerprint: Data,
    dataSignCert: RuntimePairingSignedCertificateV1,
    machineDisplayName: String
  ) throws {
    try runtimeV4ValidatePairingDisplayName(machineDisplayName)
    let components = URLComponents(string: wssURL)
    guard formatVersion == 1, relayProtocolVersion == 2,
      !wssURL.isEmpty, wssURL.utf8.count <= 2 * 1024, !wssURL.utf8.contains(0),
      components?.scheme == "wss", components?.host != nil,
      components?.user == nil, components?.password == nil, components?.query == nil,
      components?.fragment == nil, components?.port != 0, components?.percentEncodedPath == "/",
      components?.string == wssURL,
      expiresAtMs > 0,
      dataSignCert.certRole == .data,
      dataSignCert.generation > 0,
      dataSignCert.trustEpoch > 0,
      dataSignCert.notAfterMs != 0
    else {
      throw RuntimeV3MirrorError.invalidPairingPayload
    }
    try runtimeV3RequireData(pairRoute, count: 16, nonzero: true)
    try runtimeV3RequireData(inviteSecret, count: 32, nonzero: true)
    try runtimeV3RequireData(inviteHPKEPubkey, count: 32, nonzero: true)
    try runtimeV3RequireData(relayServerID, count: 16, nonzero: true)
    try runtimeV3RequireData(currentSPKIPin, count: 32, nonzero: true)
    try runtimeV3RequireData(nextSPKIPin, count: 32, nonzero: true)
    try runtimeV3RequireData(machineRootPubkey, count: 32, nonzero: true)
    try runtimeV3RequireData(machineRootFingerprint, count: 32, nonzero: true)
    guard runtimeV3SHA256(machineRootPubkey) == machineRootFingerprint else {
      throw RuntimeV3MirrorError.invalidPairingPayload
    }
    try runtimeV3RequireData(dataSignCert.subjectPubkey, count: 32, nonzero: true)
    try runtimeV3RequireData(dataSignCert.rootKeyID, count: 16, nonzero: true)
    try runtimeV3RequireData(dataSignCert.signature, count: 64, nonzero: true)
    self.formatVersion = formatVersion
    self.relayProtocolVersion = relayProtocolVersion
    self.pairRoute = pairRoute
    self.inviteSecret = inviteSecret
    self.inviteHPKEPubkey = inviteHPKEPubkey
    self.wssURL = wssURL
    self.relayServerID = relayServerID
    self.currentSPKIPin = currentSPKIPin
    self.nextSPKIPin = nextSPKIPin
    self.expiresAtMs = expiresAtMs
    self.machineRootPubkey = machineRootPubkey
    self.machineRootFingerprint = machineRootFingerprint
    self.dataSignCert = dataSignCert
    self.machineDisplayName = machineDisplayName
  }

  public init(from decoder: Decoder) throws {
    try runtimeV2RejectUnknownKeys(
      decoder,
      allowed: Set(CodingKeys.allCases.map(\.rawValue))
    )
    let container = try decoder.container(keyedBy: CodingKeys.self)
    try self.init(
      formatVersion: container.decode(UInt16.self, forKey: .formatVersion),
      relayProtocolVersion: container.decode(UInt16.self, forKey: .relayProtocolVersion),
      pairRoute: container.decode(Data.self, forKey: .pairRoute),
      inviteSecret: container.decode(Data.self, forKey: .inviteSecret),
      inviteHPKEPubkey: container.decode(Data.self, forKey: .inviteHPKEPubkey),
      wssURL: container.decode(String.self, forKey: .wssURL),
      relayServerID: container.decode(Data.self, forKey: .relayServerID),
      currentSPKIPin: container.decode(Data.self, forKey: .currentSPKIPin),
      nextSPKIPin: container.decode(Data.self, forKey: .nextSPKIPin),
      expiresAtMs: container.decode(UInt64.self, forKey: .expiresAtMs),
      machineRootPubkey: container.decode(Data.self, forKey: .machineRootPubkey),
      machineRootFingerprint: container.decode(Data.self, forKey: .machineRootFingerprint),
      dataSignCert: container.decode(RuntimePairingSignedCertificateV1.self, forKey: .dataSignCert),
      machineDisplayName: container.decode(String.self, forKey: .machineDisplayName)
    )
  }

  public func encode(to encoder: Encoder) throws {
    _ = try RuntimePairInvitePayloadV1(
      formatVersion: formatVersion,
      relayProtocolVersion: relayProtocolVersion,
      pairRoute: pairRoute,
      inviteSecret: inviteSecret,
      inviteHPKEPubkey: inviteHPKEPubkey,
      wssURL: wssURL,
      relayServerID: relayServerID,
      currentSPKIPin: currentSPKIPin,
      nextSPKIPin: nextSPKIPin,
      expiresAtMs: expiresAtMs,
      machineRootPubkey: machineRootPubkey,
      machineRootFingerprint: machineRootFingerprint,
      dataSignCert: dataSignCert,
      machineDisplayName: machineDisplayName
    )
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(formatVersion, forKey: .formatVersion)
    try container.encode(relayProtocolVersion, forKey: .relayProtocolVersion)
    try container.encode(pairRoute, forKey: .pairRoute)
    try container.encode(inviteSecret, forKey: .inviteSecret)
    try container.encode(inviteHPKEPubkey, forKey: .inviteHPKEPubkey)
    try container.encode(wssURL, forKey: .wssURL)
    try container.encode(relayServerID, forKey: .relayServerID)
    try container.encode(currentSPKIPin, forKey: .currentSPKIPin)
    try container.encode(nextSPKIPin, forKey: .nextSPKIPin)
    try container.encode(expiresAtMs, forKey: .expiresAtMs)
    try container.encode(machineRootPubkey, forKey: .machineRootPubkey)
    try container.encode(machineRootFingerprint, forKey: .machineRootFingerprint)
    try container.encode(dataSignCert, forKey: .dataSignCert)
    try container.encode(machineDisplayName, forKey: .machineDisplayName)
  }
}

public struct RuntimePairInviteV4: Codable, Sendable {
  public let pairingID: RuntimePairingID
  public let invite: RuntimePairInvitePayloadV1

  public init(pairingID: RuntimePairingID, invite: RuntimePairInvitePayloadV1) {
    self.pairingID = pairingID
    self.invite = invite
  }

  public init(from decoder: Decoder) throws {
    try self.init(decodingFieldsFrom: decoder, allowed: ["pairingId", "invite"])
  }

  init(flattenedFrom decoder: Decoder) throws {
    try runtimeV2ValidateDiscriminator(decoder, key: "reply", expected: "pairInvite")
    try self.init(decodingFieldsFrom: decoder, allowed: ["reply", "pairingId", "invite"])
  }

  private init(decodingFieldsFrom decoder: Decoder, allowed: Set<String>) throws {
    try runtimeV2RejectUnknownKeys(decoder, allowed: allowed)
    let container = try decoder.container(keyedBy: RuntimeV2CodingKey.self)
    self.init(
      pairingID: try container.decode(RuntimePairingID.self, forKey: runtimeV2Key("pairingId")),
      invite: try container.decode(RuntimePairInvitePayloadV1.self, forKey: runtimeV2Key("invite"))
    )
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: RuntimeV2CodingKey.self)
    try encodeFields(into: &container)
  }

  func encodeFields(into container: inout KeyedEncodingContainer<RuntimeV2CodingKey>) throws {
    try container.encode(pairingID, forKey: runtimeV2Key("pairingId"))
    try container.encode(invite, forKey: runtimeV2Key("invite"))
  }
}

public struct RuntimePendingPairingV4: Codable, Sendable {
  public let pairingID: RuntimePairingID
  public let requestHash: Data
  public let deviceSignFingerprint: Data
  public let requestedAtMs: UInt64
  public let expiresAtMs: UInt64

  public init(
    pairingID: RuntimePairingID,
    requestHash: Data,
    deviceSignFingerprint: Data,
    requestedAtMs: UInt64,
    expiresAtMs: UInt64
  ) throws {
    try runtimeV3RequireData(requestHash, count: 32, nonzero: true)
    try runtimeV3RequireData(deviceSignFingerprint, count: 32, nonzero: true)
    guard requestedAtMs <= expiresAtMs else {
      throw RuntimeV3MirrorError.invalidPairingPayload
    }
    self.pairingID = pairingID
    self.requestHash = requestHash
    self.deviceSignFingerprint = deviceSignFingerprint
    self.requestedAtMs = requestedAtMs
    self.expiresAtMs = expiresAtMs
  }

  public init(from decoder: Decoder) throws {
    try self.init(decodingFieldsFrom: decoder, allowed: Self.wireKeys)
  }

  init(flattenedFrom decoder: Decoder) throws {
    try runtimeV2ValidateDiscriminator(decoder, key: "stream", expected: "pairingPending")
    try self.init(decodingFieldsFrom: decoder, allowed: Self.wireKeys.union(["stream"]))
  }

  private init(decodingFieldsFrom decoder: Decoder, allowed: Set<String>) throws {
    try runtimeV2RejectUnknownKeys(decoder, allowed: allowed)
    let container = try decoder.container(keyedBy: RuntimeV2CodingKey.self)
    try self.init(
      pairingID: container.decode(RuntimePairingID.self, forKey: runtimeV2Key("pairingId")),
      requestHash: container.decode(Data.self, forKey: runtimeV2Key("requestHash")),
      deviceSignFingerprint: container.decode(
        Data.self,
        forKey: runtimeV2Key("deviceSignFingerprint")
      ),
      requestedAtMs: container.decode(UInt64.self, forKey: runtimeV2Key("requestedAtMs")),
      expiresAtMs: container.decode(UInt64.self, forKey: runtimeV2Key("expiresAtMs"))
    )
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: RuntimeV2CodingKey.self)
    try encodeFields(into: &container)
  }

  func encodeFields(into container: inout KeyedEncodingContainer<RuntimeV2CodingKey>) throws {
    try runtimeV3RequireData(requestHash, count: 32, nonzero: true)
    try runtimeV3RequireData(deviceSignFingerprint, count: 32, nonzero: true)
    guard requestedAtMs <= expiresAtMs else {
      throw RuntimeV3MirrorError.invalidPairingPayload
    }
    try container.encode(pairingID, forKey: runtimeV2Key("pairingId"))
    try container.encode(requestHash, forKey: runtimeV2Key("requestHash"))
    try container.encode(
      deviceSignFingerprint,
      forKey: runtimeV2Key("deviceSignFingerprint")
    )
    try container.encode(requestedAtMs, forKey: runtimeV2Key("requestedAtMs"))
    try container.encode(expiresAtMs, forKey: runtimeV2Key("expiresAtMs"))
  }

  private static let wireKeys: Set<String> = [
    "pairingId", "requestHash", "deviceSignFingerprint", "requestedAtMs", "expiresAtMs",
  ]
}

public enum RuntimePairingDecisionV4: String, Codable, Sendable {
  case confirm
  case cancel
  case expire
}

public enum RuntimePairingStateV4: String, Codable, Sendable {
  case routeOpening
  case unused
  case preparing
  case awaitingLocalConfirmation
  case grantPreparing
  case grantCommitted
  case orphanRevoking
  case delivered
  case expired
  case canceled
  case closedTombstone
}

public enum RuntimePairingReceiptV4: Codable, Sendable {
  case confirmed(RuntimePairingID)
  case canceled(RuntimePairingID)
  case expired(RuntimePairingID)
  case replayed(RuntimePairingID, decision: RuntimePairingDecisionV4, state: RuntimePairingStateV4)
  case alreadyHandled(
    RuntimePairingID,
    winner: RuntimePairingDecisionV4,
    state: RuntimePairingStateV4
  )
  case failed(RuntimeFailureV1)

  public init(from decoder: Decoder) throws {
    try self.init(decodingFieldsFrom: decoder, flattened: false)
  }

  init(flattenedFrom decoder: Decoder) throws {
    try runtimeV2ValidateDiscriminator(decoder, key: "reply", expected: "pairing")
    try self.init(decodingFieldsFrom: decoder, flattened: true)
  }

  private init(decodingFieldsFrom decoder: Decoder, flattened: Bool) throws {
    let container = try decoder.container(keyedBy: RuntimeV2CodingKey.self)
    let status = try container.decode(String.self, forKey: runtimeV2Key("status"))
    let outer: Set<String> = flattened ? ["reply"] : []
    switch status {
    case "confirmed", "canceled", "expired":
      try runtimeV2RejectUnknownKeys(
        decoder,
        allowed: Set(["status", "pairingId"]).union(outer)
      )
      let pairingID = try container.decode(
        RuntimePairingID.self,
        forKey: runtimeV2Key("pairingId")
      )
      switch status {
      case "confirmed": self = .confirmed(pairingID)
      case "canceled": self = .canceled(pairingID)
      default: self = .expired(pairingID)
      }
    case "replayed":
      try runtimeV2RejectUnknownKeys(
        decoder,
        allowed: Set(["status", "pairingId", "decision", "state"]).union(outer)
      )
      self = .replayed(
        try container.decode(RuntimePairingID.self, forKey: runtimeV2Key("pairingId")),
        decision: try container.decode(
          RuntimePairingDecisionV4.self,
          forKey: runtimeV2Key("decision")
        ),
        state: try container.decode(RuntimePairingStateV4.self, forKey: runtimeV2Key("state"))
      )
    case "alreadyHandled":
      try runtimeV2RejectUnknownKeys(
        decoder,
        allowed: Set(["status", "pairingId", "winner", "state"]).union(outer)
      )
      self = .alreadyHandled(
        try container.decode(RuntimePairingID.self, forKey: runtimeV2Key("pairingId")),
        winner: try container.decode(
          RuntimePairingDecisionV4.self,
          forKey: runtimeV2Key("winner")
        ),
        state: try container.decode(RuntimePairingStateV4.self, forKey: runtimeV2Key("state"))
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
        debugDescription: "unsupported Runtime v5 pairing status \(status)"
      )
    }
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: RuntimeV2CodingKey.self)
    try encodeFields(into: &container)
  }

  func encodeFields(into container: inout KeyedEncodingContainer<RuntimeV2CodingKey>) throws {
    switch self {
    case .confirmed(let pairingID):
      try encodeSimple("confirmed", pairingID: pairingID, into: &container)
    case .canceled(let pairingID):
      try encodeSimple("canceled", pairingID: pairingID, into: &container)
    case .expired(let pairingID):
      try encodeSimple("expired", pairingID: pairingID, into: &container)
    case .replayed(let pairingID, let decision, let state):
      try encodeSimple("replayed", pairingID: pairingID, into: &container)
      try container.encode(decision, forKey: runtimeV2Key("decision"))
      try container.encode(state, forKey: runtimeV2Key("state"))
    case .alreadyHandled(let pairingID, let winner, let state):
      try encodeSimple("alreadyHandled", pairingID: pairingID, into: &container)
      try container.encode(winner, forKey: runtimeV2Key("winner"))
      try container.encode(state, forKey: runtimeV2Key("state"))
    case .failed(let failure):
      try container.encode("failed", forKey: runtimeV2Key("status"))
      try container.encode(failure, forKey: runtimeV2Key("failure"))
    }
  }

  private func encodeSimple(
    _ status: String,
    pairingID: RuntimePairingID,
    into container: inout KeyedEncodingContainer<RuntimeV2CodingKey>
  ) throws {
    try container.encode(status, forKey: runtimeV2Key("status"))
    try container.encode(pairingID, forKey: runtimeV2Key("pairingId"))
  }
}

// MARK: - Runtime v3 machine administration

public enum RuntimeV3MirrorError: Error, Equatable, Sendable {
  case invalidEnrollmentBundleVersion
  case invalidBinaryLength
  case invalidFailureCode
  case invalidAdminPurgeReadback
  case invalidAdminPurgeReceipt
  case invalidUninstallPurgePlan
  case invalidMachineRemoteStatus
  case zeroMachineRemoteBinding
  case invalidPairingPayload
}

private func runtimeV3RequireData(
  _ value: Data,
  count: Int,
  nonzero: Bool = false
) throws {
  guard value.count == count else { throw RuntimeV3MirrorError.invalidBinaryLength }
  if nonzero, value.allSatisfy({ $0 == 0 }) {
    throw RuntimeV3MirrorError.zeroMachineRemoteBinding
  }
}

private func runtimeV3URLSafeBase64NoPadding(_ value: Data) -> String {
  value.base64EncodedString()
    .replacingOccurrences(of: "+", with: "-")
    .replacingOccurrences(of: "/", with: "_")
    .replacingOccurrences(of: "=", with: "")
}

private func runtimeV3DecodeURLSafeBase64NoPadding(_ value: String) throws -> Data {
  guard !value.contains("=") else { throw RuntimeV3MirrorError.invalidBinaryLength }
  var standard =
    value
    .replacingOccurrences(of: "-", with: "+")
    .replacingOccurrences(of: "_", with: "/")
  standard += String(repeating: "=", count: (4 - standard.utf8.count % 4) % 4)
  guard let decoded = Data(base64Encoded: standard),
    runtimeV3URLSafeBase64NoPadding(decoded) == value
  else {
    throw RuntimeV3MirrorError.invalidBinaryLength
  }
  return decoded
}

private func runtimeV3DecodeStandardBase64(
  _ value: String,
  count: Int,
  nonzero: Bool = false
) throws -> Data {
  guard let decoded = Data(base64Encoded: value), decoded.base64EncodedString() == value else {
    throw RuntimeV3MirrorError.invalidBinaryLength
  }
  try runtimeV3RequireData(decoded, count: count, nonzero: nonzero)
  return decoded
}

private func runtimeV3EncodeStandardBase64(
  _ value: Data,
  count: Int,
  nonzero: Bool = false
) throws -> String {
  try runtimeV3RequireData(value, count: count, nonzero: nonzero)
  return value.base64EncodedString()
}

private func runtimeV3ValidateHelperPath(_ value: String) throws {
  let components = value.split(separator: "/", omittingEmptySubsequences: false)
  guard !value.isEmpty, value.utf8.count <= 1024, !value.utf8.contains(0),
    value.hasPrefix("/"), value != "/", !value.hasSuffix("/"),
    components.first?.isEmpty == true,
    components.dropFirst().allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." })
  else {
    throw RuntimeV3MirrorError.invalidUninstallPurgePlan
  }
}

private func runtimeV3ValidateHelperVersion(_ value: String) throws {
  guard !value.isEmpty, value != ".", value != "..", value.utf8.count <= 128,
    value.utf8.allSatisfy({ byte in
      (UInt8(ascii: "a")...UInt8(ascii: "z")).contains(byte)
        || (UInt8(ascii: "A")...UInt8(ascii: "Z")).contains(byte)
        || (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(byte)
        || [UInt8(ascii: "."), UInt8(ascii: "_"), UInt8(ascii: "+"), UInt8(ascii: "-")]
          .contains(byte)
    })
  else {
    throw RuntimeV3MirrorError.invalidUninstallPurgePlan
  }
}

private func runtimeV3ValidateTeamIdentifier(_ value: String) throws {
  guard !value.isEmpty, value != "TEAMID", value.utf8.count <= 64,
    value.utf8.allSatisfy({ byte in
      (UInt8(ascii: "a")...UInt8(ascii: "z")).contains(byte)
        || (UInt8(ascii: "A")...UInt8(ascii: "Z")).contains(byte)
        || (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(byte)
    })
  else {
    throw RuntimeV3MirrorError.invalidUninstallPurgePlan
  }
}

private func runtimeV3AppendLengthPrefixed(_ value: some DataProtocol, to output: inout Data) {
  let length = UInt32(value.count)
  output.append(UInt8((length >> 24) & 0xff))
  output.append(UInt8((length >> 16) & 0xff))
  output.append(UInt8((length >> 8) & 0xff))
  output.append(UInt8(length & 0xff))
  output.append(contentsOf: value)
}

private func runtimeV3RotateRight(_ value: UInt32, by count: UInt32) -> UInt32 {
  (value >> count) | (value << (32 - count))
}

/// AgentDeckCore 保持 Foundation-only；这里实现固定 SHA-256 primitive，只用于验证
/// Runtime uninstall planId，不引入 CryptoKit 或平台 UI 依赖。
private func runtimeV3SHA256(_ input: Data) -> Data {
  let constants: [UInt32] = [
    0x428a_2f98, 0x7137_4491, 0xb5c0_fbcf, 0xe9b5_dba5,
    0x3956_c25b, 0x59f1_11f1, 0x923f_82a4, 0xab1c_5ed5,
    0xd807_aa98, 0x1283_5b01, 0x2431_85be, 0x550c_7dc3,
    0x72be_5d74, 0x80de_b1fe, 0x9bdc_06a7, 0xc19b_f174,
    0xe49b_69c1, 0xefbe_4786, 0x0fc1_9dc6, 0x240c_a1cc,
    0x2de9_2c6f, 0x4a74_84aa, 0x5cb0_a9dc, 0x76f9_88da,
    0x983e_5152, 0xa831_c66d, 0xb003_27c8, 0xbf59_7fc7,
    0xc6e0_0bf3, 0xd5a7_9147, 0x06ca_6351, 0x1429_2967,
    0x27b7_0a85, 0x2e1b_2138, 0x4d2c_6dfc, 0x5338_0d13,
    0x650a_7354, 0x766a_0abb, 0x81c2_c92e, 0x9272_2c85,
    0xa2bf_e8a1, 0xa81a_664b, 0xc24b_8b70, 0xc76c_51a3,
    0xd192_e819, 0xd699_0624, 0xf40e_3585, 0x106a_a070,
    0x19a4_c116, 0x1e37_6c08, 0x2748_774c, 0x34b0_bcb5,
    0x391c_0cb3, 0x4ed8_aa4a, 0x5b9c_ca4f, 0x682e_6ff3,
    0x748f_82ee, 0x78a5_636f, 0x84c8_7814, 0x8cc7_0208,
    0x90be_fffa, 0xa450_6ceb, 0xbef9_a3f7, 0xc671_78f2,
  ]
  var message = [UInt8](input)
  let bitLength = UInt64(message.count) * 8
  message.append(0x80)
  while message.count % 64 != 56 { message.append(0) }
  for shift in stride(from: 56, through: 0, by: -8) {
    message.append(UInt8((bitLength >> UInt64(shift)) & 0xff))
  }

  var hash: [UInt32] = [
    0x6a09_e667, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a,
    0x510e_527f, 0x9b05_688c, 0x1f83_d9ab, 0x5be0_cd19,
  ]
  for offset in stride(from: 0, to: message.count, by: 64) {
    var words = [UInt32](repeating: 0, count: 64)
    for index in 0..<16 {
      let start = offset + index * 4
      words[index] = UInt32(message[start]) << 24
        | UInt32(message[start + 1]) << 16
        | UInt32(message[start + 2]) << 8
        | UInt32(message[start + 3])
    }
    for index in 16..<64 {
      let s0 = runtimeV3RotateRight(words[index - 15], by: 7)
        ^ runtimeV3RotateRight(words[index - 15], by: 18)
        ^ (words[index - 15] >> 3)
      let s1 = runtimeV3RotateRight(words[index - 2], by: 17)
        ^ runtimeV3RotateRight(words[index - 2], by: 19)
        ^ (words[index - 2] >> 10)
      words[index] = words[index - 16] &+ s0 &+ words[index - 7] &+ s1
    }
    var a = hash[0]
    var b = hash[1]
    var c = hash[2]
    var d = hash[3]
    var e = hash[4]
    var f = hash[5]
    var g = hash[6]
    var h = hash[7]
    for index in 0..<64 {
      let upper = runtimeV3RotateRight(e, by: 6) ^ runtimeV3RotateRight(e, by: 11)
        ^ runtimeV3RotateRight(e, by: 25)
      let choose = (e & f) ^ ((~e) & g)
      let first = h &+ upper &+ choose &+ constants[index] &+ words[index]
      let lower = runtimeV3RotateRight(a, by: 2) ^ runtimeV3RotateRight(a, by: 13)
        ^ runtimeV3RotateRight(a, by: 22)
      let majority = (a & b) ^ (a & c) ^ (b & c)
      let second = lower &+ majority
      h = g
      g = f
      f = e
      e = d &+ first
      d = c
      c = b
      b = a
      a = first &+ second
    }
    hash[0] &+= a
    hash[1] &+= b
    hash[2] &+= c
    hash[3] &+= d
    hash[4] &+= e
    hash[5] &+= f
    hash[6] &+= g
    hash[7] &+= h
  }
  var output = Data()
  output.reserveCapacity(32)
  for word in hash {
    output.append(UInt8((word >> 24) & 0xff))
    output.append(UInt8((word >> 16) & 0xff))
    output.append(UInt8((word >> 8) & 0xff))
    output.append(UInt8(word & 0xff))
  }
  return output
}

public struct RuntimeRelayReceiptVerifyKeyV1: Codable, Sendable {
  public let receiptFormatVersion: UInt16
  public let relayServerID: Data
  public let keyGeneration: UInt64
  public let keyID: Data
  public let publicKey: Data

  private enum CodingKeys: String, CodingKey, CaseIterable {
    case receiptFormatVersion
    case relayServerID = "relayServerId"
    case keyGeneration
    case keyID = "keyId"
    case publicKey
  }

  public init(
    receiptFormatVersion: UInt16,
    relayServerID: Data,
    keyGeneration: UInt64,
    keyID: Data,
    publicKey: Data
  ) throws {
    try runtimeV3RequireData(relayServerID, count: 16)
    try runtimeV3RequireData(keyID, count: 32)
    try runtimeV3RequireData(publicKey, count: 32)
    self.receiptFormatVersion = receiptFormatVersion
    self.relayServerID = relayServerID
    self.keyGeneration = keyGeneration
    self.keyID = keyID
    self.publicKey = publicKey
  }

  public init(from decoder: Decoder) throws {
    try runtimeV2RejectUnknownKeys(
      decoder,
      allowed: Set(CodingKeys.allCases.map(\.rawValue))
    )
    let container = try decoder.container(keyedBy: CodingKeys.self)
    try self.init(
      receiptFormatVersion: container.decode(UInt16.self, forKey: .receiptFormatVersion),
      relayServerID: container.decode(Data.self, forKey: .relayServerID),
      keyGeneration: container.decode(UInt64.self, forKey: .keyGeneration),
      keyID: container.decode(Data.self, forKey: .keyID),
      publicKey: container.decode(Data.self, forKey: .publicKey)
    )
  }
}

public struct RuntimeEnrollmentBundleV2: Codable, Sendable {
  public let version: UInt16
  public let publicWssURL: String
  public let relayServerID: Data
  public let receiptVerifyKey: RuntimeRelayReceiptVerifyKeyV1
  public let code: Data
  public let spkiPins: [Data]
  public let expiresAtMs: UInt64

  private enum CodingKeys: String, CodingKey, CaseIterable {
    case version
    case publicWssURL = "publicWssUrl"
    case relayServerID = "relayServerId"
    case receiptVerifyKey, code, spkiPins, expiresAtMs
  }

  public init(
    version: UInt16,
    publicWssURL: String,
    relayServerID: Data,
    receiptVerifyKey: RuntimeRelayReceiptVerifyKeyV1,
    code: Data,
    spkiPins: [Data],
    expiresAtMs: UInt64
  ) throws {
    guard version == 2 else { throw RuntimeV3MirrorError.invalidEnrollmentBundleVersion }
    try runtimeV3RequireData(relayServerID, count: 16)
    try runtimeV3RequireData(code, count: 32)
    for pin in spkiPins {
      try runtimeV3RequireData(pin, count: 32)
    }
    self.version = version
    self.publicWssURL = publicWssURL
    self.relayServerID = relayServerID
    self.receiptVerifyKey = receiptVerifyKey
    self.code = code
    self.spkiPins = spkiPins
    self.expiresAtMs = expiresAtMs
  }

  public init(from decoder: Decoder) throws {
    try runtimeV2RejectUnknownKeys(
      decoder,
      allowed: Set(CodingKeys.allCases.map(\.rawValue))
    )
    let container = try decoder.container(keyedBy: CodingKeys.self)
    let encodedPins = try container.decode([String].self, forKey: .spkiPins)
    try self.init(
      version: container.decode(UInt16.self, forKey: .version),
      publicWssURL: container.decode(String.self, forKey: .publicWssURL),
      relayServerID: container.decode(Data.self, forKey: .relayServerID),
      receiptVerifyKey: container.decode(
        RuntimeRelayReceiptVerifyKeyV1.self,
        forKey: .receiptVerifyKey
      ),
      code: container.decode(Data.self, forKey: .code),
      spkiPins: try encodedPins.map(runtimeV3DecodeURLSafeBase64NoPadding),
      expiresAtMs: container.decode(UInt64.self, forKey: .expiresAtMs)
    )
  }

  public func encode(to encoder: Encoder) throws {
    _ = try RuntimeEnrollmentBundleV2(
      version: version,
      publicWssURL: publicWssURL,
      relayServerID: relayServerID,
      receiptVerifyKey: receiptVerifyKey,
      code: code,
      spkiPins: spkiPins,
      expiresAtMs: expiresAtMs
    )
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(version, forKey: .version)
    try container.encode(publicWssURL, forKey: .publicWssURL)
    try container.encode(relayServerID, forKey: .relayServerID)
    try container.encode(receiptVerifyKey, forKey: .receiptVerifyKey)
    try container.encode(code, forKey: .code)
    try container.encode(spkiPins.map(runtimeV3URLSafeBase64NoPadding), forKey: .spkiPins)
    try container.encode(expiresAtMs, forKey: .expiresAtMs)
  }
}

public struct RuntimeMachineEnrollRequestV3: RuntimeV2FlattenedPayload {
  public let bundle: RuntimeEnrollmentBundleV2
  public let scope: RuntimeLocalOnlyAdministrationV1

  public init(
    bundle: RuntimeEnrollmentBundleV2,
    scope: RuntimeLocalOnlyAdministrationV1
  ) {
    self.bundle = bundle
    self.scope = scope
  }

  public init(from decoder: Decoder) throws {
    try self.init(decodingFieldsFrom: decoder, allowed: ["bundle", "scope"])
  }

  init(flattenedFrom decoder: Decoder) throws {
    try runtimeV2ValidateDiscriminator(decoder, key: "request", expected: "machineEnroll")
    try self.init(
      decodingFieldsFrom: decoder,
      allowed: ["request", "bundle", "scope"]
    )
  }

  private init(decodingFieldsFrom decoder: Decoder, allowed: Set<String>) throws {
    try runtimeV2RejectUnknownKeys(decoder, allowed: allowed)
    let container = try decoder.container(keyedBy: RuntimeV2CodingKey.self)
    self.init(
      bundle: try container.decode(
        RuntimeEnrollmentBundleV2.self,
        forKey: runtimeV2Key("bundle")
      ),
      scope: try container.decode(
        RuntimeLocalOnlyAdministrationV1.self,
        forKey: runtimeV2Key("scope")
      )
    )
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: RuntimeV2CodingKey.self)
    try encodeFields(into: &container, includeDiscriminator: false)
  }

  func encodeFlattenedFields(
    into container: inout KeyedEncodingContainer<RuntimeV2CodingKey>
  ) throws {
    try encodeFields(into: &container, includeDiscriminator: true)
  }

  private func encodeFields(
    into container: inout KeyedEncodingContainer<RuntimeV2CodingKey>,
    includeDiscriminator: Bool
  ) throws {
    if includeDiscriminator {
      try container.encode("machineEnroll", forKey: runtimeV2Key("request"))
    }
    try container.encode(bundle, forKey: runtimeV2Key("bundle"))
    try container.encode(scope, forKey: runtimeV2Key("scope"))
  }
}

public struct RuntimeUninstallPurgePlanV1: Codable, Sendable {
  public static let currentVersion: UInt16 = 1

  public let version: UInt16
  public let planID: Data
  public let helperPath: String
  public let helperVersion: String
  public let helperSHA256: RuntimeArtifactSHA256V2
  public let teamIdentifier: String
  public let keychainAccessGroup: String

  private enum CodingKeys: String, CodingKey, CaseIterable {
    case version
    case planID = "planId"
    case helperPath, helperVersion
    case helperSHA256 = "helperSha256"
    case teamIdentifier, keychainAccessGroup
  }

  public init(
    helperPath: String,
    helperVersion: String,
    helperSHA256: RuntimeArtifactSHA256V2,
    teamIdentifier: String,
    keychainAccessGroup: String
  ) throws {
    try runtimeV3ValidateHelperPath(helperPath)
    try runtimeV3ValidateHelperVersion(helperVersion)
    try runtimeV3ValidateTeamIdentifier(teamIdentifier)
    guard keychainAccessGroup.utf8.count <= 255,
      keychainAccessGroup == "\(teamIdentifier).com.agentdeck.agentdeckd.stable"
    else {
      throw RuntimeV3MirrorError.invalidUninstallPurgePlan
    }
    self.version = Self.currentVersion
    self.planID = try Self.derivePlanID(
      helperPath: helperPath,
      helperVersion: helperVersion,
      helperSHA256: helperSHA256,
      teamIdentifier: teamIdentifier,
      keychainAccessGroup: keychainAccessGroup
    )
    self.helperPath = helperPath
    self.helperVersion = helperVersion
    self.helperSHA256 = helperSHA256
    self.teamIdentifier = teamIdentifier
    self.keychainAccessGroup = keychainAccessGroup
  }

  public static func derivePlanID(
    helperPath: String,
    helperVersion: String,
    helperSHA256: RuntimeArtifactSHA256V2,
    teamIdentifier: String,
    keychainAccessGroup: String
  ) throws -> Data {
    try runtimeV3ValidateHelperPath(helperPath)
    try runtimeV3ValidateHelperVersion(helperVersion)
    try runtimeV3ValidateTeamIdentifier(teamIdentifier)
    guard keychainAccessGroup.utf8.count <= 255,
      keychainAccessGroup == "\(teamIdentifier).com.agentdeck.agentdeckd.stable"
    else {
      throw RuntimeV3MirrorError.invalidUninstallPurgePlan
    }
    var canonical = Data("AgentDeck/UninstallPurgePlanV1\0".utf8)
    canonical.append(UInt8((currentVersion >> 8) & 0xff))
    canonical.append(UInt8(currentVersion & 0xff))
    runtimeV3AppendLengthPrefixed(Data(helperPath.utf8), to: &canonical)
    runtimeV3AppendLengthPrefixed(Data(helperVersion.utf8), to: &canonical)
    runtimeV3AppendLengthPrefixed(Data(helperSHA256.rawValue.utf8), to: &canonical)
    runtimeV3AppendLengthPrefixed(Data(teamIdentifier.utf8), to: &canonical)
    runtimeV3AppendLengthPrefixed(Data(keychainAccessGroup.utf8), to: &canonical)
    let planID = Data(runtimeV3SHA256(canonical).prefix(16))
    try runtimeV3RequireData(planID, count: 16, nonzero: true)
    return planID
  }

  public init(from decoder: Decoder) throws {
    try runtimeV2RejectUnknownKeys(decoder, allowed: Set(CodingKeys.allCases.map(\.rawValue)))
    let container = try decoder.container(keyedBy: CodingKeys.self)
    let version = try container.decode(UInt16.self, forKey: .version)
    guard version == Self.currentVersion else {
      throw RuntimeV3MirrorError.invalidUninstallPurgePlan
    }
    let suppliedPlanID = try runtimeV3DecodeStandardBase64(
      container.decode(String.self, forKey: .planID), count: 16, nonzero: true
    )
    try self.init(
      helperPath: container.decode(String.self, forKey: .helperPath),
      helperVersion: container.decode(String.self, forKey: .helperVersion),
      helperSHA256: container.decode(RuntimeArtifactSHA256V2.self, forKey: .helperSHA256),
      teamIdentifier: container.decode(String.self, forKey: .teamIdentifier),
      keychainAccessGroup: container.decode(String.self, forKey: .keychainAccessGroup)
    )
    guard suppliedPlanID == planID else {
      throw RuntimeV3MirrorError.invalidUninstallPurgePlan
    }
  }

  public func encode(to encoder: Encoder) throws {
    let expected = try RuntimeUninstallPurgePlanV1(
      helperPath: helperPath,
      helperVersion: helperVersion,
      helperSHA256: helperSHA256,
      teamIdentifier: teamIdentifier,
      keychainAccessGroup: keychainAccessGroup
    )
    guard version == Self.currentVersion, planID == expected.planID else {
      throw RuntimeV3MirrorError.invalidUninstallPurgePlan
    }
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(version, forKey: .version)
    try container.encode(
      runtimeV3EncodeStandardBase64(planID, count: 16, nonzero: true), forKey: .planID
    )
    try container.encode(helperPath, forKey: .helperPath)
    try container.encode(helperVersion, forKey: .helperVersion)
    try container.encode(helperSHA256, forKey: .helperSHA256)
    try container.encode(teamIdentifier, forKey: .teamIdentifier)
    try container.encode(keychainAccessGroup, forKey: .keychainAccessGroup)
  }
}

public enum RuntimeRelayMachineTombstoneKindV1: String, Codable, Equatable, Sendable {
  case rootLostAdminPurge
}

public struct RuntimeRelayAdminPurgeReadbackV1: Codable, Sendable {
  public let activeMachineRoutes: UInt64
  public let retiredTombstones: UInt64
  public let consumedEnrollmentRecords: UInt64
  public let deviceGrants: UInt64
  public let revocations: UInt64
  public let streams: UInt64
  public let frames: UInt64
  public let subscriptions: UInt64
  public let retirementHash: Data?
  public let retirementTerminalPresent: Bool

  private enum CodingKeys: String, CodingKey, CaseIterable {
    case activeMachineRoutes, retiredTombstones, consumedEnrollmentRecords, deviceGrants
    case revocations, streams, frames, subscriptions, retirementHash, retirementTerminalPresent
  }

  public init(
    activeMachineRoutes: UInt64,
    retiredTombstones: UInt64,
    consumedEnrollmentRecords: UInt64,
    deviceGrants: UInt64,
    revocations: UInt64,
    streams: UInt64,
    frames: UInt64,
    subscriptions: UInt64,
    retirementHash: Data?,
    retirementTerminalPresent: Bool
  ) throws {
    guard activeMachineRoutes == 0, retiredTombstones == 1,
      consumedEnrollmentRecords == 0, deviceGrants == 0, revocations == 0,
      streams == 0, frames == 0, subscriptions == 0,
      retirementHash == nil, !retirementTerminalPresent
    else {
      throw RuntimeV3MirrorError.invalidAdminPurgeReadback
    }
    self.activeMachineRoutes = activeMachineRoutes
    self.retiredTombstones = retiredTombstones
    self.consumedEnrollmentRecords = consumedEnrollmentRecords
    self.deviceGrants = deviceGrants
    self.revocations = revocations
    self.streams = streams
    self.frames = frames
    self.subscriptions = subscriptions
    self.retirementHash = retirementHash
    self.retirementTerminalPresent = retirementTerminalPresent
  }

  public init(from decoder: Decoder) throws {
    try runtimeV2RejectUnknownKeys(decoder, allowed: Set(CodingKeys.allCases.map(\.rawValue)))
    let container = try decoder.container(keyedBy: CodingKeys.self)
    let encodedRetirementHash = try container.decodeIfPresent(String.self, forKey: .retirementHash)
    try self.init(
      activeMachineRoutes: container.decode(UInt64.self, forKey: .activeMachineRoutes),
      retiredTombstones: container.decode(UInt64.self, forKey: .retiredTombstones),
      consumedEnrollmentRecords: container.decode(UInt64.self, forKey: .consumedEnrollmentRecords),
      deviceGrants: container.decode(UInt64.self, forKey: .deviceGrants),
      revocations: container.decode(UInt64.self, forKey: .revocations),
      streams: container.decode(UInt64.self, forKey: .streams),
      frames: container.decode(UInt64.self, forKey: .frames),
      subscriptions: container.decode(UInt64.self, forKey: .subscriptions),
      retirementHash: try encodedRetirementHash.map {
        try runtimeV3DecodeStandardBase64($0, count: 32)
      },
      retirementTerminalPresent: container.decode(Bool.self, forKey: .retirementTerminalPresent)
    )
  }

  public func encode(to encoder: Encoder) throws {
    _ = try RuntimeRelayAdminPurgeReadbackV1(
      activeMachineRoutes: activeMachineRoutes,
      retiredTombstones: retiredTombstones,
      consumedEnrollmentRecords: consumedEnrollmentRecords,
      deviceGrants: deviceGrants,
      revocations: revocations,
      streams: streams,
      frames: frames,
      subscriptions: subscriptions,
      retirementHash: retirementHash,
      retirementTerminalPresent: retirementTerminalPresent
    )
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(activeMachineRoutes, forKey: .activeMachineRoutes)
    try container.encode(retiredTombstones, forKey: .retiredTombstones)
    try container.encode(consumedEnrollmentRecords, forKey: .consumedEnrollmentRecords)
    try container.encode(deviceGrants, forKey: .deviceGrants)
    try container.encode(revocations, forKey: .revocations)
    try container.encode(streams, forKey: .streams)
    try container.encode(frames, forKey: .frames)
    try container.encode(subscriptions, forKey: .subscriptions)
    if let retirementHash {
      try container.encode(
        runtimeV3EncodeStandardBase64(retirementHash, count: 32),
        forKey: .retirementHash
      )
    }
    try container.encode(retirementTerminalPresent, forKey: .retirementTerminalPresent)
  }
}

public struct RuntimeRelayAdminPurgeReceiptV1: Codable, Sendable {
  public let receiptFormatVersion: UInt16
  public let relayProtocolVersion: UInt16
  public let relayServerID: Data
  public let receiptKeyGeneration: UInt64
  public let receiptKeyID: Data
  public let machineRoute: Data
  public let rootKeyID: Data
  public let rootFingerprint: Data
  public let trustEpoch: UInt64
  public let enrollmentReceiptHash: Data
  public let purgeRequestHash: Data
  public let tombstoneKind: RuntimeRelayMachineTombstoneKindV1
  public let readback: RuntimeRelayAdminPurgeReadbackV1
  public let tombstoneHash: Data
  public let signature: Data

  private enum CodingKeys: String, CodingKey, CaseIterable {
    case receiptFormatVersion, relayProtocolVersion
    case relayServerID = "relayServerId"
    case receiptKeyGeneration
    case receiptKeyID = "receiptKeyId"
    case machineRoute
    case rootKeyID = "rootKeyId"
    case rootFingerprint, trustEpoch, enrollmentReceiptHash, purgeRequestHash
    case tombstoneKind, readback, tombstoneHash, signature
  }

  public init(
    receiptFormatVersion: UInt16,
    relayProtocolVersion: UInt16,
    relayServerID: Data,
    receiptKeyGeneration: UInt64,
    receiptKeyID: Data,
    machineRoute: Data,
    rootKeyID: Data,
    rootFingerprint: Data,
    trustEpoch: UInt64,
    enrollmentReceiptHash: Data,
    purgeRequestHash: Data,
    tombstoneKind: RuntimeRelayMachineTombstoneKindV1,
    readback: RuntimeRelayAdminPurgeReadbackV1,
    tombstoneHash: Data,
    signature: Data
  ) throws {
    guard receiptFormatVersion == 1, relayProtocolVersion == 2,
      receiptKeyGeneration == 1, trustEpoch > 0,
      tombstoneKind == .rootLostAdminPurge
    else {
      throw RuntimeV3MirrorError.invalidAdminPurgeReceipt
    }
    try runtimeV3RequireData(relayServerID, count: 16, nonzero: true)
    try runtimeV3RequireData(receiptKeyID, count: 32, nonzero: true)
    try runtimeV3RequireData(machineRoute, count: 16, nonzero: true)
    try runtimeV3RequireData(rootKeyID, count: 16, nonzero: true)
    try runtimeV3RequireData(rootFingerprint, count: 32, nonzero: true)
    try runtimeV3RequireData(enrollmentReceiptHash, count: 32, nonzero: true)
    try runtimeV3RequireData(purgeRequestHash, count: 32, nonzero: true)
    try runtimeV3RequireData(tombstoneHash, count: 32, nonzero: true)
    try runtimeV3RequireData(signature, count: 64)
    self.receiptFormatVersion = receiptFormatVersion
    self.relayProtocolVersion = relayProtocolVersion
    self.relayServerID = relayServerID
    self.receiptKeyGeneration = receiptKeyGeneration
    self.receiptKeyID = receiptKeyID
    self.machineRoute = machineRoute
    self.rootKeyID = rootKeyID
    self.rootFingerprint = rootFingerprint
    self.trustEpoch = trustEpoch
    self.enrollmentReceiptHash = enrollmentReceiptHash
    self.purgeRequestHash = purgeRequestHash
    self.tombstoneKind = tombstoneKind
    self.readback = readback
    self.tombstoneHash = tombstoneHash
    self.signature = signature
  }

  public init(from decoder: Decoder) throws {
    try runtimeV2RejectUnknownKeys(decoder, allowed: Set(CodingKeys.allCases.map(\.rawValue)))
    let container = try decoder.container(keyedBy: CodingKeys.self)
    try self.init(
      receiptFormatVersion: container.decode(UInt16.self, forKey: .receiptFormatVersion),
      relayProtocolVersion: container.decode(UInt16.self, forKey: .relayProtocolVersion),
      relayServerID: try runtimeV3DecodeStandardBase64(
        container.decode(String.self, forKey: .relayServerID), count: 16, nonzero: true
      ),
      receiptKeyGeneration: container.decode(UInt64.self, forKey: .receiptKeyGeneration),
      receiptKeyID: try runtimeV3DecodeStandardBase64(
        container.decode(String.self, forKey: .receiptKeyID), count: 32, nonzero: true
      ),
      machineRoute: try runtimeV3DecodeStandardBase64(
        container.decode(String.self, forKey: .machineRoute), count: 16, nonzero: true
      ),
      rootKeyID: try runtimeV3DecodeStandardBase64(
        container.decode(String.self, forKey: .rootKeyID), count: 16, nonzero: true
      ),
      rootFingerprint: try runtimeV3DecodeStandardBase64(
        container.decode(String.self, forKey: .rootFingerprint), count: 32, nonzero: true
      ),
      trustEpoch: container.decode(UInt64.self, forKey: .trustEpoch),
      enrollmentReceiptHash: try runtimeV3DecodeStandardBase64(
        container.decode(String.self, forKey: .enrollmentReceiptHash), count: 32, nonzero: true
      ),
      purgeRequestHash: try runtimeV3DecodeStandardBase64(
        container.decode(String.self, forKey: .purgeRequestHash), count: 32, nonzero: true
      ),
      tombstoneKind: container.decode(
        RuntimeRelayMachineTombstoneKindV1.self, forKey: .tombstoneKind
      ),
      readback: container.decode(RuntimeRelayAdminPurgeReadbackV1.self, forKey: .readback),
      tombstoneHash: try runtimeV3DecodeStandardBase64(
        container.decode(String.self, forKey: .tombstoneHash), count: 32, nonzero: true
      ),
      signature: try runtimeV3DecodeStandardBase64(
        container.decode(String.self, forKey: .signature), count: 64
      )
    )
  }

  public func encode(to encoder: Encoder) throws {
    _ = try RuntimeRelayAdminPurgeReceiptV1(
      receiptFormatVersion: receiptFormatVersion,
      relayProtocolVersion: relayProtocolVersion,
      relayServerID: relayServerID,
      receiptKeyGeneration: receiptKeyGeneration,
      receiptKeyID: receiptKeyID,
      machineRoute: machineRoute,
      rootKeyID: rootKeyID,
      rootFingerprint: rootFingerprint,
      trustEpoch: trustEpoch,
      enrollmentReceiptHash: enrollmentReceiptHash,
      purgeRequestHash: purgeRequestHash,
      tombstoneKind: tombstoneKind,
      readback: readback,
      tombstoneHash: tombstoneHash,
      signature: signature
    )
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(receiptFormatVersion, forKey: .receiptFormatVersion)
    try container.encode(relayProtocolVersion, forKey: .relayProtocolVersion)
    try container.encode(
      runtimeV3EncodeStandardBase64(relayServerID, count: 16, nonzero: true),
      forKey: .relayServerID
    )
    try container.encode(receiptKeyGeneration, forKey: .receiptKeyGeneration)
    try container.encode(
      runtimeV3EncodeStandardBase64(receiptKeyID, count: 32, nonzero: true),
      forKey: .receiptKeyID
    )
    try container.encode(
      runtimeV3EncodeStandardBase64(machineRoute, count: 16, nonzero: true),
      forKey: .machineRoute
    )
    try container.encode(
      runtimeV3EncodeStandardBase64(rootKeyID, count: 16, nonzero: true), forKey: .rootKeyID
    )
    try container.encode(
      runtimeV3EncodeStandardBase64(rootFingerprint, count: 32, nonzero: true),
      forKey: .rootFingerprint
    )
    try container.encode(trustEpoch, forKey: .trustEpoch)
    try container.encode(
      runtimeV3EncodeStandardBase64(enrollmentReceiptHash, count: 32, nonzero: true),
      forKey: .enrollmentReceiptHash
    )
    try container.encode(
      runtimeV3EncodeStandardBase64(purgeRequestHash, count: 32, nonzero: true),
      forKey: .purgeRequestHash
    )
    try container.encode(tombstoneKind, forKey: .tombstoneKind)
    try container.encode(readback, forKey: .readback)
    try container.encode(
      runtimeV3EncodeStandardBase64(tombstoneHash, count: 32, nonzero: true),
      forKey: .tombstoneHash
    )
    try container.encode(
      runtimeV3EncodeStandardBase64(signature, count: 64), forKey: .signature
    )
  }
}

public enum RuntimeMachineRemoteLifecycleV3: String, Codable, Equatable, Sendable, CaseIterable {
  case unenrolled
  case enrollmentPrepared
  case enrollmentResponseValidated
  case active
  case retirePending
  case relayCommitted
  case purgeReadbackAbsent
  case localDeleted
  case blocked
}

public struct RuntimeMachineRemoteFailureCodeV3: Codable, CustomDebugStringConvertible, Equatable,
  Sendable
{
  public let rawValue: String

  public init(_ rawValue: String) throws {
    guard !rawValue.isEmpty,
      rawValue.utf8.count <= 128,
      rawValue.utf8.allSatisfy({ byte in
        (UInt8(ascii: "a")...UInt8(ascii: "z")).contains(byte)
          || (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(byte)
          || [UInt8(ascii: "."), UInt8(ascii: "_"), UInt8(ascii: "-")].contains(byte)
      })
    else {
      throw RuntimeV3MirrorError.invalidFailureCode
    }
    self.rawValue = rawValue
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.singleValueContainer()
    try self.init(container.decode(String.self))
  }

  public func encode(to encoder: Encoder) throws {
    _ = try RuntimeMachineRemoteFailureCodeV3(rawValue)
    var container = encoder.singleValueContainer()
    try container.encode(rawValue)
  }

  public var debugDescription: String {
    "RuntimeMachineRemoteFailureCodeV3(<redacted>)"
  }
}

public struct RuntimeMachineRemoteStatusV3: Codable, Sendable {
  public let lifecycle: RuntimeMachineRemoteLifecycleV3
  public let relayServerID: Data?
  public let machineRoute: Data?
  public let rootFingerprint: Data?
  public let trustEpoch: UInt64?
  public let failureCode: RuntimeMachineRemoteFailureCodeV3?

  private enum CodingKeys: String, CodingKey, CaseIterable {
    case lifecycle
    case relayServerID = "relayServerId"
    case machineRoute, rootFingerprint, trustEpoch, failureCode
  }

  public init(
    lifecycle: RuntimeMachineRemoteLifecycleV3,
    relayServerID: Data?,
    machineRoute: Data?,
    rootFingerprint: Data?,
    trustEpoch: UInt64?,
    failureCode: RuntimeMachineRemoteFailureCodeV3?
  ) throws {
    let present = [
      relayServerID != nil,
      machineRoute != nil,
      rootFingerprint != nil,
      trustEpoch != nil,
    ]
    let none = present.allSatisfy { !$0 }
    let complete = present.allSatisfy { $0 }
    switch lifecycle {
    case .unenrolled:
      guard none, failureCode == nil else {
        throw RuntimeV3MirrorError.invalidMachineRemoteStatus
      }
    case .blocked:
      guard none || complete, failureCode != nil else {
        throw RuntimeV3MirrorError.invalidMachineRemoteStatus
      }
    default:
      guard complete, failureCode == nil else {
        throw RuntimeV3MirrorError.invalidMachineRemoteStatus
      }
    }
    if complete {
      try runtimeV3RequireData(relayServerID!, count: 16, nonzero: true)
      try runtimeV3RequireData(machineRoute!, count: 16, nonzero: true)
      try runtimeV3RequireData(rootFingerprint!, count: 32, nonzero: true)
      guard trustEpoch! > 0 else { throw RuntimeV3MirrorError.zeroMachineRemoteBinding }
    }
    self.lifecycle = lifecycle
    self.relayServerID = relayServerID
    self.machineRoute = machineRoute
    self.rootFingerprint = rootFingerprint
    self.trustEpoch = trustEpoch
    self.failureCode = failureCode
  }

  public init(from decoder: Decoder) throws {
    try self.init(
      decodingFieldsFrom: decoder,
      allowed: Set(CodingKeys.allCases.map(\.rawValue))
    )
  }

  init(flattenedFrom decoder: Decoder) throws {
    try runtimeV2ValidateDiscriminator(
      decoder,
      key: "reply",
      expected: "machineRemoteStatus"
    )
    try self.init(
      decodingFieldsFrom: decoder,
      allowed: Set(CodingKeys.allCases.map(\.rawValue)).union(["reply"])
    )
  }

  private init(decodingFieldsFrom decoder: Decoder, allowed: Set<String>) throws {
    try runtimeV2RejectUnknownKeys(decoder, allowed: allowed)
    let container = try decoder.container(keyedBy: CodingKeys.self)
    try self.init(
      lifecycle: container.decode(RuntimeMachineRemoteLifecycleV3.self, forKey: .lifecycle),
      relayServerID: container.decodeIfPresent(Data.self, forKey: .relayServerID),
      machineRoute: container.decodeIfPresent(Data.self, forKey: .machineRoute),
      rootFingerprint: container.decodeIfPresent(Data.self, forKey: .rootFingerprint),
      trustEpoch: container.decodeIfPresent(UInt64.self, forKey: .trustEpoch),
      failureCode: container.decodeIfPresent(
        RuntimeMachineRemoteFailureCodeV3.self,
        forKey: .failureCode
      )
    )
  }

  public func encode(to encoder: Encoder) throws {
    _ = try RuntimeMachineRemoteStatusV3(
      lifecycle: lifecycle,
      relayServerID: relayServerID,
      machineRoute: machineRoute,
      rootFingerprint: rootFingerprint,
      trustEpoch: trustEpoch,
      failureCode: failureCode
    )
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(lifecycle, forKey: .lifecycle)
    try container.encodeIfPresent(relayServerID, forKey: .relayServerID)
    try container.encodeIfPresent(machineRoute, forKey: .machineRoute)
    try container.encodeIfPresent(rootFingerprint, forKey: .rootFingerprint)
    try container.encodeIfPresent(trustEpoch, forKey: .trustEpoch)
    try container.encodeIfPresent(failureCode, forKey: .failureCode)
  }

  func encodeFlattenedFields(
    into container: inout KeyedEncodingContainer<RuntimeV2CodingKey>
  ) throws {
    _ = try RuntimeMachineRemoteStatusV3(
      lifecycle: lifecycle,
      relayServerID: relayServerID,
      machineRoute: machineRoute,
      rootFingerprint: rootFingerprint,
      trustEpoch: trustEpoch,
      failureCode: failureCode
    )
    try container.encode("machineRemoteStatus", forKey: runtimeV2Key("reply"))
    try container.encode(lifecycle, forKey: runtimeV2Key("lifecycle"))
    try container.encodeIfPresent(relayServerID, forKey: runtimeV2Key("relayServerId"))
    try container.encodeIfPresent(machineRoute, forKey: runtimeV2Key("machineRoute"))
    try container.encodeIfPresent(rootFingerprint, forKey: runtimeV2Key("rootFingerprint"))
    try container.encodeIfPresent(trustEpoch, forKey: runtimeV2Key("trustEpoch"))
    try container.encodeIfPresent(failureCode, forKey: runtimeV2Key("failureCode"))
  }
}
