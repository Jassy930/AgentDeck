import Foundation

// MARK: - AnyCodable (type-erased JSON value)

/// Type-erased JSON value carrier. Used inside `AgentItem` payload slots
/// (e.g. `toolCall.args`, `meta.vendorExtensions`) where the wire shape is
/// schema-less by design.
public struct AnyCodable: Codable, @unchecked Sendable {
    public let value: Any

    public init(_ value: Any) { self.value = value }

    public init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() {
            self.value = NSNull()
        } else if let v = try? c.decode(Bool.self) {
            self.value = v
        } else if let v = try? c.decode(Int64.self) {
            self.value = v
        } else if let v = try? c.decode(Double.self) {
            self.value = v
        } else if let v = try? c.decode(String.self) {
            self.value = v
        } else if let v = try? c.decode([AnyCodable].self) {
            self.value = v.map(\.value)
        } else if let v = try? c.decode([String: AnyCodable].self) {
            self.value = v.mapValues(\.value)
        } else {
            self.value = NSNull()
        }
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch value {
        case is NSNull: try c.encodeNil()
        case let v as Bool: try c.encode(v)
        case let v as Int: try c.encode(v)
        case let v as Int64: try c.encode(v)
        case let v as Double: try c.encode(v)
        case let v as String: try c.encode(v)
        case let v as [Any]: try c.encode(v.map(AnyCodable.init))
        case let v as [String: Any]: try c.encode(v.mapValues(AnyCodable.init))
        default: try c.encodeNil()
        }
    }
}

// MARK: - AgentKind

public enum AgentKind: String, Codable, Hashable, Sendable {
    case codex
    case claudeCode = "claude_code"
}

// MARK: - CapabilityId

public enum CapabilityId: String, Codable, Hashable, Sendable {
    // Shared
    case streamingMessages
    case streamingReasoning
    case shell
    case diff
    case approval
    case mcp
    case tokenCounters
    case authStatus
    case reasoningEffort
    case imageInput
    case worktree

    // Codex-only
    case codexSandboxMode
    case codexApprovalPersistence
    case codexSkills
    case codexCustomPrompts

    // Claude-Code-only
    case claudeCodePermissionMode
    case claudeCodeHooks
    case claudeCodeOutputStyle
    case claudeCodeSlashCommands
    case claudeCodePlanMode
    case claudeCodeBackgroundAgents
    case claudeCodePluginDir
    case claudeCodeForkSession
}

// MARK: - Vendor enums (Codex)

public enum CodexSandboxMode: String, Codable, Hashable, Sendable {
    case readOnly = "read-only"
    case workspaceWrite = "workspace-write"
    case fullAccess = "full-access"
}

public enum CodexReasoningEffort: String, Codable, Hashable, Sendable {
    case minimal, low, medium, high
}

public enum CodexApprovalPolicy: String, Codable, Hashable, Sendable {
    case onRequest = "on-request"
    case never
    case always
}

public struct CodexCapabilities: Codable, Sendable {
    public let sandboxModes: [CodexSandboxMode]
    public let persistenceSupported: Bool
    public let reasoningEffortLevels: [CodexReasoningEffort]

    public init(
        sandboxModes: [CodexSandboxMode],
        persistenceSupported: Bool,
        reasoningEffortLevels: [CodexReasoningEffort]
    ) {
        self.sandboxModes = sandboxModes
        self.persistenceSupported = persistenceSupported
        self.reasoningEffortLevels = reasoningEffortLevels
    }
}

public struct McpOverride: Codable, Sendable {
    public let name: String
    public let enabled: Bool

    public init(name: String, enabled: Bool) {
        self.name = name
        self.enabled = enabled
    }
}

public struct CodexSessionOptions: Codable, Sendable {
    public let approvalPolicy: CodexApprovalPolicy
    public let sandbox: CodexSandboxMode
    public let persistApproval: Bool
    public let reasoningEffort: CodexReasoningEffort
    public let mcpOverrides: [McpOverride]

    public init(
        approvalPolicy: CodexApprovalPolicy,
        sandbox: CodexSandboxMode,
        persistApproval: Bool,
        reasoningEffort: CodexReasoningEffort,
        mcpOverrides: [McpOverride] = []
    ) {
        self.approvalPolicy = approvalPolicy
        self.sandbox = sandbox
        self.persistApproval = persistApproval
        self.reasoningEffort = reasoningEffort
        self.mcpOverrides = mcpOverrides
    }
}

// MARK: - Vendor enums (Claude Code)

public enum ClaudeCodePermissionMode: String, Codable, Hashable, Sendable {
    case `default`
    case acceptEdits
    case plan
    case auto
    case dontAsk
    case bypassPermissions
}

public struct ClaudeCodeCapabilities: Codable, Sendable {
    public let permissionModes: [ClaudeCodePermissionMode]
    public let outputStyles: [String]
    public let hooksSupported: [String]
    public let cliVersion: String

    public init(
        permissionModes: [ClaudeCodePermissionMode],
        outputStyles: [String],
        hooksSupported: [String],
        cliVersion: String
    ) {
        self.permissionModes = permissionModes
        self.outputStyles = outputStyles
        self.hooksSupported = hooksSupported
        self.cliVersion = cliVersion
    }
}

public struct ClaudeCodeHookConfig: Codable, Sendable {
    public let matcher: String
    public let command: String
    public let timeoutMs: UInt32?

    public init(matcher: String, command: String, timeoutMs: UInt32? = nil) {
        self.matcher = matcher
        self.command = command
        self.timeoutMs = timeoutMs
    }
}

public struct ClaudeCodeSessionOptions: Codable, Sendable {
    public let permissionMode: ClaudeCodePermissionMode
    public let model: String?
    public let effort: String?
    public let hooks: [ClaudeCodeHookConfig]
    public let outputStyle: String?
    public let allowedTools: [String]?
    public let disallowedTools: [String]?
    public let mcpConfigPath: String?
    public let pluginDirs: [String]
    public let worktree: String?
    public let sessionName: String?
    public let sessionId: String?

    public init(
        permissionMode: ClaudeCodePermissionMode,
        model: String? = nil,
        effort: String? = nil,
        hooks: [ClaudeCodeHookConfig] = [],
        outputStyle: String? = nil,
        allowedTools: [String]? = nil,
        disallowedTools: [String]? = nil,
        mcpConfigPath: String? = nil,
        pluginDirs: [String] = [],
        worktree: String? = nil,
        sessionName: String? = nil,
        sessionId: String? = nil
    ) {
        self.permissionMode = permissionMode
        self.model = model
        self.effort = effort
        self.hooks = hooks
        self.outputStyle = outputStyle
        self.allowedTools = allowedTools
        self.disallowedTools = disallowedTools
        self.mcpConfigPath = mcpConfigPath
        self.pluginDirs = pluginDirs
        self.worktree = worktree
        self.sessionName = sessionName
        self.sessionId = sessionId
    }
}

// MARK: - SessionCapabilities + VendorCapabilities

public struct SessionCapabilities: Codable, Sendable {
    public let agentKind: AgentKind
    public let agentVersion: String
    public let features: Set<CapabilityId>
    public let vendor: VendorCapabilities

    public init(
        agentKind: AgentKind,
        agentVersion: String,
        features: Set<CapabilityId>,
        vendor: VendorCapabilities
    ) {
        self.agentKind = agentKind
        self.agentVersion = agentVersion
        self.features = features
        self.vendor = vendor
    }
}

/// `#[serde(tag = "agentKind")]` — internally tagged union by agentKind.
public enum VendorCapabilities: Codable, Sendable {
    case codex(CodexCapabilities)
    case claudeCode(ClaudeCodeCapabilities)

    private enum Discriminator: String, CodingKey { case agentKind }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: Discriminator.self)
        let kind = try c.decode(AgentKind.self, forKey: .agentKind)
        switch kind {
        case .codex:
            let caps = try CodexCapabilities(from: decoder)
            self = .codex(caps)
        case .claudeCode:
            let caps = try ClaudeCodeCapabilities(from: decoder)
            self = .claudeCode(caps)
        }
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: Discriminator.self)
        switch self {
        case .codex(let caps):
            try c.encode(AgentKind.codex, forKey: .agentKind)
            try caps.encode(to: encoder)
        case .claudeCode(let caps):
            try c.encode(AgentKind.claudeCode, forKey: .agentKind)
            try caps.encode(to: encoder)
        }
    }
}

// MARK: - AgentItem + helpers

public enum ShellStatus: String, Codable, Sendable {
    case running, completed, failed, canceled
}

public enum DiffStatus: String, Codable, Sendable {
    case added, modified, deleted, renamed
}

public enum PlanStepStatus: String, Codable, Sendable {
    case pending, inProgress, done, failed
}

public struct DiffFile: Codable, Sendable {
    public let path: String
    public let status: DiffStatus
    public let patch: String?

    public init(path: String, status: DiffStatus, patch: String? = nil) {
        self.path = path
        self.status = status
        self.patch = patch
    }
}

public struct PlanStep: Codable, Sendable {
    public let title: String
    public let status: PlanStepStatus
    public let detail: String?

    public init(title: String, status: PlanStepStatus, detail: String? = nil) {
        self.title = title
        self.status = status
        self.detail = detail
    }
}

public struct AgentItemMeta: Codable, Sendable {
    public var vendorExtensions: [String: AnyCodable]

    public init(vendorExtensions: [String: AnyCodable] = [:]) {
        self.vendorExtensions = vendorExtensions
    }
}

/// `#[serde(tag = "kind", rename_all = "camelCase")]` AgentItem with custom Codable.
public enum AgentItem: Sendable {
    case userMessage(text: String, meta: AgentItemMeta)
    case assistantMessage(text: String, meta: AgentItemMeta)
    case reasoning(text: String, meta: AgentItemMeta)
    case shell(command: String, status: ShellStatus, exitCode: Int?, durationMs: UInt64?, meta: AgentItemMeta)
    case diff(files: [DiffFile], meta: AgentItemMeta)
    case plan(steps: [PlanStep], meta: AgentItemMeta)
    case imageReference(savedPath: String?, originalPath: String?, meta: AgentItemMeta)
    case toolCall(name: String, args: AnyCodable, result: AnyCodable?, meta: AgentItemMeta)
    case raw(rawKind: String, rawPayload: String, meta: AgentItemMeta)

    public var kindLabel: String {
        switch self {
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
}

extension AgentItem: Codable {
    private enum CodingKeys: String, CodingKey {
        case kind, text, command, status, exitCode, durationMs
        case files, steps, savedPath, originalPath
        case name, args, result, rawKind, rawPayload, meta
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let kind = try c.decode(String.self, forKey: .kind)
        let meta = try c.decodeIfPresent(AgentItemMeta.self, forKey: .meta) ?? AgentItemMeta()
        switch kind {
        case "userMessage":
            let text = try c.decode(String.self, forKey: .text)
            self = .userMessage(text: text, meta: meta)
        case "assistantMessage":
            let text = try c.decode(String.self, forKey: .text)
            self = .assistantMessage(text: text, meta: meta)
        case "reasoning":
            let text = try c.decode(String.self, forKey: .text)
            self = .reasoning(text: text, meta: meta)
        case "shell":
            let cmd = try c.decode(String.self, forKey: .command)
            let st = try c.decode(ShellStatus.self, forKey: .status)
            let exit = try c.decodeIfPresent(Int.self, forKey: .exitCode)
            let dur = try c.decodeIfPresent(UInt64.self, forKey: .durationMs)
            self = .shell(command: cmd, status: st, exitCode: exit, durationMs: dur, meta: meta)
        case "diff":
            let files = try c.decode([DiffFile].self, forKey: .files)
            self = .diff(files: files, meta: meta)
        case "plan":
            let steps = try c.decode([PlanStep].self, forKey: .steps)
            self = .plan(steps: steps, meta: meta)
        case "imageReference":
            let saved = try c.decodeIfPresent(String.self, forKey: .savedPath)
            let orig = try c.decodeIfPresent(String.self, forKey: .originalPath)
            self = .imageReference(savedPath: saved, originalPath: orig, meta: meta)
        case "toolCall":
            let name = try c.decode(String.self, forKey: .name)
            let args = try c.decode(AnyCodable.self, forKey: .args)
            let result = try c.decodeIfPresent(AnyCodable.self, forKey: .result)
            self = .toolCall(name: name, args: args, result: result, meta: meta)
        case "raw":
            let rk = try c.decode(String.self, forKey: .rawKind)
            let rp = try c.decode(String.self, forKey: .rawPayload)
            self = .raw(rawKind: rk, rawPayload: rp, meta: meta)
        default:
            throw DecodingError.dataCorruptedError(
                forKey: .kind, in: c, debugDescription: "unknown AgentItem kind: \(kind)"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(kindLabel, forKey: .kind)
        switch self {
        case .userMessage(let text, let meta),
             .assistantMessage(let text, let meta),
             .reasoning(let text, let meta):
            try c.encode(text, forKey: .text)
            try c.encode(meta, forKey: .meta)
        case .shell(let command, let status, let exit, let dur, let meta):
            try c.encode(command, forKey: .command)
            try c.encode(status, forKey: .status)
            try c.encodeIfPresent(exit, forKey: .exitCode)
            try c.encodeIfPresent(dur, forKey: .durationMs)
            try c.encode(meta, forKey: .meta)
        case .diff(let files, let meta):
            try c.encode(files, forKey: .files)
            try c.encode(meta, forKey: .meta)
        case .plan(let steps, let meta):
            try c.encode(steps, forKey: .steps)
            try c.encode(meta, forKey: .meta)
        case .imageReference(let s, let o, let meta):
            try c.encodeIfPresent(s, forKey: .savedPath)
            try c.encodeIfPresent(o, forKey: .originalPath)
            try c.encode(meta, forKey: .meta)
        case .toolCall(let name, let args, let result, let meta):
            try c.encode(name, forKey: .name)
            try c.encode(args, forKey: .args)
            try c.encodeIfPresent(result, forKey: .result)
            try c.encode(meta, forKey: .meta)
        case .raw(let rk, let rp, let meta):
            try c.encode(rk, forKey: .rawKind)
            try c.encode(rp, forKey: .rawPayload)
            try c.encode(meta, forKey: .meta)
        }
    }
}

// MARK: - TurnSummary / ProtocolError

public struct TurnSummary: Codable, Sendable {
    public let totalInputTokens: UInt64?
    public let totalOutputTokens: UInt64?
    public let elapsedMs: UInt64

    public init(totalInputTokens: UInt64? = nil, totalOutputTokens: UInt64? = nil, elapsedMs: UInt64) {
        self.totalInputTokens = totalInputTokens
        self.totalOutputTokens = totalOutputTokens
        self.elapsedMs = elapsedMs
    }
}

public struct ProtocolError: Codable, Sendable {
    public let code: String
    public let message: String
    public let diagnosticRef: String?

    public init(code: String, message: String, diagnosticRef: String? = nil) {
        self.code = code
        self.message = message
        self.diagnosticRef = diagnosticRef
    }
}

// MARK: - ActionKind / ActionRequest / ActionDecision

public enum ActionKind: String, Codable, Sendable {
    case executeCommand, editFiles, grantExtraPermission
}

/// `#[serde(tag = "agentKind")]` ActionRequestVendor.
public enum ActionRequestVendor: Codable, Sendable {
    case codex(approvalPolicyAtDecision: CodexApprovalPolicy, sandboxAtDecision: CodexSandboxMode, canPersist: Bool)
    case claudeCode(permissionModeAtDecision: ClaudeCodePermissionMode, toolName: String)

    private enum CodingKeys: String, CodingKey {
        case agentKind, approvalPolicyAtDecision, sandboxAtDecision, canPersist
        case permissionModeAtDecision, toolName
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let kind = try c.decode(AgentKind.self, forKey: .agentKind)
        switch kind {
        case .codex:
            let policy = try c.decode(CodexApprovalPolicy.self, forKey: .approvalPolicyAtDecision)
            let sandbox = try c.decode(CodexSandboxMode.self, forKey: .sandboxAtDecision)
            let canPersist = try c.decode(Bool.self, forKey: .canPersist)
            self = .codex(approvalPolicyAtDecision: policy, sandboxAtDecision: sandbox, canPersist: canPersist)
        case .claudeCode:
            let mode = try c.decode(ClaudeCodePermissionMode.self, forKey: .permissionModeAtDecision)
            let tool = try c.decode(String.self, forKey: .toolName)
            self = .claudeCode(permissionModeAtDecision: mode, toolName: tool)
        }
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .codex(let p, let s, let cp):
            try c.encode(AgentKind.codex, forKey: .agentKind)
            try c.encode(p, forKey: .approvalPolicyAtDecision)
            try c.encode(s, forKey: .sandboxAtDecision)
            try c.encode(cp, forKey: .canPersist)
        case .claudeCode(let m, let t):
            try c.encode(AgentKind.claudeCode, forKey: .agentKind)
            try c.encode(m, forKey: .permissionModeAtDecision)
            try c.encode(t, forKey: .toolName)
        }
    }
}

public struct ActionRequest: Codable, Sendable {
    public let requestId: String
    public let kind: ActionKind
    public let summary: String
    public let vendor: ActionRequestVendor

    public init(requestId: String, kind: ActionKind, summary: String, vendor: ActionRequestVendor) {
        self.requestId = requestId
        self.kind = kind
        self.summary = summary
        self.vendor = vendor
    }
}

public enum ActionDecisionKind: String, Codable, Sendable {
    case approve, deny
}

public struct ActionDecision: Codable, Sendable {
    public let requestId: String
    public let decision: ActionDecisionKind
    public let persist: Bool

    public init(requestId: String, decision: ActionDecisionKind, persist: Bool = false) {
        self.requestId = requestId
        self.decision = decision
        self.persist = persist
    }
}

// MARK: - VendorControl / VendorPanel

/// Codex vendor control — `tag = "kind", content = "payload"`.
public enum CodexVendorControl: Codable, Sendable {
    case updateSandbox(CodexSandboxMode)
    case updateApprovalPolicy(CodexApprovalPolicy)
    case updateReasoningEffort(CodexReasoningEffort)

    private enum CodingKeys: String, CodingKey { case kind, payload }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let kind = try c.decode(String.self, forKey: .kind)
        switch kind {
        case "updateSandbox":
            self = .updateSandbox(try c.decode(CodexSandboxMode.self, forKey: .payload))
        case "updateApprovalPolicy":
            self = .updateApprovalPolicy(try c.decode(CodexApprovalPolicy.self, forKey: .payload))
        case "updateReasoningEffort":
            self = .updateReasoningEffort(try c.decode(CodexReasoningEffort.self, forKey: .payload))
        default:
            throw DecodingError.dataCorruptedError(
                forKey: .kind, in: c, debugDescription: "unknown CodexVendorControl kind: \(kind)"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .updateSandbox(let v):
            try c.encode("updateSandbox", forKey: .kind)
            try c.encode(v, forKey: .payload)
        case .updateApprovalPolicy(let v):
            try c.encode("updateApprovalPolicy", forKey: .kind)
            try c.encode(v, forKey: .payload)
        case .updateReasoningEffort(let v):
            try c.encode("updateReasoningEffort", forKey: .kind)
            try c.encode(v, forKey: .payload)
        }
    }
}

/// Claude Code vendor control — `tag = "kind", content = "payload"`.
public enum ClaudeCodeVendorControl: Codable, Sendable {
    case updatePermissionMode(ClaudeCodePermissionMode)
    case updateOutputStyle(name: String?)
    case addHook(ClaudeCodeHookConfig)
    case removeHook(matcher: String)

    private enum CodingKeys: String, CodingKey { case kind, payload }

    private struct UpdateOutputStylePayload: Codable { let name: String? }
    private struct RemoveHookPayload: Codable { let matcher: String }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let kind = try c.decode(String.self, forKey: .kind)
        switch kind {
        case "updatePermissionMode":
            self = .updatePermissionMode(try c.decode(ClaudeCodePermissionMode.self, forKey: .payload))
        case "updateOutputStyle":
            let p = try c.decode(UpdateOutputStylePayload.self, forKey: .payload)
            self = .updateOutputStyle(name: p.name)
        case "addHook":
            self = .addHook(try c.decode(ClaudeCodeHookConfig.self, forKey: .payload))
        case "removeHook":
            let p = try c.decode(RemoveHookPayload.self, forKey: .payload)
            self = .removeHook(matcher: p.matcher)
        default:
            throw DecodingError.dataCorruptedError(
                forKey: .kind, in: c, debugDescription: "unknown ClaudeCodeVendorControl kind: \(kind)"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .updatePermissionMode(let v):
            try c.encode("updatePermissionMode", forKey: .kind)
            try c.encode(v, forKey: .payload)
        case .updateOutputStyle(let name):
            try c.encode("updateOutputStyle", forKey: .kind)
            try c.encode(UpdateOutputStylePayload(name: name), forKey: .payload)
        case .addHook(let cfg):
            try c.encode("addHook", forKey: .kind)
            try c.encode(cfg, forKey: .payload)
        case .removeHook(let m):
            try c.encode("removeHook", forKey: .kind)
            try c.encode(RemoveHookPayload(matcher: m), forKey: .payload)
        }
    }
}

/// `#[serde(tag = "agentKind", content = "control")]` — adjacently tagged.
public enum VendorControlPayload: Codable, Sendable {
    case codex(CodexVendorControl)
    case claudeCode(ClaudeCodeVendorControl)

    private enum CodingKeys: String, CodingKey { case agentKind, control }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let kind = try c.decode(AgentKind.self, forKey: .agentKind)
        switch kind {
        case .codex:
            self = .codex(try c.decode(CodexVendorControl.self, forKey: .control))
        case .claudeCode:
            self = .claudeCode(try c.decode(ClaudeCodeVendorControl.self, forKey: .control))
        }
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .codex(let v):
            try c.encode(AgentKind.codex, forKey: .agentKind)
            try c.encode(v, forKey: .control)
        case .claudeCode(let v):
            try c.encode(AgentKind.claudeCode, forKey: .agentKind)
            try c.encode(v, forKey: .control)
        }
    }
}

/// Codex panel event — placeholder only in v0.2.
public enum CodexVendorPanelEvent: Codable, Sendable {
    case placeholder

    private enum CodingKeys: String, CodingKey { case kind }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        _ = try c.decode(String.self, forKey: .kind)
        self = .placeholder
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode("placeholder", forKey: .kind)
    }
}

public enum ClaudeCodeVendorPanelEvent: Codable, Sendable {
    case hookFired(matcher: String, toolUseId: String?, elapsedMs: UInt64?)

    private enum CodingKeys: String, CodingKey { case kind, matcher, toolUseId, elapsedMs }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let kind = try c.decode(String.self, forKey: .kind)
        switch kind {
        case "hookFired":
            let m = try c.decode(String.self, forKey: .matcher)
            let t = try c.decodeIfPresent(String.self, forKey: .toolUseId)
            let e = try c.decodeIfPresent(UInt64.self, forKey: .elapsedMs)
            self = .hookFired(matcher: m, toolUseId: t, elapsedMs: e)
        default:
            throw DecodingError.dataCorruptedError(
                forKey: .kind, in: c, debugDescription: "unknown ClaudeCodeVendorPanelEvent kind: \(kind)"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .hookFired(let m, let t, let e):
            try c.encode("hookFired", forKey: .kind)
            try c.encode(m, forKey: .matcher)
            try c.encodeIfPresent(t, forKey: .toolUseId)
            try c.encodeIfPresent(e, forKey: .elapsedMs)
        }
    }
}

/// `#[serde(tag = "agentKind", content = "event")]`
public enum VendorPanelPayload: Codable, Sendable {
    case codex(CodexVendorPanelEvent)
    case claudeCode(ClaudeCodeVendorPanelEvent)

    private enum CodingKeys: String, CodingKey { case agentKind, event }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let kind = try c.decode(AgentKind.self, forKey: .agentKind)
        switch kind {
        case .codex:
            self = .codex(try c.decode(CodexVendorPanelEvent.self, forKey: .event))
        case .claudeCode:
            self = .claudeCode(try c.decode(ClaudeCodeVendorPanelEvent.self, forKey: .event))
        }
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .codex(let v):
            try c.encode(AgentKind.codex, forKey: .agentKind)
            try c.encode(v, forKey: .event)
        case .claudeCode(let v):
            try c.encode(AgentKind.claudeCode, forKey: .agentKind)
            try c.encode(v, forKey: .event)
        }
    }
}

// MARK: - SessionStart / VendorSessionOptions / RuntimeOptions

public struct RuntimeOptions: Codable, Sendable {
    public let idleTimeoutSecs: UInt32
    public let logVerbosity: String?

    public init(idleTimeoutSecs: UInt32 = 0, logVerbosity: String? = nil) {
        self.idleTimeoutSecs = idleTimeoutSecs
        self.logVerbosity = logVerbosity
    }
}

/// `#[serde(tag = "agentKind")]` — internally tagged.
public enum VendorSessionOptions: Codable, Sendable {
    case codex(CodexSessionOptions)
    case claudeCode(ClaudeCodeSessionOptions)

    private enum Discriminator: String, CodingKey { case agentKind }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: Discriminator.self)
        let kind = try c.decode(AgentKind.self, forKey: .agentKind)
        switch kind {
        case .codex:
            self = .codex(try CodexSessionOptions(from: decoder))
        case .claudeCode:
            self = .claudeCode(try ClaudeCodeSessionOptions(from: decoder))
        }
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: Discriminator.self)
        switch self {
        case .codex(let opts):
            try c.encode(AgentKind.codex, forKey: .agentKind)
            try opts.encode(to: encoder)
        case .claudeCode(let opts):
            try c.encode(AgentKind.claudeCode, forKey: .agentKind)
            try opts.encode(to: encoder)
        }
    }
}

public struct SessionStart: Codable, Sendable {
    public let agentKind: AgentKind
    public let cwd: String
    public let prompt: String?
    public let vendorOptions: VendorSessionOptions
    public let runtimeOptions: RuntimeOptions

    public init(
        agentKind: AgentKind,
        cwd: String,
        prompt: String? = nil,
        vendorOptions: VendorSessionOptions,
        runtimeOptions: RuntimeOptions = RuntimeOptions()
    ) {
        self.agentKind = agentKind
        self.cwd = cwd
        self.prompt = prompt
        self.vendorOptions = vendorOptions
        self.runtimeOptions = runtimeOptions
    }
}

// MARK: - History

public struct HistoryListItem: Codable, Sendable {
    public let threadId: String
    public let agentKind: AgentKind
    public let title: String?
    public let cwd: String
    public let lastActiveMs: UInt64
    public let archived: Bool

    public init(
        threadId: String,
        agentKind: AgentKind,
        title: String?,
        cwd: String,
        lastActiveMs: UInt64,
        archived: Bool
    ) {
        self.threadId = threadId
        self.agentKind = agentKind
        self.title = title
        self.cwd = cwd
        self.lastActiveMs = lastActiveMs
        self.archived = archived
    }
}

public struct HistoryTurn: Codable, Sendable {
    public let items: [AgentItem]

    public init(items: [AgentItem]) {
        self.items = items
    }
}

public struct HistoryReadResponse: Codable, Sendable {
    public let threadId: String
    public let agentKind: AgentKind
    public let turns: [HistoryTurn]

    public init(threadId: String, agentKind: AgentKind, turns: [HistoryTurn]) {
        self.threadId = threadId
        self.agentKind = agentKind
        self.turns = turns
    }
}

/// `#[serde(tag = "op", rename_all = "camelCase")]`
public enum HistoryRequest: Codable, Sendable {
    case list(agentKind: AgentKind?, cwdFilter: String?)
    case read(threadId: String, agentKind: AgentKind)
    case archive(threadId: String, agentKind: AgentKind)
    case unarchive(threadId: String, agentKind: AgentKind)
    case rename(threadId: String, agentKind: AgentKind, title: String)

    private enum CodingKeys: String, CodingKey { case op, agentKind, cwdFilter, threadId, title }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let op = try c.decode(String.self, forKey: .op)
        switch op {
        case "list":
            let kind = try c.decodeIfPresent(AgentKind.self, forKey: .agentKind)
            let cwd = try c.decodeIfPresent(String.self, forKey: .cwdFilter)
            self = .list(agentKind: kind, cwdFilter: cwd)
        case "read":
            let tid = try c.decode(String.self, forKey: .threadId)
            let kind = try c.decode(AgentKind.self, forKey: .agentKind)
            self = .read(threadId: tid, agentKind: kind)
        case "archive":
            let tid = try c.decode(String.self, forKey: .threadId)
            let kind = try c.decode(AgentKind.self, forKey: .agentKind)
            self = .archive(threadId: tid, agentKind: kind)
        case "unarchive":
            let tid = try c.decode(String.self, forKey: .threadId)
            let kind = try c.decode(AgentKind.self, forKey: .agentKind)
            self = .unarchive(threadId: tid, agentKind: kind)
        case "rename":
            let tid = try c.decode(String.self, forKey: .threadId)
            let kind = try c.decode(AgentKind.self, forKey: .agentKind)
            let title = try c.decode(String.self, forKey: .title)
            self = .rename(threadId: tid, agentKind: kind, title: title)
        default:
            throw DecodingError.dataCorruptedError(
                forKey: .op, in: c, debugDescription: "unknown HistoryRequest op: \(op)"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .list(let kind, let cwd):
            try c.encode("list", forKey: .op)
            try c.encodeIfPresent(kind, forKey: .agentKind)
            try c.encodeIfPresent(cwd, forKey: .cwdFilter)
        case .read(let tid, let kind):
            try c.encode("read", forKey: .op)
            try c.encode(tid, forKey: .threadId)
            try c.encode(kind, forKey: .agentKind)
        case .archive(let tid, let kind):
            try c.encode("archive", forKey: .op)
            try c.encode(tid, forKey: .threadId)
            try c.encode(kind, forKey: .agentKind)
        case .unarchive(let tid, let kind):
            try c.encode("unarchive", forKey: .op)
            try c.encode(tid, forKey: .threadId)
            try c.encode(kind, forKey: .agentKind)
        case .rename(let tid, let kind, let title):
            try c.encode("rename", forKey: .op)
            try c.encode(tid, forKey: .threadId)
            try c.encode(kind, forKey: .agentKind)
            try c.encode(title, forKey: .title)
        }
    }
}

/// `#[serde(tag = "kind", content = "value")]`
public enum HistoryResponse: Codable, Sendable {
    case list([HistoryListItem])
    case read(HistoryReadResponse)
    case ack

    private enum CodingKeys: String, CodingKey { case kind, value }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let kind = try c.decode(String.self, forKey: .kind)
        switch kind {
        case "list":
            self = .list(try c.decode([HistoryListItem].self, forKey: .value))
        case "read":
            self = .read(try c.decode(HistoryReadResponse.self, forKey: .value))
        case "ack":
            self = .ack
        default:
            throw DecodingError.dataCorruptedError(
                forKey: .kind, in: c, debugDescription: "unknown HistoryResponse kind: \(kind)"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .list(let items):
            try c.encode("list", forKey: .kind)
            try c.encode(items, forKey: .value)
        case .read(let r):
            try c.encode("read", forKey: .kind)
            try c.encode(r, forKey: .value)
        case .ack:
            try c.encode("ack", forKey: .kind)
        }
    }
}

// MARK: - ClientCommand

/// `#[serde(tag = "command", rename_all = "camelCase")]`
public enum ClientCommand: Codable, Sendable {
    case ping
    case selfcheck
    case sessionStart(SessionStart)
    case sessionContinue(threadId: String, agentKind: AgentKind, prompt: String)
    case sessionCancel(sessionId: String)
    case actionDecision(sessionId: String, decision: ActionDecision)
    case vendorControl(sessionId: String, payload: VendorControlPayload)
    case history(HistoryRequest)
    case protocolSchema
    case protocolVersion
    case agentList
    case agentCapabilities(agentKind: AgentKind)

    private enum CodingKeys: String, CodingKey {
        case command, threadId, agentKind, prompt, sessionId, decision, payload
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let cmd = try c.decode(String.self, forKey: .command)
        switch cmd {
        case "ping": self = .ping
        case "selfcheck": self = .selfcheck
        case "sessionStart":
            self = .sessionStart(try SessionStart(from: decoder))
        case "sessionContinue":
            let tid = try c.decode(String.self, forKey: .threadId)
            let kind = try c.decode(AgentKind.self, forKey: .agentKind)
            let prompt = try c.decode(String.self, forKey: .prompt)
            self = .sessionContinue(threadId: tid, agentKind: kind, prompt: prompt)
        case "sessionCancel":
            let sid = try c.decode(String.self, forKey: .sessionId)
            self = .sessionCancel(sessionId: sid)
        case "actionDecision":
            let sid = try c.decode(String.self, forKey: .sessionId)
            let d = try c.decode(ActionDecision.self, forKey: .decision)
            self = .actionDecision(sessionId: sid, decision: d)
        case "vendorControl":
            let sid = try c.decode(String.self, forKey: .sessionId)
            let p = try c.decode(VendorControlPayload.self, forKey: .payload)
            self = .vendorControl(sessionId: sid, payload: p)
        case "history":
            self = .history(try HistoryRequest(from: decoder))
        case "protocolSchema": self = .protocolSchema
        case "protocolVersion": self = .protocolVersion
        case "agentList": self = .agentList
        case "agentCapabilities":
            let k = try c.decode(AgentKind.self, forKey: .agentKind)
            self = .agentCapabilities(agentKind: k)
        default:
            throw DecodingError.dataCorruptedError(
                forKey: .command, in: c, debugDescription: "unknown ClientCommand: \(cmd)"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .ping: try c.encode("ping", forKey: .command)
        case .selfcheck: try c.encode("selfcheck", forKey: .command)
        case .sessionStart(let s):
            try c.encode("sessionStart", forKey: .command)
            try s.encode(to: encoder)
        case .sessionContinue(let tid, let kind, let prompt):
            try c.encode("sessionContinue", forKey: .command)
            try c.encode(tid, forKey: .threadId)
            try c.encode(kind, forKey: .agentKind)
            try c.encode(prompt, forKey: .prompt)
        case .sessionCancel(let sid):
            try c.encode("sessionCancel", forKey: .command)
            try c.encode(sid, forKey: .sessionId)
        case .actionDecision(let sid, let d):
            try c.encode("actionDecision", forKey: .command)
            try c.encode(sid, forKey: .sessionId)
            try c.encode(d, forKey: .decision)
        case .vendorControl(let sid, let p):
            try c.encode("vendorControl", forKey: .command)
            try c.encode(sid, forKey: .sessionId)
            try c.encode(p, forKey: .payload)
        case .history(let req):
            try c.encode("history", forKey: .command)
            try req.encode(to: encoder)
        case .protocolSchema: try c.encode("protocolSchema", forKey: .command)
        case .protocolVersion: try c.encode("protocolVersion", forKey: .command)
        case .agentList: try c.encode("agentList", forKey: .command)
        case .agentCapabilities(let k):
            try c.encode("agentCapabilities", forKey: .command)
            try c.encode(k, forKey: .agentKind)
        }
    }
}

// MARK: - ServerEvent (main trunk)

/// `#[serde(tag = "type", rename_all = "camelCase")]`
public enum ServerEvent: Sendable {
    case sessionStarted(sessionId: String, threadId: String?, agentKind: AgentKind)
    case sessionCapabilities(sessionId: String, agentKind: AgentKind, capabilities: SessionCapabilities)
    case agentItem(sessionId: String, threadId: String, agentKind: AgentKind, item: AgentItem)
    case actionRequest(sessionId: String, threadId: String, agentKind: AgentKind, request: ActionRequest)
    case turnComplete(sessionId: String, threadId: String, agentKind: AgentKind, summary: TurnSummary)
    case error(sessionId: String?, error: ProtocolError)
    case vendorControl(sessionId: String, agentKind: AgentKind, payload: VendorControlPayload)
    case vendorPanelEvent(sessionId: String, agentKind: AgentKind, payload: VendorPanelPayload)

    public var sessionId: String? {
        switch self {
        case .sessionStarted(let sid, _, _),
             .sessionCapabilities(let sid, _, _),
             .agentItem(let sid, _, _, _),
             .actionRequest(let sid, _, _, _),
             .turnComplete(let sid, _, _, _),
             .vendorControl(let sid, _, _),
             .vendorPanelEvent(let sid, _, _):
            return sid
        case .error(let sid, _):
            return sid
        }
    }

    public var agentKind: AgentKind? {
        switch self {
        case .sessionStarted(_, _, let k),
             .sessionCapabilities(_, let k, _),
             .agentItem(_, _, let k, _),
             .actionRequest(_, _, let k, _),
             .turnComplete(_, _, let k, _),
             .vendorControl(_, let k, _),
             .vendorPanelEvent(_, let k, _):
            return k
        case .error: return nil
        }
    }
}

extension ServerEvent: Codable {
    private enum CodingKeys: String, CodingKey {
        case type, sessionId, threadId, agentKind, capabilities, item, request, summary, error, payload
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let type = try c.decode(String.self, forKey: .type)
        switch type {
        case "sessionStarted":
            let sid = try c.decode(String.self, forKey: .sessionId)
            let tid = try c.decodeIfPresent(String.self, forKey: .threadId)
            let kind = try c.decode(AgentKind.self, forKey: .agentKind)
            self = .sessionStarted(sessionId: sid, threadId: tid, agentKind: kind)
        case "sessionCapabilities":
            let sid = try c.decode(String.self, forKey: .sessionId)
            let kind = try c.decode(AgentKind.self, forKey: .agentKind)
            let caps = try c.decode(SessionCapabilities.self, forKey: .capabilities)
            self = .sessionCapabilities(sessionId: sid, agentKind: kind, capabilities: caps)
        case "agentItem":
            let sid = try c.decode(String.self, forKey: .sessionId)
            let tid = try c.decode(String.self, forKey: .threadId)
            let kind = try c.decode(AgentKind.self, forKey: .agentKind)
            let item = try c.decode(AgentItem.self, forKey: .item)
            self = .agentItem(sessionId: sid, threadId: tid, agentKind: kind, item: item)
        case "actionRequest":
            let sid = try c.decode(String.self, forKey: .sessionId)
            let tid = try c.decode(String.self, forKey: .threadId)
            let kind = try c.decode(AgentKind.self, forKey: .agentKind)
            let req = try c.decode(ActionRequest.self, forKey: .request)
            self = .actionRequest(sessionId: sid, threadId: tid, agentKind: kind, request: req)
        case "turnComplete":
            let sid = try c.decode(String.self, forKey: .sessionId)
            let tid = try c.decode(String.self, forKey: .threadId)
            let kind = try c.decode(AgentKind.self, forKey: .agentKind)
            let summary = try c.decode(TurnSummary.self, forKey: .summary)
            self = .turnComplete(sessionId: sid, threadId: tid, agentKind: kind, summary: summary)
        case "error":
            let sid = try c.decodeIfPresent(String.self, forKey: .sessionId)
            let err = try c.decode(ProtocolError.self, forKey: .error)
            self = .error(sessionId: sid, error: err)
        case "vendorControl":
            let sid = try c.decode(String.self, forKey: .sessionId)
            let kind = try c.decode(AgentKind.self, forKey: .agentKind)
            let payload = try c.decode(VendorControlPayload.self, forKey: .payload)
            self = .vendorControl(sessionId: sid, agentKind: kind, payload: payload)
        case "vendorPanelEvent":
            let sid = try c.decode(String.self, forKey: .sessionId)
            let kind = try c.decode(AgentKind.self, forKey: .agentKind)
            let payload = try c.decode(VendorPanelPayload.self, forKey: .payload)
            self = .vendorPanelEvent(sessionId: sid, agentKind: kind, payload: payload)
        default:
            throw DecodingError.dataCorruptedError(
                forKey: .type, in: c, debugDescription: "unknown ServerEvent type: \(type)"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .sessionStarted(let sid, let tid, let kind):
            try c.encode("sessionStarted", forKey: .type)
            try c.encode(sid, forKey: .sessionId)
            try c.encodeIfPresent(tid, forKey: .threadId)
            try c.encode(kind, forKey: .agentKind)
        case .sessionCapabilities(let sid, let kind, let caps):
            try c.encode("sessionCapabilities", forKey: .type)
            try c.encode(sid, forKey: .sessionId)
            try c.encode(kind, forKey: .agentKind)
            try c.encode(caps, forKey: .capabilities)
        case .agentItem(let sid, let tid, let kind, let item):
            try c.encode("agentItem", forKey: .type)
            try c.encode(sid, forKey: .sessionId)
            try c.encode(tid, forKey: .threadId)
            try c.encode(kind, forKey: .agentKind)
            try c.encode(item, forKey: .item)
        case .actionRequest(let sid, let tid, let kind, let req):
            try c.encode("actionRequest", forKey: .type)
            try c.encode(sid, forKey: .sessionId)
            try c.encode(tid, forKey: .threadId)
            try c.encode(kind, forKey: .agentKind)
            try c.encode(req, forKey: .request)
        case .turnComplete(let sid, let tid, let kind, let summary):
            try c.encode("turnComplete", forKey: .type)
            try c.encode(sid, forKey: .sessionId)
            try c.encode(tid, forKey: .threadId)
            try c.encode(kind, forKey: .agentKind)
            try c.encode(summary, forKey: .summary)
        case .error(let sid, let err):
            try c.encode("error", forKey: .type)
            try c.encodeIfPresent(sid, forKey: .sessionId)
            try c.encode(err, forKey: .error)
        case .vendorControl(let sid, let kind, let payload):
            try c.encode("vendorControl", forKey: .type)
            try c.encode(sid, forKey: .sessionId)
            try c.encode(kind, forKey: .agentKind)
            try c.encode(payload, forKey: .payload)
        case .vendorPanelEvent(let sid, let kind, let payload):
            try c.encode("vendorPanelEvent", forKey: .type)
            try c.encode(sid, forKey: .sessionId)
            try c.encode(kind, forKey: .agentKind)
            try c.encode(payload, forKey: .payload)
        }
    }
}
