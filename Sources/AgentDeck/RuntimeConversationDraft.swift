import AgentDeckCore
import Foundation

/// Runtime v2 尚未承诺、不能从 legacy `VendorSessionOptions` 静默丢弃的字段。
public enum RuntimeConversationDraftUnsupportedField: String, Equatable, Sendable {
  case runtimeIdleTimeout
  case runtimeLogVerbosity
  case codexPersistApproval
  case codexMCPOverrides
  case claudeCodeHooks
  case claudeCodeAllowedTools
  case claudeCodeDisallowedTools
  case claudeCodeMCPConfigPath
  case claudeCodePluginDirectories
  case claudeCodeWorktree
  case claudeCodeSessionName
  case claudeCodeSessionID
}

public enum RuntimeConversationIdempotencyOperation: String, Equatable, Sendable {
  case start
  case configure
  case prompt
}

public enum RuntimeConversationDraftError: Error, Equatable, Sendable {
  case agentKindMismatch(expected: AgentKind, vendor: AgentKind)
  case configurationKindMismatch(expected: AgentKind, actual: AgentKind)
  case agentDescriptionUnavailable(AgentKind)
  case unsupportedField(RuntimeConversationDraftUnsupportedField)
  case cwdMustBeAbsolute
  case invalidIdempotencyKey(RuntimeConversationIdempotencyOperation)
  case duplicateIdempotencyKeys
  case configurationNotApplied
  case configurationConversationMismatch(
    expected: RuntimeConversationID,
    actual: RuntimeConversationID
  )
  case invalidConfigurationRevision
}

/// 一次新会话流程的三把稳定 key。重试必须复用同一个 draft 中的 key。
public struct RuntimeConversationIdempotencyKeys: Equatable, Sendable {
  public let start: RuntimeIdempotencyKey
  public let configure: RuntimeIdempotencyKey
  public let prompt: RuntimeIdempotencyKey

  public init(
    start: RuntimeIdempotencyKey,
    configure: RuntimeIdempotencyKey,
    prompt: RuntimeIdempotencyKey
  ) {
    self.start = start
    self.configure = configure
    self.prompt = prompt
  }

  /// 一个 nonce 派生三个 operation-separated key，便于持久化和确定性测试。
  public static func fresh(nonce: UUID = UUID()) -> Self {
    let value = nonce.uuidString.lowercased()
    return Self(
      start: RuntimeIdempotencyKey(rawValue: "start:\(value)"),
      configure: RuntimeIdempotencyKey(rawValue: "configure:\(value)"),
      prompt: RuntimeIdempotencyKey(rawValue: "prompt:\(value)")
    )
  }

  fileprivate func validate() throws {
    let values: [(RuntimeConversationIdempotencyOperation, RuntimeIdempotencyKey)] = [
      (.start, start),
      (.configure, configure),
      (.prompt, prompt),
    ]
    for (operation, key) in values {
      guard !key.rawValue.isEmpty, key.rawValue.utf8.count <= 1024 else {
        throw RuntimeConversationDraftError.invalidIdempotencyKey(operation)
      }
    }
    guard Set(values.map(\.1.rawValue)).count == values.count else {
      throw RuntimeConversationDraftError.duplicateIdempotencyKeys
    }
  }
}

/// 新会话的不可变 Runtime v2 输入。
///
/// 固定顺序是 Start → Configure(rev0) → Subscribe → SendPrompt。最后一步只接受同一
/// conversation 的 Applied/Replayed Configure 回执，不能把假定的 rev1 当作执行依据。
public struct RuntimeConversationDraft: Sendable {
  public let agentKind: AgentKind
  public let cwd: String
  public let prompt: RuntimePromptPayloadV1?
  public let configuration: RuntimeConversationConfigurationV2
  public let idempotencyKeys: RuntimeConversationIdempotencyKeys

  /// Production 新会话入口；不依赖 legacy `SessionStart`。
  public init(
    agentKind: AgentKind,
    cwd: String,
    prompt: String?,
    vendorOptions: VendorSessionOptions,
    idempotencyKeys: RuntimeConversationIdempotencyKeys = .fresh()
  ) throws {
    let vendorKind = vendorOptions.runtimeConversationDraftAgentKind
    guard vendorKind == agentKind else {
      throw RuntimeConversationDraftError.agentKindMismatch(
        expected: agentKind,
        vendor: vendorKind
      )
    }
    try self.init(
      agentKind: agentKind,
      cwd: cwd,
      prompt: prompt,
      configuration: Self.configuration(from: vendorOptions),
      idempotencyKeys: idempotencyKeys
    )
  }

  /// 使用 `DescribeAgents` 中 adapter-owned default configuration 建立新会话。
  public init(
    agentKind: AgentKind,
    cwd: String,
    prompt: String?,
    agentDescriptions: RuntimeAgentDescriptionsV2,
    idempotencyKeys: RuntimeConversationIdempotencyKeys = .fresh()
  ) throws {
    guard let description = agentDescriptions.agents.first(where: { $0.agentKind == agentKind })
    else {
      throw RuntimeConversationDraftError.agentDescriptionUnavailable(agentKind)
    }
    try self.init(
      agentKind: agentKind,
      cwd: cwd,
      prompt: prompt,
      configuration: description.defaultConfiguration,
      idempotencyKeys: idempotencyKeys
    )
  }

  /// Preview/test compatibility；production dialog 应直接使用 vendor-options initializer。
  public init(
    sessionStart: SessionStart,
    idempotencyKeys: RuntimeConversationIdempotencyKeys = .fresh()
  ) throws {
    guard sessionStart.runtimeOptions.idleTimeoutSecs == 0 else {
      throw RuntimeConversationDraftError.unsupportedField(.runtimeIdleTimeout)
    }
    if let verbosity = sessionStart.runtimeOptions.logVerbosity, !verbosity.isEmpty {
      throw RuntimeConversationDraftError.unsupportedField(.runtimeLogVerbosity)
    }
    try self.init(
      agentKind: sessionStart.agentKind,
      cwd: sessionStart.cwd,
      prompt: sessionStart.prompt,
      vendorOptions: sessionStart.vendorOptions,
      idempotencyKeys: idempotencyKeys
    )
  }

  private init(
    agentKind: AgentKind,
    cwd: String,
    prompt: String?,
    configuration: RuntimeConversationConfigurationV2,
    idempotencyKeys: RuntimeConversationIdempotencyKeys
  ) throws {
    guard NSString(string: cwd).isAbsolutePath else {
      throw RuntimeConversationDraftError.cwdMustBeAbsolute
    }
    guard configuration.agentKind == agentKind else {
      throw RuntimeConversationDraftError.configurationKindMismatch(
        expected: agentKind,
        actual: configuration.agentKind
      )
    }
    try idempotencyKeys.validate()

    self.agentKind = agentKind
    self.cwd = cwd
    self.prompt =
      if let prompt, !prompt.isEmpty {
        try RuntimePromptPayloadV1(rawValue: prompt)
      } else {
        nil
      }
    self.configuration = configuration
    self.idempotencyKeys = idempotencyKeys
  }

  /// 把 legacy vendor form 的已承诺子集严格映射到 Runtime v2 configuration。
  public static func configuration(
    from vendorOptions: VendorSessionOptions
  ) throws -> RuntimeConversationConfigurationV2 {
    switch vendorOptions {
    case .codex(let options):
      guard !options.persistApproval else {
        throw RuntimeConversationDraftError.unsupportedField(.codexPersistApproval)
      }
      guard options.mcpOverrides.isEmpty else {
        throw RuntimeConversationDraftError.unsupportedField(.codexMCPOverrides)
      }
      return RuntimeConversationConfigurationV2(
        vendorControl: .codex(
          RuntimeCodexConversationConfigurationV2(
            approvalPolicy: options.approvalPolicy,
            sandbox: options.sandbox,
            reasoningEffort: options.reasoningEffort
          )
        )
      )

    case .claudeCode(let options):
      try validateUncommittedClaudeCodeFields(options)
      return RuntimeConversationConfigurationV2(
        vendorControl: .claudeCode(
          try RuntimeClaudeCodeConversationConfigurationV2(
            permissionMode: options.permissionMode,
            model: options.model,
            effort: options.effort,
            outputStyle: options.outputStyle
          )
        )
      )
    }
  }

  public var startRequest: RuntimeRequestV2 {
    .start(
      agentKind: agentKind,
      idempotencyKey: idempotencyKeys.start,
      cwd: cwd,
      title: nil
    )
  }

  public func configureRequest(conversationID: RuntimeConversationID) -> RuntimeRequestV2 {
    .configureConversation(
      RuntimeConfigureConversationRequestV2(
        conversationID: conversationID,
        idempotencyKey: idempotencyKeys.configure,
        expectedConfigurationRevision: 0,
        configuration: configuration
      )
    )
  }

  public func subscribeRequest(conversationID: RuntimeConversationID) -> RuntimeRequestV2 {
    .subscribe(
      innerCursor: .conversation(
        conversationID: conversationID,
        cursor: .beforeFirst
      )
    )
  }

  func replacingIdempotencyKeys(
    _ idempotencyKeys: RuntimeConversationIdempotencyKeys
  ) throws -> Self {
    try Self(
      agentKind: agentKind,
      cwd: cwd,
      prompt: prompt?.rawValue,
      configuration: configuration,
      idempotencyKeys: idempotencyKeys
    )
  }

  func replacingIntent(
    cwd: String,
    prompt: String?,
    idempotencyKeys: RuntimeConversationIdempotencyKeys
  ) throws -> Self {
    try Self(
      agentKind: agentKind,
      cwd: cwd,
      prompt: prompt,
      configuration: configuration,
      idempotencyKeys: idempotencyKeys
    )
  }

  /// 空 prompt 返回 nil；非空 prompt 只接受同 conversation 的成功 Configure 回执。
  public func sendPromptRequest(
    conversationID: RuntimeConversationID,
    configurationReceipt: RuntimeConfigurationReceiptV2
  ) throws -> RuntimeRequestV2? {
    guard let prompt else { return nil }

    let receiptConversationID: RuntimeConversationID
    let revision: UInt64
    switch configurationReceipt {
    case .applied(let configuredID, let configurationRevision),
      .replayed(let configuredID, let configurationRevision):
      receiptConversationID = configuredID
      revision = configurationRevision
    case .conflict, .failed:
      throw RuntimeConversationDraftError.configurationNotApplied
    }
    guard receiptConversationID == conversationID else {
      throw RuntimeConversationDraftError.configurationConversationMismatch(
        expected: conversationID,
        actual: receiptConversationID
      )
    }
    guard revision > 0 else {
      throw RuntimeConversationDraftError.invalidConfigurationRevision
    }

    return .sendPrompt(
      conversationID: conversationID,
      idempotencyKey: idempotencyKeys.prompt,
      expectedConfigurationRevision: revision,
      prompt: prompt
    )
  }
}

extension VendorSessionOptions {
  fileprivate var runtimeConversationDraftAgentKind: AgentKind {
    switch self {
    case .codex: .codex
    case .claudeCode: .claudeCode
    }
  }
}

private func validateUncommittedClaudeCodeFields(
  _ options: ClaudeCodeSessionOptions
) throws {
  guard options.hooks.isEmpty else {
    throw RuntimeConversationDraftError.unsupportedField(.claudeCodeHooks)
  }
  guard options.allowedTools?.isEmpty != false else {
    throw RuntimeConversationDraftError.unsupportedField(.claudeCodeAllowedTools)
  }
  guard options.disallowedTools?.isEmpty != false else {
    throw RuntimeConversationDraftError.unsupportedField(.claudeCodeDisallowedTools)
  }
  if let path = options.mcpConfigPath, !path.isEmpty {
    throw RuntimeConversationDraftError.unsupportedField(.claudeCodeMCPConfigPath)
  }
  guard options.pluginDirs.isEmpty else {
    throw RuntimeConversationDraftError.unsupportedField(.claudeCodePluginDirectories)
  }
  if let worktree = options.worktree, !worktree.isEmpty {
    throw RuntimeConversationDraftError.unsupportedField(.claudeCodeWorktree)
  }
  if let name = options.sessionName, !name.isEmpty {
    throw RuntimeConversationDraftError.unsupportedField(.claudeCodeSessionName)
  }
  if let sessionID = options.sessionId, !sessionID.isEmpty {
    throw RuntimeConversationDraftError.unsupportedField(.claudeCodeSessionID)
  }
}
