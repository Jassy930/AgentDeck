import AgentDeckCore
import Foundation
import XCTest

@testable import AgentDeck

final class RuntimeConversationDraftTests: XCTestCase {
  private let keys = RuntimeConversationIdempotencyKeys(
    start: RuntimeIdempotencyKey(rawValue: "start-key"),
    configure: RuntimeIdempotencyKey(rawValue: "configure-key"),
    prompt: RuntimeIdempotencyKey(rawValue: "prompt-key")
  )

  func testCodexOptionsMapToFrozenConfigurationAndTypedSequence() throws {
    let draft = try RuntimeConversationDraft(
      agentKind: .codex,
      cwd: "/tmp/codex",
      prompt: "hello",
      vendorOptions: .codex(
        CodexSessionOptions(
          approvalPolicy: .never,
          sandbox: .readOnly,
          persistApproval: false,
          reasoningEffort: .high
        )
      ),
      idempotencyKeys: keys
    )

    XCTAssertEqual(draft.agentKind, .codex)
    XCTAssertEqual(draft.cwd, "/tmp/codex")
    XCTAssertEqual(draft.prompt?.rawValue, "hello")
    guard case .codex(let configuration) = draft.configuration.vendorControl else {
      return XCTFail("expected Codex configuration")
    }
    XCTAssertEqual(configuration.approvalPolicy, .never)
    XCTAssertEqual(configuration.sandbox, .readOnly)
    XCTAssertEqual(configuration.reasoningEffort, .high)

    guard case .start(let kind, let key, let cwd, let title) = draft.startRequest else {
      return XCTFail("expected Start")
    }
    XCTAssertEqual(kind, .codex)
    XCTAssertEqual(key, keys.start)
    XCTAssertEqual(cwd, "/tmp/codex")
    XCTAssertNil(title)

    let conversationID = RuntimeConversationID(rawValue: "conversation-1")
    guard
      case .configureConversation(let request) =
        draft.configureRequest(conversationID: conversationID)
    else {
      return XCTFail("expected ConfigureConversation")
    }
    XCTAssertEqual(request.conversationID, conversationID)
    XCTAssertEqual(request.idempotencyKey, keys.configure)
    XCTAssertEqual(request.expectedConfigurationRevision, 0)
    XCTAssertEqual(request.configuration.agentKind, .codex)

    guard case .subscribe(let cursor) = draft.subscribeRequest(conversationID: conversationID)
    else {
      return XCTFail("expected Subscribe")
    }
    guard case .conversation(let subscribedID, let streamCursor) = cursor else {
      return XCTFail("expected conversation subscription")
    }
    XCTAssertEqual(subscribedID, conversationID)
    XCTAssertEqual(streamCursor, .beforeFirst)

    let promptRequest = try XCTUnwrap(
      draft.sendPromptRequest(
        conversationID: conversationID,
        configurationReceipt: .applied(
          conversationID: conversationID,
          configurationRevision: 7
        )
      )
    )
    guard case .sendPrompt(let promptID, let key, let revision, let prompt) = promptRequest else {
      return XCTFail("expected SendPrompt")
    }
    XCTAssertEqual(promptID, conversationID)
    XCTAssertEqual(key, keys.prompt)
    XCTAssertEqual(revision, 7)
    XCTAssertEqual(prompt.rawValue, "hello")
  }

  func testClaudeCodeOptionsMapOnlyFrozenConfigurationFields() throws {
    let draft = try RuntimeConversationDraft(
      agentKind: .claudeCode,
      cwd: "/tmp/claude",
      prompt: "ship it",
      vendorOptions: .claudeCode(
        makeClaudeOptions(
          permissionMode: .plan,
          model: "opus",
          effort: "high",
          outputStyle: "concise"
        )
      ),
      idempotencyKeys: keys
    )

    guard case .claudeCode(let configuration) = draft.configuration.vendorControl else {
      return XCTFail("expected Claude Code configuration")
    }
    XCTAssertEqual(configuration.permissionMode, .plan)
    XCTAssertEqual(configuration.model, "opus")
    XCTAssertEqual(configuration.effort, "high")
    XCTAssertEqual(configuration.outputStyle, "concise")
  }

  func testEmptyPromptDoesNotProduceSendPromptRequest() throws {
    for prompt in [nil, ""] as [String?] {
      let draft = try RuntimeConversationDraft(
        agentKind: .codex,
        cwd: "/tmp/project",
        prompt: prompt,
        vendorOptions: codexOptions(),
        idempotencyKeys: keys
      )
      XCTAssertNil(
        try draft.sendPromptRequest(
          conversationID: RuntimeConversationID(rawValue: "conversation-empty"),
          configurationReceipt: .applied(
            conversationID: RuntimeConversationID(rawValue: "conversation-empty"),
            configurationRevision: 1
          )
        )
      )
    }
  }

  func testSendPromptRequiresActualNonzeroConfigurationRevision() throws {
    let draft = try RuntimeConversationDraft(
      agentKind: .codex,
      cwd: "/tmp/project",
      prompt: "hello",
      vendorOptions: codexOptions(),
      idempotencyKeys: keys
    )

    XCTAssertThrowsError(
      try draft.sendPromptRequest(
        conversationID: RuntimeConversationID(rawValue: "conversation-1"),
        configurationReceipt: .applied(
          conversationID: RuntimeConversationID(rawValue: "conversation-1"),
          configurationRevision: 0
        )
      )
    ) { error in
      XCTAssertEqual(error as? RuntimeConversationDraftError, .invalidConfigurationRevision)
    }
  }

  func testSendPromptRejectsNonAppliedOrMismatchedConfigurationReceipt() throws {
    let draft = try RuntimeConversationDraft(
      agentKind: .codex,
      cwd: "/tmp/project",
      prompt: "hello",
      vendorOptions: codexOptions(),
      idempotencyKeys: keys
    )
    let conversationID = RuntimeConversationID(rawValue: "conversation-1")

    XCTAssertThrowsError(
      try draft.sendPromptRequest(
        conversationID: conversationID,
        configurationReceipt: .conflict(
          conversationID: conversationID,
          currentConfigurationRevision: 3
        )
      )
    ) { error in
      XCTAssertEqual(error as? RuntimeConversationDraftError, .configurationNotApplied)
    }

    XCTAssertThrowsError(
      try draft.sendPromptRequest(
        conversationID: conversationID,
        configurationReceipt: .replayed(
          conversationID: RuntimeConversationID(rawValue: "conversation-other"),
          configurationRevision: 1
        )
      )
    ) { error in
      XCTAssertEqual(
        error as? RuntimeConversationDraftError,
        .configurationConversationMismatch(
          expected: conversationID,
          actual: RuntimeConversationID(rawValue: "conversation-other")
        )
      )
    }
  }

  func testAgentKindMismatchIsRejectedBeforeMapping() {
    XCTAssertThrowsError(
      try RuntimeConversationDraft(
        agentKind: .codex,
        cwd: "/tmp/project",
        prompt: nil,
        vendorOptions: .claudeCode(makeClaudeOptions()),
        idempotencyKeys: keys
      )
    ) { error in
      XCTAssertEqual(
        error as? RuntimeConversationDraftError,
        .agentKindMismatch(expected: .codex, vendor: .claudeCode)
      )
    }
  }

  func testCodexUncommittedFieldsAreTypedRejects() {
    let cases: [(RuntimeConversationDraftUnsupportedField, CodexSessionOptions)] = [
      (
        .codexPersistApproval,
        CodexSessionOptions(
          approvalPolicy: .onRequest,
          sandbox: .workspaceWrite,
          persistApproval: true,
          reasoningEffort: .medium
        )
      ),
      (
        .codexMCPOverrides,
        CodexSessionOptions(
          approvalPolicy: .onRequest,
          sandbox: .workspaceWrite,
          persistApproval: false,
          reasoningEffort: .medium,
          mcpOverrides: [McpOverride(name: "server", enabled: true)]
        )
      ),
    ]

    for (field, options) in cases {
      assertUnsupported(field, vendorOptions: .codex(options))
    }
  }

  func testClaudeCodeUncommittedFieldsAreTypedRejects() {
    let cases: [(RuntimeConversationDraftUnsupportedField, ClaudeCodeSessionOptions)] = [
      (
        .claudeCodeHooks,
        makeClaudeOptions(hooks: [ClaudeCodeHookConfig(matcher: "*", command: "true")])
      ),
      (.claudeCodeAllowedTools, makeClaudeOptions(allowedTools: ["Read"])),
      (.claudeCodeDisallowedTools, makeClaudeOptions(disallowedTools: ["Write"])),
      (.claudeCodeMCPConfigPath, makeClaudeOptions(mcpConfigPath: "/tmp/mcp.json")),
      (.claudeCodePluginDirectories, makeClaudeOptions(pluginDirs: ["/tmp/plugin"])),
      (.claudeCodeWorktree, makeClaudeOptions(worktree: "/tmp/worktree")),
      (.claudeCodeSessionName, makeClaudeOptions(sessionName: "alpha")),
      (.claudeCodeSessionID, makeClaudeOptions(sessionID: "native-session")),
    ]

    for (field, options) in cases {
      assertUnsupported(field, vendorOptions: .claudeCode(options))
    }
  }

  func testSemanticallyEmptyUncommittedClaudeCodeFieldsAreAcceptedAsAbsent() throws {
    XCTAssertNoThrow(
      try RuntimeConversationDraft(
        agentKind: .claudeCode,
        cwd: "/tmp/project",
        prompt: nil,
        vendorOptions: .claudeCode(
          makeClaudeOptions(
            allowedTools: [],
            disallowedTools: [],
            mcpConfigPath: "",
            pluginDirs: [],
            worktree: "",
            sessionName: "",
            sessionID: ""
          )
        ),
        idempotencyKeys: keys
      )
    )
  }

  func testCompatibilitySessionStartRejectsUnmappedRuntimeOptions() {
    let nondefaultRuntimeOptions: [(RuntimeConversationDraftUnsupportedField, RuntimeOptions)] = [
      (.runtimeIdleTimeout, RuntimeOptions(idleTimeoutSecs: 30)),
      (.runtimeLogVerbosity, RuntimeOptions(logVerbosity: "debug")),
    ]

    for (field, runtimeOptions) in nondefaultRuntimeOptions {
      let start = SessionStart(
        agentKind: .codex,
        cwd: "/tmp/project",
        vendorOptions: codexOptions(),
        runtimeOptions: runtimeOptions
      )
      XCTAssertThrowsError(
        try RuntimeConversationDraft(sessionStart: start, idempotencyKeys: keys)
      ) { error in
        XCTAssertEqual(error as? RuntimeConversationDraftError, .unsupportedField(field))
      }
    }
  }

  func testCompatibilitySessionStartMapsDefaultRuntimeOptions() throws {
    let draft = try RuntimeConversationDraft(
      sessionStart: SessionStart(
        agentKind: .claudeCode,
        cwd: "/tmp/compatibility",
        prompt: "hello",
        vendorOptions: .claudeCode(
          makeClaudeOptions(permissionMode: .acceptEdits, model: "sonnet")
        )
      ),
      idempotencyKeys: keys
    )

    XCTAssertEqual(draft.agentKind, .claudeCode)
    XCTAssertEqual(draft.cwd, "/tmp/compatibility")
    XCTAssertEqual(draft.prompt?.rawValue, "hello")
    guard case .claudeCode(let configuration) = draft.configuration.vendorControl else {
      return XCTFail("expected Claude Code configuration")
    }
    XCTAssertEqual(configuration.permissionMode, .acceptEdits)
    XCTAssertEqual(configuration.model, "sonnet")
  }

  func testDescribeAgentsDefaultConfigurationCanBuildDraft() throws {
    let descriptions = try makeClaudeDescriptions()
    let draft = try RuntimeConversationDraft(
      agentKind: .claudeCode,
      cwd: "/tmp/default",
      prompt: "hello",
      agentDescriptions: descriptions,
      idempotencyKeys: keys
    )

    guard case .claudeCode(let configuration) = draft.configuration.vendorControl else {
      return XCTFail("expected Claude Code default configuration")
    }
    XCTAssertEqual(configuration.permissionMode, .plan)
    XCTAssertEqual(configuration.model, "sonnet")
    XCTAssertNil(configuration.effort)
    XCTAssertEqual(configuration.outputStyle, "concise")
  }

  func testDescribeAgentsMissingKindIsTypedReject() throws {
    let descriptions = try makeClaudeDescriptions()
    XCTAssertThrowsError(
      try RuntimeConversationDraft(
        agentKind: .codex,
        cwd: "/tmp/default",
        prompt: nil,
        agentDescriptions: descriptions,
        idempotencyKeys: keys
      )
    ) { error in
      XCTAssertEqual(
        error as? RuntimeConversationDraftError,
        .agentDescriptionUnavailable(.codex)
      )
    }
  }

  func testFreshIdempotencyKeysAreOperationSeparatedAndStableForNonce() {
    let nonce = UUID(uuidString: "7C46FC79-906E-49AA-BF03-CFF34776079E")!
    let generated = RuntimeConversationIdempotencyKeys.fresh(nonce: nonce)

    XCTAssertEqual(generated.start.rawValue, "start:7c46fc79-906e-49aa-bf03-cff34776079e")
    XCTAssertEqual(generated.configure.rawValue, "configure:7c46fc79-906e-49aa-bf03-cff34776079e")
    XCTAssertEqual(generated.prompt.rawValue, "prompt:7c46fc79-906e-49aa-bf03-cff34776079e")
    XCTAssertEqual(
      Set([generated.start.rawValue, generated.configure.rawValue, generated.prompt.rawValue])
        .count, 3)
  }

  func testDraftRejectsRelativeCwdAndInvalidIdempotencyKeys() {
    XCTAssertThrowsError(
      try RuntimeConversationDraft(
        agentKind: .codex,
        cwd: "relative/path",
        prompt: nil,
        vendorOptions: codexOptions(),
        idempotencyKeys: keys
      )
    ) { error in
      XCTAssertEqual(error as? RuntimeConversationDraftError, .cwdMustBeAbsolute)
    }

    let emptyStart = RuntimeConversationIdempotencyKeys(
      start: RuntimeIdempotencyKey(rawValue: ""),
      configure: RuntimeIdempotencyKey(rawValue: "configure-key"),
      prompt: RuntimeIdempotencyKey(rawValue: "prompt-key")
    )
    XCTAssertThrowsError(
      try RuntimeConversationDraft(
        agentKind: .codex,
        cwd: "/tmp/project",
        prompt: nil,
        vendorOptions: codexOptions(),
        idempotencyKeys: emptyStart
      )
    ) { error in
      XCTAssertEqual(
        error as? RuntimeConversationDraftError,
        .invalidIdempotencyKey(.start)
      )
    }

    let duplicate = RuntimeConversationIdempotencyKeys(
      start: RuntimeIdempotencyKey(rawValue: "same"),
      configure: RuntimeIdempotencyKey(rawValue: "same"),
      prompt: RuntimeIdempotencyKey(rawValue: "prompt-key")
    )
    XCTAssertThrowsError(
      try RuntimeConversationDraft(
        agentKind: .codex,
        cwd: "/tmp/project",
        prompt: nil,
        vendorOptions: codexOptions(),
        idempotencyKeys: duplicate
      )
    ) { error in
      XCTAssertEqual(error as? RuntimeConversationDraftError, .duplicateIdempotencyKeys)
    }
  }

  private func assertUnsupported(
    _ field: RuntimeConversationDraftUnsupportedField,
    vendorOptions: VendorSessionOptions,
    file: StaticString = #filePath,
    line: UInt = #line
  ) {
    XCTAssertThrowsError(
      try RuntimeConversationDraft(
        agentKind: vendorOptions.agentKindForDraftTest,
        cwd: "/tmp/project",
        prompt: nil,
        vendorOptions: vendorOptions,
        idempotencyKeys: keys
      ),
      file: file,
      line: line
    ) { error in
      XCTAssertEqual(
        error as? RuntimeConversationDraftError,
        .unsupportedField(field),
        file: file,
        line: line
      )
    }
  }

  private func codexOptions() -> VendorSessionOptions {
    .codex(
      CodexSessionOptions(
        approvalPolicy: .onRequest,
        sandbox: .workspaceWrite,
        persistApproval: false,
        reasoningEffort: .medium
      )
    )
  }

  private func makeClaudeOptions(
    permissionMode: ClaudeCodePermissionMode = .default,
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
    sessionID: String? = nil
  ) -> ClaudeCodeSessionOptions {
    ClaudeCodeSessionOptions(
      permissionMode: permissionMode,
      model: model,
      effort: effort,
      hooks: hooks,
      outputStyle: outputStyle,
      allowedTools: allowedTools,
      disallowedTools: disallowedTools,
      mcpConfigPath: mcpConfigPath,
      pluginDirs: pluginDirs,
      worktree: worktree,
      sessionName: sessionName,
      sessionId: sessionID
    )
  }

  private func makeClaudeDescriptions() throws -> RuntimeAgentDescriptionsV2 {
    let object: [String: Any] = [
      "agents": [
        [
          "agentKind": "claude_code",
          "capabilities": [
            "agentKind": "claude_code",
            "agentVersion": "1.0",
            "features": [],
            "vendor": [
              "agentKind": "claude_code",
              "permissionModes": ["default", "plan"],
              "outputStyles": ["concise"],
              "hooksSupported": [],
              "cliVersion": "1.0",
            ],
          ],
          "defaultConfiguration": [
            "vendorControl": [
              "agentKind": "claude_code",
              "configuration": [
                "permissionMode": "plan",
                "model": "sonnet",
                "effort": NSNull(),
                "outputStyle": "concise",
              ],
            ]
          ],
        ]
      ]
    ]
    return try JSONDecoder().decode(
      RuntimeAgentDescriptionsV2.self,
      from: JSONSerialization.data(withJSONObject: object)
    )
  }
}

extension VendorSessionOptions {
  fileprivate var agentKindForDraftTest: AgentKind {
    switch self {
    case .codex: .codex
    case .claudeCode: .claudeCode
    }
  }
}
