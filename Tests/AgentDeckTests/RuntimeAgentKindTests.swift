import AgentDeckCore
import Foundation
import XCTest

@testable import AgentDeck

@MainActor
final class RuntimeAgentKindTests: XCTestCase {
  func testCodexSnapshotBridgesRuntimeCapabilitiesIntoAgentPresentation() throws {
    let id = conversationID("conversation-codex")
    let runtime = try ThreadRuntimeModel(
      conversationID: id,
      agentKind: .codex,
      cwd: URL(fileURLWithPath: "/tmp/project"),
      initialPhase: .ready
    )
    try runtime.apply(
      try ConversationSnapshotV2(
        conversationID: id,
        baseEventCursor: .beforeFirst,
        configurationState: unconfiguredState(),
        items: [
          .capabilities(
            try capabilities(
              agentKind: .codex,
              agentVersion: "codex-test",
              features: ["shell", "codexSandboxMode"]
            )
          )
        ]
      )
    )

    XCTAssertEqual(runtime.conversationID, id)
    XCTAssertEqual(runtime.agentKind, .codex)
    XCTAssertEqual(runtime.runtimeCapabilities?.agentVersion, "codex-test")
    XCTAssertEqual(runtime.capabilities?.features, [.shell, .codexSandboxMode])
    guard case .codex(let vendor)? = runtime.capabilities?.vendor else {
      return XCTFail("expected Codex presentation capabilities")
    }
    XCTAssertEqual(vendor.sandboxModes, [.readOnly, .workspaceWrite])
    XCTAssertTrue(vendor.persistenceSupported)
    XCTAssertEqual(vendor.reasoningEffortLevels, [.medium, .high])
  }

  func testClaudeCapabilityEventRefreshesPresentationWithoutReplacingIdentity() throws {
    let id = conversationID("conversation-claude")
    let runtime = try ThreadRuntimeModel(
      conversationID: id,
      agentKind: .claudeCode,
      cwd: nil,
      initialPhase: .ready
    )
    try runtime.apply(
      try ConversationSnapshotV2(
        conversationID: id,
        baseEventCursor: .beforeFirst,
        configurationState: unconfiguredState(),
        items: [
          .capabilities(
            try capabilities(
              agentKind: .claudeCode,
              agentVersion: "1.0",
              features: ["claudeCodePermissionMode"]
            )
          )
        ]
      )
    )
    let refreshed = try capabilities(
      agentKind: .claudeCode,
      agentVersion: "1.1",
      features: ["claudeCodePermissionMode", "claudeCodePlanMode"]
    )

    try runtime.apply(
      RuntimeEventV2(
        conversationID: id,
        eventID: RuntimeEventID(rawValue: "event-capabilities"),
        eventSeq: 0,
        commandID: nil,
        itemID: nil,
        entityID: nil,
        body: .capabilities(refreshed)
      )
    )

    XCTAssertEqual(runtime.conversationID, id)
    XCTAssertEqual(runtime.cursor, .at(0))
    XCTAssertEqual(runtime.runtimeCapabilities?.agentVersion, "1.1")
    XCTAssertEqual(
      runtime.capabilities?.features,
      [.claudeCodePermissionMode, .claudeCodePlanMode]
    )
    guard case .claudeCode(let vendor)? = runtime.capabilities?.vendor else {
      return XCTFail("expected Claude Code presentation capabilities")
    }
    XCTAssertEqual(vendor.permissionModes, [.default, .plan])
    XCTAssertEqual(vendor.outputStyles, ["concise"])
    XCTAssertEqual(vendor.hooksSupported, ["PreToolUse"])
    XCTAssertEqual(vendor.cliVersion, "1.1")
  }

  private func capabilities(
    agentKind: AgentKind,
    agentVersion: String,
    features: [String]
  ) throws -> RuntimeSessionCapabilitiesV1 {
    let vendor: [String: Any]
    switch agentKind {
    case .codex:
      vendor = [
        "agentKind": "codex",
        "sandboxModes": ["read-only", "workspace-write"],
        "persistenceSupported": true,
        "reasoningEffortLevels": ["medium", "high"],
      ]
    case .claudeCode:
      vendor = [
        "agentKind": "claude_code",
        "permissionModes": ["default", "plan"],
        "outputStyles": ["concise"],
        "hooksSupported": ["PreToolUse"],
        "cliVersion": agentVersion,
      ]
    }
    return try decode(
      RuntimeSessionCapabilitiesV1.self,
      [
        "agentKind": agentKind == .codex ? "codex" : "claude_code",
        "agentVersion": agentVersion,
        "features": features,
        "vendor": vendor,
      ]
    )
  }

  private func unconfiguredState() throws -> RuntimeConversationConfigurationStateV2 {
    try RuntimeConversationConfigurationStateV2(
      configurationRevision: 0,
      configuration: nil
    )
  }

  private func decode<Value: Decodable>(_ type: Value.Type, _ object: Any) throws -> Value {
    let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    return try JSONDecoder().decode(type, from: data)
  }

  private func conversationID(_ value: String) -> RuntimeConversationID {
    RuntimeConversationID(rawValue: value)
  }
}
