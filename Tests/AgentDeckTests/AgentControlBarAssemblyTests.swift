import AgentDeckCore
import AppKit
import XCTest

@testable import AgentDeck

@MainActor
final class AgentControlBarAssemblyTests: XCTestCase {

  func testBindCodexAssemblesIconAndMini() {
    let bar = AgentControlBar(frame: .zero)
    bar.bind(capabilities: .codexStub())
    XCTAssertNotNil(bar.iconView)
    XCTAssertTrue(bar.miniView is CodexControlsView)
  }

  func testBindClaudeCodeAssemblesIconAndMini() {
    let bar = AgentControlBar(frame: .zero)
    bar.bind(capabilities: .ccStub())
    XCTAssertNotNil(bar.iconView)
    XCTAssertTrue(bar.miniView is ClaudeCodeControlsView)
  }

  func testRebindReplacesPriorMini() {
    let bar = AgentControlBar(frame: .zero)
    bar.bind(capabilities: .codexStub())
    XCTAssertTrue(bar.miniView is CodexControlsView)
    bar.bind(capabilities: .ccStub())
    XCTAssertTrue(bar.miniView is ClaudeCodeControlsView)
    XCTAssertFalse(bar.miniView is CodexControlsView)
  }

  func testClearRemovesAllSubviews() {
    let bar = AgentControlBar(frame: .zero)
    bar.bind(capabilities: .ccStub())
    XCTAssertFalse(bar.subviews.isEmpty)
    bar.clear()
    XCTAssertTrue(bar.subviews.isEmpty)
    XCTAssertNil(bar.miniView)
    XCTAssertNil(bar.iconView)
  }

  /// Runtime control callbacks carry the canonical conversation identity and a
  /// UI-only mutation. SessionModel rebuilds the full Runtime configuration and
  /// performs revision CAS through AppRuntimeCoordinator.
  func testBindCodexWiresSandboxAndApprovalAndEffortCallbacks() {
    let bar = AgentControlBar(frame: .zero)
    let conversationID = RuntimeConversationID(rawValue: "conversation-1")
    var received: [(RuntimeConversationID, RuntimeAgentControlMutation)] = []
    bar.bind(
      capabilities: .codexStub(),
      conversationID: conversationID,
      onConfigurationChange: { id, mutation in received.append((id, mutation)) }
    )
    guard let codex = bar.miniView as? CodexControlsView else {
      return XCTFail("expected CodexControlsView")
    }
    codex.onSandboxChange?(.readOnly)
    codex.onApprovalChange?(.never)
    codex.onEffortChange?(.high)
    XCTAssertEqual(received.count, 3)
    XCTAssertEqual(received[0].0, conversationID)
    if case .codexSandbox(let mode) = received[0].1 {
      XCTAssertEqual(mode, .readOnly)
    } else {
      XCTFail("mutation 0 not codexSandbox")
    }
    if case .codexApprovalPolicy(let policy) = received[1].1 {
      XCTAssertEqual(policy, .never)
    } else {
      XCTFail("mutation 1 not codexApprovalPolicy")
    }
    if case .codexReasoningEffort(let effort) = received[2].1 {
      XCTAssertEqual(effort, .high)
    } else {
      XCTFail("mutation 2 not codexReasoningEffort")
    }
  }

  func testBindClaudeCodeWiresPermissionAndOutputStyleCallbacks() {
    let bar = AgentControlBar(frame: .zero)
    let conversationID = RuntimeConversationID(rawValue: "conversation-2")
    var received: [(RuntimeConversationID, RuntimeAgentControlMutation)] = []
    bar.bind(
      capabilities: .ccStub(),
      conversationID: conversationID,
      onConfigurationChange: { id, mutation in received.append((id, mutation)) }
    )
    guard let cc = bar.miniView as? ClaudeCodeControlsView else {
      return XCTFail("expected ClaudeCodeControlsView")
    }
    cc.onPermissionChange?(.acceptEdits)
    cc.onOutputStyleChange?("compact")
    XCTAssertEqual(received.count, 2)
    if case .claudeCodePermissionMode(let mode) = received[0].1 {
      XCTAssertEqual(mode, .acceptEdits)
    } else {
      XCTFail("mutation 0 not claudeCodePermissionMode")
    }
    if case .claudeCodeOutputStyle(let name) = received[1].1 {
      XCTAssertEqual(name, "compact")
    } else {
      XCTFail("mutation 1 not claudeCodeOutputStyle")
    }
  }
}
