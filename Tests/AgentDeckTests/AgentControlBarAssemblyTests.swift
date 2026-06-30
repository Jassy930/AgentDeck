import XCTest
import AppKit
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

    /// C2 fix (v0.2 final review): when bound with a sessionId +
    /// onVendorControl sink, the Codex inner mini view's callbacks
    /// must funnel popup changes into the sink as typed
    /// `VendorControlPayload.codex(...)` values. Previously the
    /// bind() method dropped the callbacks on the floor so user
    /// toggles never reached the daemon.
    func testBindCodexWiresSandboxAndApprovalAndEffortCallbacks() {
        let bar = AgentControlBar(frame: .zero)
        var received: [(String, VendorControlPayload)] = []
        bar.bind(
            capabilities: .codexStub(),
            sessionId: "sid-1",
            onVendorControl: { sid, payload in received.append((sid, payload)) }
        )
        guard let codex = bar.miniView as? CodexControlsView else {
            return XCTFail("expected CodexControlsView")
        }
        codex.onSandboxChange?(.readOnly)
        codex.onApprovalChange?(.never)
        codex.onEffortChange?(.high)
        XCTAssertEqual(received.count, 3)
        XCTAssertEqual(received[0].0, "sid-1")
        if case .codex(.updateSandbox(let mode)) = received[0].1 {
            XCTAssertEqual(mode, .readOnly)
        } else {
            XCTFail("payload 0 not updateSandbox")
        }
        if case .codex(.updateApprovalPolicy(let policy)) = received[1].1 {
            XCTAssertEqual(policy, .never)
        } else {
            XCTFail("payload 1 not updateApprovalPolicy")
        }
        if case .codex(.updateReasoningEffort(let effort)) = received[2].1 {
            XCTAssertEqual(effort, .high)
        } else {
            XCTFail("payload 2 not updateReasoningEffort")
        }
    }

    func testBindClaudeCodeWiresPermissionAndOutputStyleCallbacks() {
        let bar = AgentControlBar(frame: .zero)
        var received: [(String, VendorControlPayload)] = []
        bar.bind(
            capabilities: .ccStub(),
            sessionId: "sid-2",
            onVendorControl: { sid, payload in received.append((sid, payload)) }
        )
        guard let cc = bar.miniView as? ClaudeCodeControlsView else {
            return XCTFail("expected ClaudeCodeControlsView")
        }
        cc.onPermissionChange?(.acceptEdits)
        cc.onOutputStyleChange?("compact")
        XCTAssertEqual(received.count, 2)
        if case .claudeCode(.updatePermissionMode(let mode)) = received[0].1 {
            XCTAssertEqual(mode, .acceptEdits)
        } else {
            XCTFail("payload 0 not updatePermissionMode")
        }
        if case .claudeCode(.updateOutputStyle(let name)) = received[1].1 {
            XCTAssertEqual(name, "compact")
        } else {
            XCTFail("payload 1 not updateOutputStyle")
        }
    }
}
