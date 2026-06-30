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
}
