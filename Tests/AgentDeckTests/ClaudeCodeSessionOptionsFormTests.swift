import XCTest
@testable import AgentDeck

@MainActor
final class ClaudeCodeSessionOptionsFormTests: XCTestCase {

    func testDefaultsBuildToClaudeCodeOptions() {
        let form = ClaudeCodeSessionOptionsForm()
        form.loadViewIfNeeded()
        let opts = form.buildVendorOptions()
        guard case .claudeCode(let cc) = opts else { return XCTFail("expected cc options") }
        XCTAssertEqual(cc.permissionMode, .default)
        XCTAssertNil(cc.model)
        XCTAssertNil(cc.effort)
        XCTAssertNil(cc.outputStyle)
        XCTAssertNil(cc.worktree)
        XCTAssertNil(cc.sessionName)
        XCTAssertTrue(cc.hooks.isEmpty)
        XCTAssertTrue(cc.pluginDirs.isEmpty)
    }

    func testProgrammaticSettersTrimAndApply() {
        let form = ClaudeCodeSessionOptionsForm()
        form.loadViewIfNeeded()
        form.setPermissionMode(.plan)
        form.setModel("opus")
        form.setEffort("high")
        form.setOutputStyle("concise")
        form.setWorktree("/tmp/wt")
        form.setSessionName("alpha")
        let opts = form.buildVendorOptions()
        guard case .claudeCode(let cc) = opts else { return XCTFail() }
        XCTAssertEqual(cc.permissionMode, .plan)
        XCTAssertEqual(cc.model, "opus")
        XCTAssertEqual(cc.effort, "high")
        XCTAssertEqual(cc.outputStyle, "concise")
        XCTAssertEqual(cc.worktree, "/tmp/wt")
        XCTAssertEqual(cc.sessionName, "alpha")
    }

    func testEmptyStringsCoerceToNil() {
        let form = ClaudeCodeSessionOptionsForm()
        form.loadViewIfNeeded()
        form.setModel("   ")
        form.setEffort("")
        let opts = form.buildVendorOptions()
        guard case .claudeCode(let cc) = opts else { return XCTFail() }
        XCTAssertNil(cc.model)
        XCTAssertNil(cc.effort)
    }
}
