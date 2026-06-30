import XCTest
@testable import AgentDeck

@MainActor
final class NewSessionDialogEncodingTests: XCTestCase {

    func testBuildSessionStartCodex() throws {
        let form = CodexSessionOptionsForm()
        form.loadViewIfNeeded()
        form.setApprovalPolicy(.never)
        form.setSandbox(.readOnly)
        form.setPersistApproval(true)
        form.setReasoningEffort(.high)

        let cwd = URL(fileURLWithPath: "/tmp/proj")
        let start = NewSessionDialog.buildSessionStart(
            agentKind: .codex,
            vendorForm: form,
            cwd: cwd,
            prompt: "hi"
        )
        XCTAssertEqual(start.agentKind, .codex)
        XCTAssertEqual(start.cwd, "/tmp/proj")
        XCTAssertEqual(start.prompt, "hi")
        guard case .codex(let opts) = start.vendorOptions else {
            return XCTFail("expected codex vendor options")
        }
        XCTAssertEqual(opts.approvalPolicy, .never)
        XCTAssertEqual(opts.sandbox, .readOnly)
        XCTAssertTrue(opts.persistApproval)
        XCTAssertEqual(opts.reasoningEffort, .high)

        // Round-trip JSON-encode and ensure the agentKind discriminator + key
        // shape is preserved.
        let data = try JSONEncoder().encode(start)
        let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        XCTAssertEqual(json?["agentKind"] as? String, "codex")
        let vendor = json?["vendorOptions"] as? [String: Any]
        XCTAssertEqual(vendor?["agentKind"] as? String, "codex")
        XCTAssertEqual(vendor?["sandbox"] as? String, "read-only")
    }

    func testBuildSessionStartClaudeCode() throws {
        let form = ClaudeCodeSessionOptionsForm()
        form.loadViewIfNeeded()
        form.setPermissionMode(.plan)
        form.setModel("opus")
        form.setSessionName("alpha")

        let start = NewSessionDialog.buildSessionStart(
            agentKind: .claudeCode,
            vendorForm: form,
            cwd: URL(fileURLWithPath: "/tmp/cc"),
            prompt: nil
        )
        XCTAssertEqual(start.agentKind, .claudeCode)
        XCTAssertNil(start.prompt)
        guard case .claudeCode(let opts) = start.vendorOptions else {
            return XCTFail("expected claude_code vendor options")
        }
        XCTAssertEqual(opts.permissionMode, .plan)
        XCTAssertEqual(opts.model, "opus")
        XCTAssertEqual(opts.sessionName, "alpha")

        let data = try JSONEncoder().encode(start)
        let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        XCTAssertEqual(json?["agentKind"] as? String, "claude_code")
        let vendor = json?["vendorOptions"] as? [String: Any]
        XCTAssertEqual(vendor?["agentKind"] as? String, "claude_code")
        XCTAssertEqual(vendor?["permissionMode"] as? String, "plan")
    }

    /// 客户端命令 .sessionStart 应该被 v2 wire 形式正确编码 —— 这是
    /// NewSessionDialog 提交链路在 daemon 上的归宿。
    func testClientCommandSessionStartRoundTrip() throws {
        let form = CodexSessionOptionsForm()
        form.loadViewIfNeeded()
        let start = NewSessionDialog.buildSessionStart(
            agentKind: .codex,
            vendorForm: form,
            cwd: URL(fileURLWithPath: "/tmp/x"),
            prompt: nil
        )
        let cmd = ClientCommand.sessionStart(start)
        let data = try JSONEncoder().encode(cmd)
        let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        XCTAssertEqual(json?["command"] as? String, "sessionStart")
        XCTAssertEqual(json?["agentKind"] as? String, "codex")
        XCTAssertEqual(json?["cwd"] as? String, "/tmp/x")
    }
}
