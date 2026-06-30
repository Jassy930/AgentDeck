import XCTest
@testable import AgentDeck

/// Verifies the v2 wire shapes decode correctly on the Swift side. These
/// are guardrails for the cross-language IPC seam — daemon emits Rust
/// `serde_json` output, Swift decodes via `JSONDecoder`; both must agree
/// on field names, tag discriminators, and enum value renames.
final class ProtocolV2DecodingTests: XCTestCase {

    func testDecodeSessionStarted() throws {
        let json = #"{"type":"sessionStarted","sessionId":"s1","threadId":null,"agentKind":"codex"}"#
        let event = try DaemonClient.decodeServerEvent(json)
        guard case let .sessionStarted(sid, tid, kind) = event else {
            return XCTFail("expected sessionStarted, got \(event)")
        }
        XCTAssertEqual(sid, "s1")
        XCTAssertNil(tid)
        XCTAssertEqual(kind, .codex)
    }

    func testDecodeSessionStartedWithClaudeCode() throws {
        let json = #"{"type":"sessionStarted","sessionId":"s2","threadId":"t1","agentKind":"claude_code"}"#
        let event = try DaemonClient.decodeServerEvent(json)
        guard case let .sessionStarted(_, tid, kind) = event else {
            return XCTFail("expected sessionStarted")
        }
        XCTAssertEqual(tid, "t1")
        XCTAssertEqual(kind, .claudeCode)
    }

    func testDecodeAgentItemAssistantMessage() throws {
        let json = """
        {"type":"agentItem","sessionId":"s1","threadId":"t1","agentKind":"claude_code",
         "item":{"kind":"assistantMessage","text":"hi","meta":{"vendorExtensions":{}}}}
        """
        let event = try DaemonClient.decodeServerEvent(json)
        guard case let .agentItem(_, _, kind, item) = event else {
            return XCTFail("expected agentItem")
        }
        XCTAssertEqual(kind, .claudeCode)
        guard case let .assistantMessage(text, _) = item else {
            return XCTFail("expected assistantMessage")
        }
        XCTAssertEqual(text, "hi")
    }

    func testDecodeAgentItemShell() throws {
        let json = """
        {"type":"agentItem","sessionId":"s1","threadId":"t1","agentKind":"codex",
         "item":{"kind":"shell","command":"ls","status":"completed","exitCode":0,
                 "durationMs":42,"meta":{"vendorExtensions":{}}}}
        """
        let event = try DaemonClient.decodeServerEvent(json)
        guard case let .agentItem(_, _, _, item) = event,
              case let .shell(cmd, status, exit, dur, _) = item
        else { return XCTFail("expected shell agentItem") }
        XCTAssertEqual(cmd, "ls")
        XCTAssertEqual(status, .completed)
        XCTAssertEqual(exit, 0)
        XCTAssertEqual(dur, 42)
    }

    func testDecodeSessionCapabilitiesCodex() throws {
        let json = """
        {"type":"sessionCapabilities","sessionId":"s1","agentKind":"codex","capabilities":{
            "agentKind":"codex","agentVersion":"codex 0.x",
            "features":["streamingMessages","codexSandboxMode"],
            "vendor":{"agentKind":"codex","sandboxModes":["read-only"],
                      "persistenceSupported":true,"reasoningEffortLevels":["medium"]}
        }}
        """
        let event = try DaemonClient.decodeServerEvent(json)
        guard case let .sessionCapabilities(_, kind, caps) = event else {
            return XCTFail("expected sessionCapabilities")
        }
        XCTAssertEqual(kind, .codex)
        XCTAssertTrue(caps.features.contains(.codexSandboxMode))
        XCTAssertTrue(caps.features.contains(.streamingMessages))
        guard case let .codex(vendor) = caps.vendor else {
            return XCTFail("expected vendor=codex")
        }
        XCTAssertEqual(vendor.sandboxModes, [.readOnly])
        XCTAssertEqual(vendor.reasoningEffortLevels, [.medium])
        XCTAssertTrue(vendor.persistenceSupported)
    }

    func testDecodeSessionCapabilitiesClaudeCode() throws {
        let json = """
        {"type":"sessionCapabilities","sessionId":"s9","agentKind":"claude_code","capabilities":{
            "agentKind":"claude_code","agentVersion":"1.0",
            "features":["streamingMessages","claudeCodePermissionMode"],
            "vendor":{"agentKind":"claude_code","permissionModes":["default","plan"],
                      "outputStyles":[],"hooksSupported":[],"cliVersion":"1.0"}
        }}
        """
        let event = try DaemonClient.decodeServerEvent(json)
        guard case let .sessionCapabilities(_, _, caps) = event else {
            return XCTFail("expected sessionCapabilities")
        }
        guard case let .claudeCode(vendor) = caps.vendor else {
            return XCTFail("expected vendor=claudeCode")
        }
        XCTAssertEqual(vendor.permissionModes, [.default, .plan])
        XCTAssertEqual(vendor.cliVersion, "1.0")
    }

    func testDecodeTurnComplete() throws {
        let json = """
        {"type":"turnComplete","sessionId":"s1","threadId":"t1","agentKind":"codex",
         "summary":{"totalInputTokens":100,"totalOutputTokens":200,"elapsedMs":1500}}
        """
        let event = try DaemonClient.decodeServerEvent(json)
        guard case let .turnComplete(_, _, _, summary) = event else {
            return XCTFail("expected turnComplete")
        }
        XCTAssertEqual(summary.totalInputTokens, 100)
        XCTAssertEqual(summary.totalOutputTokens, 200)
        XCTAssertEqual(summary.elapsedMs, 1500)
    }

    func testDecodeError() throws {
        let json = #"{"type":"error","sessionId":null,"error":{"code":"x","message":"boom","diagnosticRef":null}}"#
        let event = try DaemonClient.decodeServerEvent(json)
        guard case let .error(sid, err) = event else {
            return XCTFail("expected error")
        }
        XCTAssertNil(sid)
        XCTAssertEqual(err.code, "x")
        XCTAssertEqual(err.message, "boom")
    }

    func testDecodeActionRequestCodex() throws {
        let json = """
        {"type":"actionRequest","sessionId":"s1","threadId":"t1","agentKind":"codex",
         "request":{"requestId":"r1","kind":"executeCommand","summary":"run ls",
                    "vendor":{"agentKind":"codex","approvalPolicyAtDecision":"on-request",
                              "sandboxAtDecision":"workspace-write","canPersist":true}}}
        """
        let event = try DaemonClient.decodeServerEvent(json)
        guard case let .actionRequest(_, _, _, req) = event else {
            return XCTFail("expected actionRequest")
        }
        XCTAssertEqual(req.kind, .executeCommand)
        guard case let .codex(policy, sandbox, canPersist) = req.vendor else {
            return XCTFail("expected codex vendor")
        }
        XCTAssertEqual(policy, .onRequest)
        XCTAssertEqual(sandbox, .workspaceWrite)
        XCTAssertTrue(canPersist)
    }

    func testEncodeClientCommandPing() throws {
        let line = try DaemonClient.encodeClientCommand(.ping)
        XCTAssertTrue(line.contains("\"command\":\"ping\""), "got: \(line)")
    }

    func testEncodeClientCommandSessionStartCodex() throws {
        let cmd: ClientCommand = .sessionStart(SessionStart(
            agentKind: .codex,
            cwd: "/tmp",
            prompt: "hi",
            vendorOptions: .codex(CodexSessionOptions(
                approvalPolicy: .onRequest, sandbox: .readOnly,
                persistApproval: false, reasoningEffort: .medium
            ))
        ))
        let line = try DaemonClient.encodeClientCommand(cmd)
        XCTAssertTrue(line.contains("\"command\":\"sessionStart\""))
        XCTAssertTrue(line.contains("\"agentKind\":\"codex\""))
        // The vendorOptions.codex variant should serialise the inner options
        // alongside the agentKind tag.
        XCTAssertTrue(line.contains("\"approvalPolicy\":\"on-request\""))
        XCTAssertTrue(line.contains("\"sandbox\":\"read-only\""))
    }

    func testEncodeClientCommandHistoryList() throws {
        let cmd: ClientCommand = .history(.list(agentKind: .codex, cwdFilter: nil))
        let line = try DaemonClient.encodeClientCommand(cmd)
        XCTAssertTrue(line.contains("\"command\":\"history\""))
        XCTAssertTrue(line.contains("\"op\":\"list\""))
        XCTAssertTrue(line.contains("\"agentKind\":\"codex\""))
    }

    func testDecodeHistoryResponseList() throws {
        let json = """
        {"kind":"list","value":[{"threadId":"t1","agentKind":"codex","title":null,
         "cwd":"/tmp","lastActiveMs":100,"archived":false}]}
        """
        let response = try JSONDecoder().decode(HistoryResponse.self, from: Data(json.utf8))
        guard case let .list(items) = response else {
            return XCTFail("expected list")
        }
        XCTAssertEqual(items.count, 1)
        XCTAssertEqual(items[0].threadId, "t1")
        XCTAssertEqual(items[0].agentKind, .codex)
    }
}
