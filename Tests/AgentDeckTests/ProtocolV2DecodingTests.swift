import XCTest
import AgentDeckCore
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

    func testDecodeClaudeCodeSystemStatusVendorPanelEvent() throws {
        let json = """
        {"type":"vendorPanelEvent","sessionId":"s1","agentKind":"claude_code",
         "payload":{"agentKind":"claude_code","event":{"kind":"systemStatus",
                    "subtype":"api_retry","status":null,"message":"server_error","attempt":3,
                    "error":"server_error","errorStatus":503,"maxRetries":10,"retryDelayMs":2218.38}}}
        """
        let event = try DaemonClient.decodeServerEvent(json)
        guard case let .vendorPanelEvent(_, kind, payload) = event else {
            return XCTFail("expected vendorPanelEvent")
        }
        XCTAssertEqual(kind, .claudeCode)
        guard case let .claudeCode(vendor) = payload,
              case let .systemStatus(
                  subtype,
                  status,
                  message,
                  attempt,
                  error,
                  errorStatus,
                  maxRetries,
                  retryDelayMs
              ) = vendor
        else {
            return XCTFail("expected Claude Code systemStatus")
        }
        XCTAssertEqual(subtype, "api_retry")
        XCTAssertNil(status)
        XCTAssertEqual(message, "server_error")
        XCTAssertEqual(attempt, 3)
        XCTAssertEqual(error, "server_error")
        XCTAssertEqual(errorStatus, 503)
        XCTAssertEqual(maxRetries, 10)
        XCTAssertEqual(retryDelayMs ?? 0, 2218.38, accuracy: 0.001)
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

    /// C3 fix (v0.2 final review): sessionContinue now carries `cwd`
    /// on the wire so the daemon adapter can resume CC from the
    /// right `~/.claude/projects/<encoded_cwd>/<id>.jsonl` and run
    /// tool_use in the same directory as the original session.
    /// Without this the adapter fell back to `std::env::current_dir()`,
    /// which is the daemon's spawn directory — not the user's.
    func testEncodeClientCommandSessionContinueIncludesCwd() throws {
        let cmd: ClientCommand = .sessionContinue(
            threadId: "tid-1",
            agentKind: .claudeCode,
            cwd: "/Users/me/work/proj",
            prompt: "continue please"
        )
        let line = try DaemonClient.encodeClientCommand(cmd)
        XCTAssertTrue(line.contains("\"command\":\"sessionContinue\""), "got: \(line)")
        XCTAssertTrue(line.contains("\"agentKind\":\"claude_code\""), "got: \(line)")
        XCTAssertTrue(line.contains("\"threadId\":\"tid-1\""), "got: \(line)")
        // JSONEncoder escapes forward slashes by default (`\/`), so
        // match the encoded form rather than the literal path.
        XCTAssertTrue(
            line.contains("\"cwd\":\"\\/Users\\/me\\/work\\/proj\""),
            "got: \(line)"
        )
        XCTAssertTrue(line.contains("\"prompt\":\"continue please\""), "got: \(line)")
    }

    func testEncodeClientCommandHistoryList() throws {
        let cmd: ClientCommand = .history(.list(agentKind: .codex, cwdFilter: nil, limit: nil))
        let line = try DaemonClient.encodeClientCommand(cmd)
        XCTAssertTrue(line.contains("\"command\":\"history\""))
        XCTAssertTrue(line.contains("\"op\":\"list\""))
        XCTAssertTrue(line.contains("\"agentKind\":\"codex\""))
        XCTAssertFalse(line.contains("\"requestId\""), "legacy request should omit a nil requestId")
    }

    func testDecodeLegacyHistoryRequestWithoutRequestId() throws {
        let json = #"{"op":"list","agentKind":"codex","limit":25}"#
        let request = try JSONDecoder().decode(HistoryRequest.self, from: Data(json.utf8))

        XCTAssertNil(request.requestId)
        guard case let .list(agentKind, cwdFilter, limit, requestId) = request else {
            return XCTFail("expected list")
        }
        XCTAssertEqual(agentKind, .codex)
        XCTAssertNil(cwdFilter)
        XCTAssertEqual(limit, 25)
        XCTAssertNil(requestId)
    }

    func testHistoryRequestIdRoundTripsForEveryOperation() throws {
        let requests: [HistoryRequest] = [
            .list(agentKind: nil, cwdFilter: "/proj", limit: 25),
            .read(threadId: "read-1", agentKind: .codex),
            .archive(threadId: "archive-1", agentKind: .claudeCode),
            .unarchive(threadId: "unarchive-1", agentKind: .codex),
            .rename(threadId: "rename-1", agentKind: .claudeCode, title: "renamed"),
        ]

        for request in requests {
            let correlated = request.withRequestId("history-request-42")
            XCTAssertEqual(correlated.requestId, "history-request-42")

            let data = try JSONEncoder().encode(correlated)
            let wire = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
            XCTAssertEqual(wire["requestId"] as? String, "history-request-42")

            let decoded = try JSONDecoder().decode(HistoryRequest.self, from: data)
            XCTAssertEqual(decoded.requestId, "history-request-42")
        }
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
