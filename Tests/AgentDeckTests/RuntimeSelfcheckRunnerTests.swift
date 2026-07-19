import AgentDeckCore
import Foundation
import XCTest

@testable import AgentDeck

final class RuntimeSelfcheckRunnerTests: XCTestCase {
  func testSuccessUsesDescribeAgentsAndEmitsCanonicalJSONBeforeCloseOnly() async throws {
    let wire = RuntimeSelfcheckFakeWire(reply: .agents(try agentDescriptions()))
    let execution = await RuntimeSelfcheckRunner(wireFactory: { wire }).run()

    XCTAssertEqual(execution.exitCode, 0)
    XCTAssertEqual(
      String(decoding: execution.stdout, as: UTF8.self),
      #"{"agents":["claude_code","codex"],"ok":true,"protocolVersion":2,"reply":"selfcheck"}"#
        + "\n"
    )
    XCTAssertTrue(execution.stderr.isEmpty)
    let trace = await wire.trace()
    XCTAssertEqual(trace.starts, 1)
    XCTAssertEqual(trace.requests, ["describeAgents"])
    XCTAssertEqual(trace.closes, 1)
  }

  func testWrongReplyFailsTypedAndStillClosesExactlyOnce() async {
    let wire = RuntimeSelfcheckFakeWire(reply: .hello(runtimeProtocolVersion: 2))
    let execution = await RuntimeSelfcheckRunner(wireFactory: { wire }).run()

    XCTAssertEqual(execution.exitCode, 1)
    XCTAssertTrue(execution.stdout.isEmpty)
    XCTAssertEqual(
      failureCode(in: execution.stderr),
      "daemon.client.selfcheck_reply_invalid"
    )
    let trace = await wire.trace()
    XCTAssertEqual(trace.requests, ["describeAgents"])
    XCTAssertEqual(trace.closes, 1)
  }

  func testDaemonFailurePreservesExactCodeAndDiagnosticReference() async {
    let wire = RuntimeSelfcheckFakeWire(
      reply: .failure(
        RuntimeFailureV1(
          code: "daemon.runtime.recovery_blocked",
          message: "runtime recovery is blocked",
          diagnosticRef: "diag-selfcheck"
        )
      )
    )
    let execution = await RuntimeSelfcheckRunner(wireFactory: { wire }).run()

    XCTAssertEqual(execution.exitCode, 1)
    XCTAssertEqual(failureCode(in: execution.stderr), "daemon.runtime.recovery_blocked")
    XCTAssertEqual(failureDiagnosticRef(in: execution.stderr), "diag-selfcheck")
    let trace = await wire.trace()
    XCTAssertEqual(trace.closes, 1)
  }

  func testSocketOrHelloFailurePreservesExactClientCodeAndCloses() async {
    let wire = RuntimeSelfcheckFakeWire(
      reply: .hello(runtimeProtocolVersion: 2),
      startFailure: RuntimeEnvelopeClientFailure(
        code: "daemon.client.socket_missing",
        message: "canonical shared-daemon socket is missing"
      )
    )
    let execution = await RuntimeSelfcheckRunner(wireFactory: { wire }).run()

    XCTAssertEqual(execution.exitCode, 1)
    XCTAssertEqual(failureCode(in: execution.stderr), "daemon.client.socket_missing")
    let trace = await wire.trace()
    XCTAssertEqual(trace.starts, 1)
    XCTAssertTrue(trace.requests.isEmpty)
    XCTAssertEqual(trace.closes, 1)
  }

  func testMainSelfcheckSourceHasNoLegacyOrDiagnosticsFallbackTokens() throws {
    let root = URL(fileURLWithPath: #filePath)
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
    let main = try String(
      contentsOf: root.appendingPathComponent("Sources/AgentDeck/main.swift"),
      encoding: .utf8
    )
    let runner = try String(
      contentsOf: root.appendingPathComponent("Sources/AgentDeck/RuntimeSelfcheckRunner.swift"),
      encoding: .utf8
    )
    let selfcheckStart = try XCTUnwrap(
      main.range(of: #"if CommandLine.arguments.contains("--selfcheck")"#)
    )
    let diagnosticsStart = try XCTUnwrap(
      main.range(of: #"if CommandLine.arguments.contains("--diagnostics-report")"#)
    )
    let selfcheckSource = String(main[selfcheckStart.lowerBound..<diagnosticsStart.lowerBound])
    let diagnosticsSource = String(main[diagnosticsStart.lowerBound...])

    for forbidden in ["DaemonClient", "ProcessDaemonTransport", "runDaemonOneShot", ".shutdown"] {
      XCTAssertFalse(selfcheckSource.contains(forbidden), "selfcheck source contains \(forbidden)")
      XCTAssertFalse(runner.contains(forbidden), "runner source contains \(forbidden)")
    }
    XCTAssertTrue(selfcheckSource.contains("RuntimeSelfcheckRunner"))
    XCTAssertTrue(diagnosticsSource.contains("runDaemonOneShot"))
  }

  private func failureCode(in data: Data) -> String? {
    (try? JSONSerialization.jsonObject(with: data) as? [String: Any])?["code"] as? String
  }

  private func failureDiagnosticRef(in data: Data) -> String? {
    (try? JSONSerialization.jsonObject(with: data) as? [String: Any])?["diagnosticRef"]
      as? String
  }

  private func agentDescriptions() throws -> RuntimeAgentDescriptionsV2 {
    try RuntimeAgentDescriptionsV2(agents: [
      RuntimeAgentDescriptionV2(
        agentKind: .codex,
        capabilities: try capabilities(.codex),
        defaultConfiguration: RuntimeConversationConfigurationV2(
          vendorControl: .codex(
            RuntimeCodexConversationConfigurationV2(
              approvalPolicy: .onRequest,
              sandbox: .workspaceWrite,
              reasoningEffort: .medium
            )
          )
        )
      ),
      RuntimeAgentDescriptionV2(
        agentKind: .claudeCode,
        capabilities: try capabilities(.claudeCode),
        defaultConfiguration: RuntimeConversationConfigurationV2(
          vendorControl: .claudeCode(
            try RuntimeClaudeCodeConversationConfigurationV2(
              permissionMode: .default,
              model: nil,
              effort: nil,
              outputStyle: nil
            )
          )
        )
      ),
    ])
  }

  private func capabilities(_ kind: AgentKind) throws -> RuntimeSessionCapabilitiesV1 {
    let json: String
    switch kind {
    case .codex:
      json =
        #"{"agentKind":"codex","agentVersion":"fixture","features":[],"vendor":{"agentKind":"codex","sandboxModes":[],"persistenceSupported":false,"reasoningEffortLevels":[]}}"#
    case .claudeCode:
      json =
        #"{"agentKind":"claude_code","agentVersion":"fixture","features":[],"vendor":{"agentKind":"claude_code","permissionModes":[],"outputStyles":[],"hooksSupported":[],"cliVersion":"fixture"}}"#
    }
    return try JSONDecoder().decode(RuntimeSessionCapabilitiesV1.self, from: Data(json.utf8))
  }
}

private actor RuntimeSelfcheckFakeWire: AppRuntimeWireSession {
  private let reply: RuntimeReplyV2
  private let startFailure: RuntimeEnvelopeClientFailure?
  private var startCount = 0
  private var requestKinds: [String] = []
  private var closeCount = 0

  init(
    reply: RuntimeReplyV2,
    startFailure: RuntimeEnvelopeClientFailure? = nil
  ) {
    self.reply = reply
    self.startFailure = startFailure
  }

  func start() async throws {
    startCount += 1
    if let startFailure { throw startFailure }
  }

  func request(_ request: RuntimeRequestV2) async throws -> RuntimeReplyV2 {
    guard case .describeAgents = request else {
      throw RuntimeEnvelopeClientFailure(
        code: "test.selfcheck.unexpected_request",
        message: "selfcheck sent a request other than DescribeAgents"
      )
    }
    requestKinds.append("describeAgents")
    return reply
  }

  func beginAppSynchronizedRequest(
    _ request: RuntimeRequestV2
  ) async throws -> any AppRuntimeWireReplySequence {
    throw RuntimeEnvelopeClientFailure(
      code: "test.selfcheck.sequence_forbidden",
      message: "selfcheck must not start a synchronized request"
    )
  }

  func nextStream() async throws -> LocalRuntimeStreamFrame {
    throw RuntimeEnvelopeClientFailure(
      code: "test.selfcheck.stream_forbidden",
      message: "selfcheck must not read the Runtime stream"
    )
  }

  func close() async {
    closeCount += 1
  }

  func trace() -> (starts: Int, requests: [String], closes: Int) {
    (startCount, requestKinds, closeCount)
  }
}
