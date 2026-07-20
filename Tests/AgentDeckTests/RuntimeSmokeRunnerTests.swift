#if DEBUG
  import AgentDeckCore
  import Darwin
  import Foundation
  import XCTest

  @testable import AgentDeck

  final class RuntimeSmokeRunnerTests: XCTestCase {
    func testInstallationStartsHelloPathAndEmitsCanonicalStableIdentity() async {
      let wire = RuntimeSmokeFakeWire()
      let runner = RuntimeSmokeRunner(
        contextFactory: { root in
          XCTAssertEqual(root, "/private/tmp/runtime-smoke")
          return RuntimeSmokeContext(
            installationID: "11111111-1111-4111-8111-111111111111",
            wire: wire
          )
        }
      )

      let execution = await runner.run(
        arguments: smokeArguments(operation: "installation")
      )

      XCTAssertEqual(execution.exitCode, 0)
      XCTAssertEqual(
        String(decoding: execution.stdout, as: UTF8.self),
        #"{"installationId":"11111111-1111-4111-8111-111111111111","ok":true,"operation":"installation"}"#
          + "\n"
      )
      XCTAssertTrue(execution.stderr.isEmpty)
      let trace = await wire.trace()
      XCTAssertEqual(trace.starts, 1)
      XCTAssertTrue(trace.requests.isEmpty)
      XCTAssertEqual(trace.closes, 1)
    }

    func testSendPromptUsesExplicitStableInputsAndEmitsCanonicalReceipt() async {
      let wire = RuntimeSmokeFakeWire(
        unaryReplies: [
          .command(
            .accepted(
              commandID: RuntimeCommandID(rawValue: "command-swift"),
              queuePosition: 2,
              configurationRevision: 7
            )
          )
        ]
      )
      let runner = runner(wire: wire)
      let execution = await runner.run(
        arguments: smokeArguments(
          operation: "send-prompt",
          extra: [
            "--conversation-id", "conversation-shared",
            "--idempotency-key", "swift-prompt-key",
            "--expected-configuration-revision", "7",
            "--prompt", "swift smoke prompt",
          ]
        )
      )

      XCTAssertEqual(execution.exitCode, 0)
      XCTAssertEqual(
        String(decoding: execution.stdout, as: UTF8.self),
        #"{"commandId":"command-swift","configurationRevision":7,"queuePosition":2,"reply":"command","status":"accepted"}"#
          + "\n"
      )
      XCTAssertTrue(execution.stderr.isEmpty)
      let trace = await wire.trace()
      XCTAssertEqual(
        trace.requests,
        [
          .sendPrompt(
            conversationID: "conversation-shared",
            idempotencyKey: "swift-prompt-key",
            expectedConfigurationRevision: 7,
            prompt: "swift smoke prompt"
          )
        ]
      )
      XCTAssertEqual(trace.closes, 1)
    }

    func testSendPromptRejectsConfigurationRevisionMismatch() async {
      let wire = RuntimeSmokeFakeWire(
        unaryReplies: [
          .command(
            .accepted(
              commandID: RuntimeCommandID(rawValue: "command-wrong-revision"),
              queuePosition: 0,
              configurationRevision: 8
            )
          )
        ]
      )
      let execution = await runner(wire: wire).run(
        arguments: smokeArguments(
          operation: "send-prompt",
          extra: [
            "--conversation-id", "conversation-shared",
            "--idempotency-key", "swift-prompt-key",
            "--expected-configuration-revision", "7",
            "--prompt", "swift smoke prompt",
          ]
        )
      )

      XCTAssertEqual(execution.exitCode, 1)
      XCTAssertEqual(
        failureCode(in: execution.stderr),
        "daemon.client.smoke_reply_invalid"
      )
      let trace = await wire.trace()
      XCTAssertEqual(trace.closes, 1)
    }

    func testQueryReceiptPreservesCrossOwnerDaemonFailureExactlyAndNonzero() async {
      let wire = RuntimeSmokeFakeWire(
        unaryReplies: [
          .failure(
            RuntimeFailureV1(
              code: "daemon.runtime.invalid_state",
              message: "command owner does not match the requesting principal",
              diagnosticRef: "diag-cross-owner"
            )
          )
        ]
      )
      let execution = await runner(wire: wire).run(
        arguments: smokeArguments(
          operation: "query-receipt",
          extra: [
            "--conversation-id", "conversation-shared",
            "--command-id", "command-rust-owner",
          ]
        )
      )

      XCTAssertEqual(execution.exitCode, 1)
      XCTAssertTrue(execution.stdout.isEmpty)
      XCTAssertEqual(
        String(decoding: execution.stderr, as: UTF8.self),
        #"{"code":"daemon.runtime.invalid_state","diagnosticRef":"diag-cross-owner","message":"command owner does not match the requesting principal","reply":"failure"}"#
          + "\n"
      )
      let trace = await wire.trace()
      XCTAssertEqual(
        trace.requests,
        [
          .queryReceiptByCommand(
            conversationID: "conversation-shared",
            commandID: "command-rust-owner"
          )
        ]
      )
      XCTAssertEqual(trace.closes, 1)
    }

    func testQueryReceiptSupportsOwnIdempotencySelector() async {
      let wire = RuntimeSmokeFakeWire(
        unaryReplies: [
          .commandStatus(
            CommandStatusReceiptV2(
              conversationID: RuntimeConversationID(rawValue: "conversation-shared"),
              commandID: RuntimeCommandID(rawValue: "command-swift"),
              configurationRevision: 7,
              status: .accepted,
              turnID: nil
            )
          )
        ]
      )
      let execution = await runner(wire: wire).run(
        arguments: smokeArguments(
          operation: "query-receipt",
          extra: [
            "--conversation-id", "conversation-shared",
            "--idempotency-key", "swift-owner-key",
          ]
        )
      )

      XCTAssertEqual(execution.exitCode, 0)
      XCTAssertEqual(
        String(decoding: execution.stdout, as: UTF8.self),
        #"{"commandId":"command-swift","configurationRevision":7,"conversationId":"conversation-shared","reply":"commandStatus","status":"accepted","turnId":null}"#
          + "\n"
      )
      let trace = await wire.trace()
      XCTAssertEqual(
        trace.requests,
        [
          .queryReceiptByIdempotency(
            conversationID: "conversation-shared",
            idempotencyKey: "swift-owner-key"
          )
        ]
      )
    }

    func testQueryReceiptRejectsConversationMismatch() async {
      let wire = RuntimeSmokeFakeWire(
        unaryReplies: [
          .commandStatus(
            CommandStatusReceiptV2(
              conversationID: RuntimeConversationID(rawValue: "conversation-other"),
              commandID: RuntimeCommandID(rawValue: "command-swift"),
              configurationRevision: 7,
              status: .accepted,
              turnID: nil
            )
          )
        ]
      )
      let execution = await runner(wire: wire).run(
        arguments: smokeArguments(
          operation: "query-receipt",
          extra: [
            "--conversation-id", "conversation-shared",
            "--idempotency-key", "swift-owner-key",
          ]
        )
      )

      XCTAssertEqual(execution.exitCode, 1)
      XCTAssertEqual(
        failureCode(in: execution.stderr),
        "daemon.client.smoke_reply_invalid"
      )
    }

    func testQueryReceiptCommandSelectorRejectsCommandMismatch() async {
      let wire = RuntimeSmokeFakeWire(
        unaryReplies: [
          .commandStatus(
            CommandStatusReceiptV2(
              conversationID: RuntimeConversationID(rawValue: "conversation-shared"),
              commandID: RuntimeCommandID(rawValue: "command-other"),
              configurationRevision: 7,
              status: .accepted,
              turnID: nil
            )
          )
        ]
      )
      let execution = await runner(wire: wire).run(
        arguments: smokeArguments(
          operation: "query-receipt",
          extra: [
            "--conversation-id", "conversation-shared",
            "--command-id", "command-expected",
          ]
        )
      )

      XCTAssertEqual(execution.exitCode, 1)
      XCTAssertEqual(
        failureCode(in: execution.stderr),
        "daemon.client.smoke_reply_invalid"
      )
    }

    func testSubscribeRequiresFullBarrierAndReportsSortedSharedCommandEvidence() async throws {
      let conversationID = RuntimeConversationID(rawValue: "conversation-shared")
      let wire = RuntimeSmokeFakeWire(
        synchronizedReplies: [
          .subscription(
            .subscribed(streamGeneration: RuntimeStreamGeneration(rawValue: "generation-1"))
          ),
          .snapshot(try smokeSnapshot(conversationID: conversationID)),
          .backfill(try smokeBackfill(conversationID: conversationID)),
          .syncComplete(
            try smokeSyncComplete(
              conversationID: conversationID,
              outerCursor: .at(77)
            )
          ),
        ]
      )
      let execution = await runner(wire: wire).run(
        arguments: smokeArguments(
          operation: "subscribe",
          extra: ["--conversation-id", conversationID.rawValue]
        )
      )

      XCTAssertEqual(execution.exitCode, 0)
      XCTAssertEqual(
        String(decoding: execution.stdout, as: UTF8.self),
        #"{"backfillCount":1,"commandIds":["command-rust","command-swift"],"conversationId":"conversation-shared","installationId":"11111111-1111-4111-8111-111111111111","ok":true,"operation":"subscribe","snapshotCount":1,"syncComplete":true,"terminalStreamCursor":{"at":77}}"#
          + "\n"
      )
      XCTAssertTrue(execution.stderr.isEmpty)
      let trace = await wire.trace()
      XCTAssertEqual(
        trace.synchronizedRequests,
        [.subscribe(conversationID: "conversation-shared", cursor: .beforeFirst)]
      )
      XCTAssertEqual(trace.sequenceReads, 5)
      XCTAssertEqual(trace.closes, 1)
    }

    func testSubscribeAcceptsSnapshotOnlyBarrierWithoutInventingBackfill() async throws {
      let conversationID = RuntimeConversationID(rawValue: "conversation-snapshot-only")
      let wire = RuntimeSmokeFakeWire(
        synchronizedReplies: [
          .subscription(
            .subscribed(streamGeneration: RuntimeStreamGeneration(rawValue: "generation-2"))
          ),
          .snapshot(
            try smokeSnapshot(
              conversationID: conversationID,
              baseEventCursor: .at(1),
              commandIDs: ["command-swift", "command-rust"]
            )
          ),
          .syncComplete(
            try smokeSyncComplete(
              conversationID: conversationID,
              generation: "generation-2"
            )
          ),
        ]
      )
      let execution = await runner(wire: wire).run(
        arguments: smokeArguments(
          operation: "subscribe",
          extra: ["--conversation-id", conversationID.rawValue]
        )
      )

      XCTAssertEqual(execution.exitCode, 0)
      XCTAssertEqual(
        String(decoding: execution.stdout, as: UTF8.self),
        #"{"backfillCount":0,"commandIds":["command-rust","command-swift"],"conversationId":"conversation-snapshot-only","installationId":"11111111-1111-4111-8111-111111111111","ok":true,"operation":"subscribe","snapshotCount":1,"syncComplete":true,"terminalStreamCursor":{"at":1}}"#
          + "\n"
      )
      let trace = await wire.trace()
      XCTAssertEqual(trace.sequenceReads, 4)
      XCTAssertEqual(trace.closes, 1)
    }

    func testSubscribeRejectsBackfillCursorGap() async throws {
      let conversationID = RuntimeConversationID(rawValue: "conversation-gap")
      let wire = RuntimeSmokeFakeWire(
        synchronizedReplies: [
          .subscription(
            .subscribed(streamGeneration: RuntimeStreamGeneration(rawValue: "generation-1"))
          ),
          .snapshot(try smokeSnapshot(conversationID: conversationID)),
          .backfill(
            try smokeBackfill(
              conversationID: conversationID,
              after: .at(4),
              through: .at(5),
              commandIDs: ["command-gap"]
            )
          ),
          .syncComplete(try smokeSyncComplete(conversationID: conversationID)),
        ]
      )
      let execution = await runner(wire: wire).run(
        arguments: smokeArguments(
          operation: "subscribe",
          extra: ["--conversation-id", conversationID.rawValue]
        )
      )

      XCTAssertEqual(execution.exitCode, 1)
      XCTAssertEqual(
        failureCode(in: execution.stderr),
        "daemon.client.smoke_reply_invalid"
      )
      let trace = await wire.trace()
      XCTAssertEqual(trace.sequenceReads, 3)
      XCTAssertEqual(trace.closes, 1)
    }

    func testSubscribeRejectsGenerationMismatch() async throws {
      let conversationID = RuntimeConversationID(rawValue: "conversation-generation")
      let wire = RuntimeSmokeFakeWire(
        synchronizedReplies: [
          .subscription(
            .subscribed(streamGeneration: RuntimeStreamGeneration(rawValue: "generation-1"))
          ),
          .snapshot(try smokeSnapshot(conversationID: conversationID)),
          .backfill(try smokeBackfill(conversationID: conversationID)),
          .syncComplete(
            try smokeSyncComplete(
              conversationID: conversationID,
              generation: "generation-other"
            )
          ),
        ]
      )
      let execution = await runner(wire: wire).run(
        arguments: smokeArguments(
          operation: "subscribe",
          extra: ["--conversation-id", conversationID.rawValue]
        )
      )

      XCTAssertEqual(execution.exitCode, 1)
      XCTAssertEqual(
        failureCode(in: execution.stderr),
        "daemon.client.smoke_reply_invalid"
      )
      let trace = await wire.trace()
      XCTAssertEqual(trace.closes, 1)
    }

    func testSocketFlagsAndDuplicateRootAreRejectedBeforeContextCreation() async {
      let probe = RuntimeSmokeContextFactoryProbe()
      let runner = RuntimeSmokeRunner(
        contextFactory: { root in
          await probe.record(root)
          throw RuntimeEnvelopeClientFailure(code: "test.unreachable", message: "unreachable")
        }
      )

      let socketExecution = await runner.run(
        arguments: smokeArguments(operation: "installation") + ["--socket", "/tmp/forbidden"]
      )
      XCTAssertEqual(socketExecution.exitCode, 2)
      XCTAssertEqual(
        failureCode(in: socketExecution.stderr),
        "daemon.client.smoke_usage_invalid"
      )

      let duplicateExecution = await runner.run(
        arguments: smokeArguments(operation: "installation")
          + ["--runtime-temp-root-for-test", "/private/tmp/second"]
      )
      XCTAssertEqual(duplicateExecution.exitCode, 2)
      XCTAssertEqual(
        failureCode(in: duplicateExecution.stderr),
        "daemon.client.smoke_usage_invalid"
      )
      let recordedRoots = await probe.roots()
      XCTAssertEqual(recordedRoots, [])
    }

    func testRealDiscoveredEndpointUsesPersistentInstallationReadback() async throws {
      let peer = try RuntimeSmokeRealPeer()
      let server = Task.detached {
        try peer.serveHelloConnections(count: 2)
      }
      let arguments = [
        "/tmp/AgentDeck",
        "--runtime-smoke-for-test", "installation",
        "--runtime-temp-root-for-test", peer.rootPath,
      ]

      let first = await RuntimeSmokeRunner().run(arguments: arguments)
      let second = await RuntimeSmokeRunner().run(arguments: arguments)
      let prefaceInstallationIDs = try await server.value

      XCTAssertEqual(first.exitCode, 0, String(decoding: first.stderr, as: UTF8.self))
      XCTAssertEqual(second.exitCode, 0, String(decoding: second.stderr, as: UTF8.self))
      let firstID = installationID(in: first.stdout)
      let secondID = installationID(in: second.stdout)
      XCTAssertNotNil(firstID)
      XCTAssertEqual(firstID, secondID)
      XCTAssertEqual(prefaceInstallationIDs, [firstID, secondID].compactMap { $0 })

      let installationHome = URL(fileURLWithPath: peer.rootPath, isDirectory: true)
        .appendingPathComponent("clients", isDirectory: true)
        .appendingPathComponent("macos-app", isDirectory: true)
      let installation = LocalClientInstallation.injectedForTesting(
        homeDirectory: installationHome
      )
      XCTAssertTrue(
        FileManager.default.fileExists(atPath: installation.recordPath.path),
        "smoke helper did not persist the installation under <root>/clients/macos-app"
      )
    }

    func testDebugMainSelfcheckUsesDiscoveredRootAndDescribeAgents() async throws {
      let peer = try RuntimeSmokeRealPeer()
      let server = Task.detached {
        try peer.serveSelfcheckConnection()
      }
      let projectRoot = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
      let process = Process()
      let stdout = Pipe()
      let stderr = Pipe()
      process.executableURL = projectRoot.appendingPathComponent(".build/debug/AgentDeck")
      process.currentDirectoryURL = URL(fileURLWithPath: peer.rootPath, isDirectory: true)
      process.arguments = [
        "--selfcheck",
        "--runtime-temp-root-for-test", peer.rootPath,
      ]
      process.standardOutput = stdout
      process.standardError = stderr

      try process.run()
      process.waitUntilExit()
      let evidence = try await server.value
      let output = stdout.fileHandleForReading.readDataToEndOfFile()
      let errorOutput = stderr.fileHandleForReading.readDataToEndOfFile()

      XCTAssertEqual(
        process.terminationStatus,
        0,
        String(decoding: errorOutput, as: UTF8.self)
      )
      XCTAssertEqual(
        String(decoding: output, as: UTF8.self),
        #"{"agents":[],"ok":true,"protocolVersion":3,"reply":"selfcheck"}"# + "\n"
      )
      XCTAssertTrue(errorOutput.isEmpty)
      XCTAssertEqual(evidence.request, "describeAgents")

      let installationHome = URL(fileURLWithPath: peer.rootPath, isDirectory: true)
        .appendingPathComponent("clients", isDirectory: true)
        .appendingPathComponent("macos-app", isDirectory: true)
      let persisted = try LocalClientInstallation.injectedForTesting(
        homeDirectory: installationHome
      ).loadOrCreate()
      XCTAssertEqual(evidence.installationID, persisted.rawValue)
    }

    func testSelfcheckTempRootParserDefaultsAndRejectsDuplicates() throws {
      XCTAssertNil(
        try RuntimeSmokeEnvironment.selfcheckWire(
          arguments: ["/tmp/AgentDeck", "--selfcheck"]
        )
      )
      XCTAssertThrowsError(
        try RuntimeSmokeEnvironment.selfcheckWire(
          arguments: [
            "/tmp/AgentDeck",
            "--selfcheck",
            "--runtime-temp-root-for-test", "/tmp/one",
            "--runtime-temp-root-for-test", "/tmp/two",
          ]
        )
      ) { error in
        XCTAssertEqual(
          (error as? RuntimeEnvelopeClientFailure)?.code,
          "daemon.client.selfcheck_usage_invalid"
        )
      }
      XCTAssertThrowsError(
        try RuntimeSmokeEnvironment.selfcheckWire(
          arguments: [
            "/tmp/AgentDeck",
            "--selfcheck",
            "--runtime-temp-root-for-test=/tmp/one",
          ]
        )
      ) { error in
        XCTAssertEqual(
          (error as? RuntimeEnvelopeClientFailure)?.code,
          "daemon.client.selfcheck_usage_invalid"
        )
      }
    }

    func testRealEnvironmentRejectsWrongModeMultipleAndSymlinkNamespace() async throws {
      let wrongMode = try RuntimeSmokeRealPeer()
      XCTAssertEqual(Darwin.chmod(wrongMode.rootPath, 0o755), 0)
      let wrongModeExecution = await RuntimeSmokeRunner().run(
        arguments: realInstallationArguments(root: wrongMode.rootPath)
      )
      XCTAssertEqual(failureCode(in: wrongModeExecution.stderr), "daemon.client.socket_unsafe")

      let multiple = try RuntimeSmokeRealPeer()
      try multiple.addNamespace()
      let multipleExecution = await RuntimeSmokeRunner().run(
        arguments: realInstallationArguments(root: multiple.rootPath)
      )
      XCTAssertEqual(failureCode(in: multipleExecution.stderr), "daemon.client.socket_unsafe")

      let symlinkRoot = try RuntimeSmokeSymlinkRoot()
      let symlinkExecution = await RuntimeSmokeRunner().run(
        arguments: realInstallationArguments(root: symlinkRoot.rootPath)
      )
      XCTAssertEqual(failureCode(in: symlinkExecution.stderr), "daemon.client.socket_unsafe")
    }

    func testSmokeEntryAndEndpointSeamAreDebugOnlyWithNoEnvironmentOverride() throws {
      let root = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
      let main = try String(
        contentsOf: root.appendingPathComponent("Sources/AgentDeck/main.swift"),
        encoding: .utf8
      )
      let runner = try String(
        contentsOf: root.appendingPathComponent("Sources/AgentDeck/RuntimeSmokeRunner.swift"),
        encoding: .utf8
      )
      let debugStart = try XCTUnwrap(main.range(of: "#if DEBUG"))
      let flag = try XCTUnwrap(main.range(of: #"--runtime-smoke-for-test"#))
      let debugEnd = try XCTUnwrap(
        main.range(of: "#endif", range: flag.upperBound..<main.endIndex)
      )

      XCTAssertLessThan(debugStart.lowerBound, flag.lowerBound)
      XCTAssertLessThan(flag.upperBound, debugEnd.lowerBound)
      XCTAssertTrue(runner.hasPrefix("#if DEBUG"))
      XCTAssertTrue(runner.hasSuffix("#endif\n"))
      XCTAssertFalse(runner.contains(#""--socket""#))
      XCTAssertFalse(runner.contains("ProcessInfo.processInfo.environment"))
      XCTAssertFalse(runner.contains("AGENTDECK_RELAY_SOCKET"))
    }

    func testReleaseGuardRejectsGenericRuntimeTestOnlyArgumentsOnly() {
      XCTAssertTrue(
        RuntimeTestOnlyArgumentGuard.shouldReject(
          arguments: ["/tmp/AgentDeck", "--runtime-smoke-for-test", "installation"]
        )
      )
      XCTAssertTrue(
        RuntimeTestOnlyArgumentGuard.shouldReject(
          arguments: ["/tmp/AgentDeck", "--runtime-temp-root-for-test", "/tmp/root"]
        )
      )
      XCTAssertTrue(
        RuntimeTestOnlyArgumentGuard.shouldReject(
          arguments: ["/tmp/AgentDeck", "--runtime-smoke-for-test=installation"]
        )
      )
      XCTAssertTrue(
        RuntimeTestOnlyArgumentGuard.shouldReject(
          arguments: ["/tmp/AgentDeck", "--runtime-temp-root-for-test=/tmp/root"]
        )
      )
      XCTAssertFalse(
        RuntimeTestOnlyArgumentGuard.shouldReject(
          arguments: ["/tmp/AgentDeck", "--selfcheck"]
        )
      )
      XCTAssertFalse(
        RuntimeTestOnlyArgumentGuard.shouldReject(
          arguments: ["/tmp/AgentDeck", "--runtime-profile", "dev"]
        )
      )
    }

    private func runner(wire: RuntimeSmokeFakeWire) -> RuntimeSmokeRunner {
      RuntimeSmokeRunner(
        contextFactory: { _ in
          RuntimeSmokeContext(
            installationID: "11111111-1111-4111-8111-111111111111",
            wire: wire
          )
        }
      )
    }

    private func smokeArguments(
      operation: String,
      extra: [String] = []
    ) -> [String] {
      [
        "/tmp/AgentDeck",
        "--runtime-smoke-for-test", operation,
        "--runtime-temp-root-for-test", "/private/tmp/runtime-smoke",
      ] + extra
    }

    private func failureCode(in data: Data) -> String? {
      (try? JSONSerialization.jsonObject(with: data) as? [String: Any])?["code"] as? String
    }

    private func installationID(in data: Data) -> String? {
      (try? JSONSerialization.jsonObject(with: data) as? [String: Any])?["installationId"]
        as? String
    }

    private func realInstallationArguments(root: String) -> [String] {
      [
        "/tmp/AgentDeck",
        "--runtime-smoke-for-test", "installation",
        "--runtime-temp-root-for-test", root,
      ]
    }
  }

  private enum RuntimeSmokeRecordedRequest: Equatable, Sendable {
    case sendPrompt(
      conversationID: String,
      idempotencyKey: String,
      expectedConfigurationRevision: UInt64,
      prompt: String
    )
    case queryReceiptByCommand(conversationID: String, commandID: String)
    case queryReceiptByIdempotency(conversationID: String, idempotencyKey: String)
  }

  private enum RuntimeSmokeRecordedSynchronizedRequest: Equatable, Sendable {
    case subscribe(conversationID: String, cursor: RuntimeStreamCursorV1)
  }

  private struct RuntimeSmokeWireTrace: Sendable {
    let starts: Int
    let requests: [RuntimeSmokeRecordedRequest]
    let synchronizedRequests: [RuntimeSmokeRecordedSynchronizedRequest]
    let sequenceReads: Int
    let closes: Int
  }

  private actor RuntimeSmokeFakeWire: AppRuntimeWireSession {
    private var unaryReplies: [RuntimeReplyV2]
    private let synchronizedReplies: [RuntimeReplyV2]
    private var startCount = 0
    private var requests: [RuntimeSmokeRecordedRequest] = []
    private var synchronizedRequests: [RuntimeSmokeRecordedSynchronizedRequest] = []
    private var sequenceReadCount = 0
    private var closeCount = 0

    init(
      unaryReplies: [RuntimeReplyV2] = [],
      synchronizedReplies: [RuntimeReplyV2] = []
    ) {
      self.unaryReplies = unaryReplies
      self.synchronizedReplies = synchronizedReplies
    }

    func start() async throws {
      startCount += 1
    }

    func request(_ request: RuntimeRequestV2) async throws -> RuntimeReplyV2 {
      switch request {
      case .sendPrompt(
        let conversationID,
        let idempotencyKey,
        let expectedConfigurationRevision,
        let prompt
      ):
        requests.append(
          .sendPrompt(
            conversationID: conversationID.rawValue,
            idempotencyKey: idempotencyKey.rawValue,
            expectedConfigurationRevision: expectedConfigurationRevision,
            prompt: prompt.rawValue
          )
        )
      case .queryReceipt(
        .idempotency(let conversationID, let idempotencyKey)
      ):
        requests.append(
          .queryReceiptByIdempotency(
            conversationID: conversationID.rawValue,
            idempotencyKey: idempotencyKey.rawValue
          )
        )
      case .queryReceipt(.command(let conversationID, let commandID)):
        requests.append(
          .queryReceiptByCommand(
            conversationID: conversationID.rawValue,
            commandID: commandID.rawValue
          )
        )
      default:
        throw RuntimeEnvelopeClientFailure(
          code: "test.runtime_smoke.request_unexpected",
          message: "unexpected unary request"
        )
      }
      guard !unaryReplies.isEmpty else {
        throw RuntimeEnvelopeClientFailure(
          code: "test.runtime_smoke.reply_missing",
          message: "missing unary reply"
        )
      }
      return unaryReplies.removeFirst()
    }

    func beginAppSynchronizedRequest(
      _ request: RuntimeRequestV2
    ) async throws -> any AppRuntimeWireReplySequence {
      guard case .subscribe(.conversation(let conversationID, let cursor)) = request else {
        throw RuntimeEnvelopeClientFailure(
          code: "test.runtime_smoke.sequence_unexpected",
          message: "unexpected synchronized request"
        )
      }
      synchronizedRequests.append(
        .subscribe(conversationID: conversationID.rawValue, cursor: cursor)
      )
      return RuntimeSmokeFakeSequence(replies: synchronizedReplies) {
        await self.recordSequenceRead()
      }
    }

    func nextStream() async throws -> LocalRuntimeStreamFrame {
      throw RuntimeEnvelopeClientFailure(
        code: "test.runtime_smoke.stream_forbidden",
        message: "smoke operation must not read live stream"
      )
    }

    func close() async {
      closeCount += 1
    }

    func trace() -> RuntimeSmokeWireTrace {
      RuntimeSmokeWireTrace(
        starts: startCount,
        requests: requests,
        synchronizedRequests: synchronizedRequests,
        sequenceReads: sequenceReadCount,
        closes: closeCount
      )
    }

    private func recordSequenceRead() {
      sequenceReadCount += 1
    }
  }

  private actor RuntimeSmokeFakeSequence: AppRuntimeWireReplySequence {
    private var replies: [RuntimeReplyV2]
    private let onRead: @Sendable () async -> Void

    init(
      replies: [RuntimeReplyV2],
      onRead: @escaping @Sendable () async -> Void
    ) {
      self.replies = replies
      self.onRead = onRead
    }

    func next() async throws -> RuntimeReplyV2? {
      await onRead()
      guard !replies.isEmpty else { return nil }
      return replies.removeFirst()
    }

    func cancel() async {}
  }

  private actor RuntimeSmokeContextFactoryProbe {
    private var values: [String] = []

    func record(_ value: String) {
      values.append(value)
    }

    func roots() -> [String] {
      values
    }
  }

  private final class RuntimeSmokeRealPeer: @unchecked Sendable {
    let rootPath: String
    private let listener: Int32
    private let socketPath: String

    init() throws {
      rootPath = "/tmp/ad-smk-\(UUID().uuidString.prefix(8).lowercased())"
      guard Darwin.mkdir(rootPath, 0o700) == 0 else { throw Self.posixError() }
      let namespace = try Self.createNamespace(rootPath: rootPath)
      socketPath = namespace + "/s"
      listener = try Self.makeListener(path: socketPath)
    }

    deinit {
      Darwin.close(listener)
      Darwin.unlink(socketPath)
      try? FileManager.default.removeItem(atPath: rootPath)
    }

    func addNamespace() throws {
      _ = try Self.createNamespace(rootPath: rootPath)
    }

    func serveHelloConnections(count: Int) throws -> [String] {
      var installationIDs: [String] = []
      for _ in 0..<count {
        try Self.waitReadable(listener)
        let connection = Darwin.accept(listener, nil, nil)
        guard connection >= 0 else { throw Self.posixError() }
        defer { Darwin.close(connection) }

        let preface = try Self.readObject(from: connection)
        guard
          preface["localProtocolVersion"] as? Int == 1,
          let installationID = preface["clientInstallationId"] as? String
        else {
          throw RuntimeEnvelopeClientFailure(
            code: "test.runtime_smoke.preface_invalid",
            message: "real smoke preface is invalid"
          )
        }
        installationIDs.append(installationID)

        let hello = try Self.readObject(from: connection)
        guard
          let messageID = hello["messageId"] as? String,
          let body = hello["body"] as? [String: Any],
          body["message"] as? String == "request",
          let payload = body["payload"] as? [String: Any],
          payload["request"] as? String == "hello",
          payload["runtimeProtocolVersion"] as? Int == Int(runtimeProtocolVersionCurrent)
        else {
          throw RuntimeEnvelopeClientFailure(
            code: "test.runtime_smoke.hello_invalid",
            message: "real smoke Hello is invalid"
          )
        }
        try Self.writeObject(
          [
            "version": Int(runtimeProtocolVersionCurrent),
            "messageId": messageID,
            "body": [
              "message": "reply",
              "payload": [
                "reply": "hello",
                "runtimeProtocolVersion": Int(runtimeProtocolVersionCurrent),
              ],
            ],
          ],
          to: connection
        )
        guard try Self.readLine(from: connection) == nil else {
          throw RuntimeEnvelopeClientFailure(
            code: "test.runtime_smoke.close_invalid",
            message: "installation smoke sent an unexpected post-Hello frame"
          )
        }
      }
      return installationIDs
    }

    func serveSelfcheckConnection() throws -> (installationID: String, request: String) {
      try Self.waitReadable(listener)
      let connection = Darwin.accept(listener, nil, nil)
      guard connection >= 0 else { throw Self.posixError() }
      defer { Darwin.close(connection) }

      let preface = try Self.readObject(from: connection)
      guard
        preface["localProtocolVersion"] as? Int == 1,
        let installationID = preface["clientInstallationId"] as? String
      else {
        throw RuntimeEnvelopeClientFailure(
          code: "test.runtime_smoke.preface_invalid",
          message: "real selfcheck preface is invalid"
        )
      }

      let hello = try Self.readObject(from: connection)
      guard
        let helloMessageID = hello["messageId"] as? String,
        let helloBody = hello["body"] as? [String: Any],
        helloBody["message"] as? String == "request",
        let helloPayload = helloBody["payload"] as? [String: Any],
        helloPayload["request"] as? String == "hello",
        helloPayload["runtimeProtocolVersion"] as? Int == Int(runtimeProtocolVersionCurrent)
      else {
        throw RuntimeEnvelopeClientFailure(
          code: "test.runtime_smoke.hello_invalid",
          message: "real selfcheck Hello is invalid"
        )
      }
      try Self.writeObject(
        [
          "version": Int(runtimeProtocolVersionCurrent),
          "messageId": helloMessageID,
          "body": [
            "message": "reply",
            "payload": [
              "reply": "hello",
              "runtimeProtocolVersion": Int(runtimeProtocolVersionCurrent),
            ],
          ],
        ],
        to: connection
      )

      let describe = try Self.readObject(from: connection)
      guard
        let describeMessageID = describe["messageId"] as? String,
        let describeBody = describe["body"] as? [String: Any],
        describeBody["message"] as? String == "request",
        let describePayload = describeBody["payload"] as? [String: Any],
        describePayload["request"] as? String == "describeAgents"
      else {
        throw RuntimeEnvelopeClientFailure(
          code: "test.runtime_smoke.selfcheck_request_invalid",
          message: "selfcheck did not send DescribeAgents"
        )
      }
      try Self.writeObject(
        [
          "version": Int(runtimeProtocolVersionCurrent),
          "messageId": describeMessageID,
          "body": [
            "message": "reply",
            "payload": ["reply": "agents", "agents": []],
          ],
        ],
        to: connection
      )
      guard try Self.readLine(from: connection) == nil else {
        throw RuntimeEnvelopeClientFailure(
          code: "test.runtime_smoke.selfcheck_close_invalid",
          message: "selfcheck sent an unexpected post-DescribeAgents frame"
        )
      }
      return (installationID, "describeAgents")
    }

    private static func createNamespace(rootPath: String) throws -> String {
      let namespace = rootPath + "/ad-" + UUID().uuidString.lowercased()
      guard Darwin.mkdir(namespace, 0o700) == 0 else { throw posixError() }
      return namespace
    }

    private static func makeListener(path: String) throws -> Int32 {
      let descriptor = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
      guard descriptor >= 0 else { throw posixError() }
      do {
        var address = try unixAddress(path: path)
        let status = withUnsafePointer(to: &address) {
          $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            Darwin.bind(descriptor, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
          }
        }
        guard
          status == 0,
          Darwin.chmod(path, 0o600) == 0,
          Darwin.listen(descriptor, 4) == 0
        else {
          throw posixError()
        }
        return descriptor
      } catch {
        Darwin.close(descriptor)
        throw error
      }
    }

    private static func unixAddress(path: String) throws -> sockaddr_un {
      let bytes = Array(path.utf8)
      guard bytes.count < MemoryLayout.size(ofValue: sockaddr_un().sun_path) else {
        throw POSIXError(.ENAMETOOLONG)
      }
      var address = sockaddr_un()
      address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
      address.sun_family = sa_family_t(AF_UNIX)
      withUnsafeMutablePointer(to: &address.sun_path) { pointer in
        pointer.withMemoryRebound(to: UInt8.self, capacity: bytes.count + 1) { target in
          for (index, byte) in bytes.enumerated() { target[index] = byte }
          target[bytes.count] = 0
        }
      }
      return address
    }

    private static func readObject(from descriptor: Int32) throws -> [String: Any] {
      guard let line = try readLine(from: descriptor) else {
        throw RuntimeEnvelopeClientFailure(
          code: "test.runtime_smoke.eof",
          message: "real smoke client closed before expected frame"
        )
      }
      guard
        let object = try JSONSerialization.jsonObject(with: Data(line.utf8))
          as? [String: Any]
      else {
        throw RuntimeEnvelopeClientFailure(
          code: "test.runtime_smoke.json_invalid",
          message: "real smoke frame is not a JSON object"
        )
      }
      return object
    }

    private static func readLine(from descriptor: Int32) throws -> String? {
      var data = Data()
      while true {
        try waitReadable(descriptor)
        var byte: UInt8 = 0
        let count = Darwin.read(descriptor, &byte, 1)
        if count == 0 { return data.isEmpty ? nil : String(data: data, encoding: .utf8) }
        if count < 0 {
          if errno == EINTR { continue }
          throw posixError()
        }
        if byte == 0x0A { return String(data: data, encoding: .utf8) }
        data.append(byte)
      }
    }

    private static func writeObject(
      _ object: [String: Any],
      to descriptor: Int32
    ) throws {
      var data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
      data.append(0x0A)
      try data.withUnsafeBytes { raw in
        guard let base = raw.baseAddress else { return }
        var offset = 0
        while offset < raw.count {
          let count = Darwin.write(
            descriptor,
            base.advanced(by: offset),
            raw.count - offset
          )
          if count > 0 {
            offset += count
          } else if count < 0, errno == EINTR {
            continue
          } else {
            throw posixError()
          }
        }
      }
    }

    private static func waitReadable(_ descriptor: Int32) throws {
      var pollDescriptor = pollfd(
        fd: descriptor,
        events: Int16(POLLIN),
        revents: 0
      )
      while true {
        let status = Darwin.poll(&pollDescriptor, 1, 5_000)
        if status > 0 { return }
        if status < 0, errno == EINTR { continue }
        if status == 0 { throw POSIXError(.ETIMEDOUT) }
        throw posixError()
      }
    }

    private static func posixError() -> POSIXError {
      POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
  }

  private final class RuntimeSmokeSymlinkRoot {
    let rootPath: String

    init() throws {
      rootPath = "/tmp/ad-smk-link-\(UUID().uuidString.prefix(8).lowercased())"
      guard Darwin.mkdir(rootPath, 0o700) == 0 else { throw Self.posixError() }
      let target = rootPath + "/target"
      guard Darwin.mkdir(target, 0o700) == 0 else { throw Self.posixError() }
      let link = rootPath + "/ad-" + UUID().uuidString.lowercased()
      guard Darwin.symlink(target, link) == 0 else { throw Self.posixError() }
    }

    deinit {
      try? FileManager.default.removeItem(atPath: rootPath)
    }

    private static func posixError() -> POSIXError {
      POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
  }

  private func smokeCapabilities() throws -> RuntimeSessionCapabilitiesV1 {
    try JSONDecoder().decode(
      RuntimeSessionCapabilitiesV1.self,
      from: Data(
        #"{"agentKind":"codex","agentVersion":"fixture","features":[],"vendor":{"agentKind":"codex","sandboxModes":[],"persistenceSupported":false,"reasoningEffortLevels":[]}}"#
          .utf8
      )
    )
  }

  private func smokeSnapshot(
    conversationID: RuntimeConversationID,
    baseEventCursor: RuntimeStreamCursorV1 = .beforeFirst,
    commandIDs: [String] = []
  ) throws -> ConversationSnapshotV2 {
    let commandItems = commandIDs.enumerated().map { index, commandID in
      SnapshotItemV1.item(
        itemID: RuntimeItemID(rawValue: "snapshot-item-\(index)"),
        entityID: RuntimeEntityID(rawValue: "snapshot-entity-\(index)"),
        commandID: RuntimeCommandID(rawValue: commandID),
        item: .userMessage(
          text: "snapshot command \(index)",
          meta: RuntimeAgentItemMetaV1()
        )
      )
    }
    return try ConversationSnapshotV2(
      conversationID: conversationID,
      baseEventCursor: baseEventCursor,
      configurationState: RuntimeConversationConfigurationStateV2(
        configurationRevision: 0,
        configuration: nil
      ),
      items: [.capabilities(try smokeCapabilities())] + commandItems
    )
  }

  private func smokeBackfill(
    conversationID: RuntimeConversationID,
    after: RuntimeStreamCursorV1 = .beforeFirst,
    through: RuntimeStreamCursorV1 = .at(1),
    commandIDs: [String] = ["command-swift", "command-rust"]
  ) throws -> RuntimeBackfillChunkV2 {
    let firstSequence = try after.checkedNext()
    let events = try commandIDs.enumerated().map { index, commandID in
      try RuntimeEventV2(
        conversationID: conversationID,
        eventID: RuntimeEventID(rawValue: "event-\(index)"),
        eventSeq: firstSequence + UInt64(index),
        commandID: RuntimeCommandID(rawValue: commandID),
        itemID: nil,
        entityID: nil,
        body: .turnStarted(turnID: RuntimeTurnID(rawValue: "turn-\(index)"))
      )
    }
    return .conversation(
      conversationID: conversationID,
      capabilitiesPreamble: try smokeCapabilities(),
      range: try RuntimeBackfillRangeV1(after: after, through: through),
      events: events
    )
  }

  private func smokeSyncComplete(
    conversationID: RuntimeConversationID,
    generation: String = "generation-1",
    innerCursor: RuntimeStreamCursorV1 = .at(1),
    outerCursor: RuntimeStreamCursorV1? = nil
  ) throws -> RuntimeSyncCompleteV1 {
    let innerCursorObject: Any =
      switch innerCursor {
      case .beforeFirst:
        "beforeFirst"
      case .at(let value):
        ["at": value]
      }
    let outerCursorObject: Any =
      switch outerCursor ?? innerCursor {
      case .beforeFirst:
        "beforeFirst"
      case .at(let value):
        ["at": value]
      }
    let object: [String: Any] = [
      "streamGeneration": generation,
      "streamCursor": outerCursorObject,
      "innerCursor": [
        "scope": "conversation",
        "conversationId": conversationID.rawValue,
        "cursor": innerCursorObject,
      ],
      "keyDirectoryRevision": 2,
    ]
    return try JSONDecoder().decode(
      RuntimeSyncCompleteV1.self,
      from: JSONSerialization.data(withJSONObject: object)
    )
  }
#endif
