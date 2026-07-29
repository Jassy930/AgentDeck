import AgentDeckCore
import AgentDeckSessionSource
import Darwin
import Foundation
import XCTest

@testable import AgentDeck
@testable import AgentDeckRelayClient

/// P5.7 Step 4 的真实双 scope 门禁。
///
/// Rust host 只替换 vendor 为 synthetic adapter；temp Direct TLS Relay、RuntimeCore、
/// PairingCoordinator、RemoteManager/RemoteLink、same-UID UDS 与 Swift Relay client 都走
/// production composition。host stdout 只暴露路径和非 secret identity，bearer invite
/// 始终留在 mode 0600 的文件中。
final class MachineScopeRealIntegrationTests: XCTestCase {
  func testRealLocalUDSAndRemoteLinkScopesStayCanonicalAndIsolated() async throws {
    let host = try await P57RealHost.start()
    var scenarioError: Error?

    do {
      try await runRealDualScopeScenario(host: host)
    } catch {
      scenarioError = error
    }

    do {
      try await host.shutdown()
    } catch {
      if scenarioError == nil {
        scenarioError = error
      }
    }

    if let scenarioError {
      let diagnostics = await host.diagnostics()
      throw P57IntegrationError.assertion(
        "P5.7 real dual-scope failed: \(scenarioError)\n\(diagnostics)"
      )
    }

    let ready = host.ready
    XCTAssertFalse(FileManager.default.fileExists(atPath: ready.socketPath.path))
    XCTAssertFalse(FileManager.default.fileExists(atPath: ready.rootDirectory.path))
  }

  private func runRealDualScopeScenario(host: P57RealHost) async throws {
    let ready = host.ready
    try p57RequireAbsolute(ready.rootDirectory, field: "rootDirectory")
    try p57RequireAbsolute(ready.homeDirectory, field: "homeDirectory")
    try p57RequireAbsolute(ready.socketPath, field: "socketPath")
    try p57RequireAbsolute(ready.invitePath, field: "invitePath")
    try p57RequireUnixSocket(ready.socketPath)
    try p57RequirePrivateRegularFile(ready.invitePath)

    let invitation = try p57ReadInvite(ready.invitePath)
    let installation = LocalClientInstallation.injectedForTesting(
      homeDirectory: ready.homeDirectory
    )
    guard installation.daemonSocketPath.standardizedFileURL == ready.socketPath.standardizedFileURL
    else {
      throw P57IntegrationError.hostContract("host socket does not match production installation")
    }
    let localMachineID = try installation.loadOrCreate().rawValue

    let localInboundTrace = P57LocalInboundTrace()
    let localSource = LocalDaemonSessionSource(
      installation: installation,
      machineName: "P5.7 Local",
      connectionActivation: { _ in },
      inboundHandler: { inbound, generation in
        await localInboundTrace.record(inbound, generation: generation)
      }
    )
    let localRegistration = try SessionSourceRegistration(
      scope: .local,
      source: localSource,
      capabilities: SessionSourceCapabilities(
        localPairingAdministration: localSource,
        localConversationAdministration: localSource
      ),
      lifecycle: localSource
    )

    let remoteRoot = FileManager.default.temporaryDirectory.appendingPathComponent(
      "agentdeck-p57-swift-client-\(UUID().uuidString.lowercased())",
      isDirectory: true
    )
    try FileManager.default.createDirectory(
      at: remoteRoot,
      withIntermediateDirectories: false,
      attributes: [.posixPermissions: 0o700]
    )
    defer { try? FileManager.default.removeItem(at: remoteRoot) }

    let remoteKeyStore = P57MemoryKeyStore()
    let remoteStore = PairedMachineStore(
      keyStore: remoteKeyStore,
      stateRootURL: remoteRoot,
      clientKind: .macOSApp,
      installationID: UUID(),
      testingFileProtectionPolicy: .completeUntilFirstUserAuthentication
    )
    let registry = try SessionSourceRegistry(
      local: localRegistration,
      remoteFactory: { machineID in
        let relay = try await RelaySessionSource.open(
          scope: .machine(machineID),
          pairedMachineStore: remoteStore
        )
        let lifecycle = P57RelayLifecycle(source: relay)
        return try SessionSourceRegistration(
          scope: .remote(machineID: machineID),
          source: lifecycle,
          capabilities: SessionSourceCapabilities(),
          lifecycle: lifecycle
        )
      }
    )
    let owner = SelectedMachineScopeGenerationOwner(registry: registry)

    var scenarioError: Error?
    do {
      try await exerciseScopes(
        invitation: invitation,
        conversationCWD: ready.rootDirectory.path,
        localMachineID: localMachineID,
        remoteStore: remoteStore,
        remoteKeyStore: remoteKeyStore,
        remoteStateRoot: remoteRoot,
        host: host,
        owner: owner
      )
    } catch {
      scenarioError = P57IntegrationError.assertion(
        "\(error)\nlocal inbound trace:\n\(await localInboundTrace.value())"
      )
    }

    await owner.shutdown()
    await registry.shutdown()
    if let scenarioError { throw scenarioError }
  }

  private func exerciseScopes(
    invitation: String,
    conversationCWD: String,
    localMachineID: String,
    remoteStore: PairedMachineStore,
    remoteKeyStore: P57MemoryKeyStore,
    remoteStateRoot: URL,
    host: P57RealHost,
    owner: SelectedMachineScopeGenerationOwner
  ) async throws {
    let localSelection = try await owner.select(.local)
    guard localSelection.handle.localPairingAdministration != nil,
      localSelection.handle.localConversationAdministration != nil
    else {
      throw P57IntegrationError.assertion("local scope did not expose local capabilities")
    }

    guard let conversationAdministration = localSelection.handle.localConversationAdministration
    else {
      throw P57IntegrationError.assertion("local conversation capability disappeared")
    }
    let lease = try await conversationAdministration.connectionLease()
    let descriptions = try await conversationAdministration.describeAgents(using: lease)
    let catalogPages = try await conversationAdministration.loadCatalog(using: lease)
    guard let catalogCursor = catalogPages.first?.baseCatalogCursor else {
      throw P57IntegrationError.assertion("local catalog bootstrap returned no cursor")
    }
    _ = try await conversationAdministration.synchronizeCatalog(
      cursor: catalogCursor,
      using: lease
    )

    let localCatalog = P57CatalogProbe(expectedScope: .local)
    try await owner.observeCatalog(machineID: localMachineID) { context, state in
      await localCatalog.consume(context: context, state: state)
    }
    try await localCatalog.waitUntilReady(timeout: .seconds(30))

    let draft = try RuntimeConversationDraft(
      agentKind: .codex,
      cwd: conversationCWD,
      prompt: nil,
      agentDescriptions: descriptions
    )
    let started = try await conversationAdministration.startConversation(
      draft,
      using: lease
    )
    let expectedConversationID = started.conversationID.rawValue

    let localSummary = try await localCatalog.waitForConversation(
      expectedConversationID,
      timeout: .seconds(30)
    )
    guard localSummary.machineID == localMachineID, localSummary.cwd == conversationCWD else {
      throw P57IntegrationError.assertion("local catalog identity/cwd mismatch")
    }

    let prePairStatus = try await host.status()
    guard let prePairEvidence = prePairStatus.evidence,
      prePairEvidence.machineRemoteLifecycle == "active",
      prePairEvidence.failureCode == nil,
      prePairEvidence.pendingPairingCount == 0,
      prePairEvidence.relayGrantTotal == 0,
      prePairEvidence.relayGrantActive == 0,
      prePairEvidence.activeTransitionCount == 0,
      prePairEvidence.activeCatalogStreamCount == 0
    else {
      throw P57IntegrationError.assertion("host was not business-ready before pairing")
    }

    guard let pairingAdministration = localSelection.handle.localPairingAdministration else {
      throw P57IntegrationError.assertion("local pairing capability disappeared")
    }
    let pairedMachine = try await pairThroughRealDaemon(
      invitation: invitation,
      store: remoteStore,
      localPairing: pairingAdministration,
      host: host,
      keyStore: remoteKeyStore,
      stateRoot: remoteStateRoot
    )

    let remoteSelection = try await owner.select(.remote(machineID: pairedMachine.id))
    guard remoteSelection.context.generation > localSelection.context.generation else {
      throw P57IntegrationError.assertion("scope generation did not advance")
    }
    guard remoteSelection.handle.localPairingAdministration == nil,
      remoteSelection.handle.localConversationAdministration == nil
    else {
      throw P57IntegrationError.assertion("remote scope leaked local capabilities")
    }

    let connectedMachine = try await p57WaitForConnectedMachine(
      await remoteSelection.handle.source.machines(),
      machineID: pairedMachine.id,
      timeout: .seconds(5)
    )
    guard connectedMachine.id == pairedMachine.id else {
      throw P57IntegrationError.assertion("connected machine identity mismatch")
    }

    let remoteCatalog = P57CatalogProbe(
      expectedScope: .remote(machineID: pairedMachine.id)
    )
    try await owner.observeCatalog(machineID: pairedMachine.id) { context, state in
      await remoteCatalog.consume(context: context, state: state)
    }
    let remoteSummary = try await remoteCatalog.waitForConversation(
      expectedConversationID,
      timeout: .seconds(45)
    )
    guard remoteSummary.machineID == pairedMachine.id,
      remoteSummary.id == localSummary.id,
      remoteSummary.cwd == localSummary.cwd
    else {
      throw P57IntegrationError.assertion("remote catalog crossed local scope identity")
    }

    let remoteConversation = try P57ConversationProbe(
      conversationID: expectedConversationID,
      expectedScope: .remote(machineID: pairedMachine.id)
    )
    try await owner.observeConversation(conversationID: expectedConversationID) {
      context,
      update in
      await remoteConversation.consume(context: context, update: update)
    }
    try await remoteConversation.waitUntilConnected(timeout: .seconds(45))

    let businessReady = try await p57Stage("host business-ready readback") {
      try await host.waitFor(
        .dualScopeBusinessReady,
        timeoutMilliseconds: 30_000
      )
    }
    guard businessReady.satisfied == true,
      let businessEvidence = businessReady.evidence,
      businessEvidence.machineRemoteLifecycle == "active",
      businessEvidence.failureCode == nil,
      businessEvidence.pendingPairingCount == 0,
      businessEvidence.relayGrantTotal == 1,
      businessEvidence.relayGrantActive == 1,
      businessEvidence.activeTransitionCount == 0,
      businessEvidence.activeCatalogStreamCount == 1,
      businessEvidence.runtimeActiveWriterCount == 3,
      (3...4).contains(businessEvidence.runtimeLiveSubscriptionCount),
      businessEvidence.runtimeBarrierSubscriptionCount == 0,
      businessEvidence.runtimeSnapshotSenderCount == 0,
      businessEvidence.runtimeSubscriptionJobCount
        == businessEvidence.runtimeLiveSubscriptionCount
    else {
      throw P57IntegrationError.assertion(
        "host did not enter dual-scope business-ready RemoteLink state: "
          + "satisfied=\(String(describing: businessReady.satisfied)); "
          + "evidence=\(String(describing: businessReady.evidence))"
      )
    }

    let prompt = "P5.7 real dual-scope prompt"
    let promptReceipt = try await remoteSelection.handle.source.sendPrompt(
      conversationID: expectedConversationID,
      text: prompt,
      idempotencyKey: UUID()
    )
    let commandID = try p57CommandID(from: promptReceipt)

    let pending = try await remoteConversation.waitForPendingApproval(
      prompt: prompt,
      assistantText: "synthetic Codex response",
      timeout: .seconds(45)
    )
    guard pending.commandID.rawValue == commandID else {
      throw P57IntegrationError.assertion("approval and prompt command identities differ")
    }

    let approvalReceipt = try await remoteSelection.handle.source.resolveApproval(
      conversationID: expectedConversationID,
      turnID: pending.turnID.rawValue,
      approvalID: pending.approvalID.rawValue,
      decision: .approve,
      idempotencyKey: UUID()
    )
    try p57RequireApprovalReceipt(
      approvalReceipt,
      approvalID: pending.approvalID
    )
    let remoteTerminalCommand = try await remoteConversation.waitForTerminal(
      prompt: prompt,
      assistantText: "synthetic Codex response",
      timeout: .seconds(45)
    )
    guard remoteTerminalCommand == commandID else {
      throw P57IntegrationError.assertion("remote terminal command identity mismatch")
    }

    let localReadbackSelection = try await owner.select(.local)
    guard localReadbackSelection.context.generation > remoteSelection.context.generation else {
      throw P57IntegrationError.assertion("remote-to-local generation did not advance")
    }
    let localReadback = try P57ConversationProbe(
      conversationID: expectedConversationID,
      expectedScope: .local
    )
    try await owner.observeConversation(conversationID: expectedConversationID) {
      context,
      update in
      await localReadback.consume(context: context, update: update)
    }
    let localTerminalCommand = try await localReadback.waitForTerminal(
      prompt: prompt,
      assistantText: "synthetic Codex response",
      timeout: .seconds(45)
    )
    guard localTerminalCommand == remoteTerminalCommand else {
      throw P57IntegrationError.assertion("local UDS and remote canonical terminal differ")
    }

    let status = try await host.status()
    guard let statusEvidence = status.evidence, statusEvidence.runtimeCommandCount >= 1 else {
      throw P57IntegrationError.assertion("host Runtime command ledger did not record prompt")
    }
  }

  private func pairThroughRealDaemon(
    invitation: String,
    store: PairedMachineStore,
    localPairing: any LocalPairingAdministration,
    host: P57RealHost,
    keyStore: P57MemoryKeyStore,
    stateRoot: URL
  ) async throws -> PairedMachine {
    let pairingSource = try await RelaySessionSource.open(
      scope: .allPairedMachines,
      pairedMachineStore: store
    )
    var pairingError: Error?
    var pairingFailureStorageTrace: String?
    var pairedMachine: PairedMachine?

    do {
      let preview = try await p57Stage("inspect pair invite") {
        try await pairingSource.inspectPairInvite(invitation)
      }
      guard preview.rootFingerprint.count == 32,
        preview.rootFingerprint.contains(where: { $0 != 0 })
      else {
        throw P57IntegrationError.assertion("pairing preview root fingerprint is invalid")
      }

      let progress = try await p57Stage("start pair request") {
        try await pairingSource.pair(invitation)
      }
      let pairedTask = Task {
        try await p57WithTimeout(.seconds(60), operation: "pairing terminal") {
          for try await item in progress {
            if case .paired(let machine) = item { return machine }
          }
          throw P57IntegrationError.assertion("pairing stream ended without paired terminal")
        }
      }

      let pending = try await p57Stage("local pending pairing readback") {
        try await p57WaitForPendingPairing(
          await localPairing.pendingPairings(),
          timeout: .seconds(45)
        )
      }
      let pendingEvidence = try await p57Stage("host pre-confirm readback") {
        try await host.waitFor(
          .pendingPairing,
          timeoutMilliseconds: 30_000
        )
      }
      guard pendingEvidence.satisfied == true,
        let evidence = pendingEvidence.evidence,
        evidence.pendingPairingCount == 1,
        evidence.relayGrantTotal == 0,
        evidence.relayGrantActive == 0,
        evidence.activeTransitionCount == 0,
        evidence.activeCatalogStreamCount == 0,
        evidence.socketIsUnix,
        evidence.socketMode == 0o600
      else {
        pairedTask.cancel()
        throw P57IntegrationError.assertion(
          "host did not read back pre-confirm pairing boundary"
        )
      }
      guard pending.requestHash.count == 32,
        pending.requestHash.contains(where: { $0 != 0 }),
        pending.deviceSignFingerprint.count == 32,
        pending.deviceSignFingerprint.contains(where: { $0 != 0 })
      else {
        pairedTask.cancel()
        throw P57IntegrationError.assertion("daemon pending pairing hashes are invalid")
      }

      let receipt = try await p57Stage("local confirm pairing") {
        try await localPairing.confirmPairing(id: pending.pairingID.rawValue)
      }
      try p57RequireConfirmedPairing(receipt, pairingID: pending.pairingID)
      pairedMachine = try await p57Stage("client paired terminal") {
        try await pairedTask.value
      }
      let transitionPending = try await p57Stage("host transition-pending readback") {
        try await host.status()
      }
      guard let evidence = transitionPending.evidence,
        evidence.machineRemoteLifecycle == "active",
        evidence.failureCode == nil,
        evidence.pendingPairingCount == 0,
        evidence.relayGrantTotal == 1,
        evidence.relayGrantActive == 1,
        evidence.activeTransitionCount == 1,
        evidence.activeCatalogStreamCount == 1
      else {
        throw P57IntegrationError.assertion(
          "host did not preserve the transition fence until remote snapshots were applied"
        )
      }
    } catch {
      pairingError = error
      pairingFailureStorageTrace =
        "\(await keyStore.debugSummary()); " + p57StateRootSummary(stateRoot)
    }

    await pairingSource.shutdown()
    if let pairingError {
      throw P57IntegrationError.assertion(
        "\(pairingError)\nclient storage trace: \(await keyStore.debugSummary()); "
          + p57StateRootSummary(stateRoot)
          + "\nclient storage at failure: \(pairingFailureStorageTrace ?? "<missing>")"
      )
    }
    guard let pairedMachine else {
      throw P57IntegrationError.assertion("missing paired machine")
    }
    return pairedMachine
  }
}

private enum P57IntegrationError: Error, CustomStringConvertible {
  case assertion(String)
  case hostContract(String)
  case hostExited(String)
  case hostProtocol(String)
  case timeout(String)

  var description: String {
    switch self {
    case .assertion(let message): "assertion: \(message)"
    case .hostContract(let message): "host contract: \(message)"
    case .hostExited(let message): "host exited: \(message)"
    case .hostProtocol(let message): "host protocol: \(message)"
    case .timeout(let operation): "timeout: \(operation)"
    }
  }
}

private struct P57HostReady: Sendable {
  let rootDirectory: URL
  let homeDirectory: URL
  let socketPath: URL
  let invitePath: URL
  let runtimeDatabasePath: URL
  let relayDatabasePath: URL
  let pid: UInt32
  let inviteFileMode: UInt32
}

private struct P57HostEvidence: Decodable, Sendable {
  let machineRemoteLifecycle: String
  let failureCode: String?
  let pendingPairingCount: Int
  let relayGrantTotal: Int64
  let relayGrantActive: Int64
  let activeTransitionCount: Int64
  let activeCatalogStreamCount: Int64
  let runtimeCommandCount: Int64
  let runtimeActiveWriterCount: Int
  let runtimeLiveSubscriptionCount: Int
  let runtimeBarrierSubscriptionCount: Int
  let runtimeSnapshotSenderCount: Int
  let runtimeSubscriptionJobCount: Int
  let socketIsUnix: Bool
  let socketMode: UInt32
}

private struct P57HostEvent: Decodable, Sendable {
  let kind: String
  let protocolName: String
  let requestID: String?
  let rootPath: String?
  let homePath: String?
  let socketPath: String?
  let invitePath: String?
  let runtimeDatabasePath: String?
  let relayDatabasePath: String?
  let pid: UInt32?
  let inviteFileMode: UInt32?
  let condition: P57HostWaitCondition?
  let satisfied: Bool?
  let evidence: P57HostEvidence?
  let inviteRemoved: Bool?
  let socketExists: Bool?
  let code: String?

  enum CodingKeys: String, CodingKey {
    case kind
    case protocolName = "protocol"
    case requestID = "requestId"
    case rootPath
    case homePath
    case socketPath
    case invitePath
    case runtimeDatabasePath
    case relayDatabasePath
    case pid
    case inviteFileMode
    case condition
    case satisfied
    case evidence
    case inviteRemoved
    case socketExists
    case code
  }
}

private enum P57HostWaitCondition: String, Codable, Sendable {
  case pendingPairing
  case businessReady
  case dualScopeBusinessReady
}

private struct P57HostCommand: Encodable {
  let op: String
  let requestID: String
  let condition: P57HostWaitCondition?
  let timeoutMilliseconds: UInt64?

  enum CodingKeys: String, CodingKey {
    case op
    case requestID = "requestId"
    case condition
    case timeoutMilliseconds = "timeoutMs"
  }
}

private final class P57RealHost: @unchecked Sendable {
  static let protocolName = "agentdeck-p57-host/v1"

  let ready: P57HostReady
  private let process: Process
  private let stdin: FileHandle
  private let stdoutSource: P57LineSource
  private let stderrSource: P57LineSource
  private let events: P57HostEventReader
  private let stderr: P57DiagnosticLog
  private let exit: P57ProcessExit
  private let stderrTask: Task<Void, Never>

  private init(
    ready: P57HostReady,
    process: Process,
    stdin: FileHandle,
    stdoutSource: P57LineSource,
    stderrSource: P57LineSource,
    events: P57HostEventReader,
    stderr: P57DiagnosticLog,
    exit: P57ProcessExit,
    stderrTask: Task<Void, Never>
  ) {
    self.ready = ready
    self.process = process
    self.stdin = stdin
    self.stdoutSource = stdoutSource
    self.stderrSource = stderrSource
    self.events = events
    self.stderr = stderr
    self.exit = exit
    self.stderrTask = stderrTask
  }

  static func start() async throws -> P57RealHost {
    let projectRoot = URL(fileURLWithPath: #filePath)
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
    let process = Process()
    let input = Pipe()
    let output = Pipe()
    let error = Pipe()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
    process.currentDirectoryURL = projectRoot
    process.arguments = [
      "cargo", "test", "-p", "agentdeckd", "--test", "relay_v2_machine_e2e",
      "p57_real_dual_scope_ndjson_host", "--", "--ignored", "--exact", "--nocapture",
      "--test-threads=1",
    ]
    var environment = ProcessInfo.processInfo.environment
    environment["RUSTC_WRAPPER"] = ""
    environment["AGENTDECK_P57_HOST"] = "1"
    process.environment = environment
    process.standardInput = input
    process.standardOutput = output
    process.standardError = error

    let stdoutSource = P57LineSource(handle: output.fileHandleForReading)
    let stderrSource = P57LineSource(handle: error.fileHandleForReading)
    let events = P57HostEventReader(lines: stdoutSource.lines)
    let diagnostics = P57DiagnosticLog()
    let exit = P57ProcessExit()
    process.terminationHandler = { process in
      let status = process.terminationStatus
      Task { await exit.record(status) }
    }

    do {
      try process.run()
    } catch {
      stdoutSource.close()
      stderrSource.close()
      throw error
    }
    let stdin = input.fileHandleForWriting
    guard fcntl(stdin.fileDescriptor, F_SETNOSIGPIPE, 1) == 0 else {
      let status = errno
      if process.isRunning { process.terminate() }
      stdoutSource.close()
      stderrSource.close()
      throw P57IntegrationError.hostProtocol("disable SIGPIPE failed with errno \(status)")
    }
    let stderrTask = Task {
      for await line in stderrSource.lines {
        await diagnostics.append(line)
      }
    }

    let event = try await p57WithTimeout(.seconds(300), operation: "host ready") {
      try await events.next(kind: "ready", requestID: nil)
    }
    let ready = try p57Ready(from: event)
    return P57RealHost(
      ready: ready,
      process: process,
      stdin: stdin,
      stdoutSource: stdoutSource,
      stderrSource: stderrSource,
      events: events,
      stderr: diagnostics,
      exit: exit,
      stderrTask: stderrTask
    )
  }

  func status() async throws -> P57HostEvent {
    let requestID = p57RequestID()
    try send(
      P57HostCommand(
        op: "status",
        requestID: requestID,
        condition: nil,
        timeoutMilliseconds: nil
      )
    )
    let event = try await p57WithTimeout(.seconds(30), operation: "host status") {
      try await self.events.next(kind: "status", requestID: requestID)
    }
    guard event.evidence != nil else {
      throw P57IntegrationError.hostProtocol("status omitted evidence")
    }
    return event
  }

  func waitFor(
    _ condition: P57HostWaitCondition,
    timeoutMilliseconds: UInt64
  ) async throws -> P57HostEvent {
    let requestID = p57RequestID()
    try send(
      P57HostCommand(
        op: "waitFor",
        requestID: requestID,
        condition: condition,
        timeoutMilliseconds: timeoutMilliseconds
      )
    )
    let event = try await p57WithTimeout(
      .milliseconds(Int64(timeoutMilliseconds + 5_000)),
      operation: "host waitFor \(condition.rawValue)"
    ) {
      try await self.events.next(kind: "waitFor", requestID: requestID)
    }
    guard event.condition == condition, event.satisfied != nil, event.evidence != nil else {
      throw P57IntegrationError.hostProtocol("waitFor response is incomplete")
    }
    return event
  }

  func shutdown() async throws {
    let requestID = p57RequestID()
    do {
      try send(
        P57HostCommand(
          op: "shutdown",
          requestID: requestID,
          condition: nil,
          timeoutMilliseconds: nil
        )
      )
      try stdin.close()
    } catch {
      if process.isRunning { process.terminate() }
      throw error
    }

    do {
      let stopped = try await p57WithTimeout(.seconds(45), operation: "host stopped event") {
        try await self.events.next(kind: "stopped", requestID: requestID)
      }
      guard stopped.inviteRemoved == true, stopped.socketExists == false else {
        throw P57IntegrationError.hostProtocol("host stopped without cleanup readback")
      }
      let status = try await p57WithTimeout(.seconds(30), operation: "host exit") {
        await self.exit.wait()
      }
      guard status == 0 else {
        throw P57IntegrationError.hostExited("status \(status)")
      }
    } catch {
      if process.isRunning { process.terminate() }
      throw error
    }

    stdoutSource.close()
    stderrSource.close()
    await events.join()
    await stderrTask.value
  }

  func diagnostics() async -> String {
    let stderr = await stderr.value()
    let status = await exit.recordedStatus().map(String.init) ?? "running"
    return "host status=\(status)\nstderr:\n\(stderr)"
  }

  private func send(_ command: P57HostCommand) throws {
    let data = try JSONEncoder().encode(command)
    guard data.count <= 4 * 1_024 else {
      throw P57IntegrationError.hostProtocol("command exceeds host bound")
    }
    try stdin.write(contentsOf: data + Data([0x0A]))
  }
}

private final class P57HostEventReader: @unchecked Sendable {
  private let queue: P57HostRecordQueue
  private let parserTask: Task<Void, Never>

  init(lines: AsyncStream<String>) {
    let queue = P57HostRecordQueue()
    self.queue = queue
    parserTask = Task {
      for await line in lines {
        guard line.contains(P57RealHost.protocolName) else { continue }
        do {
          let event = try JSONDecoder().decode(P57HostEvent.self, from: Data(line.utf8))
          await queue.push(.event(event))
        } catch {
          await queue.push(.failure("invalid NDJSON event"))
        }
      }
      await queue.finish()
    }
  }

  func next(kind expected: String, requestID: String?) async throws -> P57HostEvent {
    while true {
      guard let record = await queue.next() else {
        throw P57IntegrationError.hostExited("stdout closed before \(expected)")
      }
      let event: P57HostEvent
      switch record {
      case .event(let value):
        event = value
      case .failure(let message):
        throw P57IntegrationError.hostProtocol(message)
      }
      guard event.protocolName == P57RealHost.protocolName else { continue }
      if event.kind == "error", event.requestID == nil || event.requestID == requestID {
        throw P57IntegrationError.hostExited(
          event.code ?? "host returned unspecified error"
        )
      }
      if event.kind == expected, event.requestID == requestID { return event }
    }
  }

  func join() async { await parserTask.value }
}

private enum P57HostRecord: Sendable {
  case event(P57HostEvent)
  case failure(String)
}

private actor P57HostRecordQueue {
  private var records: [P57HostRecord] = []
  private var waiters: [CheckedContinuation<P57HostRecord?, Never>] = []
  private var finished = false

  func push(_ record: P57HostRecord) {
    guard !finished else { return }
    if waiters.isEmpty {
      records.append(record)
    } else {
      waiters.removeFirst().resume(returning: record)
    }
  }

  func next() async -> P57HostRecord? {
    if !records.isEmpty { return records.removeFirst() }
    if finished { return nil }
    return await withCheckedContinuation { waiters.append($0) }
  }

  func finish() {
    guard !finished else { return }
    finished = true
    let pending = waiters
    waiters.removeAll(keepingCapacity: false)
    for waiter in pending { waiter.resume(returning: nil) }
  }
}

private final class P57LineSource: @unchecked Sendable {
  let lines: AsyncStream<String>
  private let handle: FileHandle
  private let framer: P57LineFramer

  init(handle: FileHandle) {
    self.handle = handle
    var continuation: AsyncStream<String>.Continuation!
    lines = AsyncStream { continuation = $0 }
    framer = P57LineFramer(continuation: continuation)
    handle.readabilityHandler = { [framer] readable in
      framer.consume(readable.availableData)
    }
  }

  func close() {
    handle.readabilityHandler = nil
    framer.finish()
    try? handle.close()
  }
}

private final class P57LineFramer: @unchecked Sendable {
  private let lock = NSLock()
  private let continuation: AsyncStream<String>.Continuation
  private var buffer = Data()
  private var finished = false

  init(continuation: AsyncStream<String>.Continuation) {
    self.continuation = continuation
  }

  func consume(_ data: Data) {
    lock.lock()
    defer { lock.unlock() }
    guard !finished else { return }
    guard !data.isEmpty else {
      finishLocked()
      return
    }
    buffer.append(data)
    while let newline = buffer.firstIndex(of: 0x0A) {
      let line = buffer[..<newline]
      buffer.removeSubrange(...newline)
      continuation.yield(String(decoding: line, as: UTF8.self))
    }
  }

  func finish() {
    lock.lock()
    defer { lock.unlock() }
    finishLocked()
  }

  private func finishLocked() {
    guard !finished else { return }
    finished = true
    if !buffer.isEmpty {
      continuation.yield(String(decoding: buffer, as: UTF8.self))
      buffer.removeAll(keepingCapacity: false)
    }
    continuation.finish()
  }
}

private actor P57DiagnosticLog {
  private var lines: [String] = []

  func append(_ line: String) {
    if lines.count < 2_000 { lines.append(line) }
  }

  func value() -> String { lines.joined(separator: "\n") }
}

private actor P57ProcessExit {
  private var status: Int32?
  private var waiters: [CheckedContinuation<Int32, Never>] = []

  func record(_ status: Int32) {
    guard self.status == nil else { return }
    self.status = status
    let pending = waiters
    waiters.removeAll(keepingCapacity: false)
    for waiter in pending { waiter.resume(returning: status) }
  }

  func wait() async -> Int32 {
    if let status { return status }
    return await withCheckedContinuation { waiters.append($0) }
  }

  func recordedStatus() -> Int32? { status }
}

private actor P57LocalInboundTrace {
  private static let maximumRecords = 256
  private var records: [String] = []

  func record(_ inbound: AppRuntimeInbound, generation: UInt64) {
    guard records.count < Self.maximumRecords else { return }
    let record: String
    switch inbound {
    case .synchronizedReply(let reply):
      record = "synchronized \(Self.replyKind(reply))"
    case .stream(let frame):
      record = "stream \(frame.messageID.rawValue) \(Self.streamKind(frame.item))"
    }
    records.append("generation=\(generation) \(record)")
  }

  func value() -> String {
    records.isEmpty ? "<empty>" : records.joined(separator: "\n")
  }

  private static func replyKind(_ reply: RuntimeReplyV2) -> String {
    switch reply {
    case .subscription: "subscription"
    case .catalog: "catalog"
    case .snapshot: "snapshot"
    case .backfill: "backfill"
    case .syncComplete: "syncComplete"
    case .failure: "failure"
    default: "other"
    }
  }

  private static func streamKind(_ item: RuntimeStreamItemV2) -> String {
    switch item {
    case .event: "event"
    case .catalogDelta: "catalogDelta"
    case .pairingPending: "pairingPending"
    case .transferPart: "transferPart"
    }
  }
}

private actor P57CatalogProbe {
  private let expectedScope: MachineScope
  private var summaries: [ConversationSummary] = []
  private var isReady = false
  private var failure: String?

  init(expectedScope: MachineScope) {
    self.expectedScope = expectedScope
  }

  func consume(
    context: MachineScopeObservationContext,
    state: ResourceState<[ConversationSummary]>
  ) {
    guard context.scope == expectedScope else {
      failure = "catalog context crossed scope"
      return
    }
    switch state {
    case .ready(let value, _):
      summaries = value
      isReady = true
    case .stale(let value, _):
      summaries = value
    case .failed(let error, _):
      failure = "catalog failed: \(error.code.rawValue)"
    case .loading:
      break
    }
  }

  func waitUntilReady(timeout: Duration) async throws {
    _ = try await p57Eventually(timeout, operation: "catalog initial ready") {
      if let failure = await self.failureValue() {
        throw P57IntegrationError.assertion(failure)
      }
      return await self.readyValue() ? true : nil
    }
  }

  func waitForConversation(
    _ conversationID: String,
    timeout: Duration
  ) async throws -> ConversationSummary {
    try await p57Eventually(timeout, operation: "catalog \(conversationID)") {
      if let failure = await self.failureValue() {
        throw P57IntegrationError.assertion(failure)
      }
      return await self.summary(conversationID: conversationID)
    }
  }

  private func summary(conversationID: String) -> ConversationSummary? {
    summaries.first(where: { $0.id == conversationID })
  }

  private func readyValue() -> Bool { isReady }

  private func failureValue() -> String? { failure }
}

private actor P57ConversationProbe {
  private let expectedScope: MachineScope
  private var state: RuntimeConversationState
  private var connection: SessionConnectionState?
  private var failure: String?

  init(conversationID: String, expectedScope: MachineScope) throws {
    self.expectedScope = expectedScope
    state = try RuntimeConversationState(
      conversationID: RuntimeConversationID(rawValue: conversationID)
    )
  }

  func consume(
    context: MachineScopeObservationContext,
    update: ConversationUpdate
  ) {
    guard context.scope == expectedScope else {
      failure = "conversation context crossed scope"
      return
    }
    do {
      switch update {
      case .snapshot(let snapshot):
        try state.apply(snapshot)
      case .event(let event):
        try state.apply(event)
      case .commandState:
        break
      case .connectionState(let value):
        connection = value
        if value == .securityError || value == .revoked || value == .incompatible {
          failure = "fatal connection state: \(value)"
        }
      }
    } catch {
      failure = "canonical reducer rejected update: \(error)"
    }
  }

  func waitUntilConnected(timeout: Duration) async throws {
    _ = try await p57Eventually(timeout, operation: "conversation connected") {
      if let failure = await self.failureValue() {
        throw P57IntegrationError.assertion(failure)
      }
      return await self.isConnected() ? true : nil
    }
  }

  func waitForPendingApproval(
    prompt: String,
    assistantText: String,
    timeout: Duration
  ) async throws -> RuntimeConversationPendingApproval {
    try await p57Eventually(timeout, operation: "synthetic approval") {
      if let failure = await self.failureValue() {
        throw P57IntegrationError.assertion(failure)
      }
      return await self.pending(prompt: prompt, assistantText: assistantText)
    }
  }

  func waitForTerminal(
    prompt: String,
    assistantText: String,
    timeout: Duration
  ) async throws -> String {
    try await p57Eventually(timeout, operation: "canonical terminal") {
      if let failure = await self.failureValue() {
        throw P57IntegrationError.assertion(failure)
      }
      return await self.terminalCommand(prompt: prompt, assistantText: assistantText)
    }
  }

  private func isConnected() -> Bool { connection == .connected }

  private func pending(
    prompt: String,
    assistantText: String
  ) -> RuntimeConversationPendingApproval? {
    guard state.items.contains(where: { $0.text.contains(prompt) }),
      state.items.contains(where: { $0.text.contains(assistantText) })
    else { return nil }
    return state.pendingApproval
  }

  private func terminalCommand(prompt: String, assistantText: String) -> String? {
    guard state.pendingApprovals.isEmpty,
      state.items.contains(where: { $0.text.contains(prompt) }),
      state.items.contains(where: { $0.text.contains(assistantText) }),
      let terminal = state.turnTerminal
    else { return nil }
    switch terminal {
    case .completed(_, let commandID, _), .interrupted(_, let commandID):
      return commandID.rawValue
    case .failed(_, let commandID, _):
      return commandID.rawValue
    }
  }

  private func failureValue() -> String? { failure }
}

private struct P57RelayLifecycle: SessionSourceLifecycle, Sendable {
  let source: RelaySessionSource

  func machines() async -> AsyncStream<ResourceState<[MachineSummary]>> {
    await source.machines()
  }

  func conversations(
    machineID: String
  ) async -> AsyncStream<ResourceState<[ConversationSummary]>> {
    await source.conversations(machineID: machineID)
  }

  func conversation(conversationID: String) async -> AsyncStream<ConversationUpdate> {
    await source.conversation(conversationID: conversationID)
  }

  func inbox() async -> AsyncStream<ResourceState<[InboxItem]>> {
    await source.inbox()
  }

  func inspectPairInvite(_ encoded: String) async throws -> PairingPreview {
    try await source.inspectPairInvite(encoded)
  }

  func pair(
    _ encodedInvite: String
  ) async throws -> AsyncThrowingStream<PairingProgress, Error> {
    try await source.pair(encodedInvite)
  }

  func revokeSelf(machineID: String) async throws -> RevocationReceipt {
    try await source.revokeSelf(machineID: machineID)
  }

  func sendPrompt(
    conversationID: String,
    text: String,
    idempotencyKey: UUID
  ) async throws -> CommandReceipt {
    try await source.sendPrompt(
      conversationID: conversationID,
      text: text,
      idempotencyKey: idempotencyKey
    )
  }

  func resolveApproval(
    conversationID: String,
    turnID: String,
    approvalID: String,
    decision: ActionDecisionKind,
    idempotencyKey: UUID
  ) async throws -> ApprovalReceipt {
    try await source.resolveApproval(
      conversationID: conversationID,
      turnID: turnID,
      approvalID: approvalID,
      decision: decision,
      idempotencyKey: idempotencyKey
    )
  }

  func retryApprovalDelivery(
    conversationID: String,
    approvalID: String
  ) async throws -> ApprovalReceipt {
    try await source.retryApprovalDelivery(
      conversationID: conversationID,
      approvalID: approvalID
    )
  }

  func shutdown() async { await source.shutdown() }
  func join() async { await source.shutdown() }
}

private actor P57MemoryKeyStore: PairedMarkerListingKeyStore {
  private var values: [KeyStoreKey: Data] = [:]

  func load(_ key: KeyStoreKey) async throws -> Data? { values[key] }

  func persistImmutable(
    _ data: Data,
    for key: KeyStoreKey
  ) async throws -> KeyStorePersistence {
    if let existing = values[key] {
      guard existing == data else { throw KeyStoreError.immutableConflict }
      return .alreadyPresent
    }
    values[key] = data
    return .inserted
  }

  func compareAndReplaceExact(
    expected: Data,
    replacement: Data,
    for key: KeyStoreKey
  ) async throws {
    guard let existing = values[key] else {
      throw KeyStoreError.compareAndReplaceMissing
    }
    guard existing == expected else { throw KeyStoreError.compareAndReplaceMismatch }
    values[key] = replacement
  }

  func deleteExact(expected: Data, for key: KeyStoreKey) async throws {
    guard values[key] == expected else { throw KeyStoreError.deleteReadbackFailed }
    values.removeValue(forKey: key)
  }

  func pairedCommitMarkerKeys(
    clientKind: RelayClientKind,
    installationID: UUID
  ) async throws -> [KeyStoreKey] {
    let prefix = KeyStoreKey.pairedMarkerPrefix(
      clientKind: clientKind,
      installationID: installationID
    )
    return values.keys.filter {
      $0.account.hasPrefix(prefix)
        && $0.account.hasSuffix("/\(PairedKeyStorePurpose.commitMarker.rawValue)")
    }.sorted { $0.account < $1.account }
  }

  func pendingPairingRecoveryKeys(
    clientKind: RelayClientKind,
    installationID: UUID
  ) async throws -> [KeyStoreKey] {
    let prefix = KeyStoreKey.pendingMarkerPrefix(
      clientKind: clientKind,
      installationID: installationID
    )
    let suffixes = [
      "/\(PendingKeyStorePurpose.recoveryIntent.rawValue)",
      "/\(PendingKeyStorePurpose.pairingRecord.rawValue)",
    ]
    return values.keys.filter { key in
      key.account.hasPrefix(prefix)
        && suffixes.contains(where: key.account.hasSuffix)
    }.sorted { $0.account < $1.account }
  }

  func debugSummary() -> String {
    var counts: [String: Int] = [:]
    for key in values.keys {
      let purpose = key.account.split(separator: "/").last.map(String.init) ?? "unknown"
      counts[purpose, default: 0] += 1
    }
    return counts.keys.sorted().map { "\($0)=\(counts[$0]!)" }.joined(separator: ",")
  }
}

private func p57StateRootSummary(_ root: URL) -> String {
  guard
    let enumerator = FileManager.default.enumerator(
      at: root,
      includingPropertiesForKeys: [.isDirectoryKey, .isRegularFileKey],
      options: [.skipsHiddenFiles]
    )
  else { return "stateRoot=unreadable" }
  var directories = 0
  var files = 0
  for case let url as URL in enumerator {
    let values = try? url.resourceValues(forKeys: [.isDirectoryKey, .isRegularFileKey])
    if values?.isDirectory == true { directories += 1 }
    if values?.isRegularFile == true { files += 1 }
  }
  return "stateRootDirectories=\(directories),stateRootFiles=\(files)"
}

private func p57Ready(from event: P57HostEvent) throws -> P57HostReady {
  guard event.kind == "ready",
    event.protocolName == P57RealHost.protocolName,
    let rootDirectory = event.rootPath,
    let homeDirectory = event.homePath,
    let socketPath = event.socketPath,
    let invitePath = event.invitePath,
    let runtimeDatabasePath = event.runtimeDatabasePath,
    let relayDatabasePath = event.relayDatabasePath,
    let pid = event.pid,
    pid > 0,
    let inviteFileMode = event.inviteFileMode,
    inviteFileMode == 0o600
  else {
    throw P57IntegrationError.hostContract("ready event is incomplete")
  }
  return P57HostReady(
    rootDirectory: URL(fileURLWithPath: rootDirectory, isDirectory: true),
    homeDirectory: URL(fileURLWithPath: homeDirectory, isDirectory: true),
    socketPath: URL(fileURLWithPath: socketPath, isDirectory: false),
    invitePath: URL(fileURLWithPath: invitePath, isDirectory: false),
    runtimeDatabasePath: URL(fileURLWithPath: runtimeDatabasePath, isDirectory: false),
    relayDatabasePath: URL(fileURLWithPath: relayDatabasePath, isDirectory: false),
    pid: pid,
    inviteFileMode: inviteFileMode
  )
}

private func p57RequestID() -> String {
  "swift-\(UUID().uuidString.lowercased())"
}

private func p57ReadInvite(_ path: URL) throws -> String {
  let data = try Data(contentsOf: path, options: [.mappedIfSafe])
  guard data.count <= 8 * 1_024,
    let value = String(data: data, encoding: .utf8)?.trimmingCharacters(
      in: .whitespacesAndNewlines
    ),
    value.hasPrefix("agentdeck-pair:v1:")
  else {
    throw P57IntegrationError.hostContract("invite file is invalid")
  }
  return value
}

private func p57RequireAbsolute(_ path: URL, field: String) throws {
  guard path.path.hasPrefix("/") else {
    throw P57IntegrationError.hostContract("\(field) is not absolute")
  }
}

private func p57RequireUnixSocket(_ path: URL) throws {
  var metadata = stat()
  guard lstat(path.path, &metadata) == 0,
    metadata.st_mode & mode_t(S_IFMT) == mode_t(S_IFSOCK),
    metadata.st_uid == geteuid(),
    metadata.st_mode & 0o777 == 0o600
  else {
    throw P57IntegrationError.hostContract("daemon socket is not same-UID mode 0600 UDS")
  }
}

private func p57RequirePrivateRegularFile(_ path: URL) throws {
  var metadata = stat()
  guard lstat(path.path, &metadata) == 0,
    metadata.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
    metadata.st_uid == geteuid(),
    metadata.st_mode & 0o777 == 0o600,
    metadata.st_nlink == 1
  else {
    throw P57IntegrationError.hostContract("invite is not same-UID mode 0600 regular file")
  }
}

private func p57WaitForPendingPairing(
  _ stream: AsyncStream<ResourceState<[PendingPairing]>>,
  timeout: Duration
) async throws -> PendingPairing {
  try await p57WithTimeout(timeout, operation: "pending pairing") {
    for await state in stream {
      switch state {
      case .ready(let values, _), .stale(let values, _):
        if let first = values.first { return first }
      case .failed(let error, _):
        throw P57IntegrationError.assertion(
          "pending pairing failed: \(error.code.rawValue)"
        )
      case .loading:
        break
      }
    }
    throw P57IntegrationError.assertion("pending pairing stream ended")
  }
}

private func p57WaitForConnectedMachine(
  _ stream: AsyncStream<ResourceState<[MachineSummary]>>,
  machineID: String,
  timeout: Duration
) async throws -> MachineSummary {
  try await p57WithTimeout(timeout, operation: "remote machine connected") {
    for await state in stream {
      switch state {
      case .ready(let values, _), .stale(let values, _):
        if let machine = values.first(where: {
          $0.id == machineID && $0.connectionState == .connected
        }) {
          return machine
        }
      case .failed(let error, _):
        throw P57IntegrationError.assertion(
          "machine stream failed: \(error.code.rawValue)"
        )
      case .loading:
        break
      }
    }
    throw P57IntegrationError.assertion("machine stream ended before connected")
  }
}

private func p57RequireConfirmedPairing(
  _ receipt: PairingAdministrationReceipt,
  pairingID: RuntimePairingID
) throws {
  let observed: RuntimePairingID
  switch receipt {
  case .confirmed(let value):
    observed = value
  case .replayed(let value, decision: .confirm, state: _),
    .alreadyHandled(let value, winner: .confirm, state: _):
    observed = value
  default:
    throw P57IntegrationError.assertion("unexpected local pairing receipt")
  }
  guard observed == pairingID else {
    throw P57IntegrationError.assertion("local pairing receipt identity mismatch")
  }
}

private func p57CommandID(from receipt: CommandReceipt) throws -> String {
  switch receipt {
  case .accepted(let commandID, _, _), .replayed(let commandID, _):
    return commandID.rawValue
  case .failed(let failure):
    throw P57IntegrationError.assertion("prompt failed: \(failure.code)")
  }
}

private func p57RequireApprovalReceipt(
  _ receipt: ApprovalReceipt,
  approvalID: RuntimeApprovalID
) throws {
  let observed: RuntimeApprovalID
  switch receipt {
  case .claimed(let value), .applied(let value):
    observed = value
  case .alreadyHandled(let value, decision: .approve, state: .applied):
    observed = value
  default:
    throw P57IntegrationError.assertion("unexpected remote approval receipt")
  }
  guard observed == approvalID else {
    throw P57IntegrationError.assertion("remote approval receipt identity mismatch")
  }
}

private func p57JSONTrace<Value: Encodable>(_ value: Value) -> String {
  let encoder = JSONEncoder()
  encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
  guard let data = try? encoder.encode(value) else { return "<json-encode-failed>" }
  let maximumBytes = 4 * 1_024
  guard data.count > maximumBytes else { return String(decoding: data, as: UTF8.self) }
  return "\(String(decoding: data.prefix(maximumBytes), as: UTF8.self))<truncated>"
}

private func p57Stage<Value: Sendable>(
  _ stage: String,
  operation: @escaping @Sendable () async throws -> Value
) async throws -> Value {
  do {
    return try await operation()
  } catch {
    throw P57IntegrationError.assertion("\(stage): \(error)")
  }
}

private func p57Eventually<T: Sendable>(
  _ timeout: Duration,
  operation: String,
  poll: @escaping @Sendable () async throws -> T?
) async throws -> T {
  let clock = ContinuousClock()
  let deadline = clock.now.advanced(by: timeout)
  while clock.now < deadline {
    if let value = try await poll() { return value }
    try await Task.sleep(for: .milliseconds(20))
  }
  throw P57IntegrationError.timeout(operation)
}

private func p57WithTimeout<T: Sendable>(
  _ timeout: Duration,
  operation: String,
  body: @escaping @Sendable () async throws -> T
) async throws -> T {
  try await withThrowingTaskGroup(of: T.self) { group in
    group.addTask(operation: body)
    group.addTask {
      try await Task.sleep(for: timeout)
      throw P57IntegrationError.timeout(operation)
    }
    guard let value = try await group.next() else {
      throw P57IntegrationError.timeout(operation)
    }
    group.cancelAll()
    return value
  }
}
