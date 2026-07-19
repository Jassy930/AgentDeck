#if DEBUG
  import AgentDeckCore
  import Darwin
  import Foundation

  struct RuntimeSmokeExecution: Equatable, Sendable {
    let exitCode: Int32
    let stdout: Data
    let stderr: Data
  }

  struct RuntimeSmokeContext: Sendable {
    let installationID: String
    let wire: any AppRuntimeWireSession
  }

  private struct RuntimeSmokeTypedFailure: Error, Sendable {
    let code: String
    let message: String
    let diagnosticRef: String?

    init(code: String, message: String, diagnosticRef: String? = nil) {
      self.code = code
      self.message = message
      self.diagnosticRef = diagnosticRef
    }
  }

  /// P3.9-D 组合 smoke 的 DEBUG-only Swift client 入口。
  ///
  /// 它只接受一个 private TMPDIR root，自行发现 canonical daemon namespace；endpoint
  /// 仍由 `UnixSocketDaemonTransport` 执行现有 no-follow/current-UID/mode/link 校验。
  struct RuntimeSmokeRunner: Sendable {
    typealias ContextFactory =
      @Sendable (String) async throws -> RuntimeSmokeContext

    private enum Operation: String, Sendable {
      case installation
      case sendPrompt = "send-prompt"
      case queryReceipt = "query-receipt"
      case subscribe
    }

    private enum Command: Sendable {
      case installation(root: String)
      case sendPrompt(
        root: String,
        conversationID: RuntimeConversationID,
        idempotencyKey: RuntimeIdempotencyKey,
        expectedConfigurationRevision: UInt64,
        prompt: RuntimePromptPayloadV1
      )
      case queryReceipt(
        root: String,
        selector: RuntimeReceiptSelectorV1
      )
      case subscribe(root: String, conversationID: RuntimeConversationID)

      var root: String {
        switch self {
        case .installation(let root),
          .sendPrompt(let root, _, _, _, _),
          .queryReceipt(let root, _),
          .subscribe(let root, _):
          root
        }
      }
    }

    private struct InstallationPayload: Encodable {
      let installationId: String
      let ok = true
      let operation = "installation"
    }

    private struct SubscribePayload: Encodable {
      let backfillCount: Int
      let commandIds: [String]
      let conversationId: String
      let installationId: String
      let ok = true
      let operation = "subscribe"
      let snapshotCount: Int
      let syncComplete = true
      let terminalStreamCursor: RuntimeStreamCursorV1
    }

    private struct UsageFailure: Error, Sendable {
      let message: String
    }

    private let contextFactory: ContextFactory

    init(
      contextFactory: @escaping ContextFactory = { root in
        try RuntimeSmokeEnvironment.makeContext(rootPath: root)
      }
    ) {
      self.contextFactory = contextFactory
    }

    func run(arguments: [String] = CommandLine.arguments) async -> RuntimeSmokeExecution {
      let command: Command
      do {
        command = try Self.parse(arguments: arguments)
      } catch {
        return Self.failureExecution(for: error)
      }

      let context: RuntimeSmokeContext
      do {
        context = try await contextFactory(command.root)
      } catch {
        return Self.failureExecution(for: error)
      }

      let execution: RuntimeSmokeExecution
      do {
        try await context.wire.start()
        execution = try await Self.execute(command, context: context)
      } catch {
        execution = Self.failureExecution(for: error)
      }
      await context.wire.close()
      return execution
    }

    private static func parse(arguments: [String]) throws -> Command {
      var values: [String: String] = [:]
      let allowedFlags: Set<String> = [
        "--runtime-smoke-for-test",
        "--runtime-temp-root-for-test",
        "--conversation-id",
        "--idempotency-key",
        "--command-id",
        "--expected-configuration-revision",
        "--prompt",
      ]
      let tokens = Array(arguments.dropFirst())
      var index = 0
      while index < tokens.count {
        let flag = tokens[index]
        guard allowedFlags.contains(flag), index + 1 < tokens.count else {
          throw UsageFailure(message: "unknown or value-less Runtime smoke argument: \(flag)")
        }
        guard values.updateValue(tokens[index + 1], forKey: flag) == nil else {
          throw UsageFailure(message: "duplicate Runtime smoke argument: \(flag)")
        }
        index += 2
      }

      guard
        let operationValue = values["--runtime-smoke-for-test"],
        let operation = Operation(rawValue: operationValue),
        let root = values["--runtime-temp-root-for-test"],
        !root.isEmpty
      else {
        throw UsageFailure(
          message: "Runtime smoke requires one operation and one private TMPDIR root"
        )
      }

      let commonFlags: Set<String> = [
        "--runtime-smoke-for-test", "--runtime-temp-root-for-test",
      ]
      switch operation {
      case .installation:
        try requireExactFlags(values, expected: commonFlags)
        return .installation(root: root)
      case .sendPrompt:
        try requireExactFlags(
          values,
          expected: commonFlags.union([
            "--conversation-id",
            "--idempotency-key",
            "--expected-configuration-revision",
            "--prompt",
          ])
        )
        let conversationID = try requiredIdentity("--conversation-id", values: values)
        let idempotencyKey = try requiredIdentity("--idempotency-key", values: values)
        guard
          let revisionValue = values["--expected-configuration-revision"],
          let revision = UInt64(revisionValue),
          let promptValue = values["--prompt"],
          !promptValue.isEmpty
        else {
          throw UsageFailure(message: "send-prompt requires revision and non-empty prompt")
        }
        let prompt: RuntimePromptPayloadV1
        do {
          prompt = try RuntimePromptPayloadV1(rawValue: promptValue)
        } catch {
          throw UsageFailure(message: "send-prompt prompt exceeds the Runtime payload bound")
        }
        return .sendPrompt(
          root: root,
          conversationID: RuntimeConversationID(rawValue: conversationID),
          idempotencyKey: RuntimeIdempotencyKey(rawValue: idempotencyKey),
          expectedConfigurationRevision: revision,
          prompt: prompt
        )
      case .queryReceipt:
        let selectorFlags = Set(values.keys).subtracting(commonFlags)
        guard
          selectorFlags == Set(["--conversation-id", "--idempotency-key"])
            || selectorFlags == Set(["--conversation-id", "--command-id"])
        else {
          throw UsageFailure(
            message: "query-receipt requires exactly one idempotency key or command ID"
          )
        }
        let conversationID = RuntimeConversationID(
          rawValue: try requiredIdentity("--conversation-id", values: values)
        )
        let selector: RuntimeReceiptSelectorV1
        if values["--idempotency-key"] != nil {
          selector = .idempotency(
            conversationID: conversationID,
            idempotencyKey: RuntimeIdempotencyKey(
              rawValue: try requiredIdentity("--idempotency-key", values: values)
            )
          )
        } else {
          selector = .command(
            conversationID: conversationID,
            commandID: RuntimeCommandID(
              rawValue: try requiredIdentity("--command-id", values: values)
            )
          )
        }
        return .queryReceipt(
          root: root,
          selector: selector
        )
      case .subscribe:
        try requireExactFlags(
          values,
          expected: commonFlags.union(["--conversation-id"])
        )
        return .subscribe(
          root: root,
          conversationID: RuntimeConversationID(
            rawValue: try requiredIdentity("--conversation-id", values: values)
          )
        )
      }
    }

    private static func requireExactFlags(
      _ values: [String: String],
      expected: Set<String>
    ) throws {
      guard Set(values.keys) == expected else {
        throw UsageFailure(message: "Runtime smoke operation has missing or extra arguments")
      }
    }

    private static func requiredIdentity(
      _ flag: String,
      values: [String: String]
    ) throws -> String {
      guard let value = values[flag], !value.isEmpty, value.utf8.count <= 1_024 else {
        throw UsageFailure(message: "\(flag) must contain 1...1024 UTF-8 bytes")
      }
      return value
    }

    private static func execute(
      _ command: Command,
      context: RuntimeSmokeContext
    ) async throws -> RuntimeSmokeExecution {
      switch command {
      case .installation:
        return successExecution(
          InstallationPayload(installationId: context.installationID)
        )
      case .sendPrompt(
        _,
        let conversationID,
        let idempotencyKey,
        let expectedConfigurationRevision,
        let prompt
      ):
        let reply = try await context.wire.request(
          .sendPrompt(
            conversationID: conversationID,
            idempotencyKey: idempotencyKey,
            expectedConfigurationRevision: expectedConfigurationRevision,
            prompt: prompt
          )
        )
        switch reply {
        case .command(.accepted(_, _, let revision)):
          guard revision == expectedConfigurationRevision else {
            return invalidReplyExecution(
              "send-prompt receipt configuration revision does not match the request"
            )
          }
          return replyExecution(reply, succeeded: true)
        case .command(.replayed(_, let revision)):
          guard revision == expectedConfigurationRevision else {
            return invalidReplyExecution(
              "send-prompt replay configuration revision does not match the request"
            )
          }
          return replyExecution(reply, succeeded: true)
        case .command(.failed), .failure:
          return replyExecution(reply, succeeded: false)
        default:
          return invalidReplyExecution("send-prompt returned an unexpected Runtime reply")
        }
      case .queryReceipt(_, let selector):
        let reply = try await context.wire.request(
          .queryReceipt(selector)
        )
        switch reply {
        case .commandStatus(let receipt):
          guard commandStatus(receipt, matches: selector) else {
            return invalidReplyExecution(
              "query-receipt response does not match the requested conversation or command"
            )
          }
          return replyExecution(reply, succeeded: true)
        case .failure:
          return replyExecution(reply, succeeded: false)
        default:
          return invalidReplyExecution("query-receipt returned an unexpected Runtime reply")
        }
      case .subscribe(_, let conversationID):
        return try await executeSubscribe(
          conversationID: conversationID,
          context: context
        )
      }
    }

    private static func executeSubscribe(
      conversationID: RuntimeConversationID,
      context: RuntimeSmokeContext
    ) async throws -> RuntimeSmokeExecution {
      let sequence = try await context.wire.beginAppSynchronizedRequest(
        .subscribe(
          innerCursor: .conversation(
            conversationID: conversationID,
            cursor: .beforeFirst
          )
        )
      )
      var sawSubscription = false
      var subscriptionGeneration: RuntimeStreamGeneration?
      var snapshotCount = 0
      var backfillCount = 0
      var commandIDs: Set<String> = []
      var payloadCursor = RuntimeStreamCursorV1.beforeFirst
      var terminalCursor: RuntimeStreamCursorV1?

      while let reply = try await sequence.next() {
        switch reply {
        case .subscription(.subscribed(let generation)):
          guard
            !sawSubscription,
            snapshotCount == 0,
            backfillCount == 0,
            terminalCursor == nil
          else {
            await sequence.cancel()
            return invalidReplyExecution("subscribe receipt is duplicated or out of order")
          }
          sawSubscription = true
          subscriptionGeneration = generation
        case .snapshot(let snapshot):
          guard
            sawSubscription,
            snapshotCount == 0,
            backfillCount == 0,
            terminalCursor == nil,
            snapshot.conversationID == conversationID
          else {
            await sequence.cancel()
            return invalidReplyExecution("subscribe snapshot is missing, duplicated, or mismatched")
          }
          snapshotCount += 1
          payloadCursor = snapshot.baseEventCursor
          for item in snapshot.items {
            if case .item(_, _, let commandID, _) = item, let commandID {
              commandIDs.insert(commandID.rawValue)
            }
          }
        case .backfill(
          .conversation(let chunkConversationID, _, let range, let events)
        ):
          guard
            sawSubscription,
            chunkConversationID == conversationID,
            range.after == payloadCursor,
            terminalCursor == nil
          else {
            await sequence.cancel()
            return invalidReplyExecution("subscribe backfill is out of order or mismatched")
          }
          backfillCount += 1
          payloadCursor = range.through
          for event in events {
            if let commandID = event.commandID {
              commandIDs.insert(commandID.rawValue)
            }
          }
        case .syncComplete(let terminal):
          guard
            sawSubscription,
            snapshotCount == 1 || backfillCount > 0,
            terminalCursor == nil,
            let subscriptionGeneration,
            terminal.streamGeneration == subscriptionGeneration,
            case .conversation(
              let terminalConversationID,
              let terminalInnerCursor
            ) = terminal.innerCursor,
            terminalConversationID == conversationID,
            terminalInnerCursor == payloadCursor
          else {
            await sequence.cancel()
            return invalidReplyExecution("subscribe terminal is premature or mismatched")
          }
          terminalCursor = terminal.streamCursor
        case .failure:
          return replyExecution(reply, succeeded: false)
        default:
          await sequence.cancel()
          return invalidReplyExecution("subscribe returned an unexpected Runtime reply")
        }
      }

      guard
        sawSubscription,
        subscriptionGeneration != nil,
        snapshotCount <= 1,
        snapshotCount == 1 || backfillCount > 0,
        let terminalCursor
      else {
        return invalidReplyExecution("subscribe ended before the full synchronization barrier")
      }
      return successExecution(
        SubscribePayload(
          backfillCount: backfillCount,
          commandIds: commandIDs.sorted(),
          conversationId: conversationID.rawValue,
          installationId: context.installationID,
          snapshotCount: snapshotCount,
          terminalStreamCursor: terminalCursor
        )
      )
    }

    private static func commandStatus(
      _ receipt: CommandStatusReceiptV2,
      matches selector: RuntimeReceiptSelectorV1
    ) -> Bool {
      switch selector {
      case .command(let conversationID, let commandID):
        receipt.conversationID == conversationID && receipt.commandID == commandID
      case .idempotency(let conversationID, _):
        receipt.conversationID == conversationID
      }
    }

    private static func successExecution<T: Encodable>(
      _ payload: T
    ) -> RuntimeSmokeExecution {
      guard let line = encodedLine(payload) else {
        return failureExecution(
          for: RuntimeSmokeTypedFailure(
            code: "daemon.client.smoke_failed",
            message: "failed to encode Runtime smoke output"
          )
        )
      }
      return RuntimeSmokeExecution(exitCode: 0, stdout: line, stderr: Data())
    }

    private static func replyExecution(
      _ reply: RuntimeReplyV2,
      succeeded: Bool
    ) -> RuntimeSmokeExecution {
      guard let line = encodedLine(reply) else {
        return failureExecution(
          for: RuntimeSmokeTypedFailure(
            code: "daemon.client.smoke_failed",
            message: "failed to encode Runtime smoke reply"
          )
        )
      }
      return RuntimeSmokeExecution(
        exitCode: succeeded ? 0 : 1,
        stdout: succeeded ? line : Data(),
        stderr: succeeded ? Data() : line
      )
    }

    private static func invalidReplyExecution(_ message: String) -> RuntimeSmokeExecution {
      failureExecution(
        for: RuntimeSmokeTypedFailure(
          code: "daemon.client.smoke_reply_invalid",
          message: message
        )
      )
    }

    private static func failureExecution(for error: any Error) -> RuntimeSmokeExecution {
      let failure: RuntimeFailureV1
      let exitCode: Int32
      switch error {
      case let usage as UsageFailure:
        failure = RuntimeFailureV1(
          code: "daemon.client.smoke_usage_invalid",
          message: usage.message
        )
        exitCode = 2
      case let typed as RuntimeSmokeTypedFailure:
        failure = RuntimeFailureV1(
          code: typed.code,
          message: typed.message,
          diagnosticRef: typed.diagnosticRef
        )
        exitCode = 1
      case let client as RuntimeEnvelopeClientFailure:
        failure = RuntimeFailureV1(code: client.code, message: client.message)
        exitCode = 1
      case let installation as LocalClientInstallationError:
        failure = RuntimeFailureV1(
          code: installation.code,
          message: installation.description
        )
        exitCode = 1
      case let transport as UnixSocketDaemonTransportError:
        failure = RuntimeFailureV1(
          code: transport.code,
          message: transport.description
        )
        exitCode = 1
      default:
        failure = RuntimeFailureV1(
          code: "daemon.client.smoke_failed",
          message: String(describing: error)
        )
        exitCode = 1
      }
      let line = encodedLine(RuntimeReplyV2.failure(failure)) ?? encodingFailureLine()
      return RuntimeSmokeExecution(exitCode: exitCode, stdout: Data(), stderr: line)
    }

    private static func encodedLine<T: Encodable>(_ payload: T) -> Data? {
      let encoder = JSONEncoder()
      encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
      guard var data = try? encoder.encode(payload) else { return nil }
      data.append(0x0A)
      return data
    }

    private static func encodingFailureLine() -> Data {
      var data = Data(
        #"{"code":"daemon.client.smoke_failed","diagnosticRef":null,"message":"failed to encode Runtime smoke failure","reply":"failure"}"#
          .utf8
      )
      data.append(0x0A)
      return data
    }
  }

  enum RuntimeSmokeEnvironment {
    static func selfcheckWire(
      arguments: [String]
    ) throws -> (any AppRuntimeWireSession)? {
      let flag = "--runtime-temp-root-for-test"
      var root: String?
      var index = 1
      while index < arguments.count {
        if arguments[index].hasPrefix(flag + "=") {
          throw RuntimeEnvelopeClientFailure(
            code: "daemon.client.selfcheck_usage_invalid",
            message: "selfcheck Runtime temp root requires a separate absolute-path value"
          )
        }
        guard arguments[index] == flag else {
          index += 1
          continue
        }
        guard root == nil, index + 1 < arguments.count else {
          throw RuntimeEnvelopeClientFailure(
            code: "daemon.client.selfcheck_usage_invalid",
            message: "selfcheck accepts exactly one private Runtime temp root"
          )
        }
        root = arguments[index + 1]
        index += 2
      }
      guard let root else { return nil }
      do {
        return try makeContext(rootPath: root).wire
      } catch let failure as RuntimeSmokeTypedFailure {
        throw RuntimeEnvelopeClientFailure(
          code: failure.code,
          message: failure.message
        )
      }
    }

    static func makeContext(rootPath: String) throws -> RuntimeSmokeContext {
      guard rootPath.hasPrefix("/"), !rootPath.utf8.contains(0) else {
        throw unsafePath(rootPath, "private TMPDIR root must be absolute and contain no NUL")
      }
      let rootFD = rootPath.withCString {
        Darwin.open($0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
      }
      guard rootFD >= 0 else {
        throw unsafePath(rootPath, "cannot open private TMPDIR root no-follow (errno=\(errno))")
      }
      defer { Darwin.close(rootFD) }
      try validatePrivateDirectory(rootFD, path: rootPath, label: "private TMPDIR root")

      let namespaceName = try discoverNamespaceName(rootFD: rootFD, rootPath: rootPath)
      let namespacePath = URL(fileURLWithPath: rootPath, isDirectory: true)
        .appendingPathComponent(namespaceName, isDirectory: true)
      let namespaceFD = namespaceName.withCString {
        Darwin.openat(rootFD, $0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
      }
      guard namespaceFD >= 0 else {
        throw unsafePath(namespacePath.path, "cannot open Runtime namespace no-follow")
      }
      defer { Darwin.close(namespaceFD) }
      try validatePrivateDirectory(
        namespaceFD,
        path: namespacePath.path,
        label: "Runtime namespace"
      )

      let clientsPath = URL(fileURLWithPath: rootPath, isDirectory: true)
        .appendingPathComponent("clients", isDirectory: true)
      let clientsFD = try ensurePrivateDirectory(
        parentFD: rootFD,
        name: "clients",
        path: clientsPath.path,
        label: "Runtime smoke clients directory"
      )
      defer { Darwin.close(clientsFD) }
      let installationHome = clientsPath.appendingPathComponent(
        "macos-app",
        isDirectory: true
      )
      let installationHomeFD = try ensurePrivateDirectory(
        parentFD: clientsFD,
        name: "macos-app",
        path: installationHome.path,
        label: "Runtime smoke macOS installation home"
      )
      Darwin.close(installationHomeFD)

      let installation = LocalClientInstallation.injectedForTesting(
        homeDirectory: installationHome,
        expectedUID: geteuid()
      )
      let installationID = try installation.loadOrCreate()
      guard
        let installationUUID = UUID(uuidString: installationID.rawValue),
        installationUUID.uuidString.lowercased() == installationID.rawValue
      else {
        throw RuntimeSmokeTypedFailure(
          code: "daemon.client.installation_record_corrupt",
          message: "Runtime smoke installation ID is not canonical"
        )
      }

      let socketPath = namespacePath.appendingPathComponent("s", isDirectory: false).path
      let transport = UnixSocketDaemonTransport(testSocketPath: socketPath)
      let client = RuntimeEnvelopeClient(
        transport: transport,
        installationID: installationUUID
      )
      return RuntimeSmokeContext(
        installationID: installationID.rawValue,
        wire: LocalRuntimeWireSession(client: client)
      )
    }

    private static func discoverNamespaceName(
      rootFD: Int32,
      rootPath: String
    ) throws -> String {
      let listingFD = Darwin.dup(rootFD)
      guard listingFD >= 0 else {
        throw unsafePath(rootPath, "cannot duplicate private TMPDIR descriptor")
      }
      guard let directory = fdopendir(listingFD) else {
        Darwin.close(listingFD)
        throw unsafePath(rootPath, "cannot enumerate private TMPDIR descriptor")
      }
      defer { closedir(directory) }

      var candidates: [String] = []
      errno = 0
      while let entry = readdir(directory) {
        var value = entry.pointee
        let capacity = MemoryLayout.size(ofValue: value.d_name)
        let name = withUnsafePointer(to: &value.d_name) { pointer in
          pointer.withMemoryRebound(to: CChar.self, capacity: capacity) {
            String(validatingCString: $0)
          }
        }
        guard let name else {
          throw unsafePath(rootPath, "private TMPDIR contains a non-UTF-8 entry")
        }
        guard name != ".", name != "..", name.hasPrefix("ad-") else { continue }
        let suffix = String(name.dropFirst(3))
        guard
          suffix.count == 36,
          suffix == suffix.lowercased(),
          let namespaceID = UUID(uuidString: suffix),
          namespaceID.uuidString.lowercased() == suffix
        else {
          throw unsafePath(rootPath, "Runtime namespace name is not canonical")
        }
        candidates.append(name)
      }
      guard errno == 0 else {
        throw unsafePath(rootPath, "failed while enumerating private TMPDIR")
      }
      switch candidates.count {
      case 0:
        throw RuntimeSmokeTypedFailure(
          code: "daemon.client.socket_missing",
          message: "private Runtime smoke root contains no canonical endpoint"
        )
      case 1:
        return candidates[0]
      default:
        throw unsafePath(rootPath, "private Runtime smoke root contains multiple endpoints")
      }
    }

    private static func ensurePrivateDirectory(
      parentFD: Int32,
      name: String,
      path: String,
      label: String
    ) throws -> Int32 {
      let created = name.withCString { Darwin.mkdirat(parentFD, $0, 0o700) } == 0
      if !created, errno != EEXIST {
        throw unsafePath(path, "cannot create \(label) (errno=\(errno))")
      }
      let descriptor = name.withCString {
        Darwin.openat(parentFD, $0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
      }
      guard descriptor >= 0 else {
        throw unsafePath(path, "cannot open \(label) no-follow (errno=\(errno))")
      }
      do {
        try validatePrivateDirectory(descriptor, path: path, label: label)
        if created, Darwin.fsync(parentFD) != 0 {
          throw unsafePath(path, "cannot synchronize \(label) parent")
        }
        return descriptor
      } catch {
        Darwin.close(descriptor)
        throw error
      }
    }

    private static func validatePrivateDirectory(
      _ descriptor: Int32,
      path: String,
      label: String
    ) throws {
      var entry = stat()
      guard Darwin.fstat(descriptor, &entry) == 0 else {
        throw unsafePath(path, "cannot inspect \(label) (errno=\(errno))")
      }
      guard
        entry.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR),
        entry.st_uid == geteuid(),
        entry.st_mode & 0o7777 == 0o700
      else {
        throw unsafePath(path, "\(label) must be current-EUID exact-0700 directory")
      }
    }

    private static func unsafePath(
      _ path: String,
      _ reason: String
    ) -> RuntimeSmokeTypedFailure {
      RuntimeSmokeTypedFailure(
        code: "daemon.client.socket_unsafe",
        message: "unsafe Runtime smoke path \(path): \(reason)"
      )
    }
  }
#endif
