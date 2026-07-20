import AgentDeckCore
import CryptoKit
import Foundation

/// Swift shared-daemon client 暴露的稳定 typed failure。首个 failure 会冻结并关闭当前
/// connection；后续调用只读回同一 code，不用 EOF 或 channel close 猜测正常完成。
struct RuntimeEnvelopeClientFailure: Error, Equatable, Sendable, CustomStringConvertible {
  let code: String
  let message: String

  var description: String { "\(code): \(message)" }
}

enum RuntimeEnvelopeReplyItem: Sendable {
  case reply(RuntimeReplyV2)
  case transferComplete(Data)
}

enum RuntimeEnvelopeStreamItem: Sendable {
  case message(RuntimeStreamItemV2)
  case transferComplete(Data)
}

struct RuntimeEnvelopeStreamFrame: Sendable {
  let messageID: RuntimeMessageID
  let item: RuntimeEnvelopeStreamItem
}

/// Production 上界集中在这里，test 只可向下收窄以确定性覆盖 backpressure/TTL。
struct RuntimeEnvelopeClientLimits: Sendable {
  static let production = Self()

  let pendingRequests: Int
  let perSequenceFrames: Int
  let queuedReplyFrames: Int
  let queuedReplyBytes: Int
  let streamFrames: Int
  let queuedStreamBytes: Int
  let queuedIngressBytes: Int
  let activeTransfers: Int
  let activeTransferParts: Int
  let reassemblyBytes: Int
  let completedTransferTombstones: Int
  let terminalReplyTombstones: Int
  let helloTimeoutMilliseconds: UInt64
  let replyTimeoutMilliseconds: UInt64
  let synchronizedReplyTimeoutMilliseconds: UInt64
  let drainTTLMilliseconds: UInt64
  let transferTTLMilliseconds: UInt64
  let housekeepingMilliseconds: UInt64

  init(
    pendingRequests: Int = 128,
    perSequenceFrames: Int = 8,
    queuedReplyFrames: Int = 128,
    queuedReplyBytes: Int = 128 * 1024 * 1024,
    streamFrames: Int = 64,
    queuedStreamBytes: Int = 128 * 1024 * 1024,
    queuedIngressBytes: Int = 16 * 1024 * 1024,
    activeTransfers: Int = 64,
    activeTransferParts: Int = 128,
    reassemblyBytes: Int = 128 * 1024 * 1024,
    completedTransferTombstones: Int = 256,
    terminalReplyTombstones: Int = 256,
    helloTimeoutMilliseconds: UInt64 = 5_000,
    replyTimeoutMilliseconds: UInt64 = 30_000,
    synchronizedReplyTimeoutMilliseconds: UInt64 = 5 * 60 * 1_000,
    drainTTLMilliseconds: UInt64 = 5 * 60 * 1_000,
    transferTTLMilliseconds: UInt64 = 5 * 60 * 1_000,
    housekeepingMilliseconds: UInt64 = 1_000
  ) {
    precondition(pendingRequests > 0)
    precondition(perSequenceFrames > 0)
    precondition(queuedReplyFrames > 0)
    precondition(queuedReplyBytes > 0)
    precondition(streamFrames > 0)
    precondition(queuedStreamBytes > 0)
    precondition(queuedIngressBytes > 0)
    precondition(activeTransfers > 0)
    precondition(activeTransferParts > 0)
    precondition(reassemblyBytes > 0)
    precondition(completedTransferTombstones > 0)
    precondition(terminalReplyTombstones > 0)
    precondition(helloTimeoutMilliseconds > 0)
    precondition(replyTimeoutMilliseconds > 0)
    precondition(synchronizedReplyTimeoutMilliseconds > 0)
    precondition(drainTTLMilliseconds > 0)
    precondition(transferTTLMilliseconds > 0)
    precondition(housekeepingMilliseconds > 0)
    self.pendingRequests = pendingRequests
    self.perSequenceFrames = perSequenceFrames
    self.queuedReplyFrames = queuedReplyFrames
    self.queuedReplyBytes = queuedReplyBytes
    self.streamFrames = streamFrames
    self.queuedStreamBytes = queuedStreamBytes
    self.queuedIngressBytes = queuedIngressBytes
    self.activeTransfers = activeTransfers
    self.activeTransferParts = activeTransferParts
    self.reassemblyBytes = reassemblyBytes
    self.completedTransferTombstones = completedTransferTombstones
    self.terminalReplyTombstones = terminalReplyTombstones
    self.helloTimeoutMilliseconds = helloTimeoutMilliseconds
    self.replyTimeoutMilliseconds = replyTimeoutMilliseconds
    self.synchronizedReplyTimeoutMilliseconds = synchronizedReplyTimeoutMilliseconds
    self.drainTTLMilliseconds = drainTTLMilliseconds
    self.transferTTLMilliseconds = transferTTLMilliseconds
    self.housekeepingMilliseconds = housekeepingMilliseconds
  }
}

private struct RuntimeEnvelopeReplyDelivery: Sendable {
  let item: RuntimeEnvelopeReplyItem
  let terminal: Bool
}

/// 一个 request 的有界 reply sequence。Drop 只把已发送 request 转成 draining；daemon
/// terminal 到达前仍按协议消费，五分钟未收口则整条 connection fail-close。
actor RuntimeEnvelopeReplySequence {
  nonisolated let messageID: RuntimeMessageID
  private nonisolated let client: RuntimeEnvelopeClient
  private nonisolated let lease: RuntimeEnvelopeReplySequenceLease
  private var terminalSeen = false

  fileprivate init(
    messageID: RuntimeMessageID,
    client: RuntimeEnvelopeClient,
    lease: RuntimeEnvelopeReplySequenceLease
  ) {
    self.messageID = messageID
    self.client = client
    self.lease = lease
  }

  func next() async throws -> RuntimeEnvelopeReplyItem? {
    if terminalSeen { return nil }
    guard let delivery = try await client.nextReply(messageID: messageID.rawValue) else {
      return nil
    }
    if delivery.terminal { terminalSeen = true }
    return delivery.item
  }

  func cancel() async {
    guard !terminalSeen else { return }
    lease.abandon()
    await client.abandonReplySequence(messageID: messageID.rawValue)
    terminalSeen = true
  }

  deinit {
    let client = client
    let messageID = messageID.rawValue
    lease.abandon()
    Task { await client.abandonReplySequence(messageID: messageID) }
  }
}

private final class RuntimeEnvelopeReplySequenceLease: @unchecked Sendable {
  private let lock = NSLock()
  private var abandoned = false

  func abandon() {
    lock.withLock { abandoned = true }
  }

  var isAbandoned: Bool {
    lock.withLock { abandoned }
  }
}

private enum RuntimeEnvelopeClientLifecycle {
  case idle
  case starting
  case ready
  case faulted
  case closed
}

private enum RuntimeEnvelopeInstallationSource: Sendable {
  case production(LocalClientInstallation)
  case injected(UUID)
}

private enum RuntimeEnvelopeReplyMode {
  case unary
  case synchronized

  static func forRequest(_ request: RuntimeRequestV2) -> Self {
    switch request {
    case .subscribe, .backfill:
      .synchronized
    default:
      .unary
    }
  }
}

private struct RuntimeEnvelopeQueuedReply {
  let delivery: RuntimeEnvelopeReplyDelivery
  let chargedBytes: Int
}

private struct RuntimeEnvelopeReplyWaiter {
  let id: UUID
  let continuation:
    CheckedContinuation<
      Result<Void, RuntimeEnvelopeClientFailure>, Never
    >
}

private struct RuntimeEnvelopePendingReply {
  let mode: RuntimeEnvelopeReplyMode
  let lease: RuntimeEnvelopeReplySequenceLease
  var queue: [RuntimeEnvelopeQueuedReply] = []
  var waiter: RuntimeEnvelopeReplyWaiter?
  var terminalQueued = false
  var sent = false
  var drainingSinceMilliseconds: UInt64?
  let deadlineMilliseconds: UInt64
}

private struct RuntimeEnvelopeStreamWaiter {
  let id: UUID
  let continuation:
    CheckedContinuation<
      Result<Void, RuntimeEnvelopeClientFailure>, Never
    >
}

private struct RuntimeEnvelopeQueuedStream {
  let frame: RuntimeEnvelopeStreamFrame
  let chargedBytes: Int
}

private enum RuntimeEnvelopeIngressEvent: Sendable {
  case frame(String, retainedBytes: Int)
  case disconnected(RuntimeEnvelopeClientFailure)

  var retainedBytes: Int {
    switch self {
    case .frame(_, let retainedBytes): retainedBytes
    case .disconnected: 0
    }
  }
}

private final class RuntimeEnvelopeIngressBudget: @unchecked Sendable {
  private let lock = NSLock()
  private let maximumBytes: Int
  private var retainedBytes = 0

  init(maximumBytes: Int) {
    self.maximumBytes = maximumBytes
  }

  func reserve(_ bytes: Int) -> Bool {
    lock.withLock {
      let (next, overflow) = retainedBytes.addingReportingOverflow(bytes)
      guard !overflow, next <= maximumBytes else { return false }
      retainedBytes = next
      return true
    }
  }

  func release(_ bytes: Int) {
    lock.withLock { retainedBytes -= bytes }
  }
}

private final class RuntimeEnvelopeFaultLatch: @unchecked Sendable {
  private let lock = NSLock()
  private var first: RuntimeEnvelopeClientFailure?

  @discardableResult
  func claim(_ failure: RuntimeEnvelopeClientFailure) -> RuntimeEnvelopeClientFailure {
    lock.withLock {
      if first == nil { first = failure }
      return first!
    }
  }

  var current: RuntimeEnvelopeClientFailure? {
    lock.withLock { first }
  }

  func withUnfaulted<T>(_ body: () throws -> T) throws -> T {
    try lock.withLock {
      if let first { throw first }
      return try body()
    }
  }
}

private enum RuntimeEnvelopeTransferChannel: Hashable, Sendable {
  case reply
  case stream
}

private struct RuntimeEnvelopeTransferMetadata: Equatable {
  let partCount: UInt32
  let totalSHA256: Data
  let totalBytes: UInt64
}

private struct RuntimeEnvelopeActiveTransfer {
  let channel: RuntimeEnvelopeTransferChannel
  let messageID: String
  let metadata: RuntimeEnvelopeTransferMetadata
  let startedMilliseconds: UInt64
  var parts: [UInt32: Data]
  var receivedBytes: Int
}

private struct RuntimeEnvelopeCompletedTransfer {
  let channel: RuntimeEnvelopeTransferChannel
  let messageID: String
  let metadata: RuntimeEnvelopeTransferMetadata
  let partSHA256: [UInt32: Data]
  let completedMilliseconds: UInt64
}

private enum RuntimeEnvelopeTransferProgress {
  case inProgress
  case complete(Data, assemblyCharge: Int)
  case alreadyComplete
}

/// Runtime v3 JSON/UDS actor client。所有 pending、reply/stream queue、transfer reassembly
/// 与首故障都由单一 actor 拥有；transport callback 先进入有界 AsyncStream，保持 reader
/// 交付顺序后再触碰 actor 状态。
actor RuntimeEnvelopeClient {
  static let maximumPendingRequests = 128
  static let maximumReplySequenceFrames = 8
  static let maximumQueuedReplyFrames = 128
  static let maximumQueuedReplyBytes = 128 * 1024 * 1024
  static let maximumStreamFrames = 64
  static let maximumQueuedStreamBytes = 128 * 1024 * 1024
  static let maximumQueuedIngressBytes = 16 * 1024 * 1024
  static let maximumTransferBytes = 64 * 1024 * 1024
  static let maximumTransferParts = 94
  static let maximumReassemblyBytes = 128 * 1024 * 1024
  static let maximumActiveTransferParts = 128

  private let transport: UnixSocketDaemonTransport
  private let installationSource: RuntimeEnvelopeInstallationSource
  private let limits: RuntimeEnvelopeClientLimits
  private let messageIDGenerator: @Sendable () -> String
  private let nowMilliseconds: @Sendable () -> UInt64
  private let beforeIngressConsume: @Sendable () async -> Void
  private let beforeHelloReady: @Sendable () async -> Void

  private var lifecycle = RuntimeEnvelopeClientLifecycle.idle
  private var installationID: String?
  private var expectedFirstMessageID: String?
  private var firstFault: RuntimeEnvelopeClientFailure?
  private var pendingReplies: [String: RuntimeEnvelopePendingReply] = [:]
  private var terminalReplies: [String: UInt64] = [:]
  private var terminalReplyOrder: [(UInt64, String)] = []
  private var queuedReplyFrames = 0
  private var queuedReplyBytes = 0
  private var streamQueue: [RuntimeEnvelopeQueuedStream] = []
  private var queuedStreamBytes = 0
  private var streamWaiter: RuntimeEnvelopeStreamWaiter?
  private var activeTransfers: [String: RuntimeEnvelopeActiveTransfer] = [:]
  private var activeTransferParts = 0
  private var reassemblyBytes = 0
  private var completedTransfers: [String: RuntimeEnvelopeCompletedTransfer] = [:]
  private var completedTransferOrder: [(UInt64, String)] = []
  private var ingressContinuation: AsyncStream<RuntimeEnvelopeIngressEvent>.Continuation?
  private let faultLatch = RuntimeEnvelopeFaultLatch()
  private let ingressBudget: RuntimeEnvelopeIngressBudget
  private var ingressTask: Task<Void, Never>?
  private var housekeepingTask: Task<Void, Never>?

  /// Production default：installation record 与 endpoint 都只能由 OS account 派生。
  init(installation: LocalClientInstallation) {
    transport = UnixSocketDaemonTransport(installation: installation)
    installationSource = .production(installation)
    limits = .production
    messageIDGenerator = { UUID().uuidString.lowercased() }
    nowMilliseconds = { DispatchTime.now().uptimeNanoseconds / 1_000_000 }
    ingressBudget = RuntimeEnvelopeIngressBudget(
      maximumBytes: RuntimeEnvelopeClientLimits.production.queuedIngressBytes
    )
    beforeIngressConsume = {}
    beforeHelloReady = {}
  }

  /// 显式 test/harness seam；production composition 不接受任意 pathname 或 identity。
  init(
    transport: UnixSocketDaemonTransport,
    installationID: UUID,
    limits: RuntimeEnvelopeClientLimits = .production,
    messageIDGenerator: @escaping @Sendable () -> String = {
      UUID().uuidString.lowercased()
    },
    nowMilliseconds: @escaping @Sendable () -> UInt64 = {
      DispatchTime.now().uptimeNanoseconds / 1_000_000
    },
    beforeIngressConsume: @escaping @Sendable () async -> Void = {},
    beforeHelloReady: @escaping @Sendable () async -> Void = {}
  ) {
    self.transport = transport
    installationSource = .injected(installationID)
    self.limits = limits
    self.messageIDGenerator = messageIDGenerator
    self.nowMilliseconds = nowMilliseconds
    ingressBudget = RuntimeEnvelopeIngressBudget(maximumBytes: limits.queuedIngressBytes)
    self.beforeIngressConsume = beforeIngressConsume
    self.beforeHelloReady = beforeHelloReady
  }

  deinit {
    transport.close()
    ingressContinuation?.finish()
    ingressTask?.cancel()
    housekeepingTask?.cancel()
  }

  /// connect + strict preface 后发送唯一首帧 Hello，并等待 exact correlated terminal。
  func start() async throws {
    guard lifecycle == .idle else {
      throw failure(
        "daemon.client.already_started",
        "RuntimeEnvelopeClient start may be called exactly once"
      )
    }
    lifecycle = .starting
    let helloID = try nextMessageID()
    expectedFirstMessageID = helloID.rawValue
    let helloSequence = try registerPending(
      request: .hello(runtimeProtocolVersion: runtimeProtocolVersionCurrent),
      messageID: helloID,
      timeoutMilliseconds: limits.helloTimeoutMilliseconds
    )
    configureIngress()

    do {
      switch installationSource {
      case .production(let installation):
        let identity = try installation.loadOrCreate()
        installationID = identity.rawValue
        try transport.start(
          installationID: identity,
          incomingHandler: ingressHandler(),
          disconnectHandler: disconnectHandler()
        )
      case .injected(let identity):
        installationID = identity.uuidString.lowercased()
        try transport.start(
          installationID: identity,
          incomingHandler: ingressHandler(),
          disconnectHandler: disconnectHandler()
        )
      }
      try sendRegistered(
        request: .hello(runtimeProtocolVersion: runtimeProtocolVersionCurrent),
        messageID: helloID
      )
      guard let item = try await helloSequence.next() else {
        throw failure(
          "daemon.client.connection_closed",
          "Hello sequence ended before its terminal reply"
        )
      }
      switch item {
      case .reply(.hello(let runtimeProtocolVersion))
      where runtimeProtocolVersion == runtimeProtocolVersionCurrent:
        await beforeHelloReady()
        guard lifecycle == .starting, firstFault == nil, faultLatch.current == nil else {
          throw firstFault ?? faultLatch.current
            ?? failure(
              "daemon.client.connection_closed",
              "Runtime connection changed state before Hello became ready"
            )
        }
        lifecycle = .ready
      case .reply(.failure(let daemonFailure)):
        let failure = RuntimeEnvelopeClientFailure(
          code: daemonFailure.code,
          message: daemonFailure.message
        )
        failConnection(failure)
        throw failure
      default:
        let failure = failure(
          "daemon.client.hello_invalid",
          "first correlated terminal is not Runtime v3 Hello"
        )
        failConnection(failure)
        throw failure
      }
    } catch {
      let mapped = mapError(error)
      if firstFault == nil { failConnection(mapped) }
      throw firstFault ?? faultLatch.current ?? mapped
    }
  }

  /// 只用于单 terminal 请求。Subscribe/Backfill 必须使用 `beginRequest`。
  func request(_ request: RuntimeRequestV2) async throws -> RuntimeEnvelopeReplyItem {
    guard RuntimeEnvelopeReplyMode.forRequest(request) == .unary else {
      throw failure(
        "daemon.client.sequence_required",
        "Subscribe/Backfill require the reply-sequence API"
      )
    }
    let sequence = try beginRequest(request)
    guard let item = try await sequence.next() else {
      throw failure(
        "daemon.client.connection_closed",
        "unary request ended before its terminal reply"
      )
    }
    return item
  }

  /// 发起一个可并发、按 messageId 精确相关的有界 reply sequence。
  func beginRequest(_ request: RuntimeRequestV2) throws -> RuntimeEnvelopeReplySequence {
    if let connectionFault = firstFault ?? faultLatch.current {
      throw connectionFault
    }
    guard lifecycle == .ready else {
      throw firstFault ?? faultLatch.current
        ?? failure(
          "daemon.client.not_started",
          "RuntimeEnvelopeClient has not completed Hello"
        )
    }
    let messageID = try nextMessageID()
    let sequence = try registerPending(
      request: request,
      messageID: messageID,
      timeoutMilliseconds: RuntimeEnvelopeReplyMode.forRequest(request) == .synchronized
        ? limits.synchronizedReplyTimeoutMilliseconds
        : limits.replyTimeoutMilliseconds
    )
    do {
      try sendRegistered(request: request, messageID: messageID)
      return sequence
    } catch {
      removePending(messageID.rawValue)
      let mapped = mapError(error)
      if error is UnixSocketDaemonTransportError { failConnection(mapped) }
      throw firstFault ?? faultLatch.current ?? mapped
    }
  }

  func nextStream() async throws -> RuntimeEnvelopeStreamFrame {
    while true {
      if let first = streamQueue.first {
        streamQueue.removeFirst()
        queuedStreamBytes -= first.chargedBytes
        return first.frame
      }
      if let connectionFault = firstFault ?? faultLatch.current {
        throw connectionFault
      }
      guard lifecycle == .ready else {
        throw failure(
          "daemon.client.not_started",
          "RuntimeEnvelopeClient has not completed Hello"
        )
      }
      let waiterID = UUID()
      let result = await withTaskCancellationHandler {
        await withCheckedContinuation { continuation in
          installStreamWaiter(id: waiterID, continuation: continuation)
        }
      } onCancel: {
        Task { await self.cancelStreamWaiter(id: waiterID) }
      }
      try result.get()
    }
  }

  func fault() -> RuntimeEnvelopeClientFailure? { firstFault ?? faultLatch.current }

  func currentInstallationID() -> String? { installationID }

  /// 只关闭当前 client fd/pumps；绝不发送 daemon shutdown RuntimeRequest。
  func close() {
    guard lifecycle != .closed else { return }
    let latchedFault = firstFault ?? faultLatch.current
    let closeFailure =
      latchedFault
      ?? failure(
        "daemon.client.connection_closed",
        "RuntimeEnvelopeClient was explicitly closed"
      )
    lifecycle = .closed
    finishConnection(closeFailure, rememberAsFault: latchedFault != nil)
  }

  fileprivate func nextReply(
    messageID: String
  ) async throws -> RuntimeEnvelopeReplyDelivery? {
    while true {
      if var pending = pendingReplies[messageID], !pending.queue.isEmpty {
        let queued = pending.queue.removeFirst()
        queuedReplyFrames -= 1
        queuedReplyBytes -= queued.chargedBytes
        if queued.delivery.terminal {
          pendingReplies.removeValue(forKey: messageID)
          rememberTerminalReply(messageID)
        } else {
          pendingReplies[messageID] = pending
        }
        return queued.delivery
      }
      if let connectionFault = firstFault ?? faultLatch.current {
        pendingReplies.removeValue(forKey: messageID)
        throw connectionFault
      }
      guard pendingReplies[messageID] != nil else { return nil }

      let waiterID = UUID()
      let result = await withTaskCancellationHandler {
        await withCheckedContinuation { continuation in
          installReplyWaiter(
            messageID: messageID,
            id: waiterID,
            continuation: continuation
          )
        }
      } onCancel: {
        Task { await self.cancelReplyWaiter(messageID: messageID, id: waiterID) }
      }
      try result.get()
    }
  }

  fileprivate func abandonReplySequence(messageID: String) {
    guard var pending = pendingReplies[messageID] else { return }
    pending.lease.abandon()
    if pending.terminalQueued {
      releaseReplyQueue(&pending)
      pendingReplies.removeValue(forKey: messageID)
      rememberTerminalReply(messageID)
      return
    }
    markReplyDraining(&pending)
    if pending.sent {
      pendingReplies[messageID] = pending
    } else {
      pendingReplies.removeValue(forKey: messageID)
    }
  }

  private func markReplyDraining(_ pending: inout RuntimeEnvelopePendingReply) {
    releaseReplyQueue(&pending)
    if let waiter = pending.waiter {
      pending.waiter = nil
      waiter.continuation.resume(
        returning: .failure(
          failure(
            "daemon.client.reply_cancelled",
            "reply sequence consumer was dropped"
          )
        )
      )
    }
    if pending.sent {
      pending.drainingSinceMilliseconds =
        pending.drainingSinceMilliseconds
        ?? nowMilliseconds()
    }
  }

  private func configureIngress() {
    let capacity = limits.queuedReplyFrames + limits.streamFrames + 1
    let pair = AsyncStream.makeStream(
      of: RuntimeEnvelopeIngressEvent.self,
      bufferingPolicy: .bufferingOldest(capacity)
    )
    ingressContinuation = pair.continuation
    ingressTask = Task { [weak self] in
      for await event in pair.stream {
        guard let self else { return }
        await self.consumeIngressAfterHook(event)
      }
      await self?.ingressFinished()
    }
    let interval = limits.housekeepingMilliseconds
    housekeepingTask = Task { [weak self] in
      while !Task.isCancelled {
        do {
          try await Task.sleep(for: .milliseconds(Int64(interval)))
        } catch {
          return
        }
        guard let self else { return }
        await self.housekeep()
      }
    }
  }

  private func ingressHandler() -> @Sendable (String) -> Void {
    let continuation = ingressContinuation
    let transport = transport
    let faultLatch = faultLatch
    let ingressBudget = ingressBudget
    return { frame in
      guard let continuation else { return }
      let retainedBytes = max(frame.utf8.count, 1)
      guard ingressBudget.reserve(retainedBytes) else {
        faultLatch.claim(
          RuntimeEnvelopeClientFailure(
            code: "daemon.client.reply_backpressure",
            message: "bounded Runtime ingress retained-byte budget overflowed"
          )
        )
        transport.close()
        continuation.finish()
        return
      }
      switch continuation.yield(.frame(frame, retainedBytes: retainedBytes)) {
      case .enqueued:
        break
      case .dropped:
        ingressBudget.release(retainedBytes)
        faultLatch.claim(
          RuntimeEnvelopeClientFailure(
            code: "daemon.client.reply_backpressure",
            message: "bounded Runtime ingress queue overflowed"
          )
        )
        transport.close()
        continuation.finish()
      case .terminated:
        ingressBudget.release(retainedBytes)
        transport.close()
      @unknown default:
        ingressBudget.release(retainedBytes)
        faultLatch.claim(
          RuntimeEnvelopeClientFailure(
            code: "daemon.client.reply_backpressure",
            message: "bounded Runtime ingress queue overflowed"
          )
        )
        transport.close()
        continuation.finish()
      }
    }
  }

  private func disconnectHandler() -> @Sendable (UnixSocketDaemonTransportError) -> Void {
    let continuation = ingressContinuation
    let faultLatch = faultLatch
    return { error in
      guard let continuation else { return }
      let exact = RuntimeEnvelopeClientFailure(
        code: error.code,
        message: error.description
      )
      switch continuation.yield(.disconnected(exact)) {
      case .enqueued:
        break
      case .dropped, .terminated:
        faultLatch.claim(exact)
      @unknown default:
        faultLatch.claim(exact)
      }
      continuation.finish()
    }
  }

  private func consumeIngressAfterHook(_ event: RuntimeEnvelopeIngressEvent) async {
    await beforeIngressConsume()
    defer { ingressBudget.release(event.retainedBytes) }
    if let latched = faultLatch.current {
      failConnection(latched)
      return
    }
    consumeIngress(event)
  }

  private func consumeIngress(_ event: RuntimeEnvelopeIngressEvent) {
    guard lifecycle == .starting || lifecycle == .ready else { return }
    if let latched = faultLatch.current {
      failConnection(latched)
      return
    }
    switch event {
    case .disconnected(let failure):
      failConnection(failure)
    case .frame(let frame, _):
      housekeep()
      guard firstFault == nil else { return }
      do {
        let envelope = try RuntimeWireCodec.decodeEnvelope(Data(frame.utf8))
        try accept(envelope, frameBytes: frame.utf8.count)
      } catch let failure as RuntimeEnvelopeClientFailure {
        failConnection(failure)
      } catch {
        failConnection(
          failure(
            "daemon.client.frame_invalid",
            "Runtime v3 envelope decode failed: \(error)"
          )
        )
      }
    }
  }

  private func ingressFinished() {
    guard lifecycle == .starting || lifecycle == .ready else { return }
    failConnection(
      faultLatch.current
        ?? failure(
          "daemon.client.connection_closed",
          "Runtime transport ended before client close"
        )
    )
  }

  private func accept(_ envelope: RuntimeEnvelopeV2, frameBytes: Int) throws {
    if let expected = expectedFirstMessageID {
      guard envelope.messageID.rawValue == expected else {
        throw failure(
          "daemon.client.hello_order_invalid",
          "first daemon frame did not correlate to Hello"
        )
      }
      switch envelope.body {
      case .reply(.hello), .reply(.failure):
        expectedFirstMessageID = nil
      default:
        throw failure(
          "daemon.client.hello_order_invalid",
          "first daemon frame was not Hello/Failure reply"
        )
      }
    }

    switch envelope.body {
    case .request:
      throw failure(
        "daemon.client.server_request_forbidden",
        "daemon sent RuntimeRequest on client receive path"
      )
    case .reply(let reply):
      try acceptReply(
        messageID: envelope.messageID.rawValue,
        reply: reply,
        frameBytes: frameBytes
      )
    case .stream(let stream):
      try acceptStream(
        messageID: envelope.messageID,
        stream: stream,
        frameBytes: frameBytes
      )
    }
  }

  private func acceptReply(
    messageID: String,
    reply: RuntimeReplyV2,
    frameBytes: Int
  ) throws {
    guard var pending = pendingReplies[messageID] else {
      throw failure(
        "daemon.client.reply_uncorrelated",
        "reply has no pending request or follows a terminal"
      )
    }
    guard !pending.terminalQueued else {
      throw failure(
        "daemon.client.reply_uncorrelated",
        "reply arrived after a terminal for the same messageId"
      )
    }

    let item: RuntimeEnvelopeReplyItem
    let terminal: Bool
    let charge: Int
    switch reply {
    case .transferPart(let part):
      let progress = try acceptTransfer(
        part,
        channel: .reply,
        messageID: messageID
      )
      switch progress {
      case .inProgress, .alreadyComplete:
        return
      case .complete(let bytes, let assemblyCharge):
        releaseAssemblyCharge(assemblyCharge)
        item = .transferComplete(bytes)
        terminal = pending.mode == .unary
        charge = max(bytes.count, 1)
      }
    default:
      if hasActiveTransfer(channel: .reply, messageID: messageID) {
        throw failure(
          "daemon.client.transfer_incomplete",
          "reply overtook an incomplete transfer"
        )
      }
      item = .reply(reply)
      terminal = pending.mode == .unary || reply.isSynchronizedTerminal
      charge = max(frameBytes, 1)
    }

    try faultLatch.withUnfaulted {
      if pending.lease.isAbandoned, pending.drainingSinceMilliseconds == nil {
        if pending.terminalQueued {
          releaseReplyQueue(&pending)
          pendingReplies.removeValue(forKey: messageID)
          rememberTerminalReply(messageID)
          throw failure(
            "daemon.client.reply_uncorrelated",
            "reply arrived after a terminal for an abandoned sequence"
          )
        }
        markReplyDraining(&pending)
      }
      if pending.drainingSinceMilliseconds != nil {
        if terminal {
          releaseReplyQueue(&pending)
          pendingReplies.removeValue(forKey: messageID)
          rememberTerminalReply(messageID)
        } else {
          pendingReplies[messageID] = pending
        }
        return
      }
      try deliverReply(
        RuntimeEnvelopeReplyDelivery(item: item, terminal: terminal),
        charge: charge,
        messageID: messageID,
        pending: &pending
      )
    }
  }

  private func deliverReply(
    _ delivery: RuntimeEnvelopeReplyDelivery,
    charge: Int,
    messageID: String,
    pending: inout RuntimeEnvelopePendingReply
  ) throws {
    if pending.lease.isAbandoned {
      if delivery.terminal {
        releaseReplyQueue(&pending)
        pendingReplies.removeValue(forKey: messageID)
        rememberTerminalReply(messageID)
      } else {
        markReplyDraining(&pending)
        pendingReplies[messageID] = pending
      }
      return
    }
    guard pending.queue.count < limits.perSequenceFrames else {
      throw failure(
        "daemon.client.reply_sequence_backpressure",
        "per-request reply queue is full"
      )
    }
    guard queuedReplyFrames < limits.queuedReplyFrames else {
      throw failure(
        "daemon.client.reply_sequence_backpressure",
        "connection reply frame budget is full"
      )
    }
    let (nextBytes, overflow) = queuedReplyBytes.addingReportingOverflow(charge)
    guard !overflow, nextBytes <= limits.queuedReplyBytes else {
      throw failure(
        "daemon.client.reply_sequence_backpressure",
        "connection reply byte budget is full"
      )
    }
    queuedReplyFrames += 1
    queuedReplyBytes = nextBytes
    let waiter = pending.waiter
    pending.waiter = nil
    pending.queue.append(
      RuntimeEnvelopeQueuedReply(delivery: delivery, chargedBytes: charge)
    )
    pending.terminalQueued = delivery.terminal
    pendingReplies[messageID] = pending
    waiter?.continuation.resume(returning: .success(()))
  }

  private func acceptStream(
    messageID: RuntimeMessageID,
    stream: RuntimeStreamItemV2,
    frameBytes: Int
  ) throws {
    let frame: RuntimeEnvelopeStreamFrame
    let charge: Int
    switch stream {
    case .transferPart(let part):
      switch try acceptTransfer(
        part,
        channel: .stream,
        messageID: messageID.rawValue
      ) {
      case .inProgress, .alreadyComplete:
        return
      case .complete(let bytes, let assemblyCharge):
        releaseAssemblyCharge(assemblyCharge)
        frame = RuntimeEnvelopeStreamFrame(
          messageID: messageID,
          item: .transferComplete(bytes)
        )
        charge = max(bytes.count, 1)
      }
    default:
      if hasActiveTransfer(channel: .stream, messageID: messageID.rawValue) {
        throw failure(
          "daemon.client.transfer_incomplete",
          "stream item overtook an incomplete transfer"
        )
      }
      frame = RuntimeEnvelopeStreamFrame(messageID: messageID, item: .message(stream))
      charge = max(frameBytes, 1)
    }
    try faultLatch.withUnfaulted {
      guard streamQueue.count < limits.streamFrames else {
        throw failure(
          "daemon.client.stream_backpressure",
          "bounded Runtime stream queue is full"
        )
      }
      let (nextBytes, overflow) = queuedStreamBytes.addingReportingOverflow(charge)
      guard !overflow, nextBytes <= limits.queuedStreamBytes else {
        throw failure(
          "daemon.client.stream_backpressure",
          "bounded Runtime stream retained-byte budget is full"
        )
      }
      let waiter = streamWaiter
      streamWaiter = nil
      queuedStreamBytes = nextBytes
      streamQueue.append(RuntimeEnvelopeQueuedStream(frame: frame, chargedBytes: charge))
      waiter?.continuation.resume(returning: .success(()))
    }
  }

  private func acceptTransfer(
    _ part: TransferEnvelopeV2,
    channel: RuntimeEnvelopeTransferChannel,
    messageID: String
  ) throws -> RuntimeEnvelopeTransferProgress {
    guard part.totalBytes <= UInt64(Self.maximumTransferBytes),
      part.partCount <= UInt32(Self.maximumTransferParts)
    else {
      throw failure(
        "daemon.client.transfer_invalid",
        "JSON transfer exceeds 64 MiB or 94 parts"
      )
    }
    let transferID = part.transferID.rawValue
    let metadata = RuntimeEnvelopeTransferMetadata(
      partCount: part.partCount,
      totalSHA256: part.totalSHA256,
      totalBytes: part.totalBytes
    )
    if let completed = completedTransfers[transferID] {
      guard completed.channel == channel,
        completed.messageID == messageID,
        completed.metadata == metadata
      else {
        throw failure(
          "daemon.client.transfer_binding_mismatch",
          "completed transferId was reused with another binding"
        )
      }
      guard completed.partSHA256[part.partIndex] == Data(SHA256.hash(data: part.part)) else {
        throw failure(
          "daemon.client.transfer_invalid",
          "completed transfer part replay changed bytes"
        )
      }
      return .alreadyComplete
    }

    var active: RuntimeEnvelopeActiveTransfer
    if let existing = activeTransfers[transferID] {
      guard existing.channel == channel,
        existing.messageID == messageID,
        existing.metadata == metadata
      else {
        throw failure(
          "daemon.client.transfer_binding_mismatch",
          "active transferId was reused with another binding"
        )
      }
      active = existing
    } else {
      guard activeTransfers.count < limits.activeTransfers else {
        throw failure(
          "daemon.client.transfer_backpressure",
          "active transfer budget is full"
        )
      }
      active = RuntimeEnvelopeActiveTransfer(
        channel: channel,
        messageID: messageID,
        metadata: metadata,
        startedMilliseconds: nowMilliseconds(),
        parts: [:],
        receivedBytes: 0
      )
    }

    if let previous = active.parts[part.partIndex] {
      guard previous == part.part else {
        throw failure(
          "daemon.client.transfer_invalid",
          "duplicate transfer part has conflicting bytes"
        )
      }
      return .inProgress
    }
    guard activeTransferParts < limits.activeTransferParts else {
      throw failure(
        "daemon.client.transfer_backpressure",
        "active transfer-part frame budget is full"
      )
    }
    let (nextPartBytes, partOverflow) = active.receivedBytes.addingReportingOverflow(
      part.part.count
    )
    let (nextReassemblyBytes, globalOverflow) = reassemblyBytes.addingReportingOverflow(
      part.part.count
    )
    guard !partOverflow,
      !globalOverflow,
      nextReassemblyBytes <= limits.reassemblyBytes,
      UInt64(nextPartBytes) <= part.totalBytes
    else {
      throw failure(
        "daemon.client.transfer_backpressure",
        "connection transfer reassembly budget is full"
      )
    }
    active.parts[part.partIndex] = part.part
    active.receivedBytes = nextPartBytes
    activeTransferParts += 1
    reassemblyBytes = nextReassemblyBytes
    activeTransfers[transferID] = active

    guard active.parts.count == Int(part.partCount) else { return .inProgress }
    guard UInt64(active.receivedBytes) == part.totalBytes else {
      throw failure(
        "daemon.client.transfer_invalid",
        "complete transfer byte count does not match totalBytes"
      )
    }
    let (peakBytes, peakOverflow) = reassemblyBytes.addingReportingOverflow(
      active.receivedBytes
    )
    guard !peakOverflow, peakBytes <= limits.reassemblyBytes else {
      throw failure(
        "daemon.client.transfer_backpressure",
        "transfer assembly would exceed the connection reassembly peak"
      )
    }
    reassemblyBytes = peakBytes
    var assembled = Data()
    assembled.reserveCapacity(active.receivedBytes)
    for index in 0..<part.partCount {
      guard let bytes = active.parts[index] else {
        throw failure(
          "daemon.client.transfer_invalid",
          "complete transfer has a missing part index"
        )
      }
      assembled.append(bytes)
    }
    guard Data(SHA256.hash(data: assembled)) == part.totalSHA256 else {
      throw failure(
        "daemon.client.transfer_invalid",
        "complete transfer SHA-256 mismatch"
      )
    }
    let partSHA256 = active.parts.mapValues { Data(SHA256.hash(data: $0)) }
    removeActiveTransfer(transferID)
    rememberCompletedTransfer(
      transferID: transferID,
      channel: channel,
      messageID: messageID,
      metadata: metadata,
      partSHA256: partSHA256
    )
    return .complete(assembled, assemblyCharge: active.receivedBytes)
  }

  private func hasActiveTransfer(
    channel: RuntimeEnvelopeTransferChannel,
    messageID: String
  ) -> Bool {
    activeTransfers.values.contains {
      $0.channel == channel && $0.messageID == messageID
    }
  }

  private func removeActiveTransfer(_ transferID: String) {
    guard let active = activeTransfers.removeValue(forKey: transferID) else { return }
    activeTransferParts -= active.parts.count
    reassemblyBytes -= active.receivedBytes
  }

  private func releaseAssemblyCharge(_ charge: Int) {
    reassemblyBytes -= charge
  }

  private func rememberCompletedTransfer(
    transferID: String,
    channel: RuntimeEnvelopeTransferChannel,
    messageID: String,
    metadata: RuntimeEnvelopeTransferMetadata,
    partSHA256: [UInt32: Data]
  ) {
    let now = nowMilliseconds()
    while completedTransfers.count >= limits.completedTransferTombstones,
      let oldest = completedTransferOrder.first
    {
      completedTransferOrder.removeFirst()
      completedTransfers.removeValue(forKey: oldest.1)
    }
    completedTransfers[transferID] = RuntimeEnvelopeCompletedTransfer(
      channel: channel,
      messageID: messageID,
      metadata: metadata,
      partSHA256: partSHA256,
      completedMilliseconds: now
    )
    completedTransferOrder.append((now, transferID))
  }

  private func registerPending(
    request: RuntimeRequestV2,
    messageID: RuntimeMessageID,
    timeoutMilliseconds: UInt64
  ) throws -> RuntimeEnvelopeReplySequence {
    guard pendingReplies.count < limits.pendingRequests else {
      throw failure(
        "daemon.client.reply_backpressure",
        "pending Runtime request budget is full"
      )
    }
    let raw = messageID.rawValue
    guard pendingReplies[raw] == nil, terminalReplies[raw] == nil else {
      let duplicate = failure(
        "daemon.client.message_id_duplicate",
        "generated Runtime messageId was duplicated"
      )
      failConnection(duplicate)
      throw duplicate
    }
    let now = nowMilliseconds()
    let deadline = now.addingReportingOverflow(timeoutMilliseconds)
    guard !deadline.overflow else {
      throw failure(
        "daemon.client.reply_timeout",
        "reply deadline overflowed"
      )
    }
    let lease = RuntimeEnvelopeReplySequenceLease()
    pendingReplies[raw] = RuntimeEnvelopePendingReply(
      mode: .forRequest(request),
      lease: lease,
      deadlineMilliseconds: deadline.partialValue
    )
    return RuntimeEnvelopeReplySequence(messageID: messageID, client: self, lease: lease)
  }

  private func sendRegistered(request: RuntimeRequestV2, messageID: RuntimeMessageID) throws {
    let envelope = RuntimeEnvelopeV2(
      version: runtimeProtocolVersionCurrent,
      messageID: messageID,
      body: .request(request)
    )
    let data: Data
    do {
      data = try RuntimeWireCodec.encode(envelope)
    } catch {
      throw failure(
        "daemon.client.encode_failed",
        "Runtime request encoding failed: \(error)"
      )
    }
    guard let frame = String(data: data, encoding: .utf8) else {
      throw failure(
        "daemon.client.encode_failed",
        "Runtime request encoding was not UTF-8"
      )
    }
    try transport.sendFrame(frame)
    if var pending = pendingReplies[messageID.rawValue] {
      pending.sent = true
      pendingReplies[messageID.rawValue] = pending
    }
  }

  private func nextMessageID() throws -> RuntimeMessageID {
    let raw = messageIDGenerator()
    guard raw.utf8.count == 36,
      raw == raw.lowercased(),
      let uuid = UUID(uuidString: raw),
      uuid != Self.nilUUID,
      uuid.uuidString.lowercased() == raw
    else {
      throw failure(
        "daemon.client.message_id_invalid",
        "generated messageId is not a canonical non-nil UUID"
      )
    }
    return RuntimeMessageID(rawValue: raw)
  }

  private func installReplyWaiter(
    messageID: String,
    id: UUID,
    continuation: CheckedContinuation<
      Result<Void, RuntimeEnvelopeClientFailure>, Never
    >
  ) {
    guard var pending = pendingReplies[messageID] else {
      continuation.resume(returning: .success(()))
      return
    }
    if pending.lease.isAbandoned {
      markReplyDraining(&pending)
      pendingReplies[messageID] = pending
      continuation.resume(
        returning: .failure(
          failure(
            "daemon.client.reply_cancelled",
            "reply sequence consumer was dropped"
          )
        )
      )
      return
    }
    guard pending.waiter == nil else {
      let duplicate = failure(
        "daemon.client.reply_consumer_duplicate",
        "a reply sequence already has an active next() waiter"
      )
      continuation.resume(returning: .failure(duplicate))
      failConnection(duplicate)
      return
    }
    pending.waiter = RuntimeEnvelopeReplyWaiter(id: id, continuation: continuation)
    pendingReplies[messageID] = pending
  }

  private func cancelReplyWaiter(messageID: String, id: UUID) {
    guard var pending = pendingReplies[messageID], pending.waiter?.id == id else { return }
    let waiter = pending.waiter
    pending.waiter = nil
    pendingReplies[messageID] = pending
    waiter?.continuation.resume(
      returning: .failure(
        failure(
          "daemon.client.reply_cancelled",
          "reply wait was cancelled"
        )
      )
    )
  }

  private func installStreamWaiter(
    id: UUID,
    continuation: CheckedContinuation<
      Result<Void, RuntimeEnvelopeClientFailure>, Never
    >
  ) {
    guard streamWaiter == nil else {
      let duplicate = failure(
        "daemon.client.stream_consumer_duplicate",
        "stream already has an active nextStream waiter"
      )
      continuation.resume(returning: .failure(duplicate))
      failConnection(duplicate)
      return
    }
    streamWaiter = RuntimeEnvelopeStreamWaiter(id: id, continuation: continuation)
  }

  private func cancelStreamWaiter(id: UUID) {
    guard streamWaiter?.id == id else { return }
    let waiter = streamWaiter
    streamWaiter = nil
    waiter?.continuation.resume(
      returning: .failure(
        failure(
          "daemon.client.stream_cancelled",
          "stream wait was cancelled"
        )
      )
    )
  }

  private func removePending(_ messageID: String) {
    guard var pending = pendingReplies.removeValue(forKey: messageID) else { return }
    releaseReplyQueue(&pending)
    pending.waiter?.continuation.resume(
      returning: .failure(
        failure(
          "daemon.client.connection_closed",
          "request was removed before terminal"
        )
      )
    )
  }

  private func releaseReplyQueue(_ pending: inout RuntimeEnvelopePendingReply) {
    for queued in pending.queue {
      queuedReplyFrames -= 1
      queuedReplyBytes -= queued.chargedBytes
    }
    pending.queue.removeAll(keepingCapacity: false)
    pending.terminalQueued = false
  }

  private func rememberTerminalReply(_ messageID: String) {
    let now = nowMilliseconds()
    while terminalReplies.count >= limits.terminalReplyTombstones,
      let oldest = terminalReplyOrder.first
    {
      terminalReplyOrder.removeFirst()
      terminalReplies.removeValue(forKey: oldest.1)
    }
    terminalReplies[messageID] = now
    terminalReplyOrder.append((now, messageID))
  }

  private func housekeep() {
    guard firstFault == nil, faultLatch.current == nil,
      lifecycle == .starting || lifecycle == .ready
    else { return }
    let now = nowMilliseconds()
    if pendingReplies.values.contains(where: {
      !$0.terminalQueued && $0.drainingSinceMilliseconds == nil
        && now >= $0.deadlineMilliseconds
    }) {
      failConnection(
        failure(
          "daemon.client.reply_timeout",
          "a correlated Runtime reply exceeded its absolute deadline"
        )
      )
      return
    }
    if pendingReplies.values.contains(where: {
      $0.drainingSinceMilliseconds.map {
        elapsedMilliseconds(now: now, since: $0) >= limits.drainTTLMilliseconds
      } ?? false
    }) {
      failConnection(
        failure(
          "daemon.client.reply_drain_expired",
          "a dropped reply sequence did not reach terminal before TTL"
        )
      )
      return
    }
    if activeTransfers.values.contains(where: {
      elapsedMilliseconds(now: now, since: $0.startedMilliseconds)
        >= limits.transferTTLMilliseconds
    }) {
      failConnection(
        failure(
          "daemon.client.transfer_expired",
          "an active Runtime transfer exceeded its absolute TTL"
        )
      )
      return
    }
    purgeTombstones(now: now)
  }

  private func purgeTombstones(now: UInt64) {
    while let first = completedTransferOrder.first,
      elapsedMilliseconds(now: now, since: first.0) >= limits.transferTTLMilliseconds
    {
      completedTransferOrder.removeFirst()
      completedTransfers.removeValue(forKey: first.1)
    }
    while let first = terminalReplyOrder.first,
      elapsedMilliseconds(now: now, since: first.0) >= limits.transferTTLMilliseconds
    {
      terminalReplyOrder.removeFirst()
      terminalReplies.removeValue(forKey: first.1)
    }
  }

  private func elapsedMilliseconds(now: UInt64, since start: UInt64) -> UInt64 {
    now >= start ? now - start : 0
  }

  private func failConnection(_ failure: RuntimeEnvelopeClientFailure) {
    let canonical = faultLatch.claim(failure)
    guard firstFault == nil, lifecycle != .closed else { return }
    firstFault = canonical
    lifecycle = .faulted
    finishConnection(canonical, rememberAsFault: true)
  }

  private func finishConnection(
    _ failure: RuntimeEnvelopeClientFailure,
    rememberAsFault: Bool
  ) {
    if rememberAsFault, firstFault == nil { firstFault = failure }
    transport.close()
    ingressContinuation?.finish()
    ingressContinuation = nil
    housekeepingTask?.cancel()
    housekeepingTask = nil

    if rememberAsFault {
      var retained: [String: RuntimeEnvelopePendingReply] = [:]
      for (messageID, var pending) in pendingReplies {
        if pending.queue.isEmpty {
          pending.waiter?.continuation.resume(returning: .failure(failure))
        } else {
          let waiter = pending.waiter
          pending.waiter = nil
          retained[messageID] = pending
          waiter?.continuation.resume(returning: .success(()))
        }
      }
      pendingReplies = retained
      if let waiter = streamWaiter {
        streamWaiter = nil
        waiter.continuation.resume(
          returning: streamQueue.isEmpty ? .failure(failure) : .success(())
        )
      }
    } else {
      for (_, var pending) in pendingReplies {
        releaseReplyQueue(&pending)
        pending.waiter?.continuation.resume(returning: .failure(failure))
      }
      pendingReplies.removeAll(keepingCapacity: false)
      streamQueue.removeAll(keepingCapacity: false)
      queuedStreamBytes = 0
      streamWaiter?.continuation.resume(returning: .failure(failure))
      streamWaiter = nil
    }
    activeTransfers.removeAll(keepingCapacity: false)
    activeTransferParts = 0
    reassemblyBytes = 0
    completedTransfers.removeAll(keepingCapacity: false)
    completedTransferOrder.removeAll(keepingCapacity: false)
  }

  private func mapError(_ error: Error) -> RuntimeEnvelopeClientFailure {
    if let failure = error as? RuntimeEnvelopeClientFailure { return failure }
    if let error = error as? UnixSocketDaemonTransportError {
      return failure(error.code, error.description)
    }
    if let error = error as? LocalClientInstallationError {
      return failure(error.code, error.description)
    }
    return failure("daemon.client.connection_closed", String(describing: error))
  }

  private func failure(_ code: String, _ message: String) -> RuntimeEnvelopeClientFailure {
    RuntimeEnvelopeClientFailure(code: code, message: message)
  }

  private static let nilUUID = UUID(
    uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
  )
}

extension RuntimeReplyV2 {
  fileprivate var isSynchronizedTerminal: Bool {
    switch self {
    case .syncComplete, .failure:
      true
    default:
      false
    }
  }
}
