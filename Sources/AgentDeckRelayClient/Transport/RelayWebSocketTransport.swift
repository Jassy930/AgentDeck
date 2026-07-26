import Foundation
import os

public enum RelayTransportRoute: Equatable, Sendable {
  case principal
  case pairing

  fileprivate var path: String {
    switch self {
    case .principal: "/v2/connect"
    case .pairing: "/v2/pair"
    }
  }
}

public struct RelayTransportEndpoint: Equatable, Sendable {
  public let origin: URL
  public let route: RelayTransportRoute
  public let webSocketURL: URL
  public let host: String

  public init(origin: URL, route: RelayTransportRoute) throws {
    guard origin.baseURL == nil,
      var components = URLComponents(url: origin, resolvingAgainstBaseURL: false),
      components.scheme == "wss",
      let host = origin.host,
      !host.isEmpty,
      components.user == nil,
      components.password == nil,
      components.query == nil,
      components.fragment == nil,
      components.port.map({ (1...65_535).contains($0) }) ?? true,
      components.percentEncodedPath.isEmpty || components.percentEncodedPath == "/"
    else {
      throw RelayTransportError.invalidEndpoint
    }

    components.path = route.path
    guard let webSocketURL = components.url,
      webSocketURL.scheme == "wss",
      webSocketURL.host?.caseInsensitiveCompare(host) == .orderedSame
    else {
      throw RelayTransportError.invalidEndpoint
    }

    self.origin = origin
    self.route = route
    self.webSocketURL = webSocketURL
    self.host = host
  }
}

public struct RelayTransportConfiguration: Equatable, Sendable {
  public let endpoint: RelayTransportEndpoint
  public let tlsPolicy: RelayTLSPolicy

  public init(endpoint: RelayTransportEndpoint, tlsPolicy: RelayTLSPolicy) {
    self.endpoint = endpoint
    self.tlsPolicy = tlsPolicy
  }
}

public struct RelayTransportGeneration: RawRepresentable, Equatable, Hashable, Sendable {
  public let rawValue: UInt64

  public init(rawValue: UInt64) {
    self.rawValue = rawValue
  }
}

public struct ReceivedRelayFrame: Equatable, Sendable {
  public let generation: RelayTransportGeneration
  public let frame: RelayV2Frame
  public let canonicalBytes: Data

  public init(
    generation: RelayTransportGeneration,
    frame: RelayV2Frame,
    canonicalBytes: Data
  ) {
    self.generation = generation
    self.frame = frame
    self.canonicalBytes = canonicalBytes
  }
}

public enum RelayTransportError: Error, Equatable, Sendable {
  case invalidEndpoint
  case notConnected
  case incomingAlreadyClaimed
  case handshakeFrameReserved
  case staleGeneration
  case generationExhausted
  case connectionFailed
  case connectionClosed
  case connectionTimedOut
  case connectionCleanupStalled
  case peerClosed(code: UInt16)
  case canceled
  case textMessage
  case frameTooLarge
  case invalidFrame
  case incomingBackpressure
  case outgoingBackpressure
  case outcomeUnknown
  case serverRestarting(drainDeadlineMilliseconds: UInt64)
  case tls(RelayTLSError)

  public var code: String {
    switch self {
    case .invalidEndpoint: "remote.transport.endpoint_invalid"
    case .notConnected: "remote.transport.not_connected"
    case .incomingAlreadyClaimed: "remote.transport.incoming_already_claimed"
    case .handshakeFrameReserved: "remote.transport.handshake_frame_reserved"
    case .staleGeneration: "remote.transport.stale_generation"
    case .generationExhausted: "remote.transport.generation_exhausted"
    case .connectionFailed: "remote.transport.connection_failed"
    case .connectionClosed: "remote.transport.connection_closed"
    case .connectionTimedOut: "remote.transport.connection_timed_out"
    case .connectionCleanupStalled: "remote.transport.connection_cleanup_stalled"
    case .peerClosed: "remote.transport.peer_closed"
    case .canceled: "remote.transport.canceled"
    case .textMessage: "remote.transport.text_message"
    case .frameTooLarge: "remote.transport.frame_too_large"
    case .invalidFrame: "remote.transport.frame_invalid"
    case .incomingBackpressure: "remote.transport.incoming_backpressure"
    case .outgoingBackpressure: "remote.transport.outgoing_backpressure"
    case .outcomeUnknown: "remote.transport.outcome_unknown"
    case .serverRestarting: "remote.transport.server_restarting"
    case .tls(let error): error.code
    }
  }
}

enum RelayWebSocketMessage: Equatable, Sendable {
  case data(Data)
  case text(String)
  case close(code: UInt16)
}

protocol RelayWebSocketConnection: Sendable {
  func start() async throws
  func send(data: Data) async throws
  func receive() async throws -> RelayWebSocketMessage
  func close(code: URLSessionWebSocketTask.CloseCode, reason: Data?) async
  func forceClose() async
}

protocol RelayWebSocketConnectionFactory: Sendable {
  func makeConnection(
    endpoint: RelayTransportEndpoint,
    tlsPolicy: RelayTLSPolicy
  ) async throws -> any RelayWebSocketConnection
}

struct URLSessionRelayWebSocketConnectionFactory: RelayWebSocketConnectionFactory {
  func makeConnection(
    endpoint: RelayTransportEndpoint,
    tlsPolicy: RelayTLSPolicy
  ) async throws -> any RelayWebSocketConnection {
    URLSessionRelayWebSocketConnection(endpoint: endpoint, tlsPolicy: tlsPolicy)
  }
}

actor RelayWebSocketLifecycle {
  private enum State {
    case pending
    case open
    case failed(RelayTransportError)
  }

  private var state = State.pending
  private var waiter: CheckedContinuation<Void, any Error>?
  private var webSocketDidClose = false
  private var taskCompletionReadback: Bool?
  private var sessionInvalidationReadback: Bool?
  private var taskCompletionWaiters: [CheckedContinuation<Bool, Never>] = []
  private var sessionInvalidationWaiters: [CheckedContinuation<Bool, Never>] = []
  private var confirmedInvalidationWaiters: [CheckedContinuation<Void, Never>] = []

  func waitUntilOpen() async throws {
    switch state {
    case .open:
      return
    case .failed(let error):
      throw error
    case .pending:
      break
    }

    try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { continuation in
        waiter = continuation
      }
    } onCancel: {
      Task { await self.fail(.canceled) }
    }
  }

  func opened() {
    guard case .pending = state else { return }
    state = .open
    waiter?.resume()
    waiter = nil
  }

  func fail(_ error: RelayTransportError) {
    guard case .pending = state else { return }
    state = .failed(error)
    waiter?.resume(throwing: error)
    waiter = nil
  }

  func webSocketClosed() {
    webSocketDidClose = true
    fail(.connectionClosed)
  }

  func taskCompleted(openError: RelayTransportError?) {
    fail(openError ?? .connectionClosed)
    guard taskCompletionReadback != true else { return }
    taskCompletionReadback = true
    let waiters = taskCompletionWaiters
    taskCompletionWaiters.removeAll(keepingCapacity: false)
    for continuation in waiters {
      continuation.resume(returning: true)
    }
  }

  func sessionBecameInvalid() {
    guard sessionInvalidationReadback != true else { return }
    sessionInvalidationReadback = true
    let waiters = sessionInvalidationWaiters
    sessionInvalidationWaiters.removeAll(keepingCapacity: false)
    for continuation in waiters {
      continuation.resume(returning: true)
    }
    let confirmedWaiters = confirmedInvalidationWaiters
    confirmedInvalidationWaiters.removeAll(keepingCapacity: false)
    for continuation in confirmedWaiters {
      continuation.resume()
    }
  }

  func forceTerminated() {
    fail(.connectionClosed)
    resolveForcedReadback(
      value: &taskCompletionReadback,
      waiters: &taskCompletionWaiters
    )
    resolveForcedReadback(
      value: &sessionInvalidationReadback,
      waiters: &sessionInvalidationWaiters
    )
  }

  func waitUntilTaskCompleted() async -> Bool {
    if let taskCompletionReadback { return taskCompletionReadback }
    // transport 的 generation-scoped cleanup deadline 负责强制终止。这里故意不继承
    // caller cancellation；receive loop 在进入 finishGeneration 后会取消自身 task。
    return await withCheckedContinuation { continuation in
      if let taskCompletionReadback {
        continuation.resume(returning: taskCompletionReadback)
      } else {
        taskCompletionWaiters.append(continuation)
      }
    }
  }

  func waitUntilSessionInvalidated() async -> Bool {
    if let sessionInvalidationReadback { return sessionInvalidationReadback }
    return await withCheckedContinuation { continuation in
      if let sessionInvalidationReadback {
        continuation.resume(returning: sessionInvalidationReadback)
      } else {
        sessionInvalidationWaiters.append(continuation)
      }
    }
  }

  func waitUntilSessionInvalidationConfirmed() async {
    if sessionInvalidationReadback == true { return }
    await withCheckedContinuation { continuation in
      if sessionInvalidationReadback == true {
        continuation.resume()
      } else {
        confirmedInvalidationWaiters.append(continuation)
      }
    }
  }

  func debugReadback() -> (
    webSocketDidClose: Bool,
    taskCompleted: Bool?,
    sessionInvalidated: Bool?
  ) {
    (webSocketDidClose, taskCompletionReadback, sessionInvalidationReadback)
  }

  private func resolveForcedReadback(
    value: inout Bool?,
    waiters: inout [CheckedContinuation<Bool, Never>]
  ) {
    guard value == nil else { return }
    value = false
    let pending = waiters
    waiters.removeAll(keepingCapacity: false)
    for continuation in pending {
      continuation.resume(returning: false)
    }
  }
}

private actor URLSessionRelayWebSocketConnection: RelayWebSocketConnection {
  private let lifecycle: RelayWebSocketLifecycle
  private let delegate: PinnedURLSessionDelegate
  private let session: URLSession
  private let task: URLSessionWebSocketTask
  private var started = false
  private var closed = false
  private var sessionInvalidationRequested = false

  init(endpoint: RelayTransportEndpoint, tlsPolicy: RelayTLSPolicy) {
    let lifecycle = RelayWebSocketLifecycle()
    let tlsFailure = RelayTLSFailureLatch()
    self.lifecycle = lifecycle
    delegate = PinnedURLSessionDelegate(
      expectedHost: endpoint.host,
      policy: tlsPolicy,
      onOpen: {
        Task { await lifecycle.opened() }
      },
      onClose: { _ in
        Task { await lifecycle.webSocketClosed() }
      },
      onTLSFailure: { error in
        tlsFailure.record(error)
        Task { await lifecycle.fail(.tls(error)) }
      },
      onComplete: { error in
        let openError: RelayTransportError? =
          if error != nil {
            tlsFailure.load().map(RelayTransportError.tls)
              ?? .connectionFailed
          } else {
            nil
          }
        Task { await lifecycle.taskCompleted(openError: openError) }
      },
      onInvalidation: { _ in
        Task { await lifecycle.sessionBecameInvalid() }
      }
    )

    let configuration = URLSessionConfiguration.ephemeral
    configuration.httpShouldSetCookies = false
    configuration.httpCookieStorage = nil
    configuration.urlCache = nil
    configuration.urlCredentialStorage = nil
    configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
    session = URLSession(
      configuration: configuration,
      delegate: delegate,
      delegateQueue: nil
    )
    task = session.webSocketTask(with: endpoint.webSocketURL)
    // URLSession 在达到 maximumMessageSize 时可能先终止；+1 后由 canonical codec
    // 精确接受 4 MiB，并在应用层拒绝 4 MiB + 1。Foundation 自己产生的 1009
    // 会由 transport receive loop 映射回同一个 frameTooLarge typed error。
    task.maximumMessageSize = RelayWireCodecV2.maxFrameBytes + 1
  }

  func start() async throws {
    guard !closed else { throw RelayTransportError.connectionClosed }
    if !started {
      started = true
      task.resume()
    }
    try await lifecycle.waitUntilOpen()
  }

  func send(data: Data) async throws {
    guard started, !closed else { throw RelayTransportError.connectionClosed }
    try await task.send(.data(data))
  }

  func receive() async throws -> RelayWebSocketMessage {
    guard started, !closed else { throw RelayTransportError.connectionClosed }
    do {
      switch try await task.receive() {
      case .data(let data): return .data(data)
      case .string(let text): return .text(text)
      @unknown default: throw RelayTransportError.invalidFrame
      }
    } catch {
      let closeCode = task.closeCode
      if closeCode != .invalid {
        return .close(code: UInt16(clamping: closeCode.rawValue))
      }
      throw error
    }
  }

  func close(code: URLSessionWebSocketTask.CloseCode, reason: Data?) async {
    if !closed {
      closed = true
      task.cancel(with: code, reason: reason)
    }
    guard await lifecycle.waitUntilTaskCompleted() else { return }
    if !sessionInvalidationRequested {
      sessionInvalidationRequested = true
      session.finishTasksAndInvalidate()
    }
    guard await lifecycle.waitUntilSessionInvalidated() else { return }
  }

  func forceClose() async {
    closed = true
    await lifecycle.forceTerminated()
    if !sessionInvalidationRequested {
      sessionInvalidationRequested = true
      session.invalidateAndCancel()
    }
    await lifecycle.waitUntilSessionInvalidationConfirmed()
  }
}

struct RelayTransportLimits: Equatable, Sendable {
  static let production = Self(
    incomingFrames: RelayWebSocketTransport.maximumRegularIncomingFrames,
    incomingBytes: RelayWebSocketTransport.maximumRegularIncomingBytes,
    outgoingFrames: RelayWebSocketTransport.maximumApplicationWriterFrames,
    outgoingBytes: RelayWebSocketTransport.maximumApplicationWriterBytes,
    controlFrames: RelayWebSocketTransport.maximumControlWriterFrames,
    controlBytes: RelayWebSocketTransport.maximumControlWriterBytes,
    urgentIncomingFrames: RelayWebSocketTransport.maximumUrgentIncomingFrames,
    urgentIncomingBytes: RelayWebSocketTransport.maximumUrgentIncomingBytes
  )

  let incomingFrames: Int
  let incomingBytes: Int
  let outgoingFrames: Int
  let outgoingBytes: Int
  let controlFrames: Int
  let controlBytes: Int
  let urgentIncomingFrames: Int
  let urgentIncomingBytes: Int

  init(
    incomingFrames: Int,
    incomingBytes: Int,
    outgoingFrames: Int,
    outgoingBytes: Int,
    controlFrames: Int,
    controlBytes: Int,
    urgentIncomingFrames: Int,
    urgentIncomingBytes: Int
  ) {
    precondition(incomingFrames > 0)
    precondition(incomingBytes > 0)
    precondition(outgoingFrames > 0)
    precondition(outgoingBytes > 0)
    precondition(controlFrames > 0)
    precondition(controlBytes > 0)
    precondition(urgentIncomingFrames > 0)
    precondition(urgentIncomingBytes > 0)
    self.incomingFrames = incomingFrames
    self.incomingBytes = incomingBytes
    self.outgoingFrames = outgoingFrames
    self.outgoingBytes = outgoingBytes
    self.controlFrames = controlFrames
    self.controlBytes = controlBytes
    self.urgentIncomingFrames = urgentIncomingFrames
    self.urgentIncomingBytes = urgentIncomingBytes
  }
}

protocol RelayTransportSleeper: Sendable {
  func sleep(milliseconds: UInt64) async throws
}

struct ContinuousRelayTransportSleeper: RelayTransportSleeper {
  func sleep(milliseconds: UInt64) async throws {
    try await Task.sleep(for: .milliseconds(Int64(clamping: milliseconds)))
  }
}

struct RelayTransportDeadlines: Equatable, Sendable {
  static let production = Self(
    connectAttemptMilliseconds: 30_000,
    canceledAttemptCleanupMilliseconds: 5_000,
    outboundWriteMilliseconds: 10_000
  )

  let connectAttemptMilliseconds: UInt64
  let canceledAttemptCleanupMilliseconds: UInt64
  let outboundWriteMilliseconds: UInt64

  init(
    connectAttemptMilliseconds: UInt64,
    canceledAttemptCleanupMilliseconds: UInt64,
    outboundWriteMilliseconds: UInt64 = 10_000
  ) {
    precondition(connectAttemptMilliseconds > 0)
    precondition(canceledAttemptCleanupMilliseconds > 0)
    precondition(outboundWriteMilliseconds > 0)
    self.connectAttemptMilliseconds = connectAttemptMilliseconds
    self.canceledAttemptCleanupMilliseconds = canceledAttemptCleanupMilliseconds
    self.outboundWriteMilliseconds = outboundWriteMilliseconds
  }
}

private actor RelayIncomingFrameQueue {
  private struct Item {
    let value: ReceivedRelayFrame
    let chargedBytes: Int
  }

  private struct Waiter {
    let id: UInt64
    let continuation: CheckedContinuation<ReceivedRelayFrame?, any Error>
  }

  private let maximumFrames: Int
  private let maximumBytes: Int
  private let maximumUrgentFrames: Int
  private let maximumUrgentBytes: Int
  private var items: [Item] = []
  private var urgentItems: [Item] = []
  private var chargedBytes = 0
  private var urgentChargedBytes = 0
  private var waiter: Waiter?
  private var nextWaiterID: UInt64 = 1
  private var terminalError: RelayTransportError?
  private var finishedNormally = false

  init(
    maximumFrames: Int,
    maximumBytes: Int,
    maximumUrgentFrames: Int,
    maximumUrgentBytes: Int
  ) {
    self.maximumFrames = maximumFrames
    self.maximumBytes = maximumBytes
    self.maximumUrgentFrames = maximumUrgentFrames
    self.maximumUrgentBytes = maximumUrgentBytes
  }

  func enqueue(
    _ value: ReceivedRelayFrame,
    chargedBytes: Int,
    urgent: Bool
  ) -> Bool {
    guard terminalError == nil, !finishedNormally else { return false }
    if let waiter {
      self.waiter = nil
      waiter.continuation.resume(returning: value)
      return true
    }

    if urgent {
      let (projectedBytes, overflow) = urgentChargedBytes.addingReportingOverflow(
        chargedBytes
      )
      guard !overflow,
        urgentItems.count < maximumUrgentFrames,
        projectedBytes <= maximumUrgentBytes
      else {
        return false
      }
      urgentItems.append(Item(value: value, chargedBytes: chargedBytes))
      urgentChargedBytes = projectedBytes
    } else {
      let (projectedBytes, overflow) = self.chargedBytes.addingReportingOverflow(
        chargedBytes
      )
      guard !overflow,
        items.count < maximumFrames,
        projectedBytes <= maximumBytes
      else {
        return false
      }
      items.append(Item(value: value, chargedBytes: chargedBytes))
      self.chargedBytes = projectedBytes
    }
    return true
  }

  func next() async throws -> ReceivedRelayFrame? {
    if !urgentItems.isEmpty {
      let item = urgentItems.removeFirst()
      urgentChargedBytes -= item.chargedBytes
      return item.value
    }
    if !items.isEmpty {
      let item = items.removeFirst()
      chargedBytes -= item.chargedBytes
      return item.value
    }
    if let terminalError { throw terminalError }
    if finishedNormally { return nil }
    guard waiter == nil else {
      throw RelayTransportError.incomingAlreadyClaimed
    }

    let id = nextWaiterID
    nextWaiterID = nextWaiterID == UInt64.max ? 1 : nextWaiterID + 1
    return try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { continuation in
        waiter = Waiter(id: id, continuation: continuation)
      }
    } onCancel: {
      Task { await self.cancelWaiter(id: id) }
    }
  }

  func finish(error: RelayTransportError?, discardBuffered: Bool) {
    guard terminalError == nil, !finishedNormally else { return }
    if discardBuffered {
      items.removeAll(keepingCapacity: false)
      urgentItems.removeAll(keepingCapacity: false)
      chargedBytes = 0
      urgentChargedBytes = 0
    }
    terminalError = error
    finishedNormally = error == nil
    if items.isEmpty, urgentItems.isEmpty, let waiter {
      self.waiter = nil
      if let error {
        waiter.continuation.resume(throwing: error)
      } else {
        waiter.continuation.resume(returning: nil)
      }
    }
  }

  func discardRegular() {
    items.removeAll(keepingCapacity: false)
    chargedBytes = 0
  }

  func debugUsage() -> (
    regularFrames: Int,
    regularBytes: Int,
    urgentFrames: Int,
    urgentBytes: Int
  ) {
    (items.count, chargedBytes, urgentItems.count, urgentChargedBytes)
  }

  private func cancelWaiter(id: UInt64) {
    guard waiter?.id == id, let waiter else { return }
    self.waiter = nil
    waiter.continuation.resume(throwing: RelayTransportError.canceled)
  }
}

private final class RelayConnectCancellationLatch: Sendable {
  private enum State: Equatable, Sendable {
    case pendingRegistration
    case registered
    case canceled
    case completed
  }

  private let state = OSAllocatedUnfairLock(initialState: State.pendingRegistration)

  func register() -> Bool {
    state.withLock { state in
      guard state == .pendingRegistration else { return false }
      state = .registered
      return true
    }
  }

  func cancel() {
    state.withLock { state in
      switch state {
      case .pendingRegistration, .registered:
        state = .canceled
      case .canceled, .completed:
        break
      }
    }
  }

  func claimCompletion() -> Bool {
    state.withLock { state in
      guard state == .registered else { return false }
      state = .completed
      return true
    }
  }
}

private final class RelayConnectAttemptGate: Sendable {
  private struct State: Sendable {
    var waiterIDs: Set<UInt64> = []
    var attemptCanceled = false
  }

  private let state = OSAllocatedUnfairLock(initialState: State())

  func register(waiterID: UInt64) -> Bool {
    state.withLock { state in
      guard !state.attemptCanceled else { return false }
      state.waiterIDs.insert(waiterID)
      return true
    }
  }

  func cancelWaiter(id: UInt64) {
    _ = state.withLock { state in
      state.waiterIDs.remove(id)
    }
  }

  func cancelAttempt() {
    state.withLock { state in
      state.attemptCanceled = true
    }
  }

  func checkCancellation() throws {
    let canceled = state.withLock { state in
      if state.attemptCanceled || state.waiterIDs.isEmpty {
        state.attemptCanceled = true
        return true
      }
      return false
    }
    if canceled { throw RelayTransportError.canceled }
  }
}

public actor RelayWebSocketTransport {
  public static let maximumFrameBytes = RelayWireCodecV2.maxFrameBytes
  public static let maximumRegularIncomingFrames = 512
  public static let maximumRegularIncomingBytes = 16 * 1_024 * 1_024
  public static let maximumUrgentIncomingFrames = 4
  public static let maximumUrgentIncomingBytes = 8 * 1_024 * 1_024
  public static let maximumAggregateIncomingFrames = 516
  public static let maximumAggregateIncomingBytes = 24 * 1_024 * 1_024
  public static let maximumApplicationWriterFrames = 512
  public static let maximumApplicationWriterBytes = 16 * 1_024 * 1_024
  public static let maximumControlWriterFrames = 8
  public static let maximumControlWriterBytes = 1 * 1_024 * 1_024
  public static let maximumAggregateWriterFrames = 520
  public static let maximumAggregateWriterBytes = 17 * 1_024 * 1_024

  private enum Phase: Equatable {
    case idle
    case connecting(RelayTransportGeneration)
    case open(RelayTransportGeneration)
    case draining(RelayTransportGeneration, deadlineMilliseconds: UInt64)
    case closing(RelayTransportGeneration)
    case failed(RelayTransportGeneration, RelayTransportError)
  }

  private enum OutboundKind: Equatable {
    case application
    case control
  }

  private struct OutboundItem {
    let id: UInt64
    let kind: OutboundKind
    let data: Data
    let continuation: CheckedContinuation<Void, any Error>?
  }

  private struct ConnectWaiter {
    let cancellation: RelayConnectCancellationLatch
    let continuation: CheckedContinuation<RelayTransportGeneration, any Error>
  }

  private let configuration: RelayTransportConfiguration
  private let factory: any RelayWebSocketConnectionFactory
  private let limits: RelayTransportLimits
  private let sleeper: any RelayTransportSleeper
  private let deadlines: RelayTransportDeadlines
  private var phase = Phase.idle
  private var lastGeneration: UInt64 = 0
  private var connectTask: Task<any RelayWebSocketConnection, any Error>?
  private var connectWaiters: [UInt64: ConnectWaiter] = [:]
  private var nextConnectWaiterID: UInt64 = 1
  private var connectAttemptGate: RelayConnectAttemptGate?
  private var connectDeadlineTask: Task<Void, Never>?
  private var connectCleanupDeadlineTask: Task<Void, Never>?
  private var connection: (any RelayWebSocketConnection)?
  private var closingConnection: (any RelayWebSocketConnection)?
  private var incomingQueue: RelayIncomingFrameQueue?
  private var terminalIncoming:
    (generation: RelayTransportGeneration, queue: RelayIncomingFrameQueue)?
  private var incomingClaimed = false
  private var closeWaiters: [UInt64: CheckedContinuation<Void, any Error>] = [:]
  private var nextCloseWaiterID: UInt64 = 1
  private var receiveTask: Task<Void, Never>?
  private var writerTask: Task<Void, Never>?
  private var writeDeadlineTask: Task<Void, Never>?
  private var normalQueue: [OutboundItem] = []
  private var controlQueue: [OutboundItem] = []
  private var inFlight: OutboundItem?
  private var normalFrames = 0
  private var normalBytes = 0
  private var controlFrames = 0
  private var controlBytes = 0
  private var nextOutboundID: UInt64 = 1

  public init(configuration: RelayTransportConfiguration) {
    self.configuration = configuration
    factory = URLSessionRelayWebSocketConnectionFactory()
    limits = .production
    sleeper = ContinuousRelayTransportSleeper()
    deadlines = .production
  }

  init(
    configuration: RelayTransportConfiguration,
    factory: any RelayWebSocketConnectionFactory,
    limits: RelayTransportLimits = .production,
    sleeper: any RelayTransportSleeper = ContinuousRelayTransportSleeper(),
    deadlines: RelayTransportDeadlines = .production
  ) {
    self.configuration = configuration
    self.factory = factory
    self.limits = limits
    self.sleeper = sleeper
    self.deadlines = deadlines
  }

  @discardableResult
  public func connect() async throws -> RelayTransportGeneration {
    try Task.checkCancellation()
    switch phase {
    case .open(let generation):
      return generation
    case .draining(_, let deadline):
      throw RelayTransportError.serverRestarting(
        drainDeadlineMilliseconds: deadline
      )
    case .connecting(let generation):
      guard connectAttemptGate != nil else { throw RelayTransportError.connectionFailed }
      return try await waitForConnectAttempt(generation: generation)
    case .closing:
      try await waitForCloseCompletion()
      try Task.checkCancellation()
      return try await connect()
    case .failed(_, let error):
      throw error
    case .idle:
      break
    }

    let (nextRaw, overflow) = lastGeneration.addingReportingOverflow(1)
    guard !overflow else { throw RelayTransportError.generationExhausted }
    let generation = RelayTransportGeneration(rawValue: nextRaw)
    // attempt 开始即永久消费 generation；取消/失败也不得复用，否则迟到 callback
    // 可能在下一次连接上获得相同 owner token。
    lastGeneration = nextRaw
    phase = .connecting(generation)
    connectAttemptGate = RelayConnectAttemptGate()
    return try await waitForConnectAttempt(generation: generation)
  }

  private func startConnectWorker(
    generation: RelayTransportGeneration,
    gate: RelayConnectAttemptGate
  ) {
    guard phase == .connecting(generation),
      connectTask == nil,
      connectAttemptGate === gate
    else {
      return
    }
    let configuration = configuration
    let factory = factory
    let task = Task<any RelayWebSocketConnection, any Error> {
      try gate.checkCancellation()
      let connection = try await factory.makeConnection(
        endpoint: configuration.endpoint,
        tlsPolicy: configuration.tlsPolicy
      )
      do {
        try gate.checkCancellation()
        try Task.checkCancellation()
        try await connection.start()
        try gate.checkCancellation()
        try Task.checkCancellation()
        let hello = try RelayWireCodecV2.encode(.hello())
        try await connection.send(data: hello)
        try gate.checkCancellation()
        try Task.checkCancellation()
        return connection
      } catch {
        await connection.forceClose()
        throw mapConnectionError(error)
      }
    }
    connectTask = task
    startConnectDeadline(generation: generation)

    Task {
      let result = await task.result
      await resolveConnectAttempt(generation: generation, result: result)
    }
  }

  private func waitForConnectAttempt(
    generation: RelayTransportGeneration
  ) async throws -> RelayTransportGeneration {
    let waiterID = allocateConnectWaiterID()
    let cancellation = RelayConnectCancellationLatch()
    guard let gate = connectAttemptGate, phase == .connecting(generation) else {
      throw RelayTransportError.canceled
    }
    guard gate.register(waiterID: waiterID) else {
      if connectTask == nil {
        phase = .idle
        connectAttemptGate = nil
      } else {
        beginCancelConnect(generation: generation, waiterError: .canceled)
        try await waitForCloseCompletion()
      }
      try Task.checkCancellation()
      return try await connect()
    }
    return try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { continuation in
        switch phase {
        case .connecting(let current) where current == generation:
          if Task.isCancelled {
            cancellation.cancel()
            gate.cancelWaiter(id: waiterID)
          }
          if cancellation.register() {
            connectWaiters[waiterID] = ConnectWaiter(
              cancellation: cancellation,
              continuation: continuation
            )
            startConnectWorker(generation: generation, gate: gate)
          } else {
            continuation.resume(throwing: RelayTransportError.canceled)
            if connectWaiters.isEmpty {
              if connectTask == nil {
                phase = .idle
                connectAttemptGate = nil
              } else {
                beginCancelConnect(
                  generation: generation,
                  waiterError: .canceled
                )
              }
            }
          }
        case .open(let current) where current == generation:
          if Task.isCancelled {
            continuation.resume(throwing: RelayTransportError.canceled)
          } else {
            continuation.resume(returning: generation)
          }
        case .failed(_, let error):
          continuation.resume(throwing: error)
        default:
          continuation.resume(throwing: RelayTransportError.canceled)
        }
      }
    } onCancel: {
      cancellation.cancel()
      gate.cancelWaiter(id: waiterID)
      Task {
        await self.cancelConnectWaiter(
          id: waiterID,
          generation: generation,
          gate: gate
        )
      }
    }
  }

  private func resolveConnectAttempt(
    generation: RelayTransportGeneration,
    result: Result<any RelayWebSocketConnection, any Error>
  ) async {
    connectDeadlineTask?.cancel()
    connectDeadlineTask = nil

    switch phase {
    case .connecting(let current) where current == generation:
      switch result {
      case .success(let resolvedConnection):
        let liveWaiters = claimConnectWaiters()
        guard !liveWaiters.isEmpty else {
          phase = .closing(generation)
          closingConnection = resolvedConnection
          startConnectCleanupDeadline(generation: generation)
          await resolvedConnection.close(
            code: .goingAway,
            reason: Data(RelayTransportError.canceled.code.utf8)
          )
          connectTask = nil
          completeClosing(generation: generation)
          return
        }
        do {
          let installed = try installConnected(
            resolvedConnection,
            generation: generation
          )
          resumeClaimedConnectWaiters(
            liveWaiters,
            with: .success(installed)
          )
        } catch {
          phase = .closing(generation)
          closingConnection = resolvedConnection
          startConnectCleanupDeadline(generation: generation)
          resumeClaimedConnectWaiters(
            liveWaiters,
            with: .failure(mapConnectionError(error))
          )
          await resolvedConnection.close(
            code: .goingAway,
            reason: Data(RelayTransportError.connectionFailed.code.utf8)
          )
          connectTask = nil
          completeClosing(generation: generation)
        }

      case .failure(let error):
        connectTask = nil
        connectAttemptGate = nil
        phase = .idle
        resumeConnectWaiters(with: .failure(mapConnectionError(error)))
      }

    case .closing(let current) where current == generation:
      if case .success(let resolvedConnection) = result {
        closingConnection = resolvedConnection
        await resolvedConnection.close(
          code: .goingAway,
          reason: Data(RelayTransportError.canceled.code.utf8)
        )
      }
      connectTask = nil
      connectAttemptGate = nil
      completeClosing(generation: generation)

    case .failed(let current, _) where current == generation:
      if case .success(let resolvedConnection) = result {
        await resolvedConnection.forceClose()
      }
      connectTask = nil
      connectAttemptGate = nil

    case .idle, .connecting, .open, .draining, .closing, .failed:
      if case .success(let resolvedConnection) = result {
        await resolvedConnection.forceClose()
      }
    }
  }

  private func startConnectDeadline(generation: RelayTransportGeneration) {
    connectDeadlineTask?.cancel()
    let sleeper = sleeper
    let timeout = deadlines.connectAttemptMilliseconds
    connectDeadlineTask = Task {
      do {
        try await sleeper.sleep(milliseconds: timeout)
      } catch {
        return
      }
      self.connectAttemptTimedOut(generation: generation)
    }
  }

  private func connectAttemptTimedOut(generation: RelayTransportGeneration) {
    guard phase == .connecting(generation) else { return }
    beginCancelConnect(
      generation: generation,
      waiterError: .connectionTimedOut
    )
  }

  private func startConnectCleanupDeadline(
    generation: RelayTransportGeneration
  ) {
    connectCleanupDeadlineTask?.cancel()
    let sleeper = sleeper
    let timeout = deadlines.canceledAttemptCleanupMilliseconds
    connectCleanupDeadlineTask = Task {
      do {
        try await sleeper.sleep(milliseconds: timeout)
      } catch {
        return
      }
      await self.connectCleanupTimedOut(generation: generation)
    }
  }

  private func connectCleanupTimedOut(generation: RelayTransportGeneration) async {
    guard phase == .closing(generation) else { return }
    connectTask?.cancel()
    let stalledConnection = closingConnection
    closingConnection = nil
    connectCleanupDeadlineTask = nil
    connectAttemptGate = nil
    phase = .failed(generation, .connectionCleanupStalled)
    resumeCloseWaiters(with: .failure(.connectionCleanupStalled))
    await stalledConnection?.forceClose()
  }

  private func cancelConnectWaiter(
    id: UInt64,
    generation: RelayTransportGeneration,
    gate: RelayConnectAttemptGate
  ) {
    guard phase == .connecting(generation),
      connectAttemptGate === gate,
      let waiter = connectWaiters.removeValue(forKey: id)
    else {
      return
    }
    gate.cancelWaiter(id: id)
    waiter.continuation.resume(throwing: RelayTransportError.canceled)
    if connectWaiters.isEmpty {
      beginCancelConnect(generation: generation, waiterError: .canceled)
    }
  }

  private func beginCancelConnect(
    generation: RelayTransportGeneration,
    waiterError: RelayTransportError
  ) {
    guard phase == .connecting(generation), let connectTask else { return }
    phase = .closing(generation)
    connectAttemptGate?.cancelAttempt()
    connectDeadlineTask?.cancel()
    connectDeadlineTask = nil
    connectTask.cancel()
    resumeConnectWaiters(with: .failure(waiterError))
    startConnectCleanupDeadline(generation: generation)
  }

  private func resumeConnectWaiters(
    with result: Result<RelayTransportGeneration, RelayTransportError>
  ) {
    let waiters = claimConnectWaiters()
    resumeClaimedConnectWaiters(waiters, with: result)
  }

  private func claimConnectWaiters() -> [CheckedContinuation<RelayTransportGeneration, any Error>] {
    let waiters = Array(connectWaiters.values)
    connectWaiters.removeAll(keepingCapacity: false)
    var claimed: [CheckedContinuation<RelayTransportGeneration, any Error>] = []
    claimed.reserveCapacity(waiters.count)
    for waiter in waiters {
      if waiter.cancellation.claimCompletion() {
        claimed.append(waiter.continuation)
      } else {
        waiter.continuation.resume(throwing: RelayTransportError.canceled)
      }
    }
    return claimed
  }

  private func resumeClaimedConnectWaiters(
    _ waiters: [CheckedContinuation<RelayTransportGeneration, any Error>],
    with result: Result<RelayTransportGeneration, RelayTransportError>
  ) {
    for continuation in waiters {
      switch result {
      case .success(let generation):
        continuation.resume(returning: generation)
      case .failure(let error):
        continuation.resume(throwing: error)
      }
    }
  }

  private func allocateConnectWaiterID() -> UInt64 {
    let id = nextConnectWaiterID
    nextConnectWaiterID = nextConnectWaiterID == UInt64.max ? 1 : nextConnectWaiterID + 1
    return id
  }

  public func incomingFrames(on expectedGeneration: RelayTransportGeneration)
    -> AsyncThrowingStream<ReceivedRelayFrame, any Error>
  {
    let generation: RelayTransportGeneration
    let queue: RelayIncomingFrameQueue
    if case .open(let current) = phase,
      current == expectedGeneration,
      let currentQueue = incomingQueue,
      !incomingClaimed
    {
      generation = current
      queue = currentQueue
      incomingClaimed = true
    } else if let terminalIncoming,
      terminalIncoming.generation == expectedGeneration
    {
      generation = terminalIncoming.generation
      queue = terminalIncoming.queue
      self.terminalIncoming = nil
    } else {
      if case .open(let current) = phase, current != expectedGeneration {
        return Self.failedStream(.staleGeneration)
      }
      if let terminalIncoming,
        terminalIncoming.generation != expectedGeneration
      {
        return Self.failedStream(.staleGeneration)
      }
      return Self.failedStream(
        incomingClaimed ? .incomingAlreadyClaimed : .notConnected
      )
    }
    return AsyncThrowingStream { [weak self] in
      do {
        return try await queue.next()
      } catch {
        if error as? RelayTransportError == .canceled {
          await self?.incomingConsumerCanceled(generation: generation)
        }
        throw error
      }
    }
  }

  public func send(
    _ frame: RelayV2OutboundFrame,
    on generation: RelayTransportGeneration
  ) async throws {
    let encoded: Data
    do {
      encoded = try RelayWireCodecV2.encode(frame)
    } catch RelayWireCodecError.oversize {
      throw RelayTransportError.frameTooLarge
    } catch {
      throw RelayTransportError.invalidFrame
    }
    do {
      let decoded = try RelayWireCodecV2.decode(encoded)
      if case .hello = decoded.body {
        throw RelayTransportError.handshakeFrameReserved
      }
    } catch let error as RelayTransportError {
      throw error
    } catch {
      throw RelayTransportError.invalidFrame
    }

    guard case .open(let currentGeneration) = phase,
      currentGeneration == generation
    else {
      if case .draining(let currentGeneration, let deadline) = phase,
        currentGeneration == generation
      {
        throw RelayTransportError.serverRestarting(
          drainDeadlineMilliseconds: deadline
        )
      }
      if case .idle = phase { throw RelayTransportError.notConnected }
      throw RelayTransportError.staleGeneration
    }

    let id = allocateOutboundID()
    do {
      try await withTaskCancellationHandler {
        try await withCheckedThrowingContinuation { continuation in
          do {
            try enqueue(
              OutboundItem(
                id: id,
                kind: .application,
                data: encoded,
                continuation: continuation
              ),
              generation: generation
            )
          } catch {
            continuation.resume(throwing: error)
          }
        }
      } onCancel: {
        Task { await self.cancelOutbound(id: id, generation: generation) }
      }
    } catch let error as RelayTransportError {
      if error == .outgoingBackpressure {
        await finishGeneration(
          generation,
          error: error,
          closeCode: .policyViolation,
          discardIncoming: true
        )
      }
      throw error
    }
  }

  /// 显式关闭 transport 当前拥有的任何 generation；只供 owner/admin teardown。
  /// 普通 connection 状态机必须使用 generation-scoped `close(generation:)`。
  public func shutdown() async {
    switch phase {
    case .idle:
      return
    case .connecting(let generation):
      beginCancelConnect(generation: generation, waiterError: .canceled)
      _ = try? await waitForCloseCompletion()
    case .open(let generation), .draining(let generation, _):
      await finishGeneration(
        generation,
        error: nil,
        closeCode: .normalClosure,
        discardIncoming: true
      )
    case .closing:
      _ = try? await waitForCloseCompletion()
    case .failed:
      return
    }
  }

  public func close(generation: RelayTransportGeneration) async throws {
    switch phase {
    case .open(let current) where current == generation:
      await finishGeneration(
        generation,
        error: nil,
        closeCode: .normalClosure,
        discardIncoming: true
      )
      try throwIfCleanupFailed(generation: generation)
    case .draining(let current, _) where current == generation:
      await finishGeneration(
        generation,
        error: nil,
        closeCode: .normalClosure,
        discardIncoming: true
      )
      try throwIfCleanupFailed(generation: generation)
    case .closing(let current) where current == generation:
      try await waitForCloseCompletion()
    case .failed(let current, let error) where current == generation:
      throw error
    case .idle:
      throw RelayTransportError.notConnected
    case .connecting, .open, .draining, .closing, .failed:
      throw RelayTransportError.staleGeneration
    }
  }

  private func installConnected(
    _ newConnection: any RelayWebSocketConnection,
    generation: RelayTransportGeneration
  ) throws -> RelayTransportGeneration {
    if case .open(let current) = phase, current == generation {
      return current
    }
    guard phase == .connecting(generation) else {
      Task {
        await newConnection.forceClose()
      }
      throw RelayTransportError.canceled
    }

    phase = .open(generation)
    connectTask = nil
    connectAttemptGate = nil
    connection = newConnection
    terminalIncoming = nil
    let queue = RelayIncomingFrameQueue(
      maximumFrames: limits.incomingFrames,
      maximumBytes: limits.incomingBytes,
      maximumUrgentFrames: limits.urgentIncomingFrames,
      maximumUrgentBytes: limits.urgentIncomingBytes
    )
    incomingQueue = queue
    incomingClaimed = false
    receiveTask = Task { [weak self] in
      await self?.receiveLoop(
        generation: generation,
        connection: newConnection,
        queue: queue
      )
    }
    return generation
  }

  private func receiveLoop(
    generation: RelayTransportGeneration,
    connection: any RelayWebSocketConnection,
    queue: RelayIncomingFrameQueue
  ) async {
    while !Task.isCancelled {
      do {
        let message = try await connection.receive()
        switch message {
        case .close(let code):
          let terminal: RelayTransportError =
            code == UInt16(clamping: URLSessionWebSocketTask.CloseCode.messageTooBig.rawValue)
            ? .frameTooLarge
            : .peerClosed(code: code)
          await finishGeneration(
            generation,
            error: terminal,
            closeCode: .normalClosure,
            discardIncoming: false
          )
          return

        case .text:
          await finishGeneration(
            generation,
            error: .textMessage,
            closeCode: .protocolError,
            discardIncoming: true
          )
          return

        case .data(let data):
          guard data.count <= Self.maximumFrameBytes else {
            await finishGeneration(
              generation,
              error: .frameTooLarge,
              closeCode: .messageTooBig,
              discardIncoming: true
            )
            return
          }
          let frame: RelayV2Frame
          do {
            frame = try RelayWireCodecV2.decode(data)
          } catch RelayWireCodecError.oversize {
            await finishGeneration(
              generation,
              error: .frameTooLarge,
              closeCode: .messageTooBig,
              discardIncoming: true
            )
            return
          } catch {
            await finishGeneration(
              generation,
              error: .invalidFrame,
              closeCode: .protocolError,
              discardIncoming: true
            )
            return
          }

          if case .ping(let nonce) = frame.body {
            do {
              try enqueueControl(.control(.pong(nonce: nonce)), generation: generation)
            } catch {
              await finishGeneration(
                generation,
                error: .outgoingBackpressure,
                closeCode: .policyViolation,
                discardIncoming: true
              )
              return
            }
            continue
          }
          if case .serverRestarting = frame.body {
            await queue.discardRegular()
          }

          let received = ReceivedRelayFrame(
            generation: generation,
            frame: frame,
            canonicalBytes: data
          )
          let (chargedBytes, chargeOverflow) = data.count.multipliedReportingOverflow(by: 2)
          guard !chargeOverflow,
            await queue.enqueue(
              received,
              chargedBytes: chargedBytes,
              urgent: Self.isUrgent(frame.body)
            )
          else {
            await finishGeneration(
              generation,
              error: .incomingBackpressure,
              closeCode: .policyViolation,
              discardIncoming: true
            )
            return
          }

          switch frame.body {
          case .serverRestarting(let deadline):
            beginDraining(generation: generation, deadlineMilliseconds: deadline)
            await finishGeneration(
              generation,
              error: .serverRestarting(drainDeadlineMilliseconds: deadline),
              closeCode: .goingAway,
              discardIncoming: false
            )
            return
          default:
            break
          }
        }
      } catch {
        guard !Task.isCancelled else { return }
        let terminal: RelayTransportError
        if case .draining(_, let deadline) = phase {
          terminal = .serverRestarting(drainDeadlineMilliseconds: deadline)
        } else {
          terminal = .connectionClosed
        }
        await finishGeneration(
          generation,
          error: terminal,
          closeCode: .goingAway,
          discardIncoming: false
        )
        return
      }
    }
  }

  private static func isUrgent(_ body: RelayV2FrameBody) -> Bool {
    switch body {
    case .serverRestarting, .revocationCommitted, .retirementCommitted, .pairRouteClosed:
      true
    default:
      false
    }
  }

  private func enqueueControl(
    _ frame: RelayV2OutboundFrame,
    generation: RelayTransportGeneration
  ) throws {
    let encoded: Data
    do {
      encoded = try RelayWireCodecV2.encode(frame)
    } catch {
      throw RelayTransportError.invalidFrame
    }
    try enqueue(
      OutboundItem(
        id: allocateOutboundID(),
        kind: .control,
        data: encoded,
        continuation: nil
      ),
      generation: generation
    )
  }

  private func enqueue(
    _ item: OutboundItem,
    generation: RelayTransportGeneration
  ) throws {
    guard
      phase == .open(generation)
        || {
          if case .draining(let current, _) = phase { return current == generation }
          return false
        }()
    else {
      throw RelayTransportError.notConnected
    }

    switch item.kind {
    case .application:
      let (projectedBytes, overflow) = normalBytes.addingReportingOverflow(item.data.count)
      guard !overflow,
        normalFrames < limits.outgoingFrames,
        projectedBytes <= limits.outgoingBytes
      else {
        throw RelayTransportError.outgoingBackpressure
      }
      normalFrames += 1
      normalBytes = projectedBytes
      normalQueue.append(item)

    case .control:
      let (projectedBytes, overflow) = controlBytes.addingReportingOverflow(item.data.count)
      guard !overflow,
        controlFrames < limits.controlFrames,
        projectedBytes <= limits.controlBytes
      else {
        throw RelayTransportError.outgoingBackpressure
      }
      controlFrames += 1
      controlBytes = projectedBytes
      controlQueue.append(item)
    }
    startWriterIfNeeded(generation: generation)
  }

  private func startWriterIfNeeded(generation: RelayTransportGeneration) {
    guard writerTask == nil else { return }
    writerTask = Task { [weak self] in
      await self?.writerLoop(generation: generation)
    }
  }

  private func writerLoop(generation: RelayTransportGeneration) async {
    while !Task.isCancelled {
      guard inFlight == nil,
        let connection,
        let item = takeNextOutbound()
      else {
        writerTask = nil
        return
      }
      inFlight = item
      startWriteDeadline(generation: generation, outboundID: item.id)
      do {
        try await connection.send(data: item.data)
        completeOutbound(id: item.id, result: .success(()))
      } catch {
        completeOutbound(id: item.id, result: .failure(.outcomeUnknown))
        await finishGeneration(
          generation,
          error: .outcomeUnknown,
          closeCode: .goingAway,
          discardIncoming: false
        )
        return
      }
    }
  }

  private func takeNextOutbound() -> OutboundItem? {
    if !controlQueue.isEmpty { return controlQueue.removeFirst() }
    if !normalQueue.isEmpty { return normalQueue.removeFirst() }
    return nil
  }

  private func completeOutbound(
    id: UInt64,
    result: Result<Void, RelayTransportError>
  ) {
    guard let item = inFlight, item.id == id else { return }
    writeDeadlineTask?.cancel()
    writeDeadlineTask = nil
    inFlight = nil
    release(item)
    switch result {
    case .success:
      item.continuation?.resume()
    case .failure(let error):
      item.continuation?.resume(throwing: error)
    }
  }

  private func startWriteDeadline(
    generation: RelayTransportGeneration,
    outboundID: UInt64
  ) {
    writeDeadlineTask?.cancel()
    let sleeper = sleeper
    let timeout = deadlines.outboundWriteMilliseconds
    writeDeadlineTask = Task {
      do {
        try await sleeper.sleep(milliseconds: timeout)
      } catch {
        return
      }
      await self.outboundWriteTimedOut(
        generation: generation,
        outboundID: outboundID
      )
    }
  }

  private func outboundWriteTimedOut(
    generation: RelayTransportGeneration,
    outboundID: UInt64
  ) async {
    guard inFlight?.id == outboundID else { return }
    switch phase {
    case .open(let current), .draining(let current, _):
      guard current == generation else { return }
    case .idle, .connecting, .closing, .failed:
      return
    }
    completeOutbound(id: outboundID, result: .failure(.outcomeUnknown))
    await finishGeneration(
      generation,
      error: .outcomeUnknown,
      closeCode: .goingAway,
      discardIncoming: false
    )
  }

  private func release(_ item: OutboundItem) {
    switch item.kind {
    case .application:
      normalFrames = max(0, normalFrames - 1)
      normalBytes = max(0, normalBytes - item.data.count)
    case .control:
      controlFrames = max(0, controlFrames - 1)
      controlBytes = max(0, controlBytes - item.data.count)
    }
  }

  private func beginDraining(
    generation: RelayTransportGeneration,
    deadlineMilliseconds: UInt64
  ) {
    guard phase == .open(generation) else { return }
    phase = .draining(generation, deadlineMilliseconds: deadlineMilliseconds)

    let queuedApplication = normalQueue
    normalQueue.removeAll(keepingCapacity: false)
    let restartError = RelayTransportError.serverRestarting(
      drainDeadlineMilliseconds: deadlineMilliseconds
    )
    for item in queuedApplication {
      release(item)
      item.continuation?.resume(throwing: restartError)
    }

    if let current = inFlight,
      current.kind == .application,
      current.continuation != nil
    {
      current.continuation?.resume(throwing: RelayTransportError.outcomeUnknown)
      inFlight = OutboundItem(
        id: current.id,
        kind: current.kind,
        data: current.data,
        continuation: nil
      )
    }
  }

  private func cancelOutbound(id: UInt64, generation: RelayTransportGeneration) async {
    if let index = normalQueue.firstIndex(where: { $0.id == id }) {
      let item = normalQueue.remove(at: index)
      release(item)
      item.continuation?.resume(throwing: RelayTransportError.canceled)
      return
    }
    guard inFlight?.id == id else { return }
    await finishGeneration(
      generation,
      error: .outcomeUnknown,
      closeCode: .goingAway,
      discardIncoming: false
    )
  }

  private func incomingConsumerCanceled(generation: RelayTransportGeneration) async {
    await finishGeneration(
      generation,
      error: .canceled,
      closeCode: .normalClosure,
      discardIncoming: true
    )
  }

  private func finishGeneration(
    _ generation: RelayTransportGeneration,
    error: RelayTransportError?,
    closeCode: URLSessionWebSocketTask.CloseCode,
    discardIncoming: Bool
  ) async {
    let matches: Bool
    switch phase {
    case .open(let current), .draining(let current, _):
      matches = current == generation
    case .idle, .connecting, .closing, .failed:
      matches = false
    }
    guard matches else { return }

    phase = .closing(generation)
    let closingConnection = connection
    connection = nil
    let closingIncoming = incomingQueue
    let preserveUnclaimedTerminal = !incomingClaimed && error != nil
    incomingQueue = nil
    incomingClaimed = false
    receiveTask?.cancel()
    receiveTask = nil
    writerTask?.cancel()
    writerTask = nil
    writeDeadlineTask?.cancel()
    writeDeadlineTask = nil

    var pending = normalQueue
    pending.append(contentsOf: controlQueue)
    let handedToSocket = inFlight
    normalQueue.removeAll(keepingCapacity: false)
    controlQueue.removeAll(keepingCapacity: false)
    self.inFlight = nil
    normalFrames = 0
    normalBytes = 0
    controlFrames = 0
    controlBytes = 0
    for item in pending {
      item.continuation?.resume(throwing: error ?? RelayTransportError.canceled)
    }
    handedToSocket?.continuation?.resume(
      throwing: RelayTransportError.outcomeUnknown
    )

    await closingIncoming?.finish(
      error: error,
      discardBuffered: discardIncoming
    )
    if preserveUnclaimedTerminal, let closingIncoming {
      terminalIncoming = (generation, closingIncoming)
    }
    self.closingConnection = closingConnection
    startConnectCleanupDeadline(generation: generation)
    await closingConnection?.close(
      code: closeCode,
      reason: error.map { Data($0.code.utf8) }
    )
    completeClosing(generation: generation)
  }

  private func allocateOutboundID() -> UInt64 {
    let id = nextOutboundID
    nextOutboundID = nextOutboundID == UInt64.max ? 1 : nextOutboundID + 1
    return id
  }

  func debugOutgoingApplicationUsage() -> (frames: Int, bytes: Int) {
    (normalFrames, normalBytes)
  }

  func debugOutgoingControlUsage() -> (frames: Int, bytes: Int) {
    (controlFrames, controlBytes)
  }

  func debugConnectWaiterCount() -> Int {
    connectWaiters.count
  }

  func debugIncomingQueueUsage(
    on generation: RelayTransportGeneration
  ) async -> (
    regularFrames: Int,
    regularBytes: Int,
    urgentFrames: Int,
    urgentBytes: Int
  )? {
    guard case .open(let current) = phase,
      current == generation,
      let incomingQueue
    else {
      return nil
    }
    return await incomingQueue.debugUsage()
  }

  func debugIsIdle() -> Bool {
    phase == .idle
  }

  func debugIsClosing() -> Bool {
    if case .closing = phase { return true }
    return false
  }

  private func waitForCloseCompletion() async throws {
    let waiterID = nextCloseWaiterID
    nextCloseWaiterID = nextCloseWaiterID == UInt64.max ? 1 : nextCloseWaiterID + 1
    try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { continuation in
        switch phase {
        case .closing:
          closeWaiters[waiterID] = continuation
          if Task.isCancelled {
            cancelCloseWaiter(id: waiterID)
          }
        case .failed(_, let error):
          continuation.resume(throwing: error)
        case .idle, .connecting, .open, .draining:
          continuation.resume()
        }
      }
    } onCancel: {
      Task { await self.cancelCloseWaiter(id: waiterID) }
    }
  }

  private func cancelCloseWaiter(id: UInt64) {
    guard let continuation = closeWaiters.removeValue(forKey: id) else { return }
    continuation.resume(throwing: RelayTransportError.canceled)
  }

  private func resumeCloseWaiters(
    with result: Result<Void, RelayTransportError>
  ) {
    let waiters = Array(closeWaiters.values)
    closeWaiters.removeAll(keepingCapacity: false)
    for continuation in waiters {
      switch result {
      case .success:
        continuation.resume()
      case .failure(let error):
        continuation.resume(throwing: error)
      }
    }
  }

  private func completeClosing(generation: RelayTransportGeneration) {
    guard phase == .closing(generation) else { return }
    connectCleanupDeadlineTask?.cancel()
    connectCleanupDeadlineTask = nil
    connectAttemptGate = nil
    closingConnection = nil
    phase = .idle
    resumeCloseWaiters(with: .success(()))
  }

  private func throwIfCleanupFailed(generation: RelayTransportGeneration) throws {
    if case .failed(let current, let error) = phase, current == generation {
      throw error
    }
  }

  private static func failedStream(
    _ error: RelayTransportError
  ) -> AsyncThrowingStream<ReceivedRelayFrame, any Error> {
    AsyncThrowingStream { throw error }
  }
}

private func mapConnectionError(_ error: Error) -> RelayTransportError {
  if let error = error as? RelayTransportError { return error }
  if let error = error as? RelayTLSError { return .tls(error) }
  if error is CancellationError { return .canceled }
  return .connectionFailed
}
