import AgentDeckCore
import Foundation

/// Production App 的惰性 shared-daemon wire。
///
/// 构造 SessionModel/AppKit view 不产生文件系统或进程副作用；第一次 `start()` 才从
/// current OS account installation 派生 canonical endpoint。这里没有 stdio、spawn 或 fallback。
actor OSAccountRuntimeWireSession: AppRuntimeWireSession {
  typealias SessionFactory = @Sendable () throws -> any AppRuntimeWireSession

  private enum Lifecycle {
    case idle
    case starting
    case running
    case closed
  }

  private let sessionFactory: SessionFactory
  private var lifecycle = Lifecycle.idle
  private var startingSession: (any AppRuntimeWireSession)?
  private var session: (any AppRuntimeWireSession)?

  init() {
    sessionFactory = { try LocalRuntimeWireSession.forOSAccount() }
  }

  /// 确定性 lifecycle 测试 seam；production 默认构造器仍只允许 OS-account session。
  init(sessionFactory: @escaping SessionFactory) {
    self.sessionFactory = sessionFactory
  }

  func start() async throws {
    guard lifecycle == .idle else {
      if lifecycle == .closed { throw Self.closedFailure() }
      throw RuntimeEnvelopeClientFailure(
        code: "daemon.client.already_started",
        message: "OS-account Runtime wire is already started"
      )
    }

    let candidate = try sessionFactory()
    lifecycle = .starting
    startingSession = candidate
    do {
      try await candidate.start()
    } catch {
      await candidate.close()
      if lifecycle == .starting {
        startingSession = nil
        lifecycle = .idle
        throw error
      }
      startingSession = nil
      throw Self.closedFailure()
    }
    guard lifecycle == .starting else {
      await candidate.close()
      throw Self.closedFailure()
    }
    startingSession = nil
    session = candidate
    lifecycle = .running
  }

  private static func closedFailure() -> RuntimeEnvelopeClientFailure {
    RuntimeEnvelopeClientFailure(
      code: "daemon.client.connection_closed",
      message: "OS-account Runtime wire was closed while starting"
    )
  }

  private func requireSession() throws -> any AppRuntimeWireSession {
    guard lifecycle == .running, let session else {
      throw RuntimeEnvelopeClientFailure(
        code: "daemon.client.not_started",
        message: "OS-account Runtime wire has not started"
      )
    }
    return session
  }

  func request(_ request: RuntimeRequestV2) async throws -> RuntimeReplyV2 {
    try await requireSession().request(request)
  }

  func beginAppSynchronizedRequest(
    _ request: RuntimeRequestV2
  ) async throws -> any AppRuntimeWireReplySequence {
    try await requireSession().beginAppSynchronizedRequest(request)
  }

  func nextStream() async throws -> LocalRuntimeStreamFrame {
    try await requireSession().nextStream()
  }

  func close() async {
    guard lifecycle != .closed else { return }
    lifecycle = .closed
    let current = session ?? startingSession
    session = nil
    startingSession = nil
    await current?.close()
  }
}
