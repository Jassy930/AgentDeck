import Foundation

/// coordinator 已 durable 预留、可由单个 allocator 独占消费的一整块 counter。
public struct CounterBlock: Equatable, Sendable, CustomDebugStringConvertible {
  public static let size: UInt64 = 1_024

  public let start: UInt64
  public let endExclusive: UInt64

  public init(start: UInt64, endExclusive: UInt64) throws {
    self.start = start
    self.endExclusive = endExclusive
    try validate()
  }

  /// 仅供同模块 fault-injection tests 构造损坏的 coordinator 回值。
  init(uncheckedStart start: UInt64, endExclusive: UInt64) {
    self.start = start
    self.endExclusive = endExclusive
  }

  public var debugDescription: String {
    "CounterBlock(start: \(start), endExclusive: \(endExclusive))"
  }

  fileprivate func validate() throws {
    let expectedEnd = start.addingReportingOverflow(Self.size)
    guard !expectedEnd.overflow else {
      throw CounterAllocatorError.epochRetirementRequired
    }
    guard expectedEnd.partialValue == endExclusive else {
      throw CounterAllocatorError.invalidState
    }
  }
}

/// Keychain guard、sealed state 与 machine-scoped lease 均由 production coordinator 管理。
/// allocator 只接收已经完整 durable 的固定大小 block。
public protocol CounterBlockReserving: Sendable {
  func reserveCounterBlock() async throws -> CounterBlock
}

public enum CounterAllocatorError: Error, Equatable, Sendable {
  case invalidGuard
  case invalidState
  case entropyUnavailable
  case epochRetirementRequired

  public var code: String {
    switch self {
    case .invalidGuard: "remote.counter.invalid_guard"
    case .invalidState: "remote.counter.invalid_state"
    case .entropyUnavailable: "remote.counter.entropy_unavailable"
    case .epochRetirementRequired: "remote.counter.epoch_retirement_required"
    }
  }
}

private struct CounterReservationFlight: Sendable {
  let id: UUID
  let task: Task<CounterBlock, Error>
}

/// Actor 独占每个已预留 block；并发 awaiter 共享同一个 reservation flight。
public actor CounterAllocator {
  public static let blockSize = CounterBlock.size

  private let coordinator: any CounterBlockReserving
  private var reservationFlight: CounterReservationFlight?
  private var next: UInt64?
  private var endExclusive: UInt64?

  public init(coordinator: any CounterBlockReserving) {
    self.coordinator = coordinator
  }

  /// coordinator 成功返回代表整个 block 已 durable；此前绝不向 sealer 暴露 counter。
  public func nextCounter() async throws -> UInt64 {
    while true {
      if let counter = consumeCurrentBlock() {
        return counter
      }

      let flight = currentOrStartReservationFlight()
      do {
        let block = try await flight.task.value
        // 每个 waiter 都先验证 coordinator 回值；即使另一个 waiter 已安装或清理
        // flight，损坏 block 也不能被静默跳过并触发下一次 reservation。
        try block.validate()
        installBlockIfCurrent(block, flightID: flight.id)
      } catch {
        clearFlightIfCurrent(flight.id)
        throw error
      }
    }
  }

  private func currentOrStartReservationFlight() -> CounterReservationFlight {
    if let reservationFlight {
      return reservationFlight
    }

    let coordinator = self.coordinator
    let flight = CounterReservationFlight(
      id: UUID(),
      task: Task {
        try await coordinator.reserveCounterBlock()
      }
    )
    reservationFlight = flight
    return flight
  }

  private func installBlockIfCurrent(_ block: CounterBlock, flightID: UUID) {
    guard reservationFlight?.id == flightID else {
      return
    }
    reservationFlight = nil
    next = block.start
    endExclusive = block.endExclusive
  }

  private func clearFlightIfCurrent(_ flightID: UUID) {
    guard reservationFlight?.id == flightID else {
      return
    }
    reservationFlight = nil
  }

  private func consumeCurrentBlock() -> UInt64? {
    guard let current = next, let endExclusive, current < endExclusive else {
      next = nil
      self.endExclusive = nil
      return nil
    }
    next = current + 1
    return current
  }
}
