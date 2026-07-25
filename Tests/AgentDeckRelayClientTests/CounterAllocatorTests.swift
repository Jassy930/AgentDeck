import Foundation
import XCTest

@testable import AgentDeckRelayClient

final class CounterAllocatorTests: XCTestCase {
  func testPublicContractIsSendableAndBlockSizeIs1024() throws {
    requireSendable(CounterBlock.self)
    requireSendable((any CounterBlockReserving).self)
    requireSendable(CounterAllocatorError.self)
    requireSendable(CounterAllocator.self)

    XCTAssertEqual(CounterBlock.size, 1_024)
    XCTAssertEqual(CounterAllocator.blockSize, 1_024)
    XCTAssertEqual(
      try CounterBlock(start: 0, endExclusive: 1_024),
      CounterBlock(uncheckedStart: 0, endExclusive: 1_024)
    )
  }

  func testSameAllocatorSharesReservationFlightAcross2048ConcurrentCalls() async throws {
    let coordinator = MemoryCounterBlockCoordinator(yieldBeforeReturning: true)
    let allocator = CounterAllocator(coordinator: coordinator)

    let counters = try await collectCounters(count: 2_048) { _ in
      try await allocator.nextCounter()
    }

    assertExactlyUniqueContiguous(counters, count: 2_048)
    let reservationCount = await coordinator.reservationCount
    XCTAssertEqual(reservationCount, 2)
  }

  func testTwoAllocatorsSharingCoordinatorReturn2048UniqueCountersWithoutErrors() async throws {
    let coordinator = MemoryCounterBlockCoordinator(yieldBeforeReturning: true)
    let first = CounterAllocator(coordinator: coordinator)
    let second = CounterAllocator(coordinator: coordinator)

    let counters = try await collectCounters(count: 2_048) { index in
      if index.isMultiple(of: 2) {
        return try await first.nextCounter()
      }
      return try await second.nextCounter()
    }

    assertExactlyUniqueContiguous(counters, count: 2_048)
    let reservationCount = await coordinator.reservationCount
    XCTAssertEqual(reservationCount, 2)
  }

  func testRestartAbandonsUnusedRemainderOfPreviouslyReservedBlock() async throws {
    let coordinator = MemoryCounterBlockCoordinator()
    let firstProcessAllocator = CounterAllocator(coordinator: coordinator)
    let firstCounter = try await firstProcessAllocator.nextCounter()
    XCTAssertEqual(firstCounter, 0)

    let restartedAllocator = CounterAllocator(coordinator: coordinator)
    let restartedFirstCounter = try await restartedAllocator.nextCounter()
    let restartedSecondCounter = try await restartedAllocator.nextCounter()
    let reservationCount = await coordinator.reservationCount
    XCTAssertEqual(restartedFirstCounter, CounterBlock.size)
    XCTAssertEqual(restartedSecondCounter, CounterBlock.size + 1)
    XCTAssertEqual(reservationCount, 2)
  }

  func testInvalidCoordinatorBlockFailsClosedAndIsNeverInstalled() async throws {
    let coordinator = ScriptedCounterBlockCoordinator([
      .block(CounterBlock(uncheckedStart: 0, endExclusive: CounterBlock.size - 1)),
      .block(try CounterBlock(start: CounterBlock.size, endExclusive: CounterBlock.size * 2)),
    ])
    let allocator = CounterAllocator(coordinator: coordinator)

    await assertThrowsErrorAsync(try await allocator.nextCounter()) { error in
      XCTAssertEqual(error as? CounterAllocatorError, .invalidState)
    }
    let nextCounter = try await allocator.nextCounter()
    XCTAssertEqual(nextCounter, CounterBlock.size, "损坏 block 不能留下任何可消费 counter")
  }

  func testOverflowingCoordinatorBlockRequiresEpochRetirementAndIsNeverInstalled() async throws {
    let overflowStart = UInt64.max - CounterBlock.size + 1
    let coordinator = ScriptedCounterBlockCoordinator([
      .block(CounterBlock(uncheckedStart: overflowStart, endExclusive: UInt64.max))
    ])
    let allocator = CounterAllocator(coordinator: coordinator)

    await assertThrowsErrorAsync(try await allocator.nextCounter()) { error in
      XCTAssertEqual(error as? CounterAllocatorError, .epochRetirementRequired)
    }
    let callCount = await coordinator.callCount
    XCTAssertEqual(callCount, 1)
  }

  func testPublicCounterBlockInitializerRejectsInvalidSpanAndOverflow() {
    XCTAssertThrowsError(
      try CounterBlock(start: 7, endExclusive: 7 + CounterBlock.size - 1)
    ) { error in
      XCTAssertEqual(error as? CounterAllocatorError, .invalidState)
    }

    XCTAssertThrowsError(
      try CounterBlock(
        start: UInt64.max - CounterBlock.size + 1,
        endExclusive: UInt64.max
      )
    ) { error in
      XCTAssertEqual(error as? CounterAllocatorError, .epochRetirementRequired)
    }
  }

  private func requireSendable<Value: Sendable>(_: Value.Type) {}

  private func collectCounters(
    count: Int,
    operation: @escaping @Sendable (Int) async throws -> UInt64
  ) async throws -> [UInt64] {
    try await withThrowingTaskGroup(of: UInt64.self) { group in
      for index in 0..<count {
        group.addTask {
          try await operation(index)
        }
      }

      var counters: [UInt64] = []
      counters.reserveCapacity(count)
      for try await counter in group {
        counters.append(counter)
      }
      return counters
    }
  }

  private func assertExactlyUniqueContiguous(
    _ counters: [UInt64],
    count: Int,
    file: StaticString = #filePath,
    line: UInt = #line
  ) {
    XCTAssertEqual(counters.count, count, file: file, line: line)
    XCTAssertEqual(Set(counters).count, count, file: file, line: line)
    XCTAssertEqual(counters.sorted(), (0..<UInt64(count)).map { $0 }, file: file, line: line)
  }
}

private actor MemoryCounterBlockCoordinator: CounterBlockReserving {
  private var nextStart: UInt64 = 0
  private(set) var reservationCount = 0
  private let yieldBeforeReturning: Bool

  init(yieldBeforeReturning: Bool = false) {
    self.yieldBeforeReturning = yieldBeforeReturning
  }

  func reserveCounterBlock() async throws -> CounterBlock {
    let start = nextStart
    let addition = start.addingReportingOverflow(CounterBlock.size)
    guard !addition.overflow else {
      throw CounterAllocatorError.epochRetirementRequired
    }
    nextStart = addition.partialValue
    reservationCount += 1
    if yieldBeforeReturning {
      await Task.yield()
    }
    return try CounterBlock(start: start, endExclusive: addition.partialValue)
  }
}

private enum ScriptedCounterBlockOutcome: Sendable {
  case block(CounterBlock)
  case failure(CounterAllocatorError)
}

private actor ScriptedCounterBlockCoordinator: CounterBlockReserving {
  private var outcomes: [ScriptedCounterBlockOutcome]
  private(set) var callCount = 0

  init(_ outcomes: [ScriptedCounterBlockOutcome]) {
    self.outcomes = outcomes
  }

  func reserveCounterBlock() async throws -> CounterBlock {
    callCount += 1
    guard !outcomes.isEmpty else {
      throw CounterAllocatorError.invalidState
    }
    switch outcomes.removeFirst() {
    case .block(let block):
      return block
    case .failure(let error):
      throw error
    }
  }
}

private func assertThrowsErrorAsync<T>(
  _ expression: @autoclosure () async throws -> T,
  _ errorHandler: (Error) -> Void = { _ in },
  file: StaticString = #filePath,
  line: UInt = #line
) async {
  do {
    _ = try await expression()
    XCTFail("expected expression to throw", file: file, line: line)
  } catch {
    errorHandler(error)
  }
}
