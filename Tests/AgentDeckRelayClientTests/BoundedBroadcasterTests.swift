import XCTest

@testable import AgentDeckRelayClient

final class BoundedBroadcasterTests: XCTestCase {
  func testObserverAdmissionAcceptsExactCapAndRejectsPlusOneWithoutRetainingIt() async {
    let broadcaster = BoundedBroadcaster<ProbeUpdate>(
      capacity: 1,
      overflowStrategy: .bufferingNewest,
      maximumObservers: 2
    )

    let first = await broadcaster.streamIfAvailable()
    let second = await broadcaster.streamIfAvailable()
    let rejected = await broadcaster.streamIfAvailable()

    XCTAssertNotNil(first)
    XCTAssertNotNil(second)
    XCTAssertNil(rejected)
    let retained = await broadcaster.debugObserverCount
    XCTAssertEqual(retained, 2, "cap/+1 不能把 offending observer 事后留入 registry")
  }

  func testResourceStreamBuffersNewestOneForEverySlowObserver() async {
    let broadcaster = BoundedBroadcaster<ProbeUpdate>(
      capacity: 1,
      overflowStrategy: .bufferingNewest
    )
    let generation = await broadcaster.generation
    let firstStream = await broadcaster.stream()
    let secondStream = await broadcaster.stream()

    await assertPublish(.published, .value(1), on: generation, using: broadcaster)
    await assertPublish(.replacedOldest, .value(2), on: generation, using: broadcaster)

    var first = firstStream.makeAsyncIterator()
    var second = secondStream.makeAsyncIterator()
    let firstValue = await first.next()
    let secondValue = await second.next()
    XCTAssertEqual(firstValue, .value(2))
    XCTAssertEqual(secondValue, .value(2))
  }

  func testConversationAcceptsExactlyFiveHundredTwelveQueuedValues() async {
    let broadcaster = BoundedBroadcaster<ProbeUpdate>(
      capacity: 512,
      overflowStrategy: .invalidateGeneration
    )
    let generation = await broadcaster.generation
    let stream = await broadcaster.stream()

    for value in 0..<512 {
      await assertPublish(.published, .value(value), on: generation, using: broadcaster)
    }

    var iterator = stream.makeAsyncIterator()
    for expected in 0..<512 {
      let value = await iterator.next()
      XCTAssertEqual(value, .value(expected))
    }
  }

  func testTenThousandEventSlowConsumerOverflowClearsQueueAndLaggedIsNext() async {
    let broadcaster = BoundedBroadcaster<ProbeUpdate>(
      capacity: 512,
      overflowStrategy: .invalidateGeneration
    )
    let oldGeneration = await broadcaster.generation
    let stream = await broadcaster.stream()

    for value in 0..<512 {
      await assertPublish(.published, .value(value), on: oldGeneration, using: broadcaster)
    }
    await assertPublish(.overflow, .value(512), on: oldGeneration, using: broadcaster)

    let recoveryGeneration = await broadcaster.invalidateGeneration(marker: .lagged)
    for value in 513..<10_000 {
      await assertPublish(
        .staleGeneration,
        .value(value),
        on: oldGeneration,
        using: broadcaster
      )
    }

    var iterator = stream.makeAsyncIterator()
    let firstRecoveryValue = await iterator.next()
    XCTAssertEqual(
      firstRecoveryValue,
      .lagged,
      "overflow 必须原子清掉旧 512 项；慢消费者下一项只能是 lagged"
    )
    XCTAssertNotEqual(recoveryGeneration, oldGeneration)
  }

  func testOldAndPreBarrierRecoveryEventsAreRejected() async {
    let broadcaster = BoundedBroadcaster<ProbeUpdate>(
      capacity: 1,
      overflowStrategy: .invalidateGeneration
    )
    let oldGeneration = await broadcaster.generation
    _ = await broadcaster.stream()

    await assertPublish(.published, .value(1), on: oldGeneration, using: broadcaster)
    await assertPublish(.overflow, .value(2), on: oldGeneration, using: broadcaster)
    let recoveryGeneration = await broadcaster.invalidateGeneration(marker: .lagged)

    await assertPublish(.staleGeneration, .value(3), on: oldGeneration, using: broadcaster)
    await assertPublish(
      .awaitingBarrier,
      .value(4),
      on: recoveryGeneration,
      using: broadcaster
    )
  }

  func testAuthoritativeTerminalFinishesCurrentGenerationAfterInvalidation() async {
    let broadcaster = BoundedBroadcaster<Int>(
      capacity: 2,
      overflowStrategy: .invalidateGeneration
    )
    let stream = await broadcaster.stream()
    var iterator = stream.makeAsyncIterator()

    _ = await broadcaster.invalidateGeneration(marker: 41)
    let result = await broadcaster.finish(delivering: 42)
    let recoveryMarker = await iterator.next()
    let terminalMarker = await iterator.next()
    let end = await iterator.next()

    XCTAssertEqual(result, .published)
    XCTAssertEqual(recoveryMarker, 41)
    XCTAssertEqual(terminalMarker, 42)
    XCTAssertNil(end)
  }

  func testOuterObservationSurvivesLagSnapshotBarrierAndResumedLiveEvent() async {
    let broadcaster = BoundedBroadcaster<ProbeUpdate>(
      capacity: 1,
      overflowStrategy: .invalidateGeneration
    )
    let oldGeneration = await broadcaster.generation
    let stream = await broadcaster.stream()

    await assertPublish(.published, .value(1), on: oldGeneration, using: broadcaster)
    await assertPublish(.overflow, .value(2), on: oldGeneration, using: broadcaster)
    let recoveryGeneration = await broadcaster.invalidateGeneration(marker: .lagged)

    var iterator = stream.makeAsyncIterator()
    let lagged = await iterator.next()
    XCTAssertEqual(lagged, .lagged)
    await assertPublish(
      .awaitingBarrier,
      .value(3),
      on: recoveryGeneration,
      using: broadcaster,
      message: "fresh snapshot + SyncComplete 完成前不得发布 live 增量"
    )

    let resumeResult = await broadcaster.resumeAfterBarrier(
      snapshot: .snapshot(2),
      generation: recoveryGeneration
    )
    XCTAssertEqual(resumeResult, .published)
    let snapshot = await iterator.next()
    XCTAssertEqual(snapshot, .snapshot(2))

    await assertPublish(.published, .value(4), on: recoveryGeneration, using: broadcaster)
    let resumedLive = await iterator.next()
    XCTAssertEqual(
      resumedLive,
      .value(4),
      "恢复只能轮换内部 generation，用户持有的 outer AsyncStream 必须继续存活"
    )
  }

  func testUnconsumedRecoveryPrefixCannotBypassCapacityOnResumedLivePublish() async {
    let broadcaster = BoundedBroadcaster<ProbeUpdate>(
      capacity: 1,
      overflowStrategy: .invalidateGeneration
    )
    let firstGeneration = await broadcaster.generation
    let stream = await broadcaster.stream()

    await assertPublish(.published, .value(1), on: firstGeneration, using: broadcaster)
    await assertPublish(.overflow, .value(2), on: firstGeneration, using: broadcaster)
    let recoveryGeneration = await broadcaster.invalidateGeneration(marker: .lagged)
    let resumeResult = await broadcaster.resumeAfterBarrier(
      snapshot: .snapshot(2),
      generation: recoveryGeneration
    )
    XCTAssertEqual(resumeResult, .published)

    await assertPublish(
      .overflow,
      .value(3),
      on: recoveryGeneration,
      using: broadcaster,
      message: "尚未消费的 marker + snapshot 控制前缀不能让 live publish 绕过容量门禁"
    )
    _ = await broadcaster.invalidateGeneration(marker: .lagged)

    var iterator = stream.makeAsyncIterator()
    let next = await iterator.next()
    XCTAssertEqual(next, .lagged)
  }

  func testFinishDrainsQueuedFatalMarkerBeforeEndingObservation() async {
    let broadcaster = BoundedBroadcaster<ProbeUpdate>(
      capacity: 1,
      overflowStrategy: .bufferingNewest
    )
    let generation = await broadcaster.generation
    let stream = await broadcaster.stream()
    await assertPublish(.published, .lagged, on: generation, using: broadcaster)
    await broadcaster.finish()

    var iterator = stream.makeAsyncIterator()
    let marker = await iterator.next()
    let terminal = await iterator.next()
    XCTAssertEqual(marker, .lagged)
    XCTAssertNil(terminal)
  }

  func testFatalMarkerIsObservableEvenWhenConversationQueueIsFull() async {
    let broadcaster = BoundedBroadcaster<ProbeUpdate>(
      capacity: 1,
      overflowStrategy: .invalidateGeneration
    )
    let generation = await broadcaster.generation
    let stream = await broadcaster.stream()
    await assertPublish(.published, .value(1), on: generation, using: broadcaster)

    let finishResult = await broadcaster.finish(delivering: .lagged, on: generation)
    XCTAssertEqual(finishResult, .published)

    var iterator = stream.makeAsyncIterator()
    let queued = await iterator.next()
    let fatal = await iterator.next()
    let terminal = await iterator.next()
    XCTAssertEqual(queued, .value(1))
    XCTAssertEqual(fatal, .lagged)
    XCTAssertNil(terminal)
  }

  private func assertPublish(
    _ expected: BoundedBroadcastPublishResult,
    _ element: ProbeUpdate,
    on generation: BoundedBroadcastGeneration,
    using broadcaster: BoundedBroadcaster<ProbeUpdate>,
    message: @autoclosure () -> String = "",
    file: StaticString = #filePath,
    line: UInt = #line
  ) async {
    let actual = await broadcaster.publish(element, on: generation)
    XCTAssertEqual(actual, expected, message(), file: file, line: line)
  }
}

private enum ProbeUpdate: Equatable, Sendable {
  case value(Int)
  case lagged
  case snapshot(Int)
}
