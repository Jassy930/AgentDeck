import Foundation

/// `BoundedBroadcaster` 内部流的本地 generation。它不进入 Relay/Runtime wire，
/// 只用于拒绝 overflow 前已排队或迟到的 producer 任务。
public struct BoundedBroadcastGeneration: Equatable, Hashable, Sendable {
  public let rawValue: UUID

  public init(rawValue: UUID = UUID()) {
    self.rawValue = rawValue
  }
}

public enum BoundedBroadcastOverflowStrategy: Equatable, Sendable {
  /// 资源状态只保留最新值；慢观察者不触发远端重同步。
  case bufferingNewest

  /// conversation 不能静默丢事件；满队列先失效，再由调用方发布 lagged marker
  /// 并完成 fresh snapshot + `SyncComplete` barrier。
  case invalidateGeneration
}

public enum BoundedBroadcastPublishResult: Equatable, Sendable {
  case published
  case replacedOldest
  case overflow
  case staleGeneration
  case awaitingBarrier
  case finished
  case invalidState
}

/// 多观察者、有界、pull-driven 的广播器。
///
/// 外层必须是用户可长期持有的 `AsyncStream`，因此这里不能在 lag/recovery 时
/// finish stream。每个观察者的待消费值留在 actor 队列中；这使 conversation
/// overflow 可以原子清掉旧 generation，而不是受 `AsyncStream.Continuation`
/// 不可清空的内部 buffer 限制。
public actor BoundedBroadcaster<Element: Sendable> {
  /// 单个 broadcaster 的 observer metadata/queue owner 硬上界。调用方可以在
  /// internal/test composition 中选择更低值，但不能通过 initializer 放大 production cap。
  public nonisolated static var hardMaximumObservers: Int { 64 }

  private enum Phase: Sendable {
    case live
    case overflowed
    case awaitingBarrier
    case finished
  }

  private struct Observer {
    var queue: [Element]
    var waiter: CheckedContinuation<Element?, Never>?
    let onTermination: (@Sendable () -> Void)?
  }

  public nonisolated let capacity: Int
  public nonisolated let overflowStrategy: BoundedBroadcastOverflowStrategy
  public nonisolated let maximumObservers: Int

  public private(set) var generation: BoundedBroadcastGeneration

  private var phase: Phase = .live
  private var observers: [UUID: Observer] = [:]
  private var latestResourceValue: Element?

  public init(
    capacity: Int,
    overflowStrategy: BoundedBroadcastOverflowStrategy,
    generation: BoundedBroadcastGeneration = BoundedBroadcastGeneration(),
    maximumObservers: Int = BoundedBroadcaster.hardMaximumObservers
  ) {
    precondition(capacity > 0, "BoundedBroadcaster capacity must be positive")
    precondition(
      maximumObservers > 0 && maximumObservers <= Self.hardMaximumObservers,
      "BoundedBroadcaster observer cap must stay within the fixed hard limit"
    )
    self.capacity = capacity
    self.overflowStrategy = overflowStrategy
    self.generation = generation
    self.maximumObservers = maximumObservers
  }

  /// 注册一个独立的有界观察者。bufferingNewest 流会向迟到观察者 replay
  /// 当前最新资源值；conversation 流必须由上层另行执行 fresh bootstrap。
  public func stream(
    onTermination: (@Sendable () -> Void)? = nil
  ) -> AsyncStream<Element> {
    guard let admitted = streamIfAvailable(onTermination: onTermination) else {
      return AsyncStream { continuation in continuation.finish() }
    }
    return admitted
  }

  /// 带显式 admission 结果的观察入口。Source 使用它把 cap/+1 变成只影响
  /// offending observer 的 typed state；不能先把 observer 插入字典再事后统计。
  public func streamIfAvailable(
    onTermination: (@Sendable () -> Void)? = nil
  ) -> AsyncStream<Element>? {
    guard phase != .finished, observers.count < maximumObservers else {
      return nil
    }
    let observerID = UUID()
    let initialQueue = latestResourceValue.map { [$0] } ?? []
    observers[observerID] = Observer(
      queue: initialQueue,
      waiter: nil,
      onTermination: onTermination
    )

    return AsyncStream<Element>(
      // Iterator 必须在 drain 已排队的 terminal/control marker 前强持有
      // broadcaster。Source 可以先释放 owner record；若这里 weak capture，
      // broadcaster 会在慢观察者读 marker 前析构并把流静默截断。
      unfolding: {
        return await self.next(for: observerID)
      },
      onCancel: { [weak self] in
        guard let self else { return }
        Task { await self.removeObserver(observerID) }
      }
    )
  }

  var debugObserverCount: Int { observers.count }

  /// 发布 live 值。conversation 首次发现任一慢观察者满载时，会在同一 actor
  /// turn 清空所有旧队列并进入 overflowed；offending value 不会被归约或交付。
  @discardableResult
  public func publish(
    _ element: Element,
    on requestedGeneration: BoundedBroadcastGeneration
  ) -> BoundedBroadcastPublishResult {
    guard phase != .finished else { return .finished }
    guard requestedGeneration == generation else { return .staleGeneration }
    guard phase == .live else { return .awaitingBarrier }

    switch overflowStrategy {
    case .bufferingNewest:
      latestResourceValue = element
      var replacedOldest = false
      for observerID in Array(observers.keys) {
        guard var observer = observers[observerID] else { continue }
        if let waiter = observer.waiter {
          observer.waiter = nil
          observers[observerID] = observer
          waiter.resume(returning: element)
          continue
        }
        if observer.queue.count == capacity {
          observer.queue.removeFirst()
          replacedOldest = true
        }
        observer.queue.append(element)
        observers[observerID] = observer
      }
      return replacedOldest ? .replacedOldest : .published

    case .invalidateGeneration:
      if observers.values.contains(where: { observer in
        observer.waiter == nil && observer.queue.count >= capacity
      }) {
        clearQueuedValues()
        phase = .overflowed
        return .overflow
      }
      deliver(element)
      return .published
    }
  }

  /// 将 overflowed generation 换代，原子清队列并把 lagged marker 设为每个
  /// 观察者的下一项。返回的 generation 在 barrier 前只会得到 awaitingBarrier。
  @discardableResult
  public func invalidateGeneration(marker: Element) -> BoundedBroadcastGeneration {
    guard phase != .finished else { return generation }

    generation = BoundedBroadcastGeneration()
    clearQueuedValues()
    phase = .awaitingBarrier
    deliver(marker)
    return generation
  }

  /// fresh snapshot 已通过完整 `SyncComplete` 核验后才调用。snapshot 会排在
  /// lagged marker 后；方法返回后才重新接受当前 generation 的 live 增量。
  @discardableResult
  public func resumeAfterBarrier(
    snapshot: Element,
    generation requestedGeneration: BoundedBroadcastGeneration
  ) -> BoundedBroadcastPublishResult {
    guard phase != .finished else { return .finished }
    guard requestedGeneration == generation else { return .staleGeneration }
    guard phase == .awaitingBarrier else { return .invalidState }

    // recovery 的 marker/snapshot 是控制序列，允许短暂占用 capacity 之外的一个
    // slot；后续 live publish 仍按固定 capacity 判 overflow。
    deliver(snapshot)
    phase = .live
    return .published
  }

  /// 只供 fatal revoked/incompatible/securityError 或 owner teardown 使用。
  public func finish() {
    guard phase != .finished else { return }
    phase = .finished
    latestResourceValue = nil

    for observerID in Array(observers.keys) {
      guard let observer = observers[observerID], let waiter = observer.waiter else {
        // 已排队的 fatal marker/resource state 必须先被 drain，随后 next() 才返回 nil。
        continue
      }
      observers.removeValue(forKey: observerID)
      waiter.resume(returning: nil)
      observer.onTermination?()
    }
  }

  /// 发布一个必须可观察的 terminal marker 后结束。terminal control item 允许和
  /// recovery control item 一样短暂占用 capacity 之外的一个 slot；已有事件不会因
  /// fatal state 被静默清掉，慢观察者 drain marker 后下一次 `next()` 才得到 nil。
  @discardableResult
  public func finish(
    delivering terminal: Element,
    on requestedGeneration: BoundedBroadcastGeneration
  ) -> BoundedBroadcastPublishResult {
    guard phase != .finished else { return .finished }
    guard requestedGeneration == generation else { return .staleGeneration }

    return finishOnCurrentGeneration(delivering: terminal)
  }

  /// 由 owner 的单向 fatal latch 调用。fatal 是 broadcaster 当前权威 generation
  /// 的终局，而不是某个可失效 producer 的增量，因此必须和 generation 读取/结束
  /// 在同一 actor turn 内完成，避免 recovery 换代窗口把 terminal 判成 stale。
  @discardableResult
  public func finish(
    delivering terminal: Element
  ) -> BoundedBroadcastPublishResult {
    guard phase != .finished else { return .finished }

    return finishOnCurrentGeneration(delivering: terminal)
  }

  private func finishOnCurrentGeneration(
    delivering terminal: Element
  ) -> BoundedBroadcastPublishResult {
    if overflowStrategy == .bufferingNewest {
      latestResourceValue = terminal
    }
    deliver(terminal)
    phase = .finished
    return .published
  }

  private func next(for observerID: UUID) async -> Element? {
    guard var observer = observers[observerID] else { return nil }
    if !observer.queue.isEmpty {
      let next = observer.queue.removeFirst()
      observers[observerID] = observer
      return next
    }
    guard phase != .finished else {
      observers.removeValue(forKey: observerID)
      observer.onTermination?()
      return nil
    }

    return await withCheckedContinuation { continuation in
      guard var current = observers[observerID] else {
        continuation.resume(returning: nil)
        return
      }
      precondition(current.waiter == nil, "AsyncStream iterator requested concurrent next()")
      current.waiter = continuation
      observers[observerID] = current
    }
  }

  private func removeObserver(_ observerID: UUID) {
    guard let observer = observers.removeValue(forKey: observerID) else { return }
    observer.waiter?.resume(returning: nil)
    observer.onTermination?()
  }

  private func clearQueuedValues() {
    for observerID in Array(observers.keys) {
      guard var observer = observers[observerID] else { continue }
      observer.queue.removeAll(keepingCapacity: true)
      observers[observerID] = observer
    }
  }

  private func deliver(_ element: Element) {
    for observerID in Array(observers.keys) {
      guard var observer = observers[observerID] else { continue }
      if let waiter = observer.waiter {
        observer.waiter = nil
        observers[observerID] = observer
        waiter.resume(returning: element)
      } else {
        observer.queue.append(element)
        observers[observerID] = observer
      }
    }
  }
}
