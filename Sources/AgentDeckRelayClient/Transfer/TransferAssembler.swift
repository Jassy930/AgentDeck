import AgentDeckCore
import CryptoKit
import Foundation

/// Remote compact transfer 重组的稳定失败分类。
public enum TransferAssemblerError: Error, Equatable, Sendable {
  case tooLarge
  case hashMismatch
  case expired
  case reassemblyFull
  case staleScope

  public var code: String {
    switch self {
    case .tooLarge:
      "remote.transfer.too_large"
    case .hashMismatch:
      "remote.transfer.hash_mismatch"
    case .expired:
      "remote.transfer.expired"
    case .reassemblyFull:
      "remote.transfer.reassembly_full"
    case .staleScope:
      "remote.transfer.stale_scope"
    }
  }
}

/// 把易失重组状态绑定到一条逻辑 connection 与 exact transport generation。
public struct TransferAssemblyScope: Equatable, Hashable, Sendable {
  public let connectionID: UUID
  public let generation: RelayTransportGeneration

  public init(connectionID: UUID, generation: RelayTransportGeneration) {
    self.connectionID = connectionID
    self.generation = generation
  }
}

/// 完整重组后的 payload 及其 authenticated compact-carrier binding。
public struct TransferAssembly: Sendable {
  public let messageID: RuntimeMessageID
  public let channel: RuntimeTransferChannelV2
  public let transferID: RuntimeTransferID
  public let payload: Data

  public init(
    messageID: RuntimeMessageID,
    channel: RuntimeTransferChannelV2,
    transferID: RuntimeTransferID,
    payload: Data
  ) {
    self.messageID = messageID
    self.channel = channel
    self.transferID = transferID
    self.payload = payload
  }
}

public enum TransferAssemblyProgress: Sendable {
  case inProgress(receivedParts: UInt32, partCount: UInt32)
  case complete(TransferAssembly)
  case alreadyComplete
}

/// 单个 Relay connection generation 拥有的 compact transfer 纯状态机。
///
/// 调用方先使用 `RuntimeWireCodec.decodeTransferCarrier` 解码 `ADRT1`，本类型只负责
/// binding、TTL、内存预算、幂等和完整 SHA-256。connection 断开时应立即调用
/// `reset()`，不应把 `deinit` 兜底当作正常 disconnect/TTL 清理机制。
///
/// assembler 持有 process-global coordinator reservation，因此必须保持单 owner。
/// `~Copyable` 禁止 partial state 被复制后双重推进或 reset；`deinit` 则保证
/// owner 未走显式 disconnect/reset 时仍会释放 exact scope 预算。
public struct TransferAssembler: ~Copyable, Sendable {
  public static let maximumActiveTransfers = 64
  public static let maximumReassemblyBytes: UInt64 = 128 * 1024 * 1024
  public static let transferTTLMilliseconds: UInt64 = 300_000
  public static let maximumCompletedTombstones = 256

  private let maxActiveTransfers: Int
  private let maxReassemblyBytes: UInt64
  private let ttlMilliseconds: UInt64
  private let maxCompletedTombstones: Int
  private let scope: TransferAssemblyScope
  private let budgetCoordinator: TransferAssemblyBudgetCoordinator

  private var active: [RuntimeTransferID: ActiveTransfer] = [:]
  private var completed: [RuntimeTransferID: CompletedTransfer] = [:]
  private var completedOrder: [RuntimeTransferID] = []
  private(set) var bufferedBytes: UInt64 = 0

  /// 使用 process-global shared coordinator 的 production initializer。
  /// owner 必须在 exact generation disconnect/reset 时调用 `reset(scope:)`；
  /// 只有 owner teardown 的异常路径才依赖 `deinit` 同步兜底。
  public init(scope: TransferAssemblyScope) {
    self.init(scope: scope, budgetCoordinator: .shared)
  }

  init(
    scope: TransferAssemblyScope,
    budgetCoordinator: TransferAssemblyBudgetCoordinator,
    ttlMilliseconds: UInt64 = Self.transferTTLMilliseconds
  ) {
    precondition(
      ttlMilliseconds > 0
        && ttlMilliseconds <= Self.transferTTLMilliseconds
    )
    self.scope = scope
    self.budgetCoordinator = budgetCoordinator
    maxActiveTransfers = Self.maximumActiveTransfers
    maxReassemblyBytes = Self.maximumReassemblyBytes
    self.ttlMilliseconds = ttlMilliseconds
    maxCompletedTombstones = Self.maximumCompletedTombstones
  }

  init() {
    scope = TransferAssemblyScope(
      connectionID: UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1)),
      generation: RelayTransportGeneration(rawValue: 1)
    )
    budgetCoordinator = TransferAssemblyBudgetCoordinator()
    maxActiveTransfers = Self.maximumActiveTransfers
    maxReassemblyBytes = Self.maximumReassemblyBytes
    ttlMilliseconds = Self.transferTTLMilliseconds
    maxCompletedTombstones = Self.maximumCompletedTombstones
  }

  init(
    maxActiveTransfers: Int = Self.maximumActiveTransfers,
    maxReassemblyBytes: UInt64 = Self.maximumReassemblyBytes,
    ttlMilliseconds: UInt64 = Self.transferTTLMilliseconds,
    maxCompletedTombstones: Int = Self.maximumCompletedTombstones
  ) {
    precondition(maxActiveTransfers > 0)
    precondition(maxReassemblyBytes > 0)
    precondition(ttlMilliseconds > 0)
    precondition(maxCompletedTombstones > 0)
    scope = TransferAssemblyScope(
      connectionID: UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1)),
      generation: RelayTransportGeneration(rawValue: 1)
    )
    budgetCoordinator = TransferAssemblyBudgetCoordinator()
    self.maxActiveTransfers = maxActiveTransfers
    self.maxReassemblyBytes = maxReassemblyBytes
    self.ttlMilliseconds = ttlMilliseconds
    self.maxCompletedTombstones = maxCompletedTombstones
  }

  deinit {
    budgetCoordinator.releaseAll(scope: scope)
  }

  var activeTransferCount: Int { active.count }
  var completedTransferCount: Int { completed.count }

  /// 消费一个 current Runtime compact carrier。完整 hash 通过前绝不返回 payload。
  public mutating func accept(
    _ carrier: RuntimeTransferCarrierV2,
    scope expectedScope: TransferAssemblyScope,
    nowMS: UInt64
  ) throws -> TransferAssemblyProgress {
    guard expectedScope == scope else { throw TransferAssemblerError.staleScope }
    return try accept(carrier, nowMS: nowMS)
  }

  mutating func accept(
    _ carrier: RuntimeTransferCarrierV2,
    nowMS: UInt64
  ) throws -> TransferAssemblyProgress {
    let transferID = carrier.transfer.transferID
    do {
      try validate(carrier)
    } catch {
      dropActive(transferID)
      throw error
    }

    if let existing = active[transferID], isExpired(existing.startedAtMS, nowMS: nowMS) {
      dropActive(transferID)
      throw TransferAssemblerError.expired
    }
    _ = sweepExpired(nowMS: nowMS)

    let binding = TransferBinding(carrier: carrier)
    if let tombstone = completed[transferID] {
      guard tombstone.binding.matches(binding) else {
        throw TransferAssemblerError.hashMismatch
      }
      let partHash = Self.sha256(carrier.transfer.part)
      guard tombstone.partHashes[carrier.transfer.partIndex] == partHash else {
        throw TransferAssemblerError.hashMismatch
      }
      return .alreadyComplete
    }

    var current: ActiveTransfer
    if let existing = active[transferID] {
      guard existing.binding.matches(binding) else {
        dropActive(transferID)
        throw TransferAssemblerError.hashMismatch
      }
      if let previous = existing.parts[carrier.transfer.partIndex] {
        guard previous == carrier.transfer.part else {
          dropActive(transferID)
          throw TransferAssemblerError.hashMismatch
        }
        return .inProgress(
          receivedParts: UInt32(existing.parts.count),
          partCount: existing.binding.partCount
        )
      }
      current = existing
    } else {
      guard active.count < maxActiveTransfers else {
        throw TransferAssemblerError.reassemblyFull
      }
      current = ActiveTransfer(
        binding: binding,
        startedAtMS: nowMS,
        parts: [:],
        bufferedBytes: 0,
        partReservation: nil
      )
    }

    let incomingBytes = UInt64(carrier.transfer.part.count)
    let (projectedBytes, projectedOverflow) = bufferedBytes.addingReportingOverflow(incomingBytes)
    guard !projectedOverflow, projectedBytes <= maxReassemblyBytes else {
      if active[transferID] != nil {
        dropActive(transferID)
      }
      throw TransferAssemblerError.reassemblyFull
    }
    let (transferBytes, transferOverflow) = current.bufferedBytes.addingReportingOverflow(
      incomingBytes
    )
    guard !transferOverflow, transferBytes <= current.binding.totalBytes else {
      dropActive(transferID)
      throw TransferAssemblerError.hashMismatch
    }

    do {
      current.partReservation = try budgetCoordinator.reservePartBytes(
        scope: scope,
        reservation: current.partReservation,
        additionalBytes: incomingBytes
      )
    } catch {
      if active[transferID] != nil {
        dropActive(transferID)
      }
      throw error
    }

    current.parts[carrier.transfer.partIndex] = carrier.transfer.part
    current.bufferedBytes = transferBytes
    bufferedBytes = projectedBytes
    active[transferID] = current

    guard current.parts.count == Int(current.binding.partCount) else {
      return .inProgress(
        receivedParts: UInt32(current.parts.count),
        partCount: current.binding.partCount
      )
    }
    guard current.bufferedBytes == current.binding.totalBytes else {
      dropActive(transferID)
      throw TransferAssemblerError.hashMismatch
    }

    let assemblyBytes = current.binding.totalBytes
    let (peakBytes, peakOverflow) = bufferedBytes.addingReportingOverflow(assemblyBytes)
    guard !peakOverflow, peakBytes <= maxReassemblyBytes else {
      dropActive(transferID)
      throw TransferAssemblerError.reassemblyFull
    }
    let assemblyReservation: TransferAssemblyByteReservation
    do {
      assemblyReservation = try budgetCoordinator.reserveAssemblyBytes(
        scope: scope,
        bytes: assemblyBytes
      )
    } catch {
      dropActive(transferID)
      throw error
    }
    bufferedBytes = peakBytes
    defer {
      releaseAssembly(bytes: assemblyBytes)
      budgetCoordinator.release(assemblyReservation)
    }

    var assembled = Data()
    assembled.reserveCapacity(Int(assemblyBytes))
    for index in 0..<current.binding.partCount {
      guard let bytes = current.parts[index] else {
        dropActive(transferID)
        throw TransferAssemblerError.hashMismatch
      }
      assembled.append(bytes)
    }

    guard Self.sha256(assembled) == current.binding.totalSHA256 else {
      dropActive(transferID)
      throw TransferAssemblerError.hashMismatch
    }

    guard completed.count < maxCompletedTombstones else {
      dropActive(transferID)
      throw TransferAssemblerError.reassemblyFull
    }
    let tombstoneReservation: TransferAssemblyTombstoneReservation
    do {
      tombstoneReservation = try budgetCoordinator.reserveTombstone(scope: scope)
    } catch {
      dropActive(transferID)
      throw error
    }
    var tombstoneCommitted = false
    defer {
      if !tombstoneCommitted {
        budgetCoordinator.release(tombstoneReservation)
      }
    }

    let partHashes = current.parts.mapValues(Self.sha256)
    do {
      try rememberCompleted(
        transferID: transferID,
        value: CompletedTransfer(
          binding: current.binding,
          partHashes: partHashes,
          completedAtMS: nowMS,
          tombstoneReservation: tombstoneReservation
        )
      )
      tombstoneCommitted = true
    } catch {
      dropActive(transferID)
      throw error
    }
    dropActive(transferID)
    return .complete(
      TransferAssembly(
        messageID: current.binding.messageID,
        channel: current.binding.channel,
        transferID: transferID,
        payload: assembled
      )
    )
  }

  /// connection generation 终止时释放全部 active bytes 与 tombstone。
  public mutating func reset(scope expectedScope: TransferAssemblyScope) throws {
    guard expectedScope == scope else { throw TransferAssemblerError.staleScope }
    reset()
  }

  /// Source 丢弃尚未提交 reducer/cursor 的完整 transfer 时，精确释放 tombstone，
  /// 允许 Relay 对同一 authenticated parts 做一次完整重放。其他 active/completed
  /// transfer 不受影响。
  mutating func discardCompleted(
    transferID: RuntimeTransferID,
    scope expectedScope: TransferAssemblyScope
  ) throws {
    guard expectedScope == scope else { throw TransferAssemblerError.staleScope }
    guard let removed = completed.removeValue(forKey: transferID) else { return }
    completedOrder.removeAll { $0 == transferID }
    budgetCoordinator.release(removed.tombstoneReservation)
  }

  mutating func reset() {
    for value in active.values {
      if let reservation = value.partReservation {
        budgetCoordinator.release(reservation)
      }
    }
    for value in completed.values {
      budgetCoordinator.release(value.tombstoneReservation)
    }
    active.removeAll(keepingCapacity: false)
    completed.removeAll(keepingCapacity: false)
    completedOrder.removeAll(keepingCapacity: false)
    bufferedBytes = 0
    budgetCoordinator.releaseAll(scope: scope)
  }

  /// 供 connection owner 的单调 timer 调用；即使 Relay 静默也会在 absolute TTL
  /// 到达后释放 partial bytes。返回本轮终止的 active transfer IDs 供上层诊断计数。
  @discardableResult
  public mutating func sweepExpired(
    scope expectedScope: TransferAssemblyScope,
    nowMS: UInt64
  ) throws -> [RuntimeTransferID] {
    guard expectedScope == scope else { throw TransferAssemblerError.staleScope }
    return sweepExpired(nowMS: nowMS)
  }

  /// generation owner 用它把唯一 timer 安装到当前最早 absolute expiry。active parts 与
  /// completed tombstone 共用同一 TTL；空状态返回 `nil`。
  func nextAbsoluteExpiryMS(
    scope expectedScope: TransferAssemblyScope
  ) throws -> UInt64? {
    guard expectedScope == scope else { throw TransferAssemblerError.staleScope }
    return nextAbsoluteExpiryMS()
  }

  func nextAbsoluteExpiryMS() -> UInt64? {
    let configuredTTL = ttlMilliseconds
    var earliest: UInt64?
    for value in active.values {
      let expiry = Self.absoluteExpiryMS(
        after: value.startedAtMS,
        ttlMilliseconds: configuredTTL
      )
      earliest = earliest.map { min($0, expiry) } ?? expiry
    }
    for value in completed.values {
      let expiry = Self.absoluteExpiryMS(
        after: value.completedAtMS,
        ttlMilliseconds: configuredTTL
      )
      earliest = earliest.map { min($0, expiry) } ?? expiry
    }
    return earliest
  }

  @discardableResult
  mutating func sweepExpired(nowMS: UInt64) -> [RuntimeTransferID] {
    let expiredActive = active.compactMap { transferID, value in
      isExpired(value.startedAtMS, nowMS: nowMS) ? transferID : nil
    }.sorted { $0.rawValue < $1.rawValue }
    for transferID in expiredActive {
      dropActive(transferID)
    }

    // `clock` 可能回拨，completedAtMS 不保证和 insertion order 同调；固定上界只有
    // 256，直接扫描可避免较晚插入但已到期的 tombstone 被队首永久阻塞。
    let expiredCompleted = completed.compactMap { transferID, value in
      isExpired(value.completedAtMS, nowMS: nowMS) ? transferID : nil
    }
    if !expiredCompleted.isEmpty {
      let expiredSet = Set(expiredCompleted)
      completedOrder.removeAll { expiredSet.contains($0) }
      for transferID in expiredCompleted {
        guard let removed = completed.removeValue(forKey: transferID) else { continue }
        budgetCoordinator.release(removed.tombstoneReservation)
      }
    }
    return expiredActive
  }

  private func validate(_ carrier: RuntimeTransferCarrierV2) throws {
    let transfer = carrier.transfer
    let messageBytes = carrier.messageID.rawValue.utf8.count
    let transferIDBytes = transfer.transferID.rawValue.utf8.count
    let (representableBytes, representableOverflow) = UInt64(transfer.partCount)
      .multipliedReportingOverflow(by: UInt64(TransferEnvelopeV2.maxCompactPartBytes))
    guard carrier.runtimeVersion == runtimeProtocolVersionCurrent,
      messageBytes > 0,
      messageBytes <= 1_024,
      transferIDBytes > 0,
      transferIDBytes <= 1_024,
      !representableOverflow,
      transfer.partCount > 0,
      transfer.partCount <= TransferEnvelopeV2.maxCompactPartCount,
      transfer.partIndex < transfer.partCount,
      transfer.totalSHA256.count == 32,
      transfer.totalBytes <= TransferEnvelopeV2.maxTotalBytes,
      transfer.totalBytes <= representableBytes,
      transfer.part.count <= TransferEnvelopeV2.maxCompactPartBytes,
      UInt64(transfer.part.count) <= transfer.totalBytes
    else {
      throw TransferAssemblerError.tooLarge
    }
  }

  private static func absoluteExpiryMS(
    after startedAtMS: UInt64,
    ttlMilliseconds: UInt64
  ) -> UInt64 {
    let expiry = startedAtMS.addingReportingOverflow(ttlMilliseconds)
    return expiry.overflow ? .max : expiry.partialValue
  }

  private func isExpired(_ startedAtMS: UInt64, nowMS: UInt64) -> Bool {
    nowMS
      >= Self.absoluteExpiryMS(
        after: startedAtMS,
        ttlMilliseconds: ttlMilliseconds
      )
  }

  private mutating func dropActive(_ transferID: RuntimeTransferID) {
    guard let removed = active.removeValue(forKey: transferID) else { return }
    if let reservation = removed.partReservation {
      budgetCoordinator.release(reservation)
    }
    let (remaining, underflow) = bufferedBytes.subtractingReportingOverflow(removed.bufferedBytes)
    precondition(!underflow, "transfer parts accounting underflow")
    bufferedBytes = remaining
  }

  private mutating func releaseAssembly(bytes: UInt64) {
    let (remaining, underflow) = bufferedBytes.subtractingReportingOverflow(bytes)
    precondition(!underflow, "transfer assembly accounting underflow")
    bufferedBytes = remaining
  }

  private mutating func rememberCompleted(
    transferID: RuntimeTransferID,
    value: CompletedTransfer
  ) throws {
    guard completed[transferID] == nil, completed.count < maxCompletedTombstones else {
      throw TransferAssemblerError.reassemblyFull
    }
    completed[transferID] = value
    if !completedOrder.contains(transferID) {
      completedOrder.append(transferID)
    }
  }

  private static func sha256(_ data: Data) -> Data {
    Data(SHA256.hash(data: data))
  }
}

private struct TransferBinding: Sendable {
  let messageID: RuntimeMessageID
  let channel: RuntimeTransferChannelV2
  let transferID: RuntimeTransferID
  let partCount: UInt32
  let totalBytes: UInt64
  let totalSHA256: Data

  init(carrier: RuntimeTransferCarrierV2) {
    messageID = carrier.messageID
    channel = carrier.channel
    transferID = carrier.transfer.transferID
    partCount = carrier.transfer.partCount
    totalBytes = carrier.transfer.totalBytes
    totalSHA256 = carrier.transfer.totalSHA256
  }

  func matches(_ other: Self) -> Bool {
    messageID == other.messageID
      && channel.rawValue == other.channel.rawValue
      && transferID == other.transferID
      && partCount == other.partCount
      && totalBytes == other.totalBytes
      && totalSHA256 == other.totalSHA256
  }
}

private struct ActiveTransfer: Sendable {
  let binding: TransferBinding
  let startedAtMS: UInt64
  var parts: [UInt32: Data]
  var bufferedBytes: UInt64
  var partReservation: TransferAssemblyByteReservation?
}

private struct CompletedTransfer: Sendable {
  let binding: TransferBinding
  let partHashes: [UInt32: Data]
  let completedAtMS: UInt64
  let tombstoneReservation: TransferAssemblyTombstoneReservation
}
