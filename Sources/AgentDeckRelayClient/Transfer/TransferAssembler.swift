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
/// binding、TTL、内存预算、幂等和完整 SHA-256。connection 断开时必须调用 `reset()`。
public struct TransferAssembler: Sendable {
  public static let maximumActiveTransfers = 64
  public static let maximumReassemblyBytes: UInt64 = 128 * 1024 * 1024
  public static let transferTTLMilliseconds: UInt64 = 300_000
  public static let maximumCompletedTombstones = 256

  private let maxActiveTransfers: Int
  private let maxReassemblyBytes: UInt64
  private let ttlMilliseconds: UInt64
  private let maxCompletedTombstones: Int
  private let scope: TransferAssemblyScope

  private var active: [RuntimeTransferID: ActiveTransfer] = [:]
  private var completed: [RuntimeTransferID: CompletedTransfer] = [:]
  private var completedOrder: [RuntimeTransferID] = []
  private(set) var bufferedBytes: UInt64 = 0

  public init(scope: TransferAssemblyScope) {
    self.scope = scope
    maxActiveTransfers = Self.maximumActiveTransfers
    maxReassemblyBytes = Self.maximumReassemblyBytes
    ttlMilliseconds = Self.transferTTLMilliseconds
    maxCompletedTombstones = Self.maximumCompletedTombstones
  }

  init() {
    scope = TransferAssemblyScope(
      connectionID: UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1)),
      generation: RelayTransportGeneration(rawValue: 1)
    )
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
    self.maxActiveTransfers = maxActiveTransfers
    self.maxReassemblyBytes = maxReassemblyBytes
    self.ttlMilliseconds = ttlMilliseconds
    self.maxCompletedTombstones = maxCompletedTombstones
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
        bufferedBytes: 0
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
    bufferedBytes = peakBytes

    var assembled = Data()
    assembled.reserveCapacity(Int(assemblyBytes))
    for index in 0..<current.binding.partCount {
      guard let bytes = current.parts[index] else {
        dropActive(transferID)
        releaseAssembly(bytes: assemblyBytes)
        throw TransferAssemblerError.hashMismatch
      }
      assembled.append(bytes)
    }
    let partHashes = current.parts.mapValues(Self.sha256)
    dropActive(transferID)
    releaseAssembly(bytes: assemblyBytes)

    guard Self.sha256(assembled) == current.binding.totalSHA256 else {
      throw TransferAssemblerError.hashMismatch
    }
    try rememberCompleted(
      transferID: transferID,
      value: CompletedTransfer(
        binding: current.binding,
        partHashes: partHashes,
        completedAtMS: nowMS
      )
    )
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

  mutating func reset() {
    active.removeAll(keepingCapacity: false)
    completed.removeAll(keepingCapacity: false)
    completedOrder.removeAll(keepingCapacity: false)
    bufferedBytes = 0
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

  @discardableResult
  mutating func sweepExpired(nowMS: UInt64) -> [RuntimeTransferID] {
    let expiredActive = active.compactMap { transferID, value in
      isExpired(value.startedAtMS, nowMS: nowMS) ? transferID : nil
    }.sorted { $0.rawValue < $1.rawValue }
    for transferID in expiredActive {
      dropActive(transferID)
    }

    while let oldestID = completedOrder.first {
      guard let tombstone = completed[oldestID] else {
        completedOrder.removeFirst()
        continue
      }
      guard isExpired(tombstone.completedAtMS, nowMS: nowMS) else { break }
      completedOrder.removeFirst()
      completed.removeValue(forKey: oldestID)
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

  private func isExpired(_ startedAtMS: UInt64, nowMS: UInt64) -> Bool {
    let elapsed = nowMS >= startedAtMS ? nowMS - startedAtMS : 0
    return elapsed >= ttlMilliseconds
  }

  private mutating func dropActive(_ transferID: RuntimeTransferID) {
    guard let removed = active.removeValue(forKey: transferID) else { return }
    bufferedBytes =
      bufferedBytes >= removed.bufferedBytes
      ? bufferedBytes - removed.bufferedBytes
      : 0
  }

  private mutating func releaseAssembly(bytes: UInt64) {
    bufferedBytes = bufferedBytes >= bytes ? bufferedBytes - bytes : 0
  }

  private mutating func rememberCompleted(
    transferID: RuntimeTransferID,
    value: CompletedTransfer
  ) throws {
    guard completed[transferID] != nil || completed.count < maxCompletedTombstones else {
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
}

private struct CompletedTransfer: Sendable {
  let binding: TransferBinding
  let partHashes: [UInt32: Data]
  let completedAtMS: UInt64
}
