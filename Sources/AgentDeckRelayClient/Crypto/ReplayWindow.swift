import Foundation

/// 接收侧 replay tuple 的判定结果。
public enum ReplayDisposition: Equatable, Sendable {
  case fresh
  case exactDuplicate
  case stale
}

/// 可持久化的单个 `counter -> ciphertext hash` 条目。
public struct ReplayWindowEntry: Codable, Equatable, Sendable {
  public let counter: UInt64
  public let ciphertextHash: Data

  public init(counter: UInt64, ciphertextHash: Data) {
    self.counter = counter
    self.ciphertextHash = ciphertextHash
  }
}

/// ReplayWindow 的 canonical 持久化投影。
public struct ReplayWindowSnapshot: Codable, Equatable, Sendable {
  public let highWater: UInt64?
  public let floor: UInt64
  public let entries: [ReplayWindowEntry]

  public init(highWater: UInt64?, floor: UInt64, entries: [ReplayWindowEntry]) {
    self.highWater = highWater
    self.floor = floor
    self.entries = entries
  }
}

public enum ReplayWindowError: Error, Equatable, Sendable {
  case invalidSnapshot
}

/// 每个接收 key 独立的 4,096-entry replay window。
public struct ReplayWindow: Sendable {
  public static let windowSize: UInt64 = 4_096
  public static let retiredWindowRetentionMilliseconds: UInt64 = 25 * 60 * 60 * 1_000

  private var highWater: UInt64?
  private var floor: UInt64
  private var hashes: [UInt64: Data]

  public init() {
    highWater = nil
    floor = 0
    hashes = [:]
  }

  public init(snapshot: ReplayWindowSnapshot) throws {
    try Self.validate(snapshot)
    highWater = snapshot.highWater
    floor = snapshot.floor
    hashes = Dictionary(
      uniqueKeysWithValues: snapshot.entries.map {
        ($0.counter, $0.ciphertextHash)
      })
  }

  public var snapshot: ReplayWindowSnapshot {
    ReplayWindowSnapshot(
      highWater: highWater,
      floor: floor,
      entries: hashes.keys.sorted().map {
        ReplayWindowEntry(counter: $0, ciphertextHash: hashes[$0]!)
      }
    )
  }

  /// 先按 floor 淘汰历史，再在窗口内区分精确重传与 nonce reuse。
  public mutating func observe(
    counter: UInt64,
    ciphertextHash: Data
  ) throws -> ReplayDisposition {
    guard ciphertextHash.count == 32 else {
      throw RelayCryptoError.invalidLength(
        field: "ciphertextHash",
        expected: 32,
        actual: ciphertextHash.count
      )
    }
    if counter < floor {
      return .stale
    }
    if let previous = hashes[counter] {
      guard previous == ciphertextHash else {
        throw RelayCryptoError.nonceReuse
      }
      return .exactDuplicate
    }

    if highWater.map({ counter > $0 }) ?? true {
      highWater = counter
      floor = Self.floor(for: counter)
      hashes = hashes.filter { $0.key >= floor }
    }
    hashes[counter] = ciphertextHash
    return .fresh
  }

  private static func floor(for highWater: UInt64) -> UInt64 {
    let retainedBeforeHighWater = windowSize - 1
    return highWater >= retainedBeforeHighWater
      ? highWater - retainedBeforeHighWater
      : 0
  }

  private static func validate(_ snapshot: ReplayWindowSnapshot) throws {
    guard let highWater = snapshot.highWater else {
      guard snapshot.floor == 0, snapshot.entries.isEmpty else {
        throw ReplayWindowError.invalidSnapshot
      }
      return
    }
    guard snapshot.floor == floor(for: highWater),
      !snapshot.entries.isEmpty,
      snapshot.entries.count <= Int(windowSize),
      snapshot.entries.last?.counter == highWater
    else {
      throw ReplayWindowError.invalidSnapshot
    }

    var previousCounter: UInt64?
    for entry in snapshot.entries {
      guard entry.ciphertextHash.count == 32,
        entry.counter >= snapshot.floor,
        entry.counter <= highWater,
        previousCounter.map({ entry.counter > $0 }) ?? true
      else {
        throw ReplayWindowError.invalidSnapshot
      }
      previousCounter = entry.counter
    }
  }
}
