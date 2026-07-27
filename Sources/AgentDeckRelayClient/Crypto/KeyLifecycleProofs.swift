import AgentDeckCore
import Foundation

/// 已从 authenticated MachineData carrier 解出的 exact EpochBarrier 投影。
///
/// 本类型只做 Rust canonical/shape 校验；production caller 仍必须先完成 outer signature、
/// replay 与 staged-key AEAD open，Durable coordinator 再对账本地 committed cut。
struct DeviceEpochBarrierV1: Equatable, Sendable, CustomDebugStringConvertible {
  private static let domain = Data("AgentDeck/EpochBarrierV1\0".utf8)
  private static let maximumConversationIDBytes = 1_024

  let streamRoute: Data
  let streamGeneration: Data
  let streamCursor: StreamCursor
  let innerCursor: DeviceInnerCursorV1
  let oldEpoch: UInt64
  let newEpoch: UInt64
  let keyDirectoryRevision: UInt64
  let canonicalBytes: Data
  let canonicalSHA256: Data
  let appliedStreamSequence: UInt64

  init(
    streamRoute: Data,
    streamGeneration: Data,
    streamCursor: StreamCursor,
    innerCursor: DeviceInnerCursorV1,
    oldEpoch: UInt64,
    newEpoch: UInt64,
    keyDirectoryRevision: UInt64
  ) throws {
    let nextEpoch = oldEpoch.addingReportingOverflow(1)
    let applied = try Self.checkedNext(streamCursor)
    guard Self.isNonzero(streamRoute, count: 16),
      Self.isNonzero(streamGeneration, count: 16),
      !nextEpoch.overflow,
      newEpoch == nextEpoch.partialValue,
      newEpoch > 0,
      keyDirectoryRevision > 0,
      applied < UInt64.max
    else {
      throw DeviceKeyLifecycleError.invalidBarrier
    }
    if case .conversation(let id, _) = innerCursor {
      guard !id.isEmpty,
        id.utf8.count <= Self.maximumConversationIDBytes
      else {
        throw DeviceKeyLifecycleError.invalidBarrier
      }
    }
    self.streamRoute = streamRoute
    self.streamGeneration = streamGeneration
    self.streamCursor = streamCursor
    self.innerCursor = innerCursor
    self.oldEpoch = oldEpoch
    self.newEpoch = newEpoch
    self.keyDirectoryRevision = keyDirectoryRevision
    appliedStreamSequence = applied

    var canonical = Self.domain
    Self.appendBytes(streamGeneration, to: &canonical)
    Self.appendCursor(streamCursor, to: &canonical)
    switch innerCursor {
    case .catalog(let cursor):
      canonical.append(0)
      Self.appendCursor(cursor, to: &canonical)
    case .conversation(let id, let cursor):
      canonical.append(1)
      Self.appendBytes(Data(id.utf8), to: &canonical)
      Self.appendCursor(cursor, to: &canonical)
    }
    Self.appendInteger(oldEpoch, to: &canonical)
    Self.appendInteger(newEpoch, to: &canonical)
    Self.appendInteger(keyDirectoryRevision, to: &canonical)
    canonicalBytes = canonical
    canonicalSHA256 = CanonicalCodec.sha256(canonical)
  }

  var debugDescription: String {
    "DeviceEpochBarrierV1(scope: <redacted>, revision: \(keyDirectoryRevision))"
  }

  private static func checkedNext(_ cursor: StreamCursor) throws -> UInt64 {
    switch cursor {
    case .beforeFirst:
      return 0
    case .at(let value):
      let next = value.addingReportingOverflow(1)
      guard !next.overflow, next.partialValue < UInt64.max else {
        throw DeviceKeyLifecycleError.invalidBarrier
      }
      return next.partialValue
    }
  }

  private static func appendCursor(_ cursor: StreamCursor, to output: inout Data) {
    switch cursor {
    case .beforeFirst:
      output.append(0)
    case .at(let value):
      output.append(1)
      appendInteger(value, to: &output)
    }
  }

  private static func appendBytes(_ value: Data, to output: inout Data) {
    appendInteger(UInt32(value.count), to: &output)
    output.append(value)
  }

  private static func appendInteger<T: FixedWidthInteger>(
    _ value: T,
    to output: inout Data
  ) {
    var encoded = value.bigEndian
    Swift.withUnsafeBytes(of: &encoded) { output.append(contentsOf: $0) }
  }

  private static func isNonzero(_ value: Data, count: Int) -> Bool {
    value.count == count && value.contains(where: { $0 != 0 })
  }
}

/// ActivateConversation 在 current Catalog key 下承载的 revision-only proof。
struct DeviceDirectoryRevisionAdvanceV1: Equatable, Sendable, CustomDebugStringConvertible {
  private static let domain = Data("AgentDeck/DirectoryRevisionAdvanceV1\0".utf8)

  let streamRoute: Data
  let streamGeneration: Data
  let streamSequence: UInt64
  let fromRevision: UInt64
  let toRevision: UInt64
  let canonicalBytes: Data
  let canonicalSHA256: Data

  init(
    streamRoute: Data,
    streamGeneration: Data,
    streamSequence: UInt64,
    fromRevision: UInt64,
    toRevision: UInt64
  ) throws {
    let next = fromRevision.addingReportingOverflow(1)
    guard Self.isNonzero(streamRoute, count: 16),
      Self.isNonzero(streamGeneration, count: 16),
      streamSequence < UInt64.max,
      fromRevision > 0,
      !next.overflow,
      toRevision == next.partialValue
    else {
      throw DeviceKeyLifecycleError.invalidDirectoryAdvance
    }
    self.streamRoute = streamRoute
    self.streamGeneration = streamGeneration
    self.streamSequence = streamSequence
    self.fromRevision = fromRevision
    self.toRevision = toRevision
    var canonical = Self.domain
    Self.appendInteger(fromRevision, to: &canonical)
    Self.appendInteger(toRevision, to: &canonical)
    canonicalBytes = canonical
    canonicalSHA256 = CanonicalCodec.sha256(canonical)
  }

  var debugDescription: String {
    "DeviceDirectoryRevisionAdvanceV1(revision: \(fromRevision)->\(toRevision))"
  }

  private static func appendInteger<T: FixedWidthInteger>(
    _ value: T,
    to output: inout Data
  ) {
    var encoded = value.bigEndian
    Swift.withUnsafeBytes(of: &encoded) { output.append(contentsOf: $0) }
  }

  private static func isNonzero(_ value: Data, count: Int) -> Bool {
    value.count == count && value.contains(where: { $0 != 0 })
  }
}
