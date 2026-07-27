import Foundation
import os

struct TransferAssemblyBudgetUsage: Equatable, Sendable {
  let reassemblyBytes: UInt64
  let completedTombstones: Int
  let reservationCount: Int
}

struct TransferAssemblyByteReservation: Equatable, Hashable, Sendable {
  fileprivate let coordinatorID: UUID
  fileprivate let reservationID: UInt64
  fileprivate let scope: TransferAssemblyScope
}

struct TransferAssemblyTombstoneReservation: Equatable, Hashable, Sendable {
  fileprivate let coordinatorID: UUID
  fileprivate let reservationID: UInt64
  fileprivate let scope: TransferAssemblyScope
}

/// 进程内全部 `MachineConnection` 共用的易失 transfer 预算 owner。
///
/// 本类型只在一个极短的同步临界区内完成 checked projection 与 token 记账；它不持有
/// payload，也不在锁内执行 Data allocation、hash 或回调。`MachineConnection` actor
/// 负责单连接顺序，协调器负责跨 actor 的 process-global 原子上界。
public final class TransferAssemblyBudgetCoordinator: Sendable {
  public static let maximumReassemblyBytes: UInt64 = 512 * 1_024 * 1_024
  public static let maximumCompletedTombstones = 8_192

  /// production composition root 必须把同一实例注入全部 `MachineConnection`。
  public static let shared = TransferAssemblyBudgetCoordinator()

  private enum ByteReservationKind: Sendable {
    case partCache
    case finalAssembly
  }

  private enum ReservationEntry: Sendable {
    case bytes(
      scope: TransferAssemblyScope,
      kind: ByteReservationKind,
      bytes: UInt64
    )
    case tombstone(scope: TransferAssemblyScope)

    var scope: TransferAssemblyScope {
      switch self {
      case .bytes(let scope, _, _), .tombstone(let scope):
        scope
      }
    }
  }

  private struct State: Sendable {
    var nextReservationID: UInt64 = 1
    var reassemblyBytes: UInt64 = 0
    var completedTombstones = 0
    var reservations: [UInt64: ReservationEntry] = [:]
    var reservationsByScope: [TransferAssemblyScope: Set<UInt64>] = [:]
    var poisoned = false
  }

  private let coordinatorID = UUID()
  private let maximumReassemblyBytesValue: UInt64
  private let maximumCompletedTombstonesValue: Int
  private let state = OSAllocatedUnfairLock(initialState: State())

  public convenience init() {
    self.init(
      maximumReassemblyBytes: Self.maximumReassemblyBytes,
      maximumCompletedTombstones: Self.maximumCompletedTombstones
    )
  }

  init(
    maximumReassemblyBytes: UInt64,
    maximumCompletedTombstones: Int
  ) {
    precondition(
      maximumReassemblyBytes > 0
        && maximumReassemblyBytes <= Self.maximumReassemblyBytes
    )
    precondition(
      maximumCompletedTombstones > 0
        && maximumCompletedTombstones <= Self.maximumCompletedTombstones
    )
    maximumReassemblyBytesValue = maximumReassemblyBytes
    maximumCompletedTombstonesValue = maximumCompletedTombstones
  }

  var usage: TransferAssemblyBudgetUsage {
    state.withLock {
      TransferAssemblyBudgetUsage(
        reassemblyBytes: $0.reassemblyBytes,
        completedTombstones: $0.completedTombstones,
        reservationCount: $0.reservations.count
      )
    }
  }

  /// 为同一 active transfer 原子新建或增长 parts-cache reservation。
  /// 调用方必须在把 unique part 留入 assembler state 之前调用。
  func reservePartBytes(
    scope: TransferAssemblyScope,
    reservation: TransferAssemblyByteReservation?,
    additionalBytes: UInt64
  ) throws -> TransferAssemblyByteReservation {
    try state.withLock { state in
      guard !state.poisoned else { throw TransferAssemblerError.reassemblyFull }

      if let reservation {
        guard reservation.coordinatorID == coordinatorID,
          reservation.scope == scope,
          case .bytes(let entryScope, .partCache, let currentBytes) =
            state.reservations[reservation.reservationID],
          entryScope == scope
        else {
          throw TransferAssemblerError.staleScope
        }

        let nextGlobal = try Self.checkedProjection(
          current: state.reassemblyBytes,
          additional: additionalBytes,
          limit: maximumReassemblyBytesValue
        )
        let (nextReservationBytes, reservationOverflow) = currentBytes.addingReportingOverflow(
          additionalBytes
        )
        guard !reservationOverflow else {
          throw TransferAssemblerError.reassemblyFull
        }

        state.reservations[reservation.reservationID] = .bytes(
          scope: scope,
          kind: .partCache,
          bytes: nextReservationBytes
        )
        state.reassemblyBytes = nextGlobal
        return reservation
      }

      let nextGlobal = try Self.checkedProjection(
        current: state.reassemblyBytes,
        additional: additionalBytes,
        limit: maximumReassemblyBytesValue
      )
      let reservationID = try Self.takeReservationID(state: &state)
      state.reservations[reservationID] = .bytes(
        scope: scope,
        kind: .partCache,
        bytes: additionalBytes
      )
      state.reservationsByScope[scope, default: []].insert(reservationID)
      state.reassemblyBytes = nextGlobal
      return TransferAssemblyByteReservation(
        coordinatorID: coordinatorID,
        reservationID: reservationID,
        scope: scope
      )
    }
  }

  /// 在 final assembly buffer allocation 之前原子预留完整 copy 的峰值。
  func reserveAssemblyBytes(
    scope: TransferAssemblyScope,
    bytes: UInt64
  ) throws -> TransferAssemblyByteReservation {
    try state.withLock { state in
      guard !state.poisoned else { throw TransferAssemblerError.reassemblyFull }
      let nextGlobal = try Self.checkedProjection(
        current: state.reassemblyBytes,
        additional: bytes,
        limit: maximumReassemblyBytesValue
      )
      let reservationID = try Self.takeReservationID(state: &state)
      state.reservations[reservationID] = .bytes(
        scope: scope,
        kind: .finalAssembly,
        bytes: bytes
      )
      state.reservationsByScope[scope, default: []].insert(reservationID)
      state.reassemblyBytes = nextGlobal
      return TransferAssemblyByteReservation(
        coordinatorID: coordinatorID,
        reservationID: reservationID,
        scope: scope
      )
    }
  }

  /// completed metadata/part hash allocation 前预留全局 tombstone 槽。
  func reserveTombstone(
    scope: TransferAssemblyScope
  ) throws -> TransferAssemblyTombstoneReservation {
    try state.withLock { state in
      guard !state.poisoned else { throw TransferAssemblerError.reassemblyFull }
      let (nextCount, overflow) = state.completedTombstones.addingReportingOverflow(1)
      guard !overflow, nextCount <= maximumCompletedTombstonesValue else {
        throw TransferAssemblerError.reassemblyFull
      }
      let reservationID = try Self.takeReservationID(state: &state)
      state.reservations[reservationID] = .tombstone(scope: scope)
      state.reservationsByScope[scope, default: []].insert(reservationID)
      state.completedTombstones = nextCount
      return TransferAssemblyTombstoneReservation(
        coordinatorID: coordinatorID,
        reservationID: reservationID,
        scope: scope
      )
    }
  }

  func release(_ reservation: TransferAssemblyByteReservation) {
    guard reservation.coordinatorID == coordinatorID else { return }
    state.withLock { state in
      guard
        case .bytes(let scope, _, let bytes) = state.reservations[reservation.reservationID],
        scope == reservation.scope
      else { return }
      let (remaining, underflow) = state.reassemblyBytes.subtractingReportingOverflow(bytes)
      guard !underflow else {
        state.poisoned = true
        return
      }
      state.reservations.removeValue(forKey: reservation.reservationID)
      Self.removeFromScopeIndex(
        reservationID: reservation.reservationID,
        scope: scope,
        state: &state
      )
      state.reassemblyBytes = remaining
    }
  }

  func release(_ reservation: TransferAssemblyTombstoneReservation) {
    guard reservation.coordinatorID == coordinatorID else { return }
    state.withLock { state in
      guard
        case .tombstone(let scope) = state.reservations[reservation.reservationID],
        scope == reservation.scope
      else { return }
      let (remaining, underflow) = state.completedTombstones.subtractingReportingOverflow(1)
      guard !underflow else {
        state.poisoned = true
        return
      }
      state.reservations.removeValue(forKey: reservation.reservationID)
      Self.removeFromScopeIndex(
        reservationID: reservation.reservationID,
        scope: scope,
        state: &state
      )
      state.completedTombstones = remaining
    }
  }

  /// disconnect/reset/owner teardown 的 exact-scope 最终兜底；迟到 token release 为幂等 no-op。
  func releaseAll(scope: TransferAssemblyScope) {
    state.withLock { state in
      guard let reservationIDs = state.reservationsByScope[scope] else { return }

      var byteRelease: UInt64 = 0
      var tombstoneRelease = 0
      for reservationID in reservationIDs {
        guard let entry = state.reservations[reservationID], entry.scope == scope else {
          state.poisoned = true
          return
        }
        switch entry {
        case .bytes(_, _, let bytes):
          let (next, overflow) = byteRelease.addingReportingOverflow(bytes)
          guard !overflow else {
            state.poisoned = true
            return
          }
          byteRelease = next
        case .tombstone:
          let (next, overflow) = tombstoneRelease.addingReportingOverflow(1)
          guard !overflow else {
            state.poisoned = true
            return
          }
          tombstoneRelease = next
        }
      }

      let (remainingBytes, byteUnderflow) = state.reassemblyBytes.subtractingReportingOverflow(
        byteRelease
      )
      let (remainingTombstones, tombstoneUnderflow) = state.completedTombstones
        .subtractingReportingOverflow(tombstoneRelease)
      guard !byteUnderflow, !tombstoneUnderflow else {
        state.poisoned = true
        return
      }

      for reservationID in reservationIDs {
        state.reservations.removeValue(forKey: reservationID)
      }
      state.reservationsByScope.removeValue(forKey: scope)
      state.reassemblyBytes = remainingBytes
      state.completedTombstones = remainingTombstones
    }
  }

  private static func checkedProjection(
    current: UInt64,
    additional: UInt64,
    limit: UInt64
  ) throws -> UInt64 {
    let (projected, overflow) = current.addingReportingOverflow(additional)
    guard !overflow, projected <= limit else {
      throw TransferAssemblerError.reassemblyFull
    }
    return projected
  }

  private static func takeReservationID(state: inout State) throws -> UInt64 {
    let reservationID = state.nextReservationID
    guard reservationID != 0, state.reservations[reservationID] == nil else {
      throw TransferAssemblerError.reassemblyFull
    }
    let (next, overflow) = reservationID.addingReportingOverflow(1)
    guard !overflow else { throw TransferAssemblerError.reassemblyFull }
    state.nextReservationID = next
    return reservationID
  }

  private static func removeFromScopeIndex(
    reservationID: UInt64,
    scope: TransferAssemblyScope,
    state: inout State
  ) {
    guard var reservationIDs = state.reservationsByScope[scope] else {
      state.poisoned = true
      return
    }
    reservationIDs.remove(reservationID)
    if reservationIDs.isEmpty {
      state.reservationsByScope.removeValue(forKey: scope)
    } else {
      state.reservationsByScope[scope] = reservationIDs
    }
  }
}
