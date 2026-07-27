import AgentDeckSessionSource

enum MachineReconnectReason: Equatable, Sendable {
  case transportFailure
  case relayUnavailable
  case machineOffline
}

enum MachineConnectionPhase: Equatable, Sendable {
  case connecting
  case online(generation: RelayTransportGeneration)
  case reconnecting(reason: MachineReconnectReason)
  case keySyncing(
    generation: RelayTransportGeneration,
    observedRevision: UInt64,
    attempt: UInt8
  )
  case terminal(failure: SessionSourceFailure)
}

enum MachineConnectionEvent: Equatable, Sendable {
  case connected(generation: RelayTransportGeneration)
  case transportFailed
  case relayUnavailable
  case machineOffline
  case keySyncRequired(observedRevision: UInt64)
  case keySyncResumed(observedRevision: UInt64, attempt: UInt8)
  case keySyncAttemptFailed(observedRevision: UInt64)
  case keySyncSucceeded(generation: RelayTransportGeneration, acceptedRevision: UInt64)
  case revoked
  case incompatible
  case securityError
}

struct MachineConnectionStateMachine: Sendable {
  private(set) var phase: MachineConnectionPhase = .connecting
  private let maximumKeySyncAttempts: UInt8

  init(maximumKeySyncAttempts: UInt8 = 3) {
    self.maximumKeySyncAttempts = max(1, maximumKeySyncAttempts)
  }

  var connectionState: SessionConnectionState {
    switch phase {
    case .connecting:
      return .connecting
    case .online:
      return .connected
    case .reconnecting(let reason):
      switch reason {
      case .transportFailure: return .reconnecting
      case .relayUnavailable: return .relayUnavailable
      case .machineOffline: return .machineOffline
      }
    case .keySyncing:
      // KeySync 只暂停 exact affected stream；同 generation 的其它 current-key
      // stream 与在线 request/reply 继续可用。
      return .connected
    case .terminal(let failure):
      switch failure.code {
      case .revoked: return .revoked
      case .incompatible: return .incompatible
      case .securityError: return .securityError
      default: return .securityError
      }
    }
  }

  var shouldFinishObservations: Bool {
    if case .terminal = phase {
      return true
    }
    return false
  }

  mutating func handle(_ event: MachineConnectionEvent) {
    guard !shouldFinishObservations else {
      return
    }

    switch event {
    case .connected(let generation):
      phase = .online(generation: generation)
    case .transportFailed:
      phase = .reconnecting(reason: .transportFailure)
    case .relayUnavailable:
      phase = .reconnecting(reason: .relayUnavailable)
    case .machineOffline:
      phase = .reconnecting(reason: .machineOffline)
    case .keySyncRequired(let observedRevision):
      guard observedRevision > 0 else {
        enterTerminal(.securityError)
        return
      }
      if case .keySyncing(_, let currentRevision, _) = phase {
        guard currentRevision == observedRevision else {
          enterTerminal(.securityError)
          return
        }
        return
      }
      guard case .online(let generation) = phase else {
        enterTerminal(.securityError)
        return
      }
      phase = .keySyncing(
        generation: generation,
        observedRevision: observedRevision,
        attempt: 1
      )
    case .keySyncResumed(let observedRevision, let attempt):
      guard observedRevision > 0,
        (1...maximumKeySyncAttempts).contains(attempt)
      else {
        enterTerminal(.securityError)
        return
      }
      guard case .online(let generation) = phase else {
        enterTerminal(.securityError)
        return
      }
      phase = .keySyncing(
        generation: generation,
        observedRevision: observedRevision,
        attempt: attempt
      )
    case .keySyncAttemptFailed(let observedRevision):
      guard
        case .keySyncing(let generation, let currentRevision, let attempt) = phase,
        currentRevision == observedRevision
      else {
        enterTerminal(.securityError)
        return
      }
      guard attempt < maximumKeySyncAttempts else {
        enterTerminal(.securityError)
        return
      }
      phase = .keySyncing(
        generation: generation,
        observedRevision: observedRevision,
        attempt: attempt + 1
      )
    case .keySyncSucceeded(let generation, let acceptedRevision):
      guard
        case .keySyncing(let currentGeneration, let observedRevision, _) = phase,
        observedRevision == acceptedRevision,
        currentGeneration == generation
      else {
        enterTerminal(.securityError)
        return
      }
      phase = .online(generation: generation)
    case .revoked:
      enterTerminal(.revoked)
    case .incompatible:
      enterTerminal(.incompatible)
    case .securityError:
      enterTerminal(.securityError)
    }
  }

  func requireOnlineGeneration() throws -> RelayTransportGeneration {
    switch phase {
    case .online(let generation), .keySyncing(let generation, _, _):
      return generation
    case .reconnecting(reason: .machineOffline):
      throw SessionSourceFailure(code: .machineOffline)
    case .terminal(let failure):
      throw failure
    case .connecting, .reconnecting:
      throw SessionSourceFailure(code: .transportUnavailable)
    }
  }

  private mutating func enterTerminal(_ code: SessionSourceFailureCode) {
    phase = .terminal(failure: SessionSourceFailure(code: code))
  }
}
