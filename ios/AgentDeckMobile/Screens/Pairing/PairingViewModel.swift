import AgentDeckCore
import AgentDeckSessionSource
import Foundation

enum PairInviteInput {
  static let prefix = "agentdeck-pair:v1:"
  static let maximumUTF8Bytes = 8 * 1_024

  static func normalized(_ rawValue: String) -> String? {
    let value = rawValue.trimmingCharacters(in: .whitespacesAndNewlines)
    guard value.utf8.count <= maximumUTF8Bytes,
      value.hasPrefix(prefix), value.count > prefix.count,
      value.dropFirst(prefix.count).allSatisfy({
        $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_")
      })
    else {
      return nil
    }
    return value
  }
}

enum PairingViewState: Equatable {
  case idle
  case inspecting
  case awaitingConfirmation(PairingPreview)
  case pairing(PairingProgress)
  case paired(PairedMachine)
  case canceled
  case expired
  case failed(SessionSourceFailure, retryable: Bool)
}

enum LocalForgetConfirmationStep: Equatable {
  case warnResidualGrant
  case confirmDestructiveRemoval
}

enum PairingMachineActionState: Equatable {
  case idle
  case revoking(machineID: String)
  case waitingForVerifiedRevocation(machineID: String)
  case confirmLocalForget(machineID: String, step: LocalForgetConfirmationStep)
  case forgettingLocal(machineID: String)
  case failed(machineID: String, error: SessionSourceFailure, retryable: Bool)
}

/// 本地 paired material 的窄删除能力。在线 revoke 只有在 machines stream 发布
/// 已验证 `.revoked` terminal 后才能调用；`.committed` receipt 只表示 daemon 已持久化
/// revoke 请求。离线 forget 必须由 UI 完成两次明确确认。
protocol LocalPairedMachineManaging: Sendable {
  func forgetLocal(machineID: String) async throws
}

private struct RejectingLocalPairedMachineManager: LocalPairedMachineManaging {
  func forgetLocal(machineID: String) async throws {
    _ = machineID
    throw SessionSourceFailure(code: .storageUnavailable)
  }
}

@MainActor
final class PairingViewModel {
  private let source: any SessionSource
  private let localStore: any LocalPairedMachineManaging

  private(set) var pairingState: PairingViewState = .idle
  private(set) var machineActionState: PairingMachineActionState = .idle
  private(set) var machines: [MachineSummary] = []
  private(set) var inspectedInvite: String?
  private(set) var preview: PairingPreview?

  var onUpdate: (() -> Void)?
  var onPaired: ((PairedMachine) -> Void)?
  var onLocalStoreChanged: (() -> Void)?

  private var inspectionTask: Task<Void, Never>?
  private var pairingTask: Task<Void, Never>?
  private var machineTask: Task<Void, Never>?
  private var machineActionTask: Task<Void, Never>?
  private var inspectionGeneration = UUID()
  private var pairingOperationID: UUID?
  private var offlineMachineIDs: Set<String> = []

  init(
    source: any SessionSource,
    localStore: any LocalPairedMachineManaging = RejectingLocalPairedMachineManager()
  ) {
    self.source = source
    self.localStore = localStore
  }

  func start() {
    guard machineTask == nil else { return }
    let source = source
    machineTask = Task { [weak self, source] in
      let stream = await source.machines()
      for await state in stream {
        guard !Task.isCancelled, let self else { break }
        consumeMachines(state)
      }
      guard let self else { return }
      machineTask = nil
    }
  }

  func inspectInvite(_ rawValue: String) {
    guard let encoded = PairInviteInput.normalized(rawValue) else {
      inspectionGeneration = UUID()
      inspectionTask?.cancel()
      inspectionTask = nil
      cancelPairingTask()
      preview = nil
      inspectedInvite = nil
      setPairingState(
        .failed(
          SessionSourceFailure(code: .invalidPairInvite),
          retryable: false
        )
      )
      return
    }

    inspectionTask?.cancel()
    cancelPairingTask()
    let generation = UUID()
    inspectionGeneration = generation
    inspectedInvite = encoded
    preview = nil
    setPairingState(.inspecting)
    let source = source
    inspectionTask = Task { [weak self, source, encoded] in
      do {
        let inspected = try await source.inspectPairInvite(encoded)
        guard !Task.isCancelled, let self,
          inspectionGeneration == generation,
          inspectedInvite == encoded
        else { return }
        preview = inspected
        inspectionTask = nil
        setPairingState(.awaitingConfirmation(inspected))
      } catch is CancellationError {
        guard let self, inspectionGeneration == generation else { return }
        inspectionTask = nil
      } catch {
        guard !Task.isCancelled, let self,
          inspectionGeneration == generation
        else { return }
        inspectionTask = nil
        let failure = Self.publicFailure(error)
        setPairingState(
          .failed(failure, retryable: Self.isRetryable(failure))
        )
      }
    }
  }

  func confirmPairing() {
    guard case .awaitingConfirmation = pairingState,
      let encoded = inspectedInvite,
      pairingTask == nil
    else { return }
    beginPairing(encodedInvite: encoded)
  }

  func retryPairing() {
    guard case .failed(_, let retryable) = pairingState,
      retryable,
      let encoded = inspectedInvite,
      preview != nil,
      pairingTask == nil
    else { return }
    beginPairing(encodedInvite: encoded)
  }

  func revoke(machineID: String) {
    guard !machineID.isEmpty, machineActionTask == nil else { return }
    machineActionState = .revoking(machineID: machineID)
    onUpdate?()
    let source = source
    machineActionTask = Task { [weak self, source, machineID] in
      do {
        let receipt = try await source.revokeSelf(machineID: machineID)
        guard !Task.isCancelled, let self else { return }
        machineActionTask = nil
        switch receipt {
        case .committed:
          machineActionState = .waitingForVerifiedRevocation(machineID: machineID)
        case .failed(let failure):
          machineActionState = .failed(
            machineID: machineID,
            error: SessionSourceFailure(
              code: .commandRejected,
              message: failure.message,
              diagnosticReference: failure.diagnosticRef
            ),
            retryable: false
          )
        }
        onUpdate?()
      } catch is CancellationError {
        guard let self else { return }
        machineActionTask = nil
      } catch {
        guard !Task.isCancelled, let self else { return }
        machineActionTask = nil
        let failure = Self.publicFailure(error)
        machineActionState = .failed(
          machineID: machineID,
          error: failure,
          retryable: Self.isRetryable(failure)
        )
        onUpdate?()
      }
    }
  }

  func beginLocalForget(machineID: String) {
    guard !machineID.isEmpty, machineActionTask == nil else { return }
    guard validateLocalForgetEligibility(machineID: machineID) else { return }
    machineActionState = .confirmLocalForget(
      machineID: machineID,
      step: .warnResidualGrant
    )
    onUpdate?()
  }

  func confirmLocalForget(machineID: String) {
    guard
      case .confirmLocalForget(let expectedMachineID, let step) = machineActionState,
      expectedMachineID == machineID,
      machineActionTask == nil
    else { return }
    guard validateLocalForgetEligibility(machineID: machineID) else { return }
    switch step {
    case .warnResidualGrant:
      machineActionState = .confirmLocalForget(
        machineID: machineID,
        step: .confirmDestructiveRemoval
      )
      onUpdate?()
    case .confirmDestructiveRemoval:
      forgetLocal(machineID: machineID)
    }
  }

  func cancelLocalForget() {
    guard case .confirmLocalForget = machineActionState else { return }
    machineActionState = .idle
    onUpdate?()
  }

  func cancelActiveTasks() {
    inspectionGeneration = UUID()
    inspectionTask?.cancel()
    inspectionTask = nil
    cancelPairingTask()
    machineActionTask?.cancel()
    machineActionTask = nil
  }

  private func beginPairing(encodedInvite: String) {
    let operationID = UUID()
    pairingOperationID = operationID
    setPairingState(.pairing(.preparing))
    let source = source
    pairingTask = Task { [weak self, source, encodedInvite, operationID] in
      do {
        let stream = try await source.pair(encodedInvite)
        for try await progress in stream {
          guard !Task.isCancelled, let self,
            pairingOperationID == operationID
          else { return }
          switch progress {
          case .preparing, .waitingForLocalConfirmation:
            setPairingState(.pairing(progress))
          case .paired(let machine):
            finishPairingOperation(operationID)
            setPairingState(.paired(machine))
            onPaired?(machine)
            return
          case .canceled:
            finishPairingOperation(operationID)
            setPairingState(.canceled)
            return
          case .expired:
            finishPairingOperation(operationID)
            setPairingState(.expired)
            return
          }
        }
        guard !Task.isCancelled, let self,
          pairingOperationID == operationID
        else { return }
        finishPairingOperation(operationID)
        setPairingState(
          .failed(
            SessionSourceFailure(code: .transportUnavailable),
            retryable: true
          )
        )
      } catch is CancellationError {
        guard let self, pairingOperationID == operationID else { return }
        finishPairingOperation(operationID)
      } catch {
        guard !Task.isCancelled, let self,
          pairingOperationID == operationID
        else { return }
        finishPairingOperation(operationID)
        let failure = Self.publicFailure(error)
        setPairingState(
          .failed(failure, retryable: Self.isRetryable(failure))
        )
      }
    }
  }

  private func consumeMachines(_ state: ResourceState<[MachineSummary]>) {
    switch state {
    case .loading(let previous):
      if let previous { machines = previous }
    case .ready(let value, _), .stale(let value, _):
      machines = value
    case .failed:
      machines = []
    }
    offlineMachineIDs = Set(
      machines.compactMap { machine in
        switch machine.connectionState {
        case .relayUnavailable, .machineOffline:
          machine.id
        case .connecting, .connected, .reconnecting, .lagged, .revoked,
          .incompatible, .securityError:
          nil
        }
      }
    )
    if case .confirmLocalForget(let machineID, _) = machineActionState,
      !offlineMachineIDs.contains(machineID)
    {
      machineActionState = Self.localForgetEligibilityFailure(machineID: machineID)
    }
    onUpdate?()
  }

  private func forgetLocal(machineID: String) {
    guard validateLocalForgetEligibility(machineID: machineID) else { return }
    machineActionState = .forgettingLocal(machineID: machineID)
    onUpdate?()
    let localStore = localStore
    machineActionTask = Task { [weak self, localStore, machineID] in
      do {
        try await localStore.forgetLocal(machineID: machineID)
        guard !Task.isCancelled, let self else { return }
        machineActionTask = nil
        offlineMachineIDs.remove(machineID)
        machineActionState = .idle
        onLocalStoreChanged?()
        onUpdate?()
      } catch is CancellationError {
        guard let self else { return }
        machineActionTask = nil
      } catch {
        guard !Task.isCancelled, let self else { return }
        machineActionTask = nil
        machineActionState = .failed(
          machineID: machineID,
          error: Self.publicFailure(error),
          retryable: false
        )
        onUpdate?()
      }
    }
  }

  private func cancelPairingTask() {
    pairingOperationID = nil
    pairingTask?.cancel()
    pairingTask = nil
  }

  private func finishPairingOperation(_ operationID: UUID) {
    guard pairingOperationID == operationID else { return }
    pairingOperationID = nil
    pairingTask = nil
  }

  @discardableResult
  private func validateLocalForgetEligibility(machineID: String) -> Bool {
    guard offlineMachineIDs.contains(machineID) else {
      machineActionState = Self.localForgetEligibilityFailure(machineID: machineID)
      onUpdate?()
      return false
    }
    return true
  }

  private static func localForgetEligibilityFailure(
    machineID: String
  ) -> PairingMachineActionState {
    .failed(
      machineID: machineID,
      error: SessionSourceFailure(
        code: .commandRejected,
        message: "机器已恢复在线或尚未确认离线；请使用在线撤销"
      ),
      retryable: false
    )
  }

  private func setPairingState(_ state: PairingViewState) {
    pairingState = state
    onUpdate?()
  }

  private static func publicFailure(_ error: any Error) -> SessionSourceFailure {
    if let failure = error as? SessionSourceFailure { return failure }
    return SessionSourceFailure(code: .unknown)
  }

  private static func isRetryable(_ failure: SessionSourceFailure) -> Bool {
    switch failure.code {
    case .transportUnavailable, .machineOffline:
      true
    case .revoked, .incompatible, .securityError, .invalidPairInvite,
      .pairInviteExpired, .commandRejected, .storageUnavailable, .unknown:
      false
    }
  }

  deinit {
    inspectionTask?.cancel()
    pairingTask?.cancel()
    machineTask?.cancel()
    machineActionTask?.cancel()
  }
}
