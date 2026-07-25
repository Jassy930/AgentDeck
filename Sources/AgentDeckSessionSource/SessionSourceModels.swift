import AgentDeckCore
import Foundation

@frozen
public enum SessionSourceFailureCode: String, Codable, CaseIterable, Sendable {
  case transportUnavailable
  case machineOffline
  case revoked
  case incompatible
  case securityError
  case invalidPairInvite
  case pairInviteExpired
  case commandRejected
  case storageUnavailable
  case unknown
}

public struct SessionSourceFailure: Error, Equatable, Sendable {
  public let code: SessionSourceFailureCode
  public let message: String?
  public let diagnosticReference: String?

  public init(
    code: SessionSourceFailureCode,
    message: String? = nil,
    diagnosticReference: String? = nil
  ) {
    self.code = code
    self.message = message
    self.diagnosticReference = diagnosticReference
  }

}

@frozen
public enum SessionLagReason: String, Codable, CaseIterable, Sendable {
  case bufferDropped
  case cursorGap
  case snapshotRequired
}

@frozen
public enum ResourceStaleReason: Equatable, Sendable {
  case reconnecting
  case relayUnavailable
  case machineOffline
  case lagged(reason: SessionLagReason)
}

@frozen
public enum SessionConnectionState: Equatable, Sendable {
  case connecting
  case connected
  case relayUnavailable
  case machineOffline
  case reconnecting
  case lagged(reason: SessionLagReason)
  case revoked
  case incompatible
  case securityError
}

@frozen
public enum ResourceState<Value> {
  case loading(previous: Value?)
  case ready(value: Value, revision: UInt64)
  case stale(value: Value, reason: ResourceStaleReason)
  case failed(error: SessionSourceFailure, retryable: Bool)
}

extension ResourceState: Sendable where Value: Sendable {}
extension ResourceState: Equatable where Value: Equatable {}

@frozen
public enum ConversationUpdate: Sendable {
  case snapshot(ConversationSnapshotV2)
  case event(RuntimeEventV2)
  case commandState(CommandStatusReceiptV2)
  case connectionState(SessionConnectionState)
}

@frozen
public enum PairingProgress: Equatable, Sendable {
  case preparing
  case waitingForLocalConfirmation
  case paired(PairedMachine)
  case canceled
  case expired
}

public struct MachineSummary: Identifiable, Equatable, Sendable {
  public let id: String
  public let name: String
  public let connectionState: SessionConnectionState
  public let lastHeartbeat: Date?
  public let activeConversationCount: Int
  public let pendingApprovalCount: Int

  public init(
    id: String,
    name: String,
    connectionState: SessionConnectionState,
    lastHeartbeat: Date?,
    activeConversationCount: Int,
    pendingApprovalCount: Int
  ) {
    self.id = id
    self.name = name
    self.connectionState = connectionState
    self.lastHeartbeat = lastHeartbeat
    self.activeConversationCount = activeConversationCount
    self.pendingApprovalCount = pendingApprovalCount
  }
}

@frozen
public enum ConversationGroup: String, Codable, CaseIterable, Sendable {
  case waitingApproval
  case active
  case recent
}

public struct ConversationSummary: Identifiable, Equatable, Sendable {
  public let id: String
  public let machineID: String
  public let title: String
  public let cwd: String
  public let agentKind: AgentKind
  public let group: ConversationGroup
  public let lastActiveMs: UInt64
  public let archived: Bool
  public let revision: UInt64

  public init(
    id: String,
    machineID: String,
    title: String,
    cwd: String,
    agentKind: AgentKind,
    group: ConversationGroup,
    lastActiveMs: UInt64,
    archived: Bool,
    revision: UInt64
  ) {
    self.id = id
    self.machineID = machineID
    self.title = title
    self.cwd = cwd
    self.agentKind = agentKind
    self.group = group
    self.lastActiveMs = lastActiveMs
    self.archived = archived
    self.revision = revision
  }
}

public struct InboxItem: Identifiable, Equatable, Sendable {
  @frozen
  public enum Kind: String, Codable, CaseIterable, Sendable {
    case waitingApproval
    case turnCompleted
    case failed
  }

  public let id: String
  public let conversationID: String
  public let machineID: String
  public let kind: Kind
  public let title: String

  public init(
    id: String,
    conversationID: String,
    machineID: String,
    kind: Kind,
    title: String
  ) {
    self.id = id
    self.conversationID = conversationID
    self.machineID = machineID
    self.kind = kind
    self.title = title
  }
}

public struct PairingPreview: Equatable, Sendable {
  public let name: String
  public let relayHost: String
  public let rootFingerprint: Data
  public let expiresAtMs: UInt64
  public let relayServerID: Data?
  public let currentSPKIPin: Data?
  public let nextSPKIPin: Data?

  public init(
    name: String,
    relayHost: String,
    rootFingerprint: Data,
    expiresAtMs: UInt64,
    relayServerID: Data? = nil,
    currentSPKIPin: Data? = nil,
    nextSPKIPin: Data? = nil
  ) {
    self.name = name
    self.relayHost = relayHost
    self.rootFingerprint = rootFingerprint
    self.expiresAtMs = expiresAtMs
    self.relayServerID = relayServerID
    self.currentSPKIPin = currentSPKIPin
    self.nextSPKIPin = nextSPKIPin
  }
}

public struct PairedMachine: Identifiable, Equatable, Sendable {
  public let id: String
  public let name: String
  public let relayHost: String
  public let rootFingerprint: Data

  public init(
    id: String,
    name: String,
    relayHost: String,
    rootFingerprint: Data
  ) {
    self.id = id
    self.name = name
    self.relayHost = relayHost
    self.rootFingerprint = rootFingerprint
  }
}
