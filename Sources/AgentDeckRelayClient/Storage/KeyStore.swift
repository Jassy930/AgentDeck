import Foundation

/// Remote client 的持久化命名空间；App 与 CLI 不共享 private items。
public enum RelayClientKind: String, Codable, Sendable {
  case macOSApp = "macos-app"
  case iOSApp = "ios-app"
  case cli
}

public enum PendingKeyStorePurpose: String, Codable, Sendable {
  case pairingRecord = "pending-pairing-record.v1"
  case deviceSignPrivateKey = "device-sign-private-key.v1"
  case deviceHPKEPrivateKey = "device-hpke-private-key.v1"
}

public enum PairedKeyStorePurpose: String, Codable, Sendable {
  case deviceSignPrivateKey = "device-sign-private-key.v1"
  case deviceHPKEPrivateKey = "device-hpke-private-key.v1"
  case deviceGrant = "device-grant.v1"
  case deviceStorageKEK = "device-storage-kek.v1"
  case counterGuard = "counter-guard.v1"
  case commitMarker = "paired-commit-marker.v1"
}

/// 只能由版本化 typed factory 构造的 Keychain account。
public struct KeyStoreKey: Hashable, Sendable, CustomDebugStringConvertible {
  public static let maximumAccountLength = 160

  public let account: String

  private init(account: String) throws {
    guard account.utf8.allSatisfy({ $0 < 0x80 }),
      account.utf8.count <= Self.maximumAccountLength
    else {
      throw KeyStoreError.invalidAccount
    }
    self.account = account
  }

  static func validated(account: String) throws -> Self {
    try Self(account: account)
  }

  public static func pairedMarkerPrefix(
    clientKind: RelayClientKind,
    installationID: UUID
  ) -> String {
    "\(clientKind.rawValue)/\(installationID.uuidString.lowercased())/"
  }

  public static func pending(
    clientKind: RelayClientKind,
    installationID: UUID,
    inviteHash: Data,
    purpose: PendingKeyStorePurpose
  ) throws -> Self {
    guard isNonzeroRelayInstallationID(installationID),
      inviteHash.count == 32,
      inviteHash.contains(where: { $0 != 0 })
    else {
      if inviteHash.count == 32 {
        throw KeyStoreError.invalidAccount
      }
      throw KeyStoreError.invalidLength(
        field: "inviteHash",
        expected: 32,
        actual: inviteHash.count
      )
    }
    return try Self(
      account: [
        "pending",
        clientKind.rawValue,
        installationID.uuidString.lowercased(),
        inviteHash.base64URLEncodedString,
        purpose.rawValue,
      ].joined(separator: "/")
    )
  }

  public static func paired(
    clientKind: RelayClientKind,
    installationID: UUID,
    rootFingerprint: Data,
    machineRoute: Data,
    purpose: PairedKeyStorePurpose
  ) throws -> Self {
    guard isNonzeroRelayInstallationID(installationID) else {
      throw KeyStoreError.invalidAccount
    }
    guard rootFingerprint.count == 32 else {
      throw KeyStoreError.invalidLength(
        field: "rootFingerprint",
        expected: 32,
        actual: rootFingerprint.count
      )
    }
    guard rootFingerprint.contains(where: { $0 != 0 }) else {
      throw KeyStoreError.invalidAccount
    }
    guard machineRoute.count == 16 else {
      throw KeyStoreError.invalidLength(
        field: "machineRoute",
        expected: 16,
        actual: machineRoute.count
      )
    }
    guard machineRoute.contains(where: { $0 != 0 }) else {
      throw KeyStoreError.invalidAccount
    }
    return try Self(
      account: [
        clientKind.rawValue,
        installationID.uuidString.lowercased(),
        rootFingerprint.base64URLEncodedString,
        machineRoute.base64URLEncodedString,
        purpose.rawValue,
      ].joined(separator: "/")
    )
  }

  public var debugDescription: String {
    "KeyStoreKey(<redacted>)"
  }
}

public enum KeyStorePersistence: Equatable, Sendable {
  case inserted
  case alreadyPresent
}

public enum KeyStoreError: Error, Equatable, Sendable, CustomStringConvertible {
  case invalidAccount
  case invalidLength(field: String, expected: Int, actual: Int)
  case immutableConflict
  case compareAndReplaceMissing
  case compareAndReplaceMismatch
  case persistenceReadbackFailed
  case deleteReadbackFailed
  case backendUnavailable(status: Int32)

  public var code: String {
    switch self {
    case .invalidAccount: "remote.keystore.invalid_account"
    case .invalidLength: "remote.keystore.invalid_length"
    case .immutableConflict: "remote.keystore.immutable_conflict"
    case .compareAndReplaceMissing: "remote.keystore.compare_and_replace_missing"
    case .compareAndReplaceMismatch: "remote.keystore.compare_and_replace_mismatch"
    case .persistenceReadbackFailed: "remote.keystore.persistence_readback_failed"
    case .deleteReadbackFailed: "remote.keystore.delete_readback_failed"
    case .backendUnavailable: "remote.keystore.unavailable"
    }
  }

  public var description: String {
    if case .backendUnavailable(let status) = self {
      return "\(code).\(status)"
    }
    return code
  }
}

/// 所有 mutation 都要求 exact readback；不存在覆盖式 `store` 降级面。
public protocol KeyStore: Sendable {
  func load(_ key: KeyStoreKey) async throws -> Data?

  func persistImmutable(
    _ data: Data,
    for key: KeyStoreKey
  ) async throws -> KeyStorePersistence

  func compareAndReplaceExact(
    expected: Data,
    replacement: Data,
    for key: KeyStoreKey
  ) async throws

  func deleteExact(expected: Data, for key: KeyStoreKey) async throws
}

/// Keychain-native paired marker enumeration；不建立第二份可漂移 index。
public protocol PairedMarkerListingKeyStore: KeyStore {
  func pairedCommitMarkerKeys(
    clientKind: RelayClientKind,
    installationID: UUID
  ) async throws -> [KeyStoreKey]
}

extension KeyStore {
  /// convenience 仍通过 expected-value backend delete；不会退化成 blind delete。
  public func deleteExact(_ key: KeyStoreKey) async throws {
    guard let expected = try await load(key) else { return }
    try await deleteExact(expected: expected, for: key)
  }
}

extension Data {
  fileprivate var base64URLEncodedString: String {
    base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
  }
}

func isNonzeroRelayInstallationID(_ value: UUID) -> Bool {
  var bytes = value.uuid
  return Swift.withUnsafeBytes(of: &bytes) { buffer in
    buffer.contains(where: { $0 != 0 })
  }
}
