import Foundation
import Security

/// 密封状态的身份轴；所有字段都会进入文件名派生和 AEAD AAD。
public struct CryptoStateIdentity: Equatable, Sendable, CustomDebugStringConvertible {
  public let clientKind: RelayClientKind
  public let installationID: UUID
  public let machineID: String
  public let machineRootFingerprint: Data
  public let machineRoute: Data

  public init(
    clientKind: RelayClientKind,
    installationID: UUID,
    machineID: String,
    machineRootFingerprint: Data,
    machineRoute: Data
  ) throws {
    guard isNonzeroRelayInstallationID(installationID),
      !machineID.isEmpty,
      machineID.utf8.count <= 8 * 1_024
    else {
      throw CryptoStateStoreError.invalidIdentity
    }
    guard machineRootFingerprint.count == 32,
      machineRoute.count == 16,
      !machineRootFingerprint.allSatisfy({ $0 == 0 }),
      !machineRoute.allSatisfy({ $0 == 0 })
    else {
      throw CryptoStateStoreError.invalidIdentity
    }
    self.clientKind = clientKind
    self.installationID = installationID
    self.machineID = machineID
    self.machineRootFingerprint = machineRootFingerprint
    self.machineRoute = machineRoute
  }

  public var debugDescription: String {
    "CryptoStateIdentity(<redacted>)"
  }
}

/// 只用于密封本地 CryptoState；不会离开 endpoint。
public struct DeviceStorageKEK: Sendable, CustomDebugStringConvertible {
  public let rawRepresentation: Data

  public init(rawRepresentation: Data) throws {
    guard rawRepresentation.count == 32,
      !rawRepresentation.allSatisfy({ $0 == 0 })
    else {
      throw CryptoStateStoreError.invalidStorageKey
    }
    self.rawRepresentation = rawRepresentation
  }

  public static func generate() throws -> Self {
    var bytes = Data(repeating: 0, count: 32)
    let status = bytes.withUnsafeMutableBytes { buffer in
      SecRandomCopyBytes(kSecRandomDefault, buffer.count, buffer.baseAddress!)
    }
    guard status == errSecSuccess else {
      throw CryptoStateStoreError.entropyUnavailable
    }
    return try Self(rawRepresentation: bytes)
  }

  public var debugDescription: String {
    "DeviceStorageKEK(<redacted>)"
  }
}

/// `CryptoStateFileV1` 的封闭、versioned plaintext carrier。
///
/// production 调用方只能从 `DeviceCryptoStateV1` 构造；不存在任意 `Data`
/// initializer，因此 prompt/output/transcript 不能借 opaque bytes API 落盘。
public struct CryptoStateSnapshot: Equatable, Sendable, CustomDebugStringConvertible {
  public static let maximumDataBytes = 128 * 1_024 * 1_024

  public let state: DeviceCryptoStateV1
  private let encoded: Data

  public init(_ state: DeviceCryptoStateV1) throws {
    let encoded = try DeviceCryptoStateCodec.encode(state)
    guard encoded.count <= Self.maximumDataBytes else {
      throw CryptoStateStoreError.inputTooLarge
    }
    self.state = state
    self.encoded = encoded
  }

  init(authenticatedCanonicalBytes: Data) throws {
    let state: DeviceCryptoStateV1
    do {
      state = try DeviceCryptoStateCodec.decode(authenticatedCanonicalBytes)
    } catch DeviceCryptoStateError.inputTooLarge {
      throw CryptoStateStoreError.inputTooLarge
    } catch {
      throw CryptoStateStoreError.invalidFormat
    }
    let canonical: Data
    do {
      canonical = try DeviceCryptoStateCodec.encode(state)
    } catch DeviceCryptoStateError.inputTooLarge {
      throw CryptoStateStoreError.inputTooLarge
    } catch {
      throw CryptoStateStoreError.invalidFormat
    }
    guard canonical == authenticatedCanonicalBytes else {
      throw CryptoStateStoreError.invalidFormat
    }
    self.state = state
    encoded = canonical
  }

  public var debugDescription: String {
    "CryptoStateSnapshot(v1, revision: \(state.stateRevision), <redacted>)"
  }

  public var commitment: Data { CanonicalCodec.sha256(encoded) }

  var canonicalBytes: Data { encoded }
}

public enum CryptoStateCommit: Equatable, Sendable {
  case created
  case alreadyPresent
}

public enum CryptoStateStoreError: Error, Equatable, Sendable, CustomStringConvertible {
  case invalidIdentity
  case invalidStorageKey
  case entropyUnavailable
  case inputTooLarge
  case invalidFormat
  case authenticationFailed
  case immutableConflict
  case compareAndReplaceMismatch
  case missingState
  case missingStorageKey
  case unsafeFile
  case backupExclusionMissing
  case fileProtectionMissing
  case persistenceReadbackFailed
  case io(code: Int32)

  public var code: String {
    switch self {
    case .invalidIdentity: "remote.crypto_state.invalid_identity"
    case .invalidStorageKey: "remote.crypto_state.invalid_storage_key"
    case .entropyUnavailable: "remote.crypto_state.entropy_unavailable"
    case .inputTooLarge: "remote.crypto_state.input_too_large"
    case .invalidFormat: "remote.crypto_state.invalid_format"
    case .authenticationFailed: "remote.crypto_state.authentication_failed"
    case .immutableConflict: "remote.crypto_state.immutable_conflict"
    case .compareAndReplaceMismatch: "remote.crypto_state.compare_and_replace_mismatch"
    case .missingState: "remote.crypto_state.missing"
    case .missingStorageKey: "remote.crypto_state.missing_storage_key"
    case .unsafeFile: "remote.crypto_state.unsafe_file"
    case .backupExclusionMissing: "remote.crypto_state.backup_exclusion_missing"
    case .fileProtectionMissing: "remote.crypto_state.file_protection_missing"
    case .persistenceReadbackFailed: "remote.crypto_state.persistence_readback_failed"
    case .io: "remote.crypto_state.io"
    }
  }

  public var description: String {
    if case .io(let status) = self {
      return "\(code).\(status)"
    }
    return code
  }
}

public protocol CryptoStateStore: Sendable {
  func load() async throws -> CryptoStateSnapshot?

  func commitInitial(_ snapshot: CryptoStateSnapshot) async throws -> CryptoStateCommit

  func compareAndReplaceExact(
    expected: CryptoStateSnapshot,
    replacement: CryptoStateSnapshot
  ) async throws

  func deleteExact(expected: CryptoStateSnapshot) async throws
}

public enum CryptoStateStoreFactory {
  /// 只打开已有 material；绝不在 state/KEK 不一致时生成替代 key。
  public static func openExisting(
    rootURL: URL,
    identity: CryptoStateIdentity,
    keyStore: any KeyStore
  ) async throws -> FileCryptoStateStore? {
    let stateURL = FileCryptoStateStore.stateURL(rootURL: rootURL, identity: identity)
    let stateExists = try FileCryptoStateStore.entryExistsNoFollow(at: stateURL)
    let storageKeyAccount = try KeyStoreKey.paired(
      clientKind: identity.clientKind,
      installationID: identity.installationID,
      rootFingerprint: identity.machineRootFingerprint,
      machineRoute: identity.machineRoute,
      purpose: .deviceStorageKEK
    )
    let rawKey = try await keyStore.load(storageKeyAccount)
    switch (stateExists, rawKey) {
    case (false, nil):
      return nil
    case (true, nil):
      throw CryptoStateStoreError.missingStorageKey
    case (false, .some):
      throw CryptoStateStoreError.missingState
    case (true, .some):
      break
    }
    guard let rawKey else { throw CryptoStateStoreError.missingStorageKey }
    return try FileCryptoStateStore(
      rootURL: rootURL,
      identity: identity,
      storageKey: DeviceStorageKEK(rawRepresentation: rawKey)
    )
  }
}
