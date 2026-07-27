import CryptoKit
import Foundation
import Security

/// `Security.framework` 的窄后端 seam。生产默认实现直接转发 SecItem API；测试实现可在
/// 无 Keychain entitlement 的 SwiftPM runner 中验证 query 与原子 CAS 语义。
protocol AppleKeychainSecurityBackend: Sendable {
  func copyMatching(_ query: [CFString: Any]) -> AppleKeychainSecurityResult
  func add(_ attributes: [CFString: Any]) -> OSStatus
  func update(
    _ query: [CFString: Any],
    attributesToUpdate: [CFString: Any]
  ) -> OSStatus
  func delete(_ query: [CFString: Any]) -> OSStatus
}

/// Core Foundation 返回值只在同步 backend 调用与当前 actor turn 内消费，不跨并发域。
struct AppleKeychainSecurityResult {
  let status: OSStatus
  let value: Any?
}

private struct SystemAppleKeychainSecurityBackend: AppleKeychainSecurityBackend {
  func copyMatching(_ query: [CFString: Any]) -> AppleKeychainSecurityResult {
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    return AppleKeychainSecurityResult(status: status, value: result)
  }

  func add(_ attributes: [CFString: Any]) -> OSStatus {
    SecItemAdd(attributes as CFDictionary, nil)
  }

  func update(
    _ query: [CFString: Any],
    attributesToUpdate: [CFString: Any]
  ) -> OSStatus {
    SecItemUpdate(query as CFDictionary, attributesToUpdate as CFDictionary)
  }

  func delete(_ query: [CFString: Any]) -> OSStatus {
    SecItemDelete(query as CFDictionary)
  }
}

/// iOS/macOS 共用的 Keychain adapter。调用方不能覆盖 service、accessibility 或同步策略。
public actor AppleKeychainStore: PairedMarkerListingKeyStore {
  public static let service = "com.agentdeck.remote.v1"

  private let backend: any AppleKeychainSecurityBackend

  public init() {
    backend = SystemAppleKeychainSecurityBackend()
  }

  init(backend: any AppleKeychainSecurityBackend) {
    self.backend = backend
  }

  public func load(_ key: KeyStoreKey) async throws -> Data? {
    try loadValidated(key)
  }

  public func persistImmutable(
    _ data: Data,
    for key: KeyStoreKey
  ) async throws -> KeyStorePersistence {
    var attributes = mutationQuery(for: key)
    attributes[kSecValueData] = data
    attributes[kSecAttrGeneric] = Self.valueDigest(data)

    let status = backend.add(attributes)
    let persistence: KeyStorePersistence
    switch status {
    case errSecSuccess:
      persistence = .inserted
    case errSecDuplicateItem:
      guard try loadValidated(key) == data else {
        throw KeyStoreError.immutableConflict
      }
      persistence = .alreadyPresent
    default:
      throw backendError(status)
    }

    guard try loadValidated(key) == data else {
      throw KeyStoreError.persistenceReadbackFailed
    }
    return persistence
  }

  public func compareAndReplaceExact(
    expected: Data,
    replacement: Data,
    for key: KeyStoreKey
  ) async throws {
    // `kSecAttrGeneric` 是 value 的 SHA-256 commitment。把旧 commitment 放进
    // SecItemUpdate query，令“比对旧值 + 写入新值”在线性化的 Security backend
    // mutation 内完成；不能退化成 actor 外的 load -> unconditional update。
    var query = mutationQuery(for: key)
    query[kSecAttrGeneric] = Self.valueDigest(expected)

    let status = backend.update(
      query,
      attributesToUpdate: [
        kSecValueData: replacement,
        kSecAttrGeneric: Self.valueDigest(replacement),
      ]
    )
    switch status {
    case errSecSuccess:
      break
    case errSecItemNotFound:
      guard let current = try loadValidated(key) else {
        throw KeyStoreError.compareAndReplaceMissing
      }
      guard current != expected else {
        // 当前 item 满足 exact expected，却未被完整 policy + digest query 命中，
        // 说明 backend/readback 已不自洽，不能误报 mismatch 或重试覆盖。
        throw KeyStoreError.persistenceReadbackFailed
      }
      throw KeyStoreError.compareAndReplaceMismatch
    default:
      throw backendError(status)
    }

    guard try loadValidated(key) == replacement else {
      throw KeyStoreError.persistenceReadbackFailed
    }
  }

  public func deleteExact(expected: Data, for key: KeyStoreKey) async throws {
    var query = mutationQuery(for: key)
    query[kSecAttrGeneric] = Self.valueDigest(expected)

    let status = backend.delete(query)
    if status == errSecItemNotFound {
      guard let current = try loadValidated(key) else { return }
      guard current != expected else {
        throw KeyStoreError.persistenceReadbackFailed
      }
      throw KeyStoreError.deleteReadbackFailed
    }
    guard status == errSecSuccess else {
      throw backendError(status)
    }
    guard try loadValidated(key) == nil else {
      throw KeyStoreError.deleteReadbackFailed
    }
  }

  public func pairedCommitMarkerKeys(
    clientKind: RelayClientKind,
    installationID: UUID
  ) async throws -> [KeyStoreKey] {
    guard isNonzeroRelayInstallationID(installationID) else {
      throw KeyStoreError.invalidAccount
    }
    var query: [CFString: Any] = [
      kSecClass: kSecClassGenericPassword,
      kSecAttrService: Self.service,
      kSecAttrSynchronizable: kSecAttrSynchronizableAny,
      kSecReturnAttributes: true,
      kSecReturnData: true,
      kSecMatchLimit: kSecMatchLimitAll,
    ]
    #if os(macOS)
      query[kSecUseDataProtectionKeychain] = true
    #endif
    let result = backend.copyMatching(query)
    if result.status == errSecItemNotFound { return [] }
    guard result.status == errSecSuccess else {
      throw backendError(result.status)
    }

    let prefix = KeyStoreKey.pairedMarkerPrefix(
      clientKind: clientKind,
      installationID: installationID
    )
    let suffix = "/\(PairedKeyStorePurpose.commitMarker.rawValue)"
    var keys: [KeyStoreKey] = []
    for item in try Self.decodeItems(result.value) {
      guard let account = item[kSecAttrAccount as String] as? String,
        account.hasPrefix(prefix),
        account.hasSuffix(suffix)
      else {
        continue
      }
      let key = try KeyStoreKey.validated(account: account)
      _ = try Self.validate(item, for: key)
      keys.append(key)
    }
    return keys.sorted { $0.account < $1.account }
  }

  public func pendingPairingRecoveryKeys(
    clientKind: RelayClientKind,
    installationID: UUID
  ) async throws -> [KeyStoreKey] {
    guard isNonzeroRelayInstallationID(installationID) else {
      throw KeyStoreError.invalidAccount
    }
    let items = try allServiceItems()
    let prefix = KeyStoreKey.pendingMarkerPrefix(
      clientKind: clientKind,
      installationID: installationID
    )
    let allowedSuffixes = [
      "/\(PendingKeyStorePurpose.recoveryIntent.rawValue)",
      "/\(PendingKeyStorePurpose.pairingRecord.rawValue)",
    ]
    var keys: [KeyStoreKey] = []
    for item in items {
      guard let account = item[kSecAttrAccount as String] as? String,
        account.hasPrefix(prefix),
        allowedSuffixes.contains(where: account.hasSuffix)
      else {
        continue
      }
      let key = try KeyStoreKey.validated(account: account)
      _ = try Self.validate(item, for: key)
      keys.append(key)
    }
    return keys.sorted { $0.account < $1.account }
  }

  private func allServiceItems() throws -> [[String: Any]] {
    var query: [CFString: Any] = [
      kSecClass: kSecClassGenericPassword,
      kSecAttrService: Self.service,
      kSecAttrSynchronizable: kSecAttrSynchronizableAny,
      kSecReturnAttributes: true,
      kSecReturnData: true,
      kSecMatchLimit: kSecMatchLimitAll,
    ]
    #if os(macOS)
      query[kSecUseDataProtectionKeychain] = true
    #endif
    let result = backend.copyMatching(query)
    if result.status == errSecItemNotFound { return [] }
    guard result.status == errSecSuccess else {
      throw backendError(result.status)
    }
    return try Self.decodeItems(result.value)
  }

  private func loadValidated(_ key: KeyStoreKey) throws -> Data? {
    var query = identityQuery(for: key)
    // 查询同 identity 下的所有同步策略，随后显式拒绝旧的 synchronizable item；
    // 不能用 `false` 预过滤后把弱策略 item 误当成“不存在”。
    query[kSecAttrSynchronizable] = kSecAttrSynchronizableAny
    query[kSecReturnAttributes] = true
    query[kSecReturnData] = true
    query[kSecMatchLimit] = kSecMatchLimitAll

    let result = backend.copyMatching(query)
    switch result.status {
    case errSecSuccess:
      let items = try Self.decodeItems(result.value)
      guard items.count == 1 else {
        throw KeyStoreError.persistenceReadbackFailed
      }
      return try Self.validate(items[0], for: key)
    case errSecItemNotFound:
      return nil
    default:
      throw backendError(result.status)
    }
  }

  private func identityQuery(for key: KeyStoreKey) -> [CFString: Any] {
    var query: [CFString: Any] = [
      kSecClass: kSecClassGenericPassword,
      kSecAttrService: Self.service,
      kSecAttrAccount: key.account,
    ]
    #if os(macOS)
      // 在 macOS 上强制走 iOS-style Data Protection Keychain，禁止回退到旧 file
      // Keychain。该 selector 不作为 item attribute 返回，因此通过每次 query 固定。
      query[kSecUseDataProtectionKeychain] = true
    #endif
    return query
  }

  private func mutationQuery(for key: KeyStoreKey) -> [CFString: Any] {
    var query = identityQuery(for: key)
    query[kSecAttrAccessible] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    query[kSecAttrSynchronizable] = kCFBooleanFalse as Any
    return query
  }

  private static func decodeItems(_ value: Any?) throws -> [[String: Any]] {
    if let items = value as? [[String: Any]] {
      return items
    }
    if let item = value as? [String: Any] {
      return [item]
    }
    throw KeyStoreError.persistenceReadbackFailed
  }

  private static func validate(
    _ attributes: [String: Any],
    for key: KeyStoreKey
  ) throws -> Data {
    guard attributes[kSecAttrService as String] as? String == Self.service,
      attributes[kSecAttrAccount as String] as? String == key.account,
      attributes[kSecAttrAccessible as String] as? String
        == kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String,
      let synchronizable = attributes[kSecAttrSynchronizable as String] as? NSNumber,
      synchronizable.boolValue == false,
      let data = attributes[kSecValueData as String] as? Data,
      let digest = attributes[kSecAttrGeneric as String] as? Data,
      digest == valueDigest(data)
    else {
      throw KeyStoreError.persistenceReadbackFailed
    }
    return data
  }

  private static func valueDigest(_ data: Data) -> Data {
    Data(SHA256.hash(data: data))
  }

  private func backendError(_ status: OSStatus) -> KeyStoreError {
    .backendUnavailable(status: status)
  }
}
