import AgentDeckCore
import CryptoKit
import Foundation

enum MachineDataVerifierError: Error, Equatable, Sendable {
  case invalidTrustBinding
  case expiredDataCertificate
  case certificateGenerationRollback
  case invalidOuterContext
  case keyDirectoryRollback
  case keyDirectoryAdvanceExceeded
  case receivingKeyMismatch
  case invalidNonceBinding
  case payloadKindMismatch
  case invalidRequestRoute
  case exactNextRevisionRequired
  case unexpectedKeyControlVariant
  case keyControlRevisionMismatch
  case retiredReplayAdmissionRequired
  case stagedReplayAdmissionRequired
  case activatedPendingReplayAdmissionRequired
  case activationProofMismatch
  case directoryAdvanceReplayAdmissionRequired
  case directoryAdvanceProofMismatch
}

/// 已安装接收 key 的 endpoint capability。key purpose 只决定密码学用途；这里再把它
/// 收紧到唯一 outer frame family 与允许的密文内 payload kind，避免合法 key 被跨路由、
/// 跨业务 family 复用。
enum MachineDataReceivingCapability: Equatable, Sendable {
  case catalogPublication
  case conversationPublication
  case directedReply

  fileprivate var frameKind: OuterFrameKind {
    switch self {
    case .catalogPublication: .catalogPublish
    case .conversationPublication: .conversationPublish
    case .directedReply: .directedReply
    }
  }

  fileprivate func admits(_ payloadKind: SealedPayloadKind) -> Bool {
    switch self {
    case .catalogPublication:
      switch payloadKind {
      case .catalogDelta, .keyUpdate, .transferPart: true
      default: false
      }
    case .conversationPublication:
      switch payloadKind {
      case .conversationEvent, .keyUpdate, .transferPart: true
      default: false
      }
    case .directedReply:
      switch payloadKind {
      case .catalogSnapshot, .conversationSnapshot, .backfillChunk,
        .commandReceipt, .keyUpdate, .transferPart:
        true
      default:
        false
      }
    }
  }
}

struct MachineDataReceivingKeyBinding: Sendable {
  let key: AeadReceivingKey
  let streamRoute: Data?
  let noncePrefix: Data
  let keyDirectoryRevision: UInt64
  let capability: MachineDataReceivingCapability

  init(
    key: AeadReceivingKey,
    streamRoute: Data?,
    noncePrefix: Data,
    keyDirectoryRevision: UInt64,
    capability: MachineDataReceivingCapability? = nil
  ) throws {
    let resolvedCapability: MachineDataReceivingCapability
    switch (capability, key.keyID.purpose) {
    case (.some(.catalogPublication), .catalog), (.none, .catalog):
      resolvedCapability = .catalogPublication
    case (.some(.conversationPublication), .conversationDEK), (.none, .conversationDEK):
      resolvedCapability = .conversationPublication
    case (.some(.directedReply), .deviceReplyTx), (.none, .deviceReplyTx):
      resolvedCapability = .directedReply
    case (.some(_), _), (.none, .deviceCommandTx):
      throw MachineDataVerifierError.receivingKeyMismatch
    }
    let routeShapeIsValid: Bool
    switch resolvedCapability {
    case .catalogPublication, .conversationPublication:
      routeShapeIsValid = streamRoute.map({ Self.isNonzero($0, count: 16) }) ?? false
    case .directedReply:
      routeShapeIsValid = streamRoute == nil
    }
    guard routeShapeIsValid,
      noncePrefix.count == 4,
      keyDirectoryRevision > 0
    else {
      throw MachineDataVerifierError.receivingKeyMismatch
    }
    self.key = key
    self.streamRoute = streamRoute
    self.noncePrefix = noncePrefix
    self.keyDirectoryRevision = keyDirectoryRevision
    self.capability = resolvedCapability
  }

  private static func isNonzero(_ value: Data, count: Int) -> Bool {
    value.count == count && value.contains(where: { $0 != 0 })
  }

  fileprivate func rebinding(keyDirectoryRevision: UInt64) throws -> Self {
    try Self(
      key: key,
      streamRoute: streamRoute,
      noncePrefix: noncePrefix,
      keyDirectoryRevision: keyDirectoryRevision,
      capability: capability
    )
  }
}

struct VerifiedMachineDataCandidate: Sendable {
  let verifiedBlob: VerifiedSealedBlobV1
  let receivingKey: AeadReceivingKey
  let context: OuterContextV1
  let counter: UInt64
  let ciphertextHash: Data
  let keyDirectoryRevision: UInt64
}

struct OpenedMachineDataPayload: Sendable {
  let payloadKind: SealedPayloadKind
  let payload: Data
}

/// cold-open audited inventory 中唯一 active `DeviceReplyTx` key 与 owned requestRoute
/// 绑定后的 exact-next KeySync reply capability。构造不会暴露或复制 raw key bytes。
struct ExactNextKeySyncReplyCapability: Sendable, CustomDebugStringConvertible {
  fileprivate let currentBinding: MachineDataReceivingKeyBinding
  fileprivate let nextBinding: MachineDataReceivingKeyBinding
  fileprivate let requestRoute: Data
  fileprivate let currentRevision: UInt64
  fileprivate let requestedRevision: UInt64

  fileprivate init(
    inventory: AuditedDeviceKeyInventoryV1,
    requestRoute: Data
  ) throws {
    guard requestRoute.count == 16,
      requestRoute.contains(where: { $0 != 0 })
    else {
      throw MachineDataVerifierError.invalidRequestRoute
    }
    let next = inventory.activeRevision.addingReportingOverflow(1)
    guard !next.overflow else {
      throw MachineDataVerifierError.exactNextRevisionRequired
    }
    let replyKeys = inventory.currentReceivingKeys.filter {
      $0.key.keyID.purpose == .deviceReplyTx
        && $0.key.keyID.epoch > 0
        && $0.streamRoute == nil
        && $0.keyDirectoryRevision == inventory.activeRevision
    }
    guard replyKeys.count == 1, let replyKey = replyKeys.first else {
      throw MachineDataVerifierError.receivingKeyMismatch
    }
    let current = try MachineDataReceivingKeyBinding(
      key: replyKey.key,
      streamRoute: nil,
      noncePrefix: replyKey.noncePrefix,
      keyDirectoryRevision: inventory.activeRevision,
      capability: .directedReply
    )
    currentBinding = current
    nextBinding = try current.rebinding(keyDirectoryRevision: next.partialValue)
    self.requestRoute = requestRoute
    currentRevision = inventory.activeRevision
    requestedRevision = next.partialValue
  }

  var debugDescription: String {
    "ExactNextKeySyncReplyCapability(material: <redacted>)"
  }
}

extension AuditedDeviceKeyInventoryV1 {
  func exactNextKeySyncReplyCapability(
    requestRoute: Data
  ) throws -> ExactNextKeySyncReplyCapability {
    try ExactNextKeySyncReplyCapability(
      inventory: self,
      requestRoute: requestRoute
    )
  }
}

/// MachineDataSign 已验证且 outer/requestRoute/header 已收紧到 exact-next 后的候选。
/// caller 必须先以 replay tuple 完成 durable admission，才可调用 open。
struct VerifiedExactNextKeySyncReplyCandidate: Sendable, CustomDebugStringConvertible {
  fileprivate let candidate: VerifiedMachineDataCandidate
  fileprivate let receivingKey: MachineDataReceivingKeyBinding

  let replayScope: DeviceCryptoKeyScopeV1
  let counter: UInt64
  let ciphertextHash: Data
  let keyDirectoryRevision: UInt64

  fileprivate init(
    candidate: VerifiedMachineDataCandidate,
    receivingKey: MachineDataReceivingKeyBinding
  ) {
    self.candidate = candidate
    self.receivingKey = receivingKey
    replayScope = DeviceCryptoKeyScopeV1(
      keyID: receivingKey.key.keyID,
      streamRoute: nil
    )
    counter = candidate.counter
    ciphertextHash = candidate.ciphertextHash
    keyDirectoryRevision = candidate.keyDirectoryRevision
  }

  var debugDescription: String {
    "VerifiedExactNextKeySyncReplyCandidate(material: <redacted>)"
  }
}

/// exact-next reply 经过签名、durable replay、AEAD 与 daemon key-control strict decode 后
/// 交给 durable stage 的唯一 carrier；这里保存的是 inner `KeyUpdateSetV1` canonical bytes。
struct VerifiedExactNextKeyUpdateSetV1: Sendable, CustomDebugStringConvertible {
  let keyDirectoryRevision: UInt64
  let canonicalBytes: Data

  fileprivate init(updateSet: CanonicalKeyUpdateSetV1) throws {
    keyDirectoryRevision = updateSet.keyDirectoryRevision
    canonicalBytes = try KeyUpdateSetCanonicalCodec.encode(updateSet)
  }

  var debugDescription: String {
    "VerifiedExactNextKeyUpdateSetV1(revision: \(keyDirectoryRevision), material: <redacted>)"
  }
}

enum OpenedExactNextKeySyncReplyV1: Sendable {
  case updateSet(VerifiedExactNextKeyUpdateSetV1)
  case directoryCurrent(DaemonDirectoryCurrentV1)
}

/// 未持有 AEAD key 时对 unknown exact-next frame 完成 MachineDataSign 的结果。
///
/// 该类型故意不保存 `VerifiedSealedBlobV1`，因此只能驱动 bounded KeySync，不能被调用方
/// 误用为 AEAD-open capability。
struct VerifiedHigherRevisionMachineDataProbe: Sendable, CustomDebugStringConvertible {
  let keyID: KeyIDV1
  let keyDirectoryRevision: UInt64
  let frameKind: OuterFrameKind
  let streamRoute: Data?
  let streamGeneration: Data?
  let requestRoute: Data?

  fileprivate init(
    sealed: UnsignedSealedBlobV1,
    context: OuterContextV1
  ) {
    keyID = sealed.keyID
    keyDirectoryRevision = sealed.keyDirectoryRevision
    frameKind = context.frameKind
    streamRoute = context.streamRoute
    streamGeneration = context.streamGeneration
    requestRoute = context.requestRoute
  }

  var debugDescription: String {
    "VerifiedHigherRevisionMachineDataProbe(revision: \(keyDirectoryRevision), header: <redacted>)"
  }
}

/// staged receiving key 完成 outer/header/MachineDataSign admission 后的 opaque candidate。
/// AEAD open 必须继续携带同 tuple 的 durable replay proof。
struct VerifiedStagedKeyControlCandidate: Sendable, CustomDebugStringConvertible {
  fileprivate let candidate: VerifiedMachineDataCandidate
  fileprivate let receivingKey: MachineDataReceivingKeyBinding

  let replayScope: DeviceCryptoKeyScopeV1
  let counter: UInt64
  let ciphertextHash: Data
  let headerKeyDirectoryRevision: UInt64
  let stagedKeyDirectoryRevision: UInt64

  fileprivate init(
    candidate: VerifiedMachineDataCandidate,
    receivingKey: MachineDataReceivingKeyBinding,
    replayScope: DeviceCryptoKeyScopeV1,
    stagedKeyDirectoryRevision: UInt64
  ) {
    self.candidate = candidate
    self.receivingKey = receivingKey
    self.replayScope = replayScope
    counter = candidate.counter
    ciphertextHash = candidate.ciphertextHash
    headerKeyDirectoryRevision = candidate.keyDirectoryRevision
    self.stagedKeyDirectoryRevision = stagedKeyDirectoryRevision
  }

  var debugDescription: String {
    "VerifiedStagedKeyControlCandidate(material: <redacted>)"
  }
}

enum OpenedStagedKeyControlV1: Equatable, Sendable {
  case epochBarrier(DeviceEpochBarrierV1)
  case directoryRevisionAdvance(DeviceDirectoryRevisionAdvanceV1)
}

/// partial activation 中已切换 slot 的 next-revision candidate。它可以承载普通数据，
/// 但任何 KeyControl 都继续受 durable activation proof 约束。
struct VerifiedActivatedPendingMachineDataCandidate: Sendable,
  CustomDebugStringConvertible
{
  fileprivate let candidate: VerifiedMachineDataCandidate
  fileprivate let receivingKey: MachineDataReceivingKeyBinding
  fileprivate let activationProof: DeviceEpochBarrierV1

  let replayScope: DeviceCryptoKeyScopeV1
  let counter: UInt64
  let ciphertextHash: Data
  let keyDirectoryRevision: UInt64

  fileprivate init(
    candidate: VerifiedMachineDataCandidate,
    receivingKey: MachineDataReceivingKeyBinding,
    capability: AuditedReceivingKeyCapabilityV1
  ) throws {
    guard capability.lifecycle == .activatedPending else {
      throw MachineDataVerifierError.receivingKeyMismatch
    }
    let activationProof = try capability.activatedPendingProof()
    self.candidate = candidate
    self.receivingKey = receivingKey
    self.activationProof = activationProof
    replayScope = capability.replayScope
    counter = candidate.counter
    ciphertextHash = candidate.ciphertextHash
    keyDirectoryRevision = candidate.keyDirectoryRevision
  }

  var debugDescription: String {
    "VerifiedActivatedPendingMachineDataCandidate(material: <redacted>)"
  }
}

enum OpenedActivatedPendingMachineDataV1: Sendable {
  case data(OpenedMachineDataPayload)
  case epochBarrierDuplicate(DeviceEpochBarrierV1)
}

/// old physical route 上仅为 durable activation proof 保留的 exact alias candidate。
struct VerifiedEpochBarrierProofAliasCandidate: Sendable, CustomDebugStringConvertible {
  fileprivate let candidate: VerifiedMachineDataCandidate
  fileprivate let receivingKey: MachineDataReceivingKeyBinding
  fileprivate let activationProof: DeviceEpochBarrierV1

  let replayScope: DeviceCryptoKeyScopeV1
  let counter: UInt64
  let ciphertextHash: Data
  let keyDirectoryRevision: UInt64

  fileprivate init(
    candidate: VerifiedMachineDataCandidate,
    receivingKey: MachineDataReceivingKeyBinding,
    capability: AuditedReceivingKeyCapabilityV1
  ) throws {
    guard capability.lifecycle == .epochBarrierProofAlias else {
      throw MachineDataVerifierError.receivingKeyMismatch
    }
    let activationProof = try capability.epochBarrierAliasProof()
    self.candidate = candidate
    self.receivingKey = receivingKey
    self.activationProof = activationProof
    replayScope = capability.replayScope
    counter = candidate.counter
    ciphertextHash = candidate.ciphertextHash
    keyDirectoryRevision = candidate.keyDirectoryRevision
  }

  var debugDescription: String {
    "VerifiedEpochBarrierProofAliasCandidate(material: <redacted>)"
  }
}

/// revision-only activation 后，以 current Catalog material 验证 predecessor header 的
/// exact proof candidate。该能力不能解密普通 rollback frame。
struct VerifiedDirectoryAdvancePredecessorCandidate: Sendable,
  CustomDebugStringConvertible
{
  fileprivate let candidate: VerifiedMachineDataCandidate
  fileprivate let receivingKey: MachineDataReceivingKeyBinding
  fileprivate let directoryAdvanceProof: DeviceDirectoryRevisionAdvanceV1

  let replayScope: DeviceCryptoKeyScopeV1
  let counter: UInt64
  let ciphertextHash: Data
  let predecessorRevision: UInt64

  fileprivate init(
    candidate: VerifiedMachineDataCandidate,
    receivingKey: MachineDataReceivingKeyBinding,
    capability: AuditedReceivingKeyCapabilityV1
  ) throws {
    guard capability.lifecycle == .directoryAdvancePredecessor else {
      throw MachineDataVerifierError.receivingKeyMismatch
    }
    let directoryAdvanceProof = try capability.directoryAdvancePredecessorProof()
    self.candidate = candidate
    self.receivingKey = receivingKey
    self.directoryAdvanceProof = directoryAdvanceProof
    replayScope = capability.replayScope
    counter = candidate.counter
    ciphertextHash = candidate.ciphertextHash
    predecessorRevision = candidate.keyDirectoryRevision
  }

  var debugDescription: String {
    "VerifiedDirectoryAdvancePredecessorCandidate(material: <redacted>)"
  }
}

/// retained retired key 验签后的 delayed-frame candidate。只有 coordinator 针对同一
/// tuple mint 的 retired exact-duplicate proof 才能解密。
struct VerifiedRetiredMachineDataCandidate: Sendable, CustomDebugStringConvertible {
  fileprivate let candidate: VerifiedMachineDataCandidate
  fileprivate let receivingKey: MachineDataReceivingKeyBinding
  fileprivate let lifecycle: AuditedReceivingKeyLifecycleV1

  let replayScope: DeviceCryptoKeyScopeV1
  let counter: UInt64
  let ciphertextHash: Data
  let keyDirectoryRevision: UInt64

  fileprivate init(
    candidate: VerifiedMachineDataCandidate,
    receivingKey: MachineDataReceivingKeyBinding,
    lifecycle: AuditedReceivingKeyLifecycleV1,
    replayScope: DeviceCryptoKeyScopeV1
  ) {
    self.candidate = candidate
    self.receivingKey = receivingKey
    self.lifecycle = lifecycle
    self.replayScope = replayScope
    counter = candidate.counter
    ciphertextHash = candidate.ciphertextHash
    keyDirectoryRevision = candidate.keyDirectoryRevision
  }

  var debugDescription: String {
    "VerifiedRetiredMachineDataCandidate(material: <redacted>)"
  }
}

enum MachineDataVerificationResult: Sendable {
  case current(VerifiedMachineDataCandidate)
  case keySyncRequired(observedRevision: UInt64)
}

struct VerifiedMachineDataCertificate: Sendable, CustomDebugStringConvertible {
  let certificate: RelayV2SignedCertificate
  let signingKey: Curve25519.Signing.PublicKey

  var debugDescription: String {
    "VerifiedMachineDataCertificate(<redacted>)"
  }
}

enum MachineDataCertificateVerifier {
  static func verify(
    canonicalBytes: Data,
    relayServerID: Data,
    machineRoute: Data,
    machineRootPublicKey: Data,
    machineRootFingerprint: Data,
    expectedRootKeyID: Data,
    expectedTrustEpoch: UInt64,
    minimumDataCertificateGeneration: UInt64,
    nowMilliseconds: UInt64? = nil
  ) throws -> VerifiedMachineDataCertificate {
    try verify(
      SignedCertificateCanonicalCodec.decode(canonicalBytes),
      relayServerID: relayServerID,
      machineRoute: machineRoute,
      machineRootPublicKey: machineRootPublicKey,
      machineRootFingerprint: machineRootFingerprint,
      expectedRootKeyID: expectedRootKeyID,
      expectedTrustEpoch: expectedTrustEpoch,
      minimumDataCertificateGeneration: minimumDataCertificateGeneration,
      nowMilliseconds: nowMilliseconds
    )
  }

  static func verify(
    _ certificate: RelayV2SignedCertificate,
    relayServerID: Data,
    machineRoute: Data,
    machineRootPublicKey: Data,
    machineRootFingerprint: Data,
    expectedRootKeyID: Data,
    expectedTrustEpoch: UInt64,
    minimumDataCertificateGeneration: UInt64,
    nowMilliseconds: UInt64? = nil
  ) throws -> VerifiedMachineDataCertificate {
    guard isNonzero(relayServerID, count: 16),
      isNonzero(machineRoute, count: 16),
      isNonzero(machineRootPublicKey, count: 32),
      isNonzero(machineRootFingerprint, count: 32),
      CanonicalCodec.sha256(machineRootPublicKey) == machineRootFingerprint,
      isNonzero(expectedRootKeyID, count: 16),
      expectedTrustEpoch > 0,
      minimumDataCertificateGeneration > 0
    else {
      throw MachineDataVerifierError.invalidTrustBinding
    }

    let rootKey: Curve25519.Signing.PublicKey
    let certificateKey: Curve25519.Signing.PublicKey
    do {
      rootKey = try Curve25519.Signing.PublicKey(rawRepresentation: machineRootPublicKey)
      certificateKey = try Curve25519.Signing.PublicKey(
        rawRepresentation: certificate.subjectPubkey
      )
      _ = try SignedCertificateCanonicalCodec.encode(certificate)
    } catch {
      throw MachineDataVerifierError.invalidTrustBinding
    }

    guard certificate.certRole == .data,
      certificate.generation > 0,
      certificate.generation >= minimumDataCertificateGeneration,
      certificate.rootKeyId == expectedRootKeyID,
      certificate.trustEpoch == expectedTrustEpoch,
      isNonzero(certificate.subjectPubkey, count: 32),
      isNonzero(certificate.signature, count: 64)
    else {
      if certificate.generation < minimumDataCertificateGeneration {
        throw MachineDataVerifierError.certificateGenerationRollback
      }
      throw MachineDataVerifierError.invalidTrustBinding
    }
    if let notAfterMS = certificate.notAfterMs {
      let now =
        nowMilliseconds ?? UInt64(Date().timeIntervalSince1970 * 1_000)
      guard notAfterMS > now else {
        throw MachineDataVerifierError.expiredDataCertificate
      }
    }

    let certificateTBS = ToBeSignedV1(
      objectType: .dataCert,
      signatureFormatVersion: 1,
      relayProtocolVersion: relayProtocolVersionV2,
      runtimeProtocolVersion: runtimeProtocolVersionCurrent,
      e2eeFormatVersion: 1,
      relayServerID: relayServerID,
      machineRoute: machineRoute,
      deviceRoute: nil,
      streamRoute: nil,
      requestRoute: nil,
      streamGeneration: nil,
      streamCursor: nil,
      roleScope: "machine-data",
      signingKeyFingerprint: machineRootFingerprint,
      rootKeyID: certificate.rootKeyId,
      trustEpoch: certificate.trustEpoch,
      serialOrGeneration: certificate.generation,
      notAfterMS: certificate.notAfterMs,
      signedObjectSHA256: try SignedCertificateCanonicalCodec.unsignedCanonicalSHA256(
        certificate
      )
    )
    guard
      RelayCrypto.verify(
        certificate.signature,
        tbs: certificateTBS,
        key: rootKey
      )
    else {
      throw MachineDataVerifierError.invalidTrustBinding
    }
    return VerifiedMachineDataCertificate(
      certificate: certificate,
      signingKey: certificateKey
    )
  }

  private static func isNonzero(_ value: Data, count: Int) -> Bool {
    value.count == count && value.contains(where: { $0 != 0 })
  }
}

struct MachineDataVerifier: Sendable {
  private static let e2eeFormatVersion: UInt16 = 1

  private let machineRoute: Data
  private let deviceRoute: Data
  private let dataSigningKey: Curve25519.Signing.PublicKey
  private let currentKeyDirectoryRevision: UInt64
  private let maximumKeySyncAdvance: UInt64

  init(
    relayServerID: Data,
    machineRoute: Data,
    deviceRoute: Data,
    machineRootPublicKey: Data,
    machineRootFingerprint: Data,
    expectedRootKeyID: Data,
    expectedTrustEpoch: UInt64,
    dataCertificate: RelayV2SignedCertificate,
    minimumDataCertificateGeneration: UInt64,
    currentKeyDirectoryRevision: UInt64,
    maximumKeySyncAdvance: UInt64
  ) throws {
    let verifiedCertificate = try MachineDataCertificateVerifier.verify(
      dataCertificate,
      relayServerID: relayServerID,
      machineRoute: machineRoute,
      machineRootPublicKey: machineRootPublicKey,
      machineRootFingerprint: machineRootFingerprint,
      expectedRootKeyID: expectedRootKeyID,
      expectedTrustEpoch: expectedTrustEpoch,
      minimumDataCertificateGeneration: minimumDataCertificateGeneration
    )
    try self.init(
      machineRoute: machineRoute,
      deviceRoute: deviceRoute,
      verifiedCertificate: verifiedCertificate,
      currentKeyDirectoryRevision: currentKeyDirectoryRevision,
      maximumKeySyncAdvance: maximumKeySyncAdvance
    )
  }

  init(
    machineRoute: Data,
    deviceRoute: Data,
    verifiedCertificate: VerifiedMachineDataCertificate,
    currentKeyDirectoryRevision: UInt64,
    maximumKeySyncAdvance: UInt64
  ) throws {
    guard Self.isNonzero(machineRoute, count: 16),
      Self.isNonzero(deviceRoute, count: 16),
      currentKeyDirectoryRevision > 0,
      maximumKeySyncAdvance > 0
    else {
      throw MachineDataVerifierError.invalidTrustBinding
    }
    self.machineRoute = machineRoute
    self.deviceRoute = deviceRoute
    dataSigningKey = verifiedCertificate.signingKey
    self.currentKeyDirectoryRevision = currentKeyDirectoryRevision
    self.maximumKeySyncAdvance = maximumKeySyncAdvance
  }

  func verify(
    wireBytes: Data,
    context: OuterContextV1,
    receivingKey: MachineDataReceivingKeyBinding
  ) throws -> MachineDataVerificationResult {
    let (candidate, revisionDisposition) = try verifyCandidate(
      wireBytes: wireBytes,
      context: context,
      receivingKey: receivingKey
    )
    switch revisionDisposition {
    case .current:
      return .current(candidate)
    case .keySyncRequired:
      return .keySyncRequired(observedRevision: candidate.keyDirectoryRevision)
    }
  }

  private func verifyCandidate(
    wireBytes: Data,
    context: OuterContextV1,
    receivingKey: MachineDataReceivingKeyBinding
  ) throws -> (VerifiedMachineDataCandidate, RevisionDisposition) {
    let signed = try RelayV2SignedSealedBlobCodec.decode(
      wireBytes,
      maxEncodedBytes: RelayWireCodecV2.maxFrameBytes
    )

    try validateOuterContext(context, receivingKey: receivingKey, sealed: signed.inner)
    let revisionDisposition = try validateRevision(signed.inner.keyDirectoryRevision)
    let counter = try validateNonce(signed.inner.nonce, receivingKey: receivingKey)

    let verified = try RelayCrypto.verifySealed(
      signed,
      key: dataSigningKey,
      context: context
    )
    return (
      VerifiedMachineDataCandidate(
        verifiedBlob: verified,
        receivingKey: receivingKey.key,
        context: context,
        counter: counter,
        ciphertextHash: CanonicalCodec.sha256(signed.inner.ciphertext),
        keyDirectoryRevision: signed.inner.keyDirectoryRevision
      ),
      revisionDisposition
    )
  }

  /// 只有 verified candidate 才能进入 AEAD open；capability 再对密文内 kind 做穷举
  /// admission，错误 family 在 Runtime/key-control decode 之前 fail-close。
  func open(
    _ candidate: VerifiedMachineDataCandidate,
    receivingKey: MachineDataReceivingKeyBinding
  ) throws -> OpenedMachineDataPayload {
    guard candidate.keyDirectoryRevision == receivingKey.keyDirectoryRevision,
      candidate.receivingKey.keyID == receivingKey.key.keyID,
      candidate.context.frameKind == receivingKey.capability.frameKind
    else {
      throw MachineDataVerifierError.receivingKeyMismatch
    }
    let opened = try RelayCrypto.openSealedPayload(
      candidate.verifiedBlob,
      key: candidate.receivingKey,
      context: candidate.context
    )
    guard receivingKey.capability.admits(opened.payloadKind) else {
      throw MachineDataVerifierError.payloadKindMismatch
    }
    return OpenedMachineDataPayload(
      payloadKind: opened.payloadKind,
      payload: opened.payload
    )
  }

  /// exact-next KeySync directed Reply 的 signature/header admission。该方法只验到
  /// `VerifiedSealedBlobV1`，不执行 AEAD open，给 durable replay admission 留出强制边界。
  func verifyExactNextKeySyncReply(
    wireBytes: Data,
    context: OuterContextV1,
    capability: ExactNextKeySyncReplyCapability
  ) throws -> VerifiedExactNextKeySyncReplyCandidate {
    guard capability.currentRevision == currentKeyDirectoryRevision else {
      throw MachineDataVerifierError.receivingKeyMismatch
    }
    guard context.frameKind == .directedReply,
      context.machineRoute == machineRoute,
      context.deviceRoute == deviceRoute,
      context.streamRoute == nil,
      context.requestRoute == capability.requestRoute,
      context.streamGeneration == nil,
      context.streamCursor == nil,
      context.streamSeq == nil,
      context.pairRoute == nil
    else {
      throw MachineDataVerifierError.invalidRequestRoute
    }
    let (candidate, disposition) = try verifyCandidate(
      wireBytes: wireBytes,
      context: context,
      receivingKey: capability.currentBinding
    )
    guard disposition == .keySyncRequired,
      candidate.keyDirectoryRevision == capability.requestedRevision
    else {
      throw MachineDataVerifierError.exactNextRevisionRequired
    }
    // `verify` 已完成 MachineDataSign；这里只把同一 opaque SymmetricKey capability
    // 重绑定到 signed header 的 exact-next revision，未暴露 raw key。
    return VerifiedExactNextKeySyncReplyCandidate(
      candidate: VerifiedMachineDataCandidate(
        verifiedBlob: candidate.verifiedBlob,
        receivingKey: capability.nextBinding.key,
        context: context,
        counter: candidate.counter,
        ciphertextHash: candidate.ciphertextHash,
        keyDirectoryRevision: candidate.keyDirectoryRevision
      ),
      receivingKey: capability.nextBinding
    )
  }

  /// 只能在 caller 已把 candidate replay tuple durable admission 后调用。AEAD open 后
  /// 再 strict decode `KeyControlV1`，exact-next Reply 只接受 `UpdateSet` variant。
  func openExactNextKeySyncReply(
    _ verified: VerifiedExactNextKeySyncReplyCandidate
  ) throws -> VerifiedExactNextKeyUpdateSetV1 {
    guard case .updateSet(let updateSet) = try openExactNextKeySyncResponse(verified) else {
      throw MachineDataVerifierError.unexpectedKeyControlVariant
    }
    return updateSet
  }

  /// exact-next KeySync reply 的完整 typed response。`DirectoryCurrent` 表示 daemon
  /// 尚未冻结 requested revision，调用方只能消耗一次 bounded retry，不能把它当成功。
  func openExactNextKeySyncResponse(
    _ verified: VerifiedExactNextKeySyncReplyCandidate
  ) throws -> OpenedExactNextKeySyncReplyV1 {
    let opened = try open(
      verified.candidate,
      receivingKey: verified.receivingKey
    )
    guard opened.payloadKind == .keyUpdate else {
      throw MachineDataVerifierError.payloadKindMismatch
    }
    let control = try DaemonKeyControlCanonicalCodec.decode(opened.payload)
    switch control {
    case .updateSet(let updateSet):
      guard updateSet.keyDirectoryRevision == verified.keyDirectoryRevision,
        updateSet.deviceRoute == deviceRoute
      else {
        throw MachineDataVerifierError.keyControlRevisionMismatch
      }
      return .updateSet(try VerifiedExactNextKeyUpdateSetV1(updateSet: updateSet))
    case .directoryCurrent(let status):
      let next = status.currentKeyDirectoryRevision.addingReportingOverflow(1)
      guard status.authority.machineRoute == machineRoute,
        status.authority.deviceRoute == deviceRoute,
        !next.overflow,
        status.requestedKeyDirectoryRevision == next.partialValue,
        status.requestedKeyDirectoryRevision == verified.keyDirectoryRevision
      else {
        throw MachineDataVerifierError.keyControlRevisionMismatch
      }
      return .directoryCurrent(status)
    case .epochBarrier, .streamBinding, .directoryRevisionAdvance:
      throw MachineDataVerifierError.unexpectedKeyControlVariant
    }
  }

  /// unknown exact-next revision 可能已经携带全新的 keyID/epoch，不能先拿旧 AEAD key
  /// 做 header equality。这里仅按 outer family/domain 与 MachineDataSign 验证 probe；返回值
  /// 不携带 verified blob，也没有任何 AEAD-open 入口。
  func verifyExactNextHigherRevisionProbe(
    wireBytes: Data,
    context: OuterContextV1,
    expectedRequestRoute: Data? = nil
  ) throws -> VerifiedHigherRevisionMachineDataProbe {
    let signed = try RelayV2SignedSealedBlobCodec.decode(
      wireBytes,
      maxEncodedBytes: RelayWireCodecV2.maxFrameBytes
    )
    try validateHigherRevisionProbeOuterContext(
      context,
      sealed: signed.inner,
      expectedRequestRoute: expectedRequestRoute
    )
    let next = currentKeyDirectoryRevision.addingReportingOverflow(1)
    guard !next.overflow else {
      throw MachineDataVerifierError.exactNextRevisionRequired
    }
    if signed.inner.keyDirectoryRevision < currentKeyDirectoryRevision {
      throw MachineDataVerifierError.keyDirectoryRollback
    }
    guard signed.inner.keyDirectoryRevision == next.partialValue else {
      if signed.inner.keyDirectoryRevision > next.partialValue {
        throw MachineDataVerifierError.keyDirectoryAdvanceExceeded
      }
      throw MachineDataVerifierError.exactNextRevisionRequired
    }
    _ = try RelayCrypto.verifySealed(
      signed,
      key: dataSigningKey,
      context: context
    )
    return VerifiedHigherRevisionMachineDataProbe(
      sealed: signed.inner,
      context: context
    )
  }

  /// staged exact-next receiving capability 的 signature/header admission。EpochBarrier 使用
  /// next revision header；zero-cut DirectoryRevisionAdvance 按 daemon contract 使用 current
  /// revision header，但 AEAD material 来自已审计 staged Catalog carrier。
  func verifyStagedKeyControl(
    wireBytes: Data,
    context: OuterContextV1,
    capability: AuditedReceivingKeyCapabilityV1
  ) throws -> VerifiedStagedKeyControlCandidate {
    guard capability.lifecycle == .staged else {
      throw MachineDataVerifierError.receivingKeyMismatch
    }
    let next = currentKeyDirectoryRevision.addingReportingOverflow(1)
    guard !next.overflow,
      capability.keyDirectoryRevision == next.partialValue
    else {
      throw MachineDataVerifierError.exactNextRevisionRequired
    }
    let signed = try RelayV2SignedSealedBlobCodec.decode(
      wireBytes,
      maxEncodedBytes: RelayWireCodecV2.maxFrameBytes
    )
    guard
      signed.inner.keyDirectoryRevision == currentKeyDirectoryRevision
        || signed.inner.keyDirectoryRevision == capability.keyDirectoryRevision
    else {
      throw MachineDataVerifierError.keyControlRevisionMismatch
    }
    let receivingKey = try capability.machineDataBinding().rebinding(
      keyDirectoryRevision: signed.inner.keyDirectoryRevision
    )
    try validateStagedKeyControlOuterContext(
      context,
      receivingKey: receivingKey,
      sealed: signed.inner
    )
    let counter = try validateNonce(signed.inner.nonce, receivingKey: receivingKey)
    let verified = try RelayCrypto.verifySealed(
      signed,
      key: dataSigningKey,
      context: context
    )
    let candidate = VerifiedMachineDataCandidate(
      verifiedBlob: verified,
      receivingKey: receivingKey.key,
      context: context,
      counter: counter,
      ciphertextHash: CanonicalCodec.sha256(signed.inner.ciphertext),
      keyDirectoryRevision: signed.inner.keyDirectoryRevision
    )
    return VerifiedStagedKeyControlCandidate(
      candidate: candidate,
      receivingKey: receivingKey,
      replayScope: capability.replayScope,
      stagedKeyDirectoryRevision: capability.keyDirectoryRevision
    )
  }

  /// 只有 coordinator 对同一 staged-key tuple 给出 fresh/exact-duplicate active proof 后
  /// 才执行 AEAD open。inner 继续 strict decode，并只放行两种 activation control。
  func openStagedKeyControl(
    _ verified: VerifiedStagedKeyControlCandidate,
    replayAdmission: DurableReplayAdmissionResult
  ) throws -> OpenedStagedKeyControlV1 {
    let replayWasAdmitted: Bool
    switch replayAdmission.disposition {
    case .fresh, .exactDuplicate:
      replayWasAdmitted = true
    case .stale:
      replayWasAdmitted = false
    }
    guard replayWasAdmitted,
      replayAdmission.admissionProof.scope == verified.replayScope,
      replayAdmission.admissionProof.counter == verified.counter,
      replayAdmission.admissionProof.ciphertextHash == verified.ciphertextHash,
      replayAdmission.admissionProof.replayStatus == .active,
      replayAdmission.snapshot.state.replayStates.contains(where: {
        $0.scope == verified.replayScope && $0.status == .active
      })
    else {
      throw MachineDataVerifierError.stagedReplayAdmissionRequired
    }
    let opened = try open(
      verified.candidate,
      receivingKey: verified.receivingKey
    )
    guard opened.payloadKind == .keyUpdate else {
      throw MachineDataVerifierError.payloadKindMismatch
    }
    switch try DaemonKeyControlCanonicalCodec.decode(opened.payload) {
    case .epochBarrier(let barrier):
      guard verified.headerKeyDirectoryRevision == verified.stagedKeyDirectoryRevision,
        barrier.keyDirectoryRevision == verified.stagedKeyDirectoryRevision,
        barrier.streamRoute == verified.candidate.context.streamRoute,
        barrier.streamGeneration == verified.candidate.context.streamGeneration,
        barrier.appliedStreamSequence == verified.candidate.context.streamSeq,
        barrier.newEpoch == verified.receivingKey.key.keyID.epoch
      else {
        throw MachineDataVerifierError.keyControlRevisionMismatch
      }
      switch (verified.receivingKey.key.keyID.purpose, barrier.innerCursor) {
      case (.catalog, .catalog), (.conversationDEK, .conversation):
        break
      default:
        throw MachineDataVerifierError.unexpectedKeyControlVariant
      }
      return .epochBarrier(barrier)
    case .directoryRevisionAdvance(let advance):
      guard verified.receivingKey.key.keyID.purpose == .catalog,
        verified.headerKeyDirectoryRevision == currentKeyDirectoryRevision,
        advance.fromRevision == currentKeyDirectoryRevision,
        advance.toRevision == verified.stagedKeyDirectoryRevision
      else {
        throw MachineDataVerifierError.keyControlRevisionMismatch
      }
      return .directoryRevisionAdvance(try advance.binding(to: verified.candidate.context))
    case .updateSet, .directoryCurrent, .streamBinding:
      throw MachineDataVerifierError.unexpectedKeyControlVariant
    }
  }

  /// partial activation 已切换 slot 的 next-revision admission。与 staged control 不同，
  /// 该能力允许普通业务 payload；KeyControl 则在 open 阶段继续收紧到 durable proof。
  func verifyActivatedPendingMachineData(
    wireBytes: Data,
    context: OuterContextV1,
    capability: AuditedReceivingKeyCapabilityV1,
    expectedRequestRoute: Data? = nil
  ) throws -> VerifiedActivatedPendingMachineDataCandidate {
    guard capability.lifecycle == .activatedPending else {
      throw MachineDataVerifierError.receivingKeyMismatch
    }
    let proof = try capability.activatedPendingProof()
    let next = currentKeyDirectoryRevision.addingReportingOverflow(1)
    guard !next.overflow,
      capability.keyDirectoryRevision == next.partialValue,
      proof.keyDirectoryRevision == capability.keyDirectoryRevision
    else {
      throw MachineDataVerifierError.exactNextRevisionRequired
    }
    let receivingKey = try capability.machineDataBinding()
    let candidate = try verifyRetainedCandidate(
      wireBytes: wireBytes,
      context: context,
      receivingKey: receivingKey,
      expectedRequestRoute: expectedRequestRoute
    )
    return try VerifiedActivatedPendingMachineDataCandidate(
      candidate: candidate,
      receivingKey: receivingKey,
      capability: capability
    )
  }

  /// ordinary payload 可在 active replay admission 后打开；`.keyUpdate` 必须同时是
  /// exact replay duplicate、exact EpochBarrier carrier 与 capability 内的 durable proof。
  func openActivatedPendingMachineData(
    _ verified: VerifiedActivatedPendingMachineDataCandidate,
    replayAdmission: DurableReplayAdmissionResult
  ) throws -> OpenedActivatedPendingMachineDataV1 {
    guard
      activeReplayAdmissionMatches(
        replayAdmission,
        scope: verified.replayScope,
        counter: verified.counter,
        ciphertextHash: verified.ciphertextHash
      )
    else {
      throw MachineDataVerifierError.activatedPendingReplayAdmissionRequired
    }
    let opened = try open(
      verified.candidate,
      receivingKey: verified.receivingKey
    )
    guard opened.payloadKind == .keyUpdate else {
      return .data(opened)
    }
    guard replayAdmission.disposition == .exactDuplicate,
      case .epochBarrier(let barrier) = try DaemonKeyControlCanonicalCodec.decode(
        opened.payload
      ),
      barrier == verified.activationProof,
      contextMatches(
        verified.candidate.context,
        activationProof: verified.activationProof
      )
    else {
      throw MachineDataVerifierError.activationProofMismatch
    }
    return .epochBarrierDuplicate(barrier)
  }

  /// same-target rebind 后被移出 live streamStates 的旧 route，只能经该 exact alias
  /// 验签；返回的 candidate 没有普通 payload open API。
  func verifyEpochBarrierProofAlias(
    wireBytes: Data,
    context: OuterContextV1,
    capability: AuditedReceivingKeyCapabilityV1
  ) throws -> VerifiedEpochBarrierProofAliasCandidate {
    guard capability.lifecycle == .epochBarrierProofAlias else {
      throw MachineDataVerifierError.receivingKeyMismatch
    }
    let proof = try capability.epochBarrierAliasProof()
    let next = currentKeyDirectoryRevision.addingReportingOverflow(1)
    guard proof.keyDirectoryRevision == capability.keyDirectoryRevision,
      capability.keyDirectoryRevision == currentKeyDirectoryRevision
        || (!next.overflow && capability.keyDirectoryRevision == next.partialValue),
      contextMatches(context, activationProof: proof)
    else {
      throw MachineDataVerifierError.activationProofMismatch
    }
    let receivingKey = try capability.machineDataBinding()
    let candidate = try verifyRetainedCandidate(
      wireBytes: wireBytes,
      context: context,
      receivingKey: receivingKey,
      expectedRequestRoute: nil
    )
    return try VerifiedEpochBarrierProofAliasCandidate(
      candidate: candidate,
      receivingKey: receivingKey,
      capability: capability
    )
  }

  /// proof alias 永远只打开 exact duplicate EpochBarrier；fresh、普通数据、其它
  /// KeyControl 或任一 outer/proof 轴变化都会 fail-close。
  func openEpochBarrierProofAlias(
    _ verified: VerifiedEpochBarrierProofAliasCandidate,
    replayAdmission: DurableReplayAdmissionResult
  ) throws -> DeviceEpochBarrierV1 {
    guard replayAdmission.disposition == .exactDuplicate,
      activeReplayAdmissionMatches(
        replayAdmission,
        scope: verified.replayScope,
        counter: verified.counter,
        ciphertextHash: verified.ciphertextHash
      )
    else {
      throw MachineDataVerifierError.activatedPendingReplayAdmissionRequired
    }
    let opened = try open(
      verified.candidate,
      receivingKey: verified.receivingKey
    )
    guard opened.payloadKind == .keyUpdate,
      case .epochBarrier(let barrier) = try DaemonKeyControlCanonicalCodec.decode(
        opened.payload
      ),
      barrier == verified.activationProof,
      contextMatches(
        verified.candidate.context,
        activationProof: verified.activationProof
      )
    else {
      throw MachineDataVerifierError.activationProofMismatch
    }
    return barrier
  }

  /// lastDirectoryAdvanceProof 派生的 predecessor header admission。revision、route、
  /// generation、sequence 都在验签前按 durable proof 精确收紧。
  func verifyDirectoryAdvancePredecessor(
    wireBytes: Data,
    context: OuterContextV1,
    capability: AuditedReceivingKeyCapabilityV1
  ) throws -> VerifiedDirectoryAdvancePredecessorCandidate {
    guard capability.lifecycle == .directoryAdvancePredecessor else {
      throw MachineDataVerifierError.receivingKeyMismatch
    }
    let proof = try capability.directoryAdvancePredecessorProof()
    guard proof.toRevision == currentKeyDirectoryRevision,
      capability.keyDirectoryRevision == proof.fromRevision,
      contextMatches(context, directoryAdvanceProof: proof)
    else {
      throw MachineDataVerifierError.directoryAdvanceProofMismatch
    }
    let receivingKey = try capability.machineDataBinding()
    let candidate = try verifyRetainedCandidate(
      wireBytes: wireBytes,
      context: context,
      receivingKey: receivingKey,
      expectedRequestRoute: nil
    )
    return try VerifiedDirectoryAdvancePredecessorCandidate(
      candidate: candidate,
      receivingKey: receivingKey,
      capability: capability
    )
  }

  /// predecessor material 不形成 rollback decrypt 面：只有 durable replay exact duplicate
  /// 且 inner/outer 合并后等于 lastDirectoryAdvanceProof 才返回 proof。
  func openDirectoryAdvancePredecessor(
    _ verified: VerifiedDirectoryAdvancePredecessorCandidate,
    replayAdmission: DurableReplayAdmissionResult
  ) throws -> DeviceDirectoryRevisionAdvanceV1 {
    guard replayAdmission.disposition == .exactDuplicate,
      activeReplayAdmissionMatches(
        replayAdmission,
        scope: verified.replayScope,
        counter: verified.counter,
        ciphertextHash: verified.ciphertextHash
      )
    else {
      throw MachineDataVerifierError.directoryAdvanceReplayAdmissionRequired
    }
    let opened = try open(
      verified.candidate,
      receivingKey: verified.receivingKey
    )
    guard opened.payloadKind == .keyUpdate,
      case .directoryRevisionAdvance(let advance) =
        try DaemonKeyControlCanonicalCodec.decode(opened.payload),
      let bound = try? advance.binding(to: verified.candidate.context),
      bound == verified.directoryAdvanceProof
    else {
      throw MachineDataVerifierError.directoryAdvanceProofMismatch
    }
    return bound
  }

  /// cold-open resolver 已证明 carrier 属于未到期 retired lifecycle；这里按 exact
  /// signed header/key/route 验 MachineDataSign，但仍不执行 AEAD open。
  func verifyRetiredMachineData(
    wireBytes: Data,
    context: OuterContextV1,
    capability: AuditedReceivingKeyCapabilityV1,
    expectedRequestRoute: Data? = nil
  ) throws -> VerifiedRetiredMachineDataCandidate {
    guard case .retired = capability.lifecycle else {
      throw MachineDataVerifierError.receivingKeyMismatch
    }
    let receivingKey = try capability.machineDataBinding()
    let candidate = try verifyRetainedCandidate(
      wireBytes: wireBytes,
      context: context,
      receivingKey: receivingKey,
      expectedRequestRoute: expectedRequestRoute
    )
    return VerifiedRetiredMachineDataCandidate(
      candidate: candidate,
      receivingKey: receivingKey,
      lifecycle: capability.lifecycle,
      replayScope: capability.replayScope
    )
  }

  /// retired delayed frame 只允许 coordinator 已记录的 exact tuple 解密；fresh predecessor、
  /// stale、到期或 GC 后都无法伪造此 proof/capability 组合。
  func openRetiredMachineData(
    _ verified: VerifiedRetiredMachineDataCandidate,
    replayAdmission: DurableReplayAdmissionResult
  ) throws -> OpenedMachineDataPayload {
    guard case .retired(let retiredAtMS, let deleteAfterMS) = verified.lifecycle,
      replayAdmission.disposition == .exactDuplicate,
      replayAdmission.admissionProof.scope == verified.replayScope,
      replayAdmission.admissionProof.counter == verified.counter,
      replayAdmission.admissionProof.ciphertextHash == verified.ciphertextHash,
      replayAdmission.admissionProof.replayStatus
        == .retired(retiredAtMS: retiredAtMS, deleteAfterMS: deleteAfterMS),
      replayAdmission.snapshot.state.replayStates.contains(where: {
        $0.scope == verified.replayScope
          && $0.status
            == .retired(retiredAtMS: retiredAtMS, deleteAfterMS: deleteAfterMS)
      })
    else {
      throw MachineDataVerifierError.retiredReplayAdmissionRequired
    }
    return try open(
      verified.candidate,
      receivingKey: verified.receivingKey
    )
  }

  private func verifyRetainedCandidate(
    wireBytes: Data,
    context: OuterContextV1,
    receivingKey: MachineDataReceivingKeyBinding,
    expectedRequestRoute: Data?
  ) throws -> VerifiedMachineDataCandidate {
    let signed = try RelayV2SignedSealedBlobCodec.decode(
      wireBytes,
      maxEncodedBytes: RelayWireCodecV2.maxFrameBytes
    )
    try validateRetainedOuterContext(
      context,
      receivingKey: receivingKey,
      sealed: signed.inner,
      expectedRequestRoute: expectedRequestRoute
    )
    let counter = try validateNonce(signed.inner.nonce, receivingKey: receivingKey)
    let verified = try RelayCrypto.verifySealed(
      signed,
      key: dataSigningKey,
      context: context
    )
    return VerifiedMachineDataCandidate(
      verifiedBlob: verified,
      receivingKey: receivingKey.key,
      context: context,
      counter: counter,
      ciphertextHash: CanonicalCodec.sha256(signed.inner.ciphertext),
      keyDirectoryRevision: signed.inner.keyDirectoryRevision
    )
  }

  private func activeReplayAdmissionMatches(
    _ replayAdmission: DurableReplayAdmissionResult,
    scope: DeviceCryptoKeyScopeV1,
    counter: UInt64,
    ciphertextHash: Data
  ) -> Bool {
    let admitted: Bool
    switch replayAdmission.disposition {
    case .fresh, .exactDuplicate:
      admitted = true
    case .stale:
      admitted = false
    }
    return admitted
      && replayAdmission.admissionProof.scope == scope
      && replayAdmission.admissionProof.counter == counter
      && replayAdmission.admissionProof.ciphertextHash == ciphertextHash
      && replayAdmission.admissionProof.replayStatus == .active
      && replayAdmission.snapshot.state.replayStates.contains(where: {
        $0.scope == scope && $0.status == .active
      })
  }

  private func contextMatches(
    _ context: OuterContextV1,
    activationProof: DeviceEpochBarrierV1
  ) -> Bool {
    context.streamRoute == activationProof.streamRoute
      && context.streamGeneration == activationProof.streamGeneration
      && context.streamCursor == nil
      && context.streamSeq == activationProof.appliedStreamSequence
      && context.requestRoute == nil
      && context.pairRoute == nil
  }

  private func contextMatches(
    _ context: OuterContextV1,
    directoryAdvanceProof: DeviceDirectoryRevisionAdvanceV1
  ) -> Bool {
    context.frameKind == .catalogPublish
      && context.streamRoute == directoryAdvanceProof.streamRoute
      && context.streamGeneration == directoryAdvanceProof.streamGeneration
      && context.streamCursor == nil
      && context.streamSeq == directoryAdvanceProof.streamSequence
      && context.requestRoute == nil
      && context.pairRoute == nil
  }

  private func validateOuterContext(
    _ context: OuterContextV1,
    receivingKey: MachineDataReceivingKeyBinding,
    sealed: UnsignedSealedBlobV1
  ) throws {
    guard context.relayProtocolVersion == relayProtocolVersionV2,
      context.e2eeFormatVersion == Self.e2eeFormatVersion,
      context.frameKind == receivingKey.capability.frameKind,
      context.machineRoute == machineRoute,
      context.deviceRoute.map({ $0 == deviceRoute }) ?? true,
      context.streamRoute == receivingKey.streamRoute,
      context.messageKeyEpoch == sealed.keyEpoch,
      sealed.keyID == receivingKey.key.keyID,
      sealed.keyEpoch == receivingKey.key.epoch,
      receivingKey.keyDirectoryRevision == currentKeyDirectoryRevision
    else {
      throw MachineDataVerifierError.invalidOuterContext
    }
  }

  private func validateRetainedOuterContext(
    _ context: OuterContextV1,
    receivingKey: MachineDataReceivingKeyBinding,
    sealed: UnsignedSealedBlobV1,
    expectedRequestRoute: Data?
  ) throws {
    let routeShapeIsValid: Bool
    switch receivingKey.capability {
    case .catalogPublication, .conversationPublication:
      routeShapeIsValid =
        context.deviceRoute.map({ $0 == deviceRoute }) ?? true
        && context.requestRoute == nil
        && expectedRequestRoute == nil
    case .directedReply:
      routeShapeIsValid =
        context.deviceRoute == deviceRoute
        && expectedRequestRoute.map({ context.requestRoute == $0 }) == true
        && context.streamGeneration == nil
        && context.streamCursor == nil
        && context.streamSeq == nil
    }
    guard routeShapeIsValid,
      context.relayProtocolVersion == relayProtocolVersionV2,
      context.e2eeFormatVersion == Self.e2eeFormatVersion,
      context.frameKind == receivingKey.capability.frameKind,
      context.machineRoute == machineRoute,
      context.streamRoute == receivingKey.streamRoute,
      context.pairRoute == nil,
      context.messageKeyEpoch == sealed.keyEpoch,
      sealed.keyID == receivingKey.key.keyID,
      sealed.keyEpoch == receivingKey.key.epoch,
      sealed.keyDirectoryRevision == receivingKey.keyDirectoryRevision
    else {
      throw MachineDataVerifierError.invalidOuterContext
    }
  }

  private func validateHigherRevisionProbeOuterContext(
    _ context: OuterContextV1,
    sealed: UnsignedSealedBlobV1,
    expectedRequestRoute: Data?
  ) throws {
    let familyIsValid: Bool
    switch (context.frameKind, sealed.keyID.purpose) {
    case (.catalogPublish, .catalog), (.conversationPublish, .conversationDEK):
      familyIsValid =
        expectedRequestRoute == nil
        && context.deviceRoute == nil
        && context.streamRoute.map({ Self.isNonzero($0, count: 16) }) == true
        && context.requestRoute == nil
        && context.streamGeneration.map({ Self.isNonzero($0, count: 16) }) == true
        && context.streamCursor == nil
        && context.streamSeq.map({ $0 < UInt64.max }) == true
    case (.directedReply, .deviceReplyTx):
      familyIsValid =
        expectedRequestRoute.map({ Self.isNonzero($0, count: 16) }) == true
        && context.deviceRoute == deviceRoute
        && context.streamRoute == nil
        && context.requestRoute == expectedRequestRoute
        && context.streamGeneration == nil
        && context.streamCursor == nil
        && context.streamSeq == nil
    default:
      familyIsValid = false
    }
    guard familyIsValid,
      context.relayProtocolVersion == relayProtocolVersionV2,
      context.e2eeFormatVersion == Self.e2eeFormatVersion,
      context.machineRoute == machineRoute,
      context.pairRoute == nil,
      context.messageKeyEpoch == sealed.keyEpoch,
      sealed.keyID.epoch > 0,
      sealed.keyEpoch == sealed.keyID.epoch,
      sealed.nonce.count == 12
    else {
      throw MachineDataVerifierError.invalidOuterContext
    }
  }

  private func validateStagedKeyControlOuterContext(
    _ context: OuterContextV1,
    receivingKey: MachineDataReceivingKeyBinding,
    sealed: UnsignedSealedBlobV1
  ) throws {
    guard
      receivingKey.key.keyID.purpose == .catalog
        || receivingKey.key.keyID.purpose == .conversationDEK,
      context.deviceRoute == nil,
      context.requestRoute == nil,
      context.streamGeneration.map({ Self.isNonzero($0, count: 16) }) == true,
      context.streamCursor == nil,
      context.streamSeq.map({ $0 < UInt64.max }) == true
    else {
      throw MachineDataVerifierError.invalidOuterContext
    }
    try validateRetainedOuterContext(
      context,
      receivingKey: receivingKey,
      sealed: sealed,
      expectedRequestRoute: nil
    )
  }

  private func validateRevision(_ observed: UInt64) throws -> RevisionDisposition {
    if observed < currentKeyDirectoryRevision {
      throw MachineDataVerifierError.keyDirectoryRollback
    }
    if observed == currentKeyDirectoryRevision {
      return .current
    }
    let advance = observed.subtractingReportingOverflow(currentKeyDirectoryRevision)
    guard !advance.overflow, advance.partialValue <= maximumKeySyncAdvance else {
      throw MachineDataVerifierError.keyDirectoryAdvanceExceeded
    }
    return .keySyncRequired
  }

  private func validateNonce(
    _ nonce: Data,
    receivingKey: MachineDataReceivingKeyBinding
  ) throws -> UInt64 {
    guard nonce.count == 12,
      Data(nonce.prefix(4)) == receivingKey.noncePrefix
    else {
      throw MachineDataVerifierError.invalidNonceBinding
    }
    return nonce.suffix(8).reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
  }

  private static func isNonzero(_ value: Data, count: Int) -> Bool {
    value.count == count && value.contains(where: { $0 != 0 })
  }
}

private enum RevisionDisposition: Equatable {
  case current
  case keySyncRequired
}
