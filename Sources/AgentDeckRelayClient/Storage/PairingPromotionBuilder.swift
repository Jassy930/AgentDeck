import CryptoKit
import Foundation

enum PairingPromotionBuilderError: Error, Equatable, Sendable {
  case invalidBinding
  case invalidDirectory
  case invalidState
}

enum PairingPromotionBuilder {
  static func makeResponseState(
    clientKind: RelayClientKind,
    installationID: UUID,
    verified: VerifiedPendingPairResponseV1,
    prepared: PreparedPendingPairingV1,
    nowMilliseconds: UInt64
  ) throws -> PendingPairingResponseStateV1 {
    guard isNonzeroRelayInstallationID(installationID),
      prepared.record.clientKind == clientKind,
      prepared.record.installationID == installationID,
      verified.info.requestHash == prepared.record.requestHash,
      verified.info.inviteHash == prepared.record.inviteHash,
      verified.info.pairRoute == prepared.invite.pairRoute,
      verified.responseHash == CanonicalCodec.sha256(verified.canonicalResponse),
      nowMilliseconds > 0
    else {
      throw PairingPromotionBuilderError.invalidBinding
    }
    let promotionID = try promotionID(
      installationID: installationID,
      verified: verified,
      machineRootFingerprint: prepared.invite.machineRootFingerprint
    )
    let storageKEK = try DeviceStorageKEK.generate()
    let receipt = try PairResponseCrypto.sealPairResponseReceived(
      verified: verified,
      invite: prepared.invite,
      deviceSigningKey: prepared.deviceSigningKey
    )
    let pairedRecord = try makePairedRecord(
      clientKind: clientKind,
      installationID: installationID,
      verified: verified,
      prepared: prepared,
      createdAtMilliseconds: nowMilliseconds
    )
    let pairedRecordCanonicalBytes = try PairedMachineRecordCodec.encode(pairedRecord)
    let unsigned = try PendingPairingResponseStateV1(
      responseHash: verified.responseHash,
      machineRoute: verified.info.machineRoute,
      deviceRoute: verified.info.deviceRoute,
      createdAtMilliseconds: nowMilliseconds,
      promotionID: promotionID,
      storageKEK: storageKEK.rawRepresentation,
      pairedRecordCanonicalBytes: pairedRecordCanonicalBytes,
      receiptCarrier: receipt.canonicalBytes,
      receiptAuditSignature: Data(repeating: 0, count: 64),
      requireAuditSignature: false
    )
    let auditSignature = try prepared.deviceSigningKey.signature(
      for: responseAuditTBS(
        unsigned,
        clientKind: clientKind,
        installationID: installationID,
        inviteHash: prepared.record.inviteHash,
        requestHash: prepared.record.requestHash
      )
    )
    return try PendingPairingResponseStateV1(
      responseHash: unsigned.responseHash,
      machineRoute: unsigned.machineRoute,
      deviceRoute: unsigned.deviceRoute,
      createdAtMilliseconds: unsigned.createdAtMilliseconds,
      promotionID: unsigned.promotionID,
      storageKEK: unsigned.storageKEK,
      pairedRecordCanonicalBytes: unsigned.pairedRecordCanonicalBytes,
      receiptCarrier: unsigned.receiptCarrier,
      receiptAuditSignature: auditSignature
    )
  }

  static func makePromotion(
    clientKind: RelayClientKind,
    installationID: UUID,
    verified: VerifiedPendingPairResponseV1,
    prepared: PreparedPendingPairingV1,
    response: PendingPairingResponseStateV1
  ) throws -> PreparedPairedMachinePromotionV1 {
    let expectedPromotionID = try promotionID(
      installationID: installationID,
      verified: verified,
      machineRootFingerprint: prepared.invite.machineRootFingerprint
    )
    try auditResponseState(
      response,
      clientKind: clientKind,
      installationID: installationID,
      inviteHash: prepared.record.inviteHash,
      requestHash: prepared.record.requestHash,
      deviceSigningPublicKey: prepared.deviceSigningKey.publicKey
    )
    guard isNonzeroRelayInstallationID(installationID),
      prepared.record.clientKind == clientKind,
      prepared.record.installationID == installationID,
      verified.info.requestHash == prepared.record.requestHash,
      verified.info.inviteHash == prepared.record.inviteHash,
      verified.info.pairRoute == prepared.invite.pairRoute,
      response.responseHash == verified.responseHash,
      response.machineRoute == verified.info.machineRoute,
      response.deviceRoute == verified.info.deviceRoute,
      response.promotionID == expectedPromotionID
    else {
      throw PairingPromotionBuilderError.invalidBinding
    }
    let record = try makePairedRecord(
      clientKind: clientKind,
      installationID: installationID,
      verified: verified,
      prepared: prepared,
      createdAtMilliseconds: response.createdAtMilliseconds
    )
    guard
      try PairedMachineRecordCodec.encode(record)
        == response.pairedRecordCanonicalBytes
    else {
      throw PairingPromotionBuilderError.invalidBinding
    }
    let directoryVerifier = try KeyDirectoryVerifier(
      record: record,
      verifiedCertificate: verified.verifiedCertificate,
      deviceHPKEPrivateKey: prepared.deviceHPKEPrivateKey
    )
    let expectedConversationRoutes = verified.plaintext.keyDirectory.entries.compactMap {
      $0.keyID.purpose == .conversationDEK ? $0.streamRoute : nil
    }
    let audited: AuditedBootstrapKeyDirectoryV1
    do {
      audited = try directoryVerifier.auditBootstrapDirectory(
        canonicalBytes: verified.plaintext.keyDirectoryCanonicalBytes,
        expectedRevision: verified.plaintext.keyDirectory.revision,
        expectedConversationRoutes: expectedConversationRoutes
      )
    } catch {
      throw PairingPromotionBuilderError.invalidDirectory
    }
    let initialState = try makeInitialState(
      record: record,
      audited: audited
    )
    return try PreparedPairedMachinePromotionV1(
      record: record,
      promotionID32: response.promotionID,
      deviceSignPrivateKey: prepared.deviceSigningKey.rawRepresentation,
      deviceHPKEPrivateKey: prepared.deviceHPKEPrivateKey.rawRepresentation,
      deviceGrant: verified.plaintext.relayGrantCanonicalBytes,
      deviceStorageKEK: DeviceStorageKEK(rawRepresentation: response.storageKEK),
      initialCryptoState: CryptoStateSnapshot(initialState)
    )
  }

  private static func makeInitialState(
    record: StoredPairedMachineRecordV1,
    audited: AuditedBootstrapKeyDirectoryV1
  ) throws -> DeviceCryptoStateV1 {
    let trust = try DeviceCryptoTrustScopeV1(
      relayServerID: record.relayServerID,
      machineRootFingerprint: record.machineRootFingerprint,
      machineRoute: record.machineRoute,
      deviceRoute: record.deviceRoute,
      grantSerial: record.grantSerial,
      trustEpoch: record.trustEpoch
    )
    let sender = try DeviceSenderCounterV1(
      keyID: audited.commandKey.keyID,
      keyDirectoryRevision: audited.directory.revision,
      noncePrefix: audited.commandKey.noncePrefix,
      reservedHighWater: 0,
      reservationID: Data(repeating: 0, count: 16)
    )
    let replayStates = try audited.receivingKeys.map { receiving in
      try DeviceReplayStateV1(
        scope: DeviceCryptoKeyScopeV1(
          keyID: receiving.key.keyID,
          streamRoute: receiving.streamRoute
        ),
        window: ReplayWindowSnapshot(highWater: nil, floor: 0, entries: []),
        status: .active
      )
    }
    do {
      return try DeviceCryptoStateV1(
        stateRevision: 1,
        trustScope: trust,
        keyDirectory: audited.directory,
        senderCounter: sender,
        securityState: .active,
        replayStates: replayStates,
        streamStates: []
      )
    } catch {
      throw PairingPromotionBuilderError.invalidState
    }
  }

  private static func promotionID(
    installationID: UUID,
    verified: VerifiedPendingPairResponseV1,
    machineRootFingerprint: Data
  ) throws -> Data {
    guard machineRootFingerprint.count == 32,
      machineRootFingerprint.contains(where: { $0 != 0 })
    else {
      throw PairingPromotionBuilderError.invalidBinding
    }
    var input = Data("AgentDeck/SwiftPairedPromotionV1\0".utf8)
    var installationBytes = installationID.uuid
    input.append(withUnsafeBytes(of: &installationBytes) { Data($0) })
    input.append(verified.info.inviteHash)
    input.append(verified.info.requestHash)
    input.append(verified.responseHash)
    input.append(machineRootFingerprint)
    input.append(verified.info.machineRoute)
    let value = CanonicalCodec.sha256(input)
    guard value.contains(where: { $0 != 0 }) else {
      throw PairingPromotionBuilderError.invalidState
    }
    return value
  }

  static func auditResponseState(
    _ response: PendingPairingResponseStateV1,
    clientKind: RelayClientKind,
    installationID: UUID,
    inviteHash: Data,
    requestHash: Data,
    deviceSigningPublicKey: Curve25519.Signing.PublicKey
  ) throws {
    guard response.receiptAuditSignature.count == 64,
      response.receiptAuditSignature.contains(where: { $0 != 0 }),
      deviceSigningPublicKey.isValidSignature(
        response.receiptAuditSignature,
        for: try responseAuditTBS(
          response,
          clientKind: clientKind,
          installationID: installationID,
          inviteHash: inviteHash,
          requestHash: requestHash
        )
      )
    else {
      throw PairingPromotionBuilderError.invalidBinding
    }
  }

  static func attestResponseStateForPersistence(
    _ response: PendingPairingResponseStateV1,
    prepared: PreparedPendingPairingV1
  ) throws -> PendingPairingResponseStateV1 {
    let signature = try prepared.deviceSigningKey.signature(
      for: responseAuditTBS(
        response,
        clientKind: prepared.record.clientKind,
        installationID: prepared.record.installationID,
        inviteHash: prepared.record.inviteHash,
        requestHash: prepared.record.requestHash
      )
    )
    return try PendingPairingResponseStateV1(
      responseHash: response.responseHash,
      machineRoute: response.machineRoute,
      deviceRoute: response.deviceRoute,
      createdAtMilliseconds: response.createdAtMilliseconds,
      promotionID: response.promotionID,
      storageKEK: response.storageKEK,
      pairedRecordCanonicalBytes: response.pairedRecordCanonicalBytes,
      receiptCarrier: response.receiptCarrier,
      receiptAuditSignature: signature
    )
  }

  private static func responseAuditTBS(
    _ response: PendingPairingResponseStateV1,
    clientKind: RelayClientKind,
    installationID: UUID,
    inviteHash: Data,
    requestHash: Data
  ) throws -> Data {
    guard isNonzeroRelayInstallationID(installationID),
      inviteHash.count == 32,
      requestHash.count == 32
    else {
      throw PairingPromotionBuilderError.invalidBinding
    }
    var value = Data("AgentDeck/PendingPairingResponseAuditV1\0".utf8)
    switch clientKind {
    case .macOSApp: value.append(0)
    case .iOSApp: value.append(1)
    case .cli: value.append(2)
    }
    var installationBytes = installationID.uuid
    value.append(withUnsafeBytes(of: &installationBytes) { Data($0) })
    value.append(inviteHash)
    value.append(requestHash)
    value.append(response.responseHash)
    value.append(response.machineRoute)
    value.append(response.deviceRoute)
    var createdAt = response.createdAtMilliseconds.bigEndian
    value.append(withUnsafeBytes(of: &createdAt) { Data($0) })
    value.append(response.promotionID)
    value.append(CanonicalCodec.sha256(response.storageKEK))
    value.append(CanonicalCodec.sha256(response.pairedRecordCanonicalBytes))
    value.append(CanonicalCodec.sha256(response.receiptCarrier))
    return value
  }

  private static func makePairedRecord(
    clientKind: RelayClientKind,
    installationID: UUID,
    verified: VerifiedPendingPairResponseV1,
    prepared: PreparedPendingPairingV1,
    createdAtMilliseconds: UInt64
  ) throws -> StoredPairedMachineRecordV1 {
    let relayURL = try canonicalRelayURL(prepared.invite.wssURL)
    return try StoredPairedMachineRecordV1(
      clientKind: clientKind,
      installationID: installationID,
      machineID: machineID(rootFingerprint: prepared.invite.machineRootFingerprint),
      machineName: prepared.invite.machineDisplayName,
      relayURL: relayURL,
      relayServerID: verified.info.relayServerID,
      machineRootPublicKey: prepared.invite.machineRootPublicKey,
      machineRootFingerprint: prepared.invite.machineRootFingerprint,
      machineDataCertificate: verified.verifiedCertificate.certificate,
      machineRoute: verified.info.machineRoute,
      deviceRoute: verified.info.deviceRoute,
      currentSPKIPin: prepared.invite.currentSPKIPin,
      nextSPKIPin: prepared.invite.nextSPKIPin == prepared.invite.currentSPKIPin
        ? nil : prepared.invite.nextSPKIPin,
      grantSerial: verified.info.grantSerial,
      trustEpoch: verified.info.rootTrustEpoch,
      createdAtMS: createdAtMilliseconds
    )
  }

  static func machineID(rootFingerprint: Data) -> String {
    "machine-"
      + rootFingerprint.base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
  }

  private static func canonicalRelayURL(_ value: String) throws -> URL {
    guard let url = URL(string: value), url.absoluteString == value else {
      throw PairingPromotionBuilderError.invalidBinding
    }
    return url
  }
}
