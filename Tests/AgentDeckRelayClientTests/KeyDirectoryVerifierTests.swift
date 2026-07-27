import AgentDeckCore
import CryptoKit
import Foundation
import XCTest

@testable import AgentDeckRelayClient

final class KeyDirectoryVerifierTests: XCTestCase {
  func testRustCanonicalTBSInfoAADAndHPKEVectorMatchExactly() throws {
    let vectors = try loadKeyDirectoryVectors()
    let hpke = try loadVectorSection("hpke_base_kat")
    let infos = try loadVectorSection("hpke_infos")
    let dataKey = try Curve25519.Signing.PrivateKey(
      rawRepresentation: try vectorData("dataSigningSeedHex", in: vectors)
    )
    let certificate = try SignedCertificateCanonicalCodec.decode(
      try vectorData("dataCertificateCanonicalHex", in: vectors)
    )
    let record = try makeRecord(
      relayServerID: Data(repeating: 0x88, count: 16),
      machineRoute: Data(repeating: 0x11, count: 16),
      deviceRoute: Data(repeating: 0x22, count: 16),
      grantSerial: 9,
      trustEpoch: 3,
      certificate: certificate
    )
    let recipient = try Curve25519.KeyAgreement.PrivateKey(
      rawRepresentation: try vectorData("recipientPrivHex", in: hpke)
    )
    let verifier = try KeyDirectoryVerifier(
      record: record,
      verifiedCertificate: VerifiedMachineDataCertificate(
        certificate: certificate,
        signingKey: dataKey.publicKey
      ),
      deviceHPKEPrivateKey: recipient
    )

    let directoryCanonical = try vectorData("keyDirectoryCanonicalHex", in: vectors)
    let directory = try KeyDirectoryCanonicalCodec.decode(directoryCanonical)
    XCTAssertEqual(try KeyDirectoryCanonicalCodec.encode(directory), directoryCanonical)
    XCTAssertEqual(
      try KeyDirectoryCanonicalCodec.unsignedCanonicalBytes(directory),
      try vectorData("keyDirectoryUnsignedHex", in: vectors)
    )
    XCTAssertEqual(
      try verifier.directorySignatureTBS(directory),
      try vectorData("keyDirectoryTbsHex", in: vectors)
    )

    let updateCanonical = try vectorData("keyUpdateCanonicalHex", in: vectors)
    let update = try KeyUpdateCanonicalCodec.decode(updateCanonical)
    XCTAssertEqual(try KeyUpdateCanonicalCodec.encode(update), updateCanonical)
    XCTAssertEqual(
      try KeyUpdateCanonicalCodec.unsignedCanonicalBytes(update),
      try vectorData("keyUpdateUnsignedHex", in: vectors)
    )
    let sealing = try verifier.sealingContext(
      keyDirectoryRevision: update.keyDirectoryRevision,
      keyID: update.keyID,
      streamRoute: update.streamRoute
    )
    XCTAssertEqual(sealing.info, try vectorData("keyUpdateInfoHex", in: infos))
    XCTAssertEqual(
      try CanonicalCodec.encodeAAD(sealing.outerContext), try vectorData("aadHex", in: hpke))
    XCTAssertEqual(
      try verifier.keyUpdateSignatureTBS(update, sealing: sealing),
      try vectorData("keyUpdateTbsHex", in: vectors)
    )

    let signature = try dataKey.signature(
      for: verifier.keyUpdateSignatureTBS(update, sealing: sealing)
    )
    let signed = try CanonicalKeyUpdateV1(
      keyDirectoryRevision: update.keyDirectoryRevision,
      keyID: update.keyID,
      deviceRoute: update.deviceRoute,
      streamRoute: update.streamRoute,
      enc: update.enc,
      wrappedKey: update.wrappedKey,
      signature: signature
    )
    let opened = try verifier.openKeyUpdate(
      canonicalBytes: KeyUpdateCanonicalCodec.encode(signed),
      expectedRevision: update.keyDirectoryRevision
    )
    let installed = try opened.makeReceivingKey()
    let expected = try AeadSendingKey(
      keyID: update.keyID,
      epoch: update.keyID.epoch,
      keyDirectoryRevision: update.keyDirectoryRevision,
      payloadKind: .keyUpdate,
      rawKey: try vectorData("plaintextHex", in: hpke)
    )
    XCTAssertEqual(installed.noncePrefix, expected.noncePrefix)
    XCTAssertFalse(String(reflecting: opened).contains(try vectorString("plaintextHex", in: hpke)))
  }

  func testSignedDirectoryAndUpdateRejectRevisionSignatureCarrierRecipientAndLengthTamper()
    throws
  {
    let fixture = try VerifierFixture()
    let current = try fixture.directory(revision: 7, materials: fixture.materials)
    XCTAssertEqual(
      try fixture.verifier.verifyDirectory(
        canonicalBytes: current.canonical,
        expectedRevision: 7
      ).directory,
      current.directory
    )
    let audited = try fixture.verifier.auditBootstrapDirectory(
      canonicalBytes: current.canonical,
      expectedRevision: 7,
      expectedConversationRoutes: []
    )
    XCTAssertEqual(audited.directory, current.directory)
    XCTAssertEqual(audited.commandKey.keyID, fixture.materials[1].keyID)
    XCTAssertEqual(audited.receivingKeys.count, 2)
    XCTAssertFalse(String(reflecting: audited).contains("41414141"))
    assertVerifierError(.invalidBootstrapRoster) {
      _ = try fixture.verifier.auditBootstrapDirectory(
        canonicalBytes: current.canonical,
        expectedRevision: 7,
        expectedConversationRoutes: [Data(repeating: 0x44, count: 16)]
      )
    }

    assertVerifierError(.revisionMismatch) {
      _ = try fixture.verifier.verifyDirectory(
        canonicalBytes: current.canonical,
        expectedRevision: 8
      )
    }
    var badSignature = current.directory.signature
    badSignature[0] ^= 1
    let badSignatureDirectory = try DeviceKeyDirectoryV1(
      revision: current.directory.revision,
      entries: current.directory.entries,
      signature: badSignature
    )
    assertVerifierError(.badSignature) {
      _ = try fixture.verifier.verifyDirectory(
        canonicalBytes: KeyDirectoryCanonicalCodec.encode(badSignatureDirectory),
        expectedRevision: 7
      )
    }
    var changedEntries = current.directory.entries
    let first = changedEntries[0]
    var changedWrapped = first.wrappedKey
    changedWrapped[0] ^= 1
    changedEntries[0] = try DeviceWrappedKeyV1(
      keyID: first.keyID,
      deviceRoute: first.deviceRoute,
      streamRoute: first.streamRoute,
      enc: first.enc,
      wrappedKey: changedWrapped
    )
    let carrierTamper = try DeviceKeyDirectoryV1(
      revision: 7,
      entries: changedEntries,
      signature: current.directory.signature
    )
    assertVerifierError(.badSignature) {
      _ = try fixture.verifier.verifyDirectory(
        canonicalBytes: KeyDirectoryCanonicalCodec.encode(carrierTamper),
        expectedRevision: 7
      )
    }
    let resignedCarrierTamper = try DeviceKeyDirectoryV1(
      revision: 7,
      entries: changedEntries,
      signature: fixture.dataKey.signature(
        for: fixture.verifier.directorySignatureTBS(carrierTamper)
      )
    )
    assertVerifierError(.hpkeOpenFailed) {
      _ = try fixture.verifier.auditBootstrapDirectory(
        canonicalBytes: KeyDirectoryCanonicalCodec.encode(resignedCarrierTamper),
        expectedRevision: 7,
        expectedConversationRoutes: []
      )
    }

    let update = try fixture.keyUpdate(
      revision: 8,
      material: fixture.materials[0]
    )
    let opened = try fixture.verifier.openKeyUpdate(
      canonicalBytes: update,
      expectedRevision: 8
    )
    XCTAssertEqual(opened.keyDirectoryRevision, 8)
    assertVerifierError(.revisionMismatch) {
      _ = try fixture.verifier.openKeyUpdate(canonicalBytes: update, expectedRevision: 9)
    }

    let wrongRecipient = try KeyDirectoryVerifier(
      record: fixture.record,
      verifiedCertificate: fixture.verifiedCertificate,
      deviceHPKEPrivateKey: Curve25519.KeyAgreement.PrivateKey()
    )
    assertVerifierError(.hpkeOpenFailed) {
      _ = try wrongRecipient.openKeyUpdate(canonicalBytes: update, expectedRevision: 8)
    }

    assertVerifierError(.invalidEncoding) {
      _ = try fixture.keyUpdate(
        revision: 8,
        material: fixture.materials[0],
        plaintext: Data(repeating: 0xAB, count: 31)
      )
    }
  }

}

private struct TestKeyMaterial {
  let keyID: KeyIDV1
  let streamRoute: Data?
  let rawKey: Data
}

private struct SignedDirectoryFixture {
  let directory: DeviceKeyDirectoryV1
  let canonical: Data
}

private struct VerifierFixture {
  let relayServerID = Data(repeating: 0x31, count: 16)
  let machineRoute = Data(repeating: 0x32, count: 16)
  let deviceRoute = Data(repeating: 0x33, count: 16)
  let rootKeyID = Data(repeating: 0x34, count: 16)
  let rootKey: Curve25519.Signing.PrivateKey
  let dataKey: Curve25519.Signing.PrivateKey
  let hpkeKey: Curve25519.KeyAgreement.PrivateKey
  let record: StoredPairedMachineRecordV1
  let verifiedCertificate: VerifiedMachineDataCertificate
  let verifier: KeyDirectoryVerifier
  let materials: [TestKeyMaterial]

  init() throws {
    rootKey = try Curve25519.Signing.PrivateKey(
      rawRepresentation: Data(repeating: 0x71, count: 32)
    )
    dataKey = try Curve25519.Signing.PrivateKey(
      rawRepresentation: Data(repeating: 0x72, count: 32)
    )
    hpkeKey = try Curve25519.KeyAgreement.PrivateKey(
      rawRepresentation: Data(repeating: 0x73, count: 32)
    )
    let certificate = try makeCertificate(
      relayServerID: relayServerID,
      machineRoute: machineRoute,
      rootKeyID: rootKeyID,
      trustEpoch: 3,
      generation: 4,
      rootKey: rootKey,
      dataKey: dataKey
    )
    record = try makeRecord(
      relayServerID: relayServerID,
      machineRootPublicKey: rootKey.publicKey.rawRepresentation,
      machineRoute: machineRoute,
      deviceRoute: deviceRoute,
      grantSerial: 9,
      trustEpoch: 3,
      certificate: certificate
    )
    verifiedCertificate = try MachineDataCertificateVerifier.verify(
      certificate,
      relayServerID: relayServerID,
      machineRoute: machineRoute,
      machineRootPublicKey: rootKey.publicKey.rawRepresentation,
      machineRootFingerprint: CanonicalCodec.sha256(rootKey.publicKey.rawRepresentation),
      expectedRootKeyID: rootKeyID,
      expectedTrustEpoch: 3,
      minimumDataCertificateGeneration: 4,
      nowMilliseconds: 1
    )
    verifier = try KeyDirectoryVerifier(
      record: record,
      verifiedCertificate: verifiedCertificate,
      deviceHPKEPrivateKey: hpkeKey
    )
    materials = [
      TestKeyMaterial(
        keyID: KeyIDV1(purpose: .catalog, epoch: 1),
        streamRoute: nil,
        rawKey: Data(repeating: 0x41, count: 32)
      ),
      TestKeyMaterial(
        keyID: KeyIDV1(purpose: .deviceCommandTx, epoch: 1),
        streamRoute: nil,
        rawKey: Data(repeating: 0x42, count: 32)
      ),
      TestKeyMaterial(
        keyID: KeyIDV1(purpose: .deviceReplyTx, epoch: 1),
        streamRoute: nil,
        rawKey: Data(repeating: 0x43, count: 32)
      ),
    ]
  }

  func directory(
    revision: UInt64,
    materials: [TestKeyMaterial]
  ) throws -> SignedDirectoryFixture {
    let entries = try materials.map { material in
      let sealing = try verifier.sealingContext(
        keyDirectoryRevision: revision,
        keyID: material.keyID,
        streamRoute: material.streamRoute
      )
      let envelope = try RelayCrypto.sealHPKE(
        material.rawKey,
        recipient: hpkeKey.publicKey,
        info: sealing.info,
        aad: CanonicalCodec.encodeAAD(sealing.outerContext)
      )
      return try DeviceWrappedKeyV1(
        keyID: material.keyID,
        deviceRoute: deviceRoute,
        streamRoute: material.streamRoute,
        enc: envelope.enc,
        wrappedKey: envelope.ciphertext
      )
    }
    let unsigned = try DeviceKeyDirectoryV1(
      revision: revision,
      entries: entries,
      signature: Data(repeating: 1, count: 64)
    )
    let signature = try dataKey.signature(for: verifier.directorySignatureTBS(unsigned))
    let signed = try DeviceKeyDirectoryV1(
      revision: revision,
      entries: entries,
      signature: signature
    )
    return SignedDirectoryFixture(
      directory: signed,
      canonical: try KeyDirectoryCanonicalCodec.encode(signed)
    )
  }

  func keyUpdate(
    revision: UInt64,
    material: TestKeyMaterial,
    plaintext: Data? = nil
  ) throws -> Data {
    let sealing = try verifier.sealingContext(
      keyDirectoryRevision: revision,
      keyID: material.keyID,
      streamRoute: material.streamRoute
    )
    let envelope = try RelayCrypto.sealHPKE(
      plaintext ?? material.rawKey,
      recipient: hpkeKey.publicKey,
      info: sealing.info,
      aad: CanonicalCodec.encodeAAD(sealing.outerContext)
    )
    let unsigned = try CanonicalKeyUpdateV1(
      keyDirectoryRevision: revision,
      keyID: material.keyID,
      deviceRoute: deviceRoute,
      streamRoute: material.streamRoute,
      enc: envelope.enc,
      wrappedKey: envelope.ciphertext,
      signature: Data(repeating: 0, count: 64),
      requireSignature: false
    )
    let signature = try dataKey.signature(
      for: verifier.keyUpdateSignatureTBS(unsigned, sealing: sealing)
    )
    return try KeyUpdateCanonicalCodec.encode(
      CanonicalKeyUpdateV1(
        keyDirectoryRevision: revision,
        keyID: material.keyID,
        deviceRoute: deviceRoute,
        streamRoute: material.streamRoute,
        enc: envelope.enc,
        wrappedKey: envelope.ciphertext,
        signature: signature
      ))
  }
}

private func makeCertificate(
  relayServerID: Data,
  machineRoute: Data,
  rootKeyID: Data,
  trustEpoch: UInt64,
  generation: UInt64,
  rootKey: Curve25519.Signing.PrivateKey,
  dataKey: Curve25519.Signing.PrivateKey
) throws -> RelayV2SignedCertificate {
  let unsigned = RelayV2SignedCertificate(
    subjectPubkey: dataKey.publicKey.rawRepresentation,
    certRole: .data,
    generation: generation,
    rootKeyId: rootKeyID,
    trustEpoch: trustEpoch,
    notAfterMs: 4_000_000_000_000,
    signature: Data(repeating: 1, count: 64)
  )
  let tbs = ToBeSignedV1(
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
    signingKeyFingerprint: CanonicalCodec.sha256(rootKey.publicKey.rawRepresentation),
    rootKeyID: rootKeyID,
    trustEpoch: trustEpoch,
    serialOrGeneration: generation,
    notAfterMS: unsigned.notAfterMs,
    signedObjectSHA256: try SignedCertificateCanonicalCodec.unsignedCanonicalSHA256(unsigned)
  )
  return RelayV2SignedCertificate(
    subjectPubkey: unsigned.subjectPubkey,
    certRole: unsigned.certRole,
    generation: unsigned.generation,
    rootKeyId: unsigned.rootKeyId,
    trustEpoch: unsigned.trustEpoch,
    notAfterMs: unsigned.notAfterMs,
    signature: try RelayCrypto.sign(tbs, key: rootKey)
  )
}

private func makeRecord(
  relayServerID: Data,
  machineRootPublicKey: Data = Data(repeating: 0x90, count: 32),
  machineRoute: Data,
  deviceRoute: Data,
  grantSerial: UInt64,
  trustEpoch: UInt64,
  certificate: RelayV2SignedCertificate
) throws -> StoredPairedMachineRecordV1 {
  try StoredPairedMachineRecordV1(
    clientKind: .macOSApp,
    installationID: UUID(uuidString: "81000000-0000-0000-0000-000000000001")!,
    machineID: "key-directory-machine",
    machineName: "Key Directory Machine",
    relayURL: URL(string: "wss://relay.example.com/")!,
    relayServerID: relayServerID,
    machineRootPublicKey: machineRootPublicKey,
    machineRootFingerprint: CanonicalCodec.sha256(machineRootPublicKey),
    machineDataCertificate: certificate,
    machineRoute: machineRoute,
    deviceRoute: deviceRoute,
    currentSPKIPin: Data(repeating: 0x91, count: 32),
    nextSPKIPin: nil,
    grantSerial: grantSerial,
    trustEpoch: trustEpoch,
    createdAtMS: 1
  )
}

private func assertVerifierError(
  _ expected: KeyDirectoryVerifierError,
  operation: () throws -> Void,
  file: StaticString = #filePath,
  line: UInt = #line
) {
  do {
    try operation()
    XCTFail("expected verifier error", file: file, line: line)
  } catch {
    XCTAssertEqual(error as? KeyDirectoryVerifierError, expected, file: file, line: line)
  }
}

private func loadKeyDirectoryVectors() throws -> [String: Any] {
  try loadVectorSection("key_directory_update_canonical")
}

private func loadVectorSection(_ name: String) throws -> [String: Any] {
  let root = URL(fileURLWithPath: #filePath)
    .deletingLastPathComponent()
    .deletingLastPathComponent()
    .deletingLastPathComponent()
  let url = root.appendingPathComponent("protocol/agentdeck/crypto-vectors-v1.json")
  let object = try XCTUnwrap(
    try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any]
  )
  return try XCTUnwrap(object[name] as? [String: Any])
}

private func vectorString(_ key: String, in section: [String: Any]) throws -> String {
  try XCTUnwrap(section[key] as? String)
}

private func vectorData(_ key: String, in section: [String: Any]) throws -> Data {
  let value = try vectorString(key, in: section)
  guard value.count.isMultiple(of: 2) else { throw VectorError.invalidHex }
  var output = Data()
  output.reserveCapacity(value.count / 2)
  var index = value.startIndex
  while index < value.endIndex {
    let next = value.index(index, offsetBy: 2)
    guard let byte = UInt8(value[index..<next], radix: 16) else {
      throw VectorError.invalidHex
    }
    output.append(byte)
    index = next
  }
  return output
}

private enum VectorError: Error { case invalidHex }
