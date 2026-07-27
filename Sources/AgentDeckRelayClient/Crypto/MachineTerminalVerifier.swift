import AgentDeckCore
import CryptoKit
import Foundation

enum MachineTerminalVerifierError: Error, Equatable, Sendable {
  case invalidBinding
  case invalidFrame
  case badSignature
}

struct VerifiedMachineRevocationTerminalV1: Sendable, CustomDebugStringConvertible {
  let canonicalFrameBytes: Data
  let deviceRoute: Data
  let grantSerial: UInt64

  /// 只有本文件内完成 exact MachineRoot signature 验证的 terminal verifier 可以铸造。
  /// cleanup owner 不得接受裸 frame、Relay error 或调用方拼装的等价字段。
  fileprivate init(
    canonicalFrameBytes: Data,
    deviceRoute: Data,
    grantSerial: UInt64
  ) {
    self.canonicalFrameBytes = canonicalFrameBytes
    self.deviceRoute = deviceRoute
    self.grantSerial = grantSerial
  }

  var debugDescription: String {
    "VerifiedMachineRevocationTerminalV1(<redacted>)"
  }
}

enum VerifiedMachineTerminalV1: Sendable {
  case revoked(VerifiedMachineRevocationTerminalV1)
  /// Relay retirement terminal 只影响连接可用性，不授权删除本地 paired material。
  case retired
}

/// post-auth 与 reconnect handshake 共用的 terminal verifier。
///
/// RevocationCommitted 必须携带 exact MachineRoot-signed revocation；RetirementCommitted
/// 只有 Relay COMMIT readback hash，因此只能映射为 non-destructive incompatible terminal，
/// 绝不能复用 revoked cleanup capability。
struct MachineTerminalVerifier: Sendable {
  private static let revocationRoleScope = "relay-device-revocation"

  private let relayServerID: Data
  private let machineRoute: Data
  private let deviceRoute: Data
  private let grantSerial: UInt64
  private let rootKeyID: Data
  private let trustEpoch: UInt64
  private let machineRootFingerprint: Data
  private let machineRootKey: Curve25519.Signing.PublicKey

  init(material: PairedMachineConnectionMaterial) throws {
    try self.init(
      relayServerID: material.record.relayServerID,
      machineRoute: material.record.machineRoute,
      deviceRoute: material.record.deviceRoute,
      grantSerial: material.record.grantSerial,
      rootKeyID: material.relayGrant.grant.rootKeyId,
      trustEpoch: material.record.trustEpoch,
      machineRootPublicKey: material.record.machineRootPublicKey,
      machineRootFingerprint: material.record.machineRootFingerprint
    )
  }

  init(
    relayServerID: Data,
    machineRoute: Data,
    deviceRoute: Data,
    grantSerial: UInt64,
    rootKeyID: Data,
    trustEpoch: UInt64,
    machineRootPublicKey: Data,
    machineRootFingerprint: Data
  ) throws {
    guard Self.isNonzero(relayServerID, count: 16),
      Self.isNonzero(machineRoute, count: 16),
      Self.isNonzero(deviceRoute, count: 16),
      grantSerial > 0,
      Self.isNonzero(rootKeyID, count: 16),
      trustEpoch > 0,
      Self.isNonzero(machineRootPublicKey, count: 32),
      Self.isNonzero(machineRootFingerprint, count: 32),
      CanonicalCodec.sha256(machineRootPublicKey) == machineRootFingerprint
    else {
      throw MachineTerminalVerifierError.invalidBinding
    }
    do {
      machineRootKey = try Curve25519.Signing.PublicKey(
        rawRepresentation: machineRootPublicKey
      )
    } catch {
      throw MachineTerminalVerifierError.invalidBinding
    }
    self.relayServerID = relayServerID
    self.machineRoute = machineRoute
    self.deviceRoute = deviceRoute
    self.grantSerial = grantSerial
    self.rootKeyID = rootKeyID
    self.trustEpoch = trustEpoch
    self.machineRootFingerprint = machineRootFingerprint
  }

  func verify(_ frame: ReceivedRelayFrame) throws -> VerifiedMachineTerminalV1 {
    guard frame.frame.version == relayProtocolVersionV2,
      try RelayWireCodecV2.encodeFixture(frame.frame) == frame.canonicalBytes
    else {
      throw MachineTerminalVerifierError.invalidFrame
    }
    switch frame.frame.body {
    case .revocationCommitted(
      let outerDeviceRoute,
      let outerGrantSerial,
      let revocation
    ):
      guard outerDeviceRoute == revocation.deviceRoute,
        outerGrantSerial == revocation.grantSerial,
        revocation.machineRoute == machineRoute,
        revocation.deviceRoute == deviceRoute,
        revocation.grantSerial == grantSerial,
        revocation.rootKeyId == rootKeyID,
        revocation.trustEpoch == trustEpoch,
        Self.isNonzero(revocation.signature, count: 64)
      else {
        throw MachineTerminalVerifierError.invalidFrame
      }
      let tbs = try revocationTBS(revocation)
      guard machineRootKey.isValidSignature(revocation.signature, for: tbs) else {
        throw MachineTerminalVerifierError.badSignature
      }
      return .revoked(
        VerifiedMachineRevocationTerminalV1(
          canonicalFrameBytes: frame.canonicalBytes,
          deviceRoute: deviceRoute,
          grantSerial: grantSerial
        )
      )

    case .retirementCommitted(
      let terminalMachineRoute,
      let terminalTrustEpoch,
      let retireHash
    ):
      guard terminalMachineRoute == machineRoute,
        terminalTrustEpoch == trustEpoch,
        Self.isNonzero(retireHash, count: 32)
      else {
        throw MachineTerminalVerifierError.invalidFrame
      }
      return .retired

    default:
      throw MachineTerminalVerifierError.invalidFrame
    }
  }

  func revocationTBS(_ revocation: RelayV2DeviceRevocation) throws -> Data {
    guard revocation.machineRoute == machineRoute,
      revocation.deviceRoute == deviceRoute,
      revocation.grantSerial == grantSerial,
      revocation.rootKeyId == rootKeyID,
      revocation.trustEpoch == trustEpoch
    else {
      throw MachineTerminalVerifierError.invalidFrame
    }
    return try CanonicalCodec.encode(
      ToBeSignedV1(
        objectType: .deviceRevocation,
        signatureFormatVersion: 1,
        relayProtocolVersion: relayProtocolVersionV2,
        runtimeProtocolVersion: runtimeProtocolVersionCurrent,
        e2eeFormatVersion: 1,
        relayServerID: relayServerID,
        machineRoute: machineRoute,
        deviceRoute: deviceRoute,
        streamRoute: nil,
        requestRoute: nil,
        streamGeneration: nil,
        streamCursor: nil,
        roleScope: Self.revocationRoleScope,
        signingKeyFingerprint: machineRootFingerprint,
        rootKeyID: rootKeyID,
        trustEpoch: trustEpoch,
        serialOrGeneration: grantSerial,
        notAfterMS: nil,
        signedObjectSHA256: CanonicalCodec.sha256(
          Self.unsignedCanonicalBytes(revocation)
        )
      )
    )
  }

  static func unsignedCanonicalBytes(
    _ revocation: RelayV2DeviceRevocation
  ) -> Data {
    var output = Data("AgentDeck/DeviceRevocationUnsignedV1\0".utf8)
    appendBytes(revocation.machineRoute, to: &output)
    appendBytes(revocation.deviceRoute, to: &output)
    appendInteger(revocation.grantSerial, to: &output)
    appendBytes(revocation.rootKeyId, to: &output)
    appendInteger(revocation.trustEpoch, to: &output)
    return output
  }

  private static func appendBytes(_ value: Data, to output: inout Data) {
    appendInteger(UInt32(value.count), to: &output)
    output.append(value)
  }

  private static func appendInteger<T: FixedWidthInteger>(
    _ value: T,
    to output: inout Data
  ) {
    var encoded = value.bigEndian
    Swift.withUnsafeBytes(of: &encoded) { output.append(contentsOf: $0) }
  }

  private static func isNonzero(_ value: Data, count: Int) -> Bool {
    value.count == count && value.contains(where: { $0 != 0 })
  }
}
