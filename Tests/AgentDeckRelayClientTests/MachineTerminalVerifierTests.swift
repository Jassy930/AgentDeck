import Foundation
import XCTest

@testable import AgentDeckRelayClient

final class MachineTerminalVerifierTests: XCTestCase {
  func testExactRootSignedRevocationMintsCleanupCapability() throws {
    let fixture = try MachineTerminalFixture()
    let terminal = try fixture.revocationFrame()
    let revocation = fixture.signedRevocation()

    // 这些 bytes 由 Rust agentdeck-protocol 的 public DeviceRevocation/ToBeSignedV1/
    // Relay v2 codec 独立生成；不能用 Swift verifier 自签再自验替代 parity gate。
    XCTAssertEqual(
      MachineTerminalVerifier.unsignedCanonicalBytes(revocation),
      RustMachineRevocationGolden.unsignedCanonicalBytes
    )
    XCTAssertEqual(
      try fixture.verifier.revocationTBS(revocation),
      RustMachineRevocationGolden.tbsBytes
    )
    XCTAssertEqual(terminal.canonicalBytes, RustMachineRevocationGolden.frameBytes)

    let result = try fixture.verifier.verify(terminal)
    guard case .revoked(let verified) = result else {
      return XCTFail("valid root-signed revocation must be terminal")
    }
    XCTAssertEqual(verified.canonicalFrameBytes, terminal.canonicalBytes)
    XCTAssertEqual(verified.deviceRoute, fixture.deviceRoute)
    XCTAssertEqual(verified.grantSerial, fixture.grantSerial)
  }

  func testOuterMismatchForgeryAndNonCanonicalBytesFailClosed() throws {
    let fixture = try MachineTerminalFixture()
    let valid = fixture.signedRevocation()
    let badOuter = try fixture.frame(
      .revocationCommitted(
        deviceRoute: Data(repeating: 0xFF, count: 16),
        grantSerial: fixture.grantSerial,
        signedRevocation: valid
      )
    )
    XCTAssertThrowsError(try fixture.verifier.verify(badOuter)) { error in
      XCTAssertEqual(error as? MachineTerminalVerifierError, .invalidFrame)
    }

    var forged = valid
    forged.signature[0] ^= 0x01
    let forgedFrame = try fixture.frame(
      .revocationCommitted(
        deviceRoute: fixture.deviceRoute,
        grantSerial: fixture.grantSerial,
        signedRevocation: forged
      )
    )
    XCTAssertThrowsError(try fixture.verifier.verify(forgedFrame)) { error in
      XCTAssertEqual(error as? MachineTerminalVerifierError, .badSignature)
    }

    let exact = try fixture.revocationFrame()
    let nonCanonical = ReceivedRelayFrame(
      generation: exact.generation,
      frame: exact.frame,
      canonicalBytes: exact.canonicalBytes + Data([0])
    )
    XCTAssertThrowsError(try fixture.verifier.verify(nonCanonical)) { error in
      XCTAssertEqual(error as? MachineTerminalVerifierError, .invalidFrame)
    }
  }

  func testRetirementIsNonDestructiveAndCannotMintRevocationCapability() throws {
    let fixture = try MachineTerminalFixture()
    let frame = try fixture.frame(
      .retirementCommitted(
        machineRoute: fixture.machineRoute,
        trustEpoch: fixture.trustEpoch,
        retireHash: Data(repeating: 0x91, count: 32)
      )
    )
    guard case .retired = try fixture.verifier.verify(frame) else {
      return XCTFail("exact retirement readback must only produce retired")
    }

    let wrongEpoch = try fixture.frame(
      .retirementCommitted(
        machineRoute: fixture.machineRoute,
        trustEpoch: fixture.trustEpoch + 1,
        retireHash: Data(repeating: 0x91, count: 32)
      )
    )
    XCTAssertThrowsError(try fixture.verifier.verify(wrongEpoch))
  }
}

private enum RustMachineRevocationGolden {
  static let machineRootPublicKey = Data(
    hex: "5b6489c9c7fd0dcf50545e7c164886ef40491ec06c7f1b123041797e8117535e"
  )
  static let machineRootFingerprint = Data(
    hex: "c0742a797bd5374378f26a371f35e61b32c0d0cc8fc9b76f5c3ee1949a61555a"
  )
  static let signature = Data(
    hex: "e1f6531d7c62b54ca67669b4718c01d3c5af091dceacdc82c48768d4b237392b"
      + "71ff7245f9ca98eed5d7ecb5bf9cd351e606e397ecb903f6f13ced3ca27f030d"
  )
  static let unsignedCanonicalBytes = Data(
    hex: "4167656e744465636b2f4465766963655265766f636174696f6e556e7369676e6564563100"
      + "00000010111111111111111111111111111111110000001022222222222222222222222222222222"
      + "000000000000000900000010777777777777777777777777777777770000000000000003"
  )
  static let tbsBytes = Data(
    hex: "4167656e744465636b2f546f42655369676e656456310004000100020005000100000010"
      + "888888888888888888888888888888880000001011111111111111111111111111111111"
      + "0122222222222222222222222222222222000000000000001772656c61792d6465766963652d"
      + "7265766f636174696f6e00000020c0742a797bd5374378f26a371f35e61b32c0d0cc8fc9b76f"
      + "5c3ee1949a61555a00000010777777777777777777777777777777770000000000000003"
      + "0000000000000009000000002016569fad1a3d399618675b9f8c737de688a30dd0c920269d26583"
      + "ec6b99ea97b"
  )
  static let frameBytes = Data(
    hex: "414452563200020015222222222222222222222222222222220000000000000009"
      + "1111111111111111111111111111111122222222222222222222222222222222"
      + "0000000000000009777777777777777777777777777777770000000000000003"
      + "e1f6531d7c62b54ca67669b4718c01d3c5af091dceacdc82c48768d4b237392b"
      + "71ff7245f9ca98eed5d7ecb5bf9cd351e606e397ecb903f6f13ced3ca27f030d"
  )
}

private struct MachineTerminalFixture {
  let relayServerID = Data(repeating: 0x88, count: 16)
  let machineRoute = Data(repeating: 0x11, count: 16)
  let deviceRoute = Data(repeating: 0x22, count: 16)
  let grantSerial: UInt64 = 9
  let rootKeyID = Data(repeating: 0x77, count: 16)
  let trustEpoch: UInt64 = 3
  let verifier: MachineTerminalVerifier

  init() throws {
    verifier = try MachineTerminalVerifier(
      relayServerID: relayServerID,
      machineRoute: machineRoute,
      deviceRoute: deviceRoute,
      grantSerial: grantSerial,
      rootKeyID: rootKeyID,
      trustEpoch: trustEpoch,
      machineRootPublicKey: RustMachineRevocationGolden.machineRootPublicKey,
      machineRootFingerprint: RustMachineRevocationGolden.machineRootFingerprint
    )
  }

  func signedRevocation() -> RelayV2DeviceRevocation {
    RelayV2DeviceRevocation(
      machineRoute: machineRoute,
      deviceRoute: deviceRoute,
      grantSerial: grantSerial,
      rootKeyId: rootKeyID,
      trustEpoch: trustEpoch,
      signature: RustMachineRevocationGolden.signature
    )
  }

  func revocationFrame() throws -> ReceivedRelayFrame {
    try frame(
      .revocationCommitted(
        deviceRoute: deviceRoute,
        grantSerial: grantSerial,
        signedRevocation: signedRevocation()
      )
    )
  }

  func frame(_ body: RelayV2FrameBody) throws -> ReceivedRelayFrame {
    let frame = RelayV2Frame(version: relayProtocolVersionV2, body: body)
    return ReceivedRelayFrame(
      generation: RelayTransportGeneration(rawValue: 1),
      frame: frame,
      canonicalBytes: try RelayWireCodecV2.encodeFixture(frame)
    )
  }
}

extension Data {
  fileprivate init(hex: String) {
    precondition(hex.count.isMultiple(of: 2))
    var bytes: [UInt8] = []
    bytes.reserveCapacity(hex.count / 2)
    var cursor = hex.startIndex
    while cursor < hex.endIndex {
      let next = hex.index(cursor, offsetBy: 2)
      bytes.append(UInt8(hex[cursor..<next], radix: 16)!)
      cursor = next
    }
    self.init(bytes)
  }
}
