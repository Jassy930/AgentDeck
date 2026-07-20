import AgentDeckCore
import Foundation
import XCTest

final class RuntimeV2PublicAPITests: XCTestCase {
  func testCurrentCompactCodecIsAvailableWithoutTestableImport() throws {
    XCTAssertEqual(runtimeProtocolVersionV2, 2)
    XCTAssertEqual(runtimeProtocolVersionV3, 3)
    XCTAssertEqual(runtimeProtocolVersionV4, 4)
    XCTAssertEqual(runtimeProtocolVersionCurrent, runtimeProtocolVersionV4)

    let carrier = try RuntimeTransferCarrierV2(
      messageID: RuntimeMessageID(rawValue: "public-message"),
      channel: .reply,
      transferID: RuntimeTransferID(rawValue: "public-transfer"),
      partIndex: 1,
      partCount: 2,
      totalSHA256: Data(repeating: 0x5a, count: 32),
      totalBytes: 2,
      part: Data([0x42])
    )
    let encoded = try RuntimeWireCodec.encode(carrier)
    let decoded = try RuntimeWireCodec.decodeTransferCarrier(encoded)
    XCTAssertEqual(decoded.runtimeVersion, runtimeProtocolVersionCurrent)
    XCTAssertEqual(decoded.channel, .reply)
    XCTAssertEqual(decoded.transfer.partIndex, 1)
  }
}
