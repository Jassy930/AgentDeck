import Foundation
import XCTest

@testable import AgentDeckCore

final class RuntimeV4PairingProtocolTests: XCTestCase {
  func testRustPairingFixturesRoundTripThroughCurrentCodec() throws {
    XCTAssertEqual(runtimeProtocolVersionV4, 4)
    XCTAssertEqual(runtimeProtocolVersionV5, 5)
    XCTAssertEqual(runtimeProtocolVersionCurrent, runtimeProtocolVersionV5)

    for name in [
      "requestCreatePairInvite",
      "replyPairInvite",
      "replyPendingPairings",
      "replyPairingConfirmed",
      "replyPairingCanceled",
      "replyPairingExpired",
      "replyPairingReplayed",
      "replyPairingAlreadyHandled",
      "replyPairingFailed",
      "streamPairingPending",
    ] {
      let input = try fixtureValue(named: name)
      let decoded = try RuntimeV5WireCodec.decodeEnvelope(input)
      XCTAssertEqual(decoded.version, runtimeProtocolVersionV5)
      XCTAssertEqual(
        try normalizedJSON(RuntimeV5WireCodec.encode(decoded)),
        try normalizedJSON(input),
        "Rust/Swift Runtime v5 drift for \(name)"
      )
    }
  }

  func testCreatePairInviteHasFixedTTLAndStrictDisplayName() throws {
    let source = try fixtureJSONObject(named: "requestCreatePairInvite")
    guard
      let body = source["body"] as? [String: Any],
      let payload = body["payload"] as? [String: Any]
    else {
      return XCTFail("missing request payload")
    }
    XCTAssertNil(payload["ttlSecs"])
    XCTAssertEqual(payload["idempotencyKey"] as? String, "pair-invite-request-1")

    for invalidName in [
      "", " leading", "trailing ", "bad\nname", String(repeating: "x", count: 129),
    ] {
      var invalid = source
      var invalidBody = try XCTUnwrap(invalid["body"] as? [String: Any])
      var invalidPayload = try XCTUnwrap(invalidBody["payload"] as? [String: Any])
      invalidPayload["displayName"] = invalidName
      invalidBody["payload"] = invalidPayload
      invalid["body"] = invalidBody
      XCTAssertThrowsError(try decode(invalid), "accepted invalid display name")
    }

    var callerTTL = source
    var ttlBody = try XCTUnwrap(callerTTL["body"] as? [String: Any])
    var ttlPayload = try XCTUnwrap(ttlBody["payload"] as? [String: Any])
    ttlPayload["ttlSecs"] = 300
    ttlBody["payload"] = ttlPayload
    callerTTL["body"] = ttlBody
    XCTAssertThrowsError(try decode(callerTTL))

    var missingKey = source
    var keyBody = try XCTUnwrap(missingKey["body"] as? [String: Any])
    var keyPayload = try XCTUnwrap(keyBody["payload"] as? [String: Any])
    keyPayload.removeValue(forKey: "idempotencyKey")
    keyBody["payload"] = keyPayload
    missingKey["body"] = keyBody
    XCTAssertThrowsError(try decode(missingKey))
  }

  func testPairInviteAndPendingBindingsFailClosed() throws {
    for invalidURL in [
      "wss://relay.example.test/path",
      "wss://user@relay.example.test/",
      "wss://relay.example.test:0/",
      "wss://relay.example.test/?override=true",
      "wss://relay.example.test/#fragment",
    ] {
      var invalid = try fixtureJSONObject(named: "replyPairInvite")
      var invalidBody = try XCTUnwrap(invalid["body"] as? [String: Any])
      var invalidPayload = try XCTUnwrap(invalidBody["payload"] as? [String: Any])
      var invalidInvite = try XCTUnwrap(invalidPayload["invite"] as? [String: Any])
      invalidInvite["wssUrl"] = invalidURL
      invalidPayload["invite"] = invalidInvite
      invalidBody["payload"] = invalidPayload
      invalid["body"] = invalidBody
      XCTAssertThrowsError(try decode(invalid), "accepted non-origin WSS URL \(invalidURL)")
    }

    var invite = try fixtureJSONObject(named: "replyPairInvite")
    var inviteBody = try XCTUnwrap(invite["body"] as? [String: Any])
    var invitePayload = try XCTUnwrap(inviteBody["payload"] as? [String: Any])
    var inviteValue = try XCTUnwrap(invitePayload["invite"] as? [String: Any])
    inviteValue["machineRootFingerprint"] = Data(repeating: 0xff, count: 32).base64EncodedString()
    invitePayload["invite"] = inviteValue
    inviteBody["payload"] = invitePayload
    invite["body"] = inviteBody
    XCTAssertThrowsError(try decode(invite))

    var zeroCertExpiry = try fixtureJSONObject(named: "replyPairInvite")
    var expiryBody = try XCTUnwrap(zeroCertExpiry["body"] as? [String: Any])
    var expiryPayload = try XCTUnwrap(expiryBody["payload"] as? [String: Any])
    var expiryInvite = try XCTUnwrap(expiryPayload["invite"] as? [String: Any])
    var dataSignCert = try XCTUnwrap(expiryInvite["dataSignCert"] as? [String: Any])
    dataSignCert["notAfterMs"] = 0
    expiryInvite["dataSignCert"] = dataSignCert
    expiryPayload["invite"] = expiryInvite
    expiryBody["payload"] = expiryPayload
    zeroCertExpiry["body"] = expiryBody
    XCTAssertThrowsError(try decode(zeroCertExpiry))

    var pending = try fixtureJSONObject(named: "streamPairingPending")
    var pendingBody = try XCTUnwrap(pending["body"] as? [String: Any])
    var pendingPayload = try XCTUnwrap(pendingBody["payload"] as? [String: Any])
    pendingPayload["requestHash"] = Data([0]).base64EncodedString()
    pendingBody["payload"] = pendingPayload
    pending["body"] = pendingBody
    XCTAssertThrowsError(try decode(pending))

    var reversedTime = try fixtureJSONObject(named: "streamPairingPending")
    var timeBody = try XCTUnwrap(reversedTime["body"] as? [String: Any])
    var timePayload = try XCTUnwrap(timeBody["payload"] as? [String: Any])
    timePayload["requestedAtMs"] = 1_700_000_300_001 as UInt64
    timeBody["payload"] = timePayload
    reversedTime["body"] = timeBody
    XCTAssertThrowsError(try decode(reversedTime))
  }

  func testRuntimeV3EnvelopeIsRejectedAfterHardCutover() throws {
    var legacy = try fixtureJSONObject(named: "requestHello")
    legacy["version"] = 3
    var body = try XCTUnwrap(legacy["body"] as? [String: Any])
    var payload = try XCTUnwrap(body["payload"] as? [String: Any])
    payload["runtimeProtocolVersion"] = 3
    body["payload"] = payload
    legacy["body"] = body
    XCTAssertThrowsError(try decode(legacy))
  }

  private func fixtureValue(named name: String) throws -> Data {
    try JSONSerialization.data(withJSONObject: fixtureJSONObject(named: name))
  }

  private func fixtureJSONObject(named name: String) throws -> [String: Any] {
    let data = try Data(contentsOf: fixtureURL)
    for line in String(decoding: data, as: UTF8.self).split(separator: "\n") {
      guard
        let object = try JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any],
        object["case"] as? String == name
      else { continue }
      return try XCTUnwrap(object["value"] as? [String: Any])
    }
    throw CocoaError(.fileReadNoSuchFile)
  }

  private func decode(_ object: [String: Any]) throws -> RuntimeEnvelopeV4 {
    try RuntimeV4WireCodec.decodeEnvelope(JSONSerialization.data(withJSONObject: object))
  }

  private func normalizedJSON(_ data: Data) throws -> Data {
    let object = try JSONSerialization.jsonObject(with: data)
    return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
  }

  private var fixtureURL: URL {
    URL(fileURLWithPath: #filePath)
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .appendingPathComponent("protocol/agentdeck/fixtures/runtime-v5-wire.jsonl")
  }
}
