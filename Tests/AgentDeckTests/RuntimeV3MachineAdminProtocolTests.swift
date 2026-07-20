import Foundation
import XCTest

@testable import AgentDeckCore

final class RuntimeV3MachineAdminProtocolTests: XCTestCase {
  func testCurrentVersionAndSourceCompatibleAliasesAreV4() throws {
    XCTAssertEqual(runtimeProtocolVersionV2, 2)
    XCTAssertEqual(runtimeProtocolVersionV3, 3)
    XCTAssertEqual(runtimeProtocolVersionV4, 4)
    XCTAssertEqual(runtimeProtocolVersionCurrent, runtimeProtocolVersionV4)

    let request: RuntimeRequestV4 = .machineRemoteStatus(scope: .localOnly)
    let envelope = RuntimeEnvelopeV4(
      version: runtimeProtocolVersionCurrent,
      messageID: RuntimeMessageID(rawValue: "runtime-v4-alias"),
      body: .request(request)
    )
    _ = try RuntimeV4WireCodec.encode(envelope)
  }

  func testRustMachineAdministrationFixturesRoundTripThroughCurrentCodec() throws {
    for name in [
      "requestTrustReset",
      "requestTrustResetWithAdminPurgeReceipt",
      "requestTrustResetForUninstallPurge",
      "requestMachineEnroll",
      "requestMachineRemoteStatus",
      "replyMachineRemoteStatus",
    ] {
      let input = try fixtureValue(named: name)
      let decoded = try RuntimeV4WireCodec.decodeEnvelope(input)
      XCTAssertEqual(decoded.version, runtimeProtocolVersionV4)
      try XCTAssertEqual(normalizedJSON(RuntimeV4WireCodec.encode(decoded)), normalizedJSON(input))

      switch (name, decoded.body) {
      case (
        "requestTrustReset",
        .request(
          .trustReset(let scope, let uninstallPurge, let uninstallPurgePlan, let adminPurgeReceipt)
        )
      ):
        guard case .localOnly = scope else { return XCTFail("scope is not local-only") }
        XCTAssertFalse(uninstallPurge)
        XCTAssertNil(uninstallPurgePlan)
        XCTAssertNil(adminPurgeReceipt)
      case (
        "requestTrustResetWithAdminPurgeReceipt",
        .request(
          .trustReset(let scope, let uninstallPurge, let uninstallPurgePlan, let adminPurgeReceipt)
        )
      ):
        guard case .localOnly = scope else { return XCTFail("scope is not local-only") }
        XCTAssertFalse(uninstallPurge)
        XCTAssertNil(uninstallPurgePlan)
        let receipt = try XCTUnwrap(adminPurgeReceipt)
        XCTAssertEqual(receipt.receiptFormatVersion, 1)
        XCTAssertEqual(receipt.relayProtocolVersion, 2)
        XCTAssertEqual(receipt.machineRoute, Data(repeating: 0x33, count: 16))
        XCTAssertEqual(receipt.rootFingerprint, Data(repeating: 0x44, count: 32))
        XCTAssertEqual(receipt.trustEpoch, 7)
      case (
        "requestTrustResetForUninstallPurge",
        .request(
          .trustReset(let scope, let uninstallPurge, let uninstallPurgePlan, let adminPurgeReceipt)
        )
      ):
        guard case .localOnly = scope else { return XCTFail("scope is not local-only") }
        XCTAssertTrue(uninstallPurge)
        XCTAssertNil(adminPurgeReceipt)
        let plan = try XCTUnwrap(uninstallPurgePlan)
        XCTAssertEqual(plan.version, 1)
        XCTAssertEqual(
          plan.helperPath,
          "/Applications/AgentDeck.app/Contents/Helpers/agentdeck-finalizer"
        )
        XCTAssertEqual(plan.helperVersion, "1.2.3")
        XCTAssertEqual(plan.teamIdentifier, "REALTEAM42")
      case ("requestMachineEnroll", .request(.machineEnroll(let request))):
        guard case .localOnly = request.scope else { return XCTFail("scope is not local-only") }
        XCTAssertEqual(request.bundle.version, 2)
        XCTAssertEqual(request.bundle.relayServerID, Data(repeating: 0x22, count: 16))
        XCTAssertEqual(request.bundle.code, Data(repeating: 0x44, count: 32))
        XCTAssertEqual(request.bundle.spkiPins, [Data(repeating: 0xfb, count: 32)])
      case ("requestMachineRemoteStatus", .request(.machineRemoteStatus(let scope))):
        guard case .localOnly = scope else { return XCTFail("scope is not local-only") }
      case ("replyMachineRemoteStatus", .reply(.machineRemoteStatus(let status))):
        XCTAssertEqual(status.lifecycle, .active)
        XCTAssertEqual(status.relayServerID, Data(repeating: 0x22, count: 16))
        XCTAssertEqual(status.machineRoute, Data(repeating: 0x33, count: 16))
        XCTAssertEqual(status.rootFingerprint, Data(repeating: 0x44, count: 32))
        XCTAssertEqual(status.trustEpoch, 7)
        XCTAssertNil(status.failureCode)
      default:
        XCTFail("unexpected typed path for \(name)")
      }
    }
  }

  func testMachineRemoteStatusValidatesLifecycleBindingMatrix() throws {
    let relay = Data(repeating: 0x11, count: 16)
    let route = Data(repeating: 0x22, count: 16)
    let fingerprint = Data(repeating: 0x33, count: 32)
    let failure = try RuntimeMachineRemoteFailureCodeV3("daemon.remote.blocked")

    for lifecycle in RuntimeMachineRemoteLifecycleV3.allCases {
      let status: RuntimeMachineRemoteStatusV3
      switch lifecycle {
      case .unenrolled:
        status = try .init(
          lifecycle: lifecycle,
          relayServerID: nil,
          machineRoute: nil,
          rootFingerprint: nil,
          trustEpoch: nil,
          failureCode: nil
        )
      case .blocked:
        status = try .init(
          lifecycle: lifecycle,
          relayServerID: nil,
          machineRoute: nil,
          rootFingerprint: nil,
          trustEpoch: nil,
          failureCode: failure
        )
      default:
        status = try .init(
          lifecycle: lifecycle,
          relayServerID: relay,
          machineRoute: route,
          rootFingerprint: fingerprint,
          trustEpoch: 1,
          failureCode: nil
        )
      }
      let encoded = try JSONEncoder().encode(status)
      _ = try JSONDecoder().decode(RuntimeMachineRemoteStatusV3.self, from: encoded)
    }

    XCTAssertThrowsError(
      try RuntimeMachineRemoteStatusV3(
        lifecycle: .active,
        relayServerID: nil,
        machineRoute: nil,
        rootFingerprint: nil,
        trustEpoch: nil,
        failureCode: nil
      )
    )
    XCTAssertThrowsError(
      try RuntimeMachineRemoteStatusV3(
        lifecycle: .blocked,
        relayServerID: relay,
        machineRoute: nil,
        rootFingerprint: nil,
        trustEpoch: nil,
        failureCode: failure
      )
    )
    XCTAssertThrowsError(
      try RuntimeMachineRemoteStatusV3(
        lifecycle: .active,
        relayServerID: Data(repeating: 0, count: 16),
        machineRoute: route,
        rootFingerprint: fingerprint,
        trustEpoch: 1,
        failureCode: nil
      )
    )
  }

  func testMachineRemoteStatusRejectsNarrativeSensitiveAndInvalidFailureFields() throws {
    let base: [String: Any] = [
      "lifecycle": "blocked",
      "failureCode": "daemon.remote.blocked",
    ]
    _ = try decodeStatus(base)

    for field in [
      "code", "origin", "spkiPins", "linkCert", "dataCert", "purgeProof",
      "retirementProof", "message", "detail",
    ] {
      var invalid = base
      invalid[field] = "forbidden"
      XCTAssertThrowsError(try decodeStatus(invalid), field)
    }
    for invalidCode in [
      "",
      "Daemon.Remote.Blocked",
      "has space",
      String(repeating: "a", count: 129),
    ] {
      var invalid = base
      invalid["failureCode"] = invalidCode
      XCTAssertThrowsError(try decodeStatus(invalid), invalidCode)
    }

    let failure = try RuntimeMachineRemoteFailureCodeV3("daemon.remote.blocked")
    XCTAssertTrue(String(reflecting: failure).contains("<redacted>"))
    XCTAssertFalse(String(reflecting: failure).contains(failure.rawValue))
  }

  func testEnrollmentBundleUsesStrictSharedBase64ShapesAndRejectsUnknownFields() throws {
    let input = try fixtureValue(named: "requestMachineEnroll")
    var envelope = try XCTUnwrap(
      JSONSerialization.jsonObject(with: input) as? [String: Any]
    )
    var body = try XCTUnwrap(envelope["body"] as? [String: Any])
    var payload = try XCTUnwrap(body["payload"] as? [String: Any])
    var bundle = try XCTUnwrap(payload["bundle"] as? [String: Any])
    XCTAssertEqual(
      try XCTUnwrap(bundle["spkiPins"] as? [String]).first,
      "-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_s"
    )

    bundle["future"] = true
    payload["bundle"] = bundle
    body["payload"] = payload
    envelope["body"] = body
    XCTAssertThrowsError(
      try RuntimeV4WireCodec.decodeEnvelope(
        JSONSerialization.data(withJSONObject: envelope, options: [.sortedKeys])
      )
    )

    var old = try XCTUnwrap(
      JSONSerialization.jsonObject(with: try fixtureValue(named: "requestHello"))
        as? [String: Any]
    )
    old["version"] = 2
    XCTAssertThrowsError(
      try RuntimeV4WireCodec.decodeEnvelope(
        JSONSerialization.data(withJSONObject: old, options: [.sortedKeys])
      )
    )
  }

  func testTrustResetReceiptIsStrictAndUninstallPurposeIsTyped() throws {
    let rootPresent = try fixtureValue(named: "requestTrustReset")
    let decodedRootPresent = try RuntimeV4WireCodec.decodeEnvelope(rootPresent)
    guard case .request(
      .trustReset(let scope, let uninstallPurge, let uninstallPurgePlan, let adminPurgeReceipt)
    ) = decodedRootPresent.body else {
      return XCTFail("root-present trust reset did not decode")
    }
    guard case .localOnly = scope else { return XCTFail("scope is not local-only") }
    XCTAssertFalse(uninstallPurge)
    XCTAssertNil(uninstallPurgePlan)
    XCTAssertNil(adminPurgeReceipt)
    try XCTAssertEqual(
      normalizedJSON(RuntimeV4WireCodec.encode(decodedRootPresent)),
      normalizedJSON(rootPresent)
    )

    let rootLost = try fixtureValue(named: "requestTrustResetWithAdminPurgeReceipt")
    var envelope = try XCTUnwrap(
      JSONSerialization.jsonObject(with: rootLost) as? [String: Any]
    )
    var body = try XCTUnwrap(envelope["body"] as? [String: Any])
    var payload = try XCTUnwrap(body["payload"] as? [String: Any])
    var receipt = try XCTUnwrap(payload["adminPurgeReceipt"] as? [String: Any])

    receipt["future"] = true
    payload["adminPurgeReceipt"] = receipt
    body["payload"] = payload
    envelope["body"] = body
    XCTAssertThrowsError(try decodeEnvelopeJSONObject(envelope))

    receipt.removeValue(forKey: "future")
    receipt["signature"] = "AA=="
    payload["adminPurgeReceipt"] = receipt
    body["payload"] = payload
    envelope["body"] = body
    XCTAssertThrowsError(try decodeEnvelopeJSONObject(envelope))

    envelope = try XCTUnwrap(
      JSONSerialization.jsonObject(with: rootLost) as? [String: Any]
    )
    body = try XCTUnwrap(envelope["body"] as? [String: Any])
    payload = try XCTUnwrap(body["payload"] as? [String: Any])
    receipt = try XCTUnwrap(payload["adminPurgeReceipt"] as? [String: Any])
    var readback = try XCTUnwrap(receipt["readback"] as? [String: Any])
    readback["retiredTombstones"] = 2
    receipt["readback"] = readback
    payload["adminPurgeReceipt"] = receipt
    body["payload"] = payload
    envelope["body"] = body
    XCTAssertThrowsError(try decodeEnvelopeJSONObject(envelope))

    let plan = try RuntimeUninstallPurgePlanV1(
      helperPath: "/Applications/AgentDeck.app/Contents/Helpers/agentdeck-finalizer",
      helperVersion: "1.2.3",
      helperSHA256: RuntimeArtifactSHA256V2(rawValue: String(repeating: "ab", count: 32)),
      teamIdentifier: "REALTEAM42",
      keychainAccessGroup: "REALTEAM42.com.agentdeck.agentdeckd.stable"
    )
    let uninstallRequest: RuntimeRequestV4 = .trustReset(
      scope: .localOnly,
      uninstallPurge: true,
      uninstallPurgePlan: plan,
      adminPurgeReceipt: nil
    )
    let uninstallEnvelope = RuntimeEnvelopeV4(
      version: runtimeProtocolVersionV4,
      messageID: RuntimeMessageID(rawValue: "runtime-v4-uninstall-purge"),
      body: .request(uninstallRequest)
    )
    let uninstallData = try RuntimeV4WireCodec.encode(uninstallEnvelope)
    let uninstallObject = try XCTUnwrap(
      JSONSerialization.jsonObject(with: uninstallData) as? [String: Any]
    )
    let uninstallBody = try XCTUnwrap(uninstallObject["body"] as? [String: Any])
    let uninstallPayload = try XCTUnwrap(uninstallBody["payload"] as? [String: Any])
    XCTAssertEqual(uninstallPayload["uninstallPurge"] as? Bool, true)
    XCTAssertEqual(
      uninstallPayload["uninstallPurgePlan"] as? [String: Any] != nil,
      true
    )

    var invalidPurpose = uninstallObject
    var invalidBody = uninstallBody
    var invalidPayload = uninstallPayload
    invalidPayload["uninstallPurge"] = "true"
    invalidBody["payload"] = invalidPayload
    invalidPurpose["body"] = invalidBody
    XCTAssertThrowsError(try decodeEnvelopeJSONObject(invalidPurpose))

    invalidPurpose = uninstallObject
    invalidBody = uninstallBody
    invalidPayload = uninstallPayload
    invalidPayload["uninstallPurge"] = false
    invalidBody["payload"] = invalidPayload
    invalidPurpose["body"] = invalidBody
    XCTAssertThrowsError(try decodeEnvelopeJSONObject(invalidPurpose))

    invalidPurpose = uninstallObject
    invalidBody = uninstallBody
    invalidPayload = uninstallPayload
    var invalidPlan = try XCTUnwrap(invalidPayload["uninstallPurgePlan"] as? [String: Any])
    invalidPlan["planId"] = "EREREREREREREREREREREQ=="
    invalidPayload["uninstallPurgePlan"] = invalidPlan
    invalidBody["payload"] = invalidPayload
    invalidPurpose["body"] = invalidBody
    XCTAssertThrowsError(try decodeEnvelopeJSONObject(invalidPurpose))
  }

  private func decodeStatus(_ object: [String: Any]) throws -> RuntimeMachineRemoteStatusV3 {
    try JSONDecoder().decode(
      RuntimeMachineRemoteStatusV3.self,
      from: JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    )
  }

  private func decodeEnvelopeJSONObject(_ object: [String: Any]) throws -> RuntimeEnvelopeV4 {
    try RuntimeV4WireCodec.decodeEnvelope(
      JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    )
  }

  private func fixtureValue(named name: String) throws -> Data {
    let text = try String(contentsOf: fixtureURL, encoding: .utf8)
    for line in text.split(whereSeparator: \.isNewline) {
      let object = try XCTUnwrap(
        JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any]
      )
      if object["case"] as? String == name {
        return try JSONSerialization.data(
          withJSONObject: try XCTUnwrap(object["value"]),
          options: [.sortedKeys]
        )
      }
    }
    throw XCTSkip("missing fixture \(name)")
  }

  private func normalizedJSON(_ data: Data) throws -> Data {
    try JSONSerialization.data(
      withJSONObject: JSONSerialization.jsonObject(with: data),
      options: [.sortedKeys]
    )
  }

  private var fixtureURL: URL {
    URL(fileURLWithPath: #filePath)
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .appendingPathComponent("protocol/agentdeck/fixtures/runtime-v4-wire.jsonl")
  }
}
