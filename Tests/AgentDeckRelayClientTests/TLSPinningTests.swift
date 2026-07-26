import CryptoKit
import Foundation
import Security
import XCTest

@testable import AgentDeckRelayClient

final class TLSPinningTests: XCTestCase {
  func testPinSetRequiresOneOrTwoUniqueSHA256Pins() throws {
    let current = Data(repeating: 0x11, count: 32)
    let next = Data(repeating: 0x22, count: 32)

    XCTAssertNoThrow(try SPKIPinSet(current: current))
    XCTAssertNoThrow(try SPKIPinSet(current: current, next: next))
    XCTAssertThrowsError(try SPKIPinSet(current: Data(repeating: 0, count: 31)))
    XCTAssertThrowsError(try SPKIPinSet(current: current, next: current))
    XCTAssertThrowsError(
      try SPKIPinSet(current: current, next: Data(repeating: 0, count: 33))
    )
  }

  func testPoliciesRemainThreeExplicitNonFallbackModes() throws {
    let current = Data(repeating: 0x11, count: 32)
    let next = Data(repeating: 0x22, count: 32)

    XCTAssertEqual(RelayTLSPolicy.publicCA.mode, .publicCA)
    XCTAssertEqual(
      try RelayTLSPolicy.publicCAAndPins(current: current, next: next).mode,
      .publicCAAndPins(try SPKIPinSet(current: current, next: next))
    )
    XCTAssertEqual(
      try RelayTLSPolicy.pinnedSPKI(current: current, next: next).mode,
      .pinnedSPKI(try SPKIPinSet(current: current, next: next))
    )
  }

  func testEd25519FixtureHashesExactDERSubjectPublicKeyInfo() throws {
    let certificateDER = try fixtureCertificateDER()
    let spkiDER = try RelayDERSubjectPublicKeyInfo.extract(from: certificateDER)
    let pin = Data(SHA256.hash(data: spkiDER))

    XCTAssertEqual(
      pin,
      Data(hex: "e3a944f7e84ee6ec9d69b26528e720ff33df7c35ce5ed7899bb14c7718938ec3")
    )
    XCTAssertNotEqual(pin, Data(SHA256.hash(data: certificateDER)))
    XCTAssertEqual(spkiDER.first, 0x30)
  }

  func testDERExtractorRejectsTruncationTrailingAndNonCanonicalLength() throws {
    let certificateDER = try fixtureCertificateDER()
    XCTAssertThrowsError(
      try RelayDERSubjectPublicKeyInfo.extract(from: certificateDER.dropLast())
    )

    var trailing = certificateDER
    trailing.append(0)
    XCTAssertThrowsError(try RelayDERSubjectPublicKeyInfo.extract(from: trailing))

    XCTAssertThrowsError(
      try RelayDERSubjectPublicKeyInfo.extract(
        from: Data([0x30, 0x81, 0x01, 0x00])
      )
    )
    XCTAssertThrowsError(
      try RelayDERSubjectPublicKeyInfo.extract(
        from: Data([0x30, 0x80, 0x00, 0x00])
      )
    )
  }

  func testDelegateRejectsChallengeHostBeforeCallingTrustEvaluator() throws {
    let trust = try fixtureTrust()
    let evaluator = RecordingTrustEvaluator(result: .success(()))
    let delegate = PinnedURLSessionDelegate(
      expectedHost: "relay.example",
      policy: .publicCA,
      evaluator: evaluator
    )

    XCTAssertThrowsError(
      try delegate.evaluateServerTrust(trust, challengeHost: "redirect.example")
    ) { error in
      XCTAssertEqual(error as? RelayTLSError, .hostMismatch)
    }
    XCTAssertEqual(evaluator.callCount, 0)
  }

  func testDelegatePassesExactHostAndPolicyToEvaluator() throws {
    let trust = try fixtureTrust()
    let current = Data(repeating: 0x11, count: 32)
    let policy = try RelayTLSPolicy.publicCAAndPins(current: current)
    let evaluator = RecordingTrustEvaluator(result: .success(()))
    let delegate = PinnedURLSessionDelegate(
      expectedHost: "relay.example",
      policy: policy,
      evaluator: evaluator
    )

    XCTAssertNoThrow(
      try delegate.evaluateServerTrust(trust, challengeHost: "RELAY.EXAMPLE")
    )
    XCTAssertEqual(evaluator.callCount, 1)
    XCTAssertEqual(evaluator.lastHost, "relay.example")
    XCTAssertEqual(evaluator.lastPolicy, policy)
  }

  func testPublicCAAndPinsCannotRescueUntrustedSelfSignedChain() throws {
    let certificateDER = try fixtureCertificateDER()
    let pin = Data(
      SHA256.hash(
        data: try RelayDERSubjectPublicKeyInfo.extract(from: certificateDER)
      )
    )
    let trust = try fixtureTrust()

    XCTAssertThrowsError(
      try SecurityRelayServerTrustEvaluator().evaluate(
        trust,
        host: "127.0.0.1",
        policy: try .publicCAAndPins(current: pin)
      )
    ) { error in
      XCTAssertEqual(error as? RelayTLSError, .trustEvaluationFailed)
    }
  }

  func testPinnedSPKIMismatchFailsBeforeTrustFallback() throws {
    let trust = try fixtureTrust()
    XCTAssertThrowsError(
      try SecurityRelayServerTrustEvaluator().evaluate(
        trust,
        host: "127.0.0.1",
        policy: try .pinnedSPKI(current: Data(repeating: 0xA5, count: 32))
      )
    ) { error in
      XCTAssertEqual(error as? RelayTLSError, .pinMismatch)
    }
  }

  func testPinnedSPKINextSlotAllowsRotationAndBothMismatchFailClosed() throws {
    let certificateDER = try validPinnedFixtureDER()
    let leafPin = Data(
      SHA256.hash(
        data: try RelayDERSubjectPublicKeyInfo.extract(from: certificateDER)
      )
    )
    let wrongCurrent = Data(repeating: 0xA5, count: 32)
    let wrongNext = Data(repeating: 0x5A, count: 32)
    let evaluator = SecurityRelayServerTrustEvaluator()

    XCTAssertNoThrow(
      try evaluator.evaluate(
        trust(for: certificateDER, verifyDate: try pinnedFixtureValidDate),
        host: "relay.example",
        policy: try .pinnedSPKI(current: wrongCurrent, next: leafPin)
      )
    )
    XCTAssertThrowsError(
      try evaluator.evaluate(
        trust(for: certificateDER, verifyDate: try pinnedFixtureValidDate),
        host: "relay.example",
        policy: try .pinnedSPKI(current: wrongCurrent, next: wrongNext)
      )
    ) { error in
      XCTAssertEqual(error as? RelayTLSError, .pinMismatch)
    }
  }

  func testPinnedSelfSignedStillRunsSSLHostnameAndValidityPolicy() throws {
    let certificateDER = try validPinnedFixtureDER()
    let pin = Data(
      SHA256.hash(
        data: try RelayDERSubjectPublicKeyInfo.extract(from: certificateDER)
      )
    )
    XCTAssertEqual(
      pin,
      Data(hex: "83713aeb34c55bd0193bbaeac0f37f133fc3fd9ba5a01c87701deba0bfb8eada")
    )

    XCTAssertNoThrow(
      try SecurityRelayServerTrustEvaluator().evaluate(
        trust(for: certificateDER, verifyDate: try pinnedFixtureValidDate),
        host: "relay.example",
        policy: try .pinnedSPKI(current: pin)
      )
    )
    XCTAssertThrowsError(
      try SecurityRelayServerTrustEvaluator().evaluate(
        trust(for: certificateDER, verifyDate: try pinnedFixtureValidDate),
        host: "wrong.example",
        policy: try .pinnedSPKI(current: pin)
      )
    ) { error in
      XCTAssertEqual(error as? RelayTLSError, .trustEvaluationFailed)
    }
    XCTAssertThrowsError(
      try SecurityRelayServerTrustEvaluator().evaluate(
        trust(
          for: certificateDER,
          verifyDate: try XCTUnwrap(
            ISO8601DateFormatter().date(from: "2028-01-01T00:00:00Z")
          )
        ),
        host: "relay.example",
        policy: try .pinnedSPKI(current: pin)
      )
    ) { error in
      XCTAssertEqual(error as? RelayTLSError, .trustEvaluationFailed)
    }
  }

  func testEveryHTTPRedirectIsRejectedIncludingSameHostWSS() throws {
    let capture = RedirectCapture()
    let delegate = PinnedURLSessionDelegate(
      expectedHost: "relay.example",
      policy: .publicCA
    )
    let original = try XCTUnwrap(URL(string: "wss://relay.example/v2/connect"))
    let redirected = try XCTUnwrap(URL(string: "wss://relay.example/v2/connect?new=1"))
    let task = URLSession.shared.dataTask(with: original)
    let response = try XCTUnwrap(
      HTTPURLResponse(
        url: original,
        statusCode: 302,
        httpVersion: "HTTP/1.1",
        headerFields: ["Location": redirected.absoluteString]
      )
    )

    delegate.urlSession(
      URLSession.shared,
      task: task,
      willPerformHTTPRedirection: response,
      newRequest: URLRequest(url: redirected)
    ) { request in
      capture.record(request)
    }
    XCTAssertTrue(capture.wasCalled)
    XCTAssertNil(capture.request)
  }

  private func fixtureCertificateDER() throws -> Data {
    let pemURL =
      repoRoot
      .appendingPathComponent("agentdeck-relay/tests/fixtures/test_cert.pem")
    let pem = try String(contentsOf: pemURL, encoding: .utf8)
    let base64 =
      pem
      .split(whereSeparator: \.isNewline)
      .filter { !$0.hasPrefix("-----") }
      .joined()
    return try XCTUnwrap(Data(base64Encoded: String(base64)))
  }

  private func fixtureTrust() throws -> SecTrust {
    try trust(for: fixtureCertificateDER())
  }

  private func validPinnedFixtureDER() throws -> Data {
    // P-256 self-signed leaf；SAN=relay.example、CA=false、digitalSignature、serverAuth，
    // 2026-07-26 至 2027-07-26。只提交公开证书，不包含生成它的 private key。
    let base64 = """
      MIIBwzCCAWmgAwIBAgIUPLx7mzEArf5uMdxRfu+vNKtP/ZgwCgYIKoZIzj0EAwIwGDEWMBQGA1UEAwwNcmVsYXkuZXhhbXBsZTAeFw0yNjA3MjYwMDAzMTdaFw0yNzA3MjYwMDAzMTdaMBgxFjAUBgNVBAMMDXJlbGF5LmV4YW1wbGUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATxKvZIOUhl6erpSzAlVk21c3fUucuYCmyU1lRkkG/pbBWfzyxtzvTVcM/meRIenOEthAAcC/NSY57XCe2dCXUio4GQMIGNMB0GA1UdDgQWBBQJNb0GDzeGgdp86lUp9VMCs1xmIzAfBgNVHSMEGDAWgBQJNb0GDzeGgdp86lUp9VMCs1xmIzAYBgNVHREEETAPgg1yZWxheS5leGFtcGxlMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAoGCCqGSM49BAMCA0gAMEUCIB0fpEy8kpz6n+kjeblhwTs0uXs8KQVWom+ifOKulefpAiEA15lMiDkWwvaHP6gB9E5NhITAVphSqBBE6a+KA4Dp+0s=
      """
    return try XCTUnwrap(
      Data(base64Encoded: base64, options: .ignoreUnknownCharacters)
    )
  }

  private func trust(
    for certificateDER: Data,
    verifyDate: Date? = nil
  ) throws -> SecTrust {
    let certificate = try XCTUnwrap(
      SecCertificateCreateWithData(nil, certificateDER as CFData)
    )
    var trust: SecTrust?
    XCTAssertEqual(
      SecTrustCreateWithCertificates(certificate, SecPolicyCreateBasicX509(), &trust),
      errSecSuccess
    )
    let resolved = try XCTUnwrap(trust)
    if let verifyDate {
      XCTAssertEqual(SecTrustSetVerifyDate(resolved, verifyDate as CFDate), errSecSuccess)
    }
    return resolved
  }

  private var pinnedFixtureValidDate: Date {
    get throws {
      try XCTUnwrap(
        ISO8601DateFormatter().date(from: "2026-08-01T00:00:00Z")
      )
    }
  }

  private var repoRoot: URL {
    URL(fileURLWithPath: #filePath)
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
  }
}

private final class RecordingTrustEvaluator: RelayServerTrustEvaluating, @unchecked Sendable {
  private let lock = NSLock()
  private let result: Result<Void, RelayTLSError>
  private var calls: [(String, RelayTLSPolicy)] = []

  init(result: Result<Void, RelayTLSError>) {
    self.result = result
  }

  var callCount: Int {
    lock.withLock { calls.count }
  }

  var lastHost: String? {
    lock.withLock { calls.last?.0 }
  }

  var lastPolicy: RelayTLSPolicy? {
    lock.withLock { calls.last?.1 }
  }

  func evaluate(
    _ serverTrust: SecTrust,
    host: String,
    policy: RelayTLSPolicy
  ) throws {
    lock.withLock { calls.append((host, policy)) }
    try result.get()
  }
}

private final class RedirectCapture: @unchecked Sendable {
  private let lock = NSLock()
  private var captured: URLRequest??

  var wasCalled: Bool {
    lock.withLock { captured != nil }
  }

  var request: URLRequest? {
    lock.withLock { captured ?? nil }
  }

  func record(_ request: URLRequest?) {
    lock.withLock { captured = request }
  }
}

extension Data {
  fileprivate init(hex: String) {
    precondition(hex.count.isMultiple(of: 2))
    self.init(capacity: hex.count / 2)
    var index = hex.startIndex
    while index < hex.endIndex {
      let next = hex.index(index, offsetBy: 2)
      append(UInt8(hex[index..<next], radix: 16)!)
      index = next
    }
  }
}
