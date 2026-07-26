import CryptoKit
import Foundation
import Security
import os

public enum RelayTLSError: Error, Equatable, Sendable {
  case invalidPinSet
  case invalidChallenge
  case hostMismatch
  case trustEvaluationFailed
  case pinMismatch
  case invalidCertificate

  public var code: String {
    switch self {
    case .invalidPinSet:
      "remote.transport.tls_pinset_invalid"
    case .invalidChallenge:
      "remote.transport.tls_challenge_invalid"
    case .hostMismatch:
      "remote.transport.tls_hostname_mismatch"
    case .trustEvaluationFailed:
      "remote.transport.tls_trust_failed"
    case .pinMismatch:
      "remote.transport.tls_pin_mismatch"
    case .invalidCertificate:
      "remote.transport.tls_certificate_invalid"
    }
  }
}

public struct SPKIPinSet: Equatable, Sendable {
  public let current: Data
  public let next: Data?

  public init(current: Data, next: Data? = nil) throws {
    guard current.count == SHA256.byteCount,
      next == nil || next?.count == SHA256.byteCount,
      next != current
    else {
      throw RelayTLSError.invalidPinSet
    }
    self.current = current
    self.next = next
  }

  func contains(_ pin: Data) -> Bool {
    pin == current || pin == next
  }
}

public struct RelayTLSPolicy: Equatable, Sendable {
  enum Mode: Equatable, Sendable {
    case publicCA
    case publicCAAndPins(SPKIPinSet)
    case pinnedSPKI(SPKIPinSet)
  }

  let mode: Mode

  private init(mode: Mode) {
    self.mode = mode
  }

  public static var publicCA: Self {
    Self(mode: .publicCA)
  }

  public static func publicCAAndPins(
    current: Data,
    next: Data? = nil
  ) throws -> Self {
    Self(mode: .publicCAAndPins(try SPKIPinSet(current: current, next: next)))
  }

  public static func pinnedSPKI(
    current: Data,
    next: Data? = nil
  ) throws -> Self {
    Self(mode: .pinnedSPKI(try SPKIPinSet(current: current, next: next)))
  }
}

protocol RelayServerTrustEvaluating: Sendable {
  func evaluate(
    _ serverTrust: SecTrust,
    host: String,
    policy: RelayTLSPolicy
  ) throws
}

final class RelayTLSFailureLatch: Sendable {
  private let storage = OSAllocatedUnfairLock<RelayTLSError?>(initialState: nil)

  func record(_ error: RelayTLSError) {
    storage.withLock { current in
      if current == nil { current = error }
    }
  }

  func load() -> RelayTLSError? {
    storage.withLock { $0 }
  }
}

struct SecurityRelayServerTrustEvaluator: RelayServerTrustEvaluating {
  func evaluate(
    _ serverTrust: SecTrust,
    host: String,
    policy: RelayTLSPolicy
  ) throws {
    guard !host.isEmpty else { throw RelayTLSError.hostMismatch }
    guard
      SecTrustSetPolicies(serverTrust, SecPolicyCreateSSL(true, host as CFString))
        == errSecSuccess
    else {
      throw RelayTLSError.trustEvaluationFailed
    }

    let leaf = try leafCertificate(from: serverTrust)
    switch policy.mode {
    case .publicCA:
      guard SecTrustEvaluateWithError(serverTrust, nil) else {
        throw RelayTLSError.trustEvaluationFailed
      }

    case .publicCAAndPins(let pins):
      guard SecTrustEvaluateWithError(serverTrust, nil) else {
        throw RelayTLSError.trustEvaluationFailed
      }
      guard try pins.contains(spkiPin(for: leaf)) else {
        throw RelayTLSError.pinMismatch
      }

    case .pinnedSPKI(let pins):
      // Pin 先建立精确 leaf 身份，再把同一 leaf 作为显式 anchor 运行 SSL policy。
      // 该路径仍会验证 hostname、有效期、证书结构和 TLS key usage，不是 pin-only 绕过。
      guard try pins.contains(spkiPin(for: leaf)) else {
        throw RelayTLSError.pinMismatch
      }
      guard SecTrustSetAnchorCertificates(serverTrust, [leaf] as CFArray) == errSecSuccess,
        SecTrustSetAnchorCertificatesOnly(serverTrust, true) == errSecSuccess,
        SecTrustEvaluateWithError(serverTrust, nil)
      else {
        throw RelayTLSError.trustEvaluationFailed
      }
    }
  }

  private func leafCertificate(from trust: SecTrust) throws -> SecCertificate {
    guard let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
      let leaf = chain.first
    else {
      throw RelayTLSError.invalidCertificate
    }
    return leaf
  }

  private func spkiPin(for certificate: SecCertificate) throws -> Data {
    let certificateDER = SecCertificateCopyData(certificate) as Data
    let spkiDER = try RelayDERSubjectPublicKeyInfo.extract(from: certificateDER)
    return Data(SHA256.hash(data: spkiDER))
  }
}

/// 从 X.509 Certificate DER 中切出完整 SubjectPublicKeyInfo TLV。
///
/// 不能使用 `SecKeyCopyExternalRepresentation`：后者只给 raw key bytes，和协议冻结的
/// `SHA-256(DER SPKI)` 不是同一个值。
enum RelayDERSubjectPublicKeyInfo {
  static func extract(from certificateDER: Data) throws -> Data {
    let bytes = [UInt8](certificateDER)
    var reader = DERReader(bytes: bytes)
    let certificate = try reader.read(expectedTag: 0x30)
    guard certificate.end == bytes.count, reader.offset == bytes.count else {
      throw RelayTLSError.invalidCertificate
    }

    var certificateBody = DERReader(
      bytes: bytes,
      offset: certificate.valueStart,
      limit: certificate.end
    )
    let tbs = try certificateBody.read(expectedTag: 0x30)
    var tbsBody = DERReader(bytes: bytes, offset: tbs.valueStart, limit: tbs.end)

    if tbsBody.peekTag() == 0xA0 {
      _ = try tbsBody.read(expectedTag: 0xA0)
    }
    _ = try tbsBody.read(expectedTag: 0x02)  // serialNumber
    _ = try tbsBody.read(expectedTag: 0x30)  // signature
    _ = try tbsBody.read(expectedTag: 0x30)  // issuer
    _ = try tbsBody.read(expectedTag: 0x30)  // validity
    _ = try tbsBody.read(expectedTag: 0x30)  // subject
    let spki = try tbsBody.read(expectedTag: 0x30)
    return Data(bytes[spki.start..<spki.end])
  }
}

private struct DERTLV {
  let start: Int
  let valueStart: Int
  let end: Int
}

private struct DERReader {
  let bytes: [UInt8]
  var offset: Int
  let limit: Int

  init(bytes: [UInt8], offset: Int = 0, limit: Int? = nil) {
    self.bytes = bytes
    self.offset = offset
    self.limit = limit ?? bytes.count
  }

  func peekTag() -> UInt8? {
    guard offset < limit else { return nil }
    return bytes[offset]
  }

  mutating func read(expectedTag: UInt8) throws -> DERTLV {
    let start = offset
    guard offset < limit, bytes[offset] == expectedTag else {
      throw RelayTLSError.invalidCertificate
    }
    offset += 1
    let length = try readLength()
    let valueStart = offset
    let (end, overflow) = valueStart.addingReportingOverflow(length)
    guard !overflow, end <= limit else {
      throw RelayTLSError.invalidCertificate
    }
    offset = end
    return DERTLV(start: start, valueStart: valueStart, end: end)
  }

  private mutating func readLength() throws -> Int {
    guard offset < limit else { throw RelayTLSError.invalidCertificate }
    let first = bytes[offset]
    offset += 1
    if first < 0x80 { return Int(first) }

    let count = Int(first & 0x7F)
    guard count > 0, count <= MemoryLayout<Int>.size,
      offset <= limit - count,
      bytes[offset] != 0
    else {
      throw RelayTLSError.invalidCertificate
    }

    var length = 0
    for _ in 0..<count {
      let (shifted, shiftOverflow) = length.multipliedReportingOverflow(by: 256)
      let (next, addOverflow) = shifted.addingReportingOverflow(Int(bytes[offset]))
      guard !shiftOverflow, !addOverflow else {
        throw RelayTLSError.invalidCertificate
      }
      length = next
      offset += 1
    }
    guard length >= 0x80 else {
      throw RelayTLSError.invalidCertificate
    }
    return length
  }
}

final class PinnedURLSessionDelegate: NSObject, URLSessionDelegate,
  URLSessionTaskDelegate, URLSessionWebSocketDelegate
{
  typealias OpenHandler = @Sendable () -> Void
  typealias CloseHandler = @Sendable (URLSessionWebSocketTask.CloseCode) -> Void
  typealias FailureHandler = @Sendable (RelayTLSError) -> Void
  typealias CompletionHandler = @Sendable (Error?) -> Void
  typealias InvalidationHandler = @Sendable (Error?) -> Void

  private let expectedHost: String
  private let policy: RelayTLSPolicy
  private let evaluator: any RelayServerTrustEvaluating
  private let onOpen: OpenHandler
  private let onClose: CloseHandler
  private let onTLSFailure: FailureHandler
  private let onComplete: CompletionHandler
  private let onInvalidation: InvalidationHandler

  init(
    expectedHost: String,
    policy: RelayTLSPolicy,
    evaluator: any RelayServerTrustEvaluating = SecurityRelayServerTrustEvaluator(),
    onOpen: @escaping OpenHandler = {},
    onClose: @escaping CloseHandler = { _ in },
    onTLSFailure: @escaping FailureHandler = { _ in },
    onComplete: @escaping CompletionHandler = { _ in },
    onInvalidation: @escaping InvalidationHandler = { _ in }
  ) {
    self.expectedHost = expectedHost
    self.policy = policy
    self.evaluator = evaluator
    self.onOpen = onOpen
    self.onClose = onClose
    self.onTLSFailure = onTLSFailure
    self.onComplete = onComplete
    self.onInvalidation = onInvalidation
  }

  func evaluateServerTrust(_ trust: SecTrust, challengeHost: String) throws {
    guard challengeHost.caseInsensitiveCompare(expectedHost) == .orderedSame else {
      throw RelayTLSError.hostMismatch
    }
    try evaluator.evaluate(trust, host: expectedHost, policy: policy)
  }

  func urlSession(
    _ session: URLSession,
    didReceive challenge: URLAuthenticationChallenge,
    completionHandler:
      @escaping @Sendable (
        URLSession.AuthChallengeDisposition,
        URLCredential?
      ) -> Void
  ) {
    guard
      challenge.protectionSpace.authenticationMethod
        == NSURLAuthenticationMethodServerTrust
    else {
      completionHandler(.performDefaultHandling, nil)
      return
    }
    guard let trust = challenge.protectionSpace.serverTrust else {
      onTLSFailure(.invalidChallenge)
      completionHandler(.cancelAuthenticationChallenge, nil)
      return
    }
    do {
      try evaluateServerTrust(trust, challengeHost: challenge.protectionSpace.host)
      completionHandler(.useCredential, URLCredential(trust: trust))
    } catch let error as RelayTLSError {
      onTLSFailure(error)
      completionHandler(.cancelAuthenticationChallenge, nil)
    } catch {
      onTLSFailure(.trustEvaluationFailed)
      completionHandler(.cancelAuthenticationChallenge, nil)
    }
  }

  func urlSession(
    _ session: URLSession,
    task: URLSessionTask,
    willPerformHTTPRedirection response: HTTPURLResponse,
    newRequest request: URLRequest,
    completionHandler: @escaping @Sendable (URLRequest?) -> Void
  ) {
    // 包括同 host、同 scheme 在内的所有 redirect 都拒绝。
    completionHandler(nil)
  }

  func urlSession(
    _ session: URLSession,
    webSocketTask: URLSessionWebSocketTask,
    didOpenWithProtocol protocol: String?
  ) {
    onOpen()
  }

  func urlSession(
    _ session: URLSession,
    webSocketTask: URLSessionWebSocketTask,
    didCloseWith closeCode: URLSessionWebSocketTask.CloseCode,
    reason: Data?
  ) {
    onClose(closeCode)
  }

  func urlSession(
    _ session: URLSession,
    task: URLSessionTask,
    didCompleteWithError error: Error?
  ) {
    onComplete(error)
  }

  func urlSession(
    _ session: URLSession,
    didBecomeInvalidWithError error: Error?
  ) {
    onInvalidation(error)
  }
}
