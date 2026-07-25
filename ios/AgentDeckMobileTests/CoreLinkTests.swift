import AgentDeckCore
import AgentDeckRelayClient
import AgentDeckSessionSource
import XCTest

final class CoreLinkTests: XCTestCase {
  func testServerEventDecodesOnIOS() throws {
    let json = #"{"type":"sessionStarted","sessionId":"s1","threadId":null,"agentKind":"codex"}"#
    let event = try JSONDecoder().decode(ServerEvent.self, from: Data(json.utf8))
    guard case .sessionStarted(let sid, _, let kind) = event else {
      return XCTFail("expected sessionStarted")
    }
    XCTAssertEqual(sid, "s1")
    XCTAssertEqual(kind, .codex)
  }

  func testSharedSessionSourceAndRelayClientLinkOnIOS() {
    let failure = SessionSourceFailure(code: .transportUnavailable)
    let hello = RelayV2Hello(protocolVersion: relayProtocolVersionV2)

    XCTAssertEqual(failure.code, .transportUnavailable)
    XCTAssertEqual(hello.protocolVersion, relayProtocolVersionV2)
  }
}
