import AgentDeckCore
import AgentDeckRelayClient
import AgentDeckSessionSource
import XCTest

final class CoreLinkTests: XCTestCase {
    func testCanonicalConversationProjectionLinksOnIOS() throws {
        let snapshot = try SessionSourceTestValues.snapshot(conversationID: "conversation-ios")
        var projection = try RuntimeConversationState(
            conversationID: RuntimeConversationID(rawValue: "conversation-ios")
        )
        try projection.apply(snapshot)

        XCTAssertEqual(projection.items.count, 0)
        XCTAssertEqual(projection.capabilities?.agentKind, .codex)
    }

    func testSharedSessionSourceAndRelayClientLinkOnIOS() {
        let failure = SessionSourceFailure(code: .transportUnavailable)
        let hello = RelayV2Hello(protocolVersion: relayProtocolVersionV2)

        XCTAssertEqual(failure.code, .transportUnavailable)
        XCTAssertEqual(hello.protocolVersion, relayProtocolVersionV2)
    }
}
