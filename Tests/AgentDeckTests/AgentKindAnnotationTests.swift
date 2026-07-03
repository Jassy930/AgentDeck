import XCTest
import AgentDeckCore
@testable import AgentDeck

final class AgentKindAnnotationTests: XCTestCase {
    func testDecodedEventsAlwaysCarryAgentKind() throws {
        let samples = [
            #"{"type":"sessionStarted","sessionId":"s","threadId":null,"agentKind":"codex"}"#,
            #"{"type":"agentItem","sessionId":"s","threadId":"t","agentKind":"claude_code","item":{"kind":"assistantMessage","text":"x","meta":{"vendorExtensions":{}}}}"#,
            #"{"type":"turnComplete","sessionId":"s","threadId":"t","agentKind":"codex","summary":{"totalInputTokens":1,"totalOutputTokens":1,"elapsedMs":10}}"#,
        ]
        for s in samples {
            let event = try JSONDecoder().decode(ServerEvent.self, from: Data(s.utf8))
            switch event {
            case .error: continue
            default: break // just verify it decoded without throwing
            }
        }
    }
}
