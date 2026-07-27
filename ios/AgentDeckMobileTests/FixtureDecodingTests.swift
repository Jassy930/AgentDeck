import AgentDeckCore
import XCTest

@testable import AgentDeckMobile

final class FixtureDecodingTests: XCTestCase {
    private var bundle: Bundle { Bundle(for: MachineListViewController.self) }

    func testDeckDecodesIntoSharedModelInputs() throws {
        let url = try XCTUnwrap(bundle.url(forResource: "deck", withExtension: "json"))
        let deck = try JSONDecoder().decode(FixtureDeck.self, from: Data(contentsOf: url))
        XCTAssertEqual(deck.machines.count, 2)
        XCTAssertEqual(deck.sessions.count, 4)
        XCTAssertEqual(deck.machines.first?.connectionState, .connected)
        XCTAssertGreaterThan(deck.sessions.first?.revision ?? 0, 0)
    }

    func testAllStreamFixturesDecodeCanonicalSnapshotAndRuntimeEvents() throws {
        let urls = bundle.urls(forResourcesWithExtension: "json", subdirectory: nil) ?? []
        let streamURLs = urls.filter { $0.lastPathComponent.hasPrefix("stream-") }
        XCTAssertEqual(streamURLs.count, 4, "预期 4 个 stream fixture")
        for url in streamURLs {
            let fixture = try JSONDecoder().decode(
                FixtureConversation.self,
                from: Data(contentsOf: url)
            )
            XCTAssertFalse(fixture.steps.isEmpty, "\(url.lastPathComponent) 不应为空")
            XCTAssertEqual(
                fixture.snapshot.conversationID,
                fixture.steps.first?.event.conversationID
            )
            XCTAssertTrue(fixture.steps.allSatisfy { $0.event.eventID.rawValue.isEmpty == false })
        }
    }

    func testApprovalFixtureReservesThreeSequencesForDynamicResolutionChain() throws {
        let url = try XCTUnwrap(
            bundle.url(forResource: "stream-approval-01", withExtension: "json")
        )
        let fixture = try JSONDecoder().decode(
            FixtureConversation.self,
            from: Data(contentsOf: url)
        )
        let gateIndex = try XCTUnwrap(fixture.steps.firstIndex { $0.awaitApproval == true })
        XCTAssertEqual(fixture.steps[gateIndex].event.eventSeq, 2)
        XCTAssertEqual(fixture.steps[gateIndex + 1].event.eventSeq, 6)
    }
}
