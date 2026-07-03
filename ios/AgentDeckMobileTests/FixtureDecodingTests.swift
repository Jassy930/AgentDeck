import XCTest
import AgentDeckCore
@testable import AgentDeckMobile

final class FixtureDecodingTests: XCTestCase {
    private var bundle: Bundle { Bundle(for: PlaceholderViewController.self) }

    func testDeckDecodes() throws {
        let url = try XCTUnwrap(bundle.url(forResource: "deck", withExtension: "json"))
        let deck = try JSONDecoder().decode(FixtureDeck.self, from: Data(contentsOf: url))
        XCTAssertEqual(deck.machines.count, 2)
        XCTAssertEqual(deck.sessions.count, 4)
    }

    /// 防漂移门禁：所有 stream fixture 的 event 必须能被 AgentDeckCore 的
    /// ServerEvent 解码 —— fixture 本身就是对协议理解的检验。
    func testAllStreamFixturesDecodeAsServerEvents() throws {
        let urls = bundle.urls(forResourcesWithExtension: "json", subdirectory: nil) ?? []
        let streamURLs = urls.filter { $0.lastPathComponent.hasPrefix("stream-") }
        XCTAssertEqual(streamURLs.count, 4, "预期 4 个 stream fixture")
        for url in streamURLs {
            let steps = try JSONDecoder().decode([FixtureStreamStep].self, from: Data(contentsOf: url))
            XCTAssertFalse(steps.isEmpty, "\(url.lastPathComponent) 不应为空")
        }
    }

    func testApprovalFixtureCarriesGate() throws {
        let url = try XCTUnwrap(bundle.url(forResource: "stream-approval-01", withExtension: "json"))
        let steps = try JSONDecoder().decode([FixtureStreamStep].self, from: Data(contentsOf: url))
        XCTAssertTrue(steps.contains { $0.awaitApproval == true })
    }
}
