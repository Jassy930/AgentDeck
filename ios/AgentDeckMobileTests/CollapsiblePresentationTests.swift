import XCTest
import AgentDeckMobileCore
@testable import AgentDeckMobile

final class CollapsiblePresentationTests: XCTestCase {
    func testShellPresentation() {
        var item = UIItem(id: "s", lifecycle: "completed", kind: "shell")
        item.command = "bun update"
        item.statusName = "failed"
        item.exitCode = 1
        item.durationMs = 9200
        let p = CollapsiblePresentation.make(from: item)
        XCTAssertEqual(p?.title, "$ bun update")
        XCTAssertEqual(p?.detail, "failed · exit 1 · 9.2s")
        XCTAssertEqual(p?.bodyIsMono, true)
    }

    func testReasoningDefaultsCollapsedWithBody() {
        var item = UIItem(id: "r", lifecycle: "completed", kind: "reasoning")
        item.text = "思考过程"
        let p = CollapsiblePresentation.make(from: item)
        XCTAssertEqual(p?.title, "Reasoning")
        XCTAssertEqual(p?.body, "思考过程")
    }

    func testMessageKindIsNotCollapsible() {
        let item = UIItem(id: "m", lifecycle: "completed", kind: "message")
        XCTAssertNil(CollapsiblePresentation.make(from: item))
    }
}
