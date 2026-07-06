import XCTest
@testable import AgentDeck

final class DotEnvTests: XCTestCase {

    func testParsesBasicPairs() {
        let d = Dictionary(uniqueKeysWithValues: DotEnv.parse("A=1\nB=two").map { ($0.key, $0.value) })
        XCTAssertEqual(d["A"], "1")
        XCTAssertEqual(d["B"], "two")
    }

    func testSkipsCommentsAndBlankLines() {
        let pairs = DotEnv.parse("# comment\n\n  \nA=1\n#B=2")
        XCTAssertEqual(pairs.count, 1)
        XCTAssertEqual(pairs.first?.key, "A")
    }

    func testStripsExportPrefixAndQuotes() {
        let d = Dictionary(uniqueKeysWithValues: DotEnv.parse(
            "export A=1\nB=\"quoted value\"\nC='single'").map { ($0.key, $0.value) })
        XCTAssertEqual(d["A"], "1")
        XCTAssertEqual(d["B"], "quoted value")
        XCTAssertEqual(d["C"], "single")
    }

    func testTrimsWhitespaceAndKeepsInnerEquals() {
        let d = Dictionary(uniqueKeysWithValues: DotEnv.parse(
            "  A = 1 \nURL=https://x/?a=1&b=2").map { ($0.key, $0.value) })
        XCTAssertEqual(d["A"], "1")
        XCTAssertEqual(d["URL"], "https://x/?a=1&b=2", "首个 = 之后的 = 应保留在 value 里")
    }

    func testSkipsLinesWithoutEqualsOrEmptyKey() {
        XCTAssertTrue(DotEnv.parse("noequals\n=novalue").isEmpty)
    }

    // MARK: - inject 优先级：真实环境优先，只填补未设的键

    func testInjectOnlyFillsUnsetKeys() {
        var written: [String: String] = [:]
        let injected = DotEnv.inject(
            "A=fromEnvFile\nB=alsoFile",
            existing: ["A": "fromShell"],   // A 已在真实环境
            setValue: { k, v in written[k] = v })
        XCTAssertEqual(injected, 1)
        XCTAssertNil(written["A"], "已存在的键不应被 .env 覆盖")
        XCTAssertEqual(written["B"], "alsoFile", "未设的键应被注入")
    }
}
