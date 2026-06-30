import XCTest
@testable import AgentDeck

final class NoVendorBranchInUITests: XCTestCase {
    static let whitelist: Set<String> = [
        "CapabilityRouter.swift",
        "AgentKindIcon.swift",
        "DaemonClient.swift",
        "V2Types.swift",
        "AgentItemReducer.swift",
        "AgentControlBar.swift",
        "AgentTokenAuthMiniPanel.swift",
        "ReasoningEffortPicker.swift",
    ]

    func testNoHardcodedVendorBranchInUI() throws {
        let sourcesURL = URL(fileURLWithPath: #file)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Sources/AgentDeck")

        let pattern = try NSRegularExpression(
            pattern: #"\bif[^\n]*agentKind\s*==\s*\.(codex|claudeCode)\b"#
        )

        var violations: [String] = []
        let enumerator = FileManager.default.enumerator(at: sourcesURL,
                                                       includingPropertiesForKeys: nil)!
        for case let url as URL in enumerator {
            guard url.pathExtension == "swift" else { continue }
            if Self.whitelist.contains(url.lastPathComponent) { continue }
            let content = try String(contentsOf: url)
            let range = NSRange(content.startIndex..., in: content)
            pattern.enumerateMatches(in: content, range: range) { match, _, _ in
                guard let m = match, let r = Range(m.range, in: content) else { return }
                violations.append("\(url.lastPathComponent): \(content[r])")
            }
        }
        XCTAssertTrue(violations.isEmpty, "vendor branch found:\n\(violations.joined(separator: "\n"))")
    }
}
