import Foundation
import XCTest

final class ProtocolConformanceTests: XCTestCase {
    private func loadSchema() throws -> [String: Any] {
        let repoRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()   // AgentDeckMobileCoreTests/
            .deletingLastPathComponent()   // Tests/
            .deletingLastPathComponent()   // <repo>/
        let url = repoRoot
            .appendingPathComponent("protocol")
            .appendingPathComponent("agentdeck")
            .appendingPathComponent("agentdeck-protocol.schema.json")
        let data = try Data(contentsOf: url)
        let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        return json ?? [:]
    }

    /// v2 protocol uses internally-tagged `AgentItem` definition. Verify
    /// every wire `kind` discriminator is something Swift's AgentItem can
    /// decode (mirrors the cases in AgentItem.init(from:)).
    func testAgentItemKindTagsAreAllHandledBySwift() throws {
        let schema = try loadSchema()
        // v2 schema inlines AgentItem under the property tree (schemars
        // serializes types per top-level property, so nested defs land
        // under whichever property first references them). Search recursively
        // for an `AgentItem` block carrying a oneOf/anyOf of `kind` variants.
        let agentItemSchema = findAgentItemDefinition(in: schema) ?? [:]
        let tags = AgentItemKindTagExtractor.tags(from: agentItemSchema)
        XCTAssertFalse(tags.isEmpty, "schema did not parse out any AgentItem kind tags")

        // v2 Swift-side known kinds (AgentItem cases).
        let known: Set<String> = [
            "userMessage", "assistantMessage", "reasoning", "shell", "diff",
            "plan", "imageReference", "toolCall", "raw",
        ]
        let missing = tags.subtracting(known)
        XCTAssertTrue(missing.isEmpty, "schema added unhandled AgentItem kinds: \(missing.sorted())")
    }

    private func findAgentItemDefinition(in node: Any) -> [String: Any]? {
        if let dict = node as? [String: Any] {
            if let nested = dict["definitions"] as? [String: Any],
               let ai = nested["AgentItem"] as? [String: Any],
               (ai["oneOf"] != nil || ai["anyOf"] != nil) {
                return ai
            }
            for (_, v) in dict {
                if let found = findAgentItemDefinition(in: v) {
                    return found
                }
            }
        } else if let arr = node as? [Any] {
            for v in arr {
                if let found = findAgentItemDefinition(in: v) {
                    return found
                }
            }
        }
        return nil
    }
}

enum AgentItemKindTagExtractor {
    /// Schemars 0.8 internally-tagged enum shape: `oneOf` with each branch
    /// providing `properties.kind.{enum|const}`.
    static func tags(from kindSchema: [String: Any]) -> Set<String> {
        var out = Set<String>()
        let branches = (kindSchema["oneOf"] as? [[String: Any]])
            ?? (kindSchema["anyOf"] as? [[String: Any]])
            ?? []
        for branch in branches {
            guard let props = branch["properties"] as? [String: Any],
                  let kind = props["kind"] as? [String: Any] else { continue }
            if let e = kind["enum"] as? [String] { out.formUnion(e) }
            if let c = kind["const"] as? String { out.insert(c) }
        }
        return out
    }
}
