import XCTest
@testable import AgentDeck

final class ProtocolConformanceTests: XCTestCase {
    /// 读取仓库内协议 schema（子项目 1 提交的生成产物）。
    private func loadSchema() throws -> [String: Any] {
        // 用 #file 推导仓库根，避免依赖测试运行时的 CWD：
        // <repo>/Tests/AgentDeckTests/ProtocolConformanceTests.swift → 向上 3 级即仓库根。
        let repoRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()   // AgentDeckTests/
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

    /// schema 的 definitions.AgentItemKind 列出的 kind 标签，必须都是 Swift 侧
    /// 已知能渲染的 kind（与 SessionView 行分发 / AgentItemReducer 对齐）。
    func testAgentItemKindTagsAreAllHandledBySwift() throws {
        let schema = try loadSchema()
        let defs = schema["definitions"] as? [String: Any] ?? [:]
        let kindSchema = defs["AgentItemKind"] as? [String: Any] ?? [:]
        let tags = AgentItemKindTagExtractor.tags(from: kindSchema)
        XCTAssertFalse(tags.isEmpty, "schema 未解析出 AgentItemKind 标签")

        // Swift 侧已知 kind（事实源：行分发 switch / reducer）。
        let known: Set<String> = [
            "user", "message", "reasoning", "shell", "fileEdit", "webSearch",
            "plan", "hookPrompt", "toolCall", "collabAgentToolCall", "media",
            "reviewMode", "contextCompaction", "raw",
        ]
        let missing = tags.subtracting(known)
        XCTAssertTrue(missing.isEmpty, "契约新增了 Swift 未处理的 AgentItem kind: \(missing.sorted())")
    }
}

// MARK: - Schema 标签抽取助手

enum AgentItemKindTagExtractor {
    /// 从 AgentItemKind 的 JSON Schema 片段里抽出所有 kind 标签字符串。
    /// 兼容 schemars 0.8 的内部 tag 枚举形态：oneOf -> 每支 properties.kind.{enum|const}。
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
