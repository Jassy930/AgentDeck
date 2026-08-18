import AgentDeckMobileCore
import Testing

@Suite("Conversation turns")
struct ConversationTurnTests {
    @Test("multiple user boundaries keep their assistant activity isolated")
    func multipleUserBoundariesKeepAssistantActivityIsolated() {
        let turns = makeConversationTurns(from: [
            UIItem(id: "u1", lifecycle: "completed", kind: "user", text: "find docs"),
            UIItem(id: "m1", lifecycle: "completed", kind: "message", text: "I will search."),
            UIItem(id: "w1", lifecycle: "completed", kind: "webSearch"),
            UIItem(id: "m2", lifecycle: "completed", kind: "message", text: "Result."),
            UIItem(id: "u2", lifecycle: "completed", kind: "user", text: "continue"),
            UIItem(id: "m3", lifecycle: "completed", kind: "message", text: "Next."),
        ])

        #expect(turns.count == 2)
        #expect(turns[0].user?.id == "u1")
        #expect(turns[0].assistantItems.map(\.id) == ["m1", "w1", "m2"])
        #expect(turns[1].user?.id == "u2")
        #expect(turns[1].assistantItems.map(\.id) == ["m3"])
    }

    @Test("navigation summaries normalize whitespace, truncate, and count attachments")
    func navigationSummariesNormalizeWhitespaceTruncateAndCountAttachments() {
        let longPrompt = "  first line\n\nsecond line with    extra spaces and enough text to be truncated after the summary limit keeps the rail compact  "
        let turns = makeConversationTurns(from: [
            UIItem(id: "intro", lifecycle: "completed", kind: "message", text: "orphan assistant"),
            {
                var user = UIItem(id: "u1", lifecycle: "completed", kind: "user", text: longPrompt)
                user.attachments = [
                    HistoryReference(
                        kind: "file",
                        text: nil,
                        url: nil,
                        path: "/tmp/a.swift",
                        name: "a.swift"
                    ),
                    HistoryReference(
                        kind: "url",
                        text: nil,
                        url: "https://example.com",
                        path: nil,
                        name: nil
                    ),
                ]
                return user
            }(),
            UIItem(id: "m1", lifecycle: "completed", kind: "message", text: "answer"),
            UIItem(id: "u2", lifecycle: "completed", kind: "user", text: "continue"),
        ])

        let items = makeConversationTurnNavigationItems(from: turns, summaryLimit: 40)

        #expect(items.map(\.turnId) == ["u1", "u2"])
        #expect(items.map(\.index) == [1, 2])
        #expect(items[0].summary == "first line second line with extra spa...")
        #expect(items[0].attachmentCount == 2)
        #expect(items[1].summary == "continue")
        #expect(items[1].attachmentCount == 0)
    }
}
