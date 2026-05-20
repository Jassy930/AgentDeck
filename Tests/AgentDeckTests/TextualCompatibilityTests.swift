import Testing
import Textual
@testable import AgentDeck

@Suite("Textual compatibility")
struct TextualCompatibilityTests {
    @MainActor
    @Test("StructuredText accepts markdown with code block and table")
    func structuredTextAcceptsMarkdownBlocks() {
        let markdown = """
        ## Result

        ```swift
        let value = 42
        ```

        | Name | Count |
        | --- | ---: |
        | Build | 12 |
        """

        _ = StructuredText(markdown: markdown)
    }

    @MainActor
    @Test("rich message view stores raw markdown for Textual rendering")
    func richMessageViewStoresRawMarkdown() {
        let state = RichMessageRenderState()

        state.replace("## Result")

        #expect(state.markdown == "## Result")
    }

    @MainActor
    @Test("rich message view can be created from streaming buffer")
    func richMessageViewCanBeCreatedFromStreamingBuffer() {
        let buffer = StreamingTextBuffer()

        _ = RichMessageView(buffer: buffer)
    }

    @MainActor
    @Test("document reader role views can be created")
    func documentReaderRoleViewsCanBeCreated() {
        let buffer = StreamingTextBuffer()

        _ = UserPromptBlock(text: "Summarize the plan")
        _ = CodexTurnSection {
            RichMessageView(buffer: buffer)
        }
    }

    @Test("conversation turns keep assistant tool activity under one Codex rail")
    func conversationTurnsKeepAssistantActivityTogether() {
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
}
