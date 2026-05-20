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
        _ = CodexDocumentSection(buffer: buffer)
    }
}
