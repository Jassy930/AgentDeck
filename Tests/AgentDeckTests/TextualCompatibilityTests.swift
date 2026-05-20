import Testing
import Textual

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
}
