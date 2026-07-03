import Foundation
import Testing
import AgentDeckCore
@testable import AgentDeck

// A1: Unit coverage for the pure presentation helpers extracted from
// `SessionView`. These tests pin the user-visible strings produced for shell,
// tool-call, and web-search rows so a regression in label formatting fails
// here instead of requiring a manual UI sweep. SwiftUI is intentionally not
// imported — if a future change reaches for `@State` or `self.model`, this
// suite stops compiling, which is the signal the helper is no longer pure.

private func makeItem(
    id: String = "x",
    kind: String = "tool",
    lifecycle: String = "completed"
) -> UIItem {
    UIItem(id: id, lifecycle: lifecycle, kind: kind)
}

@Suite("ToolPresentation.outputLabel")
struct ToolPresentationOutputLabelTests {

    @Test("empty text collapses to 'Show output'")
    func emptyTextCollapsesToShowOutput() {
        #expect(ToolPresentation.outputLabel("") == "Show output")
    }

    @Test("single line text collapses to 'Show output'")
    func singleLineTextCollapsesToShowOutput() {
        #expect(ToolPresentation.outputLabel("hello") == "Show output")
    }

    @Test("multi-line text reports line count")
    func multiLineTextReportsLineCount() {
        // Three newline-separated rows → 3 lines (omittingEmptySubsequences is false
        // so a trailing newline still adds a row, which matches what users see).
        #expect(ToolPresentation.outputLabel("a\nb\nc") == "Show output (3 lines)")
    }

    @Test("custom noun is threaded into label")
    func customNounIsThreadedIntoLabel() {
        #expect(ToolPresentation.outputLabel("a\nb", noun: "diff") == "Show diff (2 lines)")
    }
}

@Suite("ToolPresentation.webSearchTitle")
struct ToolPresentationWebSearchTitleTests {

    @Test("empty action falls back to 'Web search'")
    func emptyActionFallsBackToWebSearch() {
        var item = makeItem(kind: "webSearch")
        item.action = ""
        #expect(ToolPresentation.webSearchTitle(item) == "Web search")
    }

    @Test("known action 'openPage' maps to 'Open web page'")
    func openPageMapsToOpenWebPage() {
        var item = makeItem(kind: "webSearch")
        item.action = "openPage"
        #expect(ToolPresentation.webSearchTitle(item) == "Open web page")
    }

    @Test("unknown action is appended after dot separator")
    func unknownActionIsAppendedAfterDotSeparator() {
        var item = makeItem(kind: "webSearch")
        item.action = "crawl"
        #expect(ToolPresentation.webSearchTitle(item) == "Web search · crawl")
    }
}

@Suite("ToolPresentation.shellMetadata")
struct ToolPresentationShellMetadataTests {

    @Test("all-empty item yields empty parts")
    func allEmptyItemYieldsEmptyParts() {
        let item = makeItem(kind: "shell")
        #expect(ToolPresentation.shellMetadata(item) == [])
    }

    @Test("populated fields ordered: status, cwd, duration, source, pid")
    func populatedFieldsOrderedStatusCwdDurationSourcePid() {
        var item = makeItem(kind: "shell")
        item.statusName = "running"
        item.cwdText = "/tmp/x"
        item.durationMs = 42
        item.sourceName = "codex"
        item.processId = "1234"
        #expect(
            ToolPresentation.shellMetadata(item)
                == ["running", "/tmp/x", "42ms", "codex", "pid 1234"]
        )
    }

    @Test("missing duration drops the ms entry without leaving a hole")
    func missingDurationDropsMsEntry() {
        var item = makeItem(kind: "shell")
        item.statusName = "done"
        item.durationMs = nil
        item.sourceName = "codex"
        #expect(ToolPresentation.shellMetadata(item) == ["done", "codex"])
    }
}

@Suite("ToolPresentation.toolName")
struct ToolPresentationToolNameTests {

    @Test("server prefix wins when both server and namespace are set")
    func serverPrefixWinsOverNamespace() {
        var item = makeItem()
        item.server = "fs"
        item.namespace = "ns"
        item.tool = "read"
        #expect(ToolPresentation.toolName(item) == "fs/read")
    }

    @Test("namespace is used when server is empty")
    func namespaceUsedWhenServerEmpty() {
        var item = makeItem()
        item.server = ""
        item.namespace = "ns"
        item.tool = "read"
        #expect(ToolPresentation.toolName(item) == "ns/read")
    }

    @Test("bare tool name when no scope is present")
    func bareToolNameWhenNoScopePresent() {
        var item = makeItem()
        item.tool = "read"
        #expect(ToolPresentation.toolName(item) == "read")
    }
}

@Suite("ToolPresentation.toolMetadata")
struct ToolPresentationToolMetadataTests {

    @Test("success=true emits literal 'success'")
    func successTrueEmitsLiteralSuccess() {
        var item = makeItem()
        item.success = true
        item.durationMs = 7
        // statusName empty → leading slot is skipped, no leading empty string.
        #expect(ToolPresentation.toolMetadata(item) == ["success", "7ms"])
    }

    @Test("success=false emits 'failed' and includes resourceUri tail")
    func successFalseEmitsFailedAndIncludesResourceUriTail() {
        var item = makeItem()
        item.statusName = "completed"
        item.success = false
        item.durationMs = 12
        item.resourceUri = "file:///x"
        #expect(
            ToolPresentation.toolMetadata(item)
                == ["completed", "failed", "12ms", "file:///x"]
        )
    }

    @Test("nil success is omitted entirely")
    func nilSuccessIsOmittedEntirely() {
        var item = makeItem()
        item.statusName = "running"
        item.success = nil
        #expect(ToolPresentation.toolMetadata(item) == ["running"])
    }
}
