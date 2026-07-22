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

    @Test("empty generic tool name has a readable fallback")
    func emptyGenericToolNameHasReadableFallback() {
        let item = makeItem()
        #expect(ToolPresentation.toolName(item) == "Tool")
    }
}

@Suite("ToolPresentation.toolContextSummary")
struct ToolPresentationToolContextSummaryTests {

    @Test("Read file_path is surfaced in the collapsed summary")
    func readFilePathIsSurfaced() {
        var item = makeItem()
        item.tool = "Read"
        item.arguments = #"{"file_path":"/tmp/first.swift","limit":200}"#
        #expect(ToolPresentation.toolContextSummary(item) == "path: /tmp/first.swift")
    }

    @Test("consecutive Read calls expose different paths")
    func consecutiveReadsExposeDifferentPaths() {
        var first = makeItem(id: "read-1")
        first.tool = "Read"
        first.arguments = #"{"file_path":"/repo/First.swift"}"#
        var second = makeItem(id: "read-2")
        second.tool = "Read"
        second.arguments = #"{"file_path":"/repo/Second.swift"}"#

        #expect(ToolPresentation.toolContextSummary(first) == "path: /repo/First.swift")
        #expect(ToolPresentation.toolContextSummary(second) == "path: /repo/Second.swift")
        #expect(
            ToolPresentation.toolContextSummary(first)
                != ToolPresentation.toolContextSummary(second)
        )
    }

    @Test("query and path are both retained so adjacent searches are identifiable")
    func queryAndPathAreBothRetained() {
        var item = makeItem()
        item.tool = "Grep"
        item.arguments = #"{"pattern":"ToolCallCellView","path":"/repo/Sources"}"#
        #expect(
            ToolPresentation.toolContextSummary(item)
                == "query: ToolCallCellView · path: /repo/Sources"
        )
    }

    @Test("node_repl title makes adjacent generic js calls identifiable")
    func nodeReplTitleIsSurfaced() {
        var item = makeItem()
        item.server = "node_repl"
        item.tool = "js"
        item.arguments = #"{"code":"...","title":"确认 AgentDeck 窗口","timeout_ms":30000}"#
        #expect(ToolPresentation.toolContextSummary(item) == "确认 AgentDeck 窗口")
    }

    @Test("resource URI is a fallback when arguments have no target")
    func resourceUriFallback() {
        var item = makeItem()
        item.arguments = #"{"limit":20}"#
        item.resourceUri = "file:///tmp/resource.txt"
        #expect(
            ToolPresentation.toolContextSummary(item)
                == "path: file:///tmp/resource.txt"
        )
    }

    @Test("non-target task arguments stay out of the compact summary")
    func nonTargetArgumentsStayOut() {
        var item = makeItem()
        item.tool = "TaskCreate"
        item.arguments = #"{"subject":"收录厂家参数","description":"完整说明"}"#
        #expect(ToolPresentation.toolContextSummary(item).isEmpty)
    }
}

@Suite("ToolPresentation.toolStatus")
struct ToolPresentationToolStatusTests {

    @Test("explicit failure wins over a stale completed status")
    func explicitFailureWins() {
        var item = makeItem()
        item.statusName = "completed"
        item.success = false
        #expect(ToolPresentation.toolStatus(item) == "failed")
    }

    @Test("result implies completed when no explicit status exists")
    func resultImpliesCompleted() {
        var item = makeItem(lifecycle: "running")
        item.result = #"{"ok":true}"#
        #expect(ToolPresentation.toolStatus(item) == "completed")
    }

    @Test("legacy lifecycle remains the final fallback")
    func lifecycleFallback() {
        let item = makeItem(lifecycle: "running")
        #expect(ToolPresentation.toolStatus(item) == "running")
    }

    @Test("collapsed status is localized and includes a compact duration")
    func localizedStatusIncludesDuration() {
        var item = makeItem()
        item.statusName = "completed"
        item.durationMs = 1_449
        #expect(ToolPresentation.toolStatusSummary(item) == "已完成 · 1.4s")
    }

    @Test("official inProgress status remains visibly active")
    func camelCaseInProgressIsLocalized() {
        var item = makeItem()
        item.statusName = "inProgress"
        #expect(ToolPresentation.toolStatusSummary(item) == "进行中")
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
