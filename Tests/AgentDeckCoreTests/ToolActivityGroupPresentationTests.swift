import AgentDeckCore
import XCTest

final class ToolActivityGroupPresentationTests: XCTestCase {
    private func tool(
        _ id: String,
        name: String,
        status: String = "completed",
        durationMs: Int? = nil,
        arguments: String = ""
    ) -> UIItem {
        var item = UIItem(id: id, lifecycle: "completed", kind: "toolCall")
        item.tool = name
        item.statusName = status
        item.durationMs = durationMs
        item.arguments = arguments
        return item
    }

    func testSummaryDescribesMixedReadAndCommandWork() {
        let read = tool("read", name: "Read")
        var firstCommand = UIItem(id: "shell-1", lifecycle: "completed", kind: "shell")
        firstCommand.statusName = "completed"
        var secondCommand = firstCommand
        secondCommand.id = "shell-2"

        XCTAssertEqual(
            ToolActivityGroupPresentation.summary([read, firstCommand, secondCommand]),
            "已读取 1 个文件并运行 2 个命令"
        )
        XCTAssertEqual(
            ToolActivityGroupPresentation.primaryCategory(in: [read, firstCommand]),
            .mixed
        )
    }

    func testGenericToolsKeepOneConcreteOperationTitle() {
        let first = tool(
            "js-1",
            name: "js",
            arguments: #"{"title":"确认 AgentDeck 窗口"}"#
        )
        let second = tool("js-2", name: "js")

        XCTAssertEqual(
            ToolActivityGroupPresentation.summary([first, second]),
            "已执行 2 项工具操作：确认 AgentDeck 窗口等"
        )
    }

    func testRunningGenericToolsPreferLatestActiveOperationTitle() {
        let completed = tool(
            "js-1",
            name: "js",
            arguments: #"{"title":"读取旧窗口"}"#
        )
        let running = tool(
            "js-2",
            name: "js",
            status: "running",
            arguments: #"{"title":"检查当前会话"}"#
        )

        XCTAssertEqual(
            ToolActivityGroupPresentation.summary([completed, running]),
            "正在执行 2 项工具操作：检查当前会话等"
        )
    }

    func testToolCategoryMatchingDoesNotTreatThreadAsRead() {
        let thread = tool("thread", name: "create_thread")
        let ripgrep = tool("rg", name: "rg")

        XCTAssertEqual(ToolActivityGroupPresentation.category(for: thread), .tool)
        XCTAssertEqual(ToolActivityGroupPresentation.category(for: ripgrep), .search)
    }

    func testFailureDominatesRunningAndRemainsVisible() {
        var failed = tool("failed", name: "Read", status: "failed")
        failed.errorText = "permission denied"
        let running = tool("running", name: "Read", status: "running")

        XCTAssertEqual(
            ToolActivityGroupPresentation.summary([failed, running]),
            "读取 2 个文件"
        )
        XCTAssertEqual(
            ToolActivityGroupPresentation.semanticStatus([failed, running]),
            "failed"
        )
        XCTAssertEqual(
            ToolActivityGroupPresentation.statusSummary([failed, running]),
            "1 项失败"
        )
    }

    func testCompletedDurationsAreSummedOnlyWhenEveryActivityHasOne() {
        let first = tool("first", name: "Read", durationMs: 400)
        let second = tool("second", name: "Read", durationMs: 750)

        XCTAssertEqual(
            ToolActivityGroupPresentation.statusSummary([first, second]),
            "1.1s"
        )
    }

    func testFileEditDoesNotInventCompletedGroupStatus() {
        var edit = UIItem(id: "edit", lifecycle: "completed", kind: "fileEdit")
        edit.statusName = "modified"
        let read = tool("read", name: "Read")

        XCTAssertEqual(
            ToolActivityGroupPresentation.summary([edit, read]),
            "修改 1 个文件并读取 1 个文件"
        )
        XCTAssertEqual(ToolActivityGroupPresentation.semanticStatus([edit, read]), "")
        XCTAssertEqual(ToolActivityGroupPresentation.statusSummary([edit, read]), "")
    }

    func testFileEditSummaryCountsFilesInsideOneDiffActivity() {
        var edit = UIItem(id: "multi-edit", lifecycle: "completed", kind: "fileEdit")
        edit.changes = [
            HistoryFileChange(path: "Sources/A.swift", diff: "", changeKind: "modified"),
            HistoryFileChange(path: "Sources/B.swift", diff: "", changeKind: "modified"),
            HistoryFileChange(path: "Tests/ATests.swift", diff: "", changeKind: "modified"),
        ]
        let read = tool("read-after-edit", name: "Read", status: "completed")

        XCTAssertEqual(
            ToolActivityGroupPresentation.summary([edit, read]),
            "修改 3 个文件并读取 1 个文件"
        )
        XCTAssertEqual(
            ToolActivityGroupPresentation.statusSummary([edit, read]),
            ""
        )
    }

    func testRunningSummaryUsesPresentProgressiveTense() {
        let completed = tool("completed", name: "Read")
        let running = tool("running", name: "Read", status: "running")

        XCTAssertEqual(
            ToolActivityGroupPresentation.summary([completed, running]),
            "正在读取 2 个文件"
        )
        XCTAssertEqual(
            ToolActivityGroupPresentation.statusSummary([completed, running]),
            "进行中"
        )
    }

    func testMediaAndCollaborationControlsRemainNonGroupableBoundaries() {
        let media = UIItem(id: "media", lifecycle: "completed", kind: "media")
        let collab = UIItem(
            id: "collab",
            lifecycle: "completed",
            kind: "collabAgentToolCall"
        )
        var loweredCollab = UIItem(
            id: "lowered-collab",
            lifecycle: "completed",
            kind: "toolCall"
        )
        loweredCollab.server = "collaboration"
        loweredCollab.tool = "spawn_agent"
        var neutralCollab = UIItem(
            id: "neutral-collab",
            lifecycle: "completed",
            kind: "toolCall"
        )
        neutralCollab.activityKind = "collaboration"
        neutralCollab.tool = "spawnAgent"

        XCTAssertFalse(ToolActivityGroupPresentation.isGroupable(media))
        XCTAssertFalse(ToolActivityGroupPresentation.isGroupable(collab))
        XCTAssertFalse(ToolActivityGroupPresentation.isGroupable(loweredCollab))
        XCTAssertFalse(ToolActivityGroupPresentation.isGroupable(neutralCollab))
    }

    func testSameTaskCollaborationEventsHaveDedicatedGroupPresentation() {
        var started = UIItem(id: "started", lifecycle: "completed", kind: "toolCall")
        started.tool = "B3a2a implement"
        started.activityKind = "collaboration"
        started.activityEvent = "started"
        var updated = started
        updated.id = "updated"
        updated.activityEvent = "interacted"

        XCTAssertTrue(ToolActivityGroupPresentation.isGroupable(started))
        XCTAssertEqual(
            ToolActivityGroupPresentation.groupingKey(for: started),
            .collaboration(taskName: "b3a2a implement")
        )
        XCTAssertEqual(
            ToolActivityGroupPresentation.summary([started, updated]),
            "B3a2a implement · 2 条协作动态"
        )
        XCTAssertEqual(ToolActivityGroupPresentation.statusSummary([started, updated]), "已更新")
        XCTAssertEqual(ToolActivityGroupPresentation.semanticStatus([started, updated]), "interacted")
        XCTAssertEqual(
            ToolActivityGroupPresentation.primaryCategory(in: [started, updated]),
            .collaboration
        )
    }

    func testDifferentCollaborationTasksHaveDifferentGroupKeys() {
        var implementation = UIItem(
            id: "implementation", lifecycle: "completed", kind: "toolCall"
        )
        implementation.tool = "B3a2a implement"
        implementation.activityKind = "collaboration"
        implementation.activityEvent = "interacted"
        var audit = implementation
        audit.id = "audit"
        audit.tool = "Relay plan audit"

        XCTAssertNotEqual(
            ToolActivityGroupPresentation.groupingKey(for: implementation),
            ToolActivityGroupPresentation.groupingKey(for: audit)
        )
    }
}
