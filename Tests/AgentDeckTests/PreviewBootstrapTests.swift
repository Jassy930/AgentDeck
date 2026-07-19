import XCTest

@testable import AgentDeck

@MainActor
final class PreviewBootstrapTests: XCTestCase {
  func testPreviewModelHasEnvironmentInfoAndLoadsRuntimeCatalog() async throws {
    let model = PreviewBootstrap.makeSessionModel()
    defer { model.teardown() }

    XCTAssertEqual(model.environmentInfo?.branch, "main")
    model.loadHistory()

    for _ in 0..<200 {
      if !model.isLoadingHistory { break }
      try await Task.sleep(for: .milliseconds(5))
    }

    XCTAssertFalse(model.isLoadingHistory, "preview Runtime catalog 应在有界等待内完成加载")
    XCTAssertNil(model.historyErrorMessage)
    XCTAssertEqual(model.workbench.catalogEntries.count, MockDaemonScript.historyList().count)
    XCTAssertEqual(model.historyThreads.count, MockDaemonScript.historyList().count)
    XCTAssertFalse(model.historyGroups.isEmpty, "preview 应通过 Runtime v2 fixture 加载到 mock 历史")
  }

  func testPreviewPromptCompletesSyntheticRuntimeTurn() async throws {
    let model = PreviewBootstrap.makeSessionModel()
    defer { model.teardown() }
    model.cwd = URL(fileURLWithPath: MockDaemonScript.previewCwd)

    model.submit("preview prompt")

    for _ in 0..<400 {
      if let runtime = model.workbench.selectedRuntime,
        runtime.phase == .ready,
        runtime.items.contains(where: { $0.text == "preview prompt" }),
        runtime.items.contains(where: {
          $0.text == "Preview fixture 已完成这次 synthetic turn。"
        })
      {
        break
      }
      try await Task.sleep(for: .milliseconds(5))
    }

    XCTAssertNil(model.errorMessage)
    XCTAssertFalse(model.workbench.runtimeList.isEmpty)
    let runtime = try XCTUnwrap(model.workbench.selectedRuntime)
    XCTAssertEqual(runtime.phase, .ready)
    XCTAssertTrue(runtime.queuedPrompts.isEmpty)
    XCTAssertTrue(runtime.items.contains(where: { $0.text == "preview prompt" }))
    XCTAssertTrue(
      runtime.items.contains(where: {
        $0.text == "Preview fixture 已完成这次 synthetic turn。"
      })
    )
  }
}
