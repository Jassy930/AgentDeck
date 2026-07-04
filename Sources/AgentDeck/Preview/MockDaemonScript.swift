import Foundation
import AgentDeckCore

/// preview 模式的 mock 数据源，复刻设计稿图1。仅被 preview 路径引用。
enum MockDaemonScript {
    static let previewCwd = "/Users/preview/glm/AgentDeck"
    static let primaryThreadId = "mock-thread-split-auth"
    static let environmentInfo = EnvironmentInfo(
        added: 128, removed: 34, fileCount: 3, branch: "main", commit: "a1b2c3d"
    )

    private static func meta() -> AgentItemMeta { AgentItemMeta() }

    static func historyList() -> [HistoryListItem] {
        let now: UInt64 = 1_720_000_000_000
        func item(_ id: String, _ title: String, _ cwd: String, _ ageMs: UInt64) -> HistoryListItem {
            HistoryListItem(threadId: id, agentKind: .codex, title: title, cwd: cwd,
                            lastActiveMs: now - ageMs, archived: false)
        }
        let refactor = previewCwd
        let docs = "/Users/preview/glm/agentdeck-docs"
        return [
            item(primaryThreadId, "把登录模块拆分为独立 service", refactor, 0),
            item("mock-thread-token-race", "修复 token 刷新竞态", refactor, 60_000),
            item("mock-thread-deploy-doc", "补充部署章节", docs, 120_000),
        ]
    }

    static func readResponse(threadId: String) -> HistoryReadResponse {
        HistoryReadResponse(threadId: threadId, agentKind: .codex, turns: [
            HistoryTurn(items: [
                .userMessage(text: "把登录模块拆分成独立的 auth service，抽出 token 刷新逻辑，并补齐单元测试。", meta: meta()),
                .reasoning(text: "先梳理 auth 目录下的依赖关系，确认哪些函数被外部引用，再决定拆分边界。", meta: meta()),
                .shell(command: "rg \"login\" src/ -l",
                       status: .completed, exitCode: 0, durationMs: 40, meta: meta()),
                .diff(files: [DiffFile(path: "auth/service.ts", status: .modified,
                                       patch: "@@ +64 -12 @@\n+ export class AuthService {}\n")],
                      meta: meta()),
                .assistantMessage(text: "正在运行测试 npm test -- auth …", meta: meta()),
            ]),
        ])
    }

    static func liveTurnEvents(sessionId: String, threadId: String) -> [ServerEvent] {
        [
            .sessionStarted(sessionId: sessionId, threadId: threadId, agentKind: .codex),
            .agentItem(sessionId: sessionId, threadId: threadId, agentKind: .codex,
                       item: .reasoning(text: "收到，我先跑一遍现有测试确认基线。", meta: meta())),
            .agentItem(sessionId: sessionId, threadId: threadId, agentKind: .codex,
                       item: .shell(command: "npm test -- auth", status: .completed, exitCode: 0, durationMs: 1200, meta: meta())),
            .agentItem(sessionId: sessionId, threadId: threadId, agentKind: .codex,
                       item: .assistantMessage(text: "测试通过，auth service 已拆分完成。", meta: meta())),
            .turnComplete(sessionId: sessionId, threadId: threadId, agentKind: .codex,
                          summary: TurnSummary(elapsedMs: 1500)),
        ]
    }
}
