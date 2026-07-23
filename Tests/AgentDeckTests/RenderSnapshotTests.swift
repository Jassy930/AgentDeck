import XCTest
import AppKit
import AgentDeckCore
@testable import AgentDeck

/// 把"有数据"的界面渲染成 PNG（/tmp），供人工核对真实呈现。
/// 用假 turnStarter，无需真 daemon、无副作用。
@MainActor
final class RenderSnapshotTests: XCTestCase {

    func testRenderHeader() {
        let model = SessionModel(turnStarter: NoopRuntimeTurnStarter())
        model.cwd = URL(fileURLWithPath: "/Users/jassy/glm/AgentDeck")
        model.submit("把登录模块拆分为独立 service，抽出 token 刷新逻辑，并补齐单元测试。")
        let header = CodexContentHeaderView(model: model)
        header.wantsLayer = true
        header.frame = NSRect(x: 0, y: 0, width: 1100, height: 44)
        header.layoutSubtreeIfNeeded()
        header.renderPNG(to: "/tmp/adk-header.png")
    }

    func testRenderComposer() {
        let model = SessionModel(turnStarter: NoopRuntimeTurnStarter())
        model.cwd = URL(fileURLWithPath: "/p/refactor-auth")
        let bar = InputBarView(model: model)
        bar.wantsLayer = true
        bar.layer?.backgroundColor = DesignTokens.bg.cgColor
        bar.frame = NSRect(x: 0, y: 0, width: 720, height: 96)
        bar.layoutSubtreeIfNeeded()
        bar.renderPNG(to: "/tmp/adk-composer.png")
    }

    func testRenderToolCallCollapsed() {
        let model = SessionModel(turnStarter: NoopRuntimeTurnStarter())
        var item = UIItem(id: "tc1", lifecycle: "completed", kind: "toolCall")
        item.tool = "Read"
        item.statusName = "completed"
        item.success = true
        item.arguments = "{\"file_path\":\"/repo/Sources/AgentDeck/ConversationRowViews.swift\"}"
        let row = ConversationDisplayRow(role: .assistantItem, turnId: "t", item: item,
                                         firstInTurn: true, lastInTurn: true)
        let cell = ToolCallCellView()
        cell.wantsLayer = true
        cell.layer?.backgroundColor = DesignTokens.bg.cgColor
        let w: CGFloat = 620
        let h = ConversationRowFactory.height(for: row, width: w) + 6
        cell.translatesAutoresizingMaskIntoConstraints = false
        cell.widthAnchor.constraint(equalToConstant: w).isActive = true
        cell.heightAnchor.constraint(equalToConstant: h).isActive = true
        cell.configure(row: row, width: w, model: model)
        cell.layoutSubtreeIfNeeded()
        cell.renderPNG(to: "/tmp/adk-toolcall.png")
    }

    func testRenderToolCallExpanded() {
        final class AlwaysExpanded: ConversationDisclosureStateStore {
            func isItemExpanded(_ itemId: String) -> Bool { true }
            func setItem(_ itemId: String, expanded: Bool) {}
        }
        let model = SessionModel(turnStarter: NoopRuntimeTurnStarter())
        var item = UIItem(id: "tc2", lifecycle: "completed", kind: "toolCall")
        item.tool = "Grep"
        item.statusName = "completed"
        item.arguments = "{\"pattern\":\"ToolCallCellView\",\"path\":\"/repo/Sources\"}"
        let row = ConversationDisplayRow(role: .assistantItem, turnId: "t", item: item,
                                         firstInTurn: true, lastInTurn: true)
        let store = AlwaysExpanded()
        let cell = ToolCallCellView()
        cell.disclosureStore = store
        cell.wantsLayer = true
        cell.layer?.backgroundColor = DesignTokens.bg.cgColor
        cell.translatesAutoresizingMaskIntoConstraints = false
        cell.widthAnchor.constraint(equalToConstant: 620).isActive = true
        cell.heightAnchor.constraint(equalToConstant: 220).isActive = true
        cell.configure(row: row, width: 620, model: model)
        cell.layoutSubtreeIfNeeded()
        cell.renderPNG(to: "/tmp/adk-toolcall-expanded.png")
    }

    func testRenderReasoningTypography() {
        final class AlwaysExpanded: ConversationDisclosureStateStore {
            func isItemExpanded(_ itemId: String) -> Bool { true }
            func setItem(_ itemId: String, expanded: Bool) {}
        }

        let model = SessionModel(turnStarter: NoopRuntimeTurnStarter())
        let item = UIItem(
            id: "reasoning-typography",
            lifecycle: "completed",
            kind: "reasoning",
            text: "**Inspecting typography tokens**\n先梳理中文正文的行高，再核对 Latin paragraph spacing."
        )
        item.textBuffer.replace(with: item.text)
        let row = ConversationDisplayRow(
            role: .assistantItem,
            turnId: "turn-reasoning-typography",
            item: item,
            firstInTurn: true,
            lastInTurn: true
        )
        let cell = ReasoningCellView()
        let store = AlwaysExpanded()
        cell.disclosureStore = store
        cell.wantsLayer = true
        cell.layer?.backgroundColor = DesignTokens.bg.cgColor
        cell.translatesAutoresizingMaskIntoConstraints = false
        cell.widthAnchor.constraint(equalToConstant: 620).isActive = true
        cell.heightAnchor.constraint(equalToConstant: 150).isActive = true
        cell.configure(row: row, width: 620, model: model)
        cell.layoutSubtreeIfNeeded()
        cell.renderPNG(to: "/tmp/adk-reasoning-typography.png")
    }

    func testRenderMarkdownBlocks() {
        let model = SessionModel(turnStarter: NoopRuntimeTurnStarter())
        let markdown = """
        ## 当前执行状态

        已核对 `agentdeck-relay/src/{bridge,router,store}.rs` 的实现。

        - 已完成结构检查
        - 正在运行回归测试

        ```swift
        let state = "running"
        ```
        """
        let item = UIItem(
            id: "message-markdown-blocks",
            lifecycle: "completed",
            kind: "message",
            text: markdown
        )
        item.textBuffer.replace(with: markdown)
        let row = ConversationDisplayRow(
            role: .assistantItem,
            turnId: "turn-markdown-blocks",
            item: item,
            firstInTurn: true,
            lastInTurn: true
        )
        let cell = MessageCellView()
        cell.wantsLayer = true
        cell.layer?.backgroundColor = DesignTokens.bg.cgColor
        let width: CGFloat = 620
        let height = ConversationRowFactory.height(for: row, width: width) + 12
        cell.translatesAutoresizingMaskIntoConstraints = false
        cell.widthAnchor.constraint(equalToConstant: width).isActive = true
        cell.heightAnchor.constraint(equalToConstant: height).isActive = true
        cell.configure(row: row, width: width, model: model)
        cell.layoutSubtreeIfNeeded()
        let streaming = cell.firstDescendant(ofType: StreamingTextContainerView.self)
        XCTAssertEqual(streaming?.currentText, MarkdownAttributedStringBuilder.attributedString(from: markdown).string)
        streaming?.layoutSubtreeIfNeeded()
        cell.renderPNG(to: "/tmp/adk-markdown-blocks.png")
    }

    func testRenderConversationStream() {
        let model = SessionModel(turnStarter: NoopRuntimeTurnStarter())
        model.cwd = URL(fileURLWithPath: "/p/refactor-auth")
        model.workbench.ensureRuntime(sessionId: "live-1", agentKind: .codex, threadId: nil, cwd: model.cwd!)
        let rt = model.workbench.runtime(sessionId: "live-1")!
        var tool = UIItem(id: "tc1", lifecycle: "completed", kind: "toolCall")
        tool.tool = "TaskCreate"
        tool.arguments = "{\"activeForm\":\"收录厂家摄像头资料\",\"subject\":\"收录厂家参数\",\"description\":\"把资料收进当前仓库\"}"
        rt.items = [
            // CLI 命令元数据噪声（应被过滤，不出现在流里）
            UIItem(id: "c0", lifecycle: "completed", kind: "user",
                   text: "<local-command-caveat>Caveat: messages below were generated by local commands. DO NOT respond…</local-command-caveat>"),
            UIItem(id: "c1", lifecycle: "completed", kind: "user",
                   text: "<command-name>/clear</command-name><command-message>clear</command-message><command-args></command-args>"),
            UIItem(id: "u1", lifecycle: "completed", kind: "user",
                   text: "把登录模块拆分成独立的 auth service，抽出 token 刷新逻辑，并补齐单元测试。"),
            UIItem(id: "r1", lifecycle: "completed", kind: "reasoning",
                   text: "先梳理 auth 目录下的依赖关系，确认哪些函数被外部引用，再决定拆分边界。"),
            UIItem(id: "m1", lifecycle: "completed", kind: "message",
                   text: "我会先分析依赖，再抽出 service，最后补测试。"),
            tool,
        ]
        model.workbench.selectRuntime(sessionId: "live-1")

        let vc = ConversationViewController(model: model)
        let v = vc.view
        v.frame = NSRect(x: 0, y: 0, width: 900, height: 640)
        v.layoutSubtreeIfNeeded()
        v.renderPNG(to: "/tmp/adk-stream.png")
    }

    func testRenderFullSessionWindow() {
        let model = SessionModel(turnStarter: NoopRuntimeTurnStarter())
        model.cwd = URL(fileURLWithPath: "/p/refactor-auth")
        // 造一个 live 运行时 + 一条用户消息（submit 会 append 用户气泡并置 starting）
        model.submit("把登录模块拆分成独立的 auth service，抽出 token 刷新逻辑，并补齐单元测试。")

        let vc = SessionViewController(model: model)
        let v = vc.view
        v.frame = NSRect(x: 0, y: 0, width: 1280, height: 760)
        v.layoutSubtreeIfNeeded()
        v.renderPNG(to: "/tmp/adk-session.png")
    }
}
