import XCTest
import AppKit
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

    func testRenderConversationStream() {
        let model = SessionModel(turnStarter: NoopRuntimeTurnStarter())
        model.cwd = URL(fileURLWithPath: "/p/refactor-auth")
        model.workbench.ensureRuntime(sessionId: "live-1", agentKind: .codex, threadId: nil, cwd: model.cwd!)
        let rt = model.workbench.runtime(sessionId: "live-1")!
        rt.items = [
            UIItem(id: "u1", lifecycle: "completed", kind: "user",
                   text: "把登录模块拆分成独立的 auth service，抽出 token 刷新逻辑，并补齐单元测试。"),
            UIItem(id: "r1", lifecycle: "completed", kind: "reasoning",
                   text: "先梳理 auth 目录下的依赖关系，确认哪些函数被外部引用，再决定拆分边界。"),
            UIItem(id: "m1", lifecycle: "completed", kind: "message",
                   text: "我会先分析依赖，再抽出 service，最后补测试。"),
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
