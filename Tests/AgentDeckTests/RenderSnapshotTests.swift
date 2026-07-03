import XCTest
import AppKit
@testable import AgentDeck

/// 把"有数据"的界面渲染成 PNG（/tmp），供人工核对真实呈现。
/// 用假 turnStarter，无需真 daemon、无副作用。
@MainActor
final class RenderSnapshotTests: XCTestCase {

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
