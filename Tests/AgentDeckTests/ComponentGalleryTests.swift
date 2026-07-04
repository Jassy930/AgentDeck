import XCTest
import AppKit
import AgentDeckCore
@testable import AgentDeck

/// 组件画廊结构断言（Phase 0/1 视觉保真门禁）。
///
/// 对 `GalleryBootstrap.specimens()` 渲染出的**真实组件**遍历视图树断言，渲染器无关、
/// 稳定。这些断言把本次修复的对齐结论编码成回归——正是之前漏网的那类偏差：
/// 用户气泡多了「You」标签/橙边条、环境面板是错的交互骨架、输入占位符文案不符。
@MainActor
final class ComponentGalleryTests: XCTestCase {

    private func specimen(_ key: String) -> NSView {
        guard let s = GalleryBootstrap.specimens().first(where: { $0.key == key }) else {
            XCTFail("画廊缺少组件 specimen: \(key)")
            return NSView()
        }
        s.view.layoutSubtreeIfNeeded()
        return s.view
    }

    /// 收集视图树里所有 NSTextField 文本。
    private func labels(in view: NSView) -> [String] {
        var out: [String] = []
        if let tf = view as? NSTextField { out.append(tf.stringValue) }
        for sub in view.subviews { out += labels(in: sub) }
        return out
    }

    /// 视图树里所有子视图（含自身），用于统计特定图层特征。
    private func allViews(in view: NSView) -> [NSView] {
        var out: [NSView] = [view]
        for sub in view.subviews { out += allViews(in: sub) }
        return out
    }

    // MARK: - 用户气泡：无 You 标签、无橙色 accent 边条

    func testUserBubbleHasNoYouLabel() {
        let v = specimen("m-user")
        XCTAssertFalse(labels(in: v).contains("You"),
            "对齐设计稿后用户气泡不应再有「You」小标题")
    }

    func testUserBubbleHasNoAccentColoredBar() {
        let v = specimen("m-user")
        // 旧实现有一条橙色（DesignTokens.accent 0.45 alpha）竖直 accent 边条。
        let accent = DesignTokens.accent.withAlphaComponent(0.45).cgColor
        let hasAccentBar = allViews(in: v).contains { sub in
            guard let bg = sub.layer?.backgroundColor else { return false }
            return bg == accent
        }
        XCTAssertFalse(hasAccentBar, "对齐设计稿后用户气泡不应再有橙色 accent 边条")
    }

    func testUserBubbleShowsBodyText() {
        let v = specimen("m-user")
        XCTAssertTrue(labels(in: v).contains { $0.contains("auth service") },
            "用户气泡应渲染正文")
    }

    // MARK: - 环境面板：只读 Changes/Git（非旧交互骨架）

    func testEnvPanelIsReadonlyChangesGit() {
        let l = labels(in: specimen("envpanel"))
        for expected in ["变更 Changes", "Git", "main", "a1b2c3d"] {
            XCTAssertTrue(l.contains(expected), "环境面板应含「\(expected)」")
        }
    }

    func testEnvPanelDropsOldSkeleton() {
        let l = labels(in: specimen("envpanel"))
        for forbidden in ["环境信息", "提交或推送", "暂无来源"] {
            XCTAssertFalse(l.contains(forbidden),
                "环境面板不应再有旧交互骨架「\(forbidden)」")
        }
    }

    // MARK: - 输入栏占位符

    func testComposerPlaceholder() {
        XCTAssertTrue(labels(in: specimen("composer")).contains("继续对话，或 @ 引用文件…"),
            "输入栏占位符应与设计稿一致")
    }

    // MARK: - 全部 specimen 都能渲染出非空内容

    func testAllSpecimensRenderNonEmpty() {
        for s in GalleryBootstrap.specimens() {
            s.view.frame = NSRect(x: 0, y: 0, width: GalleryBootstrap.specimenWidth, height: 200)
            s.view.layoutSubtreeIfNeeded()
            XCTAssertFalse(labels(in: s.view).allSatisfy { $0.isEmpty },
                "specimen \(s.key) 应渲染出可见文本")
        }
    }
}
