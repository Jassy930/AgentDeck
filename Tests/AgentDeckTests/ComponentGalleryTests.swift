import XCTest
import AppKit
import AgentDeckCore
@testable import AgentDeck

/// 组件画廊结构断言（Phase 0/1 视觉保真门禁）。
///
/// 断言由设计系统 SSOT 驱动：遍历 `ComponentSpecs.all`（生成自 components.json），对
/// `GalleryBootstrap.specimens()` 渲染出的**真实组件**遍历视图树校验必需标签/禁止元素。
/// 渲染器无关、稳定。这把对齐结论编码成回归——正是之前漏网的偏差：给组件加回禁止元素
/// （用户气泡的「You」/橙边条）、换错骨架（环境面板旧交互列）、改错文案（输入占位符）。
@MainActor
final class ComponentGalleryTests: XCTestCase {

    private func specimenView(_ key: String) -> NSView? {
        guard let s = GalleryBootstrap.specimens().first(where: { $0.key == key }) else { return nil }
        s.view.layoutSubtreeIfNeeded()
        return s.view
    }

    private func labels(in view: NSView) -> [String] {
        var out: [String] = []
        if let tf = view as? NSTextField { out.append(tf.stringValue) }
        for sub in view.subviews { out += labels(in: sub) }
        return out
    }

    private func allViews(in view: NSView) -> [NSView] {
        var out: [NSView] = [view]
        for sub in view.subviews { out += allViews(in: sub) }
        return out
    }

    private func hasAccentBar(_ view: NSView) -> Bool {
        let accent = DesignTokens.accent.withAlphaComponent(0.45).cgColor
        return allViews(in: view).contains { $0.layer?.backgroundColor == accent }
    }

    // MARK: - SSOT 驱动：每个组件契约都有对应 specimen 且满足必需/禁止约束

    func testEverySpecHasSpecimen() {
        let keys = Set(GalleryBootstrap.specimens().map(\.key))
        for spec in ComponentSpecs.all {
            XCTAssertTrue(keys.contains(spec.key), "组件契约 \(spec.key) 缺少画廊 specimen")
        }
    }

    func testSpecimensSatisfyComponentSpecs() {
        for spec in ComponentSpecs.all {
            guard let view = specimenView(spec.key) else {
                XCTFail("画廊缺少 specimen: \(spec.key)"); continue
            }
            let l = labels(in: view)
            for required in spec.requiredLabels {
                XCTAssertTrue(l.contains(required),
                    "\(spec.key) 应含必需标签「\(required)」")
            }
            for forbidden in spec.forbiddenLabels {
                XCTAssertFalse(l.contains(forbidden),
                    "\(spec.key) 不应含禁止标签「\(forbidden)」")
            }
            if spec.forbidAccentBar {
                XCTAssertFalse(hasAccentBar(view),
                    "\(spec.key) 不应有橙色 accent 边条")
            }
        }
    }

    // MARK: - fixture 专属（数据在测试侧，不进 SSOT）

    func testUserBubbleShowsBodyText() {
        guard let v = specimenView("m-user") else { return XCTFail("缺 m-user") }
        XCTAssertTrue(labels(in: v).contains { $0.contains("auth service") }, "用户气泡应渲染正文")
    }

    func testEnvPanelShowsFixtureValues() {
        guard let v = specimenView("envpanel") else { return XCTFail("缺 envpanel") }
        let l = labels(in: v)
        XCTAssertTrue(l.contains("main"), "环境面板应渲染 mock 分支值")
        XCTAssertTrue(l.contains("a1b2c3d"), "环境面板应渲染 mock 提交值")
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
