import AppKit
import AgentDeckCore
import Foundation
@testable import AgentDeck

// MARK: - 假 daemon transport（可注入，喂帧 + 捕获发出帧）

final class FakeTransport: DaemonTransport {
    private(set) var sentLines: [String] = []
    private var incoming: ((String) -> Void)?
    private var disconnect: (() -> Void)?
    private(set) var isStarted = false
    var isAlive: Bool { isStarted }

    func start() throws { isStarted = true }
    func send(_ line: String) throws { sentLines.append(line) }
    func setIncomingHandler(_ handler: @escaping (String) -> Void) { incoming = handler }
    func setDisconnectHandler(_ handler: @escaping () -> Void) { disconnect = handler }
    func shutdown() { isStarted = false; disconnect?() }

    /// 模拟 daemon 推一帧给 client。
    func pushLine(_ line: String) { incoming?(line) }
    func sent(containing needle: String) -> Bool { sentLines.contains { $0.contains(needle) } }
}

// MARK: - Spy 替身：捕获交互出口

@MainActor
final class SpyTurnStarter: RuntimeTurnStarting {
    struct Call { let sessionId: String; let threadId: String?; let agentKind: AgentKind; let cwd: URL; let prompt: String }
    private(set) var calls: [Call] = []
    var lastPrompt: String? { calls.last?.prompt }

    func startTurn(sessionId: String, threadId: String?, agentKind: AgentKind, cwd: URL,
                   prompt: String, optimisticUserItemId: String, sessionStart: SessionStart?,
                   onEvent: @escaping @MainActor (ServerEvent) -> Void) {
        calls.append(.init(sessionId: sessionId, threadId: threadId, agentKind: agentKind, cwd: cwd, prompt: prompt))
    }
}

@MainActor
final class SpyActionDecider: RuntimeActionDeciding {
    struct Decision { let sessionId: String; let requestId: String; let decision: ActionDecisionKind; let persist: Bool }
    private(set) var decisions: [Decision] = []
    func sendActionDecision(sessionId: String, requestId: String, decision: ActionDecisionKind, persist: Bool) {
        decisions.append(.init(sessionId: sessionId, requestId: requestId, decision: decision, persist: persist))
    }
}

// MARK: - 视图查找 / 交互 / 渲染 helper

extension NSView {
    func firstDescendant<T: NSView>(ofType type: T.Type) -> T? {
        if let s = self as? T { return s }
        for sub in subviews { if let m = sub.firstDescendant(ofType: type) { return m } }
        return nil
    }
    func allDescendants<T: NSView>(ofType type: T.Type) -> [T] {
        var out: [T] = []
        if let s = self as? T { out.append(s) }
        for sub in subviews { out.append(contentsOf: sub.allDescendants(ofType: type)) }
        return out
    }
    func descendant(id: String) -> NSView? {
        if accessibilityIdentifier() == id { return self }
        for sub in subviews { if let m = sub.descendant(id: id) { return m } }
        return nil
    }
    func button(id: String) -> NSButton? {
        allDescendants(ofType: NSButton.self).first { $0.accessibilityIdentifier() == id }
    }

    /// 强制布局后渲染成 PNG，供人工看真实渲染。
    @MainActor
    func renderPNG(to path: String, size: NSSize? = nil) {
        if let size { frame = NSRect(origin: .zero, size: size) }
        layoutSubtreeIfNeeded()
        let b = bounds
        guard b.width > 1, b.height > 1, let rep = bitmapImageRepForCachingDisplay(in: b) else { return }
        cacheDisplay(in: b, to: rep)
        try? rep.representation(using: .png, properties: [:])?.write(to: URL(fileURLWithPath: path))
    }
}
