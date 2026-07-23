import AppKit

/// AppKit 的 full-size content window 在右缘内部只提供极窄的原生 resize
/// 命中。窗口层在 view hit-testing 之前接管最右 16pt 的左键序列，保证空态、
/// 会话态和轨道状态都能稳定水平缩放；其他事件继续交给 NSWindow 默认实现。
@MainActor
final class AgentDeckWindow: NSWindow {
    /// 最外约 8pt 会先被 AppKit 私有 frame view 命中；扩到 16pt 后，内侧
    /// 约 8pt 可稳定进入 `sendEvent`，与系统最外缘共同形成可用缩放带。
    static let trailingResizeCaptureWidth: CGFloat = 16

    private var trailingResizeOrigin: (frame: NSRect, pointerX: CGFloat)?

    override func sendEvent(_ event: NSEvent) {
        if handleTrailingResizeEvent(
            type: event.type,
            locationInWindow: event.locationInWindow,
            pointerX: event.locationInWindow.x
        ) {
            return
        }
        super.sendEvent(event)
    }

    @discardableResult
    func handleTrailingResizeEvent(
        type: NSEvent.EventType,
        locationInWindow: NSPoint,
        pointerX: CGFloat
    ) -> Bool {
        switch type {
        case .leftMouseDown:
            guard isInTrailingResizeGutter(locationInWindow) else { return false }
            trailingResizeOrigin = (frame, pointerX)
            return true

        case .leftMouseDragged:
            guard let origin = trailingResizeOrigin else { return false }
            let nextFrame = Self.resizedFrame(
                from: origin.frame,
                deltaX: pointerX - origin.pointerX,
                minimumWidth: minSize.width,
                maximumWidth: maxSize.width
            )
            setFrame(nextFrame, display: true)
            return true

        case .leftMouseUp:
            guard trailingResizeOrigin != nil else { return false }
            trailingResizeOrigin = nil
            return true

        default:
            return false
        }
    }

    static func resizedFrame(
        from frame: NSRect,
        deltaX: CGFloat,
        minimumWidth: CGFloat,
        maximumWidth: CGFloat
    ) -> NSRect {
        let upperBound = max(minimumWidth, maximumWidth)
        let width = min(max(frame.width + deltaX, minimumWidth), upperBound)
        return NSRect(x: frame.minX, y: frame.minY, width: width, height: frame.height)
    }

    private func isInTrailingResizeGutter(_ locationInWindow: NSPoint) -> Bool {
        guard styleMask.contains(.resizable), let contentView else { return false }
        let point = contentView.convert(locationInWindow, from: nil)
        return contentView.bounds.contains(point)
            && point.x >= contentView.bounds.maxX - Self.trailingResizeCaptureWidth
    }
}

/// AppKit entry point (replaces the former SwiftUI `App`). Owns the single
/// session window assembled by `SessionViewController` and reinstalls the
/// Cmd-Q main menu the SwiftUI command group used to provide. `@MainActor`
/// because it owns the main-actor `SessionModel`/`SessionViewController` and
/// drives `NSApp`/window/menu APIs.
@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private let profile: AgentDeckProfile
    private var window: NSWindow?
    private let model: SessionModel
    private let preview: Bool
    private let gallery: Bool

    init(profile: AgentDeckProfile, preview: Bool = false, gallery: Bool = false) {
        self.profile = profile
        self.preview = preview
        self.gallery = gallery
        self.model = preview ? PreviewBootstrap.makeSessionModel() : SessionModel()
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)

        let vc: NSViewController = gallery ? GalleryViewController() : SessionViewController(model: model)
        let win = AgentDeckWindow(contentViewController: vc)
        win.title = profile.windowTitle
        win.setContentSize(NSSize(width: 1280, height: 760))
        win.styleMask.insert([.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView])
        win.titleVisibility = .hidden
        win.titlebarAppearsTransparent = true
        // 侧栏毛玻璃需要窗口非不透明，让 .behindWindow 材质透出并模糊桌面；
        // 内容区各自绘制不透明底色，故内容不跟着透。
        win.isOpaque = false
        win.backgroundColor = .clear
        win.isMovableByWindowBackground = true
        win.toolbarStyle = .unifiedCompact
        // preview/gallery 可选把窗口开在指定屏，便于对照设计稿而不占主屏。
        // 由环境变量 AGENTDECK_PREVIEW_SCREEN（1-based，与 `screencapture -D N` 一致）配置，
        // 默认关闭；在本地 shell 里 `export AGENTDECK_PREVIEW_SCREEN=2` 即长期生效，不影响他人。
        if let screen = Self.previewTargetScreen(preview: preview, gallery: gallery) {
            let size = NSSize(width: 1280, height: 760)
            let vf = screen.visibleFrame
            win.setFrame(
                NSRect(x: vf.midX - size.width / 2, y: vf.midY - size.height / 2,
                       width: size.width, height: size.height),
                display: true)
        } else {
            win.center()
        }
        win.makeKeyAndOrderFront(nil)
        self.window = win

        NSApp.activate(ignoringOtherApps: true)
        installMainMenu()

        // preview：直接开进主 mock 会话（对齐设计稿的会话视图，而非空态）。
        if preview {
            DispatchQueue.main.async { [model] in
                model.loadHistory()
                if let primary = model.historyThreads.first(where: {
                    $0.id == MockDaemonScript.primaryThreadId
                }) {
                    model.openHistoryThread(primary)
                }
            }
        }
    }

    /// 解析 `AGENTDECK_PREVIEW_SCREEN` 得到目标屏；非 preview/gallery、未设、非法或屏不存在时返回 nil（回落主屏居中）。
    private static func previewTargetScreen(
        preview: Bool,
        gallery: Bool,
        environment: [String: String] = ProcessInfo.processInfo.environment,
        screens: [NSScreen] = NSScreen.screens
    ) -> NSScreen? {
        guard preview || gallery else { return nil }
        guard let idx = previewScreenIndex(environment["AGENTDECK_PREVIEW_SCREEN"], screenCount: screens.count) else {
            return nil
        }
        return screens[idx]
    }

    /// 纯函数：把 1-based 环境值解析成 0-based 数组下标；无效/越界返回 nil。便于单测。
    static func previewScreenIndex(_ raw: String?, screenCount: Int) -> Int? {
        guard let raw, let n = Int(raw.trimmingCharacters(in: .whitespaces)), n >= 1 else { return nil }
        let idx = n - 1
        return idx < screenCount ? idx : nil
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }

    /// Reproduces the former SwiftUI Cmd-Q command (`AgentDeckQuitCommand`).
    private func installMainMenu() {
        let mainMenu = NSMenu()
        let appItem = NSMenuItem()
        mainMenu.addItem(appItem)

        let appMenu = NSMenu()
        appMenu.addItem(
            withTitle: AgentDeckQuitCommand.title,
            action: #selector(NSApplication.terminate(_:)),
            keyEquivalent: AgentDeckQuitCommand.shortcutKey
        )
        appItem.submenu = appMenu

        NSApp.mainMenu = mainMenu
    }
}
