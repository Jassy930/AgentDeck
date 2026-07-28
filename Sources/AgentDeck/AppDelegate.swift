import AppKit

@MainActor
protocol AppSessionSourceCompositionOwner: AnyObject {
    var model: SessionModel { get }
    func shutdown() async
}

extension AppSessionSourceComposition: AppSessionSourceCompositionOwner {}

/// AppKit entry point (replaces the former SwiftUI `App`). Owns the single
/// session window assembled by `SessionViewController` and reinstalls the
/// Cmd-Q main menu the SwiftUI command group used to provide. `@MainActor`
/// because it owns the main-actor `SessionModel`/`SessionViewController` and
/// drives `NSApp`/window/menu APIs.
@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private let profile: AgentDeckProfile
    private var window: NSWindow?
    private let composition: any AppSessionSourceCompositionOwner
    private let model: SessionModel
    private let preview: Bool
    private let gallery: Bool
    private let previewBootstrapOperation: @MainActor @Sendable (SessionModel) async -> Void
    private let terminationReply: @MainActor @Sendable (Bool) -> Void
    private var previewBootstrapTask: Task<Void, Never>?
    private var terminationTask: Task<Void, Never>?
    private var didReplyToTermination = false

    init(
        profile: AgentDeckProfile,
        composition: any AppSessionSourceCompositionOwner,
        preview: Bool = false,
        gallery: Bool = false,
        previewBootstrapOperation: @escaping @MainActor @Sendable (SessionModel) async -> Void =
            AppDelegate.bootstrapPreviewModel,
        terminationReply: @escaping @MainActor @Sendable (Bool) -> Void = {
            NSApp.reply(toApplicationShouldTerminate: $0)
        }
    ) {
        self.profile = profile
        self.composition = composition
        self.preview = preview
        self.gallery = gallery
        self.model = composition.model
        self.previewBootstrapOperation = previewBootstrapOperation
        self.terminationReply = terminationReply
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)

        let vc: NSViewController =
            gallery ? GalleryViewController() : SessionViewController(model: model)
        let win = NSWindow(contentViewController: vc)
        win.title = profile.windowTitle
        win.setContentSize(NSSize(width: 1280, height: 760))
        win.styleMask.insert([
            .titled, .closable, .miniaturizable, .resizable, .fullSizeContentView,
        ])
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
                NSRect(
                    x: vf.midX - size.width / 2, y: vf.midY - size.height / 2,
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
            startPreviewBootstrapIfNeeded()
        }
    }

    func startPreviewBootstrapIfNeeded() {
        guard preview, previewBootstrapTask == nil, terminationTask == nil,
            !didReplyToTermination
        else { return }
        let operation = previewBootstrapOperation
        previewBootstrapTask = Task { @MainActor [model] in
            guard !Task.isCancelled else { return }
            await operation(model)
        }
    }

    private static func bootstrapPreviewModel(_ model: SessionModel) async {
        guard !Task.isCancelled else { return }
        model.loadHistory()
        while model.isLoadingHistory {
            guard !Task.isCancelled else { return }
            await Task.yield()
        }
        guard !Task.isCancelled else { return }
        if let primary = model.historyThreads.first(where: {
            $0.id == MockDaemonScript.primaryThreadId
        }) {
            model.openHistoryThread(primary)
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
        guard
            let idx = previewScreenIndex(
                environment["AGENTDECK_PREVIEW_SCREEN"], screenCount: screens.count)
        else {
            return nil
        }
        return screens[idx]
    }

    /// 纯函数：把 1-based 环境值解析成 0-based 数组下标；无效/越界返回 nil。便于单测。
    static func previewScreenIndex(_ raw: String?, screenCount: Int) -> Int? {
        guard let raw, let n = Int(raw.trimmingCharacters(in: .whitespaces)), n >= 1 else {
            return nil
        }
        let idx = n - 1
        return idx < screenCount ? idx : nil
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }

    /// AppKit 的同步 termination callback 只建立一个 async barrier；真正退出必须等待
    /// preview consumer、model operation、scope router 与 registry-owned UDS/WSS generation 全部收口。
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard !didReplyToTermination else { return .terminateNow }
        guard terminationTask == nil else { return .terminateLater }

        let previewBootstrapTask = previewBootstrapTask
        previewBootstrapTask?.cancel()
        terminationTask = Task { @MainActor [self] in
            await composition.shutdown()
            await previewBootstrapTask?.value
            guard !didReplyToTermination else { return }
            didReplyToTermination = true
            self.previewBootstrapTask = nil
            terminationReply(true)
            terminationTask = nil
        }
        return .terminateLater
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
