import AppKit

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

    init(profile: AgentDeckProfile, preview: Bool = false) {
        self.profile = profile
        self.preview = preview
        self.model = preview ? PreviewBootstrap.makeSessionModel() : SessionModel()
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)

        let vc = SessionViewController(model: model)
        let win = NSWindow(contentViewController: vc)
        win.title = profile.windowTitle
        win.setContentSize(NSSize(width: 1280, height: 760))
        win.styleMask.insert([.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView])
        win.titleVisibility = .hidden
        win.titlebarAppearsTransparent = true
        win.backgroundColor = CodexDesktopChrome.windowBackground
        win.isMovableByWindowBackground = true
        win.toolbarStyle = .unifiedCompact
        win.center()
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
