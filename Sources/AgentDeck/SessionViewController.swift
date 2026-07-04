import AppKit
import AgentDeckCore

// MARK: - SessionViewController (Task 11)
//
// Top-level AppKit view controller that assembles all session sub-views into
// the main window content:
//
//   ┌────────────────────────────────────────────────────┐
//   │  StatusBarView  (fixed height ~36pt)               │
//   ├────────────────────────────────────────────────────┤
//   │  NSSplitView                                       │
//   │  ┌──────────┬─────────────────────────────────┐   │
//   │  │ History  │ Content (EmptyState OR           │   │
//   │  │ Sidebar  │  ConversationVC + RailOverlay)   │   │
//   │  │  ~260pt  │                                  │   │
//   │  └──────────┴─────────────────────────────────┘   │
//   └────────────────────────────────────────────────────┘
//
// cwd == nil  → content = EmptyStateView
// cwd != nil  → content = ConversationViewController
//               with TurnJumpRailView overlaid on the trailing edge (~28pt wide)
//
// Wiring:
//   conversationVC.onTopVisibleTurnChanged → rail.syncSelection(topVisibleTurnId:)
//   rail.onSelectTurn                      → conversationVC.scrollToTurn(_:)
//   rail.onJumpToLatest                    → conversationVC.scrollToLatest()
//
// model.cwd changes are observed via ObservationBinder; the content pane is
// hot-swapped between EmptyStateView and the conversation+rail composite.

@MainActor
final class SessionViewController: NSViewController {

    // MARK: - Dependencies

    private let model: SessionModel

    // MARK: - Sub-view controllers

    private lazy var historySidebarVC: HistorySidebarViewController = {
        let vc = HistorySidebarViewController(model: model)
        vc.onNewSessionRequested = { [weak self] in
            self?.presentNewSessionDialog()
        }
        return vc
    }()
    private lazy var conversationVC   = ConversationViewController(model: model)

    // MARK: - Views / containers

    private let rail: TurnJumpRailView
    private let emptyStateView: EmptyStateView
    private let contentHeaderView: CodexContentHeaderView

    /// T6B: agent control bar — bound to `selectedRuntime?.capabilities`.
    private let controlBar = AgentControlBar()
    private var controlBarHeight: NSLayoutConstraint?
    private var contentHeaderHeight: NSLayoutConstraint?

    /// T6B: optional new-session dialog, retained while open.
    private var newSessionDialog: NewSessionDialog?

    /// Container placed as the right pane of the split; we swap its content
    /// child between EmptyStateView and the conversation+rail composite.
    private let contentContainer = NSView()
    private let contentBodyContainer = NSView()

    /// Composite view that holds conversationVC.view + rail overlay.
    private let conversationComposite = NSView()

    // MARK: - Split view (retained for deferred initial-width application)

    private weak var splitVC: NSSplitViewController?
    private var didApplyInitialSidebarWidth = false

    // MARK: - Observation

    private let binder = ObservationBinder()

    // MARK: - Init

    init(model: SessionModel) {
        self.model         = model
        self.rail          = TurnJumpRailView(model: model)
        self.emptyStateView = EmptyStateView(model: model)
        self.contentHeaderView = CodexContentHeaderView(model: model)
        super.init(nibName: nil, bundle: nil)
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) not supported") }

    // MARK: - View lifecycle

    override func loadView() {
        let root = NSView()
        root.translatesAutoresizingMaskIntoConstraints = false
        root.wantsLayer = true
        root.layer?.backgroundColor = CodexDesktopChrome.windowBackground.cgColor

        // NSSplitViewController: left = sidebar, right = content
        let splitVC = NSSplitViewController()
        splitVC.splitView.isVertical = true
        splitVC.splitView.dividerStyle = .thin
        splitVC.splitView.wantsLayer = true
        splitVC.splitView.layer?.backgroundColor = CodexDesktopChrome.windowBackground.cgColor

        let sidebarItem = NSSplitViewItem(sidebarWithViewController: historySidebarVC)
        sidebarItem.minimumThickness = 236
        sidebarItem.maximumThickness = 360
        sidebarItem.preferredThicknessFraction = NSSplitViewItem.unspecifiedDimension
        // setPosition is deferred to viewDidLayout (first pass) so the split
        // view already has a real frame; calling it here (pre-layout) is a
        // no-op on some macOS versions, leaving the sidebar at ~160pt.

        let contentItem = NSSplitViewItem(viewController: makeContentContainerVC())
        contentItem.minimumThickness = 300

        splitVC.addSplitViewItem(sidebarItem)
        splitVC.addSplitViewItem(contentItem)

        addChild(splitVC)
        self.splitVC = splitVC
        splitVC.view.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(splitVC.view)

        NSLayoutConstraint.activate([
            splitVC.view.topAnchor.constraint(equalTo: root.topAnchor),
            splitVC.view.leadingAnchor.constraint(equalTo: root.leadingAnchor),
            splitVC.view.trailingAnchor.constraint(equalTo: root.trailingAnchor),
            splitVC.view.bottomAnchor.constraint(equalTo: root.bottomAnchor),
        ])

        self.view = root

        buildConversationComposite()
        wireRailCallbacks()
        observeCwdChanges()
        observeCapabilities()
        // Apply initial content based on current cwd state
        updateContentPane(hasCwd: model.cwd != nil)
        refreshContentChrome(hasCwd: model.cwd != nil)
        refreshControlBar()
    }

    override func viewDidLayout() {
        super.viewDidLayout()
        // Apply the 260pt initial sidebar width on the first layout pass, when
        // the split view has a real frame and setPosition takes effect.
        guard !didApplyInitialSidebarWidth, let sv = splitVC?.splitView,
              sv.frame.width > 0 else { return }
        sv.setPosition(220, ofDividerAt: 0)
        didApplyInitialSidebarWidth = true
    }

    override func viewDidAppear() {
        super.viewDidAppear()
        // Restore the former SwiftUI `.onAppear { model.loadHistoryOnAppear() }`
        // that the AppKit cutover (83e8853) dropped: without it the one-shot
        // initial history scan never fires, so persisted sessions only appear
        // after a manual Refresh. `loadHistoryOnAppear()` is idempotent — its
        // `shouldAutoRefreshHistoryOnAppear()` guard runs the scan only once.
        model.loadHistoryOnAppear()
    }

    // MARK: - Content container VC

    /// Returns a lightweight NSViewController that owns `contentContainer`.
    /// We use a wrapper VC so NSSplitViewItem can hold it.
    private func makeContentContainerVC() -> NSViewController {
        let vc = NSViewController()
        contentContainer.translatesAutoresizingMaskIntoConstraints = false
        contentContainer.wantsLayer = true
        contentContainer.layer?.backgroundColor = CodexDesktopChrome.windowBackground.cgColor

        contentHeaderView.translatesAutoresizingMaskIntoConstraints = false
        controlBar.translatesAutoresizingMaskIntoConstraints = false
        contentBodyContainer.translatesAutoresizingMaskIntoConstraints = false

        contentContainer.addSubview(contentHeaderView)
        contentContainer.addSubview(controlBar)
        contentContainer.addSubview(contentBodyContainer)

        let headerH = contentHeaderView.heightAnchor.constraint(equalToConstant: 0)
        let controlBarH = controlBar.heightAnchor.constraint(equalToConstant: 0)
        contentHeaderHeight = headerH
        controlBarHeight = controlBarH

        NSLayoutConstraint.activate([
            contentHeaderView.topAnchor.constraint(equalTo: contentContainer.topAnchor),
            contentHeaderView.leadingAnchor.constraint(equalTo: contentContainer.leadingAnchor),
            contentHeaderView.trailingAnchor.constraint(equalTo: contentContainer.trailingAnchor),
            headerH,

            controlBar.topAnchor.constraint(equalTo: contentHeaderView.bottomAnchor),
            controlBar.leadingAnchor.constraint(equalTo: contentContainer.leadingAnchor, constant: 18),
            controlBar.trailingAnchor.constraint(equalTo: contentContainer.trailingAnchor, constant: -18),
            controlBarH,

            contentBodyContainer.topAnchor.constraint(equalTo: controlBar.bottomAnchor),
            contentBodyContainer.leadingAnchor.constraint(equalTo: contentContainer.leadingAnchor),
            contentBodyContainer.trailingAnchor.constraint(equalTo: contentContainer.trailingAnchor),
            contentBodyContainer.bottomAnchor.constraint(equalTo: contentContainer.bottomAnchor),
        ])

        vc.view = contentContainer
        return vc
    }

    // MARK: - Conversation composite (conversationVC.view + rail overlay)

    private func buildConversationComposite() {
        // Add conversationVC as a child so its view lifecycle is properly managed
        addChild(conversationVC)

        let convView = conversationVC.view
        convView.translatesAutoresizingMaskIntoConstraints = false
        conversationComposite.translatesAutoresizingMaskIntoConstraints = false
        conversationComposite.addSubview(convView)

        // Rail: trailing overlay, 28pt wide, full height
        rail.translatesAutoresizingMaskIntoConstraints = false
        conversationComposite.addSubview(rail)

        NSLayoutConstraint.activate([
            convView.topAnchor.constraint(equalTo: conversationComposite.topAnchor),
            convView.leadingAnchor.constraint(equalTo: conversationComposite.leadingAnchor),
            convView.trailingAnchor.constraint(equalTo: conversationComposite.trailingAnchor),
            convView.bottomAnchor.constraint(equalTo: conversationComposite.bottomAnchor),

            rail.topAnchor.constraint(equalTo: conversationComposite.topAnchor),
            rail.trailingAnchor.constraint(equalTo: conversationComposite.trailingAnchor),
            rail.bottomAnchor.constraint(equalTo: conversationComposite.bottomAnchor),
            rail.widthAnchor.constraint(equalToConstant: TurnJumpRailLayout.width),
        ])
    }

    // MARK: - Rail ↔ Conversation wiring

    private func wireRailCallbacks() {
        conversationVC.onTopVisibleTurnChanged = { [weak self] turnId in
            self?.rail.syncSelection(topVisibleTurnId: turnId)
        }
        rail.onSelectTurn = { [weak self] turnId in
            self?.conversationVC.scrollToTurn(turnId)
        }
        rail.onJumpToLatest = { [weak self] in
            self?.conversationVC.scrollToLatest()
        }
    }

    // MARK: - cwd observation → content pane swap

    private func observeCwdChanges() {
        binder.bind({ [weak self] in
            guard let self else { return }
            _ = self.model.cwd
        }, onChange: { [weak self] in
            guard let self else { return }
            self.updateContentPane(hasCwd: self.model.cwd != nil)
            self.refreshContentChrome(hasCwd: self.model.cwd != nil)
        })
    }

    // MARK: - T6B: capabilities observation → AgentControlBar swap

    private let capabilitiesBinder = ObservationBinder()

    private func observeCapabilities() {
        capabilitiesBinder.bind({ [weak self] in
            guard let self else { return }
            _ = self.model.workbench.selectedSessionId
            _ = self.model.workbench.selectedRuntime?.capabilities?.agentKind
            _ = self.model.cwd
        }, onChange: { [weak self] in
            self?.refreshControlBar()
        })
    }

    private func refreshControlBar() {
        if let caps = model.workbench.selectedRuntime?.capabilities,
           let sid = model.workbench.selectedSessionId {
            // C2 fix (v0.2 final review): wire vendor-control callbacks
            // so popup changes round-trip through DaemonClient.
            // SessionModel.submitVendorControl swallows errors after
            // logging; daemon-side rejections still surface via the
            // normal events stream as `ServerEvent.error`.
            controlBar.bind(
                capabilities: caps,
                sessionId: sid,
                onVendorControl: { [weak self] sessionId, payload in
                    self?.model.submitVendorControl(sessionId: sessionId, payload: payload)
                }
            )
            controlBarHeight?.constant = 0
        } else {
            controlBar.clear()
            controlBarHeight?.constant = 0
        }
        refreshContentChrome(hasCwd: model.cwd != nil)
    }

    private func refreshContentChrome(hasCwd: Bool) {
        contentHeaderHeight?.constant = hasCwd ? 44 : 0
        contentHeaderView.isHidden = !hasCwd
    }

    /// T6B: present the new-session dialog and dispatch the resulting
    /// `SessionStart` to the workbench → daemon path.
    func presentNewSessionDialog() {
        let dlg = NewSessionDialog()
        dlg.onSubmit = { [weak self] start in
            self?.handleNewSessionStart(start)
        }
        newSessionDialog = dlg
        if let win = dlg.window {
            view.window?.beginSheet(win) { [weak self] _ in
                self?.newSessionDialog = nil
            }
        }
    }

    private func handleNewSessionStart(_ start: SessionStart) {
        // C1 fix (v0.2 final review): forward the dialog's full
        // `SessionStart` (including vendor_options: sandbox / approval /
        // permission_mode / reasoning_effort / etc.) into the workbench
        // so the daemon sees the user's choices on the first turn.
        // Previously only `prompt` + `agentKind` propagated and the
        // user's vendor options were silently replaced by synthesized
        // defaults inside `DaemonClient.startTurn`.
        if let cwdMsg = model.chooseCwd(URL(fileURLWithPath: start.cwd)) {
            model.workbench.selectedRuntime?.warningMessage = cwdMsg
            return
        }
        let prompt = start.prompt ?? ""
        model.submit(prompt, agentKind: start.agentKind, sessionStart: start)
    }

    /// Swap EmptyStateView ↔ conversationComposite inside `contentContainer`.
    private func updateContentPane(hasCwd: Bool) {
        if hasCwd {
            emptyStateView.removeFromSuperview()
            if conversationComposite.superview == nil {
                contentBodyContainer.addSubview(conversationComposite)
                NSLayoutConstraint.activate([
                    conversationComposite.topAnchor.constraint(equalTo: contentBodyContainer.topAnchor),
                    conversationComposite.leadingAnchor.constraint(equalTo: contentBodyContainer.leadingAnchor),
                    conversationComposite.trailingAnchor.constraint(equalTo: contentBodyContainer.trailingAnchor),
                    conversationComposite.bottomAnchor.constraint(equalTo: contentBodyContainer.bottomAnchor),
                ])
            }
        } else {
            conversationComposite.removeFromSuperview()
            if emptyStateView.superview == nil {
                emptyStateView.translatesAutoresizingMaskIntoConstraints = false
                contentBodyContainer.addSubview(emptyStateView)
                NSLayoutConstraint.activate([
                    emptyStateView.topAnchor.constraint(equalTo: contentBodyContainer.topAnchor),
                    emptyStateView.leadingAnchor.constraint(equalTo: contentBodyContainer.leadingAnchor),
                    emptyStateView.trailingAnchor.constraint(equalTo: contentBodyContainer.trailingAnchor),
                    emptyStateView.bottomAnchor.constraint(equalTo: contentBodyContainer.bottomAnchor),
                ])
            }
        }
    }
}
