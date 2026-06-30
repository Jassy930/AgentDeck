import AppKit

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

    private let statusBarView: StatusBarView
    private let rail: TurnJumpRailView
    private let emptyStateView: EmptyStateView

    /// T6B: agent control bar — bound to `selectedRuntime?.capabilities`.
    private let controlBar = AgentControlBar()
    private var controlBarHeight: NSLayoutConstraint?

    /// T6B: optional new-session dialog, retained while open.
    private var newSessionDialog: NewSessionDialog?

    /// Container placed as the right pane of the split; we swap its content
    /// child between EmptyStateView and the conversation+rail composite.
    private let contentContainer = NSView()

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
        self.statusBarView = StatusBarView(model: model)
        self.rail          = TurnJumpRailView(model: model)
        self.emptyStateView = EmptyStateView(model: model)
        super.init(nibName: nil, bundle: nil)
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) not supported") }

    // MARK: - View lifecycle

    override func loadView() {
        let root = NSView()
        root.translatesAutoresizingMaskIntoConstraints = false

        // Status bar (fixed height)
        statusBarView.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(statusBarView)

        // T6B: agent control bar sits below the status bar; height collapses to 0
        // when no runtime/capabilities are active.
        controlBar.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(controlBar)

        // 1pt separator between status bar and split pane
        let separator = NSBox()
        separator.boxType = .separator
        separator.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(separator)

        // NSSplitViewController: left = sidebar, right = content
        let splitVC = NSSplitViewController()
        splitVC.splitView.isVertical = true
        splitVC.splitView.dividerStyle = .thin

        let sidebarItem = NSSplitViewItem(sidebarWithViewController: historySidebarVC)
        sidebarItem.minimumThickness = 200
        sidebarItem.maximumThickness = 400
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

        let controlBarH = controlBar.heightAnchor.constraint(equalToConstant: 0)
        controlBarHeight = controlBarH

        NSLayoutConstraint.activate([
            statusBarView.topAnchor.constraint(equalTo: root.topAnchor),
            statusBarView.leadingAnchor.constraint(equalTo: root.leadingAnchor),
            statusBarView.trailingAnchor.constraint(equalTo: root.trailingAnchor),
            statusBarView.heightAnchor.constraint(equalToConstant: 36),

            controlBar.topAnchor.constraint(equalTo: statusBarView.bottomAnchor),
            controlBar.leadingAnchor.constraint(equalTo: root.leadingAnchor),
            controlBar.trailingAnchor.constraint(equalTo: root.trailingAnchor),
            controlBarH,

            separator.topAnchor.constraint(equalTo: controlBar.bottomAnchor),
            separator.leadingAnchor.constraint(equalTo: root.leadingAnchor),
            separator.trailingAnchor.constraint(equalTo: root.trailingAnchor),

            splitVC.view.topAnchor.constraint(equalTo: separator.bottomAnchor),
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
        refreshControlBar()
    }

    override func viewDidLayout() {
        super.viewDidLayout()
        // Apply the 260pt initial sidebar width on the first layout pass, when
        // the split view has a real frame and setPosition takes effect.
        guard !didApplyInitialSidebarWidth, let sv = splitVC?.splitView,
              sv.frame.width > 0 else { return }
        sv.setPosition(260, ofDividerAt: 0)
        didApplyInitialSidebarWidth = true
    }

    // MARK: - Content container VC

    /// Returns a lightweight NSViewController that owns `contentContainer`.
    /// We use a wrapper VC so NSSplitViewItem can hold it.
    private func makeContentContainerVC() -> NSViewController {
        let vc = NSViewController()
        contentContainer.translatesAutoresizingMaskIntoConstraints = false
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
        })
    }

    // MARK: - T6B: capabilities observation → AgentControlBar swap

    private let capabilitiesBinder = ObservationBinder()

    private func observeCapabilities() {
        capabilitiesBinder.bind({ [weak self] in
            guard let self else { return }
            _ = self.model.workbench.selectedSessionId
            _ = self.model.workbench.selectedRuntime?.capabilities?.agentKind
        }, onChange: { [weak self] in
            self?.refreshControlBar()
        })
    }

    private func refreshControlBar() {
        if let caps = model.workbench.selectedRuntime?.capabilities {
            controlBar.bind(capabilities: caps)
            controlBarHeight?.constant = 30
        } else {
            controlBar.clear()
            controlBarHeight?.constant = 0
        }
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
        // 在 v0.2 阶段，SessionModel 通过 workbench.submit 自带 sessionStart
        // 的链路尚未暴露，这里先把 cwd 切到 dialog 选择的目录、并 submit prompt。
        // 完整的 explicit-start (无需 prompt) 走 daemon `sessionStart` 命令在
        // T6.10 的 dialog 提交链路里补全。当前先做最小可工作的 cwd+prompt 提交。
        if let cwdMsg = model.chooseCwd(URL(fileURLWithPath: start.cwd)) {
            model.workbench.selectedRuntime?.warningMessage = cwdMsg
            return
        }
        if let prompt = start.prompt, !prompt.isEmpty {
            model.submit(prompt, agentKind: start.agentKind)
        }
    }

    /// Swap EmptyStateView ↔ conversationComposite inside `contentContainer`.
    private func updateContentPane(hasCwd: Bool) {
        if hasCwd {
            emptyStateView.removeFromSuperview()
            if conversationComposite.superview == nil {
                contentContainer.addSubview(conversationComposite)
                NSLayoutConstraint.activate([
                    conversationComposite.topAnchor.constraint(equalTo: contentContainer.topAnchor),
                    conversationComposite.leadingAnchor.constraint(equalTo: contentContainer.leadingAnchor),
                    conversationComposite.trailingAnchor.constraint(equalTo: contentContainer.trailingAnchor),
                    conversationComposite.bottomAnchor.constraint(equalTo: contentContainer.bottomAnchor),
                ])
            }
        } else {
            conversationComposite.removeFromSuperview()
            if emptyStateView.superview == nil {
                emptyStateView.translatesAutoresizingMaskIntoConstraints = false
                contentContainer.addSubview(emptyStateView)
                NSLayoutConstraint.activate([
                    emptyStateView.topAnchor.constraint(equalTo: contentContainer.topAnchor),
                    emptyStateView.leadingAnchor.constraint(equalTo: contentContainer.leadingAnchor),
                    emptyStateView.trailingAnchor.constraint(equalTo: contentContainer.trailingAnchor),
                    emptyStateView.bottomAnchor.constraint(equalTo: contentContainer.bottomAnchor),
                ])
            }
        }
    }
}
