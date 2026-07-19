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
    private var sidebarWidthConstraint: NSLayoutConstraint?
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
        // 透明：让侧栏 .behindWindow 毛玻璃不被根视图实色遮挡（内容区自绘不透明底）。
        root.layer?.backgroundColor = NSColor.clear.cgColor

        // NSSplitViewController: left = sidebar, right = content
        let splitVC = SidebarWidthSplitViewController()
        splitVC.splitView.isVertical = true
        splitVC.splitView.dividerStyle = .thin
        splitVC.splitView.wantsLayer = true
        splitVC.splitView.layer?.backgroundColor = NSColor.clear.cgColor

        // 用普通 split item 而非 `sidebarWithViewController:`：后者会套上 macOS 侧栏材质，
        // 配合透明标题栏 + fullSizeContentView 会把侧栏渲染成内嵌、圆角、带一圈描边的浮动
        // 面板。设计系统要的是齐平满高的侧栏 + 一道从顶到底的竖分割线（dividerStyle=.thin），
        // 侧栏底色由 HistorySidebarViewController 自绘 sidebarBackground，无需材质。
        let sidebarItem = NSSplitViewItem(viewController: historySidebarVC)
        // 设计系统 .workbench 侧栏列宽 232px；min/max 200–280 允许用户拖拽微调。
        sidebarItem.minimumThickness = 200
        sidebarItem.maximumThickness = 280
        sidebarItem.preferredThicknessFraction = NSSplitViewItem.unspecifiedDimension
        // 不收起：原生窗口的最小内容宽度（~760，由内容区约束决定）够不着设计的 <760 隐藏断点，
        // 自动收起实际不可达；且收起会引发标题压红绿灯。改为固定 232 + 可拖拽 + 内容随窗口伸缩。
        sidebarItem.canCollapse = false

        let sidebarWidth = historySidebarVC.view.widthAnchor.constraint(equalToConstant: 232)
        sidebarWidth.priority = .required
        sidebarWidth.isActive = true
        sidebarWidthConstraint = sidebarWidth
        splitVC.sidebarWidthConstraint = sidebarWidth

        let contentItem = NSSplitViewItem(viewController: makeContentContainerVC())
        contentItem.minimumThickness = 300

        splitVC.addSplitViewItem(sidebarItem)
        splitVC.addSplitViewItem(contentItem)
        // 内容区吃窗口伸缩；侧栏宽度由上面的 required constraint 表达。
        splitVC.splitView.setHoldingPriority(NSLayoutConstraint.Priority(250), forSubviewAt: 0)
        splitVC.splitView.setHoldingPriority(NSLayoutConstraint.Priority(250), forSubviewAt: 1)

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
        guard let sv = splitVC?.splitView, sv.frame.width > 0 else { return }
        // 首次布局设初始宽度 232（此时 split 已有真实 frame，setPosition 才生效）。
        if !didApplyInitialSidebarWidth {
            sv.setPosition(232, ofDividerAt: 0)
            sidebarWidthConstraint?.constant = 232
            didApplyInitialSidebarWidth = true
        }
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
            _ = self.model.workbench.selectedConversationID
            _ = self.model.workbench.selectedRuntime?.capabilities?.agentKind
            _ = self.model.cwd
        }, onChange: { [weak self] in
            self?.refreshControlBar()
        })
    }

    private func refreshControlBar() {
        if let caps = model.workbench.selectedRuntime?.capabilities,
           let conversationID = model.workbench.selectedConversationID {
            controlBar.bind(
                capabilities: caps,
                conversationID: conversationID,
                onConfigurationChange: { [weak self] id, mutation in
                    self?.model.updateConversationConfiguration(
                        conversationID: id,
                        mutation: mutation
                    )
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

    /// Present the new-session dialog and dispatch its Runtime v2 draft.
    func presentNewSessionDialog() {
        let dlg = NewSessionDialog()
        dlg.onSubmit = { [weak self] draft in
            self?.handleNewConversationDraft(draft)
        }
        newSessionDialog = dlg
        if let win = dlg.window {
            view.window?.beginSheet(win) { [weak self] _ in
                self?.newSessionDialog = nil
            }
        }
    }

    private func handleNewConversationDraft(_ draft: RuntimeConversationDraft) {
        if let cwdMsg = model.chooseCwd(URL(fileURLWithPath: draft.cwd)) {
            model.workbench.selectedRuntime?.warningMessage = cwdMsg
            return
        }
        model.startConversation(draft)
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

private final class SidebarWidthSplitViewController: NSSplitViewController {
    weak var sidebarWidthConstraint: NSLayoutConstraint?

    override func splitView(
        _ splitView: NSSplitView,
        constrainSplitPosition proposedPosition: CGFloat,
        ofSubviewAt dividerIndex: Int
    ) -> CGFloat {
        guard dividerIndex == 0 else { return proposedPosition }
        let width = min(max(proposedPosition, 200), 280)
        sidebarWidthConstraint?.constant = width
        return width
    }
}
