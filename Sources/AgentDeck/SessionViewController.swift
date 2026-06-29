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

    private lazy var historySidebarVC = HistorySidebarViewController(model: model)
    private lazy var conversationVC   = ConversationViewController(model: model)

    // MARK: - Views / containers

    private let statusBarView: StatusBarView
    private let rail: TurnJumpRailView
    private let emptyStateView: EmptyStateView

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

        NSLayoutConstraint.activate([
            statusBarView.topAnchor.constraint(equalTo: root.topAnchor),
            statusBarView.leadingAnchor.constraint(equalTo: root.leadingAnchor),
            statusBarView.trailingAnchor.constraint(equalTo: root.trailingAnchor),
            statusBarView.heightAnchor.constraint(equalToConstant: 36),

            separator.topAnchor.constraint(equalTo: statusBarView.bottomAnchor),
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
        // Apply initial content based on current cwd state
        updateContentPane(hasCwd: model.cwd != nil)
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
