import AppKit
import AgentDeckCore

/// 与设计系统 `.wb-stream` / `.wb-col` / `.wb-composer` 对齐的主内容布局度量。
/// inspector 有数据且空间足够时，正文和 composer 都在
/// `24 ... (width - 290)` 区域内居中；无数据或窄于响应式门槛时，左右各保留
/// 24pt，避免一个不可见或放不下的面板继续挤压正文。
enum ConversationLayoutMetrics {
    static let contentMaxWidth: CGFloat = 620
    /// 窄窗仍需留给 composer 的最低可用宽度；低于这一门槛时优先折叠 inspector。
    static let contentMinimumWidth: CGFloat = 252
    static let horizontalInset: CGFloat = 24
    static let inspectorReserve: CGFloat = 290
    static let minimumInspectorPaneWidth = horizontalInset + inspectorReserve + contentMinimumWidth
    static let environmentTop: CGFloat = 12
    static let environmentTrailing: CGFloat = 20
}

// MARK: - ConversationViewController (Task 8)
//
// Assembles the conversation pane from the pieces built in Tasks 2–7:
//
//   • Display rows  : ConversationDisplayRowBuilder.rows(from: makeConversationTurns(…))
//   • Cells/heights : ConversationRowFactory (per-kind reuse ids, makeCell, height)
//   • Height cache  : RowHeightCache (keyed rowId × version × width)
//   • Streaming     : the cells bind StreamingTextBuffer themselves (Task 6/7)
//   • Observation   : ObservationBinder re-arms on every model change
//
// A view-based, virtualized `NSTableView` renders the transcript (only visible
// rows ever own a cell). Below it sit the model-driven error / warning banners
// and the approval card, then the input bar — matching the SwiftUI layout where
// errorRow / warningRow / approvalRow appear at the end of the conversation
// stream just above the bottom input (SessionView.swift ~417-425, ~940).
//
// Selection coordination: the streaming cells embed `CoordinatedStreamingTextView`,
// which registers/clears its own `SessionTextSelectionOwner` through the shared
// `SessionTextSelectionCoordinator` on mouseDown / selectAll (StreamingTextView.swift).
// The controller therefore does NOT manually register NSTextViews — reuse is
// safe because each cell rebinds its own owner in `configure`. The controller
// still holds the shared coordinator reference for clarity and future wiring.
@MainActor
final class ConversationViewController: NSViewController {

    // MARK: Public scroll-spy surface (rail wiring — Task 10/11)

    /// The turnId of the row currently at the top of the viewport (nil when the
    /// transcript is empty). Recomputed on scroll.
    private(set) var topVisibleTurnId: String?

    /// Notified whenever `topVisibleTurnId` changes.
    var onTopVisibleTurnChanged: ((String?) -> Void)?

    // MARK: Dependencies

    private let model: SessionModel
    private let cache = RowHeightCache()
    private let binder = ObservationBinder()
    /// Held for clarity; cells self-register their text views with the shared
    /// coordinator, so the controller does not drive register/unregister.
    private let selectionCoordinator = SessionTextSelectionCoordinator.shared

    // MARK: Event monitor

    /// Local event monitor that clears any active text selection when the user
    /// clicks on empty (non-text) space inside the conversation transcript.
    /// Stored so it can be removed in `deinit`. Marked `nonisolated(unsafe)`
    /// only so the nonisolated deinit can read this non-Sendable `Any?` to
    /// remove the monitor — the controller is set/read on the main thread.
    nonisolated(unsafe) private var emptySpaceClickMonitor: Any?

    // MARK: State

    private var rows: [ConversationDisplayRow] = []
    private var lastScrollToLatestRequest = 0

    /// The `(id, contentVersion)` of every row currently presented by the table.
    /// Compared against a freshly rebuilt sequence in `modelDidChange()` so a
    /// pure streaming-text flush (identical id sequence) skips the full reload
    /// and only re-measures the rows whose content actually grew.
    private var displayedRowSignatures: [(id: String, version: Int)] = []

    /// Per-item disclosure expansion state for the collapsible tool rows
    /// (shell output / fileEdit diff). Held here so it SURVIVES cell reuse and
    /// the streaming reconfigure path (C1): a cell restores its expanded state
    /// from this set in `configure` instead of hard-resetting to collapsed.
    private var expandedItemIds: Set<String> = []

    // MARK: Views

    private let scrollView = NSScrollView()
    private let tableView = NSTableView()
    private lazy var inputBar = InputBarView(model: model)
    private lazy var environmentPanel = CodexEnvironmentPanelView(model: model)
    private let contentRegionGuide = NSLayoutGuide()
    private let contentColumnGuide = NSLayoutGuide()
    private var contentTrailingWithoutInspector: NSLayoutConstraint?
    private var contentTrailingWithInspector: NSLayoutConstraint?
    private var environmentPanelConstraints: [NSLayoutConstraint] = []
    private var isEnvironmentPanelPresented: Bool?
    private let errorCell = ErrorCellView()
    private let warningCell = WarningCellView()
    private let approvalCard = ApprovalCardView()
    private let footerStack: NSStackView = {
        let stack = NSStackView()
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 0
        stack.translatesAutoresizingMaskIntoConstraints = false
        return stack
    }()

    // MARK: Init

    init(model: SessionModel) {
        self.model = model
        super.init(nibName: nil, bundle: nil)
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) is not supported") }

    // MARK: View lifecycle

    /// Stop the observation re-arm loop only when the controller is torn down,
    /// NOT on `viewWillDisappear`. The pane binds once in `loadView`; invalidating
    /// on a transient hide would permanently freeze it on a later show, since
    /// nothing re-binds (I2). This matches `TurnJumpRailView` / `StatusBarView`.
    deinit {
        if let monitor = emptySpaceClickMonitor {
            NSEvent.removeMonitor(monitor)
        }
        let b = binder
        Task { @MainActor in b.invalidate() }
    }

    override func loadView() {
        let root = NSView()
        root.translatesAutoresizingMaskIntoConstraints = false
        root.wantsLayer = true
        root.layer?.backgroundColor = CodexDesktopChrome.windowBackground.cgColor

        configureTableView()
        configureScrollView()
        configureFooter()

        root.addLayoutGuide(contentRegionGuide)
        root.addLayoutGuide(contentColumnGuide)
        root.addSubview(scrollView)
        root.addSubview(footerStack)
        root.addSubview(inputBar)

        scrollView.setAccessibilityIdentifier("conversation-transcript")
        footerStack.setAccessibilityIdentifier("conversation-footer")
        inputBar.setAccessibilityIdentifier("conversation-input-bar")

        // `.wb-col` 与 `.wb-composer` 共用同一个内容列：最大 620pt，在可用区域内
        // 居中。`width == region.width` 只有 defaultHigh，620pt 上限不会反向撑大
        // contentViewController 的 fittingSize，保留“打开会话不放大窗口”的不变量。
        let preferredColumnWidth = contentColumnGuide.widthAnchor.constraint(
            equalTo: contentRegionGuide.widthAnchor
        )
        preferredColumnWidth.priority = .defaultHigh

        let withoutInspector = contentRegionGuide.trailingAnchor.constraint(
            equalTo: root.trailingAnchor,
            constant: -ConversationLayoutMetrics.horizontalInset
        )
        let withInspector = contentRegionGuide.trailingAnchor.constraint(
            equalTo: root.trailingAnchor,
            constant: -ConversationLayoutMetrics.inspectorReserve
        )
        contentTrailingWithoutInspector = withoutInspector
        contentTrailingWithInspector = withInspector

        environmentPanelConstraints = [
            environmentPanel.topAnchor.constraint(
                equalTo: root.topAnchor,
                constant: ConversationLayoutMetrics.environmentTop
            ),
            environmentPanel.trailingAnchor.constraint(
                equalTo: root.trailingAnchor,
                constant: -ConversationLayoutMetrics.environmentTrailing
            ),
        ]

        NSLayoutConstraint.activate([
            contentRegionGuide.leadingAnchor.constraint(
                equalTo: root.leadingAnchor,
                constant: ConversationLayoutMetrics.horizontalInset
            ),

            contentColumnGuide.centerXAnchor.constraint(equalTo: contentRegionGuide.centerXAnchor),
            contentColumnGuide.leadingAnchor.constraint(greaterThanOrEqualTo: contentRegionGuide.leadingAnchor),
            contentColumnGuide.trailingAnchor.constraint(lessThanOrEqualTo: contentRegionGuide.trailingAnchor),
            contentColumnGuide.widthAnchor.constraint(greaterThanOrEqualToConstant: 1),
            contentColumnGuide.widthAnchor.constraint(
                lessThanOrEqualToConstant: ConversationLayoutMetrics.contentMaxWidth
            ),
            preferredColumnWidth,

            scrollView.topAnchor.constraint(equalTo: root.topAnchor),
            scrollView.leadingAnchor.constraint(equalTo: contentColumnGuide.leadingAnchor),
            scrollView.trailingAnchor.constraint(equalTo: contentColumnGuide.trailingAnchor),

            footerStack.topAnchor.constraint(equalTo: scrollView.bottomAnchor),
            footerStack.leadingAnchor.constraint(equalTo: contentColumnGuide.leadingAnchor),
            footerStack.trailingAnchor.constraint(equalTo: contentColumnGuide.trailingAnchor),

            inputBar.topAnchor.constraint(equalTo: footerStack.bottomAnchor),
            inputBar.leadingAnchor.constraint(equalTo: contentColumnGuide.leadingAnchor),
            inputBar.trailingAnchor.constraint(equalTo: contentColumnGuide.trailingAnchor),
            inputBar.bottomAnchor.constraint(equalTo: root.bottomAnchor, constant: -18),
        ])

        self.view = root
        refreshEnvironmentPanelPresentation()

        rebuildRows()
        bindModel()
        observeBoundsChanges()
        installEmptySpaceClickMonitor()
    }

    /// Row heights are width-dependent (wrapped text), but `NSTableView` caches
    /// them and only re-queries on `noteHeightOfRows`. The transcript column
    /// starts at its pre-layout default width (~40pt) when rows first load, so
    /// heights measured then are wildly wrong — a single line of CJK text wraps
    /// to hundreds of points at width ~1, producing a giant user bubble that
    /// never shrinks. Re-measure every row whenever the column width actually
    /// changes (initial tiny → real width, and later window resizes).
    private var lastLaidOutColumnWidth: CGFloat = 0

    override func viewDidLayout() {
        super.viewDidLayout()
        // environmentInfo 有值也不能在窄窗强占 290pt；先按本轮真实宽度决定
        // inspector 是否参与布局，再测量正文列宽。
        refreshEnvironmentPanelPresentation()
        let width = columnWidth
        guard abs(width - lastLaidOutColumnWidth) > 0.5 else { return }
        lastLaidOutColumnWidth = width
        cache.invalidateAll()
        refreshFooter()
        if !rows.isEmpty {
            tableView.noteHeightOfRows(withIndexesChanged: IndexSet(integersIn: 0..<rows.count))
        }
    }

    // MARK: Configuration

    private func configureTableView() {
        tableView.headerView = nil
        tableView.usesAutomaticRowHeights = false
        tableView.backgroundColor = .clear
        tableView.style = .plain
        tableView.intercellSpacing = NSSize(width: 0, height: 0)
        tableView.selectionHighlightStyle = .none
        tableView.gridStyleMask = []
        tableView.rowSizeStyle = .custom
        tableView.columnAutoresizingStyle = .uniformColumnAutoresizingStyle

        let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("conversation"))
        column.resizingMask = .autoresizingMask
        tableView.addTableColumn(column)

        tableView.dataSource = self
        tableView.delegate = self
    }

    private func configureScrollView() {
        scrollView.translatesAutoresizingMaskIntoConstraints = false
        scrollView.documentView = tableView
        scrollView.hasVerticalScroller = true
        scrollView.hasHorizontalScroller = false
        scrollView.autohidesScrollers = true
        scrollView.drawsBackground = false
        scrollView.borderType = .noBorder
    }

    private func configureFooter() {
        errorCell.translatesAutoresizingMaskIntoConstraints = false
        warningCell.translatesAutoresizingMaskIntoConstraints = false
        approvalCard.translatesAutoresizingMaskIntoConstraints = false

        footerStack.addArrangedSubview(errorCell)
        footerStack.addArrangedSubview(warningCell)

        // The approval card draws its own rounded box; inset it horizontally so
        // it does not bleed to the pane edges (mirrors SwiftUI padding).
        let approvalContainer = NSView()
        approvalContainer.translatesAutoresizingMaskIntoConstraints = false
        approvalContainer.addSubview(approvalCard)
        NSLayoutConstraint.activate([
            approvalCard.topAnchor.constraint(equalTo: approvalContainer.topAnchor, constant: 6),
            approvalCard.bottomAnchor.constraint(equalTo: approvalContainer.bottomAnchor, constant: -6),
            approvalCard.leadingAnchor.constraint(equalTo: approvalContainer.leadingAnchor, constant: 20),
            approvalCard.trailingAnchor.constraint(equalTo: approvalContainer.trailingAnchor, constant: -20),
        ])
        footerStack.addArrangedSubview(approvalContainer)

        for view in [errorCell, warningCell] {
            view.leadingAnchor.constraint(equalTo: footerStack.leadingAnchor).isActive = true
            view.trailingAnchor.constraint(equalTo: footerStack.trailingAnchor).isActive = true
        }
        approvalContainer.leadingAnchor.constraint(equalTo: footerStack.leadingAnchor).isActive = true
        approvalContainer.trailingAnchor.constraint(equalTo: footerStack.trailingAnchor).isActive = true

        refreshFooter()
    }

    // MARK: Observation

    /// Bind every model field the pane renders. The binder re-arms after each
    /// change, so one `bind` call tracks them all for the controller's lifetime.
    private func bindModel() {
        binder.bind({ [weak self] in
            guard let self else { return }
            // Touch every observed field so the tracking set covers them all.
            _ = self.model.selectedItems
            _ = self.model.selectedPhase
            _ = self.model.shouldShowReasoningExpanded
            _ = self.model.scrollToLatestRequest
            _ = self.model.selectedActionRequest
            _ = self.model.selectedErrorMessage
            _ = self.model.selectedWarningMessage
            _ = self.model.queuedPrompts
            _ = self.model.environmentInfo
        }, onChange: { [weak self] in
            self?.modelDidChange()
        })
    }

    private func modelDidChange() {
        refreshEnvironmentPanelPresentation()
        let previousExpansion = lastReasoningExpanded
        let previousSignatures = displayedRowSignatures
        rebuildRows()
        // The reasoning rows auto-expand/collapse with the running phase; their
        // height changes when that flips, so drop their cached heights.
        let reasoningFlipped = previousExpansion != model.shouldShowReasoningExpanded
        if reasoningFlipped {
            invalidateReasoningHeights()
        }

        applyRowUpdate(previousSignatures: previousSignatures, reasoningFlipped: reasoningFlipped)

        refreshFooter()
        inputBar.refreshQueuedCount()

        if model.scrollToLatestRequest != lastScrollToLatestRequest {
            lastScrollToLatestRequest = model.scrollToLatestRequest
            scrollToLatestRow()
        }
        recomputeTopVisibleTurn()
    }

    /// Apply the cheapest correct table update for the transition from
    /// `previousSignatures` to the freshly rebuilt `rows`.
    ///
    /// • Same id sequence (pure streaming growth): do NOT reload or reconfigure
    ///   any cell — the visible cells already stream their own buffers. Only
    ///   `noteHeightOfRows` for rows whose content version changed so growing
    ///   text re-lays-out its height. The one exception is the reasoning
    ///   auto-expand flag flipping (running ⇄ idle): the reasoning cells must
    ///   reconfigure to show/hide their body, so those specific rows are
    ///   reloaded (and re-measured) — every other row is left untouched, so a
    ///   disclosure (C1) or selection (C2) elsewhere is never disturbed.
    /// • Structural change (append / remove / reorder): fall back to a full
    ///   `reloadData()`. Disclosure state (C1) is restored from `expandedItemIds`
    ///   and selection (C2) is protected by the streaming-view unchanged guards,
    ///   so the reload no longer destroys user state.
    private func applyRowUpdate(
        previousSignatures: [(id: String, version: Int)],
        reasoningFlipped: Bool
    ) {
        let diff = ConversationRowsDiff.decide(
            previous: previousSignatures,
            next: displayedRowSignatures
        )
        switch diff {
        case .sameRows(let changedIndexes):
            var heightIndexes = IndexSet(changedIndexes)
            if reasoningFlipped {
                // The reasoning rows toggle their visible body with the running
                // phase; reload just those so `configure` re-applies the
                // expansion, then re-measure them.
                let reasoningIndexes = IndexSet(
                    rows.enumerated()
                        .filter { $0.element.item.kind == "reasoning" }
                        .map(\.offset)
                )
                if !reasoningIndexes.isEmpty {
                    tableView.reloadData(
                        forRowIndexes: reasoningIndexes,
                        columnIndexes: IndexSet(integer: 0)
                    )
                    heightIndexes.formUnion(reasoningIndexes)
                }
            }
            if !heightIndexes.isEmpty {
                tableView.noteHeightOfRows(withIndexesChanged: heightIndexes)
            }
        case .structural:
            tableView.reloadData()
            if !rows.isEmpty {
                tableView.noteHeightOfRows(withIndexesChanged: IndexSet(integersIn: 0..<rows.count))
            }
        }
    }

    private var lastReasoningExpanded = false

    private func invalidateReasoningHeights() {
        for row in rows where row.item.kind == "reasoning" {
            cache.invalidate(rowId: row.id)
        }
    }

    private func rebuildRows() {
        let turns = makeConversationTurns(from: model.selectedItems)
        rows = ConversationDisplayRowBuilder.rows(from: turns)
        displayedRowSignatures = rows.map { ($0.id, contentVersion(for: $0)) }
        lastReasoningExpanded = model.shouldShowReasoningExpanded
    }

    private func refreshFooter() {
        if let error = model.selectedErrorMessage {
            errorCell.configure(message: error, width: footerWidth)
            errorCell.isHidden = false
        } else {
            errorCell.isHidden = true
        }

        if let warning = model.selectedWarningMessage {
            warningCell.configure(message: warning, width: footerWidth)
            warningCell.isHidden = false
        } else {
            warningCell.isHidden = true
        }

        if let action = model.selectedActionRequest {
            // T6B: route vendor slot via SessionCapabilities (may be nil briefly
            // until the daemon sends sessionCapabilities — falls back to trunk only).
            let caps = model.workbench.selectedRuntime?.capabilities
            approvalCard.configure(action: action, model: model, capabilities: caps)
            approvalCard.superview?.isHidden = false
        } else {
            approvalCard.superview?.isHidden = true
        }
    }

    private var footerWidth: CGFloat {
        max(footerStack.bounds.width, scrollView.bounds.width, 1)
    }

    /// `environmentInfo == nil` 表示真实应用没有可展示的数据源。即使有数据，
    /// 窄窗不足以同时保留 252pt composer 和 inspector 时也会响应式折叠。
    /// 折叠时把面板移出层级并停用 root 约束，让 260pt 面板不参与 fittingSize，
    /// 同时把内容区域的 trailing reserve 从 290pt 恢复为普通 24pt。
    private func refreshEnvironmentPanelPresentation() {
        guard isViewLoaded else { return }
        let shouldShow = model.environmentInfo != nil
            && view.bounds.width >= ConversationLayoutMetrics.minimumInspectorPaneWidth
        guard isEnvironmentPanelPresented != shouldShow else { return }
        isEnvironmentPanelPresented = shouldShow

        if shouldShow {
            contentTrailingWithoutInspector?.isActive = false
            contentTrailingWithInspector?.isActive = true
            if environmentPanel.superview == nil {
                view.addSubview(environmentPanel)
                NSLayoutConstraint.activate(environmentPanelConstraints)
            }
            environmentPanel.isHidden = false
        } else {
            contentTrailingWithInspector?.isActive = false
            contentTrailingWithoutInspector?.isActive = true
            environmentPanel.isHidden = true
            if environmentPanel.superview != nil {
                NSLayoutConstraint.deactivate(environmentPanelConstraints)
                environmentPanel.removeFromSuperview()
            }
        }
        view.needsLayout = true
    }

    // MARK: Scroll spy

    private func observeBoundsChanges() {
        let clip = scrollView.contentView
        clip.postsBoundsChangedNotifications = true
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(boundsDidChange),
            name: NSView.boundsDidChangeNotification,
            object: clip
        )
    }

    @objc private func boundsDidChange() {
        recomputeTopVisibleTurn()
    }

    // MARK: Empty-space click → clear selection

    /// Install a local left-mouse-down monitor that clears any active text
    /// selection when the user clicks empty space in the transcript.
    ///
    /// Design invariants:
    /// - The monitor is observe-only: it always returns `event` unchanged so
    ///   clicks, scrolling, disclosure toggles and row interactions are never
    ///   consumed.
    /// - Clicks on a `CoordinatedStreamingTextView` (or a descendant of one)
    ///   are left untouched; the text view's own `mouseDown` drives activation.
    /// - Clicks outside the `scrollView` (input bar / sidebar / status bar /
    ///   rail) are ignored — only the transcript area participates.
    private func installEmptySpaceClickMonitor() {
        emptySpaceClickMonitor = NSEvent.addLocalMonitorForEvents(matching: .leftMouseDown) { [weak self] event in
            guard let self else { return event }
            // Only handle events in this controller's window.
            guard let window = self.tableView.window, event.window === window else { return event }

            // Convert the click location into the scroll view's coordinate space
            // and hit-test against the content view hierarchy.
            let locationInWindow = event.locationInWindow
            guard let contentView = window.contentView else { return event }
            let locationInContent = contentView.convert(locationInWindow, from: nil)
            let locationInScrollView = self.scrollView.convert(locationInContent, from: contentView)
            let inTranscript = self.scrollView.bounds.contains(locationInScrollView)

            let hitView = contentView.hitTest(locationInContent)

            if ConversationViewController.shouldClearSelection(forHitView: hitView, inTranscript: inTranscript) {
                self.selectionCoordinator.clearActiveSelection()
            }
            return event
        }
    }

    /// Pure, testable decision: should a click with the given hit view and
    /// transcript-membership clear the active text selection?
    ///
    /// Returns `true` only when the click is inside the transcript area AND the
    /// hit view is NOT a `CoordinatedStreamingTextView` nor a descendant of one
    /// (those handle their own activation via `mouseDown`).
    static func shouldClearSelection(forHitView hitView: NSView?, inTranscript: Bool) -> Bool {
        guard inTranscript else { return false }
        // Walk the superview chain; if we're inside a CoordinatedStreamingTextView
        // do nothing — let the text view's own mouseDown handle it.
        var candidate: NSView? = hitView
        while let view = candidate {
            if view is CoordinatedStreamingTextView { return false }
            candidate = view.superview
        }
        return true
    }

    /// Compute the turnId of the row at the top of the viewport and publish it
    /// to the rail when it changes.
    private func recomputeTopVisibleTurn() {
        let topY = scrollView.contentView.bounds.origin.y
        let topRow = tableView.row(at: NSPoint(x: 0, y: topY))
        let turnId: String?
        if topRow >= 0, rows.indices.contains(topRow) {
            turnId = rows[topRow].turnId
        } else {
            turnId = rows.first?.turnId
        }
        if turnId != topVisibleTurnId {
            topVisibleTurnId = turnId
            onTopVisibleTurnChanged?(turnId)
        }
    }

    private func scrollToLatestRow() {
        guard !rows.isEmpty else { return }
        tableView.scrollRowToVisible(rows.count - 1)
    }

    // MARK: Public scroll API (rail wiring — Task 11)

    /// Scroll the row whose `turnId` matches `turnId` into view.
    /// No-op when no matching row exists or the transcript is empty.
    func scrollToTurn(_ turnId: String) {
        guard let index = rows.firstIndex(where: { $0.turnId == turnId }) else { return }
        tableView.scrollRowToVisible(index)
    }

    /// Public wrapper over the private `scrollToLatestRow()`.
    /// Used by `TurnJumpRailView.onJumpToLatest` (Task 11).
    func scrollToLatest() {
        scrollToLatestRow()
    }

    // MARK: Height helpers

    private var columnWidth: CGFloat {
        if let column = tableView.tableColumns.first, column.width > 0 {
            return column.width
        }
        return max(tableView.bounds.width, scrollView.contentView.bounds.width, 1)
    }

    /// A coarse content version for the height cache: changes whenever the
    /// rendered text length changes (streaming append, replace, or disclosure
    /// expansion state for reasoning). Combined with rowId × width, this keeps
    /// the cache fresh without per-token invalidation.
    private func contentVersion(for row: ConversationDisplayRow) -> Int {
        let item = row.item
        var version = item.textBuffer.text.utf8.count
        version = version &* 31 &+ item.outputBuffer.text.utf8.count
        version = version &* 31 &+ item.diffBuffer.text.utf8.count
        version = version &* 31 &+ item.descriptionText.utf8.count
        if row.item.kind == "reasoning", model.shouldShowReasoningExpanded {
            version = version &* 31 &+ 1  // distinct key for the expanded body
        }
        // A collapsible row that the user expanded measures taller (its body is
        // included). Fold the expanded flag into the version so the height cache
        // re-measures when it flips. (C1)
        if (item.kind == "shell" || item.kind == "fileEdit" || item.kind == "toolCall"),
           expandedItemIds.contains(item.id) {
            version = version &* 31 &+ 2
        }
        return version
    }

    /// Row height = factory height, plus — for reasoning rows that are
    /// auto-expanded while the turn runs — the streamed body the factory leaves
    /// out (it only counts the collapsed header). Mirrors `ReasoningCellView`,
    /// which expands when `model.shouldShowReasoningExpanded` is true.
    private func computeHeight(for row: ConversationDisplayRow, width: CGFloat) -> CGFloat {
        var height = ConversationRowFactory.height(for: row, width: width)
        if row.item.kind == "reasoning", model.shouldShowReasoningExpanded {
            height += reasoningExpandedBodyHeight(for: row, width: width)
        }
        // The factory counts only the collapsed disclosure header for shell /
        // fileEdit / toolCall rows; when the user has expanded one, add its body
        // (output / diff / JSON payload) so the row reserves room for it. (C1)
        if expandedItemIds.contains(row.item.id) {
            height += disclosureBodyHeight(for: row, width: width)
        }
        return height
    }

    /// Height of an expanded shell-output / fileEdit-diff body, measured the
    /// same way the factory measures wrapped monospaced text. The contentStack
    /// uses a 4pt gap before the body (matching the cells' `spacing = 4`).
    private func disclosureBodyHeight(for row: ConversationDisplayRow, width: CGFloat) -> CGFloat {
        let item = row.item
        let text: String
        let font: NSFont
        switch item.kind {
        case "shell":
            text = item.outputBuffer.text
            font = .monospacedSystemFont(ofSize: 13, weight: .regular)
        case "fileEdit":
            text = item.diffBuffer.text
            font = .monospacedSystemFont(ofSize: 12, weight: .regular)
        case "toolCall":
            // 展开后显示美化 JSON（payloadLabel 用 monoCaptionFont，stack 间距 5）。
            let payload = ToolPresentation.toolPayload(item)
            guard !payload.isEmpty else { return 0 }
            let contentW = max(width - ConversationRowCellView.horizontalInset * 2, 1)
            let attributed = NSAttributedString(
                string: payload, attributes: [.font: ConversationRowMetrics.monoCaptionFont])
            return 5 + measuredTextHeight(attributed, width: contentW)
        default:
            return 0
        }
        guard !text.isEmpty else { return 0 }
        let contentW = max(width - ConversationRowCellView.horizontalInset * 2, 1)
        let attributed = NSAttributedString(string: text, attributes: [.font: font])
        return 4 + measuredTextHeight(attributed, width: contentW)
    }

    /// Height of the auto-expanded reasoning body (small secondary streaming
    /// text), measured the same way the factory measures wrapped text. The
    /// contentStack spacing (5) precedes the body.
    private func reasoningExpandedBodyHeight(for row: ConversationDisplayRow, width: CGFloat) -> CGFloat {
        let text = row.item.textBuffer.text
        guard !text.isEmpty else { return 0 }
        let contentW = max(width - ConversationRowCellView.horizontalInset * 2, 1)
        let font = NSFont.systemFont(ofSize: NSFont.smallSystemFontSize)
        let attributed = NSAttributedString(string: text, attributes: [.font: font])
        return 5 + measuredTextHeight(attributed, width: contentW)
    }

    // MARK: Cell registration

    private func dequeueCell(for row: ConversationDisplayRow) -> NSTableCellView {
        let identifier = ConversationRowFactory.reuseIdentifier(for: row)
        if let reused = tableView.makeView(withIdentifier: identifier, owner: self) as? NSTableCellView {
            return reused
        }
        // `makeCell` already stamps the reuse identifier, so the table can
        // recycle this cell on its next `makeView(withIdentifier:)`.
        return ConversationRowFactory.makeCell(for: row)
    }
}

// MARK: - NSTableViewDataSource

extension ConversationViewController: NSTableViewDataSource {
    func numberOfRows(in tableView: NSTableView) -> Int {
        rows.count
    }
}

// MARK: - NSTableViewDelegate

extension ConversationViewController: NSTableViewDelegate {
    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        guard rows.indices.contains(row) else { return nil }
        let displayRow = rows[row]
        let cell = dequeueCell(for: displayRow)
        if let conversationCell = cell as? ConversationRowCellView {
            // Hand the cell the persisted disclosure store BEFORE configuring so
            // collapsible cells (shell / fileEdit) restore their expansion (C1).
            conversationCell.disclosureStore = self
            conversationCell.configure(row: displayRow, width: columnWidth, model: model)
        }
        return cell
    }

    func tableView(_ tableView: NSTableView, heightOfRow row: Int) -> CGFloat {
        guard rows.indices.contains(row) else { return 1 }
        let displayRow = rows[row]
        let width = columnWidth
        return cache.height(
            rowId: displayRow.id,
            version: contentVersion(for: displayRow),
            width: width
        ) { [weak self] in
            guard let self else { return 1 }
            return self.computeHeight(for: displayRow, width: width)
        }
    }

    func tableView(_ tableView: NSTableView, shouldSelectRow row: Int) -> Bool {
        false
    }
}

// MARK: - ConversationDisclosureStateStore (C1)

extension ConversationViewController: ConversationDisclosureStateStore {
    func isItemExpanded(_ itemId: String) -> Bool {
        expandedItemIds.contains(itemId)
    }

    /// Persist the toggle, then re-measure the affected row so the table opens /
    /// closes room for the disclosure body. The cell itself already showed /
    /// hid the body; this only updates the reserved height.
    func setItem(_ itemId: String, expanded: Bool) {
        let changed: Bool
        if expanded {
            changed = expandedItemIds.insert(itemId).inserted
        } else {
            changed = expandedItemIds.remove(itemId) != nil
        }
        guard changed else { return }

        var indexes = IndexSet()
        for (offset, row) in rows.enumerated() where row.item.id == itemId {
            cache.invalidate(rowId: row.id)
            // Keep the cached signature in sync so the next streaming flush sees
            // the new expanded version and does not force a redundant reload.
            if displayedRowSignatures.indices.contains(offset) {
                displayedRowSignatures[offset].version = contentVersion(for: row)
            }
            indexes.insert(offset)
        }
        if !indexes.isEmpty {
            tableView.noteHeightOfRows(withIndexesChanged: indexes)
        }
    }
}
