import AppKit

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

    // MARK: State

    private var rows: [ConversationDisplayRow] = []
    private var lastScrollToLatestRequest = 0
    private var registeredReuseIdentifiers: Set<String> = []

    // MARK: Views

    private let scrollView = NSScrollView()
    private let tableView = NSTableView()
    private lazy var inputBar = InputBarView(model: model)
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

    /// Stop the observation re-arm loop when the pane goes away. The binder is
    /// owned by this controller and its `onChange` already guards `[weak self]`,
    /// so an orphaned callback is a harmless no-op; invalidating here also stops
    /// the re-arm so nothing lingers.
    override func viewWillDisappear() {
        super.viewWillDisappear()
        binder.invalidate()
    }

    override func loadView() {
        let root = NSView()
        root.translatesAutoresizingMaskIntoConstraints = false

        configureTableView()
        configureScrollView()
        configureFooter()

        root.addSubview(scrollView)
        root.addSubview(footerStack)
        root.addSubview(inputBar)

        NSLayoutConstraint.activate([
            scrollView.topAnchor.constraint(equalTo: root.topAnchor),
            scrollView.leadingAnchor.constraint(equalTo: root.leadingAnchor),
            scrollView.trailingAnchor.constraint(equalTo: root.trailingAnchor),

            footerStack.topAnchor.constraint(equalTo: scrollView.bottomAnchor),
            footerStack.leadingAnchor.constraint(equalTo: root.leadingAnchor),
            footerStack.trailingAnchor.constraint(equalTo: root.trailingAnchor),

            inputBar.topAnchor.constraint(equalTo: footerStack.bottomAnchor),
            inputBar.leadingAnchor.constraint(equalTo: root.leadingAnchor),
            inputBar.trailingAnchor.constraint(equalTo: root.trailingAnchor),
            inputBar.bottomAnchor.constraint(equalTo: root.bottomAnchor),
        ])

        self.view = root

        rebuildRows()
        bindModel()
        observeBoundsChanges()
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
        }, onChange: { [weak self] in
            self?.modelDidChange()
        })
    }

    private func modelDidChange() {
        let previousExpansion = lastReasoningExpanded
        rebuildRows()
        // The reasoning rows auto-expand/collapse with the running phase; their
        // height changes when that flips, so drop their cached heights.
        if previousExpansion != model.shouldShowReasoningExpanded {
            invalidateReasoningHeights()
        }
        tableView.reloadData()
        if !rows.isEmpty {
            tableView.noteHeightOfRows(withIndexesChanged: IndexSet(integersIn: 0..<rows.count))
        }
        refreshFooter()
        inputBar.refreshQueuedCount()

        if model.scrollToLatestRequest != lastScrollToLatestRequest {
            lastScrollToLatestRequest = model.scrollToLatestRequest
            scrollToLatestRow()
        }
        recomputeTopVisibleTurn()
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
            approvalCard.configure(action: action, model: model)
            approvalCard.superview?.isHidden = false
        } else {
            approvalCard.superview?.isHidden = true
        }
    }

    private var footerWidth: CGFloat {
        max(view.bounds.width, 1)
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
        return height
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
        let cell = ConversationRowFactory.makeCell(for: row)
        cell.identifier = identifier
        registeredReuseIdentifiers.insert(identifier.rawValue)
        return cell
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
