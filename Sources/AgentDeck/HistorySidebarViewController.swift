import AppKit

/// NSOutlineView-based history sidebar (source list style).
/// Reproduces the SwiftUI `historySidebar` / `historyGroup` / `historyThreadRow`
/// visual treatment from SessionView.swift (lines 130–377) in pure AppKit.
///
/// Two levels of hierarchy:
///   - Top level : HistoryProjectGroup  → group row (non-selectable)
///   - Children  : HistoryThreadSummary → thread row (selectable)
///
/// Uses ObservationBinder to watch `model.historyGroups`,
/// `model.workbench.runtimes`, and the workbench's selected/opening state so
/// that runtime phase dots and unread indicators stay live.
@MainActor
final class HistorySidebarViewController: NSViewController {

    // MARK: - Dependencies

    private let model: SessionModel

    // MARK: - Subviews

    private let headerLabel: NSTextField = {
        let label = NSTextField(labelWithString: "History")
        label.font = .systemFont(ofSize: 13, weight: .semibold)
        label.translatesAutoresizingMaskIntoConstraints = false
        return label
    }()

    private let refreshButton: NSButton = {
        let btn = NSButton()
        btn.bezelStyle = .inline
        btn.isBordered = false
        btn.image = NSImage(systemSymbolName: "arrow.clockwise", accessibilityDescription: "Refresh history")
        btn.toolTip = "Refresh history"
        btn.translatesAutoresizingMaskIntoConstraints = false
        return btn
    }()

    private let searchField: NSSearchField = {
        let sf = NSSearchField()
        sf.placeholderString = "Search threads"
        sf.translatesAutoresizingMaskIntoConstraints = false
        return sf
    }()

    /// Shown while isLoadingHistory
    private let loadingIndicator: NSProgressIndicator = {
        let pi = NSProgressIndicator()
        pi.style = .spinning
        pi.controlSize = .small
        pi.isIndeterminate = true
        pi.isHidden = true
        pi.translatesAutoresizingMaskIntoConstraints = false
        return pi
    }()

    /// Shown on error
    private let errorLabel: NSTextField = {
        let label = NSTextField(wrappingLabelWithString: "")
        label.font = .systemFont(ofSize: NSFont.smallSystemFontSize - 1)
        label.textColor = .systemRed
        label.isSelectable = true
        label.isHidden = true
        label.translatesAutoresizingMaskIntoConstraints = false
        return label
    }()

    /// Shown when history is empty (and not loading or errored)
    private let emptyStateLabel: NSTextField = {
        let label = NSTextField(wrappingLabelWithString: "No history loaded\nRefresh to scan persisted agent threads.")
        label.font = .systemFont(ofSize: NSFont.systemFontSize)
        label.textColor = .secondaryLabelColor
        label.isHidden = true
        label.translatesAutoresizingMaskIntoConstraints = false
        return label
    }()

    private lazy var scrollView: NSScrollView = {
        let sv = NSScrollView()
        sv.hasVerticalScroller = true
        sv.autohidesScrollers = true
        sv.documentView = outlineView
        sv.translatesAutoresizingMaskIntoConstraints = false
        return sv
    }()

    private lazy var outlineView: NSOutlineView = {
        let ov = NSOutlineView()
        ov.style = .sourceList
        ov.headerView = nil          // no column header
        ov.rowHeight = 52
        ov.intercellSpacing = NSSize(width: 0, height: 2)
        ov.indentationPerLevel = 0   // groups are not indented relative to root
        ov.autoresizesOutlineColumn = false

        let col = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("main"))
        col.isEditable = false
        ov.addTableColumn(col)
        ov.outlineTableColumn = col

        ov.dataSource = nil  // set after init
        ov.delegate   = nil
        return ov
    }()

    // MARK: - Observation

    private let binder = ObservationBinder()

    // MARK: - Init

    init(model: SessionModel) {
        self.model = model
        super.init(nibName: nil, bundle: nil)
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) not supported")
    }

    // MARK: - View Life Cycle

    override func loadView() {
        let container = NSView()
        container.translatesAutoresizingMaskIntoConstraints = false
        view = container

        // Header row
        let headerRow = NSStackView(views: [headerLabel, NSView(), refreshButton])
        headerRow.orientation = .horizontal
        headerRow.spacing = 8
        headerRow.translatesAutoresizingMaskIntoConstraints = false
        headerRow.setContentHuggingPriority(.defaultHigh, for: .vertical)
        // Let the spacer expand
        headerRow.views[1].translatesAutoresizingMaskIntoConstraints = false
        headerRow.setHuggingPriority(.defaultLow, for: .horizontal)

        container.addSubview(headerRow)
        container.addSubview(searchField)
        container.addSubview(loadingIndicator)
        container.addSubview(errorLabel)
        container.addSubview(emptyStateLabel)
        container.addSubview(scrollView)

        NSLayoutConstraint.activate([
            // Header
            headerRow.topAnchor.constraint(equalTo: container.topAnchor, constant: 12),
            headerRow.leadingAnchor.constraint(equalTo: container.leadingAnchor, constant: 12),
            headerRow.trailingAnchor.constraint(equalTo: container.trailingAnchor, constant: -12),

            // Search field
            searchField.topAnchor.constraint(equalTo: headerRow.bottomAnchor, constant: 8),
            searchField.leadingAnchor.constraint(equalTo: container.leadingAnchor, constant: 12),
            searchField.trailingAnchor.constraint(equalTo: container.trailingAnchor, constant: -12),

            // Loading indicator
            loadingIndicator.topAnchor.constraint(equalTo: searchField.bottomAnchor, constant: 12),
            loadingIndicator.centerXAnchor.constraint(equalTo: container.centerXAnchor),

            // Error label
            errorLabel.topAnchor.constraint(equalTo: searchField.bottomAnchor, constant: 8),
            errorLabel.leadingAnchor.constraint(equalTo: container.leadingAnchor, constant: 12),
            errorLabel.trailingAnchor.constraint(equalTo: container.trailingAnchor, constant: -12),

            // Empty-state label
            emptyStateLabel.topAnchor.constraint(equalTo: searchField.bottomAnchor, constant: 12),
            emptyStateLabel.leadingAnchor.constraint(equalTo: container.leadingAnchor, constant: 12),
            emptyStateLabel.trailingAnchor.constraint(equalTo: container.trailingAnchor, constant: -12),

            // Outline scroll view
            scrollView.topAnchor.constraint(equalTo: searchField.bottomAnchor, constant: 8),
            scrollView.leadingAnchor.constraint(equalTo: container.leadingAnchor),
            scrollView.trailingAnchor.constraint(equalTo: container.trailingAnchor),
            scrollView.bottomAnchor.constraint(equalTo: container.bottomAnchor),
        ])

        outlineView.dataSource = self
        outlineView.delegate   = self

        refreshButton.target = self
        refreshButton.action = #selector(refreshTapped)

        searchField.target = self
        searchField.action = #selector(searchChanged)
        searchField.delegate = self

        // Reopen all groups by default after data load
        updateVisibility()
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        bindObservations()
    }

    // MARK: - Observation Binding

    private func bindObservations() {
        // Bind to historyGroups, isLoadingHistory, historyErrorMessage, workbench runtimes
        binder.bind { [weak self] in
            guard let self else { return }
            // Access all observed properties to establish tracking
            _ = self.model.historyGroups
            _ = self.model.isLoadingHistory
            _ = self.model.historyErrorMessage
            _ = self.model.openingHistoryThreadId
            _ = self.model.selectedHistoryThreadId
            // Also track runtime phases + unread counts
            for (_, runtime) in self.model.workbench.runtimes {
                _ = runtime.phase
                _ = runtime.unreadEventCount
            }
            _ = self.model.workbench.runtimes
        } onChange: { [weak self] in
            self?.reloadOutline()
        }
    }

    override func viewWillDisappear() {
        super.viewWillDisappear()
        binder.invalidate()
    }

    // MARK: - Data Helpers

    private var groups: [HistoryProjectGroup] { model.historyGroups }

    // MARK: - Reload

    private func reloadOutline() {
        outlineView.reloadData()
        expandAllGroups()
        updateVisibility()
        syncRefreshButton()
    }

    private func expandAllGroups() {
        for i in 0..<groups.count {
            outlineView.expandItem(groups[i])
        }
    }

    private func updateVisibility() {
        let loading = model.isLoadingHistory
        let hasError = model.historyErrorMessage != nil
        let isEmpty  = model.historyGroups.isEmpty

        loadingIndicator.isHidden = !loading
        if loading { loadingIndicator.startAnimation(nil) } else { loadingIndicator.stopAnimation(nil) }

        errorLabel.isHidden = !hasError
        if let err = model.historyErrorMessage { errorLabel.stringValue = err }

        // Empty state only when done loading, no error, and really empty
        emptyStateLabel.isHidden = loading || hasError || !isEmpty

        scrollView.isHidden = loading || hasError || isEmpty
    }

    private func syncRefreshButton() {
        refreshButton.isEnabled = !model.isLoadingHistory
    }

    // MARK: - Actions

    @objc private func refreshTapped() {
        model.loadHistory()
    }

    @objc private func searchChanged() {
        model.historySearchTerm = searchField.stringValue
        model.loadHistory()
    }

    // MARK: - Context Menu (Rename / Archive)

    private func showRenameAlert(for thread: HistoryThreadSummary) {
        let alert = NSAlert()
        alert.messageText = "Rename Thread"
        alert.informativeText = "Enter a new name for this thread."
        alert.addButton(withTitle: "Rename")
        alert.addButton(withTitle: "Cancel")

        let inputField = NSTextField(frame: NSRect(x: 0, y: 0, width: 260, height: 24))
        inputField.stringValue = thread.displayTitle
        inputField.selectText(nil)
        alert.accessoryView = inputField

        let response = alert.runModal()
        if response == .alertFirstButtonReturn {
            let newName = inputField.stringValue
            model.renameHistoryThread(thread, name: newName)
        }
    }
}

// MARK: - NSOutlineViewDataSource

extension HistorySidebarViewController: NSOutlineViewDataSource {

    func outlineView(_ outlineView: NSOutlineView, numberOfChildrenOfItem item: Any?) -> Int {
        if item == nil {
            return groups.count
        }
        if let group = item as? HistoryProjectGroup {
            return group.threads.count
        }
        return 0
    }

    func outlineView(_ outlineView: NSOutlineView, child index: Int, ofItem item: Any?) -> Any {
        if item == nil {
            return groups[index]
        }
        if let group = item as? HistoryProjectGroup {
            return group.threads[index]
        }
        // Unreachable in practice; return an empty placeholder
        return groups[0]
    }

    func outlineView(_ outlineView: NSOutlineView, isItemExpandable item: Any) -> Bool {
        item is HistoryProjectGroup
    }
}

// MARK: - NSOutlineViewDelegate

extension HistorySidebarViewController: NSOutlineViewDelegate {

    // MARK: View-based cell construction

    func outlineView(_ outlineView: NSOutlineView, viewFor tableColumn: NSTableColumn?, item: Any) -> NSView? {
        if let group = item as? HistoryProjectGroup {
            return makeGroupView(outlineView, group: group)
        }
        if let thread = item as? HistoryThreadSummary {
            return makeThreadView(outlineView, thread: thread)
        }
        return nil
    }

    private func makeGroupView(_ ov: NSOutlineView, group: HistoryProjectGroup) -> NSView {
        let id = NSUserInterfaceItemIdentifier("group-cell")
        if let recycled = ov.makeView(withIdentifier: id, owner: nil) as? HistoryGroupRowView {
            recycled.configure(with: group)
            recycled.onAdd = { [weak self] in
                self?.model.startNewSession(inProjectCwd: group.cwd)
            }
            return recycled
        }
        let cellView = HistoryGroupRowView()
        cellView.identifier = id
        cellView.configure(with: group)
        cellView.onAdd = { [weak self] in
            self?.model.startNewSession(inProjectCwd: group.cwd)
        }
        return cellView
    }

    private func makeThreadView(_ ov: NSOutlineView, thread: HistoryThreadSummary) -> NSView {
        let id = NSUserInterfaceItemIdentifier("thread-cell")
        let runtime = model.workbench.runtime(sessionId: thread.id)
        let presentation = HistoryThreadRowPresentation(
            threadId: thread.id,
            selectedThreadId: model.selectedHistoryThreadId,
            openingThreadId: model.openingHistoryThreadId,
            hoveredThreadId: nil,   // hover tracking is NSOutlineView's built-in highlight
            modelProvider: thread.modelProvider,
            source: thread.source,
            runtimePhase: runtime?.phase,
            unreadEventCount: runtime?.unreadEventCount ?? 0
        )

        let cellView: HistoryThreadRowView
        if let recycled = ov.makeView(withIdentifier: id, owner: nil) as? HistoryThreadRowView {
            cellView = recycled
        } else {
            cellView = HistoryThreadRowView()
            cellView.identifier = id
        }
        cellView.configure(with: thread, presentation: presentation)
        return cellView
    }

    // MARK: Row height

    func outlineView(_ outlineView: NSOutlineView, heightOfRowByItem item: Any) -> CGFloat {
        if item is HistoryProjectGroup { return 28 }
        return 52
    }

    // MARK: Group rows should not be selectable

    func outlineView(_ outlineView: NSOutlineView, shouldSelectItem item: Any) -> Bool {
        item is HistoryThreadSummary
    }

    // MARK: Selection

    func outlineViewSelectionDidChange(_ notification: Notification) {
        let row = outlineView.selectedRow
        guard row >= 0 else { return }
        if let thread = outlineView.item(atRow: row) as? HistoryThreadSummary {
            model.openHistoryThread(thread)
        }
    }

    // MARK: Row / group appearance

    func outlineView(_ outlineView: NSOutlineView, isGroupItem item: Any) -> Bool {
        item is HistoryProjectGroup
    }

    // MARK: Context Menu

    func outlineView(_ outlineView: NSOutlineView, menuFor tableColumn: NSTableColumn?, item: Any, event: NSEvent) -> NSMenu? {
        guard let thread = item as? HistoryThreadSummary else { return nil }
        let menu = NSMenu()

        let renameItem = NSMenuItem(title: "Rename", action: #selector(handleRename(_:)), keyEquivalent: "")
        renameItem.target = self
        renameItem.representedObject = thread
        menu.addItem(renameItem)

        let archiveItem = NSMenuItem(title: "Archive", action: #selector(handleArchive(_:)), keyEquivalent: "")
        archiveItem.target = self
        archiveItem.representedObject = thread
        menu.addItem(archiveItem)

        return menu
    }

    @objc private func handleRename(_ sender: NSMenuItem) {
        guard let thread = sender.representedObject as? HistoryThreadSummary else { return }
        showRenameAlert(for: thread)
    }

    @objc private func handleArchive(_ sender: NSMenuItem) {
        guard let thread = sender.representedObject as? HistoryThreadSummary else { return }
        model.archiveHistoryThread(thread)
    }
}

// MARK: - NSSearchFieldDelegate

extension HistorySidebarViewController: NSSearchFieldDelegate {
    func controlTextDidChange(_ obj: Notification) {
        guard let sf = obj.object as? NSSearchField else { return }
        model.historySearchTerm = sf.stringValue
        // Debouncing intentionally omitted — mirrors the SwiftUI onChange behaviour
        // which calls loadHistory via .onSubmit / binding. Drive explicit reload here.
        model.loadHistory()
    }
}
