import AppKit
import AgentDeckCore

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
        let label = NSTextField(labelWithString: "项目")
        label.font = .systemFont(ofSize: 12, weight: .medium)
        label.textColor = DesignTokens.text2
        label.translatesAutoresizingMaskIntoConstraints = false
        return label
    }()


    /// T6B: "+ New Session" — when set, the sidebar shows a plus button beside
    /// Refresh and invokes the closure when tapped (SessionViewController
    /// presents `NewSessionDialog`).
    var onNewSessionRequested: (() -> Void)?
    private let newSessionButton: NSButton = {
        let btn = NSButton()
        btn.bezelStyle = .inline
        btn.isBordered = false
        btn.image = NSImage(systemSymbolName: "plus", accessibilityDescription: "New session")
        btn.toolTip = "New session"
        // 显式灰色 + 关焦点环：inline 按钮拿到键盘焦点时会显蓝色高亮，关掉。
        btn.contentTintColor = DesignTokens.text3
        btn.focusRingType = .none
        btn.translatesAutoresizingMaskIntoConstraints = false
        return btn
    }()

    private let searchField: NSSearchField = {
        let sf = NSSearchField()
        sf.placeholderString = "搜索会话"
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
        label.textColor = DesignTokens.danger
        label.isSelectable = true
        label.isHidden = true
        label.translatesAutoresizingMaskIntoConstraints = false
        return label
    }()

    /// Shown when history is empty (and not loading or errored)
    private let emptyStateLabel: NSTextField = {
        let label = NSTextField(wrappingLabelWithString: "暂无历史\n刷新以扫描已持久化的 agent 会话。")
        label.font = .systemFont(ofSize: NSFont.systemFontSize)
        label.textColor = DesignTokens.text2
        label.isHidden = true
        label.translatesAutoresizingMaskIntoConstraints = false
        return label
    }()

    private lazy var scrollView: NSScrollView = {
        let sv = NSScrollView()
        sv.hasVerticalScroller = true
        sv.autohidesScrollers = true
        sv.drawsBackground = false   // 让侧栏容器底色透过，不自绘浅色/黑底
        sv.documentView = outlineView
        sv.translatesAutoresizingMaskIntoConstraints = false
        return sv
    }()

    private lazy var outlineView: NSOutlineView = {
        let ov = NSOutlineView()
        ov.style = .sourceList
        ov.headerView = nil          // no column header
        ov.rowHeight = 36
        ov.intercellSpacing = NSSize(width: 0, height: 2)
        ov.indentationPerLevel = 0   // groups are not indented relative to root
        ov.autoresizesOutlineColumn = false
        // 侧栏固定深色底，outline 用同色避免透出黑带
        ov.backgroundColor = CodexDesktopChrome.sidebarSolid
        ov.floatsGroupRows = false
        // 关掉内建满宽高亮：设计里选中/悬停是内缩圆角块，由 HistoryThreadRowView 自绘。
        ov.selectionHighlightStyle = .none

        let col = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("main"))
        col.isEditable = false
        ov.addTableColumn(col)
        ov.outlineTableColumn = col

        ov.dataSource = nil  // set after init
        ov.delegate   = nil
        return ov
    }()

    /// Right-click context menu shared by all thread rows. Its items are
    /// rebuilt in `menuNeedsUpdate(_:)` against the clicked row so Rename /
    /// Archive carry the correct thread.
    private let contextMenu = NSMenu()

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
        container.wantsLayer = true
        // 固定深色（跨屏一致）。behindWindow 毛玻璃在外接显示器上不可靠地退化为不透明，
        // 且真透明必然随各屏桌面变化——故用实色。颜色贴近之前压暗后认可的观感，单值可调。
        container.layer?.backgroundColor = CodexDesktopChrome.sidebarSolid.cgColor
        view = container

        let topActions = makeTopActions()

        // Header row
        newSessionButton.target = self
        newSessionButton.action = #selector(handleNewSession)
        let headerRow = NSStackView(views: [headerLabel, NSView(), newSessionButton])
        headerRow.orientation = .horizontal
        headerRow.spacing = 8
        headerRow.translatesAutoresizingMaskIntoConstraints = false
        headerRow.setContentHuggingPriority(.defaultHigh, for: .vertical)
        // Let the spacer expand
        headerRow.views[1].translatesAutoresizingMaskIntoConstraints = false
        headerRow.setHuggingPriority(.defaultLow, for: .horizontal)

        let accountFooter = makeAccountFooter()

        searchField.isHidden = true

        container.addSubview(topActions)
        container.addSubview(headerRow)
        container.addSubview(searchField)
        container.addSubview(loadingIndicator)
        container.addSubview(errorLabel)
        container.addSubview(emptyStateLabel)
        container.addSubview(scrollView)
        container.addSubview(accountFooter)

        NSLayoutConstraint.activate([
            // 设计系统 .wb-side padding-top:44 + .wb-side__actions padding:6 10 → 顶起 50、水平 10
            topActions.topAnchor.constraint(equalTo: container.topAnchor, constant: 50),
            topActions.leadingAnchor.constraint(equalTo: container.leadingAnchor, constant: 18),
            topActions.trailingAnchor.constraint(equalTo: container.trailingAnchor, constant: -18),

            // Header（设计 .wb-side__title padding:14 16 6 → 上 14、水平 16）
            headerRow.topAnchor.constraint(equalTo: topActions.bottomAnchor, constant: 14),
            headerRow.leadingAnchor.constraint(equalTo: container.leadingAnchor, constant: 16),
            headerRow.trailingAnchor.constraint(equalTo: container.trailingAnchor, constant: -16),

            // Search field
            searchField.topAnchor.constraint(equalTo: headerRow.bottomAnchor, constant: 8),
            searchField.leadingAnchor.constraint(equalTo: container.leadingAnchor, constant: 12),
            searchField.trailingAnchor.constraint(equalTo: container.trailingAnchor, constant: -12),
            searchField.heightAnchor.constraint(equalToConstant: 0),

            // Loading indicator
            loadingIndicator.topAnchor.constraint(equalTo: headerRow.bottomAnchor, constant: 12),
            loadingIndicator.centerXAnchor.constraint(equalTo: container.centerXAnchor),

            // Error label
            errorLabel.topAnchor.constraint(equalTo: headerRow.bottomAnchor, constant: 8),
            errorLabel.leadingAnchor.constraint(equalTo: container.leadingAnchor, constant: 12),
            errorLabel.trailingAnchor.constraint(equalTo: container.trailingAnchor, constant: -12),

            // Empty-state label
            emptyStateLabel.topAnchor.constraint(equalTo: headerRow.bottomAnchor, constant: 12),
            emptyStateLabel.leadingAnchor.constraint(equalTo: container.leadingAnchor, constant: 12),
            emptyStateLabel.trailingAnchor.constraint(equalTo: container.trailingAnchor, constant: -12),

            // Outline scroll view
            scrollView.topAnchor.constraint(equalTo: headerRow.bottomAnchor, constant: 10),
            scrollView.leadingAnchor.constraint(equalTo: container.leadingAnchor),
            scrollView.trailingAnchor.constraint(equalTo: container.trailingAnchor),
            scrollView.bottomAnchor.constraint(equalTo: accountFooter.topAnchor, constant: -10),

            accountFooter.leadingAnchor.constraint(equalTo: container.leadingAnchor, constant: 14),
            accountFooter.trailingAnchor.constraint(equalTo: container.trailingAnchor, constant: -14),
            accountFooter.bottomAnchor.constraint(equalTo: container.bottomAnchor, constant: -14),
            accountFooter.heightAnchor.constraint(equalToConstant: 44),
        ])

        outlineView.dataSource = self
        outlineView.delegate   = self

        // Real AppKit context-menu wiring: assign an NSMenu whose delegate
        // rebuilds items per clicked row (a `menuFor:` delegate method does NOT
        // exist in any AppKit protocol and would never fire).
        contextMenu.delegate = self
        outlineView.menu = contextMenu

        // Search is driven solely by NSSearchFieldDelegate.controlTextDidChange;
        // no target/action so each keystroke only reloads once.
        searchField.delegate = self

        // Reopen all groups by default after data load
        updateVisibility()
    }

    private func makeTopActions() -> NSStackView {
        let actions: [(String, String)] = [
            ("square.and.pencil", "新对话"),
            ("magnifyingglass", "搜索"),
            ("clock", "已安排"),
            ("puzzlepiece.extension", "插件"),
        ]
        let views = actions.map { symbol, title in
            let icon = NSImageView(image: NSImage(systemSymbolName: symbol, accessibilityDescription: nil) ?? NSImage())
            icon.contentTintColor = DesignTokens.text2
            icon.translatesAutoresizingMaskIntoConstraints = false
            let label = NSTextField(labelWithString: title)
            label.font = .systemFont(ofSize: 13, weight: .medium)
            label.textColor = DesignTokens.text
            label.translatesAutoresizingMaskIntoConstraints = false
            let row = NSStackView(views: [icon, label])
            row.orientation = .horizontal
            row.alignment = .centerY
            row.spacing = 9
            row.translatesAutoresizingMaskIntoConstraints = false
            NSLayoutConstraint.activate([
                icon.widthAnchor.constraint(equalToConstant: 15),
                icon.heightAnchor.constraint(equalToConstant: 15),
                row.heightAnchor.constraint(equalToConstant: 27),
            ])
            return row
        }
        let stack = NSStackView(views: views)
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 7
        stack.translatesAutoresizingMaskIntoConstraints = false
        return stack
    }

    private func makeAccountFooter() -> NSView {
        let footer = NSView()
        footer.translatesAutoresizingMaskIntoConstraints = false
        footer.wantsLayer = true
        footer.layer?.backgroundColor = DesignTokens.surface2.withAlphaComponent(0.7).cgColor
        footer.layer?.cornerRadius = 8
        footer.layer?.cornerCurve = .continuous

        let avatar = NSTextField(labelWithString: "JA")
        avatar.font = .systemFont(ofSize: 11, weight: .medium)
        avatar.textColor = .white
        avatar.alignment = .center
        avatar.translatesAutoresizingMaskIntoConstraints = false
        avatar.wantsLayer = true
        avatar.layer?.backgroundColor = DesignTokens.info.cgColor
        avatar.layer?.cornerRadius = 14

        let name = NSTextField(labelWithString: "Jassy")
        name.font = .systemFont(ofSize: 13, weight: .medium)
        name.textColor = DesignTokens.text
        // 设计系统：客户端不管理鉴权，账号栏显示身份标识而非订阅计划
        let plan = NSTextField(labelWithString: "身份 · ad_8f3k…q2b")
        plan.font = .monospacedSystemFont(ofSize: 11, weight: .regular)
        plan.textColor = DesignTokens.text3
        for label in [name, plan] {
            label.translatesAutoresizingMaskIntoConstraints = false
        }
        let textStack = NSStackView(views: [name, plan])
        textStack.orientation = .vertical
        textStack.alignment = .leading
        textStack.spacing = 1
        textStack.translatesAutoresizingMaskIntoConstraints = false

        footer.addSubview(avatar)
        footer.addSubview(textStack)

        NSLayoutConstraint.activate([
            avatar.leadingAnchor.constraint(equalTo: footer.leadingAnchor, constant: 8),
            avatar.centerYAnchor.constraint(equalTo: footer.centerYAnchor),
            avatar.widthAnchor.constraint(equalToConstant: 28),
            avatar.heightAnchor.constraint(equalToConstant: 28),
            textStack.leadingAnchor.constraint(equalTo: avatar.trailingAnchor, constant: 10),
            textStack.centerYAnchor.constraint(equalTo: footer.centerYAnchor),
            textStack.trailingAnchor.constraint(lessThanOrEqualTo: footer.trailingAnchor, constant: -8),
        ])

        return footer
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
            _ = self.model.selectedSidebarThreadId
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

    /// Invalidate the observation re-arm loop only on teardown, NOT on a
    /// transient `viewWillDisappear`. The sidebar binds once in `viewDidLoad`;
    /// invalidating on hide would permanently freeze runtime phase / unread
    /// updates on a later show, since nothing re-binds (I2). Mirrors
    /// `TurnJumpRailView` / `StatusBarView` / `ConversationViewController`.
    deinit {
        let b = binder
        Task { @MainActor in b.invalidate() }
    }

    // MARK: - Data Helpers

    private var groups: [HistoryProjectGroup] {
        model.historyGroups
    }

    // MARK: - Reload

    private func reloadOutline() {
        outlineView.reloadData()
        expandAllGroups()
        updateVisibility()
    }

    private func expandAllGroups() {
        for i in 0..<groups.count {
            outlineView.expandItem(groups[i])
        }
    }

    private func updateVisibility() {
        let loading = model.isLoadingHistory
        let hasError = model.historyErrorMessage != nil
        let isEmpty  = groups.isEmpty

        loadingIndicator.isHidden = !loading
        if loading { loadingIndicator.startAnimation(nil) } else { loadingIndicator.stopAnimation(nil) }

        errorLabel.isHidden = !hasError
        if let err = model.historyErrorMessage { errorLabel.stringValue = err }

        // Empty state only when done loading, no error, and really empty
        emptyStateLabel.isHidden = loading || hasError || !isEmpty

        scrollView.isHidden = loading || hasError || isEmpty
    }

    // MARK: - Actions

    @objc private func handleNewSession() {
        onNewSessionRequested?()
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
            if groups.indices.contains(index) { return groups[index] }
        } else if let group = item as? HistoryProjectGroup {
            if group.threads.indices.contains(index) { return group.threads[index] }
        }
        // Bounds-safe fallback: AppKit only asks for indices it learned from
        // numberOfChildrenOfItem, so this is effectively unreachable. Return an
        // empty group rather than crashing if the data shifts mid-reload.
        return HistoryProjectGroup(cwd: "", threads: [])
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
            selectedThreadId: model.selectedSidebarThreadId,
            openingThreadId: model.openingHistoryThreadId,
            hoveredThreadId: nil,   // hover tracking is NSOutlineView's built-in highlight
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
        // 设计系统：.projgroup padding:7 12（≈30）；.wb-side__list .thread padding:10 12 单行标题（≈40）。
        if item is HistoryProjectGroup { return 30 }
        return 40
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

    @objc private func handleRename(_ sender: NSMenuItem) {
        guard let thread = sender.representedObject as? HistoryThreadSummary else { return }
        showRenameAlert(for: thread)
    }

    @objc private func handleArchive(_ sender: NSMenuItem) {
        guard let thread = sender.representedObject as? HistoryThreadSummary else { return }
        model.archiveHistoryThread(thread)
    }
}

// MARK: - NSMenuDelegate (right-click context menu)

extension HistorySidebarViewController: NSMenuDelegate {

    /// Resolve which `HistoryThreadSummary` (if any) the right-clicked row maps
    /// to. Returns `nil` when the row is out of range, a group row, or empty.
    /// Pure function of the outline state so it can be unit-tested in isolation.
    static func thread(forClickedRow row: Int, in outlineView: NSOutlineView) -> HistoryThreadSummary? {
        guard row >= 0, row < outlineView.numberOfRows else { return nil }
        return outlineView.item(atRow: row) as? HistoryThreadSummary
    }

    func menuNeedsUpdate(_ menu: NSMenu) {
        menu.removeAllItems()
        // `clickedRow` is the row under the cursor at right-click time.
        guard let thread = Self.thread(forClickedRow: outlineView.clickedRow, in: outlineView) else {
            return  // group row or empty space → no thread menu
        }

        let renameItem = NSMenuItem(title: "Rename", action: #selector(handleRename(_:)), keyEquivalent: "")
        renameItem.target = self
        renameItem.representedObject = thread
        menu.addItem(renameItem)

        let archiveItem = NSMenuItem(title: "Archive", action: #selector(handleArchive(_:)), keyEquivalent: "")
        archiveItem.target = self
        archiveItem.representedObject = thread
        menu.addItem(archiveItem)
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
