import AppKit
import AgentDeckCore

private enum HistorySidebarLayout {
    /// `.sourceList` 把数据 cell 向右移 16pt，为 outline chrome 预留空间。
    /// 单列宽度必须扣除这段位移，cell 尾边才会与 clip view 对齐。
    static let sourceListCellLeadingInset: CGFloat = 16
}

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


    /// 新对话入口与项目标题行的加号共用该回调，由 SessionViewController
    /// 展示 `NewSessionDialog`。
    var onNewSessionRequested: (() -> Void)?
    private let newSessionButton: NSButton = {
        let btn = NSButton()
        btn.bezelStyle = .inline
        btn.isBordered = false
        btn.image = NSImage(systemSymbolName: "plus", accessibilityDescription: "新建会话")
        btn.toolTip = "新建会话"
        btn.contentTintColor = DesignTokens.text3
        btn.setAccessibilityIdentifier("sidebar-project-new-session")
        btn.setAccessibilityLabel("新建会话")
        btn.translatesAutoresizingMaskIntoConstraints = false
        return btn
    }()

    private let refreshHistoryButton: NSButton = {
        let btn = NSButton()
        btn.bezelStyle = .inline
        btn.isBordered = false
        btn.image = NSImage(systemSymbolName: "arrow.clockwise", accessibilityDescription: nil)
        btn.imagePosition = .imageOnly
        btn.toolTip = "刷新 Codex 与 Claude Code 会话"
        btn.contentTintColor = DesignTokens.text3
        btn.setAccessibilityIdentifier("sidebar-project-refresh-history")
        btn.setAccessibilityLabel("刷新会话")
        btn.setAccessibilityHelp("重新加载 Codex 与 Claude Code 会话")
        btn.translatesAutoresizingMaskIntoConstraints = false
        return btn
    }()

    private lazy var topNewSessionButton = makeTopActionButton(
        symbol: "square.and.pencil",
        title: "新对话",
        accessibilityIdentifier: "sidebar-new-conversation",
        action: #selector(handleNewSession)
    )

    private lazy var searchToggleButton = makeTopActionButton(
        symbol: "magnifyingglass",
        title: "搜索",
        accessibilityIdentifier: "sidebar-search-toggle",
        buttonType: .pushOnPushOff,
        action: #selector(handleSearchToggle)
    )

    private let searchField: NSSearchField = {
        let sf = NSSearchField()
        sf.placeholderString = "搜索会话"
        sf.setAccessibilityIdentifier("sidebar-search-field")
        sf.setAccessibilityLabel("搜索会话")
        sf.translatesAutoresizingMaskIntoConstraints = false
        return sf
    }()
    private var searchFieldHeightConstraint: NSLayoutConstraint?
    private var isSearchExpanded = false

    /// Shown while isLoadingHistory
    private let loadingIndicator: NSProgressIndicator = {
        let pi = NSProgressIndicator()
        pi.style = .spinning
        pi.controlSize = .small
        pi.isIndeterminate = true
        pi.isHidden = true
        pi.setAccessibilityIdentifier("sidebar-history-loading")
        pi.setAccessibilityLabel("正在刷新 Codex 与 Claude Code 会话")
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
        let label = NSTextField(
            wrappingLabelWithString: "暂无历史\n新建会话后会显示在这里；刷新可加载当前支持的历史。"
        )
        label.font = .systemFont(ofSize: NSFont.systemFontSize)
        label.textColor = DesignTokens.text2
        label.isHidden = true
        label.setAccessibilityIdentifier("sidebar-empty-history")
        label.translatesAutoresizingMaskIntoConstraints = false
        return label
    }()

    private lazy var scrollView: NSScrollView = {
        let sv = NSScrollView()
        sv.hasVerticalScroller = true
        sv.hasHorizontalScroller = false
        sv.autohidesScrollers = true
        sv.automaticallyAdjustsContentInsets = false
        sv.contentInsets = NSEdgeInsets()
        sv.scrollerInsets = NSEdgeInsets()
        sv.horizontalScrollElasticity = .none
        sv.drawsBackground = false   // 让侧栏容器底色透过，不自绘浅色/黑底
        sv.documentView = outlineView
        sv.translatesAutoresizingMaskIntoConstraints = false
        return sv
    }()

    private lazy var outlineView: NSOutlineView = {
        let ov = NSOutlineView()
        ov.style = .sourceList
        ov.headerView = nil          // no column header
        ov.rowHeight = 30
        ov.intercellSpacing = NSSize(width: 0, height: 2)
        ov.indentationPerLevel = 0   // groups are not indented relative to root
        ov.autoresizesOutlineColumn = false
        // `.sourceList` 会给单列留下隐式尾距；列宽由 `viewDidLayout()` 显式同步
        // 到 clip view，确保高亮和尾随图标真正抵达分隔线。
        ov.columnAutoresizingStyle = .noColumnAutoresizing
        // 侧栏毛玻璃做底，outline 自身透明让材质透出
        ov.backgroundColor = .clear
        ov.floatsGroupRows = false
        // 关掉内建满宽高亮：设计里选中/悬停是内缩圆角块，由 HistoryThreadRowView 自绘。
        ov.selectionHighlightStyle = .none

        let col = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("main"))
        col.isEditable = false
        col.resizingMask = []
        col.minWidth = 0
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
        container.layer?.backgroundColor = NSColor.clear.cgColor
        view = container

        // 整个侧栏毛玻璃：.sidebar 材质 + behindWindow 透出并模糊窗口后面的桌面。
        let blur = NSVisualEffectView()
        blur.material = .sidebar
        blur.blendingMode = .behindWindow
        blur.state = .followsWindowActiveState
        blur.translatesAutoresizingMaskIntoConstraints = false
        container.addSubview(blur)

        // 在材质之上叠一层半透明深色遮罩把侧栏压暗，同时保留磨砂通透（alpha 越大越黑，
        // 越小越透出桌面）。0.20 更通透、桌面透出更明显，单值可调。
        let darkTint = NSView()
        darkTint.wantsLayer = true
        darkTint.layer?.backgroundColor = NSColor.black.withAlphaComponent(0.20).cgColor
        darkTint.translatesAutoresizingMaskIntoConstraints = false
        container.addSubview(darkTint)

        NSLayoutConstraint.activate([
            blur.topAnchor.constraint(equalTo: container.topAnchor),
            blur.leadingAnchor.constraint(equalTo: container.leadingAnchor),
            blur.trailingAnchor.constraint(equalTo: container.trailingAnchor),
            blur.bottomAnchor.constraint(equalTo: container.bottomAnchor),
            darkTint.topAnchor.constraint(equalTo: container.topAnchor),
            darkTint.leadingAnchor.constraint(equalTo: container.leadingAnchor),
            darkTint.trailingAnchor.constraint(equalTo: container.trailingAnchor),
            darkTint.bottomAnchor.constraint(equalTo: container.bottomAnchor),
        ])

        let topActions = makeTopActions()

        // Header row
        newSessionButton.target = self
        newSessionButton.action = #selector(handleNewSession)
        refreshHistoryButton.target = self
        refreshHistoryButton.action = #selector(handleRefreshHistory)
        let headerRow = NSStackView(
            views: [headerLabel, NSView(), refreshHistoryButton, newSessionButton]
        )
        headerRow.orientation = .horizontal
        headerRow.spacing = 8
        headerRow.translatesAutoresizingMaskIntoConstraints = false
        headerRow.setContentHuggingPriority(.defaultHigh, for: .vertical)
        // Let the spacer expand
        headerRow.views[1].translatesAutoresizingMaskIntoConstraints = false
        headerRow.setHuggingPriority(.defaultLow, for: .horizontal)

        let accountFooter = makeAccountFooter()

        searchField.stringValue = model.historySearchTerm
        isSearchExpanded = !model.historySearchTerm.isEmpty
        searchField.isHidden = !isSearchExpanded
        searchToggleButton.state = isSearchExpanded ? .on : .off

        container.addSubview(topActions)
        container.addSubview(headerRow)
        container.addSubview(searchField)
        container.addSubview(loadingIndicator)
        container.addSubview(errorLabel)
        container.addSubview(emptyStateLabel)
        container.addSubview(scrollView)
        container.addSubview(accountFooter)

        let searchHeight = searchField.heightAnchor.constraint(
            equalToConstant: isSearchExpanded ? 28 : 0
        )
        searchFieldHeightConstraint = searchHeight

        NSLayoutConstraint.activate([
            // 设计系统 .wb-side padding-top:44 + .wb-side__actions padding:6 10 → 顶起 50、水平 10
            topActions.topAnchor.constraint(equalTo: container.topAnchor, constant: 50),
            topActions.leadingAnchor.constraint(equalTo: container.leadingAnchor, constant: 18),
            topActions.trailingAnchor.constraint(equalTo: container.trailingAnchor, constant: -18),

            // Header（紧凑侧栏：上 14、左 16、右 12）
            headerRow.topAnchor.constraint(equalTo: topActions.bottomAnchor, constant: 14),
            headerRow.leadingAnchor.constraint(equalTo: container.leadingAnchor, constant: 16),
            headerRow.trailingAnchor.constraint(equalTo: container.trailingAnchor, constant: -12),

            // Search field
            searchField.topAnchor.constraint(equalTo: headerRow.bottomAnchor, constant: 8),
            searchField.leadingAnchor.constraint(equalTo: container.leadingAnchor, constant: 12),
            searchField.trailingAnchor.constraint(equalTo: container.trailingAnchor, constant: -12),
            searchHeight,

            // Loading indicator
            loadingIndicator.topAnchor.constraint(equalTo: searchField.bottomAnchor, constant: 4),
            loadingIndicator.centerXAnchor.constraint(equalTo: container.centerXAnchor),

            // Error label
            errorLabel.topAnchor.constraint(equalTo: searchField.bottomAnchor),
            errorLabel.leadingAnchor.constraint(equalTo: container.leadingAnchor, constant: 12),
            errorLabel.trailingAnchor.constraint(equalTo: container.trailingAnchor, constant: -12),

            // Empty-state label
            emptyStateLabel.topAnchor.constraint(equalTo: searchField.bottomAnchor, constant: 4),
            emptyStateLabel.leadingAnchor.constraint(equalTo: container.leadingAnchor, constant: 12),
            emptyStateLabel.trailingAnchor.constraint(equalTo: container.trailingAnchor, constant: -12),

            // Outline scroll view
            scrollView.topAnchor.constraint(equalTo: searchField.bottomAnchor, constant: 2),
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
        updateSearchToggleAccessibility()

        // Reopen all groups by default after data load
        updateVisibility()
    }

    private func makeTopActions() -> NSStackView {
        let stack = NSStackView(views: [topNewSessionButton, searchToggleButton])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 7
        stack.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            topNewSessionButton.widthAnchor.constraint(equalTo: stack.widthAnchor),
            searchToggleButton.widthAnchor.constraint(equalTo: stack.widthAnchor),
        ])
        return stack
    }

    private func makeTopActionButton(
        symbol: String,
        title: String,
        accessibilityIdentifier: String,
        buttonType: NSButton.ButtonType = .momentaryChange,
        action: Selector
    ) -> NSButton {
        let button = NSButton(title: title, target: self, action: action)
        button.image = NSImage(systemSymbolName: symbol, accessibilityDescription: nil)
        button.imagePosition = .imageLeading
        button.imageHugsTitle = true
        button.alignment = .left
        button.font = .systemFont(ofSize: 13, weight: .medium)
        button.contentTintColor = DesignTokens.text
        button.bezelStyle = .inline
        button.isBordered = false
        button.setButtonType(buttonType)
        button.setAccessibilityIdentifier(accessibilityIdentifier)
        button.setAccessibilityLabel(title)
        button.translatesAutoresizingMaskIntoConstraints = false
        button.heightAnchor.constraint(equalToConstant: 27).isActive = true
        return button
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

    override func viewDidLayout() {
        super.viewDidLayout()
        synchronizeOutlineColumnWidth()
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
        let allGroups = model.historyGroups
        let query = model.historySearchTerm.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !query.isEmpty else { return allGroups }

        return allGroups.compactMap { group in
            if group.projectName.localizedCaseInsensitiveContains(query)
                || group.cwd.localizedCaseInsensitiveContains(query) {
                return group
            }
            let matchingThreads = group.threads.filter { thread in
                thread.displayTitle.localizedCaseInsensitiveContains(query)
                    || thread.preview.localizedCaseInsensitiveContains(query)
                    || thread.status.localizedCaseInsensitiveContains(query)
            }
            guard !matchingThreads.isEmpty else { return nil }
            return HistoryProjectGroup(cwd: group.cwd, threads: matchingThreads)
        }
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

    private func synchronizeOutlineColumnWidth() {
        let visibleWidth = scrollView.contentView.bounds.width
        guard visibleWidth > 0, let column = outlineView.tableColumns.first else { return }
        let columnWidth = max(
            0,
            visibleWidth - HistorySidebarLayout.sourceListCellLeadingInset
        )

        if abs(column.width - columnWidth) > 0.5 {
            column.width = columnWidth
        }
        if abs(outlineView.frame.width - visibleWidth) > 0.5 {
            var size = outlineView.frame.size
            size.width = visibleWidth
            outlineView.setFrameSize(size)
        }
    }

    private func updateVisibility() {
        let loading = model.isLoadingHistory
        let hasError = model.historyErrorMessage != nil
        let isEmpty  = groups.isEmpty
        let isSearching = !model.historySearchTerm.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty

        loadingIndicator.isHidden = !loading
        if loading { loadingIndicator.startAnimation(nil) } else { loadingIndicator.stopAnimation(nil) }
        refreshHistoryButton.isEnabled = !loading
        refreshHistoryButton.toolTip = loading
            ? "正在刷新 Codex 与 Claude Code 会话"
            : "刷新 Codex 与 Claude Code 会话"
        refreshHistoryButton.setAccessibilityHelp(
            loading
                ? "正在加载 Codex 与 Claude Code 会话"
                : "重新加载 Codex 与 Claude Code 会话"
        )

        errorLabel.isHidden = !hasError
        if let err = model.historyErrorMessage { errorLabel.stringValue = err }

        // Empty state only when done loading, no error, and really empty
        emptyStateLabel.stringValue = isSearching
            ? "没有匹配的会话"
            : "暂无历史\n新建会话后会显示在这里；刷新可加载当前支持的历史。"
        emptyStateLabel.isHidden = loading || hasError || !isEmpty

        scrollView.isHidden = loading || hasError || isEmpty
    }

    // MARK: - Actions

    @objc private func handleNewSession() {
        onNewSessionRequested?()
    }

    @objc private func handleRefreshHistory() {
        model.loadHistory()
    }

    @objc private func handleSearchToggle() {
        setSearchExpanded(!isSearchExpanded)
    }

    private func setSearchExpanded(_ expanded: Bool) {
        isSearchExpanded = expanded
        searchFieldHeightConstraint?.constant = expanded ? 28 : 0
        searchField.isHidden = !expanded
        searchToggleButton.state = expanded ? .on : .off

        if expanded {
            view.needsLayout = true
            view.layoutSubtreeIfNeeded()
            view.window?.makeFirstResponder(searchField)
        } else {
            view.window?.makeFirstResponder(nil)
            if !searchField.stringValue.isEmpty || !model.historySearchTerm.isEmpty {
                searchField.stringValue = ""
                model.historySearchTerm = ""
                reloadOutline()
            }
        }
        updateSearchToggleAccessibility()
    }

    private func updateSearchToggleAccessibility() {
        let stateLabel = isSearchExpanded ? "已展开" : "已收起"
        searchToggleButton.toolTip = isSearchExpanded ? "收起搜索" : "搜索会话"
        searchToggleButton.setAccessibilityValue(stateLabel)
        searchToggleButton.setAccessibilityHelp(isSearchExpanded ? "收起会话搜索框" : "展开会话搜索框")
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
        // 设计系统：.projgroup padding:7 10（≈30）；.wb-side__list .thread padding:10 单行标题（≈40）。
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

    func outlineView(_ outlineView: NSOutlineView, shouldShowOutlineCellForItem item: Any) -> Bool {
        // 分组始终展开且使用自绘行，不显示原生 disclosure cell。否则 `.sourceList`
        // 会在单列两侧各保留约 16pt，造成右侧高亮和尾随图标提前结束。
        false
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
        // 历史已经在本地，搜索只过滤现有统一历史，避免每次按键重启 daemon 查询。
        reloadOutline()
    }
}
