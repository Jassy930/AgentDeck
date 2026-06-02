import SwiftUI
import AppKit
import UniformTypeIdentifiers

// Beat 1 — the only user-perceivable wow in v0.1.
//
// Design decisions are NOT improvised here; they are the locked D3-D9 specs
// from the design review:
//   D3  info architecture: title bar (product+project) / pinned status bar
//       (D9 mirror) / single-column stream (reasoning collapsed-secondary,
//       shell+fileEdit primary) / bottom input
//   D5  empty state: centered, restrained — product name, one value line,
//       "Choose project directory" primary action, one example prompt
//   D6  transition copy: reuse the D9 state machine text, not a spinner
//   D7  NON-CARD: items separated by typographic rhythm (spacing + font
//       difference + subtle divider), never card-wrapped. Only approval is
//       a card (it IS the interaction)
//   D8  macOS system semantics: SF Pro / SF Mono, system accent, follows
//       light/dark, system warning red. No invented design system.

struct SessionView: View {
    @State private var model = SessionModel()
    @State private var input = ""
    @State private var renameThread: HistoryThreadSummary?
    @State private var renameText = ""
    @State private var hoveredHistoryThreadId: String?
    @State private var selectedConversationTurnId: String?

    var body: some View {
        VStack(spacing: 0) {
            statusBar                       // D3: pinned top, D9 mirror
            Divider()
            HStack(spacing: 0) {
                historySidebar
                Divider()
                VStack(spacing: 0) {
                    if model.cwd == nil {
                        emptyState          // D5
                    } else {
                        conversationStream  // D3 single column, D7 non-card
                        Divider()
                        inputBar            // D3 bottom
                    }
                }
            }
        }
        .frame(minWidth: 760, minHeight: 420)   // D9: min window size
        .onAppear { model.loadHistoryOnAppear() }
        .onDisappear { model.teardown() }       // A1: app exit kills daemon
        .alert("Rename thread", isPresented: renameAlertBinding) {
            TextField("Name", text: $renameText)
            Button("Cancel", role: .cancel) { renameThread = nil }
            Button("Rename") {
                if let thread = renameThread {
                    model.renameHistoryThread(thread, name: renameText)
                }
                renameThread = nil
            }
        }
    }

    // MARK: D3 — pinned status bar (D9 state mirror)

    private var statusBar: some View {
        HStack(spacing: 8) {
            Circle()
                .fill(statusColor)
                .frame(width: 8, height: 8)
            Text(model.statusText)
                .font(.system(.callout, design: .default))
                .foregroundStyle(.secondary)
            if model.selectedHistoryThreadId != nil {
                Text("Restored history")
                    .font(.system(.caption))
                    .foregroundStyle(.secondary)
                if !model.historyTimingSummary.isEmpty {
                    Text(model.historyTimingSummary)
                        .font(.system(.caption))
                        .foregroundStyle(.tertiary)
                }
                Button("New session") { model.startNewSessionFromCurrentProject() }
                    .font(.system(.caption))
                    .buttonStyle(.link)
            }
            Spacer()
            if let cwd = model.cwd {
                Text(cwd.lastPathComponent)     // project, subtle (D3)
                    .font(.system(.callout))
                    .foregroundStyle(.tertiary)
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
    }

    private var statusColor: Color {
        switch model.selectedPhase {
        case .running, .starting: return .accentColor
        case .failed: return .red                // D8 system warning
        case .waitingApproval: return .orange
        default: return .secondary
        }
    }

    // MARK: D5 — empty state (first frame; protect first impression)

    private var emptyState: some View {
        VStack(spacing: 16) {
            Spacer()
            Text("AgentDeck")
                .font(.system(size: 28, weight: .semibold))
            Text("Watch your coding agent work, and stay in control.")
                .font(.system(.body))
                .foregroundStyle(.secondary)
            Button("Choose project directory…") { pickDirectory() }
                .buttonStyle(.borderedProminent)
                .padding(.top, 4)
            Button("Refresh history") { model.loadHistory() }
                .buttonStyle(.bordered)
            Text("e.g. “Fix the crash in the settings panel”")
                .font(.system(.callout))
                .foregroundStyle(.tertiary)
                .padding(.top, 8)
            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding(40)
    }

    private var historySidebar: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 8) {
                Text("History")
                    .font(.system(.headline))
                Spacer()
                Button(action: { model.loadHistory() }) {
                    Image(systemName: "arrow.clockwise")
                }
                .buttonStyle(.borderless)
                .disabled(model.isLoadingHistory)
                .help("Refresh history")
            }
            .padding(.horizontal, 12)
            .padding(.top, 12)
            .padding(.bottom, 8)

            TextField("Search threads", text: $model.historySearchTerm)
                .textFieldStyle(.roundedBorder)
                .padding(.horizontal, 12)
                .padding(.bottom, 8)
                .onSubmit { model.loadHistory() }

            if model.isLoadingHistory {
                ProgressView()
                    .controlSize(.small)
                    .frame(maxWidth: .infinity, alignment: .center)
                    .padding(.vertical, 12)
            } else if let err = model.historyErrorMessage {
                Text(err)
                    .font(.system(.caption))
                    .foregroundStyle(.red)
                    .textSelection(.enabled)
                    .padding(12)
            } else if model.historyThreads.isEmpty {
                VStack(alignment: .leading, spacing: 6) {
                    Text("No history loaded")
                        .font(.system(.callout))
                    Text("Refresh to scan persisted agent threads.")
                        .font(.system(.caption))
                        .foregroundStyle(.tertiary)
                }
                .padding(12)
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 0) {
                        ForEach(model.historyGroups) { group in
                            historyGroup(group)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.bottom, 12)
                }
            }
        }
        .frame(width: 260)
        .background(Color(nsColor: .controlBackgroundColor))
    }

    private func historyGroup(_ group: HistoryProjectGroup) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 6) {
                Text(group.projectName)
                    .font(.system(.caption, weight: .semibold))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Spacer(minLength: 4)
                Button {
                    model.startNewSession(inProjectCwd: group.cwd)
                } label: {
                    Image(systemName: "plus")
                        .font(.system(size: 11, weight: .semibold))
                        .frame(width: 18, height: 18)
                }
                .buttonStyle(.borderless)
                .help("New session in \(group.projectName)")
                .accessibilityLabel("New session in \(group.projectName)")
            }
            .padding(.horizontal, 12)
            .padding(.top, 10)
            .padding(.bottom, 4)
            ForEach(group.threads) { thread in
                historyThreadRow(thread)
            }
        }
    }

    private func historyThreadRow(_ thread: HistoryThreadSummary) -> some View {
        let runtime = model.workbench.runtime(sessionId: thread.id)
        let presentation = HistoryThreadRowPresentation(
            threadId: thread.id,
            selectedThreadId: model.selectedHistoryThreadId,
            openingThreadId: model.openingHistoryThreadId,
            hoveredThreadId: hoveredHistoryThreadId,
            modelProvider: thread.modelProvider,
            source: thread.source,
            runtimePhase: runtime?.phase,
            unreadEventCount: runtime?.unreadEventCount ?? 0
        )

        return Button {
            model.openHistoryThread(thread)
        } label: {
            HStack(spacing: 8) {
                RoundedRectangle(cornerRadius: 1.5)
                    .fill(historyThreadAccentColor(presentation))
                    .frame(width: 3)
                VStack(alignment: .leading, spacing: 3) {
                    HStack(spacing: 6) {
                        historyThreadAgentIcon(presentation)
                        historyThreadRuntimeDot(presentation)
                        Text(thread.displayTitle)
                            .font(.system(.callout, weight: presentation.isEmphasized ? .medium : .regular))
                            .foregroundStyle(presentation.isEmphasized ? .primary : .secondary)
                            .lineLimit(2)
                        if model.openingHistoryThreadId == thread.id {
                            ProgressView()
                                .controlSize(.mini)
                        }
                    }
                    HStack(spacing: 6) {
                        Text(thread.status)
                        if let runtimeStatus = presentation.runtimeStatusLabel {
                            Text(runtimeStatus)
                        }
                        Text(thread.source)
                        Text(updatedLabel(thread.updatedAt))
                    }
                    .font(.system(.caption))
                    .foregroundStyle(.tertiary)
                    .lineLimit(1)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 10)
            .padding(.vertical, 8)
            .contentShape(Rectangle())
            .background {
                RoundedRectangle(cornerRadius: 6)
                    .fill(historyThreadBackgroundColor(presentation))
            }
        }
        .buttonStyle(.plain)
        .frame(maxWidth: .infinity, alignment: .leading)
        .contentShape(Rectangle())
        .padding(.horizontal, 6)
        .padding(.vertical, 1)
        .onHover { hovering in
            if hovering {
                hoveredHistoryThreadId = thread.id
            } else if hoveredHistoryThreadId == thread.id {
                hoveredHistoryThreadId = nil
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Open \(presentation.agentSourceLabel) thread, \(thread.displayTitle)")
        .accessibilityHint("Opens the saved thread in the conversation view")
        .contextMenu {
            Button("Rename") {
                renameThread = thread
                renameText = thread.displayTitle
            }
            Button("Archive", role: .destructive) {
                model.archiveHistoryThread(thread)
            }
        }
    }

    private func historyThreadBackgroundColor(_ presentation: HistoryThreadRowPresentation) -> Color {
        switch presentation.visualState {
        case .opening, .selected:
            return Color.accentColor.opacity(0.16)
        case .hovered:
            return Color(nsColor: .separatorColor).opacity(0.28)
        case .idle:
            return .clear
        }
    }

    private func historyThreadAccentColor(_ presentation: HistoryThreadRowPresentation) -> Color {
        switch presentation.visualState {
        case .opening, .selected:
            return .accentColor
        case .hovered:
            return Color(nsColor: .tertiaryLabelColor)
        case .idle:
            return .clear
        }
    }

    @ViewBuilder
    private func historyThreadAgentIcon(_ presentation: HistoryThreadRowPresentation) -> some View {
        if let image = historyThreadAgentImage(named: presentation.agentSourceImageName) {
            Image(nsImage: image)
                .resizable()
                .renderingMode(.template)
                .scaledToFit()
                .frame(width: 14, height: 14)
                .foregroundStyle(historyThreadAgentIconColor(presentation))
                .help(presentation.agentSourceLabel)
                .accessibilityHidden(true)
        } else {
            Image(systemName: "questionmark.circle")
                .font(.system(size: 11, weight: .medium))
                .foregroundStyle(Color(nsColor: .secondaryLabelColor))
                .frame(width: 14, height: 14)
                .help(presentation.agentSourceLabel)
                .accessibilityHidden(true)
        }
    }

    private func historyThreadAgentImage(named name: String) -> NSImage? {
        let resource: (subdirectory: String, filename: String)
        switch name {
        case "CodexIcon":
            resource = ("Assets.xcassets/CodexIcon.imageset", "codex")
        case "UnknownAgentIcon":
            resource = ("Assets.xcassets/UnknownAgentIcon.imageset", "unknown-agent")
        default:
            return nil
        }

        guard let url = Bundle.module.url(
            forResource: resource.filename,
            withExtension: "svg",
            subdirectory: resource.subdirectory
        ) else {
            return nil
        }
        return NSImage(contentsOf: url)
    }

    private func historyThreadAgentIconColor(_ presentation: HistoryThreadRowPresentation) -> Color {
        presentation.isEmphasized ? .accentColor : Color(nsColor: .secondaryLabelColor)
    }

    @ViewBuilder
    private func historyThreadRuntimeDot(_ presentation: HistoryThreadRowPresentation) -> some View {
        if presentation.hasRuntimeIndicator {
            Circle()
                .fill(historyThreadRuntimeDotColor(presentation))
                .frame(width: presentation.hasUnreadIndicator ? 7 : 5, height: presentation.hasUnreadIndicator ? 7 : 5)
                .help(presentation.hasUnreadIndicator ? "Unread runtime events" : "Cached runtime")
                .accessibilityHidden(true)
        }
    }

    private func historyThreadRuntimeDotColor(_ presentation: HistoryThreadRowPresentation) -> Color {
        if presentation.hasUnreadIndicator {
            return .accentColor
        }
        switch presentation.runtimePhase {
        case .running, .starting:
            return .accentColor
        case .waitingApproval:
            return .orange
        case .failed:
            return .red
        case .some:
            return Color(nsColor: .tertiaryLabelColor)
        case .none:
            return .clear
        }
    }

    // MARK: D3/D7 — single-column stream, NON-CARD

    private let conversationLatestAnchorId = "conversation-latest-anchor"
    private let conversationScrollCoordinateSpace = "conversation-scroll-space"

    private var conversationStream: some View {
        let turns = makeConversationTurns(from: model.selectedItems)
        let navigationItems = makeConversationTurnNavigationItems(from: turns)
        let navigableTurnIds = Set(navigationItems.map(\.turnId))

        return ScrollViewReader { proxy in
            ZStack(alignment: .trailing) {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 0) {
                        ForEach(Array(turns.enumerated()), id: \.element.id) { index, turn in
                            conversationTurn(turn)
                                .id(turn.id)
                                .background {
                                    if turn.user != nil {
                                        GeometryReader { geometry in
                                            Color.clear.preference(
                                                key: ConversationTurnPositionPreferenceKey.self,
                                                value: [
                                                    ConversationTurnViewportPosition(
                                                        turnId: turn.id,
                                                        minY: geometry.frame(
                                                            in: .named(conversationScrollCoordinateSpace)
                                                        ).minY
                                                    )
                                                ]
                                            )
                                        }
                                    }
                                }
                            if index + 1 < turns.count {
                                Divider().opacity(0.4)  // D7: subtle divider, not card
                            }
                        }
                        if let err = model.selectedErrorMessage {
                            errorRow(err)               // premise 9: visible failure
                        }
                        if let warning = model.selectedWarningMessage {
                            warningRow(warning)
                        }
                        if let action = model.selectedActionRequest {
                            approvalRow(action)
                        }
                        Color.clear
                            .frame(height: 1)
                            .id(conversationLatestAnchorId)
                    }
                    .padding(.leading, 20)
                    .padding(.trailing, navigationItems.isEmpty ? 20 : 52)
                    .padding(.vertical, 12)
                }
                .coordinateSpace(name: conversationScrollCoordinateSpace)
                .onPreferenceChange(ConversationTurnPositionPreferenceKey.self) { positions in
                    guard let turnId = ConversationScrollSpy.currentTurnId(from: positions),
                          navigableTurnIds.contains(turnId) else {
                        return
                    }
                    selectedConversationTurnId = turnId
                }

                if !navigationItems.isEmpty {
                    TurnJumpRail(
                        items: navigationItems,
                        selectedTurnId: selectedConversationTurnId,
                        onJump: { turnId in
                            selectedConversationTurnId = turnId
                            withAnimation(.easeInOut(duration: 0.18)) {
                                proxy.scrollTo(turnId, anchor: .top)
                            }
                        },
                        onJumpLatest: {
                            selectedConversationTurnId = nil
                            withAnimation(.easeInOut(duration: 0.18)) {
                                proxy.scrollTo(conversationLatestAnchorId, anchor: .bottom)
                            }
                        },
                        onWheelStep: { direction in
                            scrollConversationRailStep(direction, items: navigationItems, proxy: proxy)
                        }
                    )
                    .padding(.trailing, 8)
                    .padding(.vertical, 12)
                }
            }
            .id(model.conversationViewportIdentity)
            .onChange(of: model.conversationViewportIdentity) {
                selectedConversationTurnId = navigationItems.first?.turnId
            }
            .onChange(of: model.scrollToLatestRequest) {
                selectedConversationTurnId = nil
                DispatchQueue.main.async {
                    withAnimation(.easeInOut(duration: 0.18)) {
                        proxy.scrollTo(conversationLatestAnchorId, anchor: .bottom)
                    }
                }
            }
        }
    }

    private func scrollConversationRailStep(
        _ direction: Int,
        items: [ConversationTurnNavigationItem],
        proxy: ScrollViewProxy
    ) {
        // A2: Pure decision lives in `ConversationRailNavigator`; this method
        // is now just the SwiftUI adapter that maps each `Outcome` to a
        // selection mutation + animated scroll.
        switch ConversationRailNavigator.next(
            currentSelected: selectedConversationTurnId,
            items: items,
            direction: direction
        ) {
        case .scrollToLatest:
            selectedConversationTurnId = nil
            withAnimation(.easeInOut(duration: 0.18)) {
                proxy.scrollTo(conversationLatestAnchorId, anchor: .bottom)
            }
        case .scrollToTurn(let turnId):
            selectedConversationTurnId = turnId
            withAnimation(.easeInOut(duration: 0.18)) {
                proxy.scrollTo(turnId, anchor: .top)
            }
        case .none:
            break
        }
    }

    @ViewBuilder
    private func conversationTurn(_ turn: ConversationTurn) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            if let user = turn.user {
                userRow(user)
            }
            if !turn.assistantItems.isEmpty {
                CodexTurnSection {
                    VStack(alignment: .leading, spacing: 0) {
                        ForEach(Array(turn.assistantItems.enumerated()), id: \.element.id) { index, item in
                            assistantItemRow(item)
                            if index + 1 < turn.assistantItems.count {
                                assistantDivider(between: item, and: turn.assistantItems[index + 1])
                            }
                        }
                    }
                }
            }
        }
    }

    private func userRow(_ item: UIItem) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            UserPromptBlock(text: item.text)
            referenceList(item.attachments)
                .padding(.leading, 12)
        }
    }

    @ViewBuilder
    private func assistantItemRow(_ item: UIItem) -> some View {
        switch item.kind {
        case "user":
            EmptyView()
        case "message":
            RichMessageView(buffer: item.textBuffer)
                .frame(maxWidth: 920, alignment: .leading)
                .padding(.vertical, 4)
        case "reasoning":
            // D3: chain-of-thought is SECONDARY — collapsed by default. The
            // row auto-expands during a running turn (Codex sends the
            // final agentMessage in a stream we can't speed up, so showing
            // reasoning while we wait keeps the wait readable).
            //
            // Codex sometimes emits reasoning items with empty content
            // (started+completed but no textDelta and no summary/content
            // populated — verified Step 4 UX debug). An empty "Reasoning"
            // disclosure is pure noise, so skip it: better to show nothing
            // than a disclosure that opens to a blank panel.
            if item.hasNonWhitespaceText {
                ReasoningRow(buffer: item.textBuffer, model: model)
            }
        case "shell":
            // PRIMARY layer, but the command + exit code stay resident
            // while the (potentially huge) output collapses (D3: shell is
            // primary, its output is a DETAIL). Default-collapsed; the label
            // shows the line count so the user can judge whether to expand.
            VStack(alignment: .leading, spacing: 4) {
                Text("$ \(item.command)")
                    .font(.system(.callout, design: .monospaced))
                metadataLine(ToolPresentation.shellMetadata(item))
                if !item.output.isEmpty {
                    DisclosureGroup {
                        DeferredStreamingTextView(
                            model: model,
                            itemId: item.id,
                            content: .output,
                            buffer: item.outputBuffer,
                            font: .monospacedSystemFont(ofSize: 13, weight: .regular),
                            textColor: .secondaryLabelColor,
                            isDeferred: item.hasDeferredOutputBuffer
                        )
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.top, 4)
                    } label: {
                        Text(ToolPresentation.outputLabel(item.output))
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.tertiary)
                    }
                }
                if let code = item.exitCode, code != 0 {
                    Text("exit \(code)")
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.red)   // D8 system warning
                }
                if !item.actions.isEmpty {
                    DisclosureGroup {
                        VStack(alignment: .leading, spacing: 2) {
                            ForEach(Array(item.actions.enumerated()), id: \.offset) { _, action in
                                toolActionRow(action)
                            }
                        }
                        .padding(.top, 4)
                    } label: {
                        Text("\(item.actions.count) parsed actions")
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.tertiary)
                    }
                }
            }
            .padding(.vertical, 10)
        case "fileEdit":
            VStack(alignment: .leading, spacing: 4) {
                Text(item.path)
                    .font(.system(.callout, design: .monospaced, weight: .medium))
                metadataLine([item.statusName].filter { !$0.isEmpty })
                if !item.diff.isEmpty {
                    // Diffs can be large too — same collapse treatment.
                    DisclosureGroup {
                        DeferredStreamingTextView(
                            model: model,
                            itemId: item.id,
                            content: .diff,
                            buffer: item.diffBuffer,
                            font: .monospacedSystemFont(ofSize: 12, weight: .regular),
                            textColor: .labelColor,
                            isDeferred: item.hasDeferredDiffBuffer
                        )
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.top, 4)
                    } label: {
                        Text(ToolPresentation.outputLabel(item.diff, noun: "diff"))
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.tertiary)
                    }
                }
                if item.changes.count > 1 {
                    DisclosureGroup {
                        VStack(alignment: .leading, spacing: 8) {
                            ForEach(Array(item.changes.enumerated()), id: \.offset) { _, change in
                                VStack(alignment: .leading, spacing: 3) {
                                    Text("\(change.changeKind) \(change.path)")
                                        .font(.system(.caption, design: .monospaced))
                                        .foregroundStyle(.secondary)
                                    if !change.diff.isEmpty {
                                        Text(change.diff)
                                            .font(.system(.caption, design: .monospaced))
                                            .textSelection(.enabled)
                                    }
                                }
                            }
                        }
                        .padding(.top, 4)
                    } label: {
                        Text("\(item.changes.count) file changes")
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.tertiary)
                    }
                }
            }
            .padding(.vertical, 10)
        case "webSearch":
            VStack(alignment: .leading, spacing: 5) {
                HStack(spacing: 6) {
                    Image(systemName: "magnifyingglass")
                        .foregroundStyle(.tertiary)
                    Text(ToolPresentation.webSearchTitle(item))
                        .font(.system(.caption, weight: .medium))
                        .foregroundStyle(.tertiary)
                }
                if !item.query.isEmpty {
                    Text(item.query)
                        .font(.system(.callout))
                }
                VStack(alignment: .leading, spacing: 2) {
                    if !item.actionQuery.isEmpty {
                        webSearchDetail("query", item.actionQuery)
                    }
                    if !item.queries.isEmpty {
                        webSearchDetail("queries", item.queries.joined(separator: ", "))
                    }
                    if !item.url.isEmpty {
                        webSearchDetail("url", item.url)
                    }
                    if !item.pattern.isEmpty {
                        webSearchDetail("pattern", item.pattern)
                    }
                }
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(.secondary)
            }
            .padding(.vertical, 10)
        case "plan":
            labelledBlock(title: "Plan", systemImage: "checklist", text: item.text)
        case "hookPrompt":
            VStack(alignment: .leading, spacing: 5) {
                toolHeader("Hook prompt", systemImage: "curlybraces")
                ForEach(Array(item.fragments.enumerated()), id: \.offset) { _, fragment in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(fragment.hookRunId)
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.tertiary)
                        Text(fragment.text)
                            .font(.system(.callout))
                            .textSelection(.enabled)
                    }
                }
            }
            .padding(.vertical, 10)
        case "toolCall":
            toolCallBlock(item)
        case "collabAgentToolCall":
            collabAgentBlock(item)
        case "media":
            mediaBlock(item)
        case "reviewMode":
            labelledBlock(
                title: item.action == "entered" ? "Entered review mode" : "Exited review mode",
                systemImage: item.action == "entered" ? "text.badge.checkmark" : "text.badge.xmark",
                text: item.review
            )
        case "contextCompaction":
            toolHeader("Context compacted", systemImage: "arrow.down.right.and.arrow.up.left")
                .padding(.vertical, 10)
        default: // raw — neutralized unknown (E1/#19), visible not silent
            Text(item.descriptionText)
                .font(.system(.callout))
                .foregroundStyle(.tertiary)
                .padding(.vertical, 8)
        }
    }

    @ViewBuilder
    private func assistantDivider(between current: UIItem, and next: UIItem) -> some View {
        if current.kind != "message" || next.kind != "message" {
            Divider()
                .opacity(0.22)
                .padding(.vertical, 2)
        }
    }

    private func webSearchDetail(_ label: String, _ value: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 6) {
            Text(label)
                .foregroundStyle(.tertiary)
            Text(value)
                .textSelection(.enabled)
        }
    }

    private func toolHeader(_ title: String, systemImage: String) -> some View {
        HStack(spacing: 6) {
            Image(systemName: systemImage)
                .foregroundStyle(.tertiary)
            Text(title)
                .font(.system(.caption, weight: .medium))
                .foregroundStyle(.tertiary)
        }
    }

    private func labelledBlock(title: String, systemImage: String, text: String) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            toolHeader(title, systemImage: systemImage)
            if !text.isEmpty {
                Text(text)
                    .font(.system(.callout))
                    .textSelection(.enabled)
            }
        }
        .padding(.vertical, 10)
    }

    private func metadataLine(_ parts: [String]) -> some View {
        let values = parts.filter { !$0.isEmpty }
        return Group {
            if !values.isEmpty {
                Text(values.joined(separator: " · "))
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.tertiary)
                    .textSelection(.enabled)
            }
        }
    }

    private func toolActionRow(_ action: HistoryToolAction) -> some View {
        let detail = [action.name, action.path, action.query]
            .compactMap { $0 }
            .filter { !$0.isEmpty }
            .joined(separator: " · ")
        return HStack(alignment: .firstTextBaseline, spacing: 6) {
            Text(action.kind)
                .foregroundStyle(.tertiary)
            Text(detail.isEmpty ? action.command : "\(detail) — \(action.command)")
                .textSelection(.enabled)
        }
        .font(.system(.caption, design: .monospaced))
    }

    private func referenceList(_ refs: [HistoryReference]) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            ForEach(Array(refs.enumerated()), id: \.offset) { _, ref in
                let value = ref.text ?? ref.name ?? ref.path ?? ref.url ?? ""
                if !value.isEmpty {
                    HStack(spacing: 6) {
                        Text(ref.kind)
                            .foregroundStyle(.tertiary)
                        Text(value)
                            .textSelection(.enabled)
                    }
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
                }
            }
        }
    }

    private func toolCallBlock(_ item: UIItem) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            toolHeader(item.toolKind == "mcp" ? "MCP tool" : "Tool call", systemImage: "wrench.and.screwdriver")
            Text(ToolPresentation.toolName(item))
                .font(.system(.callout, design: .monospaced, weight: .medium))
            metadataLine(ToolPresentation.toolMetadata(item))
            toolPayload("arguments", item.arguments)
            toolPayload("result", item.result)
            toolPayload("error", item.errorText)
            referenceList(item.contentItems)
        }
        .padding(.vertical, 10)
    }

    private func toolPayload(_ label: String, _ value: String) -> some View {
        Group {
            if !value.isEmpty {
                DisclosureGroup {
                    Text(value)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                        .padding(.top, 4)
                } label: {
                    Text(label)
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.tertiary)
                }
            }
        }
    }

    private func collabAgentBlock(_ item: UIItem) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            toolHeader("Subagent", systemImage: "person.2")
            metadataLine([item.tool, item.statusName, item.model, item.reasoningEffort])
            if !item.prompt.isEmpty {
                Text(item.prompt)
                    .font(.system(.callout))
                    .textSelection(.enabled)
            }
            if !item.receiverThreadIds.isEmpty {
                webSearchDetail("receivers", item.receiverThreadIds.joined(separator: ", "))
                    .font(.system(.caption, design: .monospaced))
            }
            toolPayload("agent states", item.agentsStates)
        }
        .padding(.vertical, 10)
    }

    private func mediaBlock(_ item: UIItem) -> some View {
        let presentation = MediaPreviewPresentation(item: item)

        return VStack(alignment: .leading, spacing: 5) {
            toolHeader(item.mediaKind == "imageGeneration" ? "Image generation" : "Image", systemImage: "photo")
            if let image = presentation.localImage {
                Image(nsImage: image)
                    .resizable()
                    .interpolation(.high)
                    .scaledToFit()
                    .frame(maxWidth: 420, maxHeight: 320, alignment: .leading)
                    .clipShape(RoundedRectangle(cornerRadius: 6))
                    .overlay {
                        RoundedRectangle(cornerRadius: 6)
                            .stroke(Color(nsColor: .separatorColor), lineWidth: 1)
                    }
                    .accessibilityLabel(item.mediaKind == "imageGeneration" ? "Generated image" : "Image")
            }
            metadataLine([item.statusName, item.path, item.savedPath])
            toolPayload("result", item.result)
            if !item.revisedPrompt.isEmpty {
                webSearchDetail("revised prompt", item.revisedPrompt)
                    .font(.system(.caption, design: .monospaced))
            }
        }
        .padding(.vertical, 10)
    }

    private func errorRow(_ msg: String) -> some View {
        HStack(spacing: 6) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(.red)
            Text(msg)
                .font(.system(.callout))
                .foregroundStyle(.red)
        }
        .padding(.vertical, 10)
    }

    private func warningRow(_ msg: String) -> some View {
        HStack(spacing: 6) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
            Text(msg)
                .font(.system(.callout))
                .foregroundStyle(.orange)
        }
        .padding(.vertical, 10)
    }

    private func approvalRow(_ action: ActionRequest) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Image(systemName: "hand.raised.fill")
                    .foregroundStyle(.orange)
                Text(action.title)
                    .font(.system(.callout, weight: .semibold))
                Spacer()
                Button("Deny") { model.decidePendingAction("deny") }
                    .buttonStyle(.bordered)
                Button("Approve") { model.decidePendingAction("approve") }
                    .buttonStyle(.borderedProminent)
            }
            if !action.detail.isEmpty {
                Text(action.detail)
                    .font(.system(.callout, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }
        }
        .padding(.vertical, 10)
    }

    // MARK: D3 — bottom input + I1 queue indicator

    private var inputBar: some View {
        HStack(spacing: 10) {
            TextField(inputPlaceholder, text: $input, axis: .vertical)
                .textFieldStyle(.plain)
                .lineLimit(1...4)
                .onSubmit(send)
            if !model.queuedPrompts.isEmpty {
                Text("\(model.queuedPrompts.count) queued")
                    .font(.system(.caption))
                    .foregroundStyle(.tertiary)
            }
            Button(action: send) {
                Image(systemName: "return")
            }
            .keyboardShortcut(.return, modifiers: [])
            .disabled(input.trimmingCharacters(in: .whitespaces).isEmpty)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
    }

    private var inputPlaceholder: String {
        model.selectedHistoryThreadId == nil
            ? "Ask Codex to…"
            : "Continue this historical thread…"
    }

    private var renameAlertBinding: Binding<Bool> {
        Binding(
            get: { renameThread != nil },
            set: { if !$0 { renameThread = nil } }
        )
    }

    /// Collapsed-output label: tells the user how much is hidden so they can
    /// decide whether to expand (don't make them open it just to find out
    /// it's two lines).
    private struct ReasoningRow: View {
        let buffer: StreamingTextBuffer
        /// Observes the model so phase changes (.running → .ready) trigger
        /// this row's body. A snapshot `autoExpand: Bool` would freeze in
        /// SwiftUI's elision and miss the collapse signal.
        let model: SessionModel
        @State private var expanded = false
        @State private var lastAutoExpand = false
        var body: some View {
            let auto = model.shouldShowReasoningExpanded
            DisclosureGroup(isExpanded: $expanded) {
                StreamingTextView(
                    buffer: buffer,
                    font: .systemFont(ofSize: NSFont.systemFontSize(for: .small)),
                    textColor: .secondaryLabelColor
                )
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.top, 4)
            } label: {
                Text("Reasoning")
                    .font(.system(.callout))
                    .foregroundStyle(.tertiary)
            }
            .padding(.vertical, 8)
            // Track auto-expand edges. When model flips, sync local state.
            // Using onChange of the computed Bool — read above so the
            // dependency is registered with Observable tracking. The body
            // re-runs on every phase change because `auto` is read above.
            .onChange(of: auto) { _, newValue in
                expanded = newValue
                lastAutoExpand = newValue
            }
            .onAppear {
                expanded = auto
                lastAutoExpand = auto
            }
        }
    }

    private struct DeferredStreamingTextView: View {
        let model: SessionModel
        let itemId: String
        let content: SessionModel.DeferredContent
        let buffer: StreamingTextBuffer
        let font: NSFont
        let textColor: NSColor
        let isDeferred: Bool

        var body: some View {
            StreamingTextView(buffer: buffer, font: font, textColor: textColor)
                .overlay(alignment: .topLeading) {
                    if isDeferred {
                        ProgressView()
                            .controlSize(.small)
                    }
                }
                .onAppear {
                    model.materializeDeferredContent(itemId: itemId, content: content)
                }
        }
    }

    private func updatedLabel(_ seconds: Int) -> String {
        guard seconds > 0 else { return "" }
        let date = Date(timeIntervalSince1970: TimeInterval(seconds))
        return date.formatted(date: .abbreviated, time: .shortened)
    }

    private func send() {
        let p = input
        input = ""
        model.submit(p)
    }

    private func pickDirectory() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = false
        if panel.runModal() == .OK, let url = panel.url {
            if let err = model.chooseCwd(url) {
                model.errorMessage = err
            }
        }
    }
}

struct MediaPreviewPresentation: Equatable {
    let previewPath: String

    init(item: UIItem) {
        let saved = item.savedPath.trimmingCharacters(in: .whitespacesAndNewlines)
        let path = item.path.trimmingCharacters(in: .whitespacesAndNewlines)
        previewPath = saved.isEmpty ? path : saved
    }

    var localImage: NSImage? {
        guard !previewPath.isEmpty else { return nil }
        return NSImage(contentsOfFile: previewPath)
    }
}

struct TurnJumpRail: View {
    let items: [ConversationTurnNavigationItem]
    let selectedTurnId: String?
    let onJump: (String) -> Void
    let onJumpLatest: () -> Void
    let onWheelStep: (Int) -> Void
    @State private var hoveredTarget: TurnJumpRailHitTarget?
    @State private var railScrollOffset: CGFloat = 0

    var body: some View {
        GeometryReader { geometry in
            ZStack(alignment: .topLeading) {
                ZStack(alignment: .topLeading) {
                    ForEach(Array(items.enumerated()), id: \.element.id) { index, item in
                        Circle()
                            .fill(item.turnId == selectedTurnId ? Color.accentColor : Color(nsColor: .tertiaryLabelColor))
                            .frame(
                                width: dotSize(for: index),
                                height: dotSize(for: index)
                            )
                            .position(
                                x: TurnJumpRailLayout.centerX,
                                y: TurnJumpRailLayout.visualTurnY(
                                    index: index,
                                    count: items.count,
                                    height: geometry.size.height,
                                    scrollOffset: railScrollOffset,
                                    hoveredIndex: hoveredTurnIndex
                                )
                            )
                            .accessibilityLabel("Jump to turn \(item.index), \(item.summary)")
                    }
                }
                .frame(width: TurnJumpRailLayout.width, height: geometry.size.height)
                .clipped()

                Image(systemName: "arrow.down.to.line.compact")
                    .font(.system(size: latestSize(), weight: .semibold))
                    .foregroundStyle(selectedTurnId == nil ? Color.accentColor : Color(nsColor: .secondaryLabelColor))
                    .frame(width: 22, height: 22)
                    .position(
                        x: TurnJumpRailLayout.centerX,
                        y: TurnJumpRailLayout.latestY(height: geometry.size.height)
                    )
                    .accessibilityLabel("Jump to latest message")

                if let tooltip = tooltipText(for: hoveredTarget) {
                    Text(tooltip)
                        .font(.system(.caption))
                        .foregroundStyle(.primary)
                        .lineLimit(4)
                        .fixedSize(horizontal: false, vertical: true)
                        .frame(width: 190, alignment: .leading)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 6)
                        .background {
                            RoundedRectangle(cornerRadius: 6)
                                .fill(Color(nsColor: .windowBackgroundColor))
                                .shadow(color: Color.black.opacity(0.18), radius: 8, x: 0, y: 3)
                        }
                        .position(
                            x: -98,
                            y: tooltipY(for: hoveredTarget, height: geometry.size.height)
                        )
                        .allowsHitTesting(false)
                }

                RailInteractionView(
                    itemCount: items.count,
                    railScrollOffset: railScrollOffset,
                    onHoverTarget: { hoveredTarget = $0 },
                    onClickTarget: { target in
                        switch target {
                        case .turn(let index):
                            guard items.indices.contains(index) else { return }
                            onJump(items[index].turnId)
                        case .latest:
                            onJumpLatest()
                        }
                    },
                    onWheelStep: { direction in
                        onWheelStep(direction)
                    }
                )
                .frame(width: TurnJumpRailLayout.width, height: geometry.size.height)
            }
            .onChange(of: items.count) {
                revealSelectedTurn(height: geometry.size.height)
            }
            .onChange(of: selectedTurnId) {
                revealSelectedTurn(height: geometry.size.height)
            }
        }
        .frame(width: 28)
        .frame(maxHeight: .infinity)
        .animation(.spring(response: 0.18, dampingFraction: 0.68), value: hoveredTarget)
        .animation(.easeInOut(duration: 0.12), value: railScrollOffset)
    }

    private var hoveredTurnIndex: Int? {
        guard case .turn(let index) = hoveredTarget else { return nil }
        return index
    }

    private func revealSelectedTurn(height: CGFloat) {
        guard let selectedIndex = selectedTurnId.flatMap({ selected in
            items.firstIndex { $0.turnId == selected }
        }) else {
            railScrollOffset = TurnJumpRailLayout.clampedScrollOffset(
                railScrollOffset,
                count: items.count,
                height: height
            )
            return
        }
        railScrollOffset = TurnJumpRailLayout.scrollOffsetToReveal(
            index: selectedIndex,
            count: items.count,
            height: height,
            currentOffset: railScrollOffset
        )
    }

    private func dotSize(for index: Int) -> CGFloat {
        let selectedSize: CGFloat = items[index].turnId == selectedTurnId ? 8 : 6
        guard case .turn(let hoveredIndex) = hoveredTarget else { return selectedSize }
        if hoveredIndex == index { return 15 }
        if abs(hoveredIndex - index) == 1 { return 10 }
        return selectedSize
    }

    private func latestSize() -> CGFloat {
        hoveredTarget == .latest ? 14 : 10
    }

    private func tooltipText(for target: TurnJumpRailHitTarget?) -> String? {
        guard let target else { return nil }
        switch target {
        case .turn(let index):
            guard items.indices.contains(index) else { return nil }
            let item = items[index]
            var parts = ["第 \(item.index) 轮", item.summary]
            if item.attachmentCount > 0 {
                parts.append("\(item.attachmentCount) 个附件")
            }
            return parts.joined(separator: "\n")
        case .latest:
            return "跳到最新"
        }
    }

    private func tooltipY(for target: TurnJumpRailHitTarget?, height: CGFloat) -> CGFloat {
        guard let target else { return 0 }
        switch target {
        case .turn(let index):
            return TurnJumpRailLayout.visualTurnY(
                index: index,
                count: items.count,
                height: height,
                scrollOffset: railScrollOffset,
                hoveredIndex: hoveredTurnIndex
            )
        case .latest:
            return TurnJumpRailLayout.latestY(height: height)
        }
    }
}

enum TurnJumpRailHitTarget: Equatable {
    case turn(Int)
    case latest
}

struct ConversationTurnViewportPosition: Equatable {
    let turnId: String
    let minY: CGFloat
}

struct ConversationScrollSpy {
    static func currentTurnId(
        from positions: [ConversationTurnViewportPosition],
        topThreshold: CGFloat = 32
    ) -> String? {
        guard !positions.isEmpty else { return nil }
        let sorted = positions.sorted { lhs, rhs in
            if lhs.minY != rhs.minY {
                return lhs.minY < rhs.minY
            }
            return lhs.turnId < rhs.turnId
        }

        if let reached = sorted.filter({ $0.minY <= topThreshold }).last {
            return reached.turnId
        }
        return sorted.first?.turnId
    }
}

private struct ConversationTurnPositionPreferenceKey: PreferenceKey {
    static let defaultValue: [ConversationTurnViewportPosition] = []

    static func reduce(
        value: inout [ConversationTurnViewportPosition],
        nextValue: () -> [ConversationTurnViewportPosition]
    ) {
        value.append(contentsOf: nextValue())
    }
}

struct TurnJumpRailLayout {
    static let width: CGFloat = 28
    static let centerX: CGFloat = 14
    static let turnSpacing: CGFloat = 18
    private static let topPadding: CGFloat = 14
    private static let latestBottomPadding: CGFloat = 18
    private static let latestGap: CGFloat = 32
    private static let hitRadius: CGFloat = 12

    static func turnY(
        index: Int,
        count: Int,
        height: CGFloat,
        scrollOffset: CGFloat = 0
    ) -> CGFloat {
        firstTurnY(count: count, height: height) + CGFloat(index) * turnSpacing - scrollOffset
    }

    static func visualTurnY(
        index: Int,
        count: Int,
        height: CGFloat,
        scrollOffset: CGFloat = 0,
        hoveredIndex: Int? = nil
    ) -> CGFloat {
        let baseY = turnY(index: index, count: count, height: height, scrollOffset: scrollOffset)
        guard let hoveredIndex else { return baseY }
        let distance = index - hoveredIndex
        guard distance != 0 else { return baseY }
        return baseY + (distance > 0 ? 1 : -1) * cumulativeDockExpansion(stepsFromHover: abs(distance))
    }

    private static func cumulativeDockExpansion(stepsFromHover: Int) -> CGFloat {
        guard stepsFromHover > 0 else { return 0 }
        let perGapExpansion: [CGFloat] = [7, 3, 1.5]
        return (0..<stepsFromHover).reduce(CGFloat(0)) { total, step in
            total + (step < perGapExpansion.count ? perGapExpansion[step] : perGapExpansion.last ?? 0)
        }
    }

    static func firstTurnY(count: Int, height: CGFloat) -> CGFloat {
        guard count > 0 else { return height / 2 }
        let latest = latestY(height: height)
        let availableTop = topPadding
        let availableBottom = max(availableTop, latest - latestGap)
        let contentHeight = CGFloat(max(0, count - 1)) * turnSpacing
        let centeredStart = (height - contentHeight) / 2
        return min(max(centeredStart, availableTop), availableBottom)
    }

    static func latestY(height: CGFloat) -> CGFloat {
        max(topPadding + latestGap, height - latestBottomPadding)
    }

    static func maxScrollOffset(count: Int, height: CGFloat) -> CGFloat {
        guard count > 0 else { return 0 }
        let latest = latestY(height: height)
        let availableBottom = max(topPadding, latest - latestGap)
        let lastYWithoutScroll = turnY(index: count - 1, count: count, height: height, scrollOffset: 0)
        return max(0, lastYWithoutScroll - availableBottom)
    }

    static func clampedScrollOffset(_ offset: CGFloat, count: Int, height: CGFloat) -> CGFloat {
        min(max(0, offset), maxScrollOffset(count: count, height: height))
    }

    static func scrollOffsetToReveal(
        index: Int,
        count: Int,
        height: CGFloat,
        currentOffset: CGFloat
    ) -> CGFloat {
        let currentY = turnY(index: index, count: count, height: height, scrollOffset: currentOffset)
        let visibleTop = topPadding
        let visibleBottom = max(visibleTop, latestY(height: height) - latestGap)
        if currentY < visibleTop {
            return clampedScrollOffset(
                currentOffset - (visibleTop - currentY),
                count: count,
                height: height
            )
        }
        if currentY > visibleBottom {
            return clampedScrollOffset(
                currentOffset + (currentY - visibleBottom),
                count: count,
                height: height
            )
        }
        return clampedScrollOffset(currentOffset, count: count, height: height)
    }

    static func stepTarget(
        selectedIndex: Int?,
        direction: Int,
        count: Int
    ) -> TurnJumpRailHitTarget? {
        guard count > 0 else { return nil }
        if direction > 0 {
            guard let selectedIndex else { return nil }
            if selectedIndex >= count - 1 { return .latest }
            return .turn(selectedIndex + 1)
        }
        if direction < 0 {
            guard let selectedIndex else { return .turn(count - 1) }
            if selectedIndex <= 0 { return .turn(0) }
            return .turn(selectedIndex - 1)
        }
        return nil
    }

    static func hitTarget(
        at point: CGPoint,
        count: Int,
        height: CGFloat,
        scrollOffset: CGFloat = 0
    ) -> TurnJumpRailHitTarget? {
        guard point.x >= 0, point.x <= width else { return nil }
        if abs(point.y - latestY(height: height)) <= hitRadius {
            return .latest
        }

        guard count > 0 else { return nil }
        let hits = (0..<count).map { index in
            (index: index, distance: abs(point.y - turnY(
                index: index,
                count: count,
                height: height,
                scrollOffset: scrollOffset
            )))
        }
        guard let nearest = hits.min(by: { $0.distance < $1.distance }),
              nearest.distance <= hitRadius else {
            return nil
        }
        return .turn(nearest.index)
    }
}

private struct RailInteractionView: NSViewRepresentable {
    let itemCount: Int
    let railScrollOffset: CGFloat
    let onHoverTarget: (TurnJumpRailHitTarget?) -> Void
    let onClickTarget: (TurnJumpRailHitTarget) -> Void
    let onWheelStep: (Int) -> Void

    func makeNSView(context: Context) -> RailInteractionNSView {
        RailInteractionNSView(
            itemCount: itemCount,
            railScrollOffset: railScrollOffset,
            onHoverTarget: onHoverTarget,
            onClickTarget: onClickTarget,
            onWheelStep: onWheelStep
        )
    }

    func updateNSView(_ nsView: RailInteractionNSView, context: Context) {
        nsView.itemCount = itemCount
        nsView.railScrollOffset = railScrollOffset
        nsView.onHoverTarget = onHoverTarget
        nsView.onClickTarget = onClickTarget
        nsView.onWheelStep = onWheelStep
    }
}

private final class RailInteractionNSView: NSView {
    var itemCount: Int
    var railScrollOffset: CGFloat
    var onHoverTarget: (TurnJumpRailHitTarget?) -> Void
    var onClickTarget: (TurnJumpRailHitTarget) -> Void
    var onWheelStep: (Int) -> Void
    private var lastStepAt = Date.distantPast

    init(
        itemCount: Int,
        railScrollOffset: CGFloat,
        onHoverTarget: @escaping (TurnJumpRailHitTarget?) -> Void,
        onClickTarget: @escaping (TurnJumpRailHitTarget) -> Void,
        onWheelStep: @escaping (Int) -> Void
    ) {
        self.itemCount = itemCount
        self.railScrollOffset = railScrollOffset
        self.onHoverTarget = onHoverTarget
        self.onClickTarget = onClickTarget
        self.onWheelStep = onWheelStep
        super.init(frame: .zero)
        wantsLayer = true
        layer?.backgroundColor = NSColor.clear.cgColor
    }

    required init?(coder: NSCoder) { nil }

    override func updateTrackingAreas() {
        super.updateTrackingAreas()
        trackingAreas.forEach(removeTrackingArea)
        addTrackingArea(NSTrackingArea(
            rect: bounds,
            options: [.activeInKeyWindow, .mouseMoved, .mouseEnteredAndExited, .inVisibleRect],
            owner: self,
            userInfo: nil
        ))
    }

    override func mouseMoved(with event: NSEvent) {
        onHoverTarget(hitTarget(for: event))
    }

    override func mouseExited(with event: NSEvent) {
        onHoverTarget(nil)
    }

    override func mouseDown(with event: NSEvent) {
        guard let target = hitTarget(for: event) else { return }
        onClickTarget(target)
    }

    override func scrollWheel(with event: NSEvent) {
        let now = Date()
        guard now.timeIntervalSince(lastStepAt) >= 0.12 else { return }
        let delta = event.scrollingDeltaY
        guard abs(delta) >= 0.1 else { return }
        lastStepAt = now
        onWheelStep(delta < 0 ? 1 : -1)
    }

    private func hitTarget(for event: NSEvent) -> TurnJumpRailHitTarget? {
        let local = convert(event.locationInWindow, from: nil)
        let topOriginPoint = CGPoint(x: local.x, y: bounds.height - local.y)
        return TurnJumpRailLayout.hitTarget(
            at: topOriginPoint,
            count: itemCount,
            height: bounds.height,
            scrollOffset: railScrollOffset
        )
    }
}
