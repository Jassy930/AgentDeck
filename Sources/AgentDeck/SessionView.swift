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
        switch model.phase {
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
                    .padding(.bottom, 12)
                }
            }
        }
        .frame(width: 260)
        .background(Color(nsColor: .controlBackgroundColor))
    }

    private func historyGroup(_ group: HistoryProjectGroup) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(group.projectName)
                .font(.system(.caption, weight: .semibold))
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .truncationMode(.middle)
                .padding(.horizontal, 12)
                .padding(.top, 10)
                .padding(.bottom, 4)
            ForEach(group.threads) { thread in
                historyThreadRow(thread)
            }
        }
    }

    private func historyThreadRow(_ thread: HistoryThreadSummary) -> some View {
        Button {
            model.openHistoryThread(thread)
        } label: {
            VStack(alignment: .leading, spacing: 3) {
                Text(thread.displayTitle)
                    .font(.system(.callout))
                    .foregroundStyle(.primary)
                    .lineLimit(2)
                HStack(spacing: 6) {
                    Text(thread.status)
                    Text(thread.source)
                    Text(updatedLabel(thread.updatedAt))
                }
                .font(.system(.caption))
                .foregroundStyle(.tertiary)
                .lineLimit(1)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 12)
            .padding(.vertical, 7)
        }
        .buttonStyle(.plain)
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

    // MARK: D3/D7 — single-column stream, NON-CARD

    private var conversationStream: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 0) {
                ForEach(Array(model.items.enumerated()), id: \.element.id) { index, item in
                    itemRow(item)
                    if shouldShowDivider(after: index) {
                        Divider().opacity(0.4)  // D7: subtle divider, not card
                    }
                }
                if let err = model.errorMessage {
                    errorRow(err)               // premise 9: visible failure
                }
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 12)
        }
    }

    @ViewBuilder
    private func itemRow(_ item: UIItem) -> some View {
        switch item.kind {
        case "user":
            VStack(alignment: .leading, spacing: 6) {
                UserPromptBlock(text: item.text)
                referenceList(item.attachments)
                    .padding(.leading, 12)
            }
        case "message":
            CodexDocumentSection(buffer: item.textBuffer)
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
                metadataLine(shellMetadata(item))
                if !item.output.isEmpty {
                    DisclosureGroup {
                        StreamingTextView(
                            buffer: item.outputBuffer,
                            font: .monospacedSystemFont(ofSize: 13, weight: .regular),
                            textColor: .secondaryLabelColor
                        )
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.top, 4)
                    } label: {
                        Text(outputLabel(item.output))
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
                        StreamingTextView(
                            buffer: item.diffBuffer,
                            font: .monospacedSystemFont(ofSize: 12, weight: .regular),
                            textColor: .labelColor
                        )
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.top, 4)
                    } label: {
                        Text(outputLabel(item.diff, noun: "diff"))
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
                    Text(webSearchTitle(item))
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

    private func shouldShowDivider(after index: Int) -> Bool {
        guard index + 1 < model.items.count else { return false }
        let current = model.items[index]
        let next = model.items[index + 1]
        return !(current.kind == "message" && next.kind == "message")
    }

    private func webSearchTitle(_ item: UIItem) -> String {
        switch item.action {
        case "search": return "Web search"
        case "openPage": return "Open web page"
        case "findInPage": return "Find in web page"
        case "other": return "Web search action"
        case "": return "Web search"
        default: return "Web search · \(item.action)"
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

    private func shellMetadata(_ item: UIItem) -> [String] {
        var parts: [String] = []
        if !item.statusName.isEmpty { parts.append(item.statusName) }
        if !item.cwdText.isEmpty { parts.append(item.cwdText) }
        if let duration = item.durationMs { parts.append("\(duration)ms") }
        if !item.sourceName.isEmpty { parts.append(item.sourceName) }
        if !item.processId.isEmpty { parts.append("pid \(item.processId)") }
        return parts
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
            Text(toolName(item))
                .font(.system(.callout, design: .monospaced, weight: .medium))
            metadataLine(toolMetadata(item))
            toolPayload("arguments", item.arguments)
            toolPayload("result", item.result)
            toolPayload("error", item.errorText)
            referenceList(item.contentItems)
        }
        .padding(.vertical, 10)
    }

    private func toolName(_ item: UIItem) -> String {
        let prefix = [item.server, item.namespace].first { !$0.isEmpty }
        if let prefix {
            return "\(prefix)/\(item.tool)"
        }
        return item.tool
    }

    private func toolMetadata(_ item: UIItem) -> [String] {
        var parts = [item.statusName].filter { !$0.isEmpty }
        if let success = item.success { parts.append(success ? "success" : "failed") }
        if let duration = item.durationMs { parts.append("\(duration)ms") }
        if !item.resourceUri.isEmpty { parts.append(item.resourceUri) }
        return parts
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
        VStack(alignment: .leading, spacing: 5) {
            toolHeader(item.mediaKind == "imageGeneration" ? "Image generation" : "Image", systemImage: "photo")
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

    private func outputLabel(_ text: String, noun: String = "output") -> String {
        let lines = text.split(separator: "\n", omittingEmptySubsequences: false).count
        return lines <= 1
            ? "Show \(noun)"
            : "Show \(noun) (\(lines) lines)"
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
