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
        .onDisappear { model.teardown() }       // A1: app exit kills daemon
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
            // Reading/replay lands in the next implementation slice. The row
            // is already shaped as a real selection target so the UI can grow
            // without changing the information architecture.
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
    }

    // MARK: D3/D7 — single-column stream, NON-CARD

    private var conversationStream: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 0) {
                ForEach(model.items) { item in
                    itemRow(item)
                    Divider().opacity(0.4)      // D7: subtle divider, not card
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
            // The user's prompt gets a subtle background block so "what I
            // said" is instantly distinct from "what the agent said". Kept
            // restrained (system fill, small radius, no border/shadow/left-
            // bar) so it reads as typographic grouping, not an AI-slop chat
            // bubble — the D7 line, walked deliberately.
            Text(item.text)
                .font(.system(.body, weight: .medium))
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 12)
                .padding(.vertical, 9)
                .background(
                    RoundedRectangle(cornerRadius: 6)
                        .fill(Color(nsColor: .quaternarySystemFill))  // D8
                )
                .padding(.vertical, 8)
        case "message":
            // PRIMARY answer the user reads. NOT collapsed — this is the
            // reply. A small "Codex" caption gives it an identity opposite
            // the user's background block, so the two are unmistakable
            // without making the reply a bubble too (asymmetry on purpose:
            // user = block, agent = labelled prose).
            VStack(alignment: .leading, spacing: 4) {
                Text("Codex")
                    .font(.system(.caption, weight: .medium))
                    .foregroundStyle(.tertiary)
                StreamingTextView(
                    buffer: item.textBuffer,
                    font: .systemFont(ofSize: NSFont.systemFontSize),
                    textColor: .labelColor
                )
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .padding(.vertical, 10)
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
            }
            .padding(.vertical, 10)
        case "fileEdit":
            VStack(alignment: .leading, spacing: 4) {
                Text(item.path)
                    .font(.system(.callout, design: .monospaced, weight: .medium))
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
            }
            .padding(.vertical, 10)
        default: // raw — neutralized unknown (E1/#19), visible not silent
            Text(item.descriptionText)
                .font(.system(.callout))
                .foregroundStyle(.tertiary)
                .padding(.vertical, 8)
        }
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
            TextField("Ask Codex to…", text: $input, axis: .vertical)
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
