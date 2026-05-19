import SwiftUI
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
            if model.cwd == nil {
                emptyState                  // D5
            } else {
                conversationStream          // D3 single column, D7 non-card
                Divider()
                inputBar                    // D3 bottom
            }
        }
        .frame(minWidth: 560, minHeight: 420)   // D9: min window size
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
            Text("e.g. “Fix the crash in the settings panel”")
                .font(.system(.callout))
                .foregroundStyle(.tertiary)
                .padding(.top, 8)
            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding(40)
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
            Text(item.text)
                .font(.system(.body, weight: .medium))
                .padding(.vertical, 10)
        case "reasoning":
            // D3: reasoning is SECONDARY — default-collapsed, muted.
            DisclosureGroup {
                Text(item.text)
                    .font(.system(.callout))
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                    .padding(.top, 4)
            } label: {
                Text("Reasoning")
                    .font(.system(.callout))
                    .foregroundStyle(.tertiary)
            }
            .padding(.vertical, 8)
        case "shell":
            // PRIMARY. SF Mono block (D8), no card (D7).
            VStack(alignment: .leading, spacing: 4) {
                Text("$ \(item.command)")
                    .font(.system(.callout, design: .monospaced))
                if !item.output.isEmpty {
                    Text(item.output)
                        .font(.system(.callout, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
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
                    Text(item.diff)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
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
