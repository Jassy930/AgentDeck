import AppKit

// MARK: - EmptyStateView (Task 11)
//
// AppKit port of SessionView.emptyState (D5 first-frame / no-cwd state).
//
// Layout (vertical, centred):
//   "AgentDeck"                       — title (semibold, 28pt)
//   "Watch your coding agent…"        — subtitle (.body, secondary)
//   [Choose project directory…]       — borderedProminent → NSOpenPanel → model.chooseCwd
//   [Refresh history]                 — bordered → model.loadHistory
//   "e.g. "Fix the crash…""           — callout, tertiary
//
// The view is stateless; SessionViewController replaces it with
// ConversationViewController when model.cwd becomes non-nil.

@MainActor
final class EmptyStateView: NSView {

    // MARK: - Init

    private let model: SessionModel

    init(model: SessionModel) {
        self.model = model
        super.init(frame: .zero)
        setupSubviews()
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) not supported") }

    // MARK: - Layout

    private func setupSubviews() {
        translatesAutoresizingMaskIntoConstraints = false

        // Title
        let titleLabel = NSTextField(labelWithString: "AgentDeck")
        titleLabel.font = .systemFont(ofSize: 28, weight: .semibold)
        titleLabel.alignment = .center
        titleLabel.translatesAutoresizingMaskIntoConstraints = false

        // Subtitle
        let subtitleLabel = NSTextField(labelWithString: "Watch your coding agent work, and stay in control.")
        subtitleLabel.font = .systemFont(ofSize: NSFont.systemFontSize)
        subtitleLabel.textColor = .secondaryLabelColor
        subtitleLabel.alignment = .center
        subtitleLabel.translatesAutoresizingMaskIntoConstraints = false

        // "Choose project directory…" button
        let chooseButton = NSButton(
            title: "Choose project directory…",
            target: self,
            action: #selector(pickDirectory)
        )
        chooseButton.bezelStyle = .rounded
        chooseButton.controlSize = .regular
        if #available(macOS 14.0, *) {
            // borderedProminent style equivalent
            chooseButton.hasDestructiveAction = false
        }
        chooseButton.keyEquivalent = "\r"
        chooseButton.translatesAutoresizingMaskIntoConstraints = false

        // "Refresh history" button
        let refreshButton = NSButton(
            title: "Refresh history",
            target: self,
            action: #selector(refreshHistory)
        )
        refreshButton.bezelStyle = .rounded
        refreshButton.controlSize = .regular
        refreshButton.translatesAutoresizingMaskIntoConstraints = false

        // Example hint
        let hintLabel = NSTextField(labelWithString: "e.g. \u{201C}Fix the crash in the settings panel\u{201D}")
        hintLabel.font = .systemFont(ofSize: NSFont.smallSystemFontSize + 1)
        hintLabel.textColor = .tertiaryLabelColor
        hintLabel.alignment = .center
        hintLabel.translatesAutoresizingMaskIntoConstraints = false

        // Spacers mimic SwiftUI Spacer() above and below
        let topSpacer = NSView()
        topSpacer.translatesAutoresizingMaskIntoConstraints = false
        let bottomSpacer = NSView()
        bottomSpacer.translatesAutoresizingMaskIntoConstraints = false

        // Stack: topSpacer | title | subtitle | choose | refresh | hint | bottomSpacer
        let stack = NSStackView(views: [
            topSpacer,
            titleLabel,
            subtitleLabel,
            chooseButton,
            refreshButton,
            hintLabel,
            bottomSpacer,
        ])
        stack.orientation = .vertical
        stack.alignment = .centerX
        stack.spacing = 16
        // Match SwiftUI's `.padding(.top, 4)` before choose button, `.padding(.top, 8)` before hint
        stack.setCustomSpacing(20, after: subtitleLabel)   // subtitle → chooseButton (body + 4pt extra)
        stack.setCustomSpacing(16, after: chooseButton)    // chooseButton → refreshButton
        stack.setCustomSpacing(24, after: refreshButton)   // refreshButton → hint (8pt extra)
        stack.translatesAutoresizingMaskIntoConstraints = false
        addSubview(stack)

        NSLayoutConstraint.activate([
            stack.topAnchor.constraint(equalTo: topAnchor, constant: 40),
            stack.bottomAnchor.constraint(equalTo: bottomAnchor, constant: -40),
            stack.centerXAnchor.constraint(equalTo: centerXAnchor),
            // Cap width so the text doesn't stretch absurdly wide
            stack.widthAnchor.constraint(lessThanOrEqualToConstant: 480),

            // Equal-height spacers so content is vertically centred
            topSpacer.heightAnchor.constraint(equalTo: bottomSpacer.heightAnchor),
        ])
    }

    // MARK: - Actions

    @objc private func pickDirectory() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = false
        // Run modally attached to the window when available, falling back to app-modal.
        if let window = window {
            panel.beginSheetModal(for: window) { [weak self] response in
                guard let self, response == .OK, let url = panel.url else { return }
                if let err = self.model.chooseCwd(url) {
                    self.model.errorMessage = err
                }
            }
        } else {
            if panel.runModal() == .OK, let url = panel.url {
                if let err = model.chooseCwd(url) {
                    model.errorMessage = err
                }
            }
        }
    }

    @objc private func refreshHistory() {
        model.loadHistory()
    }
}
