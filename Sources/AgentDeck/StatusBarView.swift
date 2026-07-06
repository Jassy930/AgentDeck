import AppKit
import AgentDeckCore
import Observation

/// AppKit status bar mirroring the SwiftUI `SessionView.statusBar` (D3/D9).
///
/// Layout (left → right):
///   • Phase dot (8×8, color by phase — see `phaseColor`)
///   • Agent kind icon (18×18, Task 6C)
///   • Status text (statusText, already includes elapsed seconds when running)
///   • [history badge] "Restored history" + timing if selectedHistoryThreadId != nil
///   • [new-session button] shown when viewing history
///   • Flexible spacer
///   • Project name (cwd.lastPathComponent), subtle trailing label
///
/// Refresh: `ObservationBinder` re-arms on every `selectedPhase`/`statusText`/
/// `cwd`/`selectedHistoryThreadId` read, so the bar stays in sync with the model
/// without polling.
@MainActor
final class StatusBarView: NSView {
    // MARK: - Init

    init(model: SessionModel) {
        self.model = model
        super.init(frame: .zero)
        buildSubviews()
        setupObservation()
        refresh()
    }

    /// No-arg init for unit tests or standalone usage (no model binding).
    init() {
        self.model = nil
        super.init(frame: .zero)
        buildSubviews()
    }

    required init?(coder: NSCoder) { nil }

    // MARK: - Private state

    private let model: SessionModel?
    private var binder: ObservationBinder?

    // MARK: - Subviews

    private let phaseDot: NSView = {
        let v = NSView()
        v.wantsLayer = true
        v.layer?.cornerRadius = 4
        return v
    }()

    /// T6C: agent kind icon shown between phase dot and status label.
    private let agentKindIconView: NSImageView = {
        let iv = NSImageView()
        iv.imageScaling = .scaleProportionallyUpOrDown
        iv.contentTintColor = DesignTokens.text2   // 模板图着色，暗背景可见
        iv.isHidden = true
        return iv
    }()

    private let statusLabel: NSTextField = {
        let f = NSTextField(labelWithString: "")
        f.font = .systemFont(ofSize: NSFont.systemFontSize(for: .small) + 1)
        f.textColor = DesignTokens.text2
        f.lineBreakMode = .byTruncatingTail
        return f
    }()

    private let historyBadge: NSTextField = {
        let f = NSTextField(labelWithString: "Restored history")
        f.font = .systemFont(ofSize: NSFont.systemFontSize(for: .mini))
        f.textColor = DesignTokens.text2
        f.isHidden = true
        return f
    }()

    private let historyTimingLabel: NSTextField = {
        let f = NSTextField(labelWithString: "")
        f.font = .systemFont(ofSize: NSFont.systemFontSize(for: .mini))
        f.textColor = DesignTokens.text3
        f.isHidden = true
        return f
    }()

    private let newSessionButton: NSButton = {
        let b = NSButton(title: "New session", target: nil, action: nil)
        b.bezelStyle = .inline
        b.isBordered = false
        b.font = .systemFont(ofSize: NSFont.systemFontSize(for: .mini))
        b.contentTintColor = DesignTokens.accent
        b.isHidden = true
        return b
    }()

    private let spacer = NSView()

    private let projectLabel: NSTextField = {
        let f = NSTextField(labelWithString: "")
        f.font = .systemFont(ofSize: NSFont.systemFontSize(for: .small) + 1)
        f.textColor = DesignTokens.text3
        f.lineBreakMode = .byTruncatingHead
        f.setContentHuggingPriority(.required, for: .horizontal)
        return f
    }()

    // MARK: - Layout

    private func buildSubviews() {
        for sub in [phaseDot, agentKindIconView, statusLabel, historyBadge, historyTimingLabel,
                    newSessionButton, spacer, projectLabel] as [NSView] {
            sub.translatesAutoresizingMaskIntoConstraints = false
            addSubview(sub)
        }

        // Horizontal stack: dot · agentKindIcon · statusLabel · historyBadge · timing · newSession · spacer · project
        let h: CGFloat = 16
        let vPad: CGFloat = 8
        let hPad: CGFloat = 16
        let gap: CGFloat = 8

        NSLayoutConstraint.activate([
            // Height of this view pinned by padding
            heightAnchor.constraint(greaterThanOrEqualToConstant: h + 2 * vPad),

            // Phase dot
            phaseDot.widthAnchor.constraint(equalToConstant: 8),
            phaseDot.heightAnchor.constraint(equalToConstant: 8),
            phaseDot.leadingAnchor.constraint(equalTo: leadingAnchor, constant: hPad),
            phaseDot.centerYAnchor.constraint(equalTo: centerYAnchor),

            // Agent kind icon (T6C) — sits between dot and status label
            agentKindIconView.widthAnchor.constraint(equalToConstant: 18),
            agentKindIconView.heightAnchor.constraint(equalToConstant: 18),
            agentKindIconView.leadingAnchor.constraint(equalTo: phaseDot.trailingAnchor, constant: gap),
            agentKindIconView.centerYAnchor.constraint(equalTo: centerYAnchor),

            // Status label
            statusLabel.leadingAnchor.constraint(equalTo: agentKindIconView.trailingAnchor, constant: gap),
            statusLabel.centerYAnchor.constraint(equalTo: centerYAnchor),

            // History badge
            historyBadge.leadingAnchor.constraint(equalTo: statusLabel.trailingAnchor, constant: gap),
            historyBadge.centerYAnchor.constraint(equalTo: centerYAnchor),

            // History timing
            historyTimingLabel.leadingAnchor.constraint(equalTo: historyBadge.trailingAnchor, constant: gap),
            historyTimingLabel.centerYAnchor.constraint(equalTo: centerYAnchor),

            // New session button
            newSessionButton.leadingAnchor.constraint(equalTo: historyTimingLabel.trailingAnchor, constant: gap),
            newSessionButton.centerYAnchor.constraint(equalTo: centerYAnchor),

            // Flexible spacer fills remaining width
            spacer.leadingAnchor.constraint(equalTo: newSessionButton.trailingAnchor, constant: gap),
            spacer.centerYAnchor.constraint(equalTo: centerYAnchor),
            spacer.heightAnchor.constraint(equalToConstant: 1),

            // Project label pinned to trailing
            projectLabel.leadingAnchor.constraint(equalTo: spacer.trailingAnchor, constant: gap),
            projectLabel.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -hPad),
            projectLabel.centerYAnchor.constraint(equalTo: centerYAnchor),
        ])

        newSessionButton.target = self
        newSessionButton.action = #selector(newSessionTapped)
    }

    // MARK: - T6C: Agent kind icon binding

    /// Bind an agent-kind icon into the status bar. Shown when a runtime is
    /// active; hidden when `kind == nil` (e.g., empty state, no selected runtime).
    func bind(agentKind: AgentKind?) {
        if let kind = agentKind, let img = AgentKindIcon.compactImage(for: kind) {
            agentKindIconView.image = img
            agentKindIconView.isHidden = false
        } else {
            agentKindIconView.isHidden = true
        }
    }

    // MARK: - Observation

    private func setupObservation() {
        guard let model else { return }
        let binder = ObservationBinder()
        self.binder = binder
        binder.bind { [weak model] in
            guard let model else { return }
            _ = model.selectedPhase
            _ = model.statusText
            _ = model.cwd
            _ = model.selectedHistoryThreadId
            _ = model.historyTimingSummary
        } onChange: { [weak self] in
            self?.refresh()
        }
    }

    // MARK: - Refresh

    private func refresh() {
        guard let model else { return }
        // Phase dot color (mirrors SessionView.statusColor)
        phaseDot.layer?.backgroundColor = phaseColor(for: model.selectedPhase).cgColor

        // Status text (already includes elapsed seconds)
        statusLabel.stringValue = model.statusText

        // History section
        let isHistory = model.selectedHistoryThreadId != nil
        historyBadge.isHidden = !isHistory
        newSessionButton.isHidden = !isHistory

        if isHistory {
            let timing = model.historyTimingSummary
            historyTimingLabel.stringValue = timing
            historyTimingLabel.isHidden = timing.isEmpty
        } else {
            historyTimingLabel.isHidden = true
        }

        // Project name
        projectLabel.stringValue = model.cwd?.lastPathComponent ?? ""
    }

    // MARK: - Phase color (ported from SessionView.statusColor)

    private func phaseColor(for phase: SessionModel.Phase) -> NSColor {
        switch phase {
        case .running, .starting:
            return DesignTokens.accent
        case .failed:
            return DesignTokens.danger
        case .waitingApproval:
            return DesignTokens.accent
        default:
            return DesignTokens.text2
        }
    }

    // MARK: - Actions

    @objc private func newSessionTapped() {
        model?.startNewSessionFromCurrentProject()
    }

    // MARK: - Deinit

    deinit {
        let b = binder
        Task { @MainActor in b?.invalidate() }
    }
}
