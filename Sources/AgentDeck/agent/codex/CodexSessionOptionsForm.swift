import AppKit
import AgentDeckCore

// MARK: - CodexSessionOptionsForm (Task 6B)
//
// NewSessionDialog 中嵌入的 Codex vendor 选项表单。
// 表单状态：approvalPolicy / sandbox / persistApproval / reasoningEffort。
// `buildVendorOptions()` 把状态打包为 `VendorSessionOptions.codex(...)`。
@MainActor
public final class CodexSessionOptionsForm: NSViewController, VendorOptionsFormVC {

    // MARK: - State

    private var approvalPolicy: CodexApprovalPolicy = .onRequest
    private var sandbox: CodexSandboxMode = .workspaceWrite
    private var persistApproval: Bool = false
    private var reasoningEffort: CodexReasoningEffort = .medium

    // MARK: - UI

    private let approvalPopup = NSPopUpButton(frame: .zero, pullsDown: false)
    private let sandboxPopup = NSPopUpButton(frame: .zero, pullsDown: false)
    private let persistCheckbox = NSButton(
        checkboxWithTitle: "Persist approval", target: nil, action: nil
    )
    private let effortPopup = NSPopUpButton(frame: .zero, pullsDown: false)

    private let approvalOrder: [CodexApprovalPolicy] = [.onRequest, .never, .always]
    private let sandboxOrder: [CodexSandboxMode] = [.readOnly, .workspaceWrite, .fullAccess]
    private let effortOrder: [CodexReasoningEffort] = [.minimal, .low, .medium, .high]

    // MARK: - Programmatic setters (used by tests)

    public func setApprovalPolicy(_ v: CodexApprovalPolicy) {
        approvalPolicy = v
        if let idx = approvalOrder.firstIndex(of: v) {
            approvalPopup.selectItem(at: idx)
        }
    }
    public func setSandbox(_ v: CodexSandboxMode) {
        sandbox = v
        if let idx = sandboxOrder.firstIndex(of: v) {
            sandboxPopup.selectItem(at: idx)
        }
    }
    public func setPersistApproval(_ v: Bool) {
        persistApproval = v
        persistCheckbox.state = v ? .on : .off
    }
    public func setReasoningEffort(_ v: CodexReasoningEffort) {
        reasoningEffort = v
        if let idx = effortOrder.firstIndex(of: v) {
            effortPopup.selectItem(at: idx)
        }
    }

    // MARK: - VendorOptionsFormVC

    public func buildVendorOptions() -> VendorSessionOptions {
        .codex(CodexSessionOptions(
            approvalPolicy: approvalPolicy,
            sandbox: sandbox,
            persistApproval: persistApproval,
            reasoningEffort: reasoningEffort,
            mcpOverrides: []
        ))
    }

    // MARK: - loadView

    public override func loadView() {
        let root = NSView()
        root.translatesAutoresizingMaskIntoConstraints = false

        approvalPopup.addItems(withTitles: approvalOrder.map(\.rawValue))
        approvalPopup.target = self
        approvalPopup.action = #selector(approvalChanged)
        approvalPopup.selectItem(at: approvalOrder.firstIndex(of: approvalPolicy) ?? 0)

        sandboxPopup.addItems(withTitles: sandboxOrder.map(\.rawValue))
        sandboxPopup.target = self
        sandboxPopup.action = #selector(sandboxChanged)
        sandboxPopup.selectItem(at: sandboxOrder.firstIndex(of: sandbox) ?? 1)

        persistCheckbox.target = self
        persistCheckbox.action = #selector(persistChanged)
        persistCheckbox.state = persistApproval ? .on : .off

        effortPopup.addItems(withTitles: effortOrder.map(\.rawValue))
        effortPopup.target = self
        effortPopup.action = #selector(effortChanged)
        effortPopup.selectItem(at: effortOrder.firstIndex(of: reasoningEffort) ?? 2)

        let approvalRow = labeledRow(title: "Approval", control: approvalPopup)
        let sandboxRow = labeledRow(title: "Sandbox", control: sandboxPopup)
        let effortRow = labeledRow(title: "Effort", control: effortPopup)
        let persistRow = labeledRow(title: "", control: persistCheckbox)

        let column = NSStackView(views: [approvalRow, sandboxRow, persistRow, effortRow])
        column.orientation = .vertical
        column.alignment = .leading
        column.spacing = 8
        column.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(column)
        NSLayoutConstraint.activate([
            column.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 12),
            column.trailingAnchor.constraint(lessThanOrEqualTo: root.trailingAnchor, constant: -12),
            column.topAnchor.constraint(equalTo: root.topAnchor, constant: 8),
            column.bottomAnchor.constraint(lessThanOrEqualTo: root.bottomAnchor, constant: -8),
        ])
        view = root
    }

    private func labeledRow(title: String, control: NSView) -> NSView {
        let label = NSTextField(labelWithString: title)
        label.alignment = .right
        label.widthAnchor.constraint(equalToConstant: 90).isActive = true
        let row = NSStackView(views: [label, control])
        row.orientation = .horizontal
        row.alignment = .centerY
        row.spacing = 8
        return row
    }

    // MARK: - Actions

    @objc private func approvalChanged() {
        let idx = approvalPopup.indexOfSelectedItem
        if approvalOrder.indices.contains(idx) { approvalPolicy = approvalOrder[idx] }
    }
    @objc private func sandboxChanged() {
        let idx = sandboxPopup.indexOfSelectedItem
        if sandboxOrder.indices.contains(idx) { sandbox = sandboxOrder[idx] }
    }
    @objc private func persistChanged() {
        persistApproval = persistCheckbox.state == .on
    }
    @objc private func effortChanged() {
        let idx = effortPopup.indexOfSelectedItem
        if effortOrder.indices.contains(idx) { reasoningEffort = effortOrder[idx] }
    }
}
