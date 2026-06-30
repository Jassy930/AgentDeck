import AppKit

// MARK: - ClaudeCodeSessionOptionsForm (Task 6B)
//
// NewSessionDialog 中嵌入的 Claude Code vendor 选项表单。
// 表单字段：permissionMode / model / effort / outputStyle / worktree / sessionName。
// `buildVendorOptions()` 把状态打包为 `VendorSessionOptions.claudeCode(...)`。
@MainActor
public final class ClaudeCodeSessionOptionsForm: NSViewController, VendorOptionsFormVC {

    // MARK: - State

    private var permissionMode: ClaudeCodePermissionMode = .default
    private var model: String? = nil
    private var effort: String? = nil
    private var outputStyle: String? = nil
    private var worktree: String? = nil
    private var sessionName: String? = nil

    // MARK: - UI

    private let permissionPopup = NSPopUpButton(frame: .zero, pullsDown: false)
    private let modelField = NSTextField()
    private let effortField = NSTextField()
    private let outputStyleField = NSTextField()
    private let worktreeField = NSTextField()
    private let sessionNameField = NSTextField()

    private let permissionOrder: [ClaudeCodePermissionMode] = [
        .default, .acceptEdits, .plan, .auto, .dontAsk, .bypassPermissions
    ]

    // MARK: - Programmatic setters (used by tests)

    public func setPermissionMode(_ v: ClaudeCodePermissionMode) {
        permissionMode = v
        if let idx = permissionOrder.firstIndex(of: v) {
            permissionPopup.selectItem(at: idx)
        }
    }
    public func setModel(_ v: String?) {
        model = v
        modelField.stringValue = v ?? ""
    }
    public func setEffort(_ v: String?) {
        effort = v
        effortField.stringValue = v ?? ""
    }
    public func setOutputStyle(_ v: String?) {
        outputStyle = v
        outputStyleField.stringValue = v ?? ""
    }
    public func setWorktree(_ v: String?) {
        worktree = v
        worktreeField.stringValue = v ?? ""
    }
    public func setSessionName(_ v: String?) {
        sessionName = v
        sessionNameField.stringValue = v ?? ""
    }

    // MARK: - VendorOptionsFormVC

    public func buildVendorOptions() -> VendorSessionOptions {
        .claudeCode(ClaudeCodeSessionOptions(
            permissionMode: permissionMode,
            model: nilIfEmpty(model),
            effort: nilIfEmpty(effort),
            hooks: [],
            outputStyle: nilIfEmpty(outputStyle),
            allowedTools: nil,
            disallowedTools: nil,
            mcpConfigPath: nil,
            pluginDirs: [],
            worktree: nilIfEmpty(worktree),
            sessionName: nilIfEmpty(sessionName),
            sessionId: nil
        ))
    }

    private func nilIfEmpty(_ s: String?) -> String? {
        guard let s, !s.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            return nil
        }
        return s
    }

    // MARK: - loadView

    public override func loadView() {
        let root = NSView()
        root.translatesAutoresizingMaskIntoConstraints = false

        permissionPopup.addItems(withTitles: permissionOrder.map(\.rawValue))
        permissionPopup.target = self
        permissionPopup.action = #selector(permissionChanged)
        permissionPopup.selectItem(at: permissionOrder.firstIndex(of: permissionMode) ?? 0)

        for f in [modelField, effortField, outputStyleField, worktreeField, sessionNameField] {
            f.placeholderString = nil
            f.bezelStyle = .roundedBezel
            f.delegate = self
            f.translatesAutoresizingMaskIntoConstraints = false
            f.widthAnchor.constraint(greaterThanOrEqualToConstant: 200).isActive = true
        }
        modelField.placeholderString = "model (optional, e.g. opus)"
        effortField.placeholderString = "effort (optional, e.g. medium)"
        outputStyleField.placeholderString = "output style (optional)"
        worktreeField.placeholderString = "worktree path (optional)"
        sessionNameField.placeholderString = "session name (optional)"

        let rows: [NSView] = [
            labeledRow(title: "Permission", control: permissionPopup),
            labeledRow(title: "Model", control: modelField),
            labeledRow(title: "Effort", control: effortField),
            labeledRow(title: "Output", control: outputStyleField),
            labeledRow(title: "Worktree", control: worktreeField),
            labeledRow(title: "Name", control: sessionNameField),
        ]
        let column = NSStackView(views: rows)
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

    @objc private func permissionChanged() {
        let idx = permissionPopup.indexOfSelectedItem
        if permissionOrder.indices.contains(idx) {
            permissionMode = permissionOrder[idx]
        }
    }
}

extension ClaudeCodeSessionOptionsForm: NSTextFieldDelegate {
    public func controlTextDidChange(_ obj: Notification) {
        guard let field = obj.object as? NSTextField else { return }
        switch field {
        case modelField: model = field.stringValue
        case effortField: effort = field.stringValue
        case outputStyleField: outputStyle = field.stringValue
        case worktreeField: worktree = field.stringValue
        case sessionNameField: sessionName = field.stringValue
        default: break
        }
    }
}
