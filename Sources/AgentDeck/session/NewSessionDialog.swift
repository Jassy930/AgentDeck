import AgentDeckCore
import AppKit

// MARK: - NewSessionDialog (Task 6B)
//
// 单页表单：顶部用 NSSegmentedControl 选 agent；中部按所选 agent 展示
// vendor 选项表单（由 CapabilityRouter.sessionOptionsForm(for:) 提供）；
// 底部 cwd NSPathControl + 提示词 NSTextView + Start 按钮。
//
// 提交时直接构造 `RuntimeConversationDraft`，通过 `onSubmit` 交给
// SessionModel / AppRuntimeCoordinator；不再经过旧的 stdio 会话启动请求。
@MainActor
public final class NewSessionDialog: NSWindowController {

  public var onSubmit: ((RuntimeConversationDraft) -> Void)?

  // MARK: - State

  private var selectedAgent: AgentKind = .codex
  private var vendorForm: (NSViewController & VendorOptionsFormVC)?

  // MARK: - UI

  private let agentSegment = NSSegmentedControl(
    labels: ["Codex", "Claude Code"], trackingMode: .selectOne, target: nil, action: nil
  )
  private let vendorFormContainer = NSView()
  private let cwdPathControl = NSPathControl()
  private let promptTextView = NSTextView()
  private let promptScroll = NSScrollView()
  private let startButton = NSButton(title: "Start", target: nil, action: nil)
  private let cancelButton = NSButton(title: "Cancel", target: nil, action: nil)

  public init() {
    let window = NSWindow(
      contentRect: NSRect(x: 0, y: 0, width: 520, height: 460),
      styleMask: [.titled, .closable],
      backing: .buffered,
      defer: false
    )
    window.title = "New Session"
    super.init(window: window)
    buildContent()
    // 默认装载 Codex 表单
    installVendorForm(for: .codex)
  }

  required init?(coder: NSCoder) { fatalError("init(coder:) is not supported") }

  // MARK: - Build UI

  private func buildContent() {
    guard let window else { return }
    let root = NSView()
    root.translatesAutoresizingMaskIntoConstraints = false

    agentSegment.translatesAutoresizingMaskIntoConstraints = false
    agentSegment.setSelected(true, forSegment: 0)
    agentSegment.target = self
    agentSegment.action = #selector(agentSegmentChanged)

    vendorFormContainer.translatesAutoresizingMaskIntoConstraints = false

    cwdPathControl.translatesAutoresizingMaskIntoConstraints = false
    cwdPathControl.pathStyle = .standard
    cwdPathControl.url = URL(fileURLWithPath: NSHomeDirectory())
    cwdPathControl.isEditable = true
    cwdPathControl.target = self
    cwdPathControl.action = #selector(cwdChanged)

    promptScroll.translatesAutoresizingMaskIntoConstraints = false
    promptScroll.borderType = .bezelBorder
    promptScroll.hasVerticalScroller = true
    promptScroll.documentView = promptTextView
    promptTextView.isRichText = false
    promptTextView.isVerticallyResizable = true
    promptTextView.font = .monospacedSystemFont(
      ofSize: NSFont.systemFontSize, weight: .regular
    )

    startButton.target = self
    startButton.action = #selector(submit)
    startButton.bezelStyle = .rounded
    startButton.keyEquivalent = "\r"

    cancelButton.target = self
    cancelButton.action = #selector(cancel)
    cancelButton.bezelStyle = .rounded
    cancelButton.keyEquivalent = "\u{1b}"

    let agentRow = labeledRow(title: "Agent", control: agentSegment)
    let cwdRow = labeledRow(title: "Cwd", control: cwdPathControl)

    let promptLabel = NSTextField(labelWithString: "Prompt (optional)")
    promptLabel.font = .systemFont(ofSize: NSFont.systemFontSize(for: .small) + 1)
    promptLabel.textColor = DesignTokens.text2

    let buttonRow = NSStackView(views: [NSView(), cancelButton, startButton])
    buttonRow.orientation = .horizontal
    buttonRow.spacing = 8
    buttonRow.alignment = .centerY
    buttonRow.distribution = .fill

    let column = NSStackView(views: [
      agentRow,
      vendorFormContainer,
      cwdRow,
      promptLabel,
      promptScroll,
      buttonRow,
    ])
    column.orientation = .vertical
    column.alignment = .leading
    column.spacing = 10
    column.translatesAutoresizingMaskIntoConstraints = false
    root.addSubview(column)

    NSLayoutConstraint.activate([
      column.topAnchor.constraint(equalTo: root.topAnchor, constant: 16),
      column.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 16),
      column.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -16),
      column.bottomAnchor.constraint(equalTo: root.bottomAnchor, constant: -16),

      promptScroll.heightAnchor.constraint(greaterThanOrEqualToConstant: 80),
      promptScroll.leadingAnchor.constraint(equalTo: column.leadingAnchor),
      promptScroll.trailingAnchor.constraint(equalTo: column.trailingAnchor),

      vendorFormContainer.leadingAnchor.constraint(equalTo: column.leadingAnchor),
      vendorFormContainer.trailingAnchor.constraint(equalTo: column.trailingAnchor),
      vendorFormContainer.heightAnchor.constraint(greaterThanOrEqualToConstant: 160),

      buttonRow.leadingAnchor.constraint(equalTo: column.leadingAnchor),
      buttonRow.trailingAnchor.constraint(equalTo: column.trailingAnchor),
    ])

    window.contentView = root
  }

  private func labeledRow(title: String, control: NSView) -> NSView {
    let label = NSTextField(labelWithString: title)
    label.alignment = .right
    label.widthAnchor.constraint(equalToConstant: 60).isActive = true
    let row = NSStackView(views: [label, control])
    row.orientation = .horizontal
    row.alignment = .centerY
    row.spacing = 8
    return row
  }

  // MARK: - Vendor form switching

  private func installVendorForm(for kind: AgentKind) {
    for subview in vendorFormContainer.subviews {
      subview.removeFromSuperview()
    }
    let form = CapabilityRouter.sessionOptionsForm(for: kind)
    self.vendorForm = form
    // Force view load
    form.loadViewIfNeeded()
    let v = form.view
    v.translatesAutoresizingMaskIntoConstraints = false
    vendorFormContainer.addSubview(v)
    NSLayoutConstraint.activate([
      v.topAnchor.constraint(equalTo: vendorFormContainer.topAnchor),
      v.leadingAnchor.constraint(equalTo: vendorFormContainer.leadingAnchor),
      v.trailingAnchor.constraint(equalTo: vendorFormContainer.trailingAnchor),
      v.bottomAnchor.constraint(equalTo: vendorFormContainer.bottomAnchor),
    ])
    selectedAgent = kind
  }

  // MARK: - Actions

  @objc private func agentSegmentChanged() {
    let kind: AgentKind = agentSegment.selectedSegment == 0 ? .codex : .claudeCode
    installVendorForm(for: kind)
  }

  @objc private func cwdChanged() {
    // NSPathControl 自动写回 url；这里无需额外处理。
  }

  @objc private func submit() {
    guard let form = vendorForm else { return }
    let cwd = cwdPathControl.url ?? URL(fileURLWithPath: NSHomeDirectory())
    let prompt = promptTextView.string.isEmpty ? nil : promptTextView.string
    do {
      let draft = try Self.buildConversationDraft(
        agentKind: selectedAgent,
        vendorForm: form,
        cwd: cwd,
        prompt: prompt
      )
      onSubmit?(draft)
      window?.close()
    } catch {
      window?.presentError(error)
    }
  }

  @objc private func cancel() {
    window?.close()
  }

  // MARK: - Pure / testable assembly

  /// 纯函数，便于测试校验 Runtime v2 draft 装配和 unsupported-field fail-close。
  public static func buildConversationDraft(
    agentKind: AgentKind,
    vendorForm: VendorOptionsFormVC,
    cwd: URL,
    prompt: String?
  ) throws -> RuntimeConversationDraft {
    try RuntimeConversationDraft(
      agentKind: agentKind,
      cwd: cwd.path,
      prompt: prompt,
      vendorOptions: vendorForm.buildVendorOptions()
    )
  }
}
