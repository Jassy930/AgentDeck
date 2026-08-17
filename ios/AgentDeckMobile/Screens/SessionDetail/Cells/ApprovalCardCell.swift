import UIKit
import AgentDeckMobileCore

struct ApprovalCardPresentation: Equatable {
    let summary: String
    let vendorLine: String
    let kindLabel: String

    static func make(from request: ActionRequest) -> ApprovalCardPresentation {
        let vendorLine: String
        switch request.vendor {
        case .codex(let policy, let sandbox, let canPersist):
            vendorLine = "codex · \(policy.rawValue) · \(sandbox.rawValue)"
                + (canPersist ? " · can persist" : "")
        case .claudeCode(let mode, let toolName):
            vendorLine = "claude code · \(mode.rawValue) · \(toolName)"
        }
        let kindLabel: String
        switch request.kind {
        case .executeCommand:
            kindLabel = "执行命令"
        case .editFiles:
            kindLabel = "编辑文件"
        case .grantExtraPermission:
            kindLabel = "授予额外权限"
        }
        return ApprovalCardPresentation(summary: request.summary, vendorLine: vendorLine, kindLabel: kindLabel)
    }
}

final class ApprovalCardCell: UICollectionViewCell {
    private let kindLabel = UILabel()
    private let summaryLabel = UILabel()
    private let vendorLabel = UILabel()
    private let approveButton = UIButton(configuration: .filled())
    private let denyButton = UIButton(configuration: .gray())
    private let stateLabel = UILabel()
    var onApprove: (() -> Void)?
    var onDeny: (() -> Void)?

    override init(frame: CGRect) {
        super.init(frame: frame)

        // 深色背景透明，避免系统默认白色覆盖外层 bg（与 CollapsibleItemCell 同先例）
        var bgConfig = UIBackgroundConfiguration.listPlainCell()
        bgConfig.backgroundColor = .clear
        backgroundConfiguration = bgConfig

        let card = UIStackView()
        card.axis = .vertical
        card.spacing = DesignTokens.sp2
        card.isLayoutMarginsRelativeArrangement = true
        card.layoutMargins = .init(top: DesignTokens.sp3, left: DesignTokens.sp3,
                                   bottom: DesignTokens.sp3, right: DesignTokens.sp3)
        card.backgroundColor = DesignTokens.surface
        card.layer.cornerRadius = DesignTokens.radiusLg
        card.layer.borderWidth = 1
        card.layer.borderColor = DesignTokens.accent.cgColor
        card.translatesAutoresizingMaskIntoConstraints = false
        contentView.addSubview(card)
        NSLayoutConstraint.activate([
            card.topAnchor.constraint(equalTo: contentView.topAnchor, constant: DesignTokens.sp2),
            card.bottomAnchor.constraint(equalTo: contentView.bottomAnchor, constant: -DesignTokens.sp2),
            card.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: DesignTokens.sp4),
            card.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -DesignTokens.sp4),
        ])
        kindLabel.font = .preferredFont(forTextStyle: .caption1)
        kindLabel.textColor = DesignTokens.accent
        summaryLabel.font = .monospacedSystemFont(ofSize: 14, weight: .medium)
        summaryLabel.textColor = DesignTokens.text
        summaryLabel.numberOfLines = 0
        vendorLabel.font = .preferredFont(forTextStyle: .caption1)
        vendorLabel.textColor = DesignTokens.text2
        stateLabel.font = .preferredFont(forTextStyle: .subheadline)
        approveButton.setTitle("Approve", for: .normal)
        approveButton.addAction(UIAction { [weak self] _ in self?.onApprove?() }, for: .touchUpInside)
        denyButton.setTitle("Deny", for: .normal)
        denyButton.addAction(UIAction { [weak self] _ in self?.onDeny?() }, for: .touchUpInside)
        let buttons = UIStackView(arrangedSubviews: [approveButton, denyButton])
        buttons.axis = .horizontal
        buttons.spacing = DesignTokens.sp2
        buttons.distribution = .fillEqually
        [kindLabel, summaryLabel, vendorLabel, buttons, stateLabel].forEach(card.addArrangedSubview)
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    func configure(with presentation: ApprovalCardPresentation, state: ApprovalState) {
        kindLabel.text = presentation.kindLabel
        summaryLabel.text = presentation.summary
        vendorLabel.text = presentation.vendorLine
        let decided = state == .approved || state == .denied
        approveButton.isHidden = decided
        denyButton.isHidden = decided
        stateLabel.isHidden = !decided
        stateLabel.text = state == .approved ? "已批准 ✓" : "已拒绝 ✕"
        stateLabel.textColor = state == .approved ? DesignTokens.accent : DesignTokens.text2
    }
}
