import AgentDeckCore
import UIKit

struct ApprovalCardPresentation: Equatable {
    let summary: String
    let vendorLine: String
    let kindLabel: String

    static func make(from request: RuntimeActionRequestV1) -> ApprovalCardPresentation {
        let vendorLine: String
        switch request.vendor {
        case .codex(let policy, let sandbox, let canPersist):
            vendorLine =
                "codex · \(policy.rawValue) · \(sandbox.rawValue)"
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
        return ApprovalCardPresentation(
            summary: request.summary, vendorLine: vendorLine, kindLabel: kindLabel)
    }

    static func allowsDecision(_ state: ApprovalState) -> Bool {
        state == .pending
    }

    static func allowsRetry(_ state: ApprovalState) -> Bool {
        switch state {
        case .submissionFailed, .deliveryFailed, .alreadyHandled(_, .deliveryFailed):
            true
        case .none, .pending, .submitting, .applied, .alreadyHandled, .expired:
            false
        }
    }

    static func stateText(_ state: ApprovalState) -> String {
        switch state {
        case .none, .pending:
            ""
        case .submitting(let decision):
            "正在提交\(decisionText(decision))…"
        case .applied(let decision):
            "已应用\(decisionText(decision)) ✓"
        case .alreadyHandled(let decision, let deliveryState):
            "已在另一控制端\(decisionText(decision)) · \(deliveryStateText(deliveryState))"
        case .submissionFailed(let decision):
            "\(decisionText(decision))提交结果未知 · 可重试同一决定"
        case .deliveryFailed(let decision):
            "\(decisionText(decision))已锁定 · 投递失败"
        case .expired(let decision):
            if let decision {
                "\(decisionText(decision))已锁定 · 已过期"
            } else {
                "审批已过期"
            }
        }
    }

    private static func decisionText(_ decision: ActionDecisionKind) -> String {
        switch decision {
        case .approve: "批准"
        case .deny: "拒绝"
        }
    }

    private static func deliveryStateText(_ state: ApprovalDeliveryStateV1) -> String {
        switch state {
        case .claimed: "已认领"
        case .applying: "正在投递"
        case .applied: "已应用"
        case .deliveryFailed: "投递失败"
        case .expired: "已过期"
        }
    }
}

final class ApprovalCardCell: UICollectionViewCell {
    private let kindLabel = UILabel()
    private let summaryLabel = UILabel()
    private let vendorLabel = UILabel()
    private let approveButton = UIButton(configuration: .filled())
    private let denyButton = UIButton(configuration: .gray())
    private let retryButton = UIButton(configuration: .filled())
    private let stateLabel = UILabel()
    var onApprove: (() -> Void)?
    var onDeny: (() -> Void)?
    var onRetry: (() -> Void)?

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
        card.layoutMargins = .init(
            top: DesignTokens.sp3, left: DesignTokens.sp3,
            bottom: DesignTokens.sp3, right: DesignTokens.sp3)
        card.backgroundColor = DesignTokens.surface
        card.layer.cornerRadius = DesignTokens.radiusLg
        card.layer.borderWidth = 1
        card.layer.borderColor = DesignTokens.accent.cgColor
        card.translatesAutoresizingMaskIntoConstraints = false
        contentView.addSubview(card)
        NSLayoutConstraint.activate([
            card.topAnchor.constraint(equalTo: contentView.topAnchor, constant: DesignTokens.sp2),
            card.bottomAnchor.constraint(
                equalTo: contentView.bottomAnchor, constant: -DesignTokens.sp2),
            card.leadingAnchor.constraint(
                equalTo: contentView.leadingAnchor, constant: DesignTokens.sp4),
            card.trailingAnchor.constraint(
                equalTo: contentView.trailingAnchor, constant: -DesignTokens.sp4),
        ])
        kindLabel.font = .preferredFont(forTextStyle: .caption1)
        kindLabel.textColor = DesignTokens.accent
        summaryLabel.font = .monospacedSystemFont(ofSize: 14, weight: .medium)
        summaryLabel.textColor = DesignTokens.text
        summaryLabel.numberOfLines = 0
        vendorLabel.font = .preferredFont(forTextStyle: .caption1)
        vendorLabel.textColor = DesignTokens.text2
        stateLabel.font = .preferredFont(forTextStyle: .subheadline)
        approveButton.setTitle("批准", for: .normal)
        approveButton.addAction(
            UIAction { [weak self] _ in self?.onApprove?() }, for: .touchUpInside)
        denyButton.setTitle("拒绝", for: .normal)
        denyButton.addAction(UIAction { [weak self] _ in self?.onDeny?() }, for: .touchUpInside)
        retryButton.setTitle("重试同一决定", for: .normal)
        retryButton.addAction(UIAction { [weak self] _ in self?.onRetry?() }, for: .touchUpInside)
        let buttons = UIStackView(arrangedSubviews: [approveButton, denyButton])
        buttons.axis = .horizontal
        buttons.spacing = DesignTokens.sp2
        buttons.distribution = .fillEqually
        [kindLabel, summaryLabel, vendorLabel, buttons, retryButton, stateLabel]
            .forEach(card.addArrangedSubview)
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    func configure(with presentation: ApprovalCardPresentation, state: ApprovalState) {
        kindLabel.text = presentation.kindLabel
        summaryLabel.text = presentation.summary
        vendorLabel.text = presentation.vendorLine
        let allowsDecision = ApprovalCardPresentation.allowsDecision(state)
        approveButton.isHidden = !allowsDecision
        denyButton.isHidden = !allowsDecision
        retryButton.isHidden = !ApprovalCardPresentation.allowsRetry(state)
        let text = ApprovalCardPresentation.stateText(state)
        stateLabel.isHidden = text.isEmpty
        stateLabel.text = text
        switch state {
        case .applied:
            stateLabel.textColor = DesignTokens.accent
        case .submissionFailed, .deliveryFailed, .alreadyHandled(_, .deliveryFailed), .expired:
            stateLabel.textColor = DesignTokens.warn
        case .none, .pending, .submitting, .alreadyHandled:
            stateLabel.textColor = DesignTokens.text2
        }
    }
}
