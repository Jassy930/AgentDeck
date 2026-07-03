import UIKit
import AgentDeckCore

struct CollapsiblePresentation: Equatable {
    let title: String
    let detail: String?
    let body: String?
    let bodyIsMono: Bool

    /// 与 macOS 端折叠规范一致：reasoning / shell / toolCall / fileEdit 折叠，
    /// 其余 kind 不归本 cell 管。纯函数，便于单测。
    static func make(from item: UIItem) -> CollapsiblePresentation? {
        switch item.kind {
        case "reasoning":
            return CollapsiblePresentation(title: "Reasoning", detail: nil,
                                           body: item.text.isEmpty ? nil : item.text, bodyIsMono: false)
        case "shell":
            var parts: [String] = []
            if !item.statusName.isEmpty { parts.append(item.statusName) }
            if let exit = item.exitCode { parts.append("exit \(exit)") }
            if let ms = item.durationMs { parts.append(String(format: "%.1fs", Double(ms) / 1000)) }
            return CollapsiblePresentation(
                title: "$ \(item.command)",
                detail: parts.isEmpty ? nil : parts.joined(separator: " · "),
                body: item.output.isEmpty ? nil : item.output,
                bodyIsMono: true)
        case "toolCall":
            let body = [item.arguments, item.result].filter { !$0.isEmpty }.joined(separator: "\n→ ")
            return CollapsiblePresentation(title: item.tool.isEmpty ? "Tool call" : item.tool,
                                           detail: nil, body: body.isEmpty ? nil : body, bodyIsMono: true)
        case "fileEdit":
            return CollapsiblePresentation(title: item.path.isEmpty ? "Diff" : item.path,
                                           detail: item.statusName.isEmpty ? nil : item.statusName,
                                           body: item.diff.isEmpty ? nil : item.diff, bodyIsMono: true)
        default:
            return nil
        }
    }
}

final class CollapsibleItemCell: UICollectionViewCell {
    private let headerButton = UIButton(type: .system)
    private let detailLabel = UILabel()
    private let bodyLabel = UILabel()
    private let container = UIStackView()
    var onToggle: (() -> Void)?

    override init(frame: CGRect) {
        super.init(frame: frame)
        // 深色背景透明，避免系统默认白色覆盖外层 bg
        var bgConfig = UIBackgroundConfiguration.listPlainCell()
        bgConfig.backgroundColor = .clear
        backgroundConfiguration = bgConfig

        container.axis = .vertical
        container.spacing = DesignTokens.sp1
        container.translatesAutoresizingMaskIntoConstraints = false
        contentView.addSubview(container)
        NSLayoutConstraint.activate([
            container.topAnchor.constraint(equalTo: contentView.topAnchor, constant: DesignTokens.sp1),
            container.bottomAnchor.constraint(equalTo: contentView.bottomAnchor, constant: -DesignTokens.sp1),
            container.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: DesignTokens.sp4),
            container.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -DesignTokens.sp4),
        ])
        headerButton.contentHorizontalAlignment = .leading
        headerButton.titleLabel?.font = .monospacedSystemFont(ofSize: 13, weight: .medium)
        headerButton.setTitleColor(DesignTokens.text2, for: .normal)
        headerButton.addAction(UIAction { [weak self] _ in self?.onToggle?() }, for: .touchUpInside)
        detailLabel.font = .preferredFont(forTextStyle: .caption1)
        detailLabel.textColor = DesignTokens.text2
        bodyLabel.numberOfLines = 0
        container.addArrangedSubview(headerButton)
        container.addArrangedSubview(detailLabel)
        container.addArrangedSubview(bodyLabel)
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    func configure(with presentation: CollapsiblePresentation, expanded: Bool) {
        let chevron = presentation.body == nil ? "" : (expanded ? "▾ " : "▸ ")
        headerButton.setTitle(chevron + presentation.title, for: .normal)
        detailLabel.text = presentation.detail
        detailLabel.isHidden = presentation.detail == nil
        bodyLabel.text = presentation.body
        bodyLabel.isHidden = !(expanded && presentation.body != nil)
        bodyLabel.font = presentation.bodyIsMono
            ? .monospacedSystemFont(ofSize: 12, weight: .regular)
            : .preferredFont(forTextStyle: .callout)
        bodyLabel.textColor = presentation.bodyIsMono ? DesignTokens.text2 : DesignTokens.text
    }
}
