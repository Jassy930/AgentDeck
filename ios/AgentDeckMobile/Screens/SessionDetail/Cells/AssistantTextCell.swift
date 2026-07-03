import UIKit
import AgentDeckCore

final class AssistantTextCell: UICollectionViewCell {
    private let label = UILabel()

    override init(frame: CGRect) {
        super.init(frame: frame)
        // 深色背景透明，避免系统默认白色覆盖外层 bg
        var bgConfig = UIBackgroundConfiguration.listPlainCell()
        bgConfig.backgroundColor = .clear
        backgroundConfiguration = bgConfig

        label.numberOfLines = 0
        label.translatesAutoresizingMaskIntoConstraints = false
        contentView.addSubview(label)
        NSLayoutConstraint.activate([
            label.topAnchor.constraint(equalTo: contentView.topAnchor, constant: DesignTokens.sp2),
            label.bottomAnchor.constraint(equalTo: contentView.bottomAnchor, constant: -DesignTokens.sp2),
            label.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: DesignTokens.sp4),
            label.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -DesignTokens.sp4),
        ])
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    func configure(with item: UIItem) {
        label.attributedText = MarkdownRenderer.attributed(item.text, color: DesignTokens.text)
    }
}
