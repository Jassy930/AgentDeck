import UIKit
import AgentDeckMobileCore

final class UserPromptCell: UICollectionViewCell {
    private let bubble = UIView()
    private let label = UILabel()

    override init(frame: CGRect) {
        super.init(frame: frame)
        // 深色背景透明，避免系统默认白色覆盖外层 bg
        var bgConfig = UIBackgroundConfiguration.listPlainCell()
        bgConfig.backgroundColor = .clear
        backgroundConfiguration = bgConfig

        bubble.backgroundColor = DesignTokens.surface
        bubble.layer.cornerRadius = DesignTokens.radiusMd
        label.numberOfLines = 0
        label.font = .preferredFont(forTextStyle: .body)
        label.textColor = DesignTokens.text
        bubble.translatesAutoresizingMaskIntoConstraints = false
        label.translatesAutoresizingMaskIntoConstraints = false
        contentView.addSubview(bubble)
        bubble.addSubview(label)
        NSLayoutConstraint.activate([
            bubble.topAnchor.constraint(equalTo: contentView.topAnchor, constant: DesignTokens.sp3),
            bubble.bottomAnchor.constraint(equalTo: contentView.bottomAnchor, constant: -DesignTokens.sp1),
            bubble.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -DesignTokens.sp4),
            bubble.leadingAnchor.constraint(greaterThanOrEqualTo: contentView.leadingAnchor, constant: 48),
            label.topAnchor.constraint(equalTo: bubble.topAnchor, constant: DesignTokens.sp2),
            label.bottomAnchor.constraint(equalTo: bubble.bottomAnchor, constant: -DesignTokens.sp2),
            label.leadingAnchor.constraint(equalTo: bubble.leadingAnchor, constant: DesignTokens.sp3),
            label.trailingAnchor.constraint(equalTo: bubble.trailingAnchor, constant: -DesignTokens.sp3),
        ])
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    func configure(with item: UIItem) {
        label.text = item.text
    }
}
