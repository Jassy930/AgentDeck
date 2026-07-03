import UIKit

/// 空列表 / 加载占位 / 错误提示三合一（设计文档第 9 节）。
final class MobileEmptyStateView: UIView {
    private let titleLabel = UILabel()
    private let subtitleLabel = UILabel()

    init(title: String, subtitle: String? = nil) {
        super.init(frame: .zero)
        titleLabel.font = .preferredFont(forTextStyle: .headline)
        titleLabel.textColor = DesignTokens.text
        titleLabel.textAlignment = .center
        subtitleLabel.font = .preferredFont(forTextStyle: .subheadline)
        subtitleLabel.textColor = DesignTokens.text2
        subtitleLabel.textAlignment = .center
        subtitleLabel.numberOfLines = 0
        let stack = UIStackView(arrangedSubviews: [titleLabel, subtitleLabel])
        stack.axis = .vertical
        stack.spacing = DesignTokens.sp2
        stack.translatesAutoresizingMaskIntoConstraints = false
        addSubview(stack)
        NSLayoutConstraint.activate([
            stack.centerXAnchor.constraint(equalTo: centerXAnchor),
            stack.centerYAnchor.constraint(equalTo: centerYAnchor),
            stack.leadingAnchor.constraint(greaterThanOrEqualTo: leadingAnchor, constant: DesignTokens.sp6),
            stack.trailingAnchor.constraint(lessThanOrEqualTo: trailingAnchor, constant: -DesignTokens.sp6),
        ])
        update(title: title, subtitle: subtitle)
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    func update(title: String, subtitle: String?) {
        titleLabel.text = title
        subtitleLabel.text = subtitle
        subtitleLabel.isHidden = subtitle == nil
    }
}
