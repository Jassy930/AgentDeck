import UIKit

/// 会话详情屏顶部错误横幅。使用 dangerWeak（alpha 0.13）作为底色，
/// danger 作为文字色——比 danger.withAlphaComponent(0.15) 更贴近设计 token 语义。
final class ErrorBannerView: UIView {
    private let label = UILabel()

    override init(frame: CGRect) {
        super.init(frame: frame)
        backgroundColor = DesignTokens.dangerWeak
        layer.cornerRadius = DesignTokens.radiusMd
        label.numberOfLines = 0
        label.font = .preferredFont(forTextStyle: .footnote)
        label.textColor = DesignTokens.danger
        label.translatesAutoresizingMaskIntoConstraints = false
        addSubview(label)
        NSLayoutConstraint.activate([
            label.topAnchor.constraint(equalTo: topAnchor, constant: DesignTokens.sp2),
            label.bottomAnchor.constraint(equalTo: bottomAnchor, constant: -DesignTokens.sp2),
            label.leadingAnchor.constraint(equalTo: leadingAnchor, constant: DesignTokens.sp3),
            label.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -DesignTokens.sp3),
        ])
        isHidden = true
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    func show(message: String) { label.text = message; isHidden = false }
    func hide() { isHidden = true }
}
