import UIKit

final class MobileInputBarView: UIView, UITextViewDelegate {
    private let textView = UITextView()
    private let sendButton = UIButton(configuration: .filled())
    private var heightConstraint: NSLayoutConstraint!
    var onSend: ((String) -> Void)?
    var onTextChange: ((String) -> Void)?

    override init(frame: CGRect) {
        super.init(frame: frame)
        backgroundColor = DesignTokens.surface
        layer.cornerRadius = DesignTokens.radiusLg
        textView.font = .preferredFont(forTextStyle: .body)
        textView.textColor = DesignTokens.text
        textView.backgroundColor = .clear
        textView.isScrollEnabled = false
        textView.delegate = self
        sendButton.setImage(UIImage(systemName: "arrow.up"), for: .normal)
        sendButton.addAction(UIAction { [weak self] _ in self?.send() }, for: .touchUpInside)
        textView.translatesAutoresizingMaskIntoConstraints = false
        sendButton.translatesAutoresizingMaskIntoConstraints = false
        addSubview(textView)
        addSubview(sendButton)
        heightConstraint = textView.heightAnchor.constraint(equalToConstant: 36)
        NSLayoutConstraint.activate([
            textView.topAnchor.constraint(equalTo: topAnchor, constant: DesignTokens.sp1),
            textView.bottomAnchor.constraint(equalTo: bottomAnchor, constant: -DesignTokens.sp1),
            textView.leadingAnchor.constraint(equalTo: leadingAnchor, constant: DesignTokens.sp2),
            textView.trailingAnchor.constraint(
                equalTo: sendButton.leadingAnchor, constant: -DesignTokens.sp2),
            heightConstraint,
            sendButton.trailingAnchor.constraint(
                equalTo: trailingAnchor, constant: -DesignTokens.sp2),
            sendButton.bottomAnchor.constraint(equalTo: bottomAnchor, constant: -DesignTokens.sp1),
            sendButton.widthAnchor.constraint(equalToConstant: 36),
            sendButton.heightAnchor.constraint(equalToConstant: 36),
        ])
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    func textViewDidChange(_ textView: UITextView) {
        let height = textView.sizeThatFits(CGSize(width: textView.bounds.width, height: .infinity))
            .height
        heightConstraint.constant = min(max(36, height), 120)
        onTextChange?(textView.text ?? "")
    }

    func configure(
        draft: String,
        state: PromptSubmissionState,
        isEnabled: Bool = true
    ) {
        if textView.text != draft {
            textView.text = draft
            let height = textView.sizeThatFits(
                CGSize(width: textView.bounds.width, height: .infinity)
            ).height
            heightConstraint.constant = min(max(36, height), 120)
        }
        let submitting: Bool
        switch state {
        case .sending, .queued:
            submitting = true
        case .idle, .failed:
            submitting = false
        }
        sendButton.isEnabled = isEnabled && !submitting
        textView.isEditable = isEnabled && !submitting
        sendButton.setImage(
            UIImage(systemName: submitting ? "ellipsis" : "arrow.up"),
            for: .normal
        )
    }

    private func send() {
        let text = textView.text ?? ""
        guard !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return }
        onSend?(text)
    }
}
