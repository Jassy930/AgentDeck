import UIKit

/// 全假数据的配对骨架：扫码区域是占位（相机与真实配对在 Relay/R2 后接入）。
final class PairingViewController: UIViewController, UITableViewDataSource, UITableViewDelegate {
    private struct PairedDevice { let id: String; let name: String }
    private var devices: [PairedDevice] = [.init(id: "dev-1", name: "Mac Studio · agentdeckd")]
    private let codeField = UITextField()
    private let tableView = UITableView(frame: .zero, style: .insetGrouped)

    override func viewDidLoad() {
        super.viewDidLoad()
        title = "配对"
        view.backgroundColor = DesignTokens.bg
        navigationItem.leftBarButtonItem = UIBarButtonItem(systemItem: .close, primaryAction:
            UIAction { [weak self] _ in self?.dismiss(animated: true) })

        let scanPlaceholder = UIView()
        scanPlaceholder.layer.borderWidth = 2
        scanPlaceholder.layer.borderColor = DesignTokens.text2.cgColor
        scanPlaceholder.layer.cornerRadius = DesignTokens.radiusLg
        let scanLabel = UILabel()
        scanLabel.text = "扫码配对\n（实机功能后置）"
        scanLabel.numberOfLines = 0
        scanLabel.textAlignment = .center
        scanLabel.textColor = DesignTokens.text2
        scanLabel.translatesAutoresizingMaskIntoConstraints = false
        scanPlaceholder.addSubview(scanLabel)

        codeField.placeholder = "或粘贴配对码"
        codeField.borderStyle = .roundedRect
        let pairButton = UIButton(configuration: .filled())
        pairButton.setTitle("配对", for: .normal)
        pairButton.addAction(UIAction { [weak self] _ in self?.pairFromCode() }, for: .touchUpInside)
        let codeRow = UIStackView(arrangedSubviews: [codeField, pairButton])
        codeRow.spacing = DesignTokens.sp2

        tableView.dataSource = self
        tableView.delegate = self
        tableView.register(UITableViewCell.self, forCellReuseIdentifier: "device")
        tableView.backgroundColor = DesignTokens.bg

        let stack = UIStackView(arrangedSubviews: [scanPlaceholder, codeRow, tableView])
        stack.axis = .vertical
        stack.spacing = DesignTokens.sp4
        stack.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(stack)
        NSLayoutConstraint.activate([
            scanPlaceholder.heightAnchor.constraint(equalToConstant: 180),
            scanLabel.centerXAnchor.constraint(equalTo: scanPlaceholder.centerXAnchor),
            scanLabel.centerYAnchor.constraint(equalTo: scanPlaceholder.centerYAnchor),
            stack.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: DesignTokens.sp4),
            stack.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: DesignTokens.sp4),
            stack.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -DesignTokens.sp4),
            stack.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor),
        ])
    }

    private func pairFromCode() {
        guard let code = codeField.text, !code.isEmpty else { return }
        devices.append(.init(id: UUID().uuidString, name: "机器 \(code.prefix(6))"))
        codeField.text = ""
        tableView.reloadData()
    }

    func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int { devices.count }

    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: "device", for: indexPath)
        var bgConfig = UIBackgroundConfiguration.listGroupedCell()
        bgConfig.backgroundColor = DesignTokens.surface
        bgConfig.backgroundColorTransformer = nil
        cell.backgroundConfiguration = bgConfig
        var content = cell.defaultContentConfiguration()
        content.text = devices[indexPath.row].name
        content.secondaryText = "已配对"
        content.textProperties.color = DesignTokens.text
        content.secondaryTextProperties.color = DesignTokens.text2
        cell.contentConfiguration = content
        return cell
    }

    func tableView(_ tableView: UITableView, titleForHeaderInSection section: Int) -> String? { "已配对设备" }

    func tableView(_ tableView: UITableView,
                   trailingSwipeActionsConfigurationForRowAt indexPath: IndexPath) -> UISwipeActionsConfiguration? {
        let revoke = UIContextualAction(style: .destructive, title: "撤销") { [weak self] _, _, done in
            self?.devices.remove(at: indexPath.row)
            self?.tableView.deleteRows(at: [indexPath], with: .automatic)
            done(true)
        }
        return UISwipeActionsConfiguration(actions: [revoke])
    }
}
