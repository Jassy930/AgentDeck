import UIKit

final class MachineListViewController: UIViewController {
    private let source: MobileSessionSource
    private let viewModel: MachineListViewModel
    private var collectionView: UICollectionView!
    private var dataSource: UICollectionViewDiffableDataSource<Int, String>!
    private let emptyView = MobileEmptyStateView(title: "还没有机器", subtitle: "当前仅展示内置 Fixture 数据")

    init(source: MobileSessionSource) {
        self.source = source
        self.viewModel = MachineListViewModel(source: source)
        super.init(nibName: nil, bundle: nil)
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    override func viewDidLoad() {
        super.viewDidLoad()
        title = "AgentDeck"
        view.backgroundColor = DesignTokens.bg
        navigationItem.rightBarButtonItems = [
            UIBarButtonItem(image: UIImage(systemName: "tray"), style: .plain,
                            target: self, action: #selector(openInbox)),
        ]
        configureCollectionView()
        view.addSubview(emptyView)
        emptyView.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            emptyView.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            emptyView.centerYAnchor.constraint(equalTo: view.centerYAnchor),
            emptyView.widthAnchor.constraint(equalTo: view.widthAnchor),
            emptyView.heightAnchor.constraint(equalToConstant: 160),
        ])
        viewModel.onUpdate = { [weak self] in self?.applySnapshot() }
        viewModel.start()
        applySnapshot()
    }

    private func configureCollectionView() {
        var config = UICollectionLayoutListConfiguration(appearance: .insetGrouped)
        config.backgroundColor = DesignTokens.bg
        let layout = UICollectionViewCompositionalLayout.list(using: config)
        collectionView = UICollectionView(frame: .zero, collectionViewLayout: layout)
        collectionView.delegate = self
        collectionView.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(collectionView)
        NSLayoutConstraint.activate([
            collectionView.topAnchor.constraint(equalTo: view.topAnchor),
            collectionView.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            collectionView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            collectionView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
        ])
        let registration = UICollectionView.CellRegistration<UICollectionViewListCell, MachineSummary> { cell, _, machine in
            // 覆盖系统默认白色 cell 背景，使用设计系统 surface token
            var bgConfig = UIBackgroundConfiguration.listGroupedCell()
            bgConfig.backgroundColor = DesignTokens.surface
            bgConfig.backgroundColorTransformer = nil
            cell.backgroundConfiguration = bgConfig

            var content = UIListContentConfiguration.subtitleCell()
            content.text = machine.name
            let status = machine.isOnline ? "在线" : "离线"
            content.secondaryText = "\(status) · \(machine.activeSessionCount) 活跃会话"
            content.textProperties.color = DesignTokens.text
            content.secondaryTextProperties.color = DesignTokens.text2
            content.image = UIImage(systemName: "circle.fill")
            content.imageProperties.tintColor = machine.isOnline ? DesignTokens.accent : DesignTokens.text2
            content.imageProperties.maximumSize = CGSize(width: 10, height: 10)
            cell.contentConfiguration = content
            var accessories: [UICellAccessory] = [.disclosureIndicator()]
            if machine.pendingApprovalCount > 0 {
                let badge = UILabel()
                badge.text = " \(machine.pendingApprovalCount) 待审批 "
                badge.font = .preferredFont(forTextStyle: .caption1)
                badge.textColor = DesignTokens.bg
                badge.backgroundColor = DesignTokens.accent
                // radiusPill=999 远大于 badge 高度一半，需要 layoutIfNeeded 才能获取实际高度。
                // 此处用固定值 10（caption1 约 20pt 高的一半）保证胶囊形状。
                // 若用 999 直接赋值，layer.masksToBounds 截断后视觉正常，但不如语义清晰。
                badge.layer.cornerRadius = 10
                badge.layer.masksToBounds = true
                accessories.append(.customView(configuration: .init(customView: badge, placement: .trailing())))
            }
            cell.accessories = accessories
        }
        dataSource = UICollectionViewDiffableDataSource<Int, String>(collectionView: collectionView) {
            [weak self] collectionView, indexPath, machineID in
            guard let machine = self?.viewModel.machines.first(where: { $0.id == machineID }) else { return nil }
            return collectionView.dequeueConfiguredReusableCell(using: registration, for: indexPath, item: machine)
        }
    }

    private func applySnapshot() {
        var snapshot = NSDiffableDataSourceSnapshot<Int, String>()
        snapshot.appendSections([0])
        snapshot.appendItems(viewModel.machines.map(\.id))
        snapshot.reconfigureItems(viewModel.machines.map(\.id).filter { id in
            dataSource.snapshot().itemIdentifiers.contains(id)
        })
        dataSource.apply(snapshot, animatingDifferences: false)
        emptyView.isHidden = !viewModel.machines.isEmpty
    }

    @objc private func openInbox() {
        navigationController?.pushViewController(InboxViewController(source: source), animated: true)
    }
}

extension MachineListViewController: UICollectionViewDelegate {
    func collectionView(_ collectionView: UICollectionView, didSelectItemAt indexPath: IndexPath) {
        collectionView.deselectItem(at: indexPath, animated: true)
        guard let machineID = dataSource.itemIdentifier(for: indexPath) else { return }
        navigationController?.pushViewController(
            SessionListViewController(source: source, machineID: machineID), animated: true)
    }
}
