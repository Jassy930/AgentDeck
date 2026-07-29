import AgentDeckSessionSource
import UIKit

final class MachineListViewController: UIViewController {
    typealias PairingViewModelFactory = @MainActor (any SessionSource) -> PairingViewModel

    private let source: any SessionSource
    private let viewModel: MachineListViewModel
    private let pairingViewModelFactory: PairingViewModelFactory
    private var initialPairInvite: String?
    private var collectionView: UICollectionView!
    private var dataSource: UICollectionViewDiffableDataSource<Int, String>!
    private let emptyView = MobileEmptyStateView(title: "还没有机器", subtitle: "用右上角「配对」把 Mac 接入")

    init(
        source: any SessionSource,
        pairingViewModelFactory: @escaping PairingViewModelFactory,
        initialPairInvite: String?
    ) {
        self.source = source
        self.viewModel = MachineListViewModel(source: source)
        self.pairingViewModelFactory = pairingViewModelFactory
        self.initialPairInvite = initialPairInvite
        super.init(nibName: nil, bundle: nil)
    }

    /// Preview/旧调用点的显式降级入口。它允许配对，但本地 material 删除会 fail-close；
    /// 发行 composition 必须注入持有正确 local store 与 generation 的 factory。
    convenience init(source: any SessionSource) {
        self.init(
            source: source,
            pairingViewModelFactory: { PairingViewModel(source: $0) },
            initialPairInvite: nil
        )
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    override func viewDidLoad() {
        super.viewDidLoad()
        title = "AgentDeck"
        view.backgroundColor = DesignTokens.bg
        let pairingButton = UIBarButtonItem(
            image: UIImage(systemName: "qrcode.viewfinder"), style: .plain,
            target: self, action: #selector(openPairing))
        pairingButton.accessibilityIdentifier = "machines.pair"
        let inboxButton = UIBarButtonItem(
            image: UIImage(systemName: "tray"), style: .plain,
            target: self, action: #selector(openInbox))
        navigationItem.rightBarButtonItems = [pairingButton, inboxButton]
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

    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        guard let initialPairInvite, presentedViewController == nil else { return }
        self.initialPairInvite = nil
        presentPairing(initialInvite: initialPairInvite)
    }

    private func configureCollectionView() {
        var config = UICollectionLayoutListConfiguration(appearance: .insetGrouped)
        config.backgroundColor = DesignTokens.bg
        let layout = UICollectionViewCompositionalLayout.list(using: config)
        collectionView = UICollectionView(frame: .zero, collectionViewLayout: layout)
        collectionView.delegate = self
        collectionView.accessibilityIdentifier = "machines.list"
        collectionView.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(collectionView)
        NSLayoutConstraint.activate([
            collectionView.topAnchor.constraint(equalTo: view.topAnchor),
            collectionView.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            collectionView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            collectionView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
        ])
        let registration = UICollectionView.CellRegistration<
            UICollectionViewListCell, MachineSummary
        > { cell, _, machine in
            // 覆盖系统默认白色 cell 背景，使用设计系统 surface token
            var bgConfig = UIBackgroundConfiguration.listGroupedCell()
            bgConfig.backgroundColor = DesignTokens.surface
            bgConfig.backgroundColorTransformer = nil
            cell.backgroundConfiguration = bgConfig

            var content = UIListContentConfiguration.subtitleCell()
            content.text = machine.name
            let presentation = MachineRowPresentation.make(from: machine)
            content.secondaryText =
                "\(presentation.statusText) · \(machine.activeConversationCount) 活跃会话"
            content.textProperties.color = DesignTokens.text
            content.secondaryTextProperties.color = DesignTokens.text2
            content.image = UIImage(systemName: "circle.fill")
            content.imageProperties.tintColor = {
                switch presentation.indicator {
                case .healthy: DesignTokens.accent
                case .neutral: DesignTokens.text2
                case .warning: DesignTokens.warn
                case .danger: DesignTokens.danger
                }
            }()
            content.imageProperties.maximumSize = CGSize(width: 10, height: 10)
            cell.contentConfiguration = content
            cell.accessibilityIdentifier = "machines.row.\(machine.id)"
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
                accessories.append(
                    .customView(configuration: .init(customView: badge, placement: .trailing())))
            }
            cell.accessories = accessories
        }
        dataSource = UICollectionViewDiffableDataSource<Int, String>(collectionView: collectionView) {
            [weak self] collectionView, indexPath, machineID in
            guard let machine = self?.viewModel.machines.first(where: { $0.id == machineID }) else {
                return nil
            }
            return collectionView.dequeueConfiguredReusableCell(
                using: registration, for: indexPath, item: machine)
        }
    }

    private func applySnapshot() {
        var snapshot = NSDiffableDataSourceSnapshot<Int, String>()
        snapshot.appendSections([0])
        snapshot.appendItems(viewModel.machines.map(\.id))
        snapshot.reconfigureItems(
            viewModel.machines.map(\.id).filter { id in
                dataSource.snapshot().itemIdentifiers.contains(id)
            })
        dataSource.apply(snapshot, animatingDifferences: false)
        emptyView.isHidden = !viewModel.machines.isEmpty
        if viewModel.machines.isEmpty {
            switch viewModel.resourceState {
            case .loading:
                emptyView.update(title: "正在加载机器…", subtitle: nil)
            case .failed(let error, _):
                emptyView.update(
                    title: "无法加载机器",
                    subtitle: error.message ?? error.code.rawValue
                )
            case .ready, .stale:
                emptyView.update(title: "还没有机器", subtitle: "用右上角「配对」把 Mac 接入")
            }
        }
    }

    @objc private func openPairing() {
        presentPairing(initialInvite: nil)
    }

    private func presentPairing(initialInvite: String?) {
        guard presentedViewController == nil else { return }
        let pairingViewModel = pairingViewModelFactory(source)
        let pairing = PairingViewController(
            viewModel: pairingViewModel,
            initialInvite: initialInvite
        )
        present(UINavigationController(rootViewController: pairing), animated: true)
    }

    @objc private func openInbox() {
        navigationController?.pushViewController(
            InboxViewController(source: source), animated: true)
    }
}

extension MachineListViewController: UICollectionViewDelegate {
    func collectionView(_ collectionView: UICollectionView, didSelectItemAt indexPath: IndexPath) {
        collectionView.deselectItem(at: indexPath, animated: true)
        guard let machineID = dataSource.itemIdentifier(for: indexPath),
            let machine = viewModel.machines.first(where: { $0.id == machineID }),
            MachineRowPresentation.make(from: machine).isSelectable
        else { return }
        navigationController?.pushViewController(
            SessionListViewController(source: source, machineID: machineID), animated: true)
    }
}
