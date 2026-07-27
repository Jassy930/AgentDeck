import AgentDeckSessionSource
import UIKit

final class InboxViewController: UIViewController {
    private let source: any SessionSource
    private let viewModel: InboxViewModel
    private var collectionView: UICollectionView!
    private var dataSource: UICollectionViewDiffableDataSource<Int, String>!
    private let emptyView = MobileEmptyStateView(title: "收件箱为空", subtitle: "等待审批、已完成、失败的会话会在这里显示")

    init(source: any SessionSource) {
        self.source = source
        self.viewModel = InboxViewModel(source: source)
        super.init(nibName: nil, bundle: nil)
        title = "收件箱"
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = DesignTokens.bg
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

    private func kindLabel(_ kind: InboxItem.Kind) -> (text: String, symbol: String) {
        switch kind {
        case .waitingApproval: ("等待审批", "exclamationmark.circle")
        case .turnCompleted: ("已完成", "checkmark.circle")
        case .failed: ("失败", "xmark.circle")
        }
    }

    private func item(for id: String) -> InboxItem? {
        viewModel.items.first(where: { $0.id == id })
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
        let registration = UICollectionView.CellRegistration<UICollectionViewListCell, InboxItem> {
            [weak self] cell, _, inboxItem in
            // 覆盖 insetGrouped 默认白底，使用设计系统 surface token
            var bgConfig = UIBackgroundConfiguration.listGroupedCell()
            bgConfig.backgroundColor = DesignTokens.surface
            bgConfig.backgroundColorTransformer = nil
            cell.backgroundConfiguration = bgConfig

            var content = UIListContentConfiguration.subtitleCell()
            let label = self?.kindLabel(inboxItem.kind) ?? (text: "", symbol: "")
            content.text = inboxItem.title
            content.secondaryText = label.text
            content.textProperties.color = DesignTokens.text
            content.secondaryTextProperties.color = DesignTokens.text2
            content.image = UIImage(systemName: label.symbol)
            content.imageProperties.tintColor = {
                switch inboxItem.kind {
                case .waitingApproval: DesignTokens.warn
                case .turnCompleted: DesignTokens.success
                case .failed: DesignTokens.danger
                }
            }()
            cell.contentConfiguration = content
            cell.accessories = [.disclosureIndicator()]
        }
        dataSource = UICollectionViewDiffableDataSource<Int, String>(collectionView: collectionView)
        {
            [weak self] collectionView, indexPath, itemID in
            guard let inboxItem = self?.item(for: itemID) else { return nil }
            return collectionView.dequeueConfiguredReusableCell(
                using: registration, for: indexPath, item: inboxItem)
        }
    }

    private func applySnapshot() {
        var snapshot = NSDiffableDataSourceSnapshot<Int, String>()
        snapshot.appendSections([0])
        snapshot.appendItems(viewModel.items.map(\.id))
        let existing = Set(dataSource.snapshot().itemIdentifiers)
        snapshot.reconfigureItems(snapshot.itemIdentifiers.filter(existing.contains))
        dataSource.apply(snapshot, animatingDifferences: false)
        emptyView.isHidden = !viewModel.items.isEmpty
        if viewModel.items.isEmpty {
            switch viewModel.resourceState {
            case .loading:
                emptyView.update(title: "正在加载收件箱…", subtitle: nil)
            case .failed(let error, _):
                emptyView.update(
                    title: "无法加载收件箱",
                    subtitle: error.message ?? error.code.rawValue
                )
            case .ready, .stale:
                emptyView.update(
                    title: "收件箱为空",
                    subtitle: "等待审批、已完成、失败的会话会在这里显示"
                )
            }
        }
    }
}

extension InboxViewController: UICollectionViewDelegate {
    func collectionView(_ collectionView: UICollectionView, didSelectItemAt indexPath: IndexPath) {
        collectionView.deselectItem(at: indexPath, animated: true)
        guard let itemID = dataSource.itemIdentifier(for: indexPath),
            let inboxItem = item(for: itemID)
        else { return }
        let vc = SessionDetailViewController(
            source: source,
            conversationID: inboxItem.conversationID,
            title: inboxItem.title
        )
        navigationController?.pushViewController(vc, animated: true)
    }
}
