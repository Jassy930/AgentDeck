import AgentDeckCore
import AgentDeckSessionSource
import UIKit

final class SessionListViewController: UIViewController {
    private let source: any SessionSource
    private let viewModel: SessionListViewModel
    private var collectionView: UICollectionView!
    private var dataSource: UICollectionViewDiffableDataSource<ConversationGroup, String>!
    private let emptyView = MobileEmptyStateView(title: "这台机器还没有会话", subtitle: nil)

    init(source: any SessionSource, machineID: String) {
        self.source = source
        self.viewModel = SessionListViewModel(source: source, machineID: machineID)
        super.init(nibName: nil, bundle: nil)
        title = "会话"
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

    private func headerTitle(_ group: ConversationGroup) -> String {
        switch group {
        case .waitingApproval: return "等待审批"
        case .active: return "活跃"
        case .recent: return "最近"
        }
    }

    /// 纯展示文案映射；渲染路径仍由 capability/item 数据决定（N2）。
    private static func vendorDisplayName(_ kind: AgentKind) -> String {
        switch kind {
        case .codex: "Codex"
        case .claudeCode: "Claude Code"
        }
    }

    private func session(for id: String) -> ConversationSummary? {
        for (_, sessions) in viewModel.groups {
            if let match = sessions.first(where: { $0.id == id }) { return match }
        }
        return nil
    }

    private func configureCollectionView() {
        var config = UICollectionLayoutListConfiguration(appearance: .insetGrouped)
        config.backgroundColor = DesignTokens.bg
        config.headerMode = .supplementary
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
        let cellReg = UICollectionView.CellRegistration<
            UICollectionViewListCell, ConversationSummary
        > { cell, _, session in
            // 覆盖 insetGrouped 默认白底，使用设计系统 surface token
            var bgConfig = UIBackgroundConfiguration.listGroupedCell()
            bgConfig.backgroundColor = DesignTokens.surface
            bgConfig.backgroundColorTransformer = nil
            cell.backgroundConfiguration = bgConfig

            var content = UIListContentConfiguration.subtitleCell()
            content.text = session.title
            content.secondaryText = "\(Self.vendorDisplayName(session.agentKind)) · \(session.cwd)"
            content.textProperties.color = DesignTokens.text
            content.secondaryTextProperties.color = DesignTokens.text2
            cell.contentConfiguration = content
            cell.accessories = [.disclosureIndicator()]
        }
        let headerReg = UICollectionView.SupplementaryRegistration<UICollectionViewListCell>(
            elementKind: UICollectionView.elementKindSectionHeader
        ) { [weak self] header, _, indexPath in
            guard let self else { return }
            let group = dataSource.snapshot().sectionIdentifiers[indexPath.section]
            var content = UIListContentConfiguration.groupedHeader()
            content.text = headerTitle(group)
            header.contentConfiguration = content
        }
        dataSource = UICollectionViewDiffableDataSource<ConversationGroup, String>(
            collectionView: collectionView
        ) {
            [weak self] collectionView, indexPath, sessionID in
            guard let session = self?.session(for: sessionID) else { return nil }
            return collectionView.dequeueConfiguredReusableCell(
                using: cellReg, for: indexPath, item: session)
        }
        dataSource.supplementaryViewProvider = { collectionView, kind, indexPath in
            collectionView.dequeueConfiguredReusableSupplementary(using: headerReg, for: indexPath)
        }
    }

    private func applySnapshot() {
        var snapshot = NSDiffableDataSourceSnapshot<ConversationGroup, String>()
        for (group, sessions) in viewModel.groups {
            snapshot.appendSections([group])
            snapshot.appendItems(sessions.map(\.id), toSection: group)
        }
        let existing = Set(dataSource.snapshot().itemIdentifiers)
        snapshot.reconfigureItems(snapshot.itemIdentifiers.filter(existing.contains))
        dataSource.apply(snapshot, animatingDifferences: false)
        emptyView.isHidden = !viewModel.groups.isEmpty
        if viewModel.groups.isEmpty {
            switch viewModel.resourceState {
            case .loading:
                emptyView.update(title: "正在加载会话…", subtitle: nil)
            case .failed(let error, _):
                emptyView.update(
                    title: "无法加载会话",
                    subtitle: error.message ?? error.code.rawValue
                )
            case .ready, .stale:
                emptyView.update(title: "这台机器还没有会话", subtitle: nil)
            }
        }
    }
}

extension SessionListViewController: UICollectionViewDelegate {
    func collectionView(_ collectionView: UICollectionView, didSelectItemAt indexPath: IndexPath) {
        collectionView.deselectItem(at: indexPath, animated: true)
        guard let sessionID = dataSource.itemIdentifier(for: indexPath),
            let session = session(for: sessionID)
        else { return }
        let vc = SessionDetailViewController(
            source: source,
            conversationID: session.id,
            title: session.title
        )
        navigationController?.pushViewController(vc, animated: true)
    }
}
