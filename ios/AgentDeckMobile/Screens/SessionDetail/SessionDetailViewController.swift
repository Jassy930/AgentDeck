import UIKit
import AgentDeckCore

final class SessionDetailViewController: UIViewController {
    private enum Section: Hashable { case conversation }

    private let viewModel: SessionDetailViewModel
    private var collectionView: UICollectionView!
    private var dataSource: UICollectionViewDiffableDataSource<Section, String>!

    init(source: MobileSessionSource, sessionID: String, title: String) {
        self.viewModel = SessionDetailViewModel(source: source, sessionID: sessionID)
        super.init(nibName: nil, bundle: nil)
        self.title = title
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = DesignTokens.bg
        configureCollectionView()
        viewModel.onUpdate = { [weak self] in self?.applySnapshot() }
        viewModel.start()
    }

    private func configureCollectionView() {
        var config = UICollectionLayoutListConfiguration(appearance: .plain)
        config.backgroundColor = DesignTokens.bg
        config.showsSeparators = false
        let layout = UICollectionViewCompositionalLayout.list(using: config)
        collectionView = UICollectionView(frame: .zero, collectionViewLayout: layout)
        collectionView.backgroundColor = DesignTokens.bg
        collectionView.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(collectionView)
        NSLayoutConstraint.activate([
            collectionView.topAnchor.constraint(equalTo: view.topAnchor),
            collectionView.bottomAnchor.constraint(equalTo: view.keyboardLayoutGuide.topAnchor),
            collectionView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            collectionView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
        ])
        let userReg = UICollectionView.CellRegistration<UserPromptCell, UIItem> { cell, _, item in
            cell.configure(with: item)
        }
        let textReg = UICollectionView.CellRegistration<AssistantTextCell, UIItem> { cell, _, item in
            cell.configure(with: item)
        }
        dataSource = UICollectionViewDiffableDataSource<Section, String>(collectionView: collectionView) {
            [weak self] collectionView, indexPath, rowID in
            guard let self, let row = self.viewModel.rows.first(where: { $0.id == rowID }) else { return nil }
            // 渲染路径由 row 数据（role / item.kind）决定，不看 agentKind（N2）。
            switch row.role {
            case .userPrompt:
                return collectionView.dequeueConfiguredReusableCell(using: userReg, for: indexPath, item: row.item)
            case .assistantItem:
                return collectionView.dequeueConfiguredReusableCell(using: textReg, for: indexPath, item: row.item)
            }
        }
    }

    private func applySnapshot() {
        var snapshot = NSDiffableDataSourceSnapshot<Section, String>()
        snapshot.appendSections([.conversation])
        let ids = viewModel.rows.map(\.id)
        snapshot.appendItems(ids, toSection: .conversation)
        let existing = Set(dataSource.snapshot().itemIdentifiers)
        snapshot.reconfigureItems(ids.filter(existing.contains))
        dataSource.apply(snapshot, animatingDifferences: false)
        if let last = ids.last, let indexPath = dataSource.indexPath(for: last) {
            collectionView.scrollToItem(at: indexPath, at: .bottom, animated: false)
        }
    }
}
