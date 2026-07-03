import UIKit
import AgentDeckCore

final class SessionDetailViewController: UIViewController {
    private enum Section: Hashable { case conversation }

    private let viewModel: SessionDetailViewModel
    private var collectionView: UICollectionView!
    private var dataSource: UICollectionViewDiffableDataSource<Section, String>!
    private var expandedRowIDs: Set<String> = []
    private let errorBanner = ErrorBannerView()

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
        configureErrorBanner()
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
        let collapsibleReg = UICollectionView.CellRegistration<CollapsibleItemCell, String> {
            [weak self] cell, _, rowID in
            guard let self, let row = self.viewModel.rows.first(where: { $0.id == rowID }),
                  let presentation = CollapsiblePresentation.make(from: row.item) else { return }
            let expanded = self.expandedRowIDs.contains(rowID)
            cell.configure(with: presentation, expanded: expanded)
            cell.onToggle = { [weak self] in
                guard let self else { return }
                if self.expandedRowIDs.contains(rowID) {
                    self.expandedRowIDs.remove(rowID)
                } else {
                    self.expandedRowIDs.insert(rowID)
                }
                // reconfigure 该行，并 invalidateLayout 刷新高度
                var snapshot = self.dataSource.snapshot()
                snapshot.reconfigureItems([rowID])
                self.dataSource.apply(snapshot, animatingDifferences: true)
                self.collectionView.collectionViewLayout.invalidateLayout()
            }
        }
        dataSource = UICollectionViewDiffableDataSource<Section, String>(collectionView: collectionView) {
            [weak self] collectionView, indexPath, rowID in
            guard let self, let row = self.viewModel.rows.first(where: { $0.id == rowID }) else { return nil }
            // 渲染路径由 row 数据（role / item.kind）决定，不看 agentKind（N2）。
            switch row.role {
            case .userPrompt:
                return collectionView.dequeueConfiguredReusableCell(using: userReg, for: indexPath, item: row.item)
            case .assistantItem:
                // 优先走折叠 cell；非折叠 kind 降级到文本 cell
                if CollapsiblePresentation.make(from: row.item) != nil {
                    return collectionView.dequeueConfiguredReusableCell(using: collapsibleReg, for: indexPath, item: rowID)
                } else {
                    return collectionView.dequeueConfiguredReusableCell(using: textReg, for: indexPath, item: row.item)
                }
            }
        }
    }

    private func configureErrorBanner() {
        errorBanner.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(errorBanner)
        NSLayoutConstraint.activate([
            errorBanner.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: DesignTokens.sp2),
            errorBanner.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: DesignTokens.sp4),
            errorBanner.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -DesignTokens.sp4),
        ])
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
        // 同步错误横幅
        if let errorText = viewModel.errorText {
            errorBanner.show(message: errorText)
        } else {
            errorBanner.hide()
        }
    }
}
