import UIKit
import AgentDeckMobileCore

final class SessionDetailViewController: UIViewController {
    private enum Section: Hashable { case conversation; case approval }

    private let viewModel: SessionDetailViewModel
    private var collectionView: UICollectionView!
    private var dataSource: UICollectionViewDiffableDataSource<Section, String>!
    private var expandedRowIDs: Set<String> = []
    private let errorBanner = ErrorBannerView()
    private let inputBar = MobileInputBarView()

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
        configureInputBar()
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
            collectionView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            collectionView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
        ])
        let userReg = UICollectionView.CellRegistration<UserPromptCell, UIItem> { cell, _, item in
            cell.configure(with: item)
        }
        let textReg = UICollectionView.CellRegistration<AssistantTextCell, UIItem> { cell, _, item in
            cell.configure(with: item)
        }
        // item 为 (rowID, presentation) 元组：presentation 由 cellProvider 计算一次传入，
        // 配置闭包内不再调用 make(from:)。
        let collapsibleReg = UICollectionView.CellRegistration<CollapsibleItemCell, (String, CollapsiblePresentation)> {
            [weak self] cell, _, pair in
            guard let self else { return }
            let (rowID, presentation) = pair
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
        let approvalReg = UICollectionView.CellRegistration<ApprovalCardCell, Void> {
            [weak self] cell, _, _ in
            guard let self, let request = self.viewModel.pendingApproval else { return }
            let presentation = ApprovalCardPresentation.make(from: request)
            cell.configure(with: presentation, state: self.viewModel.approvalState)
            cell.onApprove = { [weak self] in self?.viewModel.resolveApproval(approve: true) }
            cell.onDeny = { [weak self] in self?.viewModel.resolveApproval(approve: false) }
        }
        dataSource = UICollectionViewDiffableDataSource<Section, String>(collectionView: collectionView) {
            [weak self] collectionView, indexPath, rowID in
            guard let self else { return nil }
            // 审批卡片：固定 item ID
            if rowID == "approval-card" {
                guard self.viewModel.pendingApproval != nil else { return UICollectionViewCell() }
                return collectionView.dequeueConfiguredReusableCell(using: approvalReg, for: indexPath, item: ())
            }
            guard let row = self.viewModel.rows.first(where: { $0.id == rowID }) else { return nil }
            // 渲染路径由 row 数据（role / item.kind）决定，不看 agentKind（N2）。
            switch row.role {
            case .userPrompt:
                return collectionView.dequeueConfiguredReusableCell(using: userReg, for: indexPath, item: row.item)
            case .assistantItem:
                // 优先走折叠 cell；非折叠 kind 降级到文本 cell。make(from:) 只算一次，
                // 结果经元组直接传入 registration。
                if let presentation = CollapsiblePresentation.make(from: row.item) {
                    return collectionView.dequeueConfiguredReusableCell(
                        using: collapsibleReg, for: indexPath, item: (rowID, presentation))
                } else {
                    return collectionView.dequeueConfiguredReusableCell(using: textReg, for: indexPath, item: row.item)
                }
            }
        }
    }

    private func configureInputBar() {
        inputBar.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(inputBar)
        NSLayoutConstraint.activate([
            inputBar.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: DesignTokens.sp3),
            inputBar.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -DesignTokens.sp3),
            inputBar.bottomAnchor.constraint(equalTo: view.keyboardLayoutGuide.topAnchor, constant: -DesignTokens.sp2),
            collectionView.bottomAnchor.constraint(equalTo: inputBar.topAnchor, constant: -DesignTokens.sp2),
        ])
        inputBar.onSend = { [weak self] text in self?.viewModel.sendPrompt(text) }
        inputBar.setEnabled(!viewModel.isStreaming)
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
        // 审批 section：仅当 approvalState != .none 时追加
        var reconfigureIDs: [String] = []
        let existing = Set(dataSource.snapshot().itemIdentifiers)
        reconfigureIDs = ids.filter(existing.contains)
        if viewModel.approvalState != .none {
            snapshot.appendSections([.approval])
            snapshot.appendItems(["approval-card"], toSection: .approval)
            if existing.contains("approval-card") {
                reconfigureIDs.append("approval-card")
            }
        }
        snapshot.reconfigureItems(reconfigureIDs)
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
        inputBar.setEnabled(!viewModel.isStreaming)
    }
}
