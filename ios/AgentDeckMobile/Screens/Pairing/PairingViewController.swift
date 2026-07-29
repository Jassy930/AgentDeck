import AgentDeckSessionSource
import UIKit

struct LocalForgetFlowPresentationGate {
  private(set) var machineID: String?
  private(set) var flowID: UUID?

  mutating func claim(machineID: String) -> UUID? {
    guard self.machineID != machineID else { return nil }
    let claimedFlowID = UUID()
    self.machineID = machineID
    flowID = claimedFlowID
    return claimedFlowID
  }

  mutating func reconcile(with state: PairingMachineActionState) {
    guard let machineID else { return }
    guard case .confirmLocalForget(let currentMachineID, _) = state,
      currentMachineID == machineID
    else {
      self.machineID = nil
      flowID = nil
      return
    }
  }

  mutating func allowsDestructiveConfirmation(
    machineID: String,
    flowID: UUID,
    state: PairingMachineActionState
  ) -> Bool {
    reconcile(with: state)
    guard self.machineID == machineID,
      self.flowID == flowID,
      case .confirmLocalForget(let currentMachineID, .confirmDestructiveRemoval) = state
    else { return false }
    return currentMachineID == machineID
  }

  mutating func release() {
    machineID = nil
    flowID = nil
  }
}

/// Relay Companion 的真实配对入口。视图层只消费 `PairingViewModel`，不解析 invite、
/// 不接触 Relay wire 或密码学材料。
@MainActor
final class PairingViewController: UIViewController, UITableViewDataSource, UITableViewDelegate {
  private let viewModel: PairingViewModel
  private let initialInvite: String?

  private let scanButton = UIButton(configuration: .tinted())
  private let inviteField = UITextField()
  private let inspectButton = UIButton(configuration: .filled())
  private let statusLabel = UILabel()
  private let machineActionLabel = UILabel()
  private let progressView = UIActivityIndicatorView(style: .medium)
  private let primaryActionButton = UIButton(configuration: .borderedProminent())
  private let tableView = UITableView(frame: .zero, style: .insetGrouped)

  private var didInspectInitialInvite = false
  private var pendingScannedInvite: String?
  private var confirmationInvitePresented: String?
  private var localForgetFlowGate = LocalForgetFlowPresentationGate()
  private var machineFailureAlertKey: String?

  init(viewModel: PairingViewModel, initialInvite: String? = nil) {
    self.viewModel = viewModel
    self.initialInvite = initialInvite
    super.init(nibName: nil, bundle: nil)
  }

  required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

  override func viewDidLoad() {
    super.viewDidLoad()
    title = "配对"
    view.backgroundColor = DesignTokens.bg
    navigationItem.leftBarButtonItem = UIBarButtonItem(
      systemItem: .close,
      primaryAction: UIAction { [weak self] _ in self?.close() }
    )

    configurePairingControls()
    configureMachineTable()

    viewModel.onUpdate = { [weak self] in self?.render() }
    viewModel.start()
    render()
  }

  override func viewDidAppear(_ animated: Bool) {
    super.viewDidAppear(animated)

    if let scannedInvite = pendingScannedInvite {
      pendingScannedInvite = nil
      inspect(scannedInvite)
      return
    }

    guard !didInspectInitialInvite else { return }
    didInspectInitialInvite = true
    guard let initialInvite else { return }
    inviteField.text = initialInvite
    inspect(initialInvite)
  }

  private func configurePairingControls() {
    var scanConfiguration = UIButton.Configuration.tinted()
    scanConfiguration.title = "扫描完整配对二维码"
    scanConfiguration.image = UIImage(systemName: "qrcode.viewfinder")
    scanConfiguration.imagePadding = DesignTokens.sp2
    scanConfiguration.baseForegroundColor = DesignTokens.accent
    scanConfiguration.contentInsets = NSDirectionalEdgeInsets(
      top: DesignTokens.sp4,
      leading: DesignTokens.sp4,
      bottom: DesignTokens.sp4,
      trailing: DesignTokens.sp4
    )
    scanButton.configuration = scanConfiguration
    scanButton.layer.cornerRadius = DesignTokens.radiusLg
    scanButton.layer.borderWidth = 1
    scanButton.layer.borderColor = DesignTokens.borderStrong.cgColor
    scanButton.accessibilityIdentifier = "pairing.scan-complete-invite"
    scanButton.addAction(
      UIAction { [weak self] _ in self?.openScanner() },
      for: .touchUpInside
    )

    inviteField.placeholder = "粘贴完整 agentdeck-pair:v1:… 邀请"
    inviteField.borderStyle = .roundedRect
    inviteField.textContentType = nil
    inviteField.autocapitalizationType = .none
    inviteField.autocorrectionType = .no
    inviteField.spellCheckingType = .no
    inviteField.smartDashesType = .no
    inviteField.smartQuotesType = .no
    inviteField.smartInsertDeleteType = .no
    inviteField.clearButtonMode = .whileEditing
    inviteField.returnKeyType = .go
    inviteField.delegate = self
    inviteField.accessibilityIdentifier = "pairing.complete-invite"

    inspectButton.setTitle("检查邀请", for: .normal)
    inspectButton.accessibilityIdentifier = "pairing.inspect-invite"
    inspectButton.addAction(
      UIAction { [weak self] _ in self?.inspectFromField() },
      for: .touchUpInside
    )

    let inviteRow = UIStackView(arrangedSubviews: [inviteField, inspectButton])
    inviteRow.spacing = DesignTokens.sp2
    inviteRow.alignment = .fill

    statusLabel.numberOfLines = 0
    statusLabel.font = .preferredFont(forTextStyle: .subheadline)
    statusLabel.textColor = DesignTokens.text2
    statusLabel.accessibilityIdentifier = "pairing.status"

    machineActionLabel.numberOfLines = 0
    machineActionLabel.font = .preferredFont(forTextStyle: .footnote)
    machineActionLabel.textColor = DesignTokens.warn
    machineActionLabel.isHidden = true
    machineActionLabel.accessibilityIdentifier = "pairing.machine-action-status"

    progressView.color = DesignTokens.accent
    progressView.hidesWhenStopped = true

    primaryActionButton.isHidden = true
    primaryActionButton.accessibilityIdentifier = "pairing.primary-state-action"
    primaryActionButton.addAction(
      UIAction { [weak self] _ in self?.performPrimaryStateAction() },
      for: .touchUpInside
    )

    let stateRow = UIStackView(arrangedSubviews: [progressView, statusLabel])
    stateRow.spacing = DesignTokens.sp2
    stateRow.alignment = .center

    let controls = UIStackView(arrangedSubviews: [
      scanButton,
      inviteRow,
      stateRow,
      primaryActionButton,
      machineActionLabel,
    ])
    controls.axis = .vertical
    controls.spacing = DesignTokens.sp3
    controls.translatesAutoresizingMaskIntoConstraints = false

    let root = UIStackView(arrangedSubviews: [controls, tableView])
    root.axis = .vertical
    root.spacing = DesignTokens.sp2
    root.translatesAutoresizingMaskIntoConstraints = false
    view.addSubview(root)

    NSLayoutConstraint.activate([
      root.topAnchor.constraint(
        equalTo: view.safeAreaLayoutGuide.topAnchor,
        constant: DesignTokens.sp4
      ),
      root.leadingAnchor.constraint(
        equalTo: view.leadingAnchor,
        constant: DesignTokens.sp4
      ),
      root.trailingAnchor.constraint(
        equalTo: view.trailingAnchor,
        constant: -DesignTokens.sp4
      ),
      root.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor),
      inspectButton.widthAnchor.constraint(greaterThanOrEqualToConstant: 92),
    ])
  }

  private func configureMachineTable() {
    tableView.dataSource = self
    tableView.delegate = self
    tableView.register(UITableViewCell.self, forCellReuseIdentifier: "machine")
    tableView.backgroundColor = DesignTokens.bg
    tableView.accessibilityIdentifier = "pairing.paired-machines"
  }

  private func render() {
    renderPairingState()
    renderMachineActionState()
    tableView.reloadData()
  }

  private func renderPairingState() {
    progressView.stopAnimating()
    primaryActionButton.isHidden = true
    statusLabel.textColor = DesignTokens.text2

    switch viewModel.pairingState {
    case .idle:
      statusLabel.text = "仅支持完整 PairInvite；不接受短 PIN。"
      confirmationInvitePresented = nil
    case .inspecting:
      statusLabel.text = "正在本地检查邀请…"
      progressView.startAnimating()
      confirmationInvitePresented = nil
    case .awaitingConfirmation:
      statusLabel.text = "邀请已通过检查，请核对机器与信任信息后明确确认。"
      primaryActionButton.setTitle("查看并确认", for: .normal)
      primaryActionButton.isHidden = false
      presentPairingConfirmationIfNeeded(force: false)
    case .pairing(let progress):
      switch progress {
      case .preparing:
        statusLabel.text = "正在准备并持久化配对请求…"
      case .waitingForLocalConfirmation:
        statusLabel.text = "等待被控机器本地确认…"
      case .paired(let machine):
        statusLabel.text = "已与 \(machine.name) 配对。"
        statusLabel.textColor = DesignTokens.success
      case .canceled:
        statusLabel.text = "被控机器已取消配对。"
        statusLabel.textColor = DesignTokens.warn
      case .expired:
        statusLabel.text = "配对邀请已过期，请生成新邀请。"
        statusLabel.textColor = DesignTokens.warn
      }
      if progress == .preparing || progress == .waitingForLocalConfirmation {
        progressView.startAnimating()
      }
    case .paired(let machine):
      statusLabel.text = "已与 \(machine.name) 配对。"
      statusLabel.textColor = DesignTokens.success
    case .canceled:
      statusLabel.text = "被控机器已取消配对；本地 pending 材料已清理。"
      statusLabel.textColor = DesignTokens.warn
    case .expired:
      statusLabel.text = "配对邀请已过期；请在被控机器生成新邀请。"
      statusLabel.textColor = DesignTokens.warn
    case .failed(let failure, let retryable):
      statusLabel.text = Self.failureDescription(failure)
      statusLabel.textColor = DesignTokens.danger
      if retryable {
        primaryActionButton.setTitle("重试原邀请", for: .normal)
        primaryActionButton.isHidden = false
      }
    }
  }

  private func renderMachineActionState() {
    localForgetFlowGate.reconcile(with: viewModel.machineActionState)
    switch viewModel.machineActionState {
    case .idle:
      machineActionLabel.isHidden = true
      machineActionLabel.text = nil
      machineFailureAlertKey = nil
    case .revoking(let machineID):
      machineActionLabel.isHidden = false
      machineActionLabel.text = "正在为 \(machineName(machineID)) 提交在线撤销…"
      machineFailureAlertKey = nil
    case .waitingForVerifiedRevocation(let machineID):
      machineActionLabel.isHidden = false
      machineActionLabel.text =
        "\(machineName(machineID)) 的撤销已提交，正在等待已验证终态；本机密钥尚未删除。"
      machineFailureAlertKey = nil
    case .confirmLocalForget(let machineID, let step):
      machineActionLabel.isHidden = false
      machineActionLabel.text =
        "仅删除本机配对材料不会撤销被控机器上的残留 grant。"
      presentLocalForgetConfirmationIfNeeded(machineID: machineID, step: step)
    case .forgettingLocal(let machineID):
      machineActionLabel.isHidden = false
      machineActionLabel.text = "正在删除 \(machineName(machineID)) 的本机配对材料…"
      machineFailureAlertKey = nil
    case .failed(let machineID, let error, let retryable):
      machineActionLabel.isHidden = false
      machineActionLabel.text =
        "\(machineName(machineID))：\(Self.failureDescription(error))"
      presentMachineFailureIfNeeded(
        machineID: machineID,
        error: error,
        retryable: retryable
      )
    }
  }

  private func performPrimaryStateAction() {
    switch viewModel.pairingState {
    case .awaitingConfirmation:
      presentPairingConfirmationIfNeeded(force: true)
    case .failed(_, let retryable) where retryable:
      viewModel.retryPairing()
    case .idle, .inspecting, .pairing, .paired, .canceled, .expired, .failed:
      break
    }
  }

  private func inspectFromField() {
    inspect(inviteField.text ?? "")
  }

  private func inspect(_ invite: String) {
    view.endEditing(true)
    viewModel.inspectInvite(invite)
  }

  private func openScanner() {
    guard let navigationController else {
      presentMessage(
        title: "无法打开扫码器",
        message: "当前页面不在导航栈中，请粘贴完整配对邀请。"
      )
      return
    }
    let scanner = QRCodeScannerViewController()
    scanner.onInvite = { [weak self] invite in
      guard let self else { return }
      pendingScannedInvite = invite
      inviteField.text = invite
      navigationController.popViewController(animated: true)
    }
    navigationController.pushViewController(scanner, animated: true)
  }

  private func presentPairingConfirmationIfNeeded(force: Bool) {
    guard case .awaitingConfirmation(let preview) = viewModel.pairingState,
      let invite = viewModel.inspectedInvite
    else { return }
    guard force || confirmationInvitePresented != invite else { return }
    guard presentedViewController == nil else { return }
    confirmationInvitePresented = invite

    let alert = UIAlertController(
      title: "确认配对这台机器？",
      message: Self.previewDescription(preview),
      preferredStyle: .alert
    )
    alert.addAction(UIAlertAction(title: "取消", style: .cancel))
    alert.addAction(
      UIAlertAction(title: "核对无误，开始配对", style: .default) {
        [weak self] _ in
        self?.viewModel.confirmPairing()
      }
    )
    present(alert, animated: true)
  }

  private func confirmOnlineRevocation(machine: MachineSummary) {
    let alert = UIAlertController(
      title: "撤销 \(machine.name) 的本机授权？",
      message:
        "将向被控机器提交在线撤销。只有收到已验证的撤销终态后，AgentDeck 才会删除本机密钥。",
      preferredStyle: .alert
    )
    alert.addAction(UIAlertAction(title: "取消", style: .cancel))
    alert.addAction(
      UIAlertAction(title: "撤销授权", style: .destructive) { [weak self] _ in
        self?.viewModel.revoke(machineID: machine.id)
      }
    )
    present(alert, animated: true)
  }

  private func presentLocalForgetConfirmationIfNeeded(
    machineID: String,
    step: LocalForgetConfirmationStep
  ) {
    guard presentedViewController == nil else { return }
    guard let flowID = localForgetFlowGate.claim(machineID: machineID) else { return }

    switch step {
    case .warnResidualGrant:
      presentResidualGrantWarning(machineID: machineID, flowID: flowID)
    case .confirmDestructiveRemoval:
      presentDestructiveForgetConfirmation(machineID: machineID, flowID: flowID)
    }
  }

  private func presentResidualGrantWarning(machineID: String, flowID: UUID) {
    let alert = UIAlertController(
      title: "仅忘记这台离线机器？",
      message:
        "这只会删除当前 iPhone 上的配对材料，不会撤销被控机器上的残留 grant。你之后必须回到被控机器撤销该授权。",
      preferredStyle: .alert
    )
    alert.addAction(
      UIAlertAction(title: "取消", style: .cancel) { [weak self] _ in
        self?.localForgetFlowGate.release()
        self?.viewModel.cancelLocalForget()
      }
    )
    alert.addAction(
      UIAlertAction(title: "了解风险，继续", style: .destructive) { [weak self] _ in
        guard let self else { return }
        viewModel.confirmLocalForget(machineID: machineID)
        Task { @MainActor [weak self] in
          try? await Task.sleep(for: .milliseconds(300))
          guard let self,
            case .confirmLocalForget(let expectedID, .confirmDestructiveRemoval) =
              viewModel.machineActionState,
            expectedID == machineID
          else { return }
          presentDestructiveForgetConfirmation(machineID: machineID, flowID: flowID)
        }
      }
    )
    present(alert, animated: true)
  }

  private func presentDestructiveForgetConfirmation(machineID: String, flowID: UUID) {
    guard
      localForgetFlowGate.allowsDestructiveConfirmation(
        machineID: machineID,
        flowID: flowID,
        state: viewModel.machineActionState
      )
    else { return }
    guard presentedViewController == nil else {
      Task { @MainActor [weak self] in
        try? await Task.sleep(for: .milliseconds(200))
        self?.presentDestructiveForgetConfirmation(machineID: machineID, flowID: flowID)
      }
      return
    }
    let alert = UIAlertController(
      title: "最后确认：删除本机配对材料",
      message:
        "删除后必须重新配对才能从这部 iPhone 访问该机器；被控机器上的残留 grant 仍需单独撤销。",
      preferredStyle: .alert
    )
    alert.addAction(
      UIAlertAction(title: "保留", style: .cancel) { [weak self] _ in
        self?.localForgetFlowGate.release()
        self?.viewModel.cancelLocalForget()
      }
    )
    alert.addAction(
      UIAlertAction(title: "删除本机材料", style: .destructive) { [weak self] _ in
        guard let self else { return }
        localForgetFlowGate.release()
        viewModel.confirmLocalForget(machineID: machineID)
      }
    )
    present(alert, animated: true)
  }

  private func presentMachineFailureIfNeeded(
    machineID: String,
    error: SessionSourceFailure,
    retryable: Bool
  ) {
    let key = "\(machineID)|\(error.code.rawValue)|\(error.diagnosticReference ?? "")"
    guard machineFailureAlertKey != key, presentedViewController == nil else { return }
    machineFailureAlertKey = key

    let alert = UIAlertController(
      title: retryable ? "撤销未确认" : "机器操作失败",
      message: Self.failureDescription(error),
      preferredStyle: .alert
    )
    alert.addAction(UIAlertAction(title: "关闭", style: .cancel))
    if retryable {
      alert.addAction(
        UIAlertAction(title: "重试在线撤销", style: .default) { [weak self] _ in
          self?.viewModel.revoke(machineID: machineID)
        }
      )
      alert.addAction(
        UIAlertAction(title: "仅忘记本机…", style: .destructive) { [weak self] _ in
          guard let self else { return }
          viewModel.beginLocalForget(machineID: machineID)
          Task { @MainActor [weak self] in
            try? await Task.sleep(for: .milliseconds(300))
            self?.renderMachineActionState()
          }
        }
      )
    }
    present(alert, animated: true)
  }

  private func presentMessage(title: String, message: String) {
    let alert = UIAlertController(title: title, message: message, preferredStyle: .alert)
    alert.addAction(UIAlertAction(title: "好", style: .default))
    present(alert, animated: true)
  }

  private func machineName(_ machineID: String) -> String {
    viewModel.machines.first(where: { $0.id == machineID })?.name ?? machineID
  }

  private func close() {
    viewModel.cancelActiveTasks()
    dismiss(animated: true)
  }

  private static func previewDescription(_ preview: PairingPreview) -> String {
    let expiry = ISO8601DateFormatter().string(
      from: Date(timeIntervalSince1970: TimeInterval(preview.expiresAtMs) / 1_000)
    )
    return [
      "机器名：\(preview.name)",
      "Relay host：\(preview.relayHost)",
      "Machine Root fingerprint：\(hex(preview.rootFingerprint))",
      "Relay server ID：\(optionalHex(preview.relayServerID))",
      "Current SPKI pin：\(optionalHex(preview.currentSPKIPin))",
      "Next SPKI pin：\(optionalHex(preview.nextSPKIPin))",
      "过期时间：\(expiry)（\(preview.expiresAtMs) ms）",
    ].joined(separator: "\n\n")
  }

  private static func optionalHex(_ value: Data?) -> String {
    value.map(hex) ?? "未提供"
  }

  private static func hex(_ value: Data) -> String {
    value.map { String(format: "%02X", $0) }.joined(separator: ":")
  }

  private static func failureDescription(_ failure: SessionSourceFailure) -> String {
    let summary: String
    if let message = failure.message, !message.isEmpty {
      summary = message
    } else {
      summary =
        switch failure.code {
        case .transportUnavailable: "Relay 暂时不可达"
        case .machineOffline: "机器离线"
        case .revoked: "授权已撤销"
        case .incompatible: "协议或版本不兼容"
        case .securityError: "安全校验失败"
        case .invalidPairInvite: "配对邀请无效；请粘贴完整 PairInvite，不要输入短 PIN"
        case .pairInviteExpired: "配对邀请已过期"
        case .commandRejected: "被控机器拒绝了请求"
        case .storageUnavailable: "本地安全存储不可用"
        case .unknown: "发生未知错误"
        }
    }
    var result = "\(summary)（\(failure.code.rawValue)）"
    if let reference = failure.diagnosticReference, !reference.isEmpty {
      result += "\n诊断引用：\(reference)"
    }
    return result
  }

  func tableView(
    _ tableView: UITableView,
    numberOfRowsInSection section: Int
  ) -> Int {
    _ = tableView
    _ = section
    return viewModel.machines.count
  }

  func tableView(
    _ tableView: UITableView,
    cellForRowAt indexPath: IndexPath
  ) -> UITableViewCell {
    let cell = tableView.dequeueReusableCell(withIdentifier: "machine", for: indexPath)
    let machine = viewModel.machines[indexPath.row]
    let presentation = MachineRowPresentation.make(from: machine)

    var background = UIBackgroundConfiguration.listGroupedCell()
    background.backgroundColor = DesignTokens.surface
    background.backgroundColorTransformer = nil
    cell.backgroundConfiguration = background

    var content = cell.defaultContentConfiguration()
    content.text = machine.name
    content.secondaryText = presentation.statusText
    content.textProperties.color = DesignTokens.text
    content.secondaryTextProperties.color = DesignTokens.text2
    cell.contentConfiguration = content
    cell.accessibilityIdentifier = "pairing.machine.\(machine.id)"
    return cell
  }

  func tableView(
    _ tableView: UITableView,
    titleForHeaderInSection section: Int
  ) -> String? {
    _ = tableView
    _ = section
    return "已配对机器"
  }

  func tableView(
    _ tableView: UITableView,
    trailingSwipeActionsConfigurationForRowAt indexPath: IndexPath
  ) -> UISwipeActionsConfiguration? {
    let machine = viewModel.machines[indexPath.row]
    switch machine.connectionState {
    case .relayUnavailable, .machineOffline:
      let forget = UIContextualAction(style: .destructive, title: "本地忘记") {
        [weak self] _, _, completion in
        completion(false)
        self?.viewModel.beginLocalForget(machineID: machine.id)
      }
      return UISwipeActionsConfiguration(actions: [forget])
    case .revoked:
      return nil
    case .connecting, .connected, .reconnecting, .lagged, .incompatible,
      .securityError:
      let revoke = UIContextualAction(style: .destructive, title: "在线撤销") {
        [weak self] _, _, completion in
        completion(false)
        self?.confirmOnlineRevocation(machine: machine)
      }
      return UISwipeActionsConfiguration(actions: [revoke])
    }
  }
}

extension PairingViewController: UITextFieldDelegate {
  func textFieldShouldReturn(_ textField: UITextField) -> Bool {
    guard textField === inviteField else { return true }
    inspectFromField()
    return true
  }
}
