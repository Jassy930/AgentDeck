import AgentDeckSessionSource
import AppKit
import Foundation

/// 被控 Mac 的本机 pending-device 确认面板。
///
/// 控制器只依赖 `LocalPairingAdministration` facade，不知道 UDS、Relay、daemon concrete source
/// 或 wire DTO。每次决定绑定 pairing ID、request hash、完整 DeviceSign fingerprint 与 expiry；
/// 同 ID 在请求途中换成另一份身份时，迟到结果会 fail-closed，不能覆盖新请求。
@MainActor
final class PendingDeviceApprovalController: NSViewController {
  enum Decision: String, Equatable, Sendable {
    case confirm
    case cancel
  }

  enum FailureKind: String, Equatable, Sendable {
    case transportUnavailable
    case expired
    case canceled
    case securityFailure
    case rejected
    case unknown
  }

  enum Outcome: Equatable, Sendable {
    case confirmed(pairingID: String)
    case canceled(pairingID: String)
    case expired(pairingID: String)
    case replayed(pairingID: String, decision: String, state: String)
    case alreadyHandled(pairingID: String, winner: String, state: String)
    case failed(pairingID: String, kind: FailureKind, retryable: Bool)
    case securityFailure(pairingID: String)
  }

  enum ResourceStatus: Equatable, Sendable {
    case loading
    case ready(revision: UInt64)
    case stale
    case failed(kind: FailureKind, retryable: Bool)
  }

  struct Row: Equatable, Sendable {
    let pairingID: String
    let fingerprint: String
    let requestedAtMilliseconds: UInt64
    let expiresAtMilliseconds: UInt64
    let isDecisionInFlight: Bool
    let isExpired: Bool
    let isActionEnabled: Bool
  }

  private struct Identity: Equatable, Sendable {
    let pairingID: String
    let requestHash: Data
    let fingerprint: Data
    let expiresAtMilliseconds: UInt64
  }

  private struct InFlightDecision: Sendable {
    let identity: Identity
    let decision: Decision
  }

  private static let maximumVisiblePairings = 1_024

  private let administration: any LocalPairingAdministration
  private let nowMilliseconds: @Sendable () -> UInt64
  private let rowsStack = NSStackView()
  private let statusLabel = NSTextField(labelWithString: "")
  private var observationTask: Task<Void, Never>?
  private var pairingsByID: [String: PendingPairing] = [:]
  private var identitiesByID: [String: Identity] = [:]
  private var inFlightByID: [String: InFlightDecision] = [:]
  private var compromisedIDs: Set<String> = []
  private var invalidatedOperationIDs: Set<String> = []
  private var terminalIDs: Set<String> = []

  private(set) var rows: [Row] = []
  private(set) var lastOutcome: Outcome?
  private(set) var resourceStatus: ResourceStatus = .loading

  init(
    administration: any LocalPairingAdministration,
    nowMilliseconds: @escaping @Sendable () -> UInt64 = {
      let milliseconds = Date().timeIntervalSince1970 * 1_000
      return milliseconds > 0 ? UInt64(milliseconds) : 0
    }
  ) {
    self.administration = administration
    self.nowMilliseconds = nowMilliseconds
    super.init(nibName: nil, bundle: nil)
  }

  @available(*, unavailable)
  required init?(coder: NSCoder) {
    fatalError("init(coder:) has not been implemented")
  }

  override func loadView() {
    let root = NSView()
    root.translatesAutoresizingMaskIntoConstraints = false

    let title = NSTextField(labelWithString: "待确认的设备配对")
    title.font = .systemFont(ofSize: 20, weight: .semibold)
    title.setAccessibilityIdentifier("pending-device-approval.title")

    let explanation = NSTextField(
      wrappingLabelWithString:
        "仅在这台被控 Mac 上核对完整 DeviceSign 指纹。确认前，请求设备不能自行获得授权。"
    )
    explanation.textColor = .secondaryLabelColor
    explanation.maximumNumberOfLines = 0

    statusLabel.textColor = .secondaryLabelColor
    statusLabel.maximumNumberOfLines = 0
    statusLabel.setAccessibilityIdentifier("pending-device-approval.status")

    rowsStack.orientation = .vertical
    rowsStack.alignment = .width
    rowsStack.spacing = 12
    rowsStack.translatesAutoresizingMaskIntoConstraints = false

    let scrollView = NSScrollView()
    scrollView.hasVerticalScroller = true
    scrollView.drawsBackground = false
    scrollView.documentView = rowsStack
    scrollView.translatesAutoresizingMaskIntoConstraints = false

    let content = NSStackView(views: [title, explanation, statusLabel, scrollView])
    content.orientation = .vertical
    content.alignment = .leading
    content.spacing = 12
    content.translatesAutoresizingMaskIntoConstraints = false
    root.addSubview(content)

    NSLayoutConstraint.activate([
      root.widthAnchor.constraint(greaterThanOrEqualToConstant: 640),
      root.heightAnchor.constraint(greaterThanOrEqualToConstant: 420),
      content.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 24),
      content.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -24),
      content.topAnchor.constraint(equalTo: root.topAnchor, constant: 22),
      content.bottomAnchor.constraint(equalTo: root.bottomAnchor, constant: -22),
      scrollView.leadingAnchor.constraint(equalTo: content.leadingAnchor),
      scrollView.trailingAnchor.constraint(equalTo: content.trailingAnchor),
      scrollView.heightAnchor.constraint(greaterThanOrEqualToConstant: 280),
      rowsStack.widthAnchor.constraint(equalTo: scrollView.contentView.widthAnchor),
    ])

    view = root
    render()
    startObserving()
  }

  func startObserving() {
    guard observationTask == nil else { return }
    let administration = administration
    observationTask = Task { @MainActor [weak self, administration] in
      let stream = await administration.pendingPairings()
      for await state in stream {
        guard !Task.isCancelled, let self else { return }
        self.apply(state)
      }
    }
  }

  func stopObserving() async {
    guard let task = observationTask else { return }
    observationTask = nil
    task.cancel()
    await task.value
  }

  @discardableResult
  func submit(pairingID: String, decision: Decision) -> Bool {
    guard let pairing = pairingsByID[pairingID], let identity = identitiesByID[pairingID],
      inFlightByID[pairingID] == nil, !compromisedIDs.contains(pairingID),
      !terminalIDs.contains(pairingID)
    else {
      return false
    }
    guard pairing.expiresAtMs > nowMilliseconds() else {
      lastOutcome = .expired(pairingID: pairingID)
      terminalIDs.insert(pairingID)
      rebuildRows()
      render()
      return false
    }

    inFlightByID[pairingID] = InFlightDecision(identity: identity, decision: decision)
    rebuildRows()
    render()
    let administration = administration
    Task { @MainActor [weak self, administration, pairingID, decision] in
      do {
        let receipt: PairingAdministrationReceipt
        switch decision {
        case .confirm:
          receipt = try await administration.confirmPairing(id: pairingID)
        case .cancel:
          receipt = try await administration.cancelPairing(id: pairingID)
        }
        self?.finish(pairingID: pairingID, result: .success(Self.outcome(for: receipt)))
      } catch {
        self?.finish(
          pairingID: pairingID,
          result: .failure(error)
        )
      }
    }
    return true
  }

  static func outcome(for receipt: PairingAdministrationReceipt) -> Outcome {
    switch receipt {
    case .confirmed(let id):
      return .confirmed(pairingID: id.rawValue)
    case .canceled(let id):
      return .canceled(pairingID: id.rawValue)
    case .expired(let id):
      return .expired(pairingID: id.rawValue)
    case .replayed(let id, let decision, let state):
      return .replayed(
        pairingID: id.rawValue,
        decision: decision.rawValue,
        state: state.rawValue
      )
    case .alreadyHandled(let id, let winner, let state):
      return .alreadyHandled(
        pairingID: id.rawValue,
        winner: winner.rawValue,
        state: state.rawValue
      )
    case .failed(let failure):
      let kind = failureKind(forDaemonCode: failure.code)
      return .failed(
        pairingID: "unknown",
        kind: kind,
        retryable: kind == .transportUnavailable
      )
    }
  }

  static func outcome(for error: any Error, pairingID: String) -> Outcome {
    guard let failure = error as? SessionSourceFailure else {
      return .failed(pairingID: pairingID, kind: .securityFailure, retryable: false)
    }
    switch failure.code {
    case .transportUnavailable, .machineOffline, .storageUnavailable:
      return .failed(pairingID: pairingID, kind: .transportUnavailable, retryable: true)
    case .pairInviteExpired:
      return .failed(pairingID: pairingID, kind: .expired, retryable: false)
    case .revoked, .incompatible, .securityError, .invalidPairInvite:
      return .failed(pairingID: pairingID, kind: .securityFailure, retryable: false)
    case .commandRejected:
      return .failed(pairingID: pairingID, kind: .rejected, retryable: false)
    case .unknown:
      return .failed(pairingID: pairingID, kind: .unknown, retryable: true)
    }
  }

  private static func failureKind(forDaemonCode code: String) -> FailureKind {
    switch code {
    case "daemon.pairing.expired":
      return .expired
    case "daemon.pairing.canceled":
      return .canceled
    default:
      if code.contains("transport_unavailable") || code.contains("not_ready")
        || code.contains("recovering") || code.contains("store_busy")
      {
        return .transportUnavailable
      }
      if code.contains("invalid") || code.contains("security") || code.contains("rollback")
        || code.contains("replay")
      {
        return .securityFailure
      }
      return .rejected
    }
  }

  private func apply(_ state: ResourceState<[PendingPairing]>) {
    switch state {
    case .loading(let previous):
      resourceStatus = .loading
      if let previous { applyPairings(previous) }
    case .ready(let value, let revision):
      resourceStatus = .ready(revision: revision)
      applyPairings(value)
    case .stale(let value, _):
      resourceStatus = .stale
      applyPairings(value)
    case .failed(let error, let retryable):
      let mapped = Self.outcome(for: error, pairingID: "resource")
      let kind: FailureKind
      if case .failed(_, let failureKind, _) = mapped {
        kind = failureKind
      } else {
        kind = .unknown
      }
      resourceStatus = .failed(kind: kind, retryable: retryable)
      applyPairings([])
    }
    render()
  }

  private func applyPairings(_ pairings: [PendingPairing]) {
    guard pairings.count <= Self.maximumVisiblePairings else {
      resourceStatus = .failed(kind: .securityFailure, retryable: false)
      pairingsByID.removeAll(keepingCapacity: false)
      identitiesByID.removeAll(keepingCapacity: false)
      rows = []
      return
    }

    var nextPairings: [String: PendingPairing] = [:]
    var nextIdentities: [String: Identity] = [:]
    for pairing in pairings {
      let identity = Self.identity(for: pairing)
      let id = identity.pairingID
      guard nextPairings[id] == nil else {
        resourceStatus = .failed(kind: .securityFailure, retryable: false)
        pairingsByID.removeAll(keepingCapacity: false)
        identitiesByID.removeAll(keepingCapacity: false)
        rows = []
        return
      }
      if let operation = inFlightByID[id], operation.identity != identity {
        invalidatedOperationIDs.insert(id)
        compromisedIDs.insert(id)
        lastOutcome = .securityFailure(pairingID: id)
      } else if let existing = identitiesByID[id], existing != identity {
        compromisedIDs.insert(id)
        lastOutcome = .securityFailure(pairingID: id)
      }
      nextPairings[id] = pairing
      nextIdentities[id] = identity
    }

    let retainedIDs = Set(nextPairings.keys).union(inFlightByID.keys)
    compromisedIDs.formIntersection(retainedIDs)
    terminalIDs.formIntersection(retainedIDs)
    pairingsByID = nextPairings
    identitiesByID = nextIdentities
    rebuildRows()
  }

  private func finish(
    pairingID: String,
    result: Result<Outcome, any Error>
  ) {
    guard let operation = inFlightByID.removeValue(forKey: pairingID) else { return }
    let currentIdentity = identitiesByID[pairingID]
    let wasInvalidated = invalidatedOperationIDs.remove(pairingID) != nil
    guard !wasInvalidated, currentIdentity == nil || currentIdentity == operation.identity else {
      compromisedIDs.insert(pairingID)
      lastOutcome = .securityFailure(pairingID: pairingID)
      rebuildRows()
      render()
      return
    }

    switch result {
    case .success(let outcome):
      let validated = Self.validating(outcome, for: pairingID)
      if case .securityFailure = validated {
        compromisedIDs.insert(pairingID)
      }
      lastOutcome = validated
    case .failure(let error):
      lastOutcome = Self.outcome(for: error, pairingID: pairingID)
    }
    if let lastOutcome, Self.isTerminal(lastOutcome) {
      terminalIDs.insert(pairingID)
    }
    rebuildRows()
    render()
  }

  private static func validating(_ outcome: Outcome, for pairingID: String) -> Outcome {
    switch outcome {
    case .confirmed(let receiptID), .canceled(let receiptID), .expired(let receiptID):
      return receiptID == pairingID ? outcome : .securityFailure(pairingID: pairingID)
    case .replayed(let receiptID, _, _), .alreadyHandled(let receiptID, _, _):
      return receiptID == pairingID ? outcome : .securityFailure(pairingID: pairingID)
    case .failed(_, let kind, let retryable):
      return .failed(pairingID: pairingID, kind: kind, retryable: retryable)
    case .securityFailure(let receiptID):
      return receiptID == pairingID ? outcome : .securityFailure(pairingID: pairingID)
    }
  }

  private static func isTerminal(_ outcome: Outcome) -> Bool {
    switch outcome {
    case .failed(_, _, let retryable):
      return !retryable
    default:
      return true
    }
  }

  private static func identity(for pairing: PendingPairing) -> Identity {
    Identity(
      pairingID: pairing.pairingID.rawValue,
      requestHash: pairing.requestHash,
      fingerprint: pairing.deviceSignFingerprint,
      expiresAtMilliseconds: pairing.expiresAtMs
    )
  }

  private func rebuildRows() {
    let now = nowMilliseconds()
    rows = pairingsByID.values
      .sorted {
        if $0.requestedAtMs == $1.requestedAtMs {
          return $0.pairingID.rawValue < $1.pairingID.rawValue
        }
        return $0.requestedAtMs < $1.requestedAtMs
      }
      .map { pairing in
        let id = pairing.pairingID.rawValue
        let expired = pairing.expiresAtMs <= now
        let inFlight = inFlightByID[id] != nil
        return Row(
          pairingID: id,
          fingerprint: Self.fingerprintText(pairing.deviceSignFingerprint),
          requestedAtMilliseconds: pairing.requestedAtMs,
          expiresAtMilliseconds: pairing.expiresAtMs,
          isDecisionInFlight: inFlight,
          isExpired: expired,
          isActionEnabled: !expired && !inFlight && !compromisedIDs.contains(id)
            && !terminalIDs.contains(id)
        )
      }
  }

  private static func fingerprintText(_ fingerprint: Data) -> String {
    guard fingerprint.count == 32 else { return "INVALID-FINGERPRINT" }
    return fingerprint.map { String(format: "%02X", $0) }.joined(separator: ":")
  }

  private func render() {
    guard isViewLoaded else { return }
    for arranged in rowsStack.arrangedSubviews {
      rowsStack.removeArrangedSubview(arranged)
      arranged.removeFromSuperview()
    }

    statusLabel.stringValue = statusText()
    if rows.isEmpty {
      let empty = NSTextField(labelWithString: emptyStateText())
      empty.textColor = .secondaryLabelColor
      empty.setAccessibilityIdentifier("pending-device-approval.empty")
      rowsStack.addArrangedSubview(empty)
      return
    }

    for row in rows {
      rowsStack.addArrangedSubview(makeRowView(row))
    }
  }

  private func makeRowView(_ row: Row) -> NSView {
    let pairingLabel = NSTextField(labelWithString: "请求 \(row.pairingID)")
    pairingLabel.font = .systemFont(ofSize: 13, weight: .medium)

    let fingerprintTitle = NSTextField(labelWithString: "DeviceSign fingerprint")
    fingerprintTitle.textColor = .secondaryLabelColor
    let fingerprint = NSTextField(labelWithString: row.fingerprint)
    fingerprint.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
    fingerprint.isSelectable = true
    fingerprint.lineBreakMode = .byCharWrapping
    fingerprint.maximumNumberOfLines = 0
    fingerprint.setAccessibilityIdentifier("pending-device-approval.fingerprint.\(row.pairingID)")

    let expiry = Date(timeIntervalSince1970: TimeInterval(row.expiresAtMilliseconds) / 1_000)
    let expiryLabel = NSTextField(
      labelWithString: row.isExpired
        ? "状态：已过期"
        : "有效期至：\(Self.dateFormatter.string(from: expiry))"
    )
    expiryLabel.textColor = row.isExpired ? .systemOrange : .secondaryLabelColor

    let confirm = PendingDeviceDecisionButton(
      title: row.isDecisionInFlight ? "处理中…" : "确认设备",
      target: self,
      action: #selector(handleDecisionButton(_:))
    )
    confirm.pairingID = row.pairingID
    confirm.decision = .confirm
    confirm.bezelStyle = .rounded
    confirm.isEnabled = row.isActionEnabled

    let cancel = PendingDeviceDecisionButton(
      title: "拒绝并取消",
      target: self,
      action: #selector(handleDecisionButton(_:))
    )
    cancel.pairingID = row.pairingID
    cancel.decision = .cancel
    cancel.bezelStyle = .rounded
    cancel.isEnabled = row.isActionEnabled

    let buttons = NSStackView(views: [confirm, cancel])
    buttons.orientation = .horizontal
    buttons.spacing = 8

    let content = NSStackView(
      views: [pairingLabel, fingerprintTitle, fingerprint, expiryLabel, buttons]
    )
    content.orientation = .vertical
    content.alignment = .leading
    content.spacing = 6
    content.translatesAutoresizingMaskIntoConstraints = false
    // 不替换 `NSBox.contentView`：普通容器的 ownership 更直接，也让 padding
    // 完全由约束表达。行宽由父 `rowsStack.alignment = .width` 单向管理。
    let card = NSView()
    card.wantsLayer = true
    card.layer?.cornerRadius = 8
    card.layer?.borderColor = NSColor.separatorColor.cgColor
    card.layer?.borderWidth = 1
    card.layer?.backgroundColor = NSColor.controlBackgroundColor.cgColor
    card.translatesAutoresizingMaskIntoConstraints = false
    card.addSubview(content)
    NSLayoutConstraint.activate([
      content.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 14),
      content.trailingAnchor.constraint(equalTo: card.trailingAnchor, constant: -14),
      content.topAnchor.constraint(equalTo: card.topAnchor, constant: 12),
      content.bottomAnchor.constraint(equalTo: card.bottomAnchor, constant: -12),
    ])
    return card
  }

  @objc private func handleDecisionButton(_ sender: PendingDeviceDecisionButton) {
    guard let pairingID = sender.pairingID, let decision = sender.decision else { return }
    _ = submit(pairingID: pairingID, decision: decision)
  }

  private func statusText() -> String {
    if let lastOutcome { return Self.outcomeText(lastOutcome) }
    switch resourceStatus {
    case .loading:
      return "正在读取本机 pending-device 请求…"
    case .ready:
      return rows.isEmpty ? "当前没有待确认的设备。" : "请逐字核对完整指纹后再确认。"
    case .stale:
      return "连接正在恢复；列表可能已过期，确认操作暂以服务端结果为准。"
    case .failed(let kind, let retryable):
      return Self.failureText(kind: kind, retryable: retryable)
    }
  }

  private func emptyStateText() -> String {
    switch resourceStatus {
    case .failed:
      return "无法读取待确认设备。"
    default:
      return "没有 pending-device 请求。"
    }
  }

  private static func outcomeText(_ outcome: Outcome) -> String {
    switch outcome {
    case .confirmed:
      return "设备已确认；授权响应正在按 daemon 状态机交付。"
    case .canceled:
      return "请求已取消。"
    case .expired:
      return "请求已过期，未授予设备权限。"
    case .replayed(_, let decision, let state):
      return "幂等重放：决定 \(decision)，当前状态 \(state)。"
    case .alreadyHandled(_, let winner, let state):
      return "已由另一操作处理：赢家 \(winner)，当前状态 \(state)。"
    case .failed(_, let kind, let retryable):
      return failureText(kind: kind, retryable: retryable)
    case .securityFailure:
      return "安全校验失败：同一请求 ID 的指纹发生变化，迟到结果已拒绝。"
    }
  }

  private static func failureText(kind: FailureKind, retryable: Bool) -> String {
    switch kind {
    case .transportUnavailable:
      return retryable ? "本机 Runtime 暂不可用，可以稍后重试。" : "本机 Runtime 不可用。"
    case .expired:
      return "请求已过期，未授予设备权限。"
    case .canceled:
      return "请求已取消。"
    case .securityFailure:
      return "安全校验失败；没有执行授权。"
    case .rejected:
      return "请求已失效或已被处理。"
    case .unknown:
      return retryable ? "状态未知，可以稍后重试。" : "状态未知，未执行授权。"
    }
  }

  private static let dateFormatter: DateFormatter = {
    let formatter = DateFormatter()
    formatter.locale = Locale(identifier: "zh_CN")
    formatter.dateStyle = .medium
    formatter.timeStyle = .medium
    return formatter
  }()
}

@MainActor
private final class PendingDeviceDecisionButton: NSButton {
  var pairingID: String?
  var decision: PendingDeviceApprovalController.Decision?
}
