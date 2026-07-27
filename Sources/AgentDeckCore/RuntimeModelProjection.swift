import Foundation

/// Runtime canonical 数据进入 App model 前的纯校验错误。
///
/// 这些错误只描述本地投影不变量；wire decode 与 daemon failure code 仍由各自边界负责。
public enum RuntimeCanonicalProjectionError: Error, Equatable, Sendable {
  case emptyConversationID
  case emptyEventID
  case emptyItemID
  case emptyEntityID
  case emptyCommandID
  case userMessageRequiresCommandID
  case snapshotDoesNotContainItem
  case eventDoesNotContainItem
  case duplicateSnapshotItem
  case duplicateSnapshotEntity
  case itemIdentityConflict
  case entityIdentityConflict
  case commandIdentityConflict
  case itemKindConflict
  case conversationMismatch
  case duplicateEventID
  case unexpectedEventSequence(expected: UInt64, actual: UInt64)
  case eventCursorExhausted
  case unexpectedRevision(expected: UInt64, actual: UInt64)
  case revisionExhausted
}

/// daemon 签发的稳定 UI item 身份。App 不再生成 `ai-N` 之类的替代 ID。
public struct RuntimeCanonicalItemIdentity: Equatable, Sendable {
  public let itemID: RuntimeItemID
  public let entityID: RuntimeEntityID
  public let commandID: RuntimeCommandID?

  public init(
    itemID: RuntimeItemID,
    entityID: RuntimeEntityID,
    commandID: RuntimeCommandID?
  ) throws {
    guard !itemID.rawValue.isEmpty else {
      throw RuntimeCanonicalProjectionError.emptyItemID
    }
    guard !entityID.rawValue.isEmpty else {
      throw RuntimeCanonicalProjectionError.emptyEntityID
    }
    if let commandID, commandID.rawValue.isEmpty {
      throw RuntimeCanonicalProjectionError.emptyCommandID
    }
    self.itemID = itemID
    self.entityID = entityID
    self.commandID = commandID
  }
}

/// Snapshot 与 Event 共用的 canonical AgentItem 投影。
///
/// 构造器要求调用方提供 daemon identity，因此从类型入口上禁止回退到本地序号合成。
struct RuntimeCanonicalItemProjection: Sendable {
  let identity: RuntimeCanonicalItemIdentity
  let item: RuntimeAgentItemV1

  fileprivate let kind: RuntimeCanonicalItemKind

  init(
    itemID: RuntimeItemID,
    entityID: RuntimeEntityID,
    commandID: RuntimeCommandID?,
    item: RuntimeAgentItemV1
  ) throws {
    if case .userMessage = item, commandID == nil {
      throw RuntimeCanonicalProjectionError.userMessageRequiresCommandID
    }
    identity = try RuntimeCanonicalItemIdentity(
      itemID: itemID,
      entityID: entityID,
      commandID: commandID
    )
    self.item = item
    kind = RuntimeCanonicalItemKind(item)
  }

  init(snapshotItem: SnapshotItemV1) throws {
    guard case .item(let itemID, let entityID, let commandID, let item) = snapshotItem else {
      throw RuntimeCanonicalProjectionError.snapshotDoesNotContainItem
    }
    try self.init(
      itemID: itemID,
      entityID: entityID,
      commandID: commandID,
      item: item
    )
  }

  init(event: RuntimeEventV2) throws {
    guard case .item(let item) = event.body,
      let itemID = event.itemID,
      let entityID = event.entityID
    else {
      throw RuntimeCanonicalProjectionError.eventDoesNotContainItem
    }
    try self.init(
      itemID: itemID,
      entityID: entityID,
      commandID: event.commandID,
      item: item
    )
  }

  /// 将 snapshot 的 final-state item 插入空白投影；重复 item/entity 一律拒绝。
  func applySnapshot(
    into store: inout AgentItemStore,
    identities: inout RuntimeCanonicalIdentityState
  ) throws {
    let nextIdentities = try identities.insertingSnapshot(self)
    AgentItemReducer.apply(
      item.agentDeckItem,
      itemId: identity.itemID.rawValue,
      into: &store
    )
    identities = nextIdentities
  }

  /// 应用一条 cumulative event；同一 item/entity/command/kind 更新保留首次位置。
  func applyEvent(
    into store: inout AgentItemStore,
    identities: inout RuntimeCanonicalIdentityState
  ) throws {
    let nextIdentities = try identities.reducingEvent(self)
    AgentItemReducer.apply(
      item.agentDeckItem,
      itemId: identity.itemID.rawValue,
      into: &store
    )
    identities = nextIdentities
  }
}

/// 稳定 item/entity 双向绑定与 command/kind 绑定。
///
/// Snapshot 使用唯一插入语义；Event 允许同一绑定的 cumulative replacement。
struct RuntimeCanonicalIdentityState: Sendable {
  private var bindingsByItemID: [RuntimeItemID: RuntimeCanonicalItemBinding] = [:]
  private var itemIDByEntityID: [RuntimeEntityID: RuntimeItemID] = [:]

  var count: Int { bindingsByItemID.count }

  func insertingSnapshot(_ projection: RuntimeCanonicalItemProjection) throws -> Self {
    let identity = projection.identity
    if bindingsByItemID[identity.itemID] != nil {
      throw RuntimeCanonicalProjectionError.duplicateSnapshotItem
    }
    if itemIDByEntityID[identity.entityID] != nil {
      throw RuntimeCanonicalProjectionError.duplicateSnapshotEntity
    }
    return inserting(identity, kind: projection.kind)
  }

  func reducingEvent(_ projection: RuntimeCanonicalItemProjection) throws -> Self {
    let identity = projection.identity
    let binding = bindingsByItemID[identity.itemID]
    let itemID = itemIDByEntityID[identity.entityID]

    switch (binding, itemID) {
    case (nil, nil):
      return inserting(identity, kind: projection.kind)
    case (.some(let existing), .some(let existingItemID)):
      guard existing.identity.entityID == identity.entityID,
        existingItemID == identity.itemID
      else {
        if existing.identity.entityID != identity.entityID {
          throw RuntimeCanonicalProjectionError.itemIdentityConflict
        }
        throw RuntimeCanonicalProjectionError.entityIdentityConflict
      }
      guard existing.identity.commandID == identity.commandID else {
        throw RuntimeCanonicalProjectionError.commandIdentityConflict
      }
      guard existing.kind == projection.kind else {
        throw RuntimeCanonicalProjectionError.itemKindConflict
      }
      return self
    case (.some, nil):
      throw RuntimeCanonicalProjectionError.itemIdentityConflict
    case (nil, .some):
      throw RuntimeCanonicalProjectionError.entityIdentityConflict
    }
  }

  private func inserting(
    _ identity: RuntimeCanonicalItemIdentity,
    kind: RuntimeCanonicalItemKind
  ) -> Self {
    var next = self
    next.bindingsByItemID[identity.itemID] = RuntimeCanonicalItemBinding(
      identity: identity,
      kind: kind
    )
    next.itemIDByEntityID[identity.entityID] = identity.itemID
    return next
  }
}

/// Conversation snapshot 的 base cursor 与后续 canonical event 的连续性状态。
public struct RuntimeCanonicalEventCursorState: Equatable, Sendable {
  public let conversationID: RuntimeConversationID
  public let cursor: RuntimeStreamCursorV1
  public let lastEventID: RuntimeEventID?

  public init(
    conversationID: RuntimeConversationID,
    baseCursor: RuntimeStreamCursorV1,
    lastEventID: RuntimeEventID? = nil
  ) throws {
    guard !conversationID.rawValue.isEmpty else {
      throw RuntimeCanonicalProjectionError.emptyConversationID
    }
    if let lastEventID, lastEventID.rawValue.isEmpty {
      throw RuntimeCanonicalProjectionError.emptyEventID
    }
    self.conversationID = conversationID
    cursor = baseCursor
    self.lastEventID = lastEventID
  }

  /// 只接受 exact next sequence。重复、回退与 gap 都不会产生新状态。
  public func reducing(_ event: RuntimeEventV2) throws -> Self {
    guard event.conversationID == conversationID else {
      throw RuntimeCanonicalProjectionError.conversationMismatch
    }
    guard !event.eventID.rawValue.isEmpty else {
      throw RuntimeCanonicalProjectionError.emptyEventID
    }
    let expected: UInt64
    do {
      expected = try cursor.checkedNext()
    } catch {
      throw RuntimeCanonicalProjectionError.eventCursorExhausted
    }
    guard event.eventSeq == expected else {
      throw RuntimeCanonicalProjectionError.unexpectedEventSequence(
        expected: expected,
        actual: event.eventSeq
      )
    }
    guard event.eventID != lastEventID else {
      throw RuntimeCanonicalProjectionError.duplicateEventID
    }
    return try Self(
      conversationID: conversationID,
      baseCursor: .at(event.eventSeq),
      lastEventID: event.eventID
    )
  }
}

/// Catalog 等全局 revision 轴的 exact-next 纯 reducer。
public struct RuntimeCanonicalRevisionState: Equatable, Sendable {
  public let cursor: RuntimeStreamCursorV1

  public init(baseCursor: RuntimeStreamCursorV1) {
    cursor = baseCursor
  }

  public func reducing(_ revision: UInt64) throws -> Self {
    let expected: UInt64
    do {
      expected = try cursor.checkedNext()
    } catch {
      throw RuntimeCanonicalProjectionError.revisionExhausted
    }
    guard revision == expected else {
      throw RuntimeCanonicalProjectionError.unexpectedRevision(
        expected: expected,
        actual: revision
      )
    }
    return Self(baseCursor: .at(revision))
  }
}

private struct RuntimeCanonicalItemBinding: Sendable {
  let identity: RuntimeCanonicalItemIdentity
  let kind: RuntimeCanonicalItemKind
}

private enum RuntimeCanonicalItemKind: Sendable {
  case userMessage
  case assistantMessage
  case reasoning
  case shell
  case diff
  case plan
  case imageReference
  case toolCall
  case raw

  init(_ item: RuntimeAgentItemV1) {
    switch item {
    case .userMessage: self = .userMessage
    case .assistantMessage: self = .assistantMessage
    case .reasoning: self = .reasoning
    case .shell: self = .shell
    case .diff: self = .diff
    case .plan: self = .plan
    case .imageReference: self = .imageReference
    case .toolCall: self = .toolCall
    case .raw: self = .raw
    }
  }
}

extension RuntimeAgentItemV1 {
  fileprivate var agentDeckItem: AgentItem {
    switch self {
    case .userMessage(let text, let meta):
      return .userMessage(text: text, meta: meta.agentDeckMeta)
    case .assistantMessage(let text, let meta):
      return .assistantMessage(text: text, meta: meta.agentDeckMeta)
    case .reasoning(let text, let meta):
      return .reasoning(text: text, meta: meta.agentDeckMeta)
    case .shell(let command, let status, let exitCode, let durationMs, let meta):
      return .shell(
        command: command,
        status: status,
        exitCode: exitCode.map(Int.init),
        durationMs: durationMs,
        meta: meta.agentDeckMeta
      )
    case .diff(let files, let meta):
      return .diff(
        files: files.map { file in
          DiffFile(path: file.path, status: file.status, patch: file.patch)
        },
        meta: meta.agentDeckMeta
      )
    case .plan(let steps, let meta):
      return .plan(
        steps: steps.map { step in
          PlanStep(title: step.title, status: step.status, detail: step.detail)
        },
        meta: meta.agentDeckMeta
      )
    case .imageReference(let savedPath, let originalPath, let meta):
      return .imageReference(
        savedPath: savedPath,
        originalPath: originalPath,
        meta: meta.agentDeckMeta
      )
    case .toolCall(let name, let args, let result, let meta):
      return .toolCall(
        name: name,
        args: args,
        result: result,
        meta: meta.agentDeckMeta
      )
    case .raw(let rawKind, let rawPayload, let meta):
      return .raw(
        rawKind: rawKind,
        rawPayload: rawPayload,
        meta: meta.agentDeckMeta
      )
    }
  }
}

extension RuntimeAgentItemMetaV1 {
  fileprivate var agentDeckMeta: AgentItemMeta {
    AgentItemMeta(vendorExtensions: vendorExtensions)
  }
}
