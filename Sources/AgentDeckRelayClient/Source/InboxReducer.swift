import AgentDeckSessionSource
import Foundation

/// Inbox 没有独立 Relay 数据面；只能由已验证 Catalog/Conversation projection 派生。
enum InboxReducer {
  static func derive(
    catalog: CatalogProjection,
    conversations: [ConversationProjection]
  ) -> [InboxItem] {
    let summaries = Dictionary(uniqueKeysWithValues: catalog.summaries.map { ($0.id, $0) })
    var items: [InboxItem] = []

    for conversation in conversations
    where conversation.machineID == catalog.machineID {
      guard let summary = summaries[conversation.conversationID] else { continue }

      for approval in conversation.pendingApprovals {
        items.append(
          InboxItem(
            id: "\(catalog.machineID)/\(conversation.conversationID)/\(approval.approvalID)",
            conversationID: conversation.conversationID,
            machineID: catalog.machineID,
            kind: .waitingApproval,
            title: summary.title
          )
        )
      }
      if let eventID = conversation.failedEventID {
        items.append(
          InboxItem(
            id: "\(catalog.machineID)/\(conversation.conversationID)/failed/\(eventID)",
            conversationID: conversation.conversationID,
            machineID: catalog.machineID,
            kind: .failed,
            title: summary.title
          )
        )
      } else if let eventID = conversation.completedEventID {
        items.append(
          InboxItem(
            id: "\(catalog.machineID)/\(conversation.conversationID)/completed/\(eventID)",
            conversationID: conversation.conversationID,
            machineID: catalog.machineID,
            kind: .turnCompleted,
            title: summary.title
          )
        )
      }
    }

    return items.sorted { lhs, rhs in
      let lhsPriority = priority(lhs.kind)
      let rhsPriority = priority(rhs.kind)
      if lhsPriority != rhsPriority { return lhsPriority < rhsPriority }
      return lhs.id < rhs.id
    }
  }

  private static func priority(_ kind: InboxItem.Kind) -> Int {
    switch kind {
    case .waitingApproval: 0
    case .failed: 1
    case .turnCompleted: 2
    }
  }
}
