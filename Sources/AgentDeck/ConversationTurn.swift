import Foundation

struct ConversationTurn: Identifiable {
    let id: String
    var user: UIItem?
    var assistantItems: [UIItem]
}

struct ConversationTurnNavigationItem: Identifiable, Equatable {
    var id: String { turnId }
    let turnId: String
    let index: Int
    let summary: String
    let attachmentCount: Int
}

func makeConversationTurns(from items: [UIItem]) -> [ConversationTurn] {
    var turns: [ConversationTurn] = []
    var currentUser: UIItem?
    var currentAssistantItems: [UIItem] = []

    func flush() {
        guard currentUser != nil || !currentAssistantItems.isEmpty else { return }
        let id = currentUser?.id ?? currentAssistantItems.first?.id ?? UUID().uuidString
        turns.append(ConversationTurn(id: id, user: currentUser, assistantItems: currentAssistantItems))
        currentUser = nil
        currentAssistantItems = []
    }

    for item in items {
        if item.kind == "user" {
            flush()
            currentUser = item
        } else {
            currentAssistantItems.append(item)
        }
    }
    flush()

    return turns
}

func makeConversationTurnNavigationItems(
    from turns: [ConversationTurn],
    summaryLimit: Int = 80
) -> [ConversationTurnNavigationItem] {
    turns.compactMap(\.user).enumerated().map { offset, user in
        ConversationTurnNavigationItem(
            turnId: user.id,
            index: offset + 1,
            summary: conversationTurnSummary(user.text, limit: summaryLimit),
            attachmentCount: user.attachments.count
        )
    }
}

private func conversationTurnSummary(_ text: String, limit: Int) -> String {
    let normalized = text
        .split(whereSeparator: \.isWhitespace)
        .joined(separator: " ")
    guard normalized.count > limit else { return normalized }
    return String(normalized.prefix(max(0, limit - 3))) + "..."
}
