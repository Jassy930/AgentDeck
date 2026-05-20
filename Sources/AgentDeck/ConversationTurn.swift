import Foundation

struct ConversationTurn: Identifiable {
    let id: String
    var user: UIItem?
    var assistantItems: [UIItem]
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
