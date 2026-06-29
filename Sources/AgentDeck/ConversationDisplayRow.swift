import Foundation

/// A single virtualizable row in the conversation transcript.
///
/// Each `ConversationTurn` is flattened into one or more `ConversationDisplayRow`
/// values: the turn's user prompt (if present) followed by each assistant item.
/// `firstInTurn`/`lastInTurn` carry the turn-boundary flags needed for
/// visual grouping without requiring the table to look up neighbours.
///
/// Approval (`pendingActionRequest`) is a separate field on `ThreadRuntimeModel`
/// and is NOT represented here — it is rendered independently by the
/// ConversationViewController (Task 8).
///
/// Error/warning messages (`errorMessage`/`warningMessage`) are also separate
/// model fields, not `UIItem` kinds, so they are likewise excluded from the
/// flattened stream.
struct ConversationDisplayRow: Identifiable {

    enum Role: Equatable {
        case userPrompt
        case assistantItem
    }

    let role: Role
    let turnId: String
    let item: UIItem
    let firstInTurn: Bool
    let lastInTurn: Bool

    /// Globally unique within the flattened list.
    /// Uses turnId + item.id + role to guarantee uniqueness even if the same
    /// UIItem somehow appears in two roles (which the model prevents, but
    /// defensive uniqueness costs nothing).
    var id: String { "\(turnId)#\(item.id)#\(role)" }
}

// MARK: - Builder

enum ConversationDisplayRowBuilder {

    /// Flatten `[ConversationTurn]` into a virtualizable sequence of rows.
    ///
    /// Order: user-prompt row (if present) then assistant-item rows, in the
    /// order stored on the turn. `firstInTurn`/`lastInTurn` mark the first and
    /// last row of each turn respectively.
    static func rows(from turns: [ConversationTurn]) -> [ConversationDisplayRow] {
        var out: [ConversationDisplayRow] = []
        for turn in turns {
            // Collect (role, item) pairs for this turn.
            var pairs: [(ConversationDisplayRow.Role, UIItem)] = []
            if let user = turn.user {
                pairs.append((.userPrompt, user))
            }
            for item in turn.assistantItems {
                pairs.append((.assistantItem, item))
            }
            guard !pairs.isEmpty else { continue }
            let last = pairs.count - 1
            for (idx, pair) in pairs.enumerated() {
                out.append(ConversationDisplayRow(
                    role: pair.0,
                    turnId: turn.id,
                    item: pair.1,
                    firstInTurn: idx == 0,
                    lastInTurn: idx == last
                ))
            }
        }
        return out
    }
}
