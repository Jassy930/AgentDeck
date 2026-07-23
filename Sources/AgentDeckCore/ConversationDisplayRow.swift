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
public struct ConversationDisplayRow: Identifiable {

    public enum Role: Equatable {
        case userPrompt
        case assistantItem
    }

    public let role: Role
    public let turnId: String
    public let item: UIItem
    /// Present only for the macOS opt-in collapsed execution summary. `item`
    /// remains the first real activity item, so no synthetic `UIItem.kind`
    /// leaks into the shared agent model or iOS renderer.
    public let toolActivityGroup: ConversationToolActivityGroup?
    public let firstInTurn: Bool
    public let lastInTurn: Bool

    public var presentationKind: String {
        if toolActivityGroup != nil { return "toolActivityGroup" }
        if item.activityKind.caseInsensitiveCompare("contextMaintenance") == .orderedSame {
            return "contextCompaction"
        }
        return item.kind
    }

    /// Globally unique within the flattened list.
    /// Uses turnId + item.id + role to guarantee uniqueness even if the same
    /// UIItem somehow appears in two roles (which the model prevents, but
    /// defensive uniqueness costs nothing).
    public var id: String {
        let presentationId = toolActivityGroup?.disclosureId ?? item.id
        return "\(turnId)#\(presentationId)#\(role)"
    }

    public init(
        role: Role,
        turnId: String,
        item: UIItem,
        toolActivityGroup: ConversationToolActivityGroup? = nil,
        firstInTurn: Bool,
        lastInTurn: Bool
    ) {
        self.role = role
        self.turnId = turnId
        self.item = item
        self.toolActivityGroup = toolActivityGroup
        self.firstInTurn = firstInTurn
        self.lastInTurn = lastInTurn
    }
}

public struct ConversationToolActivityGroup {
    public let disclosureId: String
    /// All original items in display order, including reasoning records that
    /// occur between activity items. Expanding the group restores this array.
    public let members: [UIItem]

    public var activityItems: [UIItem] {
        members.filter(ToolActivityGroupPresentation.isGroupable)
    }

    public init(disclosureId: String, members: [UIItem]) {
        self.disclosureId = disclosureId
        self.members = members
    }
}

public enum ConversationToolGroupingPolicy {
    case none
    case consecutiveActivity
}

// MARK: - Reload decision

/// The structural relationship between a previously displayed row sequence and a
/// freshly rebuilt one, used by `ConversationViewController` to pick the cheapest
/// correct table-view update.
public enum ConversationRowsDiff: Equatable {
    /// The `row.id` sequence is identical — the only thing that can have changed
    /// is streaming text growth inside existing rows. No cell needs to be
    /// reconfigured (each cell already streams its own buffer); the table only
    /// needs row-height re-measurement. Carries the offsets whose content
    /// version changed so the controller can `noteHeightOfRows` precisely.
    case sameRows(changedIndexes: [Int])
    /// The id sequence differs (append / remove / reorder). The controller falls
    /// back to a full `reloadData()` for correctness; disclosure state (C1) is
    /// restored from the persisted set and selection (C2) is protected by the
    /// unchanged-guards, so a reload no longer destroys user state.
    case structural

    /// Decide how the table should update from `previous` to `next`.
    ///
    /// Pure function of the two id/version sequences so it is unit-testable
    /// without any AppKit view. When the id sequence matches, only rows whose
    /// content `version` changed are reported as needing height re-measurement.
    public static func decide<Version: Equatable>(
        previous: [(id: String, version: Version)],
        next: [(id: String, version: Version)]
    ) -> ConversationRowsDiff {
        guard previous.count == next.count else { return .structural }
        var changed: [Int] = []
        for index in next.indices {
            if previous[index].id != next[index].id {
                return .structural
            }
            if previous[index].version != next[index].version {
                changed.append(index)
            }
        }
        return .sameRows(changedIndexes: changed)
    }
}

// MARK: - Builder

public enum ConversationDisplayRowBuilder {

    /// Flatten `[ConversationTurn]` into a virtualizable sequence of rows.
    ///
    /// Order: user-prompt row (if present) then assistant-item rows, in the
    /// order stored on the turn. `firstInTurn`/`lastInTurn` mark the first and
    /// last row of each turn respectively.
    public static func rows(
        from turns: [ConversationTurn],
        toolGrouping: ConversationToolGroupingPolicy = .none,
        expandedToolGroupIds: Set<String> = []
    ) -> [ConversationDisplayRow] {
        var out: [ConversationDisplayRow] = []
        for turn in turns {
            // Collect presentation entries for this turn. Grouping defaults to
            // off so existing shared/iOS callers retain the one-item-per-row
            // contract; the macOS controller opts in explicitly.
            var entries: [PendingRow] = []
            if let user = turn.user {
                entries.append(PendingRow(role: .userPrompt, item: user, group: nil))
            }
            switch toolGrouping {
            case .none:
                entries.append(contentsOf: turn.assistantItems.map {
                    PendingRow(role: .assistantItem, item: $0, group: nil)
                })
            case .consecutiveActivity:
                entries.append(contentsOf: groupedAssistantRows(
                    turn: turn,
                    expandedToolGroupIds: expandedToolGroupIds
                ))
            }
            guard !entries.isEmpty else { continue }
            let last = entries.count - 1
            for (idx, entry) in entries.enumerated() {
                out.append(ConversationDisplayRow(
                    role: entry.role,
                    turnId: turn.id,
                    item: entry.item,
                    toolActivityGroup: entry.group,
                    firstInTurn: idx == 0,
                    lastInTurn: idx == last
                ))
            }
        }
        return out
    }

    private struct PendingRow {
        let role: ConversationDisplayRow.Role
        let item: UIItem
        let group: ConversationToolActivityGroup?
    }

    private static func groupedAssistantRows(
        turn: ConversationTurn,
        expandedToolGroupIds: Set<String>
    ) -> [PendingRow] {
        let items = turn.assistantItems
        var result: [PendingRow] = []
        var index = 0

        while index < items.count {
            guard let groupingKey = ToolActivityGroupPresentation.groupingKey(for: items[index]) else {
                result.append(PendingRow(role: .assistantItem, item: items[index], group: nil))
                index += 1
                continue
            }

            let start = index
            var cursor = index + 1
            var lastActivity = index
            var activityCount = 1
            while cursor < items.count {
                if ToolActivityGroupPresentation.groupingKey(for: items[cursor]) == groupingKey {
                    lastActivity = cursor
                    activityCount += 1
                    cursor += 1
                } else if items[cursor].kind == "reasoning" {
                    // Reasoning is transparent only between two execution
                    // items. Trailing reasoning is trimmed by `lastActivity`.
                    cursor += 1
                } else {
                    break
                }
            }

            guard activityCount >= 2 else {
                result.append(PendingRow(role: .assistantItem, item: items[index], group: nil))
                index += 1
                continue
            }

            let members = Array(items[start...lastActivity])
            let disclosureId = "tool-group:\(turn.id):\(items[start].id)"
            let group = ConversationToolActivityGroup(
                disclosureId: disclosureId,
                members: members
            )
            result.append(PendingRow(role: .assistantItem, item: items[start], group: group))
            if expandedToolGroupIds.contains(disclosureId) {
                result.append(contentsOf: members.map {
                    PendingRow(role: .assistantItem, item: $0, group: nil)
                })
            }
            index = lastActivity + 1
        }
        return result
    }
}
