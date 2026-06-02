import Foundation

// A2: Pure decision core for the conversation rail's wheel-step navigation.
// `SessionView.scrollConversationRailStep` previously interleaved this logic
// with SwiftUI imperatives (`proxy.scrollTo`, `withAnimation`). By lifting the
// decision into a namespaced enum that returns a value-typed `Outcome`, the
// behavior can be exhaustively unit-tested without a view hierarchy, while the
// view shrinks to a thin adapter that translates `Outcome` → scroll calls.
//
// The navigator wraps two layers:
//   1. The empty-items short-circuit (always reset to the latest anchor).
//   2. `TurnJumpRailLayout.stepTarget` index-level math, re-keyed to the
//      turn-id strings the SwiftUI proxy actually consumes.
//
// `direction` follows the same sign convention as `stepTarget`: positive ==
// forward (newer turns), negative == backward (older turns), zero is a no-op.

enum ConversationRailNavigator {
    /// What the view should do after a wheel step. All cases are decisions
    /// about scroll/selection state — none of them touch SwiftUI directly.
    enum Outcome: Equatable {
        /// Clear the current selection and scroll to the latest anchor.
        case scrollToLatest
        /// Select the given turn id and scroll to it.
        case scrollToTurn(String)
        /// No change.
        case none
    }

    /// Compute the next outcome for a wheel-step on the conversation rail.
    ///
    /// - Parameters:
    ///   - currentSelected: The turn id currently selected (nil == "latest").
    ///   - items: Visible navigation items in display order.
    ///   - direction: Sign indicates direction (>0 forward, <0 backward, 0 no-op).
    static func next(
        currentSelected: String?,
        items: [ConversationTurnNavigationItem],
        direction: Int
    ) -> Outcome {
        // Empty rail: snapping to latest is the only sensible action and also
        // clears any stale selection that no longer corresponds to a turn.
        guard !items.isEmpty else {
            return .scrollToLatest
        }

        let currentIndex = currentSelected.flatMap { selected in
            items.firstIndex { $0.turnId == selected }
        }

        switch TurnJumpRailLayout.stepTarget(
            selectedIndex: currentIndex,
            direction: direction,
            count: items.count
        ) {
        case .latest:
            return .scrollToLatest
        case .turn(let nextIndex):
            return .scrollToTurn(items[nextIndex].turnId)
        case nil:
            return .none
        }
    }
}
