import Foundation
import Testing
import AgentDeckCore
@testable import AgentDeck

@Suite("ConversationRailNavigator (A2)")
struct ConversationRailNavigatorTests {
    private func makeItems(_ count: Int) -> [ConversationTurnNavigationItem] {
        (0..<count).map { i in
            ConversationTurnNavigationItem(
                turnId: "turn-\(i)",
                index: i + 1,
                summary: "summary \(i)",
                attachmentCount: 0
            )
        }
    }

    @Test("empty items always returns scrollToLatest regardless of direction or selection")
    func emptyItemsReturnsScrollToLatest() {
        #expect(ConversationRailNavigator.next(currentSelected: nil, items: [], direction: 1) == .scrollToLatest)
        #expect(ConversationRailNavigator.next(currentSelected: nil, items: [], direction: -1) == .scrollToLatest)
        #expect(ConversationRailNavigator.next(currentSelected: "missing", items: [], direction: 0) == .scrollToLatest)
    }

    @Test("forward step from nil selection returns none")
    func forwardFromNilCurrentReturnsNone() {
        // Mirrors TurnJumpRailLayout.stepTarget: direction>0 + selectedIndex=nil → nil.
        let items = makeItems(3)
        #expect(ConversationRailNavigator.next(currentSelected: nil, items: items, direction: 1) == .none)
    }

    @Test("forward step from first item returns scrollToTurn of the next one")
    func forwardFromFirstReturnsNextTurn() {
        let items = makeItems(3)
        #expect(
            ConversationRailNavigator.next(currentSelected: items[0].turnId, items: items, direction: 1)
                == .scrollToTurn(items[1].turnId)
        )
    }

    @Test("forward step from last item returns scrollToLatest")
    func forwardFromLastReturnsScrollToLatest() {
        let items = makeItems(3)
        #expect(
            ConversationRailNavigator.next(currentSelected: items[2].turnId, items: items, direction: 1)
                == .scrollToLatest
        )
    }

    @Test("backward step from nil selection returns scrollToTurn of the last item")
    func backwardFromNilCurrentReturnsLast() {
        let items = makeItems(3)
        #expect(
            ConversationRailNavigator.next(currentSelected: nil, items: items, direction: -1)
                == .scrollToTurn(items[2].turnId)
        )
    }

    @Test("backward step from middle returns scrollToTurn of the previous one")
    func backwardFromMiddleReturnsPrevious() {
        let items = makeItems(3)
        #expect(
            ConversationRailNavigator.next(currentSelected: items[1].turnId, items: items, direction: -1)
                == .scrollToTurn(items[0].turnId)
        )
    }

    @Test("backward step from first item clamps to the first item")
    func backwardFromFirstStaysAtFirst() {
        // Mirrors TurnJumpRailLayout.stepTarget: selectedIndex<=0 + direction<0 → .turn(0).
        let items = makeItems(3)
        #expect(
            ConversationRailNavigator.next(currentSelected: items[0].turnId, items: items, direction: -1)
                == .scrollToTurn(items[0].turnId)
        )
    }

    @Test("zero direction returns none")
    func zeroDirectionReturnsNone() {
        let items = makeItems(3)
        #expect(ConversationRailNavigator.next(currentSelected: items[1].turnId, items: items, direction: 0) == .none)
    }

    @Test("unknown selected id is treated as nil and folds into the direction default")
    func unknownSelectedFoldsToNilSemantics() {
        // turnId not present in items behaves like nil: forward → none, backward → last.
        let items = makeItems(3)
        #expect(ConversationRailNavigator.next(currentSelected: "ghost", items: items, direction: 1) == .none)
        #expect(
            ConversationRailNavigator.next(currentSelected: "ghost", items: items, direction: -1)
                == .scrollToTurn(items[2].turnId)
        )
    }
}
