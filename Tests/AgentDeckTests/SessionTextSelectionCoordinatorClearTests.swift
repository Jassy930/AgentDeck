import XCTest
@testable import AgentDeck

/// Tests for `SessionTextSelectionCoordinator.clearActiveSelection()`.
///
/// Invariants under test:
/// 1. After `clearActiveSelection()`, the registered owner's `clearSelection`
///    was called (flag is set).
/// 2. After `clearActiveSelection()`, `activeOwner` is nil — proved by
///    activating a NEW owner which must NOT trigger the old owner's clear
///    again.
@MainActor
final class SessionTextSelectionCoordinatorClearTests: XCTestCase {

    func testClearActiveSelectionCallsClearOnActiveOwner() {
        let coordinator = SessionTextSelectionCoordinator()

        var cleared = false
        let owner = SessionTextSelectionOwner { cleared = true }
        coordinator.activate(owner)

        coordinator.clearActiveSelection()

        XCTAssertTrue(cleared, "clearActiveSelection() must call clearSelection() on the active owner")
    }

    func testClearActiveSelectionNilsActiveOwner() {
        let coordinator = SessionTextSelectionCoordinator()

        var oldOwnerClearCount = 0
        let oldOwner = SessionTextSelectionOwner { oldOwnerClearCount += 1 }
        coordinator.activate(oldOwner)

        // First clear — expected: oldOwner.clearSelection() called once.
        coordinator.clearActiveSelection()
        XCTAssertEqual(oldOwnerClearCount, 1)

        // Activating a NEW owner after clearActiveSelection must NOT call
        // oldOwner.clearSelection() again — the old owner was already deregistered.
        var newOwnerCleared = false
        let newOwner = SessionTextSelectionOwner { newOwnerCleared = true }
        coordinator.activate(newOwner)

        XCTAssertEqual(
            oldOwnerClearCount, 1,
            "Old owner's clearSelection must NOT be called again after clearActiveSelection() reset activeOwner"
        )
        _ = newOwnerCleared  // suppress unused-variable warning; value irrelevant here
    }

    func testClearActiveSelectionOnNilOwnerIsNoop() {
        // No owner registered — must not crash.
        let coordinator = SessionTextSelectionCoordinator()
        XCTAssertNoThrow(coordinator.clearActiveSelection())
    }
}
