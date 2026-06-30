import XCTest
import AppKit
@testable import AgentDeck

/// Tests for `ConversationViewController.shouldClearSelection(forHitView:inTranscript:)`.
///
/// This pure function encapsulates the decision of whether a left-mouse-down
/// event in the conversation transcript should clear the active text selection.
///
/// Rules:
/// - Returns false when `inTranscript` is false (click outside scroll view).
/// - Returns false when the hit view is a `CoordinatedStreamingTextView`.
/// - Returns false when the hit view is a DESCENDANT of a `CoordinatedStreamingTextView`.
/// - Returns true when the hit view is an ordinary NSView inside the transcript.
/// - Returns true when `hitView` is nil but `inTranscript` is true (click on empty background).
@MainActor
final class ConversationEmptySpaceClearTests: XCTestCase {

    // MARK: CoordinatedStreamingTextView hit → false

    func testHitOnStreamingTextViewReturnsFalse() {
        let textView = CoordinatedStreamingTextView(frame: .zero)
        let result = ConversationViewController.shouldClearSelection(
            forHitView: textView,
            inTranscript: true
        )
        XCTAssertFalse(result, "Clicking directly on CoordinatedStreamingTextView must NOT clear selection")
    }

    // MARK: Descendant of CoordinatedStreamingTextView → false

    func testHitOnDescendantOfStreamingTextViewReturnsFalse() {
        let textView = CoordinatedStreamingTextView(frame: .zero)
        let descendant = NSView()
        textView.addSubview(descendant)

        let result = ConversationViewController.shouldClearSelection(
            forHitView: descendant,
            inTranscript: true
        )
        XCTAssertFalse(result, "Clicking a descendant of CoordinatedStreamingTextView must NOT clear selection")
    }

    func testHitOnDeepDescendantOfStreamingTextViewReturnsFalse() {
        let textView = CoordinatedStreamingTextView(frame: .zero)
        let child = NSView()
        let grandchild = NSView()
        textView.addSubview(child)
        child.addSubview(grandchild)

        let result = ConversationViewController.shouldClearSelection(
            forHitView: grandchild,
            inTranscript: true
        )
        XCTAssertFalse(result, "Clicking a deep descendant of CoordinatedStreamingTextView must NOT clear selection")
    }

    // MARK: Plain NSView inside transcript → true

    func testHitOnPlainViewInsideTranscriptReturnsTrue() {
        let plainView = NSView()
        let result = ConversationViewController.shouldClearSelection(
            forHitView: plainView,
            inTranscript: true
        )
        XCTAssertTrue(result, "Clicking empty/non-text space in the transcript MUST clear selection")
    }

    func testNilHitViewInsideTranscriptReturnsTrue() {
        // Clicking on the raw background (no hit view) should still clear.
        let result = ConversationViewController.shouldClearSelection(
            forHitView: nil,
            inTranscript: true
        )
        XCTAssertTrue(result, "Nil hit view inside transcript MUST clear selection")
    }

    // MARK: Outside transcript → false regardless of hit view

    func testHitOnPlainViewOutsideTranscriptReturnsFalse() {
        let plainView = NSView()
        let result = ConversationViewController.shouldClearSelection(
            forHitView: plainView,
            inTranscript: false
        )
        XCTAssertFalse(result, "Click outside transcript must NOT clear selection")
    }

    func testHitOnStreamingTextViewOutsideTranscriptReturnsFalse() {
        let textView = CoordinatedStreamingTextView(frame: .zero)
        let result = ConversationViewController.shouldClearSelection(
            forHitView: textView,
            inTranscript: false
        )
        XCTAssertFalse(result, "Click on streaming text view outside transcript must NOT clear selection")
    }

    func testNilHitViewOutsideTranscriptReturnsFalse() {
        let result = ConversationViewController.shouldClearSelection(
            forHitView: nil,
            inTranscript: false
        )
        XCTAssertFalse(result, "Nil hit view outside transcript must NOT clear selection")
    }
}
