import Testing
import CoreGraphics
import Foundation
import AgentDeckCore
@testable import AgentDeck

/// Framework-agnostic rendering/geometry assertions that survived the AppKit
/// cutover. The former SwiftUI-view-construction cases (RichMessageView,
/// UserPromptBlock, StaticRichMessageView, CodexTurnSection, TurnJumpRail) and
/// the Textual `StructuredText` smoke test were removed with the SwiftUI layer;
/// markdown rendering is now covered by `MarkdownAttributedStringBuilder` tests.
@Suite("Rich rendering")
struct RichRenderingTests {
    @Test("image generation media selects saved path for preview")
    func imageGenerationMediaSelectsSavedPathForPreview() {
        var item = UIItem(id: "ig1", lifecycle: "completed", kind: "media")
        item.mediaKind = "imageGeneration"
        item.path = "/tmp/intermediate.png"
        item.savedPath = "/tmp/generated.png"

        let presentation = MediaPreviewPresentation(item: item)

        #expect(presentation.previewPath == "/tmp/generated.png")
    }

    @Test("conversation turns keep assistant tool activity under one Codex rail")
    func conversationTurnsKeepAssistantActivityTogether() {
        let turns = makeConversationTurns(from: [
            UIItem(id: "u1", lifecycle: "completed", kind: "user", text: "find docs"),
            UIItem(id: "m1", lifecycle: "completed", kind: "message", text: "I will search."),
            UIItem(id: "w1", lifecycle: "completed", kind: "webSearch"),
            UIItem(id: "m2", lifecycle: "completed", kind: "message", text: "Result."),
            UIItem(id: "u2", lifecycle: "completed", kind: "user", text: "continue"),
            UIItem(id: "m3", lifecycle: "completed", kind: "message", text: "Next."),
        ])

        #expect(turns.count == 2)
        #expect(turns[0].user?.id == "u1")
        #expect(turns[0].assistantItems.map(\.id) == ["m1", "w1", "m2"])
        #expect(turns[1].user?.id == "u2")
        #expect(turns[1].assistantItems.map(\.id) == ["m3"])
    }

    @Test("conversation turn navigation items summarize user turns")
    func conversationTurnNavigationItemsSummarizeUserTurns() {
        let longPrompt = "  first line\n\nsecond line with    extra spaces and enough text to be truncated after the summary limit keeps the rail compact  "
        let turns = makeConversationTurns(from: [
            UIItem(id: "intro", lifecycle: "completed", kind: "message", text: "orphan assistant"),
            {
                var u1 = UIItem(id: "u1", lifecycle: "completed", kind: "user", text: longPrompt)
                u1.attachments = [
                    HistoryReference(kind: "file", text: nil, url: nil, path: "/tmp/a.swift", name: "a.swift"),
                    HistoryReference(kind: "url", text: nil, url: "https://example.com", path: nil, name: nil),
                ]
                return u1
            }(),
            UIItem(id: "m1", lifecycle: "completed", kind: "message", text: "answer"),
            UIItem(id: "u2", lifecycle: "completed", kind: "user", text: "continue"),
        ])

        let items = makeConversationTurnNavigationItems(from: turns, summaryLimit: 40)

        #expect(items.map(\.turnId) == ["u1", "u2"])
        #expect(items.map(\.index) == [1, 2])
        #expect(items[0].summary == "first line second line with extra spa...")
        #expect(items[0].attachmentCount == 2)
        #expect(items[1].summary == "continue")
        #expect(items[1].attachmentCount == 0)
    }

    @Test("turn jump rail hit testing covers full rail positions")
    func turnJumpRailHitTestingCoversFullRailPositions() {
        let height: CGFloat = 200
        let firstY = TurnJumpRailLayout.turnY(index: 0, count: 3, height: height)
        let middleY = TurnJumpRailLayout.turnY(index: 1, count: 3, height: height)
        let latestY = TurnJumpRailLayout.latestY(height: height)

        #expect(TurnJumpRailLayout.hitTarget(at: CGPoint(x: 14, y: firstY), count: 3, height: height) == .turn(0))
        #expect(TurnJumpRailLayout.hitTarget(at: CGPoint(x: 14, y: middleY + 9), count: 3, height: height) == .turn(1))
        #expect(TurnJumpRailLayout.hitTarget(at: CGPoint(x: 14, y: latestY), count: 3, height: height) == .latest)
        #expect(TurnJumpRailLayout.hitTarget(at: CGPoint(x: 14, y: height - 40), count: 3, height: height) == nil)
    }

    @Test("turn jump rail keeps fixed spacing centered when it fits")
    func turnJumpRailKeepsFixedSpacingCenteredWhenItFits() {
        let height: CGFloat = 240
        let firstY = TurnJumpRailLayout.turnY(index: 0, count: 3, height: height, scrollOffset: 0)
        let secondY = TurnJumpRailLayout.turnY(index: 1, count: 3, height: height, scrollOffset: 0)
        let thirdY = TurnJumpRailLayout.turnY(index: 2, count: 3, height: height, scrollOffset: 0)

        #expect(secondY - firstY == TurnJumpRailLayout.turnSpacing)
        #expect(thirdY - secondY == TurnJumpRailLayout.turnSpacing)
        #expect(secondY == height / 2)
    }

    @Test("turn jump rail content scrolls only when fixed spacing overflows")
    func turnJumpRailContentScrollsOnlyWhenFixedSpacingOverflows() {
        let height: CGFloat = 120
        let maxOffset = TurnJumpRailLayout.maxScrollOffset(count: 8, height: height)
        let clamped = TurnJumpRailLayout.clampedScrollOffset(10_000, count: 8, height: height)
        let noOverflow = TurnJumpRailLayout.maxScrollOffset(count: 3, height: 240)

        #expect(maxOffset > 0)
        #expect(clamped == maxOffset)
        #expect(noOverflow == 0)
    }

    @Test("turn jump rail reveals selected dots without consuming wheel steps")
    func turnJumpRailRevealsSelectedDotsWithoutConsumingWheelSteps() {
        let height: CGFloat = 120
        let offset = TurnJumpRailLayout.scrollOffsetToReveal(index: 7, count: 8, height: height, currentOffset: 0)
        let revealedY = TurnJumpRailLayout.turnY(index: 7, count: 8, height: height, scrollOffset: offset)

        #expect(offset == TurnJumpRailLayout.maxScrollOffset(count: 8, height: height))
        #expect(revealedY <= TurnJumpRailLayout.latestY(height: height) - 32)
    }

    @Test("turn jump rail dock magnification pushes neighboring dots away")
    func turnJumpRailDockMagnificationPushesNeighboringDotsAway() {
        let height: CGFloat = 240
        let basePrevious = TurnJumpRailLayout.turnY(index: 0, count: 3, height: height)
        let baseHovered = TurnJumpRailLayout.turnY(index: 1, count: 3, height: height)
        let baseNext = TurnJumpRailLayout.turnY(index: 2, count: 3, height: height)

        let previous = TurnJumpRailLayout.visualTurnY(index: 0, count: 3, height: height, hoveredIndex: 1)
        let hovered = TurnJumpRailLayout.visualTurnY(index: 1, count: 3, height: height, hoveredIndex: 1)
        let next = TurnJumpRailLayout.visualTurnY(index: 2, count: 3, height: height, hoveredIndex: 1)

        #expect(previous < basePrevious)
        #expect(hovered == baseHovered)
        #expect(next > baseNext)
        #expect(next - previous > baseNext - basePrevious)
    }

    @Test("turn jump rail dock magnification expands the whole visible rail")
    func turnJumpRailDockMagnificationExpandsTheWholeVisibleRail() {
        let height: CGFloat = 320
        let count = 7
        let baseFirst = TurnJumpRailLayout.turnY(index: 0, count: count, height: height)
        let baseLast = TurnJumpRailLayout.turnY(index: count - 1, count: count, height: height)
        let visualFirst = TurnJumpRailLayout.visualTurnY(index: 0, count: count, height: height, hoveredIndex: 3)
        let visualLast = TurnJumpRailLayout.visualTurnY(index: count - 1, count: count, height: height, hoveredIndex: 3)

        #expect(visualFirst < baseFirst)
        #expect(visualLast > baseLast)
        #expect(visualLast - visualFirst > baseLast - baseFirst)
    }

    @Test("turn jump rail step target clamps at edges")
    func turnJumpRailStepTargetClampsAtEdges() {
        #expect(TurnJumpRailLayout.stepTarget(selectedIndex: nil, direction: 1, count: 3) == nil)
        #expect(TurnJumpRailLayout.stepTarget(selectedIndex: nil, direction: -1, count: 3) == .turn(2))
        #expect(TurnJumpRailLayout.stepTarget(selectedIndex: 0, direction: -1, count: 3) == .turn(0))
        #expect(TurnJumpRailLayout.stepTarget(selectedIndex: 2, direction: 1, count: 3) == .latest)
        #expect(TurnJumpRailLayout.stepTarget(selectedIndex: 1, direction: 1, count: 3) == .turn(2))
    }
}
