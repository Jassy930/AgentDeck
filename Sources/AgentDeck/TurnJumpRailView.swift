import AppKit
import CoreGraphics

// MARK: - Migrated from SessionView.swift (verbatim logic, visibility changed private → internal)

enum TurnJumpRailHitTarget: Equatable {
    case turn(Int)
    case latest
}

struct TurnJumpRailLayout {
    static let width: CGFloat = 28
    static let centerX: CGFloat = 14
    static let turnSpacing: CGFloat = 18
    private static let topPadding: CGFloat = 14
    private static let latestBottomPadding: CGFloat = 18
    private static let latestGap: CGFloat = 32
    private static let hitRadius: CGFloat = 12

    static func turnY(
        index: Int,
        count: Int,
        height: CGFloat,
        scrollOffset: CGFloat = 0
    ) -> CGFloat {
        firstTurnY(count: count, height: height) + CGFloat(index) * turnSpacing - scrollOffset
    }

    static func visualTurnY(
        index: Int,
        count: Int,
        height: CGFloat,
        scrollOffset: CGFloat = 0,
        hoveredIndex: Int? = nil
    ) -> CGFloat {
        let baseY = turnY(index: index, count: count, height: height, scrollOffset: scrollOffset)
        guard let hoveredIndex else { return baseY }
        let distance = index - hoveredIndex
        guard distance != 0 else { return baseY }
        return baseY + (distance > 0 ? 1 : -1) * cumulativeDockExpansion(stepsFromHover: abs(distance))
    }

    private static func cumulativeDockExpansion(stepsFromHover: Int) -> CGFloat {
        guard stepsFromHover > 0 else { return 0 }
        let perGapExpansion: [CGFloat] = [7, 3, 1.5]
        return (0..<stepsFromHover).reduce(CGFloat(0)) { total, step in
            total + (step < perGapExpansion.count ? perGapExpansion[step] : perGapExpansion.last ?? 0)
        }
    }

    static func firstTurnY(count: Int, height: CGFloat) -> CGFloat {
        guard count > 0 else { return height / 2 }
        let latest = latestY(height: height)
        let availableTop = topPadding
        let availableBottom = max(availableTop, latest - latestGap)
        let contentHeight = CGFloat(max(0, count - 1)) * turnSpacing
        let centeredStart = (height - contentHeight) / 2
        return min(max(centeredStart, availableTop), availableBottom)
    }

    static func latestY(height: CGFloat) -> CGFloat {
        max(topPadding + latestGap, height - latestBottomPadding)
    }

    static func maxScrollOffset(count: Int, height: CGFloat) -> CGFloat {
        guard count > 0 else { return 0 }
        let latest = latestY(height: height)
        let availableBottom = max(topPadding, latest - latestGap)
        let lastYWithoutScroll = turnY(index: count - 1, count: count, height: height, scrollOffset: 0)
        return max(0, lastYWithoutScroll - availableBottom)
    }

    static func clampedScrollOffset(_ offset: CGFloat, count: Int, height: CGFloat) -> CGFloat {
        min(max(0, offset), maxScrollOffset(count: count, height: height))
    }

    static func scrollOffsetToReveal(
        index: Int,
        count: Int,
        height: CGFloat,
        currentOffset: CGFloat
    ) -> CGFloat {
        let currentY = turnY(index: index, count: count, height: height, scrollOffset: currentOffset)
        let visibleTop = topPadding
        let visibleBottom = max(visibleTop, latestY(height: height) - latestGap)
        if currentY < visibleTop {
            return clampedScrollOffset(
                currentOffset - (visibleTop - currentY),
                count: count,
                height: height
            )
        }
        if currentY > visibleBottom {
            return clampedScrollOffset(
                currentOffset + (currentY - visibleBottom),
                count: count,
                height: height
            )
        }
        return clampedScrollOffset(currentOffset, count: count, height: height)
    }

    static func stepTarget(
        selectedIndex: Int?,
        direction: Int,
        count: Int
    ) -> TurnJumpRailHitTarget? {
        guard count > 0 else { return nil }
        if direction > 0 {
            guard let selectedIndex else { return nil }
            if selectedIndex >= count - 1 { return .latest }
            return .turn(selectedIndex + 1)
        }
        if direction < 0 {
            guard let selectedIndex else { return .turn(count - 1) }
            if selectedIndex <= 0 { return .turn(0) }
            return .turn(selectedIndex - 1)
        }
        return nil
    }

    static func hitTarget(
        at point: CGPoint,
        count: Int,
        height: CGFloat,
        scrollOffset: CGFloat = 0
    ) -> TurnJumpRailHitTarget? {
        guard point.x >= 0, point.x <= width else { return nil }
        if abs(point.y - latestY(height: height)) <= hitRadius {
            return .latest
        }

        guard count > 0 else { return nil }
        let hits = (0..<count).map { index in
            (index: index, distance: abs(point.y - turnY(
                index: index,
                count: count,
                height: height,
                scrollOffset: scrollOffset
            )))
        }
        guard let nearest = hits.min(by: { $0.distance < $1.distance }),
              nearest.distance <= hitRadius else {
            return nil
        }
        return .turn(nearest.index)
    }
}

final class RailInteractionNSView: NSView {
    var itemCount: Int
    var railScrollOffset: CGFloat
    var onHoverTarget: (TurnJumpRailHitTarget?) -> Void
    var onClickTarget: (TurnJumpRailHitTarget) -> Void
    var onWheelStep: (Int) -> Void
    private var lastStepAt = Date.distantPast

    init(
        itemCount: Int,
        railScrollOffset: CGFloat,
        onHoverTarget: @escaping (TurnJumpRailHitTarget?) -> Void,
        onClickTarget: @escaping (TurnJumpRailHitTarget) -> Void,
        onWheelStep: @escaping (Int) -> Void
    ) {
        self.itemCount = itemCount
        self.railScrollOffset = railScrollOffset
        self.onHoverTarget = onHoverTarget
        self.onClickTarget = onClickTarget
        self.onWheelStep = onWheelStep
        super.init(frame: .zero)
        wantsLayer = true
        layer?.backgroundColor = NSColor.clear.cgColor
    }

    required init?(coder: NSCoder) { nil }

    override func updateTrackingAreas() {
        super.updateTrackingAreas()
        trackingAreas.forEach(removeTrackingArea)
        addTrackingArea(NSTrackingArea(
            rect: bounds,
            options: [.activeInKeyWindow, .mouseMoved, .mouseEnteredAndExited, .inVisibleRect],
            owner: self,
            userInfo: nil
        ))
    }

    override func mouseMoved(with event: NSEvent) {
        onHoverTarget(hitTarget(for: event))
    }

    override func mouseExited(with event: NSEvent) {
        onHoverTarget(nil)
    }

    override func mouseDown(with event: NSEvent) {
        guard let target = hitTarget(for: event) else { return }
        onClickTarget(target)
    }

    override func scrollWheel(with event: NSEvent) {
        let now = Date()
        guard now.timeIntervalSince(lastStepAt) >= 0.12 else { return }
        let delta = event.scrollingDeltaY
        guard abs(delta) >= 0.1 else { return }
        lastStepAt = now
        onWheelStep(delta < 0 ? 1 : -1)
    }

    private func hitTarget(for event: NSEvent) -> TurnJumpRailHitTarget? {
        let local = convert(event.locationInWindow, from: nil)
        let topOriginPoint = CGPoint(x: local.x, y: bounds.height - local.y)
        return TurnJumpRailLayout.hitTarget(
            at: topOriginPoint,
            count: itemCount,
            height: bounds.height,
            scrollOffset: railScrollOffset
        )
    }
}

// MARK: - TurnJumpRailView (AppKit, Task 10)

/// AppKit turn-jump rail. Renders dots and the jump-to-latest glyph via
/// `draw(_:)` (CGContext). Dock-magnification and rail scroll are animated by a
/// manual eased timer animation — a self-scheduled `DispatchQueue.main.asyncAfter`
/// step loop that interpolates state and calls `needsDisplay` each frame
/// (replacing SwiftUI `withAnimation`). Each animation chain carries a
/// generation token so starting a new chain (or deinit) invalidates the old one,
/// preventing overlapping/zombie animations. Wheel steps go through
/// `ConversationRailNavigator.next(…)`.
@MainActor
final class TurnJumpRailView: NSView {
    // MARK: Public interface

    /// Fired when the user selects a concrete conversation turn (dot click or
    /// wheel-step that lands on a turn). The argument is always a real
    /// `turnId` — never a sentinel. For "jump to latest", `onJumpToLatest` fires
    /// instead.
    var onSelectTurn: ((String) -> Void)?

    /// Fired when the user jumps to the latest message (latest-anchor click or
    /// wheel-step past the newest turn). Distinct from `onSelectTurn` so callers
    /// never have to interpret an empty-string sentinel.
    var onJumpToLatest: (() -> Void)?

    // MARK: Private state
    private let model: SessionModel
    private var binder: ObservationBinder?
    private var navItems: [ConversationTurnNavigationItem] = []
    private var selectedTurnId: String?
    private var hoveredTarget: TurnJumpRailHitTarget?
    private var railScrollOffset: CGFloat = 0

    /// Bumped whenever a new rail-scroll animation starts. A scheduled scroll
    /// step that finds its captured token no longer current simply returns,
    /// which cancels the stale chain — preventing two scroll chains from fighting
    /// over `railScrollOffset`, and stopping any in-flight scroll on deinit.
    private var scrollGeneration: UInt64 = 0

    /// Same idea, dedicated to the hover redraw burst so a hover never cancels an
    /// in-flight scroll (they animate independent state) and vice versa.
    private var hoverGeneration: UInt64 = 0

    // MARK: Subviews
    private let interactionView: RailInteractionNSView

    init(model: SessionModel) {
        self.model = model
        self.interactionView = RailInteractionNSView(
            itemCount: 0,
            railScrollOffset: 0,
            onHoverTarget: { _ in },
            onClickTarget: { _ in },
            onWheelStep: { _ in }
        )
        super.init(frame: .zero)
        setupLayers()
        setupInteraction()
        setupObservation()
    }

    required init?(coder: NSCoder) { nil }

    /// Update highlighted (top-visible) turn without triggering a full model read.
    func syncSelection(topVisibleTurnId: String?) {
        guard selectedTurnId != topVisibleTurnId else { return }
        selectedTurnId = topVisibleTurnId
        needsDisplay = true
        revealSelectedTurnAnimated()
    }

    // MARK: Layout

    override func layout() {
        super.layout()
        interactionView.frame = bounds
        interactionView.itemCount = navItems.count
        interactionView.railScrollOffset = railScrollOffset
        needsDisplay = true
    }

    override var isFlipped: Bool { true }

    // MARK: Drawing

    override func draw(_ dirtyRect: NSRect) {
        guard let context = NSGraphicsContext.current?.cgContext else { return }
        let height = bounds.height
        let count = navItems.count

        // Draw turn dots
        for (index, item) in navItems.enumerated() {
            let y = TurnJumpRailLayout.visualTurnY(
                index: index,
                count: count,
                height: height,
                scrollOffset: railScrollOffset,
                hoveredIndex: hoveredTurnIndex
            )
            let isSelected = item.turnId == selectedTurnId
            let size = dotSize(for: index)

            let color: NSColor
            if isSelected {
                color = .controlAccentColor
            } else {
                color = .tertiaryLabelColor
            }
            context.setFillColor(color.cgColor)

            let rect = CGRect(
                x: TurnJumpRailLayout.centerX - size / 2,
                y: y - size / 2,
                width: size,
                height: size
            )
            let path = CGPath(ellipseIn: rect, transform: nil)
            context.addPath(path)
            context.fillPath()
        }

        // Draw "jump to latest" arrow at bottom
        let latestY = TurnJumpRailLayout.latestY(height: height)
        let latestColor: NSColor = selectedTurnId == nil ? .controlAccentColor : .secondaryLabelColor
        let latestSize = latestIconSize()

        // Draw a downward-pointing chevron glyph as a simple filled triangle
        let arrowWidth: CGFloat = latestSize * 0.7
        let arrowHeight: CGFloat = latestSize * 0.5
        let ax = TurnJumpRailLayout.centerX
        context.setFillColor(latestColor.cgColor)
        context.move(to: CGPoint(x: ax - arrowWidth / 2, y: latestY - arrowHeight / 2))
        context.addLine(to: CGPoint(x: ax + arrowWidth / 2, y: latestY - arrowHeight / 2))
        context.addLine(to: CGPoint(x: ax, y: latestY + arrowHeight / 2))
        context.closePath()
        context.fillPath()
    }

    // MARK: Private helpers

    private func dotSize(for index: Int) -> CGFloat {
        let selectedSize: CGFloat = navItems[index].turnId == selectedTurnId ? 8 : 6
        guard case .turn(let hoveredIndex) = hoveredTarget else { return selectedSize }
        if hoveredIndex == index { return 15 }
        if abs(hoveredIndex - index) == 1 { return 10 }
        return selectedSize
    }

    private func latestIconSize() -> CGFloat {
        hoveredTarget == .latest ? 14 : 10
    }

    private var hoveredTurnIndex: Int? {
        guard case .turn(let index) = hoveredTarget else { return nil }
        return index
    }

    private func setupLayers() {
        wantsLayer = true
        layer?.backgroundColor = NSColor.clear.cgColor
    }

    private func setupInteraction() {
        addSubview(interactionView)

        interactionView.onHoverTarget = { [weak self] target in
            guard let self else { return }
            self.hoveredTarget = target
            self.animateHoverChange()
            self.needsDisplay = true
        }

        interactionView.onClickTarget = { [weak self] target in
            guard let self else { return }
            switch target {
            case .turn(let index):
                guard self.navItems.indices.contains(index) else { return }
                self.onSelectTurn?(self.navItems[index].turnId)
            case .latest:
                self.selectedTurnId = nil
                self.onJumpToLatest?()
                self.needsDisplay = true
            }
        }

        interactionView.onWheelStep = { [weak self] direction in
            guard let self else { return }
            let outcome = ConversationRailNavigator.next(
                currentSelected: self.selectedTurnId,
                items: self.navItems,
                direction: direction
            )
            switch outcome {
            case .scrollToLatest:
                self.selectedTurnId = nil
                self.onJumpToLatest?()
                self.needsDisplay = true
            case .scrollToTurn(let turnId):
                self.selectedTurnId = turnId
                self.onSelectTurn?(turnId)
                self.revealSelectedTurnAnimated()
                self.needsDisplay = true
            case .none:
                break
            }
        }
    }

    private func setupObservation() {
        let binder = ObservationBinder()
        self.binder = binder
        binder.bind { [weak self] in
            guard let self else { return }
            _ = self.model.selectedItems
        } onChange: { [weak self] in
            self?.reloadNavItems()
        }
    }

    private func reloadNavItems() {
        let turns = makeConversationTurns(from: model.selectedItems)
        navItems = makeConversationTurnNavigationItems(from: turns)
        interactionView.itemCount = navItems.count
        needsDisplay = true
        revealSelectedTurnAnimated()
    }

    private func revealSelectedTurnAnimated() {
        guard let selectedIndex = selectedTurnId.flatMap({ id in
            navItems.firstIndex { $0.turnId == id }
        }) else {
            let clamped = TurnJumpRailLayout.clampedScrollOffset(
                railScrollOffset,
                count: navItems.count,
                height: bounds.height
            )
            if clamped != railScrollOffset {
                animateScrollOffset(to: clamped)
            }
            return
        }

        let newOffset = TurnJumpRailLayout.scrollOffsetToReveal(
            index: selectedIndex,
            count: navItems.count,
            height: bounds.height,
            currentOffset: railScrollOffset
        )
        if newOffset != railScrollOffset {
            animateScrollOffset(to: newOffset)
        }
    }

    /// Animate `railScrollOffset` toward `target` with a manual eased timer
    /// animation (self-scheduled `asyncAfter` step loop, not Core Animation).
    /// Bumps `scrollGeneration` so any in-flight chain is cancelled before a
    /// new one starts. Sub-pixel deltas snap immediately.
    private func animateScrollOffset(to target: CGFloat) {
        let start = railScrollOffset
        let delta = target - start

        // Starting (or short-circuiting) a new animation invalidates the
        // previous chain: stale steps will see a mismatched token and bail.
        scrollGeneration &+= 1

        guard abs(delta) > 0.5 else {
            railScrollOffset = target
            interactionView.railScrollOffset = railScrollOffset
            needsDisplay = true
            return
        }
        animateScroll(from: start, to: target, step: 0, totalSteps: 6, generation: scrollGeneration)
    }

    /// One frame of the manual eased scroll animation. Re-schedules the next
    /// frame via `asyncAfter` unless its `generation` token is stale (a newer
    /// scroll started, or the view was torn down) — that check is what makes
    /// the chain cancellable and non-overlapping.
    private func animateScroll(from start: CGFloat, to end: CGFloat, step: Int, totalSteps: Int, generation: UInt64) {
        guard generation == scrollGeneration else { return }

        let progress = CGFloat(step + 1) / CGFloat(totalSteps)
        // Ease-in-out curve
        let eased = progress < 0.5
            ? 2 * progress * progress
            : -1 + (4 - 2 * progress) * progress
        railScrollOffset = start + (end - start) * eased
        interactionView.railScrollOffset = railScrollOffset
        needsDisplay = true

        guard step + 1 < totalSteps else { return }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.02) { [weak self] in
            self?.animateScroll(from: start, to: end, step: step + 1, totalSteps: totalSteps, generation: generation)
        }
    }

    /// Briefly nudge the rail to redraw so dot dock-magnification animates in.
    /// Carries its own generation token so a newer hover (or deinit) cancels the
    /// redraw burst, while leaving any in-flight scroll untouched.
    private func animateHoverChange() {
        hoverGeneration &+= 1
        let generation = hoverGeneration
        let steps = 4
        for i in 0..<steps {
            DispatchQueue.main.asyncAfter(deadline: .now() + Double(i) * 0.03) { [weak self] in
                guard let self, generation == self.hoverGeneration else { return }
                self.needsDisplay = true
            }
        }
    }

    deinit {
        // Bump both generations so any scheduled animation step bails on its next
        // tick (it captured the now-stale value), stopping in-flight chains.
        scrollGeneration &+= 1
        hoverGeneration &+= 1
        // binder is @MainActor; invalidate may be reached off-main on deinit, so
        // hop onto the actor. invalidate() only flips a Bool — cheap and safe.
        let b = binder
        Task { @MainActor in b?.invalidate() }
    }
}
