import Observation
import SwiftUI
import Textual

@MainActor
@Observable
final class RichMessageRenderState {
    private(set) var markdown = ""
    private weak var observedBuffer: StreamingTextBuffer?
    private var observationToken: UUID?

    func replace(_ text: String) {
        markdown = text
    }

    func append(_ suffix: String) {
        markdown.append(contentsOf: suffix)
    }

    func bind(to buffer: StreamingTextBuffer) {
        guard observedBuffer !== buffer else { return }
        unbind()
        observedBuffer = buffer
        observationToken = buffer.observe { [weak self] change in
            Task { @MainActor in
                switch change {
                case .append(let suffix):
                    self?.append(suffix)
                case .replace(let text):
                    self?.replace(text)
                }
            }
        }
    }

    func unbind() {
        if let observationToken {
            observedBuffer?.removeObserver(observationToken)
        }
        observationToken = nil
        observedBuffer = nil
    }
}

@MainActor
@Observable
final class RichMessageSelectionState {
    var resetGeneration = 0
    private(set) var owner: SessionTextSelectionOwner!

    init() {
        owner = SessionTextSelectionOwner { [weak self] in
            self?.resetGeneration += 1
        }
    }
}

struct RichMessageView: View {
    let buffer: StreamingTextBuffer
    @State private var state = RichMessageRenderState()
    @State private var selectionState = RichMessageSelectionState()

    var body: some View {
        StructuredText(markdown: state.markdown)
            .id(selectionState.resetGeneration)
            .textual.structuredTextStyle(.gitHub)
            .textual.textSelection(.enabled)
            .background(SessionTextSelectionActivationMonitor(owner: selectionState.owner))
            .onAppear { state.bind(to: buffer) }
            .onDisappear { state.unbind() }
    }
}
