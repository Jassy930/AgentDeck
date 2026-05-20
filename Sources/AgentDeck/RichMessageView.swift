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

struct RichMessageView: View {
    let buffer: StreamingTextBuffer
    @State private var state = RichMessageRenderState()

    var body: some View {
        StructuredText(markdown: state.markdown)
            .textual.structuredTextStyle(.gitHub)
            .textual.textSelection(.enabled)
            .onAppear { state.bind(to: buffer) }
            .onDisappear { state.unbind() }
    }
}
