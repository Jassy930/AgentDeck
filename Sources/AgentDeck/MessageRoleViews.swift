import SwiftUI

struct UserPromptBlock: View {
    let text: String

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            RoundedRectangle(cornerRadius: 1.5)
                .fill(Color.accentColor.opacity(0.45))
                .frame(width: 3)
            VStack(alignment: .leading, spacing: 5) {
                Text("You")
                    .font(.system(.caption, weight: .semibold))
                    .foregroundStyle(.secondary)
                Text(text)
                    .font(.system(.callout, weight: .medium))
                    .foregroundStyle(.primary)
                    .textSelection(.enabled)
            }
            .frame(maxWidth: 760, alignment: .leading)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
        .background(
            RoundedRectangle(cornerRadius: 7)
                .fill(Color(nsColor: .quaternarySystemFill))
        )
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.vertical, 8)
    }
}

struct CodexTurnSection<Content: View>: View {
    @ViewBuilder var content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Codex")
                .font(.system(.caption, weight: .semibold))
                .foregroundStyle(.primary)
            content
                .frame(maxWidth: 920, alignment: .leading)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.leading, 17)
        .padding(.vertical, 14)
        .overlay(alignment: .leading) {
            RoundedRectangle(cornerRadius: 1.5)
                .fill(Color.accentColor)
                .frame(width: 3)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

struct CodexDocumentSection: View {
    let buffer: StreamingTextBuffer

    var body: some View {
        CodexTurnSection {
            RichMessageView(buffer: buffer)
        }
    }
}
