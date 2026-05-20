import SwiftUI

struct RuntimeSelectorView: View {
    let workbench: WorkbenchModel

    var body: some View {
        let runtimes = workbench.runtimeList
        if !runtimes.isEmpty {
            VStack(alignment: .leading, spacing: 0) {
                Text("Runtime")
                    .font(.system(.caption, weight: .semibold))
                    .foregroundStyle(.secondary)
                    .padding(.horizontal, 12)
                    .padding(.top, 8)
                    .padding(.bottom, 4)

                ForEach(runtimes) { runtime in
                    runtimeRow(runtime)
                }
            }
        }
    }

    private func runtimeRow(_ runtime: ThreadRuntimeModel) -> some View {
        Button {
            workbench.selectRuntime(sessionId: runtime.id)
        } label: {
            HStack(spacing: 8) {
                Circle()
                    .fill(statusColor(for: runtime.phase))
                    .frame(width: 7, height: 7)
                VStack(alignment: .leading, spacing: 2) {
                    Text(runtime.displayTitle)
                        .font(.system(.callout))
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Text(runtime.statusLabel)
                        .font(.system(.caption))
                        .foregroundStyle(.tertiary)
                        .lineLimit(1)
                }
                Spacer(minLength: 8)
                if runtime.unreadEventCount > 0 {
                    Text(unreadLabel(runtime.unreadEventCount))
                        .font(.system(.caption2, weight: .semibold))
                        .monospacedDigit()
                        .foregroundStyle(.secondary)
                }
            }
            .frame(maxWidth: .infinity, minHeight: 34, alignment: .leading)
            .padding(.horizontal, 12)
            .padding(.vertical, 5)
            .background(
                runtime.id == workbench.selectedSessionId
                    ? Color(nsColor: .selectedContentBackgroundColor).opacity(0.18)
                    : Color.clear
            )
        }
        .buttonStyle(.plain)
    }

    private func unreadLabel(_ count: Int) -> String {
        count > 99 ? "99+" : "\(count)"
    }

    private func statusColor(for phase: SessionModel.Phase) -> Color {
        switch phase {
        case .running, .starting:
            return .accentColor
        case .waitingApproval:
            return .orange
        case .failed:
            return .red
        default:
            return .secondary
        }
    }
}
