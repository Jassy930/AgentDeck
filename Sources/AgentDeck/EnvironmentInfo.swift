import Foundation

/// 右上环境面板的只读数据模型（macOS UI chrome，不进 AgentDeckCore 共享层）。
/// 真实 app 暂无 daemon 后端提供它（见 2026-07-01-codex-desktop-chrome-sync.md），
/// 默认 nil 时不展示、也不预留 inspector 宽度；preview 在引导层注入 mock 值。
struct EnvironmentInfo: Equatable {
    let added: Int
    let removed: Int
    let fileCount: Int
    let branch: String?
    let commit: String?

    var changesSummary: String { "+\(added) -\(removed)" }
    var fileCountSummary: String { "\(fileCount) 文件" }
}
