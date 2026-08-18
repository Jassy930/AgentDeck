import Foundation
import AgentDeckMobileCore

struct MachineSummary: Identifiable, Equatable {
    let id: String
    let name: String
    let isOnline: Bool
    let lastHeartbeat: Date?
    let activeSessionCount: Int
    let pendingApprovalCount: Int
}

enum SessionGroup: String, Codable {
    case waitingApproval, active, recent
}

struct SessionSummary: Identifiable, Equatable {
    let id: String
    let machineID: String
    let title: String
    let cwd: String
    let agentKind: AgentKind
    var group: SessionGroup
    let streamResource: String?
}

struct InboxItem: Identifiable, Equatable {
    enum Kind: Equatable { case waitingApproval, turnCompleted, failed }
    let id: String
    let sessionID: String
    let machineID: String
    let kind: Kind
    let title: String
}

struct SessionStreamElement: Sendable {
    let itemId: String?
    let event: ServerEvent
}

/// 纯展示文案映射（不是渲染路径路由，N2 不适用）。
func vendorDisplayName(_ kind: AgentKind) -> String {
    switch kind {
    case .codex: "Codex"
    case .claudeCode: "Claude Code"
    }
}
