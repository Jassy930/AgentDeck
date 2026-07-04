import Foundation

/// preview 模式引导：构造一个由进程内 mock daemon 驱动、前端完全真实的 SessionModel。
enum PreviewBootstrap {
    @MainActor
    static func makeSessionModel() -> SessionModel {
        let client = DaemonClient(profile: .dev, transport: MockDaemonTransport())
        let model = SessionModel(client: client)
        model.environmentInfo = MockDaemonScript.environmentInfo
        return model
    }
}
