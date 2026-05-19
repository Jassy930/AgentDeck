import SwiftUI

// AgentDeck — Step 4: the SwiftUI app. Beat 1 (the only user-perceivable
// wow in v0.1) lives in SessionView, built to the locked D3-D9 design specs.
//
// A headless self-check mode is retained for CI: `AgentDeck --selfcheck`
// runs the Step 1 IPC round trip + A1 lifecycle assertion without a
// windowing session, so the IPC/lifecycle contract stays CI-testable.

if CommandLine.arguments.contains("--selfcheck") {
    let client = DaemonClient()
    do {
        try client.start()
        let pong = try client.roundTrip(IpcMessage(kind: "ping", id: 1, payload: nil))
        guard pong.kind == "pong", pong.id == 1 else {
            FileHandle.standardError.write(Data("selfcheck: unexpected reply\n".utf8))
            client.shutdown()
            exit(1)
        }
        client.shutdown()
        print("selfcheck OK: IPC round trip + A1 lifecycle clean.")
        exit(0)
    } catch {
        FileHandle.standardError.write(Data("selfcheck FATAL: \(error)\n".utf8))
        client.shutdown()
        exit(1)
    }
}

struct AgentDeckApp: App {
    var body: some Scene {
        WindowGroup("AgentDeck") {     // D3: title bar reads "AgentDeck"
            SessionView()
        }
        .windowResizability(.contentSize)
    }
}

AgentDeckApp.main()
