import SwiftUI

// AgentDeck — Step 4: the SwiftUI app. Beat 1 (the only user-perceivable
// wow in v0.1) lives in SessionView, built to the locked D3-D9 design specs.
//
// A headless self-check mode is retained for CI: `AgentDeck --selfcheck`
// runs the Step 1 IPC round trip + A1 lifecycle assertion without a
// windowing session, so the IPC/lifecycle contract stays CI-testable.

func argumentValue(after flag: String) -> String? {
    let args = CommandLine.arguments
    guard let idx = args.firstIndex(of: flag), args.indices.contains(idx + 1) else {
        return nil
    }
    return args[idx + 1]
}

if CommandLine.arguments.contains("--diagnostics-report") {
    guard CommandLine.arguments.contains("--json") else {
        FileHandle.standardError.write(Data("diagnostics-report FATAL: --json is required\n".utf8))
        exit(1)
    }

    let client = DaemonClient()
    do {
        try client.start()
        let report = try client.diagnosticsReport(
            limit: argumentValue(after: "--limit").flatMap(Int.init) ?? 50,
            sinceSeconds: argumentValue(after: "--since-seconds").flatMap(Int.init) ?? 3600,
            runId: argumentValue(after: "--run-id")
        )
        let data = try JSONSerialization.data(
            withJSONObject: report,
            options: [.prettyPrinted, .sortedKeys]
        )
        client.shutdown()
        FileHandle.standardOutput.write(data)
        FileHandle.standardOutput.write(Data("\n".utf8))
        exit(0)
    } catch {
        FileHandle.standardError.write(Data("diagnostics-report FATAL: \(error)\n".utf8))
        client.shutdown()
        exit(1)
    }
}

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
        let logging = try client.loggingSelfcheck()
        let recordOk = logging["recordOk"] as? Bool ?? false
        let diagnosticOk = logging["diagnosticOk"] as? Bool ?? false
        let redactionOk = logging["redactionOk"] as? Bool ?? false
        guard recordOk, diagnosticOk, redactionOk else {
            let failures = logging["failures"] ?? []
            FileHandle.standardError.write(Data("selfcheck FATAL: logging selfcheck failed: \(failures)\n".utf8))
            client.shutdown()
            exit(1)
        }
        client.shutdown()
        print("selfcheck OK: IPC lifecycle + logging clean.")
        exit(0)
    } catch {
        FileHandle.standardError.write(Data("selfcheck FATAL: \(error)\n".utf8))
        client.shutdown()
        exit(1)
    }
}

// A SwiftPM executable is a plain command-line binary, not a `.app`
// bundle, so macOS treats it as a background tool by default — the
// WindowGroup never shows (no Info.plist declaring it a GUI app). Force
// regular activation policy and bring the app to the front so the window
// appears even when launched from a terminal. (A real `.app` bundle with
// Info.plist is the Step 5 README distribution path; this makes the dev
// build runnable too.)
final class AppActivator: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
    }
}

struct AgentDeckApp: App {
    @NSApplicationDelegateAdaptor(AppActivator.self) var activator

    var body: some Scene {
        WindowGroup("AgentDeck") {     // D3: title bar reads "AgentDeck"
            SessionView()
        }
        .windowResizability(.contentSize)
    }
}

AgentDeckApp.main()
