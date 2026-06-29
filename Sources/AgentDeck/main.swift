import AppKit

enum AgentDeckProfile: String, Equatable {
    case stable
    case dev

    static var defaultForCurrentBuild: AgentDeckProfile {
        #if DEBUG
        .dev
        #else
        .stable
        #endif
    }

    var windowTitle: String {
        switch self {
        case .stable:
            "AgentDeck"
        case .dev:
            "AgentDeck Dev"
        }
    }

    static func parse(
        arguments: [String] = CommandLine.arguments,
        defaultProfile: AgentDeckProfile = .stable
    ) throws -> AgentDeckProfile {
        guard let raw = argumentValue(after: "--profile", in: arguments) else {
            return defaultProfile
        }
        guard let profile = AgentDeckProfile(rawValue: raw) else {
            throw AgentDeckProfileError.unsupported(raw)
        }
        return profile
    }
}

enum AgentDeckProfileError: Error, Equatable, CustomStringConvertible {
    case unsupported(String)

    var description: String {
        switch self {
        case .unsupported(let value):
            return "unsupported --profile '\(value)'; expected stable or dev"
        }
    }
}

// AgentDeck — AppKit bootstrapping. The app is a pure AppKit build: the
// AppDelegate installs an NSWindow whose content is driven by
// SessionViewController (status bar + history sidebar + conversation pane +
// input bar), all to the locked D3-D9 design specs.
//
// A headless self-check mode is retained for CI: `AgentDeck --selfcheck`
// runs the Step 1 IPC round trip + A1 lifecycle assertion without a
// windowing session, so the IPC/lifecycle contract stays CI-testable.

func argumentValue(after flag: String, in args: [String] = CommandLine.arguments) -> String? {
    guard let idx = args.firstIndex(of: flag), args.indices.contains(idx + 1) else {
        return nil
    }
    return args[idx + 1]
}

let launchProfile: AgentDeckProfile
do {
    launchProfile = try AgentDeckProfile.parse(defaultProfile: .defaultForCurrentBuild)
} catch {
    FileHandle.standardError.write(Data("AgentDeck FATAL: \(error)\n".utf8))
    exit(1)
}

if CommandLine.arguments.contains("--diagnostics-report") {
    guard CommandLine.arguments.contains("--json") else {
        FileHandle.standardError.write(Data("diagnostics-report FATAL: --json is required\n".utf8))
        exit(1)
    }

    let client = DaemonClient(profile: launchProfile)
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
    let client = DaemonClient(profile: launchProfile)
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
// bundle, so macOS treats it as a background tool by default — the window
// never shows (no Info.plist declaring it a GUI app). The AppDelegate forces
// the regular activation policy and brings the app to the front so the window
// appears even when launched from a terminal. (A real `.app` bundle with
// Info.plist is the README distribution path; this makes the dev build
// runnable too.)
enum AgentDeckQuitCommand {
    static let title = "Quit AgentDeck"
    static let shortcutKey = "q"
}

let app = NSApplication.shared
let delegate = AppDelegate(profile: launchProfile)
app.delegate = delegate
app.run()
