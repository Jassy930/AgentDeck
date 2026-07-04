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

func runDaemonOneShot(args daemonArgs: [String]) -> Int32 {
    guard let path = DaemonClient.locateDaemon() else {
        FileHandle.standardError.write(Data("AgentDeck FATAL: agentdeckd not found at target/{debug,release}/agentdeckd or PATH\n".utf8))
        return 1
    }
    let process = Process()
    let stdout = Pipe()
    let stderr = Pipe()
    process.executableURL = URL(fileURLWithPath: path)
    process.arguments = daemonArgs
    process.standardOutput = stdout
    process.standardError = stderr
    do {
        try process.run()
    } catch {
        FileHandle.standardError.write(Data("AgentDeck FATAL: failed to spawn agentdeckd: \(error)\n".utf8))
        return 1
    }
    process.waitUntilExit()
    let out = stdout.fileHandleForReading.readDataToEndOfFile()
    let err = stderr.fileHandleForReading.readDataToEndOfFile()
    if !out.isEmpty {
        FileHandle.standardOutput.write(out)
    }
    if !err.isEmpty {
        FileHandle.standardError.write(err)
    }
    return process.terminationStatus
}

let launchProfile: AgentDeckProfile
do {
    launchProfile = try AgentDeckProfile.parse(defaultProfile: .defaultForCurrentBuild)
} catch {
    FileHandle.standardError.write(Data("AgentDeck FATAL: \(error)\n".utf8))
    exit(1)
}

if CommandLine.arguments.contains("--selfcheck") {
    let client = DaemonClient(profile: launchProfile)
    do {
        try client.start()
        try client.ping()
        let reply = try client.selfcheck()
        let ok = reply["ok"] as? Bool ?? false
        guard ok else {
            FileHandle.standardError.write(Data("selfcheck FATAL: daemon reported failure: \(reply)\n".utf8))
            client.shutdown()
            exit(1)
        }
        client.shutdown()
        print("selfcheck OK: v2 ping + selfcheck clean.")
        exit(0)
    } catch {
        FileHandle.standardError.write(Data("selfcheck FATAL: \(error)\n".utf8))
        client.shutdown()
        exit(1)
    }
}

if CommandLine.arguments.contains("--diagnostics-report") {
    var args = ["--diagnostics-report", "--profile", launchProfile.rawValue]
    if let dataDir = argumentValue(after: "--data-dir") {
        args += ["--data-dir", dataDir]
    }
    exit(runDaemonOneShot(args: args))
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

let previewMode = CommandLine.arguments.contains("--preview")
if previewMode {
    FileHandle.standardError.write(Data("[AgentDeck] preview mode: mock daemon\n".utf8))
}
let app = NSApplication.shared
let delegate = AppDelegate(profile: launchProfile, preview: previewMode)
app.delegate = delegate
app.run()
