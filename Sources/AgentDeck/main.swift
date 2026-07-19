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
    FileHandle.standardError.write(
      Data(
        "AgentDeck FATAL: agentdeckd not found at target/{debug,release}/agentdeckd or PATH\n".utf8)
    )
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
    FileHandle.standardError.write(
      Data("AgentDeck FATAL: failed to spawn agentdeckd: \(error)\n".utf8))
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

enum RuntimeTestOnlyArgumentGuard {
  static func shouldReject(arguments: [String]) -> Bool {
    arguments.dropFirst().contains { argument in
      let optionName =
        argument.split(
          separator: "=",
          maxSplits: 1,
          omittingEmptySubsequences: false
        ).first ?? ""
      return optionName.hasPrefix("--runtime-") && optionName.hasSuffix("-for-test")
    }
  }

  static let releaseFailure =
    Data(
      #"{"code":"daemon.client.test_only_argument_rejected","diagnosticRef":null,"message":"test-only Runtime arguments are unavailable in release builds","reply":"failure"}"#
        .utf8
    ) + Data([0x0A])
}

#if DEBUG
  if CommandLine.arguments.contains("--runtime-smoke-for-test") {
    let execution = await RuntimeSmokeRunner().run()
    if !execution.stdout.isEmpty {
      FileHandle.standardOutput.write(execution.stdout)
    }
    if !execution.stderr.isEmpty {
      FileHandle.standardError.write(execution.stderr)
    }
    exit(execution.exitCode)
  }
#else
  if RuntimeTestOnlyArgumentGuard.shouldReject(arguments: CommandLine.arguments) {
    FileHandle.standardError.write(RuntimeTestOnlyArgumentGuard.releaseFailure)
    exit(2)
  }
#endif

// 启动最早期加载 CWD 下的 `.env`（真实环境优先，只填补未设的键）。放在一切读环境变量
// 之前，让 AGENTDECK_* 配置项经 .env 也能生效；daemon 子进程继承本进程环境亦受惠。
let injectedEnvCount = DotEnv.loadDefault()
if injectedEnvCount > 0 {
  FileHandle.standardError.write(
    Data("[AgentDeck] .env: injected \(injectedEnvCount) var(s)\n".utf8))
}

let launchProfile: AgentDeckProfile
do {
  launchProfile = try AgentDeckProfile.parse(defaultProfile: .defaultForCurrentBuild)
} catch {
  FileHandle.standardError.write(Data("AgentDeck FATAL: \(error)\n".utf8))
  exit(1)
}

if CommandLine.arguments.contains("--selfcheck") {
  #if DEBUG
    let selfcheckArguments = CommandLine.arguments
    let runner = RuntimeSelfcheckRunner(wireFactory: {
      if let wire = try RuntimeSmokeEnvironment.selfcheckWire(
        arguments: selfcheckArguments
      ) {
        return wire
      }
      return OSAccountRuntimeWireSession()
    })
  #else
    let runner = RuntimeSelfcheckRunner()
  #endif
  let execution = await runner.run()
  if !execution.stdout.isEmpty {
    FileHandle.standardOutput.write(execution.stdout)
  }
  if !execution.stderr.isEmpty {
    FileHandle.standardError.write(execution.stderr)
  }
  exit(execution.exitCode)
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
let galleryMode = CommandLine.arguments.contains("--gallery")
if previewMode {
  FileHandle.standardError.write(Data("[AgentDeck] preview mode: mock daemon\n".utf8))
}
if galleryMode {
  FileHandle.standardError.write(
    Data("[AgentDeck] gallery mode: design-system component gallery\n".utf8))
}
let app = NSApplication.shared
let delegate = AppDelegate(profile: launchProfile, preview: previewMode, gallery: galleryMode)
app.delegate = delegate
app.run()
