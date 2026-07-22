import Foundation
import XCTest
@testable import AgentDeck

final class DaemonLocatorTests: XCTestCase {
    private var tempRoot: URL!

    override func setUpWithError() throws {
        tempRoot = FileManager.default.temporaryDirectory
            .appendingPathComponent("agentdeck-daemon-locator-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(
            at: tempRoot,
            withIntermediateDirectories: true
        )
    }

    override func tearDownWithError() throws {
        if let tempRoot {
            try? FileManager.default.removeItem(at: tempRoot)
        }
        tempRoot = nil
    }

    func testExplicitDaemonPathOverridesBundleSibling() throws {
        let override = try makeExecutable(at: tempRoot.appendingPathComponent("override/agentdeckd"))
        let appExecutable = tempRoot.appendingPathComponent("AgentDeck.app/Contents/MacOS/AgentDeck")
        _ = try makeExecutable(
            at: appExecutable.deletingLastPathComponent().appendingPathComponent("agentdeckd")
        )

        let located = DaemonClient.locateDaemon(
            environment: ["AGENTDECK_DAEMON_PATH": override.path, "PATH": ""],
            executableURL: appExecutable,
            currentDirectoryPath: tempRoot.path
        )

        XCTAssertEqual(located, override.standardizedFileURL.path)
    }

    func testBundleSiblingWorksWhenLaunchServicesCwdIsRoot() throws {
        let appExecutable = tempRoot.appendingPathComponent("AgentDeck.app/Contents/MacOS/AgentDeck")
        let bundled = try makeExecutable(
            at: appExecutable.deletingLastPathComponent().appendingPathComponent("agentdeckd")
        )

        let located = DaemonClient.locateDaemon(
            environment: ["PATH": ""],
            executableURL: appExecutable,
            currentDirectoryPath: "/"
        )

        XCTAssertEqual(located, bundled.standardizedFileURL.path)
    }

    func testDevelopmentTargetFallbackWorksWithoutBundleSibling() throws {
        let developmentDaemon = try makeExecutable(
            at: tempRoot.appendingPathComponent("target/debug/agentdeckd")
        )
        let appExecutable = tempRoot.appendingPathComponent("missing/AgentDeck")

        let located = DaemonClient.locateDaemon(
            environment: ["PATH": ""],
            executableURL: appExecutable,
            currentDirectoryPath: tempRoot.path
        )

        XCTAssertEqual(located, developmentDaemon.standardizedFileURL.path)
    }

    func testDaemonEnvironmentRepairsLaunchServicesPathForBothVendorCLIs() {
        let environment = DaemonClient.daemonEnvironment(
            profile: .dev,
            base: ["HOME": "/Users/example", "PATH": "/custom/bin:/usr/bin"]
        )

        XCTAssertEqual(environment["AGENTDECK_PROFILE"], "dev")
        XCTAssertEqual(
            environment["PATH"],
            "/Users/example/.local/bin:/Users/example/.bun/bin:/opt/homebrew/bin:"
                + "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/custom/bin"
        )
    }

    private func makeExecutable(at url: URL) throws -> URL {
        try FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        XCTAssertTrue(FileManager.default.createFile(atPath: url.path, contents: Data("fixture".utf8)))
        try FileManager.default.setAttributes(
            [.posixPermissions: NSNumber(value: Int16(0o755))],
            ofItemAtPath: url.path
        )
        return url
    }
}

private final class FailingStartTransport: DaemonTransport {
    var isStarted: Bool { false }
    var isAlive: Bool { false }

    func start() throws {
        throw DaemonError.spawnFailed("launch-fixture")
    }

    func send(_ line: String) throws {}
    func setIncomingHandler(_ handler: @escaping (String) -> Void) {}
    func setDisconnectHandler(_ handler: @escaping () -> Void) {}
    func shutdown() {}
}

private final class RetryStartTransport: DaemonTransport {
    private(set) var startAttempts = 0
    private(set) var isStarted = false
    var isAlive: Bool { isStarted }
    private var incomingHandler: ((String) -> Void)?

    func start() throws {
        startAttempts += 1
        if startAttempts == 1 {
            throw DaemonError.spawnFailed("retry-fixture")
        }
        isStarted = true
    }

    func send(_ line: String) throws {
        guard let command = try? JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any],
              let requestId = command["requestId"] as? String else {
            return
        }
        let reply: [String: Any] = [
            "reply": "history",
            "requestId": requestId,
            "response": ["kind": "list", "value": []],
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: reply),
              let line = String(data: data, encoding: .utf8) else {
            return
        }
        incomingHandler?(line)
    }

    func setIncomingHandler(_ handler: @escaping (String) -> Void) {
        incomingHandler = handler
    }

    func setDisconnectHandler(_ handler: @escaping () -> Void) {}
    func shutdown() { isStarted = false }
}

@MainActor
final class HistoryDaemonLaunchTests: XCTestCase {
    func testHistoryLaunchFailureUsesHistoryErrorSurface() {
        let client = DaemonClient(transport: FailingStartTransport())
        let model = SessionModel(client: client)

        model.loadHistory()

        XCTAssertTrue(model.historyThreads.isEmpty)
        XCTAssertEqual(model.historyErrorMessage, "failed to spawn agentdeckd: launch-fixture")
    }

    func testSuccessfulRetryClearsOnlyDaemonLaunchFailureState() async {
        let transport = RetryStartTransport()
        let client = DaemonClient(transport: transport)
        let model = SessionModel(client: client)

        model.loadHistory()
        XCTAssertEqual(model.phase, .failed)
        XCTAssertEqual(model.errorMessage, "failed to spawn agentdeckd: retry-fixture")
        XCTAssertEqual(model.historyErrorMessage, "failed to spawn agentdeckd: retry-fixture")

        model.loadHistory()

        XCTAssertEqual(transport.startAttempts, 2)
        XCTAssertEqual(model.phase, .idle)
        XCTAssertNil(model.errorMessage)
        XCTAssertNil(model.historyErrorMessage)
        XCTAssertTrue(model.isLoadingHistory)
        let didFinish = await waitUntil { !model.isLoadingHistory }
        XCTAssertTrue(didFinish)
        XCTAssertNil(model.historyErrorMessage)
    }

    func testSuccessfulRetryPreservesIndependentGlobalFailureState() async {
        let transport = RetryStartTransport()
        let client = DaemonClient(transport: transport)
        let model = SessionModel(client: client)

        model.loadHistory()
        model.errorMessage = "independent failure"

        model.loadHistory()

        XCTAssertEqual(transport.startAttempts, 2)
        XCTAssertEqual(model.phase, .failed)
        XCTAssertEqual(model.errorMessage, "independent failure")
        let didFinish = await waitUntil { !model.isLoadingHistory }
        XCTAssertTrue(didFinish)
        XCTAssertNil(model.historyErrorMessage)
    }
}
