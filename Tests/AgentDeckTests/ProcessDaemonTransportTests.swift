import XCTest
@testable import AgentDeck

final class ProcessDaemonTransportTests: XCTestCase {
    func testStdioChildArgumentsAreExplicitEphemeralNoRemoteDev() {
        XCTAssertEqual(
            ProcessDaemonTransport.stdioDaemonArguments,
            ["--ephemeral", "--no-remote", "--profile", "dev"]
        )
    }

    func testStdioChildEnvironmentDropsLegacyNamespaceOverrides() {
        let environment = ProcessDaemonTransport.stdioDaemonEnvironment(base: [
            "PATH": "/usr/bin",
            "AGENTDECK_DATA_DIR": "/tmp/legacy",
            "AGENTDECK_PROFILE": "stable",
            "KEEP_ME": "yes",
        ])

        XCTAssertNil(environment["AGENTDECK_DATA_DIR"])
        XCTAssertNil(environment["AGENTDECK_PROFILE"])
        XCTAssertEqual(environment["PATH"], "/usr/bin")
        XCTAssertEqual(environment["KEEP_ME"], "yes")
    }
}
