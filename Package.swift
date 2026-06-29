// swift-tools-version: 6.0
import PackageDescription

// AgentDeck — macOS native app.
//
// Step 1 scope: a SwiftPM executable (NOT an .xcodeproj) so the project is
// command-line buildable, CI-friendly, and contributors don't need the Xcode
// GUI — this serves the open-source / community-contribution goal. The
// SwiftUI window comes in Step 4; Step 1 is the IPC round trip + the daemon
// process-lifecycle contract (Swift spawns agentdeckd, kills it on exit —
// Eng A1's first layer).
let package = Package(
    name: "AgentDeck",
    platforms: [.macOS(.v15)],
    targets: [
        .executableTarget(
            name: "AgentDeck",
            path: "Sources/AgentDeck",
            resources: [
                .process("Resources"),
            ]
        ),
        .testTarget(
            name: "AgentDeckTests",
            dependencies: [
                "AgentDeck",
            ],
            path: "Tests/AgentDeckTests"
        ),
    ]
)
