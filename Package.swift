// swift-tools-version: 6.0
import PackageDescription

// AgentDeck — macOS native app + 平台无关共享层。
//
// AgentDeckCore 收纳中立协议与平台无关模型；AgentDeckSessionSource 在其上提供
// 非 UI 的 typed facade；AgentDeckRelayClient 再依赖前两层承载 wire/crypto/client。
// macOS executable 与 ios/ 下的 UIKit 工程（XcodeGen）显式消费三个 product；
// Core/SessionSource 内禁止平台 UI 或网络实现，依赖只允许单向向上。
let package = Package(
    name: "AgentDeck",
    platforms: [.macOS(.v15), .iOS(.v17)],
    products: [
        .library(name: "AgentDeckCore", targets: ["AgentDeckCore"]),
        .library(name: "AgentDeckSessionSource", targets: ["AgentDeckSessionSource"]),
        .library(name: "AgentDeckRelayClient", targets: ["AgentDeckRelayClient"]),
    ],
    targets: [
        .target(
            name: "AgentDeckCore",
            path: "Sources/AgentDeckCore"
        ),
        .target(
            name: "AgentDeckSessionSource",
            dependencies: [.target(name: "AgentDeckCore")],
            path: "Sources/AgentDeckSessionSource"
        ),
        .target(
            name: "AgentDeckRelayClient",
            dependencies: [
                .target(name: "AgentDeckCore"),
                .target(name: "AgentDeckSessionSource"),
            ],
            path: "Sources/AgentDeckRelayClient"
        ),
        .executableTarget(
            name: "AgentDeck",
            dependencies: [
                .target(name: "AgentDeckCore"),
                .target(name: "AgentDeckSessionSource"),
                .target(name: "AgentDeckRelayClient"),
            ],
            path: "Sources/AgentDeck",
            resources: [
                .process("Resources")
            ]
        ),
        .testTarget(
            name: "AgentDeckTests",
            dependencies: [
                "AgentDeck",
                "AgentDeckCore",
                .target(name: "AgentDeckSessionSource"),
                .target(name: "AgentDeckRelayClient"),
            ],
            path: "Tests/AgentDeckTests"
        ),
        .testTarget(
            name: "AgentDeckSessionSourceTests",
            dependencies: [
                .target(name: "AgentDeckCore"),
                .target(name: "AgentDeckSessionSource"),
            ],
            path: "Tests/AgentDeckSessionSourceTests"
        ),
        .testTarget(
            name: "AgentDeckRelayClientTests",
            dependencies: ["AgentDeckRelayClient"],
            path: "Tests/AgentDeckRelayClientTests"
        ),
    ]
)
