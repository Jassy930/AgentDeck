// swift-tools-version: 6.0
import PackageDescription

// AgentDeck — macOS native app + 平台无关共享层。
//
// AgentDeckCore 收纳协议类型与平台无关会话模型，供 macOS 可执行目标与
// ios/ 下的 UIKit 工程（XcodeGen，经本地 package 依赖）共同消费。
// Core 内禁止 AppKit / UIKit import，边界由编译器保证。
let package = Package(
    name: "AgentDeck",
    platforms: [.macOS(.v15), .iOS(.v17)],
    products: [
        .library(name: "AgentDeckCore", targets: ["AgentDeckCore"]),
        .library(name: "AgentDeckRelayClient", targets: ["AgentDeckRelayClient"]),
    ],
    targets: [
        .target(
            name: "AgentDeckCore",
            path: "Sources/AgentDeckCore"
        ),
        .target(
            name: "AgentDeckRelayClient",
            path: "Sources/AgentDeckRelayClient"
        ),
        .executableTarget(
            name: "AgentDeck",
            dependencies: ["AgentDeckCore"],
            path: "Sources/AgentDeck",
            resources: [
                .process("Resources"),
            ]
        ),
        .testTarget(
            name: "AgentDeckTests",
            dependencies: [
                "AgentDeck",
                "AgentDeckCore",
            ],
            path: "Tests/AgentDeckTests"
        ),
        .testTarget(
            name: "AgentDeckRelayClientTests",
            dependencies: ["AgentDeckRelayClient"],
            path: "Tests/AgentDeckRelayClientTests"
        ),
    ]
)
