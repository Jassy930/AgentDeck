// swift-tools-version: 6.0
import PackageDescription

// AgentDeck — iOS companion 使用的平台无关 Swift 共享层。
//
// macOS 桌面端已迁到 Rust/GPUI；AgentDeckMobileCore 继续供 ios/ 下的 UIKit
// 工程（XcodeGen，经本地 package 依赖）消费。Mobile Core 内禁止 AppKit / UIKit
// import，边界由编译器保证。
let package = Package(
    name: "AgentDeck",
    platforms: [.macOS(.v15), .iOS(.v17)],
    products: [
        .library(name: "AgentDeckMobileCore", targets: ["AgentDeckMobileCore"]),
    ],
    targets: [
        .target(
            name: "AgentDeckMobileCore",
            path: "Sources/AgentDeckMobileCore"
        ),
        .testTarget(
            name: "AgentDeckMobileCoreTests",
            dependencies: ["AgentDeckMobileCore"],
            path: "Tests/AgentDeckMobileCoreTests"
        ),
    ]
)
