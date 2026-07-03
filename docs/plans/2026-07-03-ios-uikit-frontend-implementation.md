# AgentDeck iOS UIKit 前端实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在 iPhone 模拟器上跑通 R3 companion 全部界面（机器列表、会话列表、会话详情流式、审批卡、prompt 输入、配对、收件箱），数据用协议对齐 fixture 回放；同时把平台无关代码抽成 `AgentDeckCore` SPM 共享库。

**Architecture:** 先做两步无逻辑改动的重构（剥离 `StreamingTextBuffer`、抽 `AgentDeckCore` target），让 macOS/iOS 共享协议类型与会话模型；再用 XcodeGen 建 `ios/` 工程，iOS 端唯一数据入口是 `MobileSessionSource` 协议，本期唯一实现 `FixtureSessionSource` 按 `delayMs` 回放 `ServerEvent` JSON。

**Tech Stack:** Swift 6 / SPM、UIKit（UICollectionView compositional list + diffable data source）、XcodeGen、XCTest、node（设计系统生成脚本，沿用现状）。

**设计文档:** `docs/plans/2026-07-03-ios-uikit-frontend-design.md`

## Global Constraints

- 目标平台：iPhone 竖屏，iOS 17.0+；`TARGETED_DEVICE_FAMILY = 1`，只支持 `UIInterfaceOrientationPortrait`。
- `ios/` 下禁止 `import SwiftUI`；`Sources/AgentDeckCore/` 下禁止 `import AppKit` / `import UIKit`（只允许 Foundation / Observation）。
- iOS app 不含任何网络代码、不直连 daemon；所有数据经 `MobileSessionSource` 协议；无磁盘持久化（杀 app 重置）。
- 渲染路径按数据/`SessionCapabilities` 路由，禁止 `if agentKind == .codex` 之类分支决定渲染路径（不变量 N2）；`vendorDisplayName(_:)` 这类纯展示文案映射不算渲染路径分支。vendor 原词（审批 summary、policy/sandbox/permissionMode/toolName）原样展示。
- fixture JSON 的 `event` 字段必须能被 `AgentDeckCore` 的 `ServerEvent`（Codable）解码——这是防漂移门禁，有专门单测。
- macOS 零回归：每个动到 `Sources/`、`Package.swift` 的任务结束时 `swift test` 必须全绿（当前 126 个）。
- 生成物不手改：`ios/AgentDeckMobile/DesignTokens.swift` 由 `designs/agentdeck-design-system/tools/build.mjs` 生成。
- `ios/AgentDeckMobile.xcodeproj/`、`ios/AgentDeckMobile/Info.plist` 是 xcodegen 生成物，不入库（加 .gitignore）。
- 提交信息不加 co-author；文档一律中文。
- 模拟器验证目标：`platform=iOS Simulator,name=iPhone 17`（本机已有该模拟器；没有 iPhone 16）。
- xcodebuild 命令统一形如：`xcodebuild -project AgentDeckMobile.xcodeproj -scheme AgentDeckMobile -destination 'platform=iOS Simulator,name=iPhone 17' <build|test>`，在 `ios/` 目录执行。

---

### Task 1: 剥离 StreamingTextBuffer（macOS 内部重构，为共享做准备）

`StreamingTextBuffer` 是纯 Foundation 类型，但目前定义在 AppKit 文件 `StreamingTextView.swift` 里，而 `UIItem` 持有它——这是共享链上唯一的 AppKit 阻断。本任务只做文件内搬移，零逻辑改动。

**Files:**
- Create: `Sources/AgentDeck/StreamingTextBuffer.swift`
- Modify: `Sources/AgentDeck/StreamingTextView.swift`（删除第 36-74 行的两个类型）

**Interfaces:**
- Produces: `StreamingTextBuffer`、`StreamingTextBufferChange`（代码与现状完全一致，仅换文件）

- [ ] **Step 1: 新建 StreamingTextBuffer.swift**

把 `StreamingTextView.swift` 第 36-74 行的 `StreamingTextBufferChange` 与 `StreamingTextBuffer` 原样剪切到新文件（内容逐字保留，包括注释）：

```swift
import Foundation

enum StreamingTextBufferChange: Equatable {
    case append(String)
    case replace(String)
}

// Owned by the main-render path. Marked unchecked only so AppKit deinit can
// detach observers under Swift 6's nonisolated deinitializer rules.
final class StreamingTextBuffer: @unchecked Sendable {
    private var observers: [UUID: (StreamingTextBufferChange) -> Void] = [:]
    private(set) var text = ""

    func append(_ suffix: String) {
        guard !suffix.isEmpty else { return }
        text.append(contentsOf: suffix)
        notify(.append(suffix))
    }

    func replace(with nextText: String) {
        text = nextText
        notify(.replace(nextText))
    }

    func observe(_ handler: @escaping (StreamingTextBufferChange) -> Void) -> UUID {
        let id = UUID()
        observers[id] = handler
        handler(.replace(text))
        return id
    }

    func removeObserver(_ id: UUID) {
        observers.removeValue(forKey: id)
    }

    private func notify(_ change: StreamingTextBufferChange) {
        for observer in observers.values {
            observer(change)
        }
    }
}
```

同时从 `StreamingTextView.swift` 删除这两个类型（保留文件其余部分：`StreamingTextStorageSyncResult`、`StreamingTextStorageSynchronizer`、各视图类）。

- [ ] **Step 2: 验证**

Run: `swift test 2>&1 | tail -3`
Expected: `Test Suite 'All tests' passed`，126 个测试全绿。

- [ ] **Step 3: Commit**

```bash
git add Sources/AgentDeck/StreamingTextBuffer.swift Sources/AgentDeck/StreamingTextView.swift
git commit -m "refactor(macos): 剥离 StreamingTextBuffer 到纯 Foundation 文件"
```

---

### Task 2: 新增 AgentDeckCore target 并迁入 V2Types

**Files:**
- Modify: `Package.swift`
- Move: `Sources/AgentDeck/Protocol/V2Types.swift` → `Sources/AgentDeckCore/Protocol/V2Types.swift`
- Modify: `Sources/AgentDeck/*.swift` 与 `Tests/AgentDeckTests/*.swift` 中引用协议类型的文件（加 `import AgentDeckCore`）

**Interfaces:**
- Produces: SPM library product `AgentDeckCore`（平台 macOS 15 / iOS 17），导出 V2Types 全部 public 类型（`ServerEvent`、`AgentItem`、`ActionRequest`、`SessionCapabilities`、`AgentKind` 等，已全 public，无需改动）

- [ ] **Step 1: 改写 Package.swift**

```swift
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
    ],
    targets: [
        .target(
            name: "AgentDeckCore",
            path: "Sources/AgentDeckCore"
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
    ]
)
```

- [ ] **Step 2: 移动 V2Types**

```bash
mkdir -p Sources/AgentDeckCore/Protocol
git mv Sources/AgentDeck/Protocol/V2Types.swift Sources/AgentDeckCore/Protocol/V2Types.swift
rmdir Sources/AgentDeck/Protocol
```

- [ ] **Step 3: 编译驱动补 import**

Run: `swift build 2>&1 | grep -oE '(Sources|Tests)/[A-Za-z/]+\.swift' | sort -u`

对列出的每个文件，在其第一个 `import` 行后加一行 `import AgentDeckCore`，重复直到 `swift build` 无错。预期涉及 `DaemonClient.swift`、`SessionModel.swift`、`ThreadRuntimeModel.swift`、`ObservationBinder.swift`、`HistoryModel.swift`、`WorkbenchModel.swift`、`capability/`、`agent/` 下多数文件及大部分测试文件（约 20-40 个）。

- [ ] **Step 4: 验证**

Run: `swift test 2>&1 | tail -3`
Expected: 126 个测试全绿。

- [ ] **Step 5: Commit**

```bash
git add -A Package.swift Sources Tests
git commit -m "refactor: 新增 AgentDeckCore target，迁入协议类型 V2Types"
```

---

### Task 3: 迁移平台无关模型链到 AgentDeckCore

**Files:**
- Move（`git mv` 到 `Sources/AgentDeckCore/`）: `CommandMessageSanitizer.swift`、`StreamingTextBuffer.swift`、`AgentItemReducer.swift`、`ConversationTurn.swift`、`ConversationDisplayRow.swift`、`ToolPresentation.swift`
- Create: `Sources/AgentDeckCore/UIItem.swift`（从 `SessionModel.swift` 第 1-137 行拆出：`UIItem`、`agentDeckContainsNonWhitespace`、`agentDeckStringArray`、`agentDeckUIItem`）
- Create: `Sources/AgentDeck/HistoryThreadRowPresentation.swift`（`HistoryThreadRowPresentation` 依赖 `SessionModel.Phase`，留在 app target）
- Move: `Sources/AgentDeck/HistoryModel.swift` → `Sources/AgentDeckCore/HistoryModel.swift`（移出 `HistoryThreadRowPresentation` 后）
- Modify: `Sources/AgentDeck/SessionModel.swift`（删除已拆出部分，保留 `HistoryOpenTiming` 与 `SessionModel` 类）

**Interfaces:**
- Produces（全部升为 public，后续 iOS 任务按这些签名消费）:
  - `public struct UIItem`（字段名不变，全部 public）+ `public init(id: String, lifecycle: String, kind: String)`
  - `public func agentDeckUIItem(from replay: HistoryReplayItem, largeHistoryTextThreshold: Int = 16 * 1024) -> UIItem`
  - `public struct AgentItemStore { public var items: [UIItem]; public var itemIndexById: [String: Int]; public init() }`
  - `public enum AgentItemReducer { public static func apply(_ item: AgentItem, itemId: String, into store: inout AgentItemStore); public static func kindLabel(for item: AgentItem) -> String }`
  - `public struct ConversationTurn` + `public func makeConversationTurns(from items: [UIItem]) -> [ConversationTurn]`
  - `public struct ConversationDisplayRow`（`role/turnId/item/firstInTurn/lastInTurn/id`）+ `public enum ConversationDisplayRowBuilder { public static func rows(from turns: [ConversationTurn]) -> [ConversationDisplayRow] }` + `public enum ConversationRowsDiff`
  - `public enum ToolPresentation`（`outputLabel(_:noun:)`、`webSearchTitle(_:)` 等 static 全 public）
  - `public enum CommandMessageSanitizer { public static func sanitize(userText:) ... }`
  - `public final class StreamingTextBuffer`（`public init()`、`text/append/replace/observe/removeObserver` public）+ `public enum StreamingTextBufferChange`
  - HistoryModel 全部 struct public（`HistoryThreadSummary`、`HistoryProjectGroup`、`HistoryThreadListPayload`、`HistoryReference`、`HistoryHookFragment`、`HistoryFileChange`、`HistoryToolAction`、`HistoryReplayItem`、`HistoryThreadDetail`）

- [ ] **Step 1: 移动六个纯 Foundation 文件**

```bash
git mv Sources/AgentDeck/CommandMessageSanitizer.swift \
       Sources/AgentDeck/StreamingTextBuffer.swift \
       Sources/AgentDeck/AgentItemReducer.swift \
       Sources/AgentDeck/ConversationTurn.swift \
       Sources/AgentDeck/ConversationDisplayRow.swift \
       Sources/AgentDeck/ToolPresentation.swift \
       Sources/AgentDeckCore/
```

- [ ] **Step 2: 拆分 SessionModel.swift**

把 `SessionModel.swift` 第 1-137 行（`UIItem` 定义、`agentDeckContainsNonWhitespace`、`agentDeckStringArray`、`agentDeckUIItem`）剪切为 `Sources/AgentDeckCore/UIItem.swift`（代码逐字保留，头部 `import Foundation`，不需要 Observation）。`SessionModel.swift` 保留 `HistoryOpenTiming` 与 `SessionModel` 类，头部补 `import AgentDeckCore`。

- [ ] **Step 3: 拆分 HistoryModel.swift**

把 `HistoryThreadRowPresentation` 结构体（当前 `HistoryModel.swift` 第 59-109 行附近）剪切到新文件 `Sources/AgentDeck/HistoryThreadRowPresentation.swift`（头部 `import Foundation` + `import AgentDeckCore`），然后：

```bash
git mv Sources/AgentDeck/HistoryModel.swift Sources/AgentDeckCore/HistoryModel.swift
```

- [ ] **Step 4: public 化**

对 Step 1-3 落入 `Sources/AgentDeckCore/` 的所有顶层类型、其被外部使用的属性/方法、以及顶层函数加 `public`。struct 的 memberwise init 是 internal 的，凡被 app/tests 直接构造的 struct 需补显式 `public init`（编译错误驱动逐个补齐；已知必须的：`UIItem(id:lifecycle:kind:)`、`ConversationTurn(id:user:assistantItems:)`、`ConversationTurnNavigationItem`、`ConversationDisplayRow(role:turnId:item:firstInTurn:lastInTurn:)`、`HistoryFileChange(path:diff:changeKind:)`、`HistoryThreadSummary`、`HistoryReplayItem`）。Codable 合成不受影响，无需手写 `init(from:)`。

- [ ] **Step 5: 编译驱动补 import 并验证**

Run: `swift build 2>&1 | grep -oE '(Sources|Tests)/[A-Za-z/]+\.swift' | sort -u`
对报错文件补 `import AgentDeckCore`，直到构建通过。然后：

Run: `swift test 2>&1 | tail -3`
Expected: 126 个测试全绿。

- [ ] **Step 6: 边界自检 + Commit**

Run: `grep -rl "import AppKit\|import UIKit\|import SwiftUI" Sources/AgentDeckCore/ ; echo "exit=$?"`
Expected: 无输出，`exit=1`（Core 无平台 UI import）。

```bash
git add -A Package.swift Sources Tests
git commit -m "refactor: 平台无关会话模型迁入 AgentDeckCore（UIItem/reducer/turn/rows）"
```

---

### Task 4: iOS 工程脚手架（XcodeGen）

**Files:**
- Create: `ios/project.yml`、`ios/AgentDeckMobile/App/AppDelegate.swift`、`ios/AgentDeckMobile/App/SceneDelegate.swift`、`ios/AgentDeckMobile/App/PlaceholderViewController.swift`、`ios/AgentDeckMobileTests/CoreLinkTests.swift`
- Modify: `.gitignore`

**Interfaces:**
- Produces: 可构建的 `AgentDeckMobile` app target（依赖本仓 SPM 的 `AgentDeckCore` product）与 `AgentDeckMobileTests` 单测 target。`SceneDelegate` 的根控制器在 Task 8 被替换为 `MachineListViewController`。

- [ ] **Step 1: 安装 xcodegen（本机没有）**

Run: `brew install xcodegen && xcodegen --version`
Expected: 输出版本号。

- [ ] **Step 2: 写 ios/project.yml**

```yaml
name: AgentDeckMobile
options:
  bundleIdPrefix: dev.agentdeck
  deploymentTarget:
    iOS: "17.0"
  createIntermediateGroups: true
packages:
  AgentDeck:
    path: ..
targets:
  AgentDeckMobile:
    type: application
    platform: iOS
    sources:
      - AgentDeckMobile
      - path: Fixtures
        buildPhase: resources
        optional: true
    dependencies:
      - package: AgentDeck
        product: AgentDeckCore
    info:
      path: AgentDeckMobile/Info.plist
      properties:
        UILaunchScreen: {}
        UISupportedInterfaceOrientations: [UIInterfaceOrientationPortrait]
        UIApplicationSceneManifest:
          UIApplicationSupportsMultipleScenes: false
          UISceneConfigurations:
            UIWindowSceneSessionRoleApplication:
              - UISceneConfigurationName: Default
                UISceneDelegateClassName: $(PRODUCT_MODULE_NAME).SceneDelegate
    settings:
      base:
        TARGETED_DEVICE_FAMILY: "1"
        SWIFT_VERSION: "6.0"
  AgentDeckMobileTests:
    type: bundle.unit-test
    platform: iOS
    sources:
      - AgentDeckMobileTests
    dependencies:
      - target: AgentDeckMobile
```

- [ ] **Step 3: App 骨架三文件**

`ios/AgentDeckMobile/App/AppDelegate.swift`：

```swift
import UIKit

@main
final class AppDelegate: UIResponder, UIApplicationDelegate {
    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
    ) -> Bool {
        true
    }
}
```

`ios/AgentDeckMobile/App/SceneDelegate.swift`：

```swift
import UIKit

final class SceneDelegate: UIResponder, UIWindowSceneDelegate {
    var window: UIWindow?

    func scene(
        _ scene: UIScene,
        willConnectTo session: UISceneSession,
        options connectionOptions: UIScene.ConnectionOptions
    ) {
        guard let windowScene = scene as? UIWindowScene else { return }
        let window = UIWindow(windowScene: windowScene)
        // Task 8 起替换为 MachineListViewController(source: FixtureSessionSource())
        window.rootViewController = UINavigationController(rootViewController: PlaceholderViewController())
        window.makeKeyAndVisible()
        self.window = window
    }
}
```

`ios/AgentDeckMobile/App/PlaceholderViewController.swift`：

```swift
import UIKit

final class PlaceholderViewController: UIViewController {
    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .systemBackground
        let label = UILabel()
        label.text = "AgentDeck Mobile"
        label.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(label)
        NSLayoutConstraint.activate([
            label.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            label.centerYAnchor.constraint(equalTo: view.centerYAnchor),
        ])
    }
}
```

`ios/AgentDeckMobileTests/CoreLinkTests.swift`（同时验证 Core 在 iOS 侧可用）：

```swift
import XCTest
import AgentDeckCore

final class CoreLinkTests: XCTestCase {
    func testServerEventDecodesOnIOS() throws {
        let json = #"{"type":"sessionStarted","sessionId":"s1","threadId":null,"agentKind":"codex"}"#
        let event = try JSONDecoder().decode(ServerEvent.self, from: Data(json.utf8))
        guard case .sessionStarted(let sid, _, let kind) = event else {
            return XCTFail("expected sessionStarted")
        }
        XCTAssertEqual(sid, "s1")
        XCTAssertEqual(kind, .codex)
    }
}
```

- [ ] **Step 4: .gitignore**

在仓库根 `.gitignore` 追加：

```text
ios/AgentDeckMobile.xcodeproj/
ios/AgentDeckMobile/Info.plist
ios/DerivedData/
```

- [ ] **Step 5: 生成 + 构建 + 测试**

Run:
```bash
cd ios && xcodegen generate && \
xcodebuild -project AgentDeckMobile.xcodeproj -scheme AgentDeckMobile \
  -destination 'platform=iOS Simulator,name=iPhone 17' test 2>&1 | tail -5
```
Expected: `** TEST SUCCEEDED **`。

- [ ] **Step 6: Commit**

```bash
git add .gitignore ios/project.yml ios/AgentDeckMobile ios/AgentDeckMobileTests
git commit -m "feat(ios): XcodeGen 工程脚手架，依赖 AgentDeckCore"
```

---

### Task 5: 设计系统生成 UIKit DesignTokens

**Files:**
- Modify: `designs/agentdeck-design-system/tools/build.mjs`
- Generate: `ios/AgentDeckMobile/DesignTokens.swift`

**Interfaces:**
- Produces: `enum DesignTokens`（iOS 模块内 internal 即可）：语义色 `static let <token>: UIColor`（与 macOS 版同名，如 `bg`、`fg`、`accent` 等，以 tokens.json 的 color key 为准）、圆角 `radiusLg/radiusMd/radiusSm/radiusPill: CGFloat`、间距 `sp1...spN: CGFloat`。

- [ ] **Step 1: 在 build.mjs 里加 genMobileSwift**

参照现有 `genAppSwift()`（第 176-209 行）在其后新增，并在文件末尾调用处同步：

```js
/* ============================================================
   5) ios/AgentDeckMobile/DesignTokens.swift —— UIKit 消费（codex 主题）
   仅当 iOS 源码树存在时生成。
   ============================================================ */
function genMobileSwift() {
  const appDir = path.join(root, "../../ios/AgentDeckMobile");
  if (!fs.existsSync(appDir)) return null;
  const id = src.$meta.primaryTheme;
  const t = src.themes[id];
  const g = src.global;
  const L = [];
  L.push("// 生成物 · 由设计系统 SSOT 生成（designs/agentdeck-design-system/tokens/tokens.json，" + id + " 主题）。");
  L.push("// 禁止手改；改 SSOT 后在 designs/agentdeck-design-system 跑 `node tools/build.mjs` 重生成。");
  L.push("import UIKit\n");
  L.push("enum DesignTokens {");
  L.push("    // 颜色（sRGB，来自设计系统语义 token）");
  for (const [k, v] of Object.entries(t.color)) {
    const c = parseColor(v);
    if (!c) continue;
    L.push(`    static let ${k} = UIColor(red: ${f4(c.r)}, green: ${f4(c.g)}, blue: ${f4(c.b)}, alpha: ${f4(c.a)})`);
  }
  L.push("");
  L.push("    // 圆角");
  L.push(`    static let radiusLg: CGFloat = ${t.radius.lg}`);
  L.push(`    static let radiusMd: CGFloat = ${t.radius.md}`);
  L.push(`    static let radiusSm: CGFloat = ${t.radius.sm}`);
  L.push(`    static let radiusPill: CGFloat = ${t.radius.pill}`);
  L.push("");
  L.push("    // 间距（4pt 基准）");
  for (const [k, v] of Object.entries(g.spacing)) L.push(`    static let sp${k}: CGFloat = ${v}`);
  L.push("}");
  fs.writeFileSync(path.join(appDir, "DesignTokens.swift"), L.join("\n") + "\n");
  return "ios/AgentDeckMobile/DesignTokens.swift";
}
```

文件末尾调用区改为（保留原有调用与日志，追加 mobile 输出）：

```js
genCss();
genSwift();
genTs();
const appOut = genAppSwift();
const mobileOut = genMobileSwift();
console.log("✓ 生成完成 → generated/tokens.css, generated/Theme.swift, generated/DesignTokens.ts");
if (appOut) console.log("✓ App 契约 → " + appOut);
if (mobileOut) console.log("✓ Mobile 契约 → " + mobileOut);
```

注意：原脚本末尾若已有 `if (appOut) console.log(...)` 之类输出行，保持原样只追加 mobile 行。

- [ ] **Step 2: 生成并验证**

Run: `cd designs/agentdeck-design-system && node tools/build.mjs && head -6 ../../ios/AgentDeckMobile/DesignTokens.swift`
Expected: 输出含 `✓ Mobile 契约 → ios/AgentDeckMobile/DesignTokens.swift`；文件头两行是生成物声明，第三行 `import UIKit`。
再验证 macOS 侧生成物无 diff：`git diff --stat Sources/AgentDeck/DesignTokens.swift` 应为空。

Run: `cd ios && xcodegen generate && xcodebuild -project AgentDeckMobile.xcodeproj -scheme AgentDeckMobile -destination 'platform=iOS Simulator,name=iPhone 17' build 2>&1 | tail -3`
Expected: `** BUILD SUCCEEDED **`。

- [ ] **Step 3: Commit**

```bash
git add designs/agentdeck-design-system/tools/build.mjs ios/AgentDeckMobile/DesignTokens.swift
git commit -m "feat(design-system): 生成 UIKit DesignTokens 供 iOS 消费"
```

---

### Task 6: 数据模型、fixture 格式与 fixture 文件

**Files:**
- Create: `ios/AgentDeckMobile/DataSource/MobileSessionModels.swift`
- Create: `ios/AgentDeckMobile/DataSource/FixtureFormat.swift`
- Create: `ios/Fixtures/deck.json`、`ios/Fixtures/stream-codex-01.json`、`ios/Fixtures/stream-cc-01.json`、`ios/Fixtures/stream-approval-01.json`、`ios/Fixtures/stream-failed-01.json`
- Test: `ios/AgentDeckMobileTests/FixtureDecodingTests.swift`

**Interfaces:**
- Produces:
  - `struct MachineSummary: Identifiable, Equatable { id, name, isOnline: Bool, lastHeartbeat: Date?, activeSessionCount: Int, pendingApprovalCount: Int }`
  - `enum SessionGroup: String, Codable { case waitingApproval, active, recent }`
  - `struct SessionSummary: Identifiable, Equatable { id, machineID, title, cwd: String, agentKind: AgentKind, group: SessionGroup, streamResource: String? }`
  - `struct InboxItem: Identifiable, Equatable { id: String; sessionID: String; machineID: String; kind: Kind; title: String }`，`enum Kind { case waitingApproval, turnCompleted, failed }`
  - `struct SessionStreamElement: Sendable { let itemId: String?; let event: ServerEvent }`
  - `struct FixtureDeck: Decodable { machines: [FixtureMachine]; sessions: [FixtureSession] }`、`FixtureMachine`、`FixtureSession`、`struct FixtureStreamStep: Decodable { delayMs: Int; itemId: String?; awaitApproval: Bool?; event: ServerEvent }`
  - `func vendorDisplayName(_ kind: AgentKind) -> String`（codex→"Codex"，claudeCode→"Claude Code"）

- [ ] **Step 1: 写模型文件**

`ios/AgentDeckMobile/DataSource/MobileSessionModels.swift`：

```swift
import Foundation
import AgentDeckCore

struct MachineSummary: Identifiable, Equatable {
    let id: String
    let name: String
    let isOnline: Bool
    let lastHeartbeat: Date?
    let activeSessionCount: Int
    let pendingApprovalCount: Int
}

enum SessionGroup: String, Codable {
    case waitingApproval, active, recent
}

struct SessionSummary: Identifiable, Equatable {
    let id: String
    let machineID: String
    let title: String
    let cwd: String
    let agentKind: AgentKind
    var group: SessionGroup
    let streamResource: String?
}

struct InboxItem: Identifiable, Equatable {
    enum Kind: Equatable { case waitingApproval, turnCompleted, failed }
    let id: String
    let sessionID: String
    let machineID: String
    let kind: Kind
    let title: String
}

struct SessionStreamElement: Sendable {
    let itemId: String?
    let event: ServerEvent
}

/// 纯展示文案映射（不是渲染路径路由，N2 不适用）。
func vendorDisplayName(_ kind: AgentKind) -> String {
    switch kind {
    case .codex: "Codex"
    case .claudeCode: "Claude Code"
    }
}
```

`ios/AgentDeckMobile/DataSource/FixtureFormat.swift`：

```swift
import Foundation
import AgentDeckCore

struct FixtureMachine: Decodable {
    let id: String
    let name: String
    let isOnline: Bool
    /// 相对秒数而非绝对时间戳，让 fixture 不随日期腐烂。
    let lastHeartbeatSecondsAgo: Int?
}

struct FixtureSession: Decodable {
    let id: String
    let machineId: String
    let title: String
    let cwd: String
    let agentKind: AgentKind
    let group: SessionGroup
    /// 对应 ios/Fixtures/<stream>.json；无流的会话（纯历史行）可为 nil。
    let stream: String?
}

struct FixtureDeck: Decodable {
    let machines: [FixtureMachine]
    let sessions: [FixtureSession]
}

/// 回放信封：event 是协议原样的 ServerEvent JSON；itemId 供 AgentItemReducer
/// 做累积语义槽位（同一 itemId 的后续事件替换同一槽位，模拟流式增长）；
/// awaitApproval=true 表示回放在该事件后暂停，直到 resolveApproval。
struct FixtureStreamStep: Decodable {
    let delayMs: Int
    let itemId: String?
    let awaitApproval: Bool?
    let event: ServerEvent
}
```

- [ ] **Step 2: 写 fixture 文件**

事件 JSON 形状以 `Tests/AgentDeckTests/ProtocolV2DecodingTests.swift` 的样例为事实源（写新 kind 时先查那里）。

`ios/Fixtures/deck.json`：

```json
{
  "machines": [
    { "id": "mac-studio", "name": "Mac Studio", "isOnline": true, "lastHeartbeatSecondsAgo": 12 },
    { "id": "macbook-air", "name": "MacBook Air", "isOnline": false, "lastHeartbeatSecondsAgo": 7200 }
  ],
  "sessions": [
    { "id": "sess-codex-01", "machineId": "mac-studio", "title": "重构 IPC 重连逻辑", "cwd": "~/Documents/glm/AgentDeck", "agentKind": "codex", "group": "active", "stream": "stream-codex-01" },
    { "id": "sess-cc-01", "machineId": "mac-studio", "title": "补充历史聚合测试", "cwd": "~/Documents/glm/AgentDeck", "agentKind": "claude_code", "group": "active", "stream": "stream-cc-01" },
    { "id": "sess-approval-01", "machineId": "mac-studio", "title": "运行数据库迁移脚本", "cwd": "~/work/api-server", "agentKind": "codex", "group": "waitingApproval", "stream": "stream-approval-01" },
    { "id": "sess-failed-01", "machineId": "mac-studio", "title": "升级依赖到最新版", "cwd": "~/work/web-app", "agentKind": "claude_code", "group": "recent", "stream": "stream-failed-01" }
  ]
}
```

（`macbook-air` 无会话 = 空状态场景。）

`ios/Fixtures/stream-codex-01.json`（Codex：reasoning + shell + diff + 流式 assistant，注意 `i4` 三次事件同一 itemId 模拟累积增长）：

```json
[
  { "delayMs": 0, "event": { "type": "sessionStarted", "sessionId": "sess-codex-01", "threadId": "t1", "agentKind": "codex" } },
  { "delayMs": 100, "itemId": "i1", "event": { "type": "agentItem", "sessionId": "sess-codex-01", "threadId": "t1", "agentKind": "codex", "item": { "kind": "userMessage", "text": "把 IPC 重连改成指数退避", "meta": { "vendorExtensions": {} } } } },
  { "delayMs": 400, "itemId": "i2", "event": { "type": "agentItem", "sessionId": "sess-codex-01", "threadId": "t1", "agentKind": "codex", "item": { "kind": "reasoning", "text": "需要先确认现有重连在 ipc.rs 的位置，然后加退避与上限。", "meta": { "vendorExtensions": {} } } } },
  { "delayMs": 500, "itemId": "i3", "event": { "type": "agentItem", "sessionId": "sess-codex-01", "threadId": "t1", "agentKind": "codex", "item": { "kind": "shell", "command": "rg -n \"reconnect\" agentdeckd/src", "status": "completed", "exitCode": 0, "durationMs": 180, "meta": { "vendorExtensions": {} } } } },
  { "delayMs": 400, "itemId": "i4", "event": { "type": "agentItem", "sessionId": "sess-codex-01", "threadId": "t1", "agentKind": "codex", "item": { "kind": "assistantMessage", "text": "找到重连入口，", "meta": { "vendorExtensions": {} } } } },
  { "delayMs": 300, "itemId": "i4", "event": { "type": "agentItem", "sessionId": "sess-codex-01", "threadId": "t1", "agentKind": "codex", "item": { "kind": "assistantMessage", "text": "找到重连入口，我把固定 1s 间隔改成 **指数退避**（上限 30s），", "meta": { "vendorExtensions": {} } } } },
  { "delayMs": 300, "itemId": "i4", "event": { "type": "agentItem", "sessionId": "sess-codex-01", "threadId": "t1", "agentKind": "codex", "item": { "kind": "assistantMessage", "text": "找到重连入口，我把固定 1s 间隔改成 **指数退避**（上限 30s），并补了抖动，避免雪崩重连。", "meta": { "vendorExtensions": {} } } } },
  { "delayMs": 500, "itemId": "i5", "event": { "type": "agentItem", "sessionId": "sess-codex-01", "threadId": "t1", "agentKind": "codex", "item": { "kind": "diff", "files": [ { "path": "agentdeckd/src/ipc.rs", "status": "modified", "patch": "@@ -41,7 +41,12 @@\n-    sleep(Duration::from_secs(1));\n+    let backoff = base * 2u32.pow(attempt.min(5));\n+    sleep(jitter(backoff));" } ], "meta": { "vendorExtensions": {} } } } },
  { "delayMs": 400, "event": { "type": "turnComplete", "sessionId": "sess-codex-01", "threadId": "t1", "agentKind": "codex", "summary": { "totalInputTokens": 1200, "totalOutputTokens": 460, "elapsedMs": 8400 } } }
]
```

`ios/Fixtures/stream-cc-01.json`（Claude Code：userMessage + toolCall + assistant）：

```json
[
  { "delayMs": 0, "event": { "type": "sessionStarted", "sessionId": "sess-cc-01", "threadId": "t2", "agentKind": "claude_code" } },
  { "delayMs": 100, "itemId": "c1", "event": { "type": "agentItem", "sessionId": "sess-cc-01", "threadId": "t2", "agentKind": "claude_code", "item": { "kind": "userMessage", "text": "给跨 agent 历史聚合补边界测试", "meta": { "vendorExtensions": {} } } } },
  { "delayMs": 500, "itemId": "c2", "event": { "type": "agentItem", "sessionId": "sess-cc-01", "threadId": "t2", "agentKind": "claude_code", "item": { "kind": "toolCall", "name": "Read", "args": { "file_path": "Tests/AgentDeckTests/HistorySidebarUnifiedHistoryTests.swift" }, "result": "读取 220 行", "meta": { "vendorExtensions": {} } } } },
  { "delayMs": 600, "itemId": "c3", "event": { "type": "agentItem", "sessionId": "sess-cc-01", "threadId": "t2", "agentKind": "claude_code", "item": { "kind": "assistantMessage", "text": "已有测试覆盖了合并排序，缺空列表与重复 threadId 两个边界，我来补上。", "meta": { "vendorExtensions": {} } } } },
  { "delayMs": 400, "event": { "type": "turnComplete", "sessionId": "sess-cc-01", "threadId": "t2", "agentKind": "claude_code", "summary": { "totalInputTokens": 900, "totalOutputTokens": 310, "elapsedMs": 5200 } } }
]
```

`ios/Fixtures/stream-approval-01.json`（进场即等待审批；approve 后继续）：

```json
[
  { "delayMs": 0, "event": { "type": "sessionStarted", "sessionId": "sess-approval-01", "threadId": "t3", "agentKind": "codex" } },
  { "delayMs": 100, "itemId": "a1", "event": { "type": "agentItem", "sessionId": "sess-approval-01", "threadId": "t3", "agentKind": "codex", "item": { "kind": "userMessage", "text": "执行本周的数据库迁移", "meta": { "vendorExtensions": {} } } } },
  { "delayMs": 200, "awaitApproval": true, "event": { "type": "actionRequest", "sessionId": "sess-approval-01", "threadId": "t3", "agentKind": "codex", "request": { "requestId": "req-1", "kind": "executeCommand", "summary": "uv run alembic upgrade head", "vendor": { "agentKind": "codex", "approvalPolicyAtDecision": "on-request", "sandboxAtDecision": "workspace-write", "canPersist": true } } } },
  { "delayMs": 600, "itemId": "a2", "event": { "type": "agentItem", "sessionId": "sess-approval-01", "threadId": "t3", "agentKind": "codex", "item": { "kind": "shell", "command": "uv run alembic upgrade head", "status": "completed", "exitCode": 0, "durationMs": 3200, "meta": { "vendorExtensions": {} } } } },
  { "delayMs": 300, "itemId": "a3", "event": { "type": "agentItem", "sessionId": "sess-approval-01", "threadId": "t3", "agentKind": "codex", "item": { "kind": "assistantMessage", "text": "迁移已执行完成，共应用 3 个 revision。", "meta": { "vendorExtensions": {} } } } },
  { "delayMs": 300, "event": { "type": "turnComplete", "sessionId": "sess-approval-01", "threadId": "t3", "agentKind": "codex", "summary": { "totalInputTokens": 700, "totalOutputTokens": 150, "elapsedMs": 4100 } } }
]
```

`ios/Fixtures/stream-failed-01.json`（中途失败）：

```json
[
  { "delayMs": 0, "event": { "type": "sessionStarted", "sessionId": "sess-failed-01", "threadId": "t4", "agentKind": "claude_code" } },
  { "delayMs": 100, "itemId": "f1", "event": { "type": "agentItem", "sessionId": "sess-failed-01", "threadId": "t4", "agentKind": "claude_code", "item": { "kind": "userMessage", "text": "把所有依赖升级到最新", "meta": { "vendorExtensions": {} } } } },
  { "delayMs": 500, "itemId": "f2", "event": { "type": "agentItem", "sessionId": "sess-failed-01", "threadId": "t4", "agentKind": "claude_code", "item": { "kind": "shell", "command": "bun update", "status": "failed", "exitCode": 1, "durationMs": 9200, "meta": { "vendorExtensions": {} } } } },
  { "delayMs": 300, "event": { "type": "error", "sessionId": "sess-failed-01", "error": { "code": "cc.turn.failed", "message": "bun update 失败：peer dependency 冲突（react@19 与 legacy-ui@2）", "diagnosticRef": null } } }
]
```

- [ ] **Step 3: 写解码门禁测试**

`ios/AgentDeckMobileTests/FixtureDecodingTests.swift`：

```swift
import XCTest
import AgentDeckCore
@testable import AgentDeckMobile

final class FixtureDecodingTests: XCTestCase {
    private var bundle: Bundle { Bundle(for: PlaceholderViewController.self) }

    func testDeckDecodes() throws {
        let url = try XCTUnwrap(bundle.url(forResource: "deck", withExtension: "json"))
        let deck = try JSONDecoder().decode(FixtureDeck.self, from: Data(contentsOf: url))
        XCTAssertEqual(deck.machines.count, 2)
        XCTAssertEqual(deck.sessions.count, 4)
    }

    /// 防漂移门禁：所有 stream fixture 的 event 必须能被 AgentDeckCore 的
    /// ServerEvent 解码 —— fixture 本身就是对协议理解的检验。
    func testAllStreamFixturesDecodeAsServerEvents() throws {
        let urls = bundle.urls(forResourcesWithExtension: "json", subdirectory: nil) ?? []
        let streamURLs = urls.filter { $0.lastPathComponent.hasPrefix("stream-") }
        XCTAssertEqual(streamURLs.count, 4, "预期 4 个 stream fixture")
        for url in streamURLs {
            let steps = try JSONDecoder().decode([FixtureStreamStep].self, from: Data(contentsOf: url))
            XCTAssertFalse(steps.isEmpty, "\(url.lastPathComponent) 不应为空")
        }
    }

    func testApprovalFixtureCarriesGate() throws {
        let url = try XCTUnwrap(bundle.url(forResource: "stream-approval-01", withExtension: "json"))
        let steps = try JSONDecoder().decode([FixtureStreamStep].self, from: Data(contentsOf: url))
        XCTAssertTrue(steps.contains { $0.awaitApproval == true })
    }
}
```

- [ ] **Step 4: 运行测试**

Run: `cd ios && xcodegen generate && xcodebuild -project AgentDeckMobile.xcodeproj -scheme AgentDeckMobile -destination 'platform=iOS Simulator,name=iPhone 17' test 2>&1 | tail -5`
Expected: `** TEST SUCCEEDED **`。若解码失败，修 fixture JSON（对照 `ProtocolV2DecodingTests.swift` 的形状），不改 V2Types。

- [ ] **Step 5: Commit**

```bash
git add ios/AgentDeckMobile/DataSource ios/Fixtures ios/AgentDeckMobileTests/FixtureDecodingTests.swift
git commit -m "feat(ios): MobileSession 数据模型 + 协议对齐 fixture 与解码门禁"
```

---

### Task 7: MobileSessionSource 协议与 FixtureSessionSource 回放引擎

**Files:**
- Create: `ios/AgentDeckMobile/DataSource/MobileSessionSource.swift`
- Create: `ios/AgentDeckMobile/DataSource/FixtureSessionSource.swift`
- Test: `ios/AgentDeckMobileTests/FixtureSessionSourceTests.swift`

**Interfaces:**
- Produces（后续所有屏依赖这些签名）:

```swift
@MainActor
protocol MobileSessionSource: AnyObject {
    func machines() -> AsyncStream<[MachineSummary]>
    func sessions(machineID: String) -> AsyncStream<[SessionSummary]>
    func events(sessionID: String) -> AsyncStream<SessionStreamElement>
    func inbox() -> AsyncStream<[InboxItem]>
    func sendPrompt(sessionID: String, text: String) async
    func resolveApproval(sessionID: String, requestID: String, approve: Bool) async
}
```

- `FixtureSessionSource: MobileSessionSource`，`init(bundle: Bundle = .main, tickScale: Double = 1.0)`；`tickScale = 0` 供测试即时回放。

- [ ] **Step 1: 写协议文件**

`ios/AgentDeckMobile/DataSource/MobileSessionSource.swift`：上面 Interfaces 里的协议全文 + 文档注释：

```swift
import Foundation
import AgentDeckCore

/// iOS 端唯一数据入口。本期唯一实现是 FixtureSessionSource（bundle 内
/// JSON 回放）；R2 Relay 就绪后新增 RelaySessionSource，视图层不动。
@MainActor
protocol MobileSessionSource: AnyObject {
    func machines() -> AsyncStream<[MachineSummary]>
    func sessions(machineID: String) -> AsyncStream<[SessionSummary]>
    func events(sessionID: String) -> AsyncStream<SessionStreamElement>
    func inbox() -> AsyncStream<[InboxItem]>
    func sendPrompt(sessionID: String, text: String) async
    func resolveApproval(sessionID: String, requestID: String, approve: Bool) async
}
```

- [ ] **Step 2: 写失败测试**

`ios/AgentDeckMobileTests/FixtureSessionSourceTests.swift`：

```swift
import XCTest
import AgentDeckCore
@testable import AgentDeckMobile

@MainActor
final class FixtureSessionSourceTests: XCTestCase {
    private var testBundle: Bundle { Bundle(for: PlaceholderViewController.self) }

    private func makeSource() -> FixtureSessionSource {
        FixtureSessionSource(bundle: testBundle, tickScale: 0)
    }

    private func collect<T>(_ stream: AsyncStream<T>, until stop: @escaping (T) -> Bool) async -> [T] {
        var out: [T] = []
        for await value in stream {
            out.append(value)
            if stop(value) { break }
        }
        return out
    }

    func testMachinesSnapshot() async {
        let source = makeSource()
        var it = source.machines().makeAsyncIterator()
        let machines = await it.next() ?? []
        XCTAssertEqual(machines.map(\.id).sorted(), ["mac-studio", "macbook-air"])
        let studio = machines.first { $0.id == "mac-studio" }
        XCTAssertEqual(studio?.activeSessionCount, 2)
        XCTAssertEqual(studio?.pendingApprovalCount, 1)
    }

    func testReplayDeliversAllEventsAndKeepsTranscript() async {
        let source = makeSource()
        func isTurnComplete(_ e: SessionStreamElement) -> Bool {
            if case .turnComplete = e.event { return true }
            return false
        }
        let first = await collect(source.events(sessionID: "sess-codex-01"), until: isTurnComplete)
        XCTAssertEqual(first.count, 9)
        // 二次订阅（模拟切屏返回）应立刻拿到完整 transcript。
        let second = await collect(source.events(sessionID: "sess-codex-01"), until: isTurnComplete)
        XCTAssertEqual(second.count, 9)
    }

    func testApprovalGatePausesUntilResolved() async {
        let source = makeSource()
        var received: [SessionStreamElement] = []
        for await element in source.events(sessionID: "sess-approval-01") {
            received.append(element)
            if case .actionRequest = element.event { break }
        }
        XCTAssertEqual(received.count, 3) // sessionStarted + userMessage + actionRequest
        await source.resolveApproval(sessionID: "sess-approval-01", requestID: "req-1", approve: true)
        var rest: [SessionStreamElement] = []
        for await element in source.events(sessionID: "sess-approval-01") {
            rest.append(element)
            if case .turnComplete = element.event { break }
        }
        XCTAssertEqual(rest.count, 6) // transcript 3 + shell + assistant + turnComplete
    }

    func testSendPromptEchoesUserMessageAndReplies() async {
        let source = makeSource()
        func isTurnComplete(_ e: SessionStreamElement) -> Bool {
            if case .turnComplete = e.event { return true }
            return false
        }
        _ = await collect(source.events(sessionID: "sess-cc-01"), until: isTurnComplete)
        await source.sendPrompt(sessionID: "sess-cc-01", text: "继续，补第三个边界")
        let after = await collect(source.events(sessionID: "sess-cc-01"), until: isTurnComplete)
        let texts: [String] = after.compactMap { element in
            if case .agentItem(_, _, _, let item) = element.event,
               case .userMessage(let text, _) = item { return text }
            return nil
        }
        XCTAssertTrue(texts.contains("继续，补第三个边界"))
    }
}
```

- [ ] **Step 3: 跑测试确认失败**

Run: `cd ios && xcodegen generate && xcodebuild ... test 2>&1 | grep -E "error:" | head -5`（完整命令见 Global Constraints）
Expected: 编译错误 `cannot find 'FixtureSessionSource'`。

- [ ] **Step 4: 实现 FixtureSessionSource**

`ios/AgentDeckMobile/DataSource/FixtureSessionSource.swift`：

```swift
import Foundation
import AgentDeckCore

@MainActor
final class FixtureSessionSource: MobileSessionSource {

    private final class Playback {
        var transcript: [SessionStreamElement] = []
        var subscribers: [UUID: AsyncStream<SessionStreamElement>.Continuation] = [:]
        var approvalGate: CheckedContinuation<Void, Never>?
        var started = false
        var finished = false
    }

    private let bundle: Bundle
    private let tickScale: Double
    private var machineRows: [FixtureMachine] = []
    private var sessionRows: [SessionSummary] = []
    private var playbacks: [String: Playback] = [:]
    private var machineSubs: [UUID: AsyncStream<[MachineSummary]>.Continuation] = [:]
    private var sessionSubs: [UUID: (machineID: String, cont: AsyncStream<[SessionSummary]>.Continuation)] = [:]
    private var inboxItems: [InboxItem] = []
    private var inboxSubs: [UUID: AsyncStream<[InboxItem]>.Continuation] = [:]
    private var promptSeq = 0

    init(bundle: Bundle = .main, tickScale: Double = 1.0) {
        self.bundle = bundle
        self.tickScale = tickScale
        loadDeck()
    }

    private func loadDeck() {
        guard let url = bundle.url(forResource: "deck", withExtension: "json"),
              let deck = try? JSONDecoder().decode(FixtureDeck.self, from: Data(contentsOf: url))
        else {
            assertionFailure("deck.json 缺失或无法解码")
            return
        }
        machineRows = deck.machines
        sessionRows = deck.sessions.map {
            SessionSummary(
                id: $0.id, machineID: $0.machineId, title: $0.title, cwd: $0.cwd,
                agentKind: $0.agentKind, group: $0.group, streamResource: $0.stream
            )
        }
        inboxItems = sessionRows.filter { $0.group == .waitingApproval }.map {
            InboxItem(id: "inbox-\($0.id)", sessionID: $0.id, machineID: $0.machineID,
                      kind: .waitingApproval, title: $0.title)
        }
    }

    // MARK: - Snapshots

    private func machineSummaries() -> [MachineSummary] {
        machineRows.map { m in
            let sessions = sessionRows.filter { $0.machineID == m.id }
            return MachineSummary(
                id: m.id, name: m.name, isOnline: m.isOnline,
                lastHeartbeat: m.lastHeartbeatSecondsAgo.map { Date(timeIntervalSinceNow: -Double($0)) },
                activeSessionCount: sessions.filter { $0.group == .active }.count,
                pendingApprovalCount: sessions.filter { $0.group == .waitingApproval }.count
            )
        }
    }

    private func broadcastState() {
        let machines = machineSummaries()
        for cont in machineSubs.values { cont.yield(machines) }
        for (_, sub) in sessionSubs {
            sub.cont.yield(sessionRows.filter { $0.machineID == sub.machineID })
        }
        for cont in inboxSubs.values { cont.yield(inboxItems) }
    }

    // MARK: - MobileSessionSource

    func machines() -> AsyncStream<[MachineSummary]> {
        AsyncStream { cont in
            let id = UUID()
            machineSubs[id] = cont
            cont.yield(machineSummaries())
            cont.onTermination = { _ in
                Task { @MainActor [weak self] in self?.machineSubs[id] = nil }
            }
        }
    }

    func sessions(machineID: String) -> AsyncStream<[SessionSummary]> {
        AsyncStream { cont in
            let id = UUID()
            sessionSubs[id] = (machineID, cont)
            cont.yield(sessionRows.filter { $0.machineID == machineID })
            cont.onTermination = { _ in
                Task { @MainActor [weak self] in self?.sessionSubs[id] = nil }
            }
        }
    }

    func events(sessionID: String) -> AsyncStream<SessionStreamElement> {
        let playback = playbacks[sessionID] ?? Playback()
        playbacks[sessionID] = playback
        startPlaybackIfNeeded(sessionID: sessionID, playback: playback)
        return AsyncStream { cont in
            let id = UUID()
            for element in playback.transcript { cont.yield(element) }
            if playback.finished {
                cont.finish()
            } else {
                playback.subscribers[id] = cont
                cont.onTermination = { _ in
                    Task { @MainActor [weak self] in self?.playbacks[sessionID]?.subscribers[id] = nil }
                }
            }
        }
    }

    func inbox() -> AsyncStream<[InboxItem]> {
        AsyncStream { cont in
            let id = UUID()
            inboxSubs[id] = cont
            cont.yield(inboxItems)
            cont.onTermination = { _ in
                Task { @MainActor [weak self] in self?.inboxSubs[id] = nil }
            }
        }
    }

    func sendPrompt(sessionID: String, text: String) async {
        guard let playback = playbacks[sessionID] else { return }
        guard let session = sessionRows.first(where: { $0.id == sessionID }) else { return }
        promptSeq += 1
        let seq = promptSeq
        playback.finished = false
        let kind = session.agentKind
        let threadId = "t-prompt-\(seq)"
        emit(SessionStreamElement(
            itemId: "prompt-user-\(seq)",
            event: .agentItem(sessionId: sessionID, threadId: threadId, agentKind: kind,
                              item: .userMessage(text: text, meta: AgentItemMeta()))
        ), sessionID: sessionID, playback: playback)
        let reply = "（fixture 回声）收到：\(text)。真实链路接入后此处为 agent 输出。"
        await sleepTicks(600)
        emit(SessionStreamElement(
            itemId: "prompt-reply-\(seq)",
            event: .agentItem(sessionId: sessionID, threadId: threadId, agentKind: kind,
                              item: .assistantMessage(text: reply, meta: AgentItemMeta()))
        ), sessionID: sessionID, playback: playback)
        await sleepTicks(200)
        emit(SessionStreamElement(
            itemId: nil,
            event: .turnComplete(sessionId: sessionID, threadId: threadId, agentKind: kind,
                                 summary: TurnSummary(elapsedMs: 800))
        ), sessionID: sessionID, playback: playback)
        appendInbox(.init(id: "inbox-turn-\(sessionID)-\(seq)", sessionID: sessionID,
                          machineID: session.machineID, kind: .turnCompleted, title: session.title))
    }

    func resolveApproval(sessionID: String, requestID: String, approve: Bool) async {
        guard let playback = playbacks[sessionID] else { return }
        if let index = sessionRows.firstIndex(where: { $0.id == sessionID }) {
            sessionRows[index].group = .active
        }
        inboxItems.removeAll { $0.sessionID == sessionID && $0.kind == .waitingApproval }
        broadcastState()
        playback.approvalGate?.resume()
        playback.approvalGate = nil
        _ = approve // fixture 状态机不区分 approve/deny 的后续流；卡片状态由 view model 记录
    }

    // MARK: - Playback

    private func startPlaybackIfNeeded(sessionID: String, playback: Playback) {
        guard !playback.started else { return }
        playback.started = true
        guard let resource = sessionRows.first(where: { $0.id == sessionID })?.streamResource,
              let url = bundle.url(forResource: resource, withExtension: "json"),
              let steps = try? JSONDecoder().decode([FixtureStreamStep].self, from: Data(contentsOf: url))
        else {
            playback.finished = true
            return
        }
        Task { [weak self] in
            for step in steps {
                await self?.sleepTicks(step.delayMs)
                guard let self else { return }
                self.emit(SessionStreamElement(itemId: step.itemId, event: step.event),
                          sessionID: sessionID, playback: playback)
                self.noteSideEffects(of: step.event, sessionID: sessionID)
                if step.awaitApproval == true {
                    await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
                        playback.approvalGate = cont
                    }
                }
            }
            playback.finished = true
            for cont in playback.subscribers.values { cont.finish() }
            playback.subscribers.removeAll()
        }
    }

    private func emit(_ element: SessionStreamElement, sessionID: String, playback: Playback) {
        playback.transcript.append(element)
        for cont in playback.subscribers.values { cont.yield(element) }
    }

    private func noteSideEffects(of event: ServerEvent, sessionID: String) {
        guard let session = sessionRows.first(where: { $0.id == sessionID }) else { return }
        switch event {
        case .actionRequest:
            if let index = sessionRows.firstIndex(where: { $0.id == sessionID }) {
                sessionRows[index].group = .waitingApproval
            }
            if !inboxItems.contains(where: { $0.sessionID == sessionID && $0.kind == .waitingApproval }) {
                inboxItems.append(.init(id: "inbox-\(sessionID)", sessionID: sessionID,
                                        machineID: session.machineID, kind: .waitingApproval, title: session.title))
            }
            broadcastState()
        case .turnComplete:
            appendInbox(.init(id: "inbox-done-\(sessionID)", sessionID: sessionID,
                              machineID: session.machineID, kind: .turnCompleted, title: session.title))
        case .error:
            if let index = sessionRows.firstIndex(where: { $0.id == sessionID }) {
                sessionRows[index].group = .recent
            }
            appendInbox(.init(id: "inbox-fail-\(sessionID)", sessionID: sessionID,
                              machineID: session.machineID, kind: .failed, title: session.title))
            broadcastState()
        default:
            break
        }
    }

    private func appendInbox(_ item: InboxItem) {
        guard !inboxItems.contains(where: { $0.id == item.id }) else { return }
        inboxItems.append(item)
        for cont in inboxSubs.values { cont.yield(inboxItems) }
    }

    private func sleepTicks(_ ms: Int) async {
        let ns = UInt64(Double(ms) * 1_000_000 * tickScale)
        if ns > 0 { try? await Task.sleep(nanoseconds: ns) }
    }
}
```

注意：`AgentItem.userMessage/.assistantMessage` 的关联值签名以 `V2Types.swift` 为准（`text:` + meta）；`AgentItemMeta()` 有默认空 init。若编译报关联值标签不符，对照 V2Types 修调用处，不改 V2Types。

- [ ] **Step 5: 跑测试**

Run: `cd ios && xcodegen generate && xcodebuild ... test 2>&1 | tail -5`
Expected: `** TEST SUCCEEDED **`（含 Task 6 的解码测试）。

- [ ] **Step 6: Commit**

```bash
git add ios/AgentDeckMobile/DataSource ios/AgentDeckMobileTests/FixtureSessionSourceTests.swift
git commit -m "feat(ios): MobileSessionSource 协议与 FixtureSessionSource 回放引擎"
```

---

### Task 8: 机器列表屏 + 空态组件

**Files:**
- Create: `ios/AgentDeckMobile/Screens/MachineList/MachineListViewModel.swift`
- Create: `ios/AgentDeckMobile/Screens/MachineList/MachineListViewController.swift`
- Create: `ios/AgentDeckMobile/Screens/Shared/MobileEmptyStateView.swift`
- Modify: `ios/AgentDeckMobile/App/SceneDelegate.swift`（根控制器换成机器列表）
- Delete: `ios/AgentDeckMobile/App/PlaceholderViewController.swift`（测试里的 `Bundle(for:)` 改用 `MachineListViewController.self`）
- Test: `ios/AgentDeckMobileTests/MachineListViewModelTests.swift`

**Interfaces:**
- Consumes: `MobileSessionSource.machines()`
- Produces:
  - `@MainActor final class MachineListViewModel { init(source: MobileSessionSource); private(set) var machines: [MachineSummary]; var onUpdate: (() -> Void)?; func start() }`
  - `final class MachineListViewController: UIViewController { init(source: MobileSessionSource) }`（右上角两个 bar button：收件箱、配对，Task 14 前先留空动作）
  - `final class MobileEmptyStateView: UIView { init(title: String, subtitle: String?); func update(title:subtitle:) }`

- [ ] **Step 1: 失败测试**

`ios/AgentDeckMobileTests/MachineListViewModelTests.swift`：

```swift
import XCTest
@testable import AgentDeckMobile

@MainActor
final class MachineListViewModelTests: XCTestCase {
    func testLoadsMachinesFromFixture() async {
        let source = FixtureSessionSource(bundle: Bundle(for: MachineListViewController.self), tickScale: 0)
        let vm = MachineListViewModel(source: source)
        let updated = expectation(description: "updated")
        vm.onUpdate = { if !vm.machines.isEmpty { updated.fulfill() } }
        vm.start()
        await fulfillment(of: [updated], timeout: 2)
        XCTAssertEqual(vm.machines.count, 2)
        XCTAssertEqual(vm.machines.first?.name, "Mac Studio")
    }
}
```

- [ ] **Step 2: 确认编译失败**（`cannot find 'MachineListViewModel'`）

- [ ] **Step 3: 实现**

`MachineListViewModel.swift`：

```swift
import Foundation

@MainActor
final class MachineListViewModel {
    private let source: MobileSessionSource
    private(set) var machines: [MachineSummary] = []
    var onUpdate: (() -> Void)?
    private var task: Task<Void, Never>?

    init(source: MobileSessionSource) {
        self.source = source
    }

    func start() {
        task = Task { [weak self] in
            guard let stream = self?.source.machines() else { return }
            for await machines in stream {
                self?.machines = machines
                self?.onUpdate?()
            }
        }
    }

    deinit { task?.cancel() }
}
```

`MobileEmptyStateView.swift`：

```swift
import UIKit

/// 空列表 / 加载占位 / 错误提示三合一（设计文档第 9 节）。
final class MobileEmptyStateView: UIView {
    private let titleLabel = UILabel()
    private let subtitleLabel = UILabel()

    init(title: String, subtitle: String? = nil) {
        super.init(frame: .zero)
        titleLabel.font = .preferredFont(forTextStyle: .headline)
        titleLabel.textColor = DesignTokens.fg
        titleLabel.textAlignment = .center
        subtitleLabel.font = .preferredFont(forTextStyle: .subheadline)
        subtitleLabel.textColor = DesignTokens.fgMuted
        subtitleLabel.textAlignment = .center
        subtitleLabel.numberOfLines = 0
        let stack = UIStackView(arrangedSubviews: [titleLabel, subtitleLabel])
        stack.axis = .vertical
        stack.spacing = DesignTokens.sp2
        stack.translatesAutoresizingMaskIntoConstraints = false
        addSubview(stack)
        NSLayoutConstraint.activate([
            stack.centerXAnchor.constraint(equalTo: centerXAnchor),
            stack.centerYAnchor.constraint(equalTo: centerYAnchor),
            stack.leadingAnchor.constraint(greaterThanOrEqualTo: leadingAnchor, constant: DesignTokens.sp6),
            stack.trailingAnchor.constraint(lessThanOrEqualTo: trailingAnchor, constant: -DesignTokens.sp6),
        ])
        update(title: title, subtitle: subtitle)
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    func update(title: String, subtitle: String?) {
        titleLabel.text = title
        subtitleLabel.text = subtitle
        subtitleLabel.isHidden = subtitle == nil
    }
}
```

注意：`DesignTokens` 的颜色/间距成员名以生成文件 `ios/AgentDeckMobile/DesignTokens.swift` 为准（token key 与 macOS 版一致）。若 `fgMuted`/`sp2` 等名字不存在，打开生成文件选最接近的语义 token（例如次级文字色、4/8pt 间距），不要手改生成文件。

`MachineListViewController.swift`：

```swift
import UIKit

final class MachineListViewController: UIViewController {
    private let source: MobileSessionSource
    private let viewModel: MachineListViewModel
    private var collectionView: UICollectionView!
    private var dataSource: UICollectionViewDiffableDataSource<Int, String>!
    private let emptyView = MobileEmptyStateView(title: "还没有机器", subtitle: "用右上角「配对」把 Mac 接入")

    init(source: MobileSessionSource) {
        self.source = source
        self.viewModel = MachineListViewModel(source: source)
        super.init(nibName: nil, bundle: nil)
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    override func viewDidLoad() {
        super.viewDidLoad()
        title = "AgentDeck"
        view.backgroundColor = DesignTokens.bg
        navigationItem.rightBarButtonItems = [
            UIBarButtonItem(image: UIImage(systemName: "qrcode.viewfinder"), style: .plain,
                            target: self, action: #selector(openPairing)),
            UIBarButtonItem(image: UIImage(systemName: "tray"), style: .plain,
                            target: self, action: #selector(openInbox)),
        ]
        configureCollectionView()
        view.addSubview(emptyView)
        emptyView.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            emptyView.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            emptyView.centerYAnchor.constraint(equalTo: view.centerYAnchor),
            emptyView.widthAnchor.constraint(equalTo: view.widthAnchor),
            emptyView.heightAnchor.constraint(equalToConstant: 160),
        ])
        viewModel.onUpdate = { [weak self] in self?.applySnapshot() }
        viewModel.start()
        applySnapshot()
    }

    private func configureCollectionView() {
        var config = UICollectionLayoutListConfiguration(appearance: .insetGrouped)
        config.backgroundColor = DesignTokens.bg
        let layout = UICollectionViewCompositionalLayout.list(using: config)
        collectionView = UICollectionView(frame: .zero, collectionViewLayout: layout)
        collectionView.delegate = self
        collectionView.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(collectionView)
        NSLayoutConstraint.activate([
            collectionView.topAnchor.constraint(equalTo: view.topAnchor),
            collectionView.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            collectionView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            collectionView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
        ])
        let registration = UICollectionView.CellRegistration<UICollectionViewListCell, MachineSummary> { cell, _, machine in
            var content = UIListContentConfiguration.subtitleCell()
            content.text = machine.name
            let status = machine.isOnline ? "在线" : "离线"
            content.secondaryText = "\(status) · \(machine.activeSessionCount) 活跃会话"
            content.textProperties.color = DesignTokens.fg
            content.secondaryTextProperties.color = DesignTokens.fgMuted
            content.image = UIImage(systemName: "circle.fill")
            content.imageProperties.tintColor = machine.isOnline ? DesignTokens.accent : DesignTokens.fgMuted
            content.imageProperties.maximumSize = CGSize(width: 10, height: 10)
            cell.contentConfiguration = content
            var accessories: [UICellAccessory] = [.disclosureIndicator()]
            if machine.pendingApprovalCount > 0 {
                let badge = UILabel()
                badge.text = " \(machine.pendingApprovalCount) 待审批 "
                badge.font = .preferredFont(forTextStyle: .caption1)
                badge.textColor = DesignTokens.bg
                badge.backgroundColor = DesignTokens.accent
                badge.layer.cornerRadius = DesignTokens.radiusPill
                badge.layer.masksToBounds = true
                accessories.append(.customView(configuration: .init(customView: badge, placement: .trailing())))
            }
            cell.accessories = accessories
        }
        dataSource = UICollectionViewDiffableDataSource<Int, String>(collectionView: collectionView) {
            [weak self] collectionView, indexPath, machineID in
            guard let machine = self?.viewModel.machines.first(where: { $0.id == machineID }) else { return nil }
            return collectionView.dequeueConfiguredReusableCell(using: registration, for: indexPath, item: machine)
        }
    }

    private func applySnapshot() {
        var snapshot = NSDiffableDataSourceSnapshot<Int, String>()
        snapshot.appendSections([0])
        snapshot.appendItems(viewModel.machines.map(\.id))
        snapshot.reconfigureItems(viewModel.machines.map(\.id).filter { id in
            dataSource.snapshot().itemIdentifiers.contains(id)
        })
        dataSource.apply(snapshot, animatingDifferences: false)
        emptyView.isHidden = !viewModel.machines.isEmpty
    }

    @objc private func openPairing() { /* Task 14 接 PairingViewController */ }
    @objc private func openInbox() { /* Task 14 接 InboxViewController */ }
}

extension MachineListViewController: UICollectionViewDelegate {
    func collectionView(_ collectionView: UICollectionView, didSelectItemAt indexPath: IndexPath) {
        collectionView.deselectItem(at: indexPath, animated: true)
        guard let machineID = dataSource.itemIdentifier(for: indexPath) else { return }
        navigationController?.pushViewController(
            SessionListViewController(source: source, machineID: machineID), animated: true)
    }
}
```

`SessionListViewController` 在 Task 9 才有——本任务先建一个最小占位（同文件夹 `Screens/SessionList/SessionListViewController.swift`，仅 `init(source:machineID:)` + 空视图 + title），Task 9 覆写为完整实现。SceneDelegate 根控制器改为：

```swift
window.rootViewController = UINavigationController(
    rootViewController: MachineListViewController(source: FixtureSessionSource()))
```

删除 `PlaceholderViewController.swift`，把 Task 6/7 测试里的 `Bundle(for: PlaceholderViewController.self)` 全部改为 `Bundle(for: MachineListViewController.self)`。

- [ ] **Step 4: 测试 + 模拟器目检**

Run: `cd ios && xcodegen generate && xcodebuild ... test 2>&1 | tail -5` → `** TEST SUCCEEDED **`
Run: `xcrun simctl boot "iPhone 17" 2>/dev/null; xcodebuild ... build && xcrun simctl install booted <DerivedData 下的 .app 路径> && xcrun simctl launch booted dev.agentdeck.AgentDeckMobile`
Expected: 机器列表显示 Mac Studio（在线，2 活跃会话，1 待审批 badge）与 MacBook Air（离线）。

- [ ] **Step 5: Commit**

```bash
git add ios/AgentDeckMobile ios/AgentDeckMobileTests
git commit -m "feat(ios): 机器列表屏 + 空态组件"
```

---

### Task 9: 会话列表屏

**Files:**
- Create/覆写: `ios/AgentDeckMobile/Screens/SessionList/SessionListViewModel.swift`、`ios/AgentDeckMobile/Screens/SessionList/SessionListViewController.swift`
- Test: `ios/AgentDeckMobileTests/SessionListViewModelTests.swift`

**Interfaces:**
- Consumes: `MobileSessionSource.sessions(machineID:)`、`vendorDisplayName(_:)`
- Produces:
  - `@MainActor final class SessionListViewModel { init(source: MobileSessionSource, machineID: String); private(set) var groups: [(group: SessionGroup, sessions: [SessionSummary])]; var onUpdate: (() -> Void)?; func start() }`（分组顺序固定 waitingApproval → active → recent，空组不出现）
  - `final class SessionListViewController: UIViewController { init(source: MobileSessionSource, machineID: String) }`，点击行 push `SessionDetailViewController(source:sessionID:title:)`（Task 10 提供；本任务先 push 占位，同 Task 8 的做法）

- [ ] **Step 1: 失败测试**

```swift
import XCTest
@testable import AgentDeckMobile

@MainActor
final class SessionListViewModelTests: XCTestCase {
    func testGroupsOrderedAndFiltered() async {
        let source = FixtureSessionSource(bundle: Bundle(for: MachineListViewController.self), tickScale: 0)
        let vm = SessionListViewModel(source: source, machineID: "mac-studio")
        let updated = expectation(description: "updated")
        vm.onUpdate = { if !vm.groups.isEmpty { updated.fulfill() } }
        vm.start()
        await fulfillment(of: [updated], timeout: 2)
        XCTAssertEqual(vm.groups.map(\.group), [.waitingApproval, .active, .recent])
        XCTAssertEqual(vm.groups.first?.sessions.map(\.id), ["sess-approval-01"])
    }
}
```

- [ ] **Step 2: 实现 view model**

```swift
import Foundation

@MainActor
final class SessionListViewModel {
    private let source: MobileSessionSource
    private let machineID: String
    private(set) var groups: [(group: SessionGroup, sessions: [SessionSummary])] = []
    var onUpdate: (() -> Void)?
    private var task: Task<Void, Never>?

    init(source: MobileSessionSource, machineID: String) {
        self.source = source
        self.machineID = machineID
    }

    func start() {
        task = Task { [weak self] in
            guard let self else { return }
            for await sessions in source.sessions(machineID: machineID) {
                groups = [SessionGroup.waitingApproval, .active, .recent].compactMap { group in
                    let matched = sessions.filter { $0.group == group }
                    return matched.isEmpty ? nil : (group, matched)
                }
                onUpdate?()
            }
        }
    }

    deinit { task?.cancel() }
}
```

- [ ] **Step 3: 实现 VC**

`ios/AgentDeckMobile/Screens/SessionList/SessionListViewController.swift`（覆写 Task 8 的占位）：

```swift
import UIKit

final class SessionListViewController: UIViewController {
    private let source: MobileSessionSource
    private let viewModel: SessionListViewModel
    private var collectionView: UICollectionView!
    private var dataSource: UICollectionViewDiffableDataSource<SessionGroup, String>!
    private let emptyView = MobileEmptyStateView(title: "这台机器还没有会话", subtitle: nil)

    init(source: MobileSessionSource, machineID: String) {
        self.source = source
        self.viewModel = SessionListViewModel(source: source, machineID: machineID)
        super.init(nibName: nil, bundle: nil)
        title = "会话"
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = DesignTokens.bg
        configureCollectionView()
        view.addSubview(emptyView)
        emptyView.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            emptyView.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            emptyView.centerYAnchor.constraint(equalTo: view.centerYAnchor),
            emptyView.widthAnchor.constraint(equalTo: view.widthAnchor),
            emptyView.heightAnchor.constraint(equalToConstant: 160),
        ])
        viewModel.onUpdate = { [weak self] in self?.applySnapshot() }
        viewModel.start()
        applySnapshot()
    }

    private func headerTitle(_ group: SessionGroup) -> String {
        switch group {
        case .waitingApproval: "等待审批"
        case .active: "活跃"
        case .recent: "最近"
        }
    }

    private func session(for id: String) -> SessionSummary? {
        for (_, sessions) in viewModel.groups {
            if let match = sessions.first(where: { $0.id == id }) { return match }
        }
        return nil
    }

    private func configureCollectionView() {
        var config = UICollectionLayoutListConfiguration(appearance: .insetGrouped)
        config.backgroundColor = DesignTokens.bg
        config.headerMode = .supplementary
        let layout = UICollectionViewCompositionalLayout.list(using: config)
        collectionView = UICollectionView(frame: .zero, collectionViewLayout: layout)
        collectionView.delegate = self
        collectionView.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(collectionView)
        NSLayoutConstraint.activate([
            collectionView.topAnchor.constraint(equalTo: view.topAnchor),
            collectionView.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            collectionView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            collectionView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
        ])
        let cellReg = UICollectionView.CellRegistration<UICollectionViewListCell, SessionSummary> { cell, _, session in
            var content = UIListContentConfiguration.subtitleCell()
            content.text = session.title
            content.secondaryText = "\(vendorDisplayName(session.agentKind)) · \(session.cwd)"
            content.textProperties.color = DesignTokens.fg
            content.secondaryTextProperties.color = DesignTokens.fgMuted   // cwd 灰字（COMPONENTS.md）
            cell.contentConfiguration = content
            cell.accessories = [.disclosureIndicator()]
        }
        let headerReg = UICollectionView.SupplementaryRegistration<UICollectionViewListCell>(
            elementKind: UICollectionView.elementKindSectionHeader
        ) { [weak self] header, _, indexPath in
            guard let self else { return }
            let group = dataSource.snapshot().sectionIdentifiers[indexPath.section]
            var content = UIListContentConfiguration.groupedHeader()
            content.text = headerTitle(group)
            header.contentConfiguration = content
        }
        dataSource = UICollectionViewDiffableDataSource<SessionGroup, String>(collectionView: collectionView) {
            [weak self] collectionView, indexPath, sessionID in
            guard let session = self?.session(for: sessionID) else { return nil }
            return collectionView.dequeueConfiguredReusableCell(using: cellReg, for: indexPath, item: session)
        }
        dataSource.supplementaryViewProvider = { collectionView, kind, indexPath in
            collectionView.dequeueConfiguredReusableSupplementary(using: headerReg, for: indexPath)
        }
    }

    private func applySnapshot() {
        var snapshot = NSDiffableDataSourceSnapshot<SessionGroup, String>()
        for (group, sessions) in viewModel.groups {
            snapshot.appendSections([group])
            snapshot.appendItems(sessions.map(\.id), toSection: group)
        }
        let existing = Set(dataSource.snapshot().itemIdentifiers)
        snapshot.reconfigureItems(snapshot.itemIdentifiers.filter(existing.contains))
        dataSource.apply(snapshot, animatingDifferences: false)
        emptyView.isHidden = !viewModel.groups.isEmpty
    }
}

extension SessionListViewController: UICollectionViewDelegate {
    func collectionView(_ collectionView: UICollectionView, didSelectItemAt indexPath: IndexPath) {
        collectionView.deselectItem(at: indexPath, animated: true)
        guard let sessionID = dataSource.itemIdentifier(for: indexPath),
              let session = session(for: sessionID) else { return }
        // Task 10 前 SessionDetailViewController 尚不存在，先 push 占位 VC；
        // Task 10 落地后改为：
        // SessionDetailViewController(source: source, sessionID: session.id, title: session.title)
        let placeholder = UIViewController()
        placeholder.view.backgroundColor = DesignTokens.bg
        placeholder.title = session.title
        navigationController?.pushViewController(placeholder, animated: true)
    }
}
```

- [ ] **Step 4: 测试 + 目检 + Commit**

Run: `cd ios && xcodegen generate && xcodebuild ... test 2>&1 | tail -5` → `** TEST SUCCEEDED **`；模拟器进入 Mac Studio 应看到三组四行。

```bash
git add ios/AgentDeckMobile/Screens/SessionList ios/AgentDeckMobileTests/SessionListViewModelTests.swift
git commit -m "feat(ios): 会话列表屏（等待审批/活跃/最近分组）"
```

---

### Task 10: 会话详情屏——collection view 骨架与文本 cell

**Files:**
- Create/覆写: `ios/AgentDeckMobile/Screens/SessionDetail/SessionDetailViewModel.swift`、`ios/AgentDeckMobile/Screens/SessionDetail/SessionDetailViewController.swift`
- Create: `ios/AgentDeckMobile/Screens/SessionDetail/Cells/UserPromptCell.swift`、`ios/AgentDeckMobile/Screens/SessionDetail/Cells/AssistantTextCell.swift`、`ios/AgentDeckMobile/Screens/SessionDetail/MarkdownRenderer.swift`
- Test: `ios/AgentDeckMobileTests/SessionDetailViewModelTests.swift`

**Interfaces:**
- Consumes: `MobileSessionSource.events(sessionID:)`、Core 的 `AgentItemReducer`/`AgentItemStore`/`makeConversationTurns`/`ConversationDisplayRowBuilder`
- Produces:
  - `@MainActor final class SessionDetailViewModel { init(source: MobileSessionSource, sessionID: String); private(set) var rows: [ConversationDisplayRow]; private(set) var pendingApproval: ActionRequest?; private(set) var approvalState: ApprovalState; private(set) var errorText: String?; private(set) var isStreaming: Bool; var onUpdate: (() -> Void)?; func start(); func resolveApproval(approve: Bool); func sendPrompt(_ text: String) }`
  - `enum ApprovalState: Equatable { case none, pending, approved, denied }`
  - `enum MarkdownRenderer { static func attributed(_ text: String, color: UIColor) -> NSAttributedString }`
  - `SessionDetailViewController(source:sessionID:title:)`：渲染路径按 `row.role` 与 `row.item.kind`（数据驱动）分派 cell，不按 agentKind 分支（N2）。

- [ ] **Step 1: 失败测试**

```swift
import XCTest
import AgentDeckCore
@testable import AgentDeckMobile

@MainActor
final class SessionDetailViewModelTests: XCTestCase {
    private func makeVM(_ sessionID: String) -> SessionDetailViewModel {
        let source = FixtureSessionSource(bundle: Bundle(for: MachineListViewController.self), tickScale: 0)
        return SessionDetailViewModel(source: source, sessionID: sessionID)
    }

    func testCodexStreamProducesRows() async {
        let vm = makeVM("sess-codex-01")
        let done = expectation(description: "stream done")
        vm.onUpdate = { if !vm.isStreaming { done.fulfill() } }
        vm.start()
        await fulfillment(of: [done], timeout: 3)
        // i1 user + i2 reasoning + i3 shell + i4 assistant(累积成 1 行) + i5 diff = 5 行
        XCTAssertEqual(vm.rows.count, 5)
        XCTAssertEqual(vm.rows.first?.role, .userPrompt)
        // 三次 i4 事件应累积在同一行（cumulative 语义）
        let messageRows = vm.rows.filter { $0.item.kind == "message" }
        XCTAssertEqual(messageRows.count, 1)
        XCTAssertTrue(messageRows[0].item.text.hasSuffix("避免雪崩重连。"))
    }

    func testApprovalSurfacesAndResolves() async {
        let vm = makeVM("sess-approval-01")
        let pending = expectation(description: "pending approval")
        vm.onUpdate = { if vm.approvalState == .pending { pending.fulfill() } }
        vm.start()
        await fulfillment(of: [pending], timeout: 3)
        XCTAssertEqual(vm.pendingApproval?.summary, "uv run alembic upgrade head")
        let done = expectation(description: "stream done after approve")
        vm.onUpdate = { if !vm.isStreaming { done.fulfill() } }
        vm.resolveApproval(approve: true)
        await fulfillment(of: [done], timeout: 3)
        XCTAssertEqual(vm.approvalState, .approved)
        XCTAssertEqual(vm.rows.count, 3) // user + shell + assistant
    }

    func testErrorSurfaces() async {
        let vm = makeVM("sess-failed-01")
        let errored = expectation(description: "error surfaced")
        vm.onUpdate = { if vm.errorText != nil { errored.fulfill() } }
        vm.start()
        await fulfillment(of: [errored], timeout: 3)
        XCTAssertTrue(vm.errorText?.contains("peer dependency") == true)
    }
}
```

- [ ] **Step 2: 实现 view model**

```swift
import Foundation
import AgentDeckCore

enum ApprovalState: Equatable { case none, pending, approved, denied }

@MainActor
final class SessionDetailViewModel {
    private let source: MobileSessionSource
    let sessionID: String
    private(set) var rows: [ConversationDisplayRow] = []
    private(set) var pendingApproval: ActionRequest?
    private(set) var approvalState: ApprovalState = .none
    private(set) var errorText: String?
    private(set) var isStreaming = true
    var onUpdate: (() -> Void)?
    private var store = AgentItemStore()
    private var autoItemSeq = 0
    private var task: Task<Void, Never>?

    init(source: MobileSessionSource, sessionID: String) {
        self.source = source
        self.sessionID = sessionID
    }

    func start() {
        task = Task { [weak self] in
            guard let self else { return }
            for await element in source.events(sessionID: sessionID) {
                handle(element)
            }
            isStreaming = false
            onUpdate?()
        }
    }

    func resolveApproval(approve: Bool) {
        guard let request = pendingApproval else { return }
        approvalState = approve ? .approved : .denied
        onUpdate?()
        Task { [weak self] in
            guard let self else { return }
            await source.resolveApproval(sessionID: sessionID, requestID: request.requestId, approve: approve)
        }
    }

    func sendPrompt(_ text: String) {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        isStreaming = true
        Task { [weak self] in
            guard let self else { return }
            await source.sendPrompt(sessionID: sessionID, text: trimmed)
            // FixtureSessionSource 会在同一 events 流上推送回声（若流已结束，
            // 重新订阅一次以接收后续事件）。
            start()
        }
    }

    private func handle(_ element: SessionStreamElement) {
        switch element.event {
        case .agentItem(_, _, _, let item):
            let itemId = element.itemId ?? nextAutoItemId()
            AgentItemReducer.apply(item, itemId: itemId, into: &store)
        case .actionRequest(_, _, _, let request):
            pendingApproval = request
            approvalState = .pending
        case .error(_, let protocolError):
            errorText = protocolError.message
        case .turnComplete:
            isStreaming = false
        case .sessionStarted, .sessionCapabilities, .vendorControl, .vendorPanelEvent:
            break
        }
        rows = ConversationDisplayRowBuilder.rows(from: makeConversationTurns(from: store.items))
        onUpdate?()
    }

    private func nextAutoItemId() -> String {
        autoItemSeq += 1
        return "auto-\(autoItemSeq)"
    }

    deinit { task?.cancel() }
}
```

- [ ] **Step 3: MarkdownRenderer 与两个文本 cell**

`MarkdownRenderer.swift`：

```swift
import UIKit

/// 第一期用系统 AttributedString(markdown:)（设计文档第 6 节取舍），
/// 不移植 macOS 的 AppKit builder。
enum MarkdownRenderer {
    static func attributed(_ text: String, color: UIColor) -> NSAttributedString {
        var attributed = (try? AttributedString(
            markdown: text,
            options: .init(interpretedSyntax: .inlineOnlyPreservingWhitespace)
        )) ?? AttributedString(text)
        attributed.foregroundColor = color
        attributed.font = .preferredFont(forTextStyle: .body)
        return NSAttributedString(attributed)
    }
}
```

`UserPromptCell.swift`（右侧对齐胶囊气泡，设计系统胶囊语义）：

```swift
import UIKit
import AgentDeckCore

final class UserPromptCell: UICollectionViewCell {
    private let bubble = UIView()
    private let label = UILabel()

    override init(frame: CGRect) {
        super.init(frame: frame)
        bubble.backgroundColor = DesignTokens.bgRaised
        bubble.layer.cornerRadius = DesignTokens.radiusMd
        label.numberOfLines = 0
        label.font = .preferredFont(forTextStyle: .body)
        label.textColor = DesignTokens.fg
        bubble.translatesAutoresizingMaskIntoConstraints = false
        label.translatesAutoresizingMaskIntoConstraints = false
        contentView.addSubview(bubble)
        bubble.addSubview(label)
        NSLayoutConstraint.activate([
            bubble.topAnchor.constraint(equalTo: contentView.topAnchor, constant: DesignTokens.sp3),
            bubble.bottomAnchor.constraint(equalTo: contentView.bottomAnchor, constant: -DesignTokens.sp1),
            bubble.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -DesignTokens.sp4),
            bubble.leadingAnchor.constraint(greaterThanOrEqualTo: contentView.leadingAnchor, constant: 48),
            label.topAnchor.constraint(equalTo: bubble.topAnchor, constant: DesignTokens.sp2),
            label.bottomAnchor.constraint(equalTo: bubble.bottomAnchor, constant: -DesignTokens.sp2),
            label.leadingAnchor.constraint(equalTo: bubble.leadingAnchor, constant: DesignTokens.sp3),
            label.trailingAnchor.constraint(equalTo: bubble.trailingAnchor, constant: -DesignTokens.sp3),
        ])
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    func configure(with item: UIItem) {
        label.text = item.text
    }
}
```

`AssistantTextCell.swift`（左对齐 markdown；`message` 与 `plan` 共用）：

```swift
import UIKit
import AgentDeckCore

final class AssistantTextCell: UICollectionViewCell {
    private let label = UILabel()

    override init(frame: CGRect) {
        super.init(frame: frame)
        label.numberOfLines = 0
        label.translatesAutoresizingMaskIntoConstraints = false
        contentView.addSubview(label)
        NSLayoutConstraint.activate([
            label.topAnchor.constraint(equalTo: contentView.topAnchor, constant: DesignTokens.sp2),
            label.bottomAnchor.constraint(equalTo: contentView.bottomAnchor, constant: -DesignTokens.sp2),
            label.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: DesignTokens.sp4),
            label.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -DesignTokens.sp4),
        ])
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    func configure(with item: UIItem) {
        label.attributedText = MarkdownRenderer.attributed(item.text, color: DesignTokens.fg)
    }
}
```

- [ ] **Step 4: 实现 VC 骨架**

`SessionDetailViewController.swift`：

```swift
import UIKit
import AgentDeckCore

final class SessionDetailViewController: UIViewController {
    private enum Section: Hashable { case conversation }

    private let viewModel: SessionDetailViewModel
    private var collectionView: UICollectionView!
    private var dataSource: UICollectionViewDiffableDataSource<Section, String>!

    init(source: MobileSessionSource, sessionID: String, title: String) {
        self.viewModel = SessionDetailViewModel(source: source, sessionID: sessionID)
        super.init(nibName: nil, bundle: nil)
        self.title = title
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = DesignTokens.bg
        configureCollectionView()
        viewModel.onUpdate = { [weak self] in self?.applySnapshot() }
        viewModel.start()
    }

    private func configureCollectionView() {
        var config = UICollectionLayoutListConfiguration(appearance: .plain)
        config.backgroundColor = DesignTokens.bg
        config.showsSeparators = false
        let layout = UICollectionViewCompositionalLayout.list(using: config)
        collectionView = UICollectionView(frame: .zero, collectionViewLayout: layout)
        collectionView.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(collectionView)
        NSLayoutConstraint.activate([
            collectionView.topAnchor.constraint(equalTo: view.topAnchor),
            collectionView.bottomAnchor.constraint(equalTo: view.keyboardLayoutGuide.topAnchor),
            collectionView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            collectionView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
        ])
        let userReg = UICollectionView.CellRegistration<UserPromptCell, UIItem> { cell, _, item in
            cell.configure(with: item)
        }
        let textReg = UICollectionView.CellRegistration<AssistantTextCell, UIItem> { cell, _, item in
            cell.configure(with: item)
        }
        dataSource = UICollectionViewDiffableDataSource<Section, String>(collectionView: collectionView) {
            [weak self] collectionView, indexPath, rowID in
            guard let self, let row = self.viewModel.rows.first(where: { $0.id == rowID }) else { return nil }
            // 渲染路径由 row 数据（role / item.kind）决定，不看 agentKind（N2）。
            switch row.role {
            case .userPrompt:
                return collectionView.dequeueConfiguredReusableCell(using: userReg, for: indexPath, item: row.item)
            case .assistantItem:
                return collectionView.dequeueConfiguredReusableCell(using: textReg, for: indexPath, item: row.item)
            }
        }
    }

    private func applySnapshot() {
        var snapshot = NSDiffableDataSourceSnapshot<Section, String>()
        snapshot.appendSections([.conversation])
        let ids = viewModel.rows.map(\.id)
        snapshot.appendItems(ids, toSection: .conversation)
        let existing = Set(dataSource.snapshot().itemIdentifiers)
        snapshot.reconfigureItems(ids.filter(existing.contains))
        dataSource.apply(snapshot, animatingDifferences: false)
        if let last = ids.last, let indexPath = dataSource.indexPath(for: last) {
            collectionView.scrollToItem(at: indexPath, at: .bottom, animated: false)
        }
    }
}
```

同时把 Task 9 里 didSelect 的占位替换为真实 push：`SessionDetailViewController(source: source, sessionID: session.id, title: session.title)`。

- [ ] **Step 5: 测试 + 目检 + Commit**

Run: `cd ios && xcodegen generate && xcodebuild ... test 2>&1 | tail -5` → `** TEST SUCCEEDED **`；模拟器打开「重构 IPC 重连逻辑」应看到 assistant 文本分三步流式变长（reasoning/shell/diff 行此时以纯文本 cell 显示，Task 11 换折叠样式）。

```bash
git add ios/AgentDeckMobile/Screens/SessionDetail ios/AgentDeckMobileTests/SessionDetailViewModelTests.swift ios/AgentDeckMobile/Screens/SessionList
git commit -m "feat(ios): 会话详情屏骨架与流式文本渲染"
```

---

### Task 11: 会话详情屏——折叠 cell 与错误横幅

**Files:**
- Create: `ios/AgentDeckMobile/Screens/SessionDetail/Cells/CollapsibleItemCell.swift`
- Create: `ios/AgentDeckMobile/Screens/SessionDetail/ErrorBannerView.swift`
- Modify: `SessionDetailViewController.swift`（kind 分派 + 折叠状态 + 横幅）
- Test: `ios/AgentDeckMobileTests/CollapsiblePresentationTests.swift`

**Interfaces:**
- Consumes: Core 的 `ToolPresentation.outputLabel(_:noun:)`、`UIItem` 字段
- Produces:
  - `struct CollapsiblePresentation { let title: String; let detail: String?; let body: String?; let bodyIsMono: Bool }` + `static func make(from item: UIItem) -> CollapsiblePresentation?`（kind ∈ reasoning/shell/toolCall/fileEdit 返回值，其余 nil——纯函数，可单测）
  - `final class CollapsibleItemCell: UICollectionViewCell { func configure(with presentation: CollapsiblePresentation, expanded: Bool); var onToggle: (() -> Void)? }`
  - `final class ErrorBannerView: UIView { func show(message: String); func hide() }`

- [ ] **Step 1: 失败测试（纯 presentation 函数）**

```swift
import XCTest
import AgentDeckCore
@testable import AgentDeckMobile

final class CollapsiblePresentationTests: XCTestCase {
    func testShellPresentation() {
        var item = UIItem(id: "s", lifecycle: "completed", kind: "shell")
        item.command = "bun update"
        item.statusName = "failed"
        item.exitCode = 1
        item.durationMs = 9200
        let p = CollapsiblePresentation.make(from: item)
        XCTAssertEqual(p?.title, "$ bun update")
        XCTAssertEqual(p?.detail, "failed · exit 1 · 9.2s")
        XCTAssertEqual(p?.bodyIsMono, true)
    }

    func testReasoningDefaultsCollapsedWithBody() {
        var item = UIItem(id: "r", lifecycle: "completed", kind: "reasoning")
        item.text = "思考过程"
        let p = CollapsiblePresentation.make(from: item)
        XCTAssertEqual(p?.title, "Reasoning")
        XCTAssertEqual(p?.body, "思考过程")
    }

    func testMessageKindIsNotCollapsible() {
        let item = UIItem(id: "m", lifecycle: "completed", kind: "message")
        XCTAssertNil(CollapsiblePresentation.make(from: item))
    }
}
```

- [ ] **Step 2: 实现 CollapsiblePresentation + cell**

`CollapsibleItemCell.swift`（同文件放 presentation 纯函数与 cell）：

```swift
import UIKit
import AgentDeckCore

struct CollapsiblePresentation: Equatable {
    let title: String
    let detail: String?
    let body: String?
    let bodyIsMono: Bool

    /// 与 macOS 端折叠规范一致：reasoning / shell / toolCall / fileEdit 折叠，
    /// 其余 kind 不归本 cell 管。纯函数，便于单测。
    static func make(from item: UIItem) -> CollapsiblePresentation? {
        switch item.kind {
        case "reasoning":
            return CollapsiblePresentation(title: "Reasoning", detail: nil,
                                           body: item.text.isEmpty ? nil : item.text, bodyIsMono: false)
        case "shell":
            var parts: [String] = []
            if !item.statusName.isEmpty { parts.append(item.statusName) }
            if let exit = item.exitCode { parts.append("exit \(exit)") }
            if let ms = item.durationMs { parts.append(String(format: "%.1fs", Double(ms) / 1000)) }
            return CollapsiblePresentation(
                title: "$ \(item.command)",
                detail: parts.isEmpty ? nil : parts.joined(separator: " · "),
                body: item.output.isEmpty ? nil : item.output,
                bodyIsMono: true)
        case "toolCall":
            let body = [item.arguments, item.result].filter { !$0.isEmpty }.joined(separator: "\n→ ")
            return CollapsiblePresentation(title: item.tool.isEmpty ? "Tool call" : item.tool,
                                           detail: nil, body: body.isEmpty ? nil : body, bodyIsMono: true)
        case "fileEdit":
            return CollapsiblePresentation(title: item.path.isEmpty ? "Diff" : item.path,
                                           detail: item.statusName.isEmpty ? nil : item.statusName,
                                           body: item.diff.isEmpty ? nil : item.diff, bodyIsMono: true)
        default:
            return nil
        }
    }
}

final class CollapsibleItemCell: UICollectionViewCell {
    private let headerButton = UIButton(type: .system)
    private let detailLabel = UILabel()
    private let bodyLabel = UILabel()
    private let container = UIStackView()
    var onToggle: (() -> Void)?

    override init(frame: CGRect) {
        super.init(frame: frame)
        container.axis = .vertical
        container.spacing = DesignTokens.sp1
        container.translatesAutoresizingMaskIntoConstraints = false
        contentView.addSubview(container)
        NSLayoutConstraint.activate([
            container.topAnchor.constraint(equalTo: contentView.topAnchor, constant: DesignTokens.sp1),
            container.bottomAnchor.constraint(equalTo: contentView.bottomAnchor, constant: -DesignTokens.sp1),
            container.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: DesignTokens.sp4),
            container.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -DesignTokens.sp4),
        ])
        headerButton.contentHorizontalAlignment = .leading
        headerButton.titleLabel?.font = .monospacedSystemFont(ofSize: 13, weight: .medium)
        headerButton.setTitleColor(DesignTokens.fgMuted, for: .normal)
        headerButton.addAction(UIAction { [weak self] _ in self?.onToggle?() }, for: .touchUpInside)
        detailLabel.font = .preferredFont(forTextStyle: .caption1)
        detailLabel.textColor = DesignTokens.fgMuted
        bodyLabel.numberOfLines = 0
        container.addArrangedSubview(headerButton)
        container.addArrangedSubview(detailLabel)
        container.addArrangedSubview(bodyLabel)
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    func configure(with presentation: CollapsiblePresentation, expanded: Bool) {
        let chevron = presentation.body == nil ? "" : (expanded ? "▾ " : "▸ ")
        headerButton.setTitle(chevron + presentation.title, for: .normal)
        detailLabel.text = presentation.detail
        detailLabel.isHidden = presentation.detail == nil
        bodyLabel.text = presentation.body
        bodyLabel.isHidden = !(expanded && presentation.body != nil)
        bodyLabel.font = presentation.bodyIsMono
            ? .monospacedSystemFont(ofSize: 12, weight: .regular)
            : .preferredFont(forTextStyle: .callout)
        bodyLabel.textColor = presentation.bodyIsMono ? DesignTokens.fgMuted : DesignTokens.fg
    }
}
```

`ErrorBannerView.swift`：

```swift
import UIKit

final class ErrorBannerView: UIView {
    private let label = UILabel()

    override init(frame: CGRect) {
        super.init(frame: frame)
        backgroundColor = DesignTokens.danger.withAlphaComponent(0.15)
        layer.cornerRadius = DesignTokens.radiusMd
        label.numberOfLines = 0
        label.font = .preferredFont(forTextStyle: .footnote)
        label.textColor = DesignTokens.danger
        label.translatesAutoresizingMaskIntoConstraints = false
        addSubview(label)
        NSLayoutConstraint.activate([
            label.topAnchor.constraint(equalTo: topAnchor, constant: DesignTokens.sp2),
            label.bottomAnchor.constraint(equalTo: bottomAnchor, constant: -DesignTokens.sp2),
            label.leadingAnchor.constraint(equalTo: leadingAnchor, constant: DesignTokens.sp3),
            label.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -DesignTokens.sp3),
        ])
        isHidden = true
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    func show(message: String) { label.text = message; isHidden = false }
    func hide() { isHidden = true }
}
```

（`DesignTokens.danger` 若生成 token 中叫别的名字——如 `error`/`red`——以生成文件为准。）

- [ ] **Step 3: 接入 VC**

`SessionDetailViewController` 修改点：

1. 新增 `private var expandedRowIDs: Set<String> = []`。
2. cellProvider 的 `.assistantItem` 分支改为：先 `CollapsiblePresentation.make(from: row.item)`，非 nil 走 `CollapsibleItemCell`（`expanded: expandedRowIDs.contains(rowID)`，`onToggle` 里 toggle 集合成员并 `snapshot.reconfigureItems([rowID])`），nil 走 `AssistantTextCell`。
3. `viewDidLoad` 加 `errorBanner`（`ErrorBannerView`），约束贴在 `collectionView` 顶部之上（`view.safeAreaLayoutGuide.topAnchor` + 左右 `sp4` 边距）；`applySnapshot()` 里同步 `viewModel.errorText` → `show/hide`。

- [ ] **Step 4: 测试 + 目检 + Commit**

Run: `cd ios && xcodegen generate && xcodebuild ... test 2>&1 | tail -5` → `** TEST SUCCEEDED **`；模拟器里 reasoning/shell/diff 默认折叠可展开；「升级依赖到最新版」会话顶部出现红色错误横幅。

```bash
git add ios/AgentDeckMobile/Screens/SessionDetail ios/AgentDeckMobileTests/CollapsiblePresentationTests.swift
git commit -m "feat(ios): 折叠 cell（reasoning/shell/tool/diff）与错误横幅"
```

---

### Task 12: 审批卡片

**Files:**
- Create: `ios/AgentDeckMobile/Screens/SessionDetail/Cells/ApprovalCardCell.swift`
- Modify: `SessionDetailViewController.swift`（新增 approval section）
- Test: `ios/AgentDeckMobileTests/ApprovalCardPresentationTests.swift`

**Interfaces:**
- Consumes: `SessionDetailViewModel.pendingApproval/approvalState/resolveApproval(approve:)`、`ActionRequest`（`requestId/kind/summary/vendor`）
- Produces:
  - `struct ApprovalCardPresentation { let summary: String; let vendorLine: String; let kindLabel: String; static func make(from request: ActionRequest) -> ApprovalCardPresentation }`
  - `final class ApprovalCardCell: UICollectionViewCell { func configure(with presentation: ApprovalCardPresentation, state: ApprovalState); var onApprove: (() -> Void)?; var onDeny: (() -> Void)? }`

- [ ] **Step 1: 失败测试**

```swift
import XCTest
import AgentDeckCore
@testable import AgentDeckMobile

final class ApprovalCardPresentationTests: XCTestCase {
    func testCodexVendorLineUsesVendorWords() {
        let request = ActionRequest(
            requestId: "r1", kind: .executeCommand, summary: "uv run alembic upgrade head",
            vendor: .codex(approvalPolicyAtDecision: .onRequest, sandboxAtDecision: .workspaceWrite, canPersist: true))
        let p = ApprovalCardPresentation.make(from: request)
        XCTAssertEqual(p.summary, "uv run alembic upgrade head")
        // vendor 原词：rawValue 原样透出，不翻译不改写
        XCTAssertTrue(p.vendorLine.contains(CodexApprovalPolicy.onRequest.rawValue))
        XCTAssertTrue(p.vendorLine.contains(CodexSandboxMode.workspaceWrite.rawValue))
    }

    func testClaudeCodeVendorLine() {
        let request = ActionRequest(
            requestId: "r2", kind: .editFiles, summary: "写入 3 个文件",
            vendor: .claudeCode(permissionModeAtDecision: .acceptEdits, toolName: "Write"))
        let p = ApprovalCardPresentation.make(from: request)
        XCTAssertTrue(p.vendorLine.contains(ClaudeCodePermissionMode.acceptEdits.rawValue))
        XCTAssertTrue(p.vendorLine.contains("Write"))
    }
}
```

（`CodexApprovalPolicy.onRequest`、`ClaudeCodePermissionMode.acceptEdits` 的 case 名以 V2Types 为准，测试编译不过就对照改测试里的 case 名，断言逻辑不变。）

- [ ] **Step 2: 实现**

`ApprovalCardCell.swift`：

```swift
import UIKit
import AgentDeckCore

struct ApprovalCardPresentation: Equatable {
    let summary: String
    let vendorLine: String
    let kindLabel: String

    static func make(from request: ActionRequest) -> ApprovalCardPresentation {
        let vendorLine: String
        switch request.vendor {
        case .codex(let policy, let sandbox, let canPersist):
            vendorLine = "codex · \(policy.rawValue) · \(sandbox.rawValue)"
                + (canPersist ? " · can persist" : "")
        case .claudeCode(let mode, let toolName):
            vendorLine = "claude code · \(mode.rawValue) · \(toolName)"
        }
        let kindLabel: String = switch request.kind {
        case .executeCommand: "执行命令"
        case .editFiles: "编辑文件"
        case .grantExtraPermission: "授予额外权限"
        }
        return ApprovalCardPresentation(summary: request.summary, vendorLine: vendorLine, kindLabel: kindLabel)
    }
}

final class ApprovalCardCell: UICollectionViewCell {
    private let kindLabel = UILabel()
    private let summaryLabel = UILabel()
    private let vendorLabel = UILabel()
    private let approveButton = UIButton(configuration: .filled())
    private let denyButton = UIButton(configuration: .gray())
    private let stateLabel = UILabel()
    var onApprove: (() -> Void)?
    var onDeny: (() -> Void)?

    override init(frame: CGRect) {
        super.init(frame: frame)
        let card = UIStackView()
        card.axis = .vertical
        card.spacing = DesignTokens.sp2
        card.isLayoutMarginsRelativeArrangement = true
        card.layoutMargins = .init(top: DesignTokens.sp3, left: DesignTokens.sp3,
                                   bottom: DesignTokens.sp3, right: DesignTokens.sp3)
        card.backgroundColor = DesignTokens.bgRaised
        card.layer.cornerRadius = DesignTokens.radiusLg
        card.layer.borderWidth = 1
        card.layer.borderColor = DesignTokens.accent.cgColor
        card.translatesAutoresizingMaskIntoConstraints = false
        contentView.addSubview(card)
        NSLayoutConstraint.activate([
            card.topAnchor.constraint(equalTo: contentView.topAnchor, constant: DesignTokens.sp2),
            card.bottomAnchor.constraint(equalTo: contentView.bottomAnchor, constant: -DesignTokens.sp2),
            card.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: DesignTokens.sp4),
            card.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -DesignTokens.sp4),
        ])
        kindLabel.font = .preferredFont(forTextStyle: .caption1)
        kindLabel.textColor = DesignTokens.accent
        summaryLabel.font = .monospacedSystemFont(ofSize: 14, weight: .medium)
        summaryLabel.textColor = DesignTokens.fg
        summaryLabel.numberOfLines = 0
        vendorLabel.font = .preferredFont(forTextStyle: .caption1)
        vendorLabel.textColor = DesignTokens.fgMuted
        stateLabel.font = .preferredFont(forTextStyle: .subheadline)
        approveButton.setTitle("Approve", for: .normal)
        approveButton.addAction(UIAction { [weak self] _ in self?.onApprove?() }, for: .touchUpInside)
        denyButton.setTitle("Deny", for: .normal)
        denyButton.addAction(UIAction { [weak self] _ in self?.onDeny?() }, for: .touchUpInside)
        let buttons = UIStackView(arrangedSubviews: [approveButton, denyButton])
        buttons.axis = .horizontal
        buttons.spacing = DesignTokens.sp2
        buttons.distribution = .fillEqually
        [kindLabel, summaryLabel, vendorLabel, buttons, stateLabel].forEach(card.addArrangedSubview)
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    func configure(with presentation: ApprovalCardPresentation, state: ApprovalState) {
        kindLabel.text = presentation.kindLabel
        summaryLabel.text = presentation.summary
        vendorLabel.text = presentation.vendorLine
        let decided = state == .approved || state == .denied
        approveButton.isHidden = decided
        denyButton.isHidden = decided
        stateLabel.isHidden = !decided
        stateLabel.text = state == .approved ? "已批准 ✓" : "已拒绝 ✕"
        stateLabel.textColor = state == .approved ? DesignTokens.accent : DesignTokens.fgMuted
    }
}
```

- [ ] **Step 3: 接入 VC**

`SessionDetailViewController` 修改点：

1. `Section` 加 case `approval`；approval item identifier 用固定串 `"approval-card"`。
2. `applySnapshot()`：当 `viewModel.approvalState != .none` 时 append `.approval` section + `"approval-card"` item（放在 conversation 之后），并把它加进 reconfigure 列表（状态变化时刷新卡片）。
3. cellProvider 遇到 `"approval-card"` 用 `ApprovalCardCell`，`configure(with: ApprovalCardPresentation.make(from: viewModel.pendingApproval!), state: viewModel.approvalState)`，`onApprove/onDeny` 调 `viewModel.resolveApproval(approve:)`。

- [ ] **Step 4: 测试 + 目检 + Commit**

Run: 同前 `xcodebuild ... test` → `** TEST SUCCEEDED **`；模拟器打开「运行数据库迁移脚本」：进场即见审批卡（vendor 原词 `codex · on-request · workspace-write · can persist`），点 Approve 后卡片变「已批准 ✓」、流继续到 turnComplete，会话列表分组同步从「等待审批」挪到「活跃」。

```bash
git add ios/AgentDeckMobile/Screens/SessionDetail ios/AgentDeckMobileTests/ApprovalCardPresentationTests.swift
git commit -m "feat(ios): 审批卡片（vendor 原词 + approve/deny 假状态机）"
```

---

### Task 13: prompt 输入栏

**Files:**
- Create: `ios/AgentDeckMobile/Screens/SessionDetail/MobileInputBarView.swift`
- Modify: `SessionDetailViewController.swift`
- Test: 复用 `SessionDetailViewModelTests`，新增一条

**Interfaces:**
- Consumes: `SessionDetailViewModel.sendPrompt(_:)`
- Produces: `final class MobileInputBarView: UIView { var onSend: ((String) -> Void)?; func setEnabled(_:) }`（多行自增高 UITextView + 发送按钮）

- [ ] **Step 1: 失败测试（view model 层）**

在 `SessionDetailViewModelTests` 追加：

```swift
    func testSendPromptAppendsOptimisticUserRow() async {
        let vm = makeVM("sess-cc-01")
        let done = expectation(description: "initial stream done")
        vm.onUpdate = { if !vm.isStreaming { done.fulfill() } }
        vm.start()
        await fulfillment(of: [done], timeout: 3)
        let baseline = vm.rows.count
        let echoed = expectation(description: "prompt echoed")
        vm.onUpdate = {
            if vm.rows.count > baseline,
               vm.rows.contains(where: { $0.role == .userPrompt && $0.item.text == "再补一个空输入的用例" }) {
                echoed.fulfill()
            }
        }
        vm.sendPrompt("再补一个空输入的用例")
        await fulfillment(of: [echoed], timeout: 3)
    }
```

- [ ] **Step 2: 实现输入栏**

```swift
import UIKit

final class MobileInputBarView: UIView, UITextViewDelegate {
    private let textView = UITextView()
    private let sendButton = UIButton(configuration: .filled())
    private var heightConstraint: NSLayoutConstraint!
    var onSend: ((String) -> Void)?

    override init(frame: CGRect) {
        super.init(frame: frame)
        backgroundColor = DesignTokens.bgRaised
        layer.cornerRadius = DesignTokens.radiusLg
        textView.font = .preferredFont(forTextStyle: .body)
        textView.textColor = DesignTokens.fg
        textView.backgroundColor = .clear
        textView.isScrollEnabled = false
        textView.delegate = self
        sendButton.setImage(UIImage(systemName: "arrow.up"), for: .normal)
        sendButton.addAction(UIAction { [weak self] _ in self?.send() }, for: .touchUpInside)
        textView.translatesAutoresizingMaskIntoConstraints = false
        sendButton.translatesAutoresizingMaskIntoConstraints = false
        addSubview(textView)
        addSubview(sendButton)
        heightConstraint = textView.heightAnchor.constraint(equalToConstant: 36)
        NSLayoutConstraint.activate([
            textView.topAnchor.constraint(equalTo: topAnchor, constant: DesignTokens.sp1),
            textView.bottomAnchor.constraint(equalTo: bottomAnchor, constant: -DesignTokens.sp1),
            textView.leadingAnchor.constraint(equalTo: leadingAnchor, constant: DesignTokens.sp2),
            textView.trailingAnchor.constraint(equalTo: sendButton.leadingAnchor, constant: -DesignTokens.sp2),
            heightConstraint,
            sendButton.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -DesignTokens.sp2),
            sendButton.bottomAnchor.constraint(equalTo: bottomAnchor, constant: -DesignTokens.sp1),
            sendButton.widthAnchor.constraint(equalToConstant: 36),
            sendButton.heightAnchor.constraint(equalToConstant: 36),
        ])
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    func textViewDidChange(_ textView: UITextView) {
        let height = textView.sizeThatFits(CGSize(width: textView.bounds.width, height: .infinity)).height
        heightConstraint.constant = min(max(36, height), 120)
    }

    func setEnabled(_ enabled: Bool) {
        sendButton.isEnabled = enabled
    }

    private func send() {
        let text = textView.text ?? ""
        guard !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return }
        textView.text = ""
        textViewDidChange(textView)
        onSend?(text)
    }
}
```

- [ ] **Step 3: 接入 VC**

`SessionDetailViewController.viewDidLoad` 加输入栏：贴 `view.keyboardLayoutGuide.topAnchor`（bottom）、左右 `sp3` 边距；`collectionView.bottomAnchor` 改为约束到输入栏顶部（-sp2）。`inputBar.onSend = { [weak self] text in self?.viewModel.sendPrompt(text) }`。

- [ ] **Step 4: 测试 + 目检 + Commit**

Run: `xcodebuild ... test` → `** TEST SUCCEEDED **`；模拟器发一条消息：用户气泡立即出现（乐观插入），~0.6s 后 fixture 回声回复。键盘弹起时输入栏跟随。

```bash
git add ios/AgentDeckMobile/Screens/SessionDetail ios/AgentDeckMobileTests/SessionDetailViewModelTests.swift
git commit -m "feat(ios): prompt 输入栏与乐观插入"
```

---

### Task 14: 配对屏与收件箱

**Files:**
- Create: `ios/AgentDeckMobile/Screens/Pairing/PairingViewController.swift`
- Create: `ios/AgentDeckMobile/Screens/Inbox/InboxViewController.swift`、`ios/AgentDeckMobile/Screens/Inbox/InboxViewModel.swift`
- Modify: `MachineListViewController.swift`（接上两个入口）
- Test: `ios/AgentDeckMobileTests/InboxViewModelTests.swift`

**Interfaces:**
- Consumes: `MobileSessionSource.inbox()`
- Produces:
  - `PairingViewController()`：modal（包 UINavigationController），扫码占位 + 粘贴配对码 + 已配对设备列表（内存假数据）+ 逐行「撤销」
  - `@MainActor final class InboxViewModel { init(source: MobileSessionSource); private(set) var items: [InboxItem]; var onUpdate: (() -> Void)?; func start() }`
  - `InboxViewController(source:)`：列表 + 点击跳会话详情

- [ ] **Step 1: 失败测试**

```swift
import XCTest
@testable import AgentDeckMobile

@MainActor
final class InboxViewModelTests: XCTestCase {
    func testInboxSeededWithPendingApproval() async {
        let source = FixtureSessionSource(bundle: Bundle(for: MachineListViewController.self), tickScale: 0)
        let vm = InboxViewModel(source: source)
        let updated = expectation(description: "updated")
        vm.onUpdate = { if !vm.items.isEmpty { updated.fulfill() } }
        vm.start()
        await fulfillment(of: [updated], timeout: 2)
        XCTAssertEqual(vm.items.first?.kind, .waitingApproval)
        XCTAssertEqual(vm.items.first?.sessionID, "sess-approval-01")
    }
}
```

- [ ] **Step 2: 实现**

`InboxViewModel.swift` 与 `MachineListViewModel` 同构（订阅 `source.inbox()`）。

`InboxViewController.swift`：insetGrouped list + diffable（Item = `InboxItem.ID`），cell 文案：

```swift
func kindLabel(_ kind: InboxItem.Kind) -> (text: String, symbol: String) {
    switch kind {
    case .waitingApproval: ("等待审批", "exclamationmark.circle")
    case .turnCompleted: ("已完成", "checkmark.circle")
    case .failed: ("失败", "xmark.circle")
    }
}
// content.text = item.title；content.secondaryText = kindLabel.text
```

didSelect：`navigationController?.pushViewController(SessionDetailViewController(source: source, sessionID: item.sessionID, title: item.title), animated: true)`。

`PairingViewController.swift`：

```swift
import UIKit

/// 全假数据的配对骨架：扫码区域是占位（相机与真实配对在 Relay/R2 后接入）。
final class PairingViewController: UIViewController, UITableViewDataSource, UITableViewDelegate {
    private struct PairedDevice { let id: String; let name: String }
    private var devices: [PairedDevice] = [.init(id: "dev-1", name: "Mac Studio · agentdeckd")]
    private let codeField = UITextField()
    private let tableView = UITableView(frame: .zero, style: .insetGrouped)

    override func viewDidLoad() {
        super.viewDidLoad()
        title = "配对"
        view.backgroundColor = DesignTokens.bg
        navigationItem.leftBarButtonItem = UIBarButtonItem(systemItem: .close, primaryAction:
            UIAction { [weak self] _ in self?.dismiss(animated: true) })

        let scanPlaceholder = UIView()
        scanPlaceholder.layer.borderWidth = 2
        scanPlaceholder.layer.borderColor = DesignTokens.fgMuted.cgColor
        scanPlaceholder.layer.cornerRadius = DesignTokens.radiusLg
        let scanLabel = UILabel()
        scanLabel.text = "扫码配对\n（实机功能后置）"
        scanLabel.numberOfLines = 0
        scanLabel.textAlignment = .center
        scanLabel.textColor = DesignTokens.fgMuted
        scanLabel.translatesAutoresizingMaskIntoConstraints = false
        scanPlaceholder.addSubview(scanLabel)

        codeField.placeholder = "或粘贴配对码"
        codeField.borderStyle = .roundedRect
        let pairButton = UIButton(configuration: .filled())
        pairButton.setTitle("配对", for: .normal)
        pairButton.addAction(UIAction { [weak self] _ in self?.pairFromCode() }, for: .touchUpInside)
        let codeRow = UIStackView(arrangedSubviews: [codeField, pairButton])
        codeRow.spacing = DesignTokens.sp2

        tableView.dataSource = self
        tableView.delegate = self
        tableView.register(UITableViewCell.self, forCellReuseIdentifier: "device")

        let stack = UIStackView(arrangedSubviews: [scanPlaceholder, codeRow, tableView])
        stack.axis = .vertical
        stack.spacing = DesignTokens.sp4
        stack.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(stack)
        NSLayoutConstraint.activate([
            scanPlaceholder.heightAnchor.constraint(equalToConstant: 180),
            scanLabel.centerXAnchor.constraint(equalTo: scanPlaceholder.centerXAnchor),
            scanLabel.centerYAnchor.constraint(equalTo: scanPlaceholder.centerYAnchor),
            stack.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: DesignTokens.sp4),
            stack.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: DesignTokens.sp4),
            stack.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -DesignTokens.sp4),
            stack.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor),
        ])
    }

    private func pairFromCode() {
        guard let code = codeField.text, !code.isEmpty else { return }
        devices.append(.init(id: UUID().uuidString, name: "机器 \(code.prefix(6))"))
        codeField.text = ""
        tableView.reloadData()
    }

    func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int { devices.count }

    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: "device", for: indexPath)
        var content = cell.defaultContentConfiguration()
        content.text = devices[indexPath.row].name
        content.secondaryText = "已配对"
        cell.contentConfiguration = content
        return cell
    }

    func tableView(_ tableView: UITableView, titleForHeaderInSection section: Int) -> String? { "已配对设备" }

    func tableView(_ tableView: UITableView,
                   trailingSwipeActionsConfigurationForRowAt indexPath: IndexPath) -> UISwipeActionsConfiguration? {
        let revoke = UIContextualAction(style: .destructive, title: "撤销") { [weak self] _, _, done in
            self?.devices.remove(at: indexPath.row)
            self?.tableView.deleteRows(at: [indexPath], with: .automatic)
            done(true)
        }
        return UISwipeActionsConfiguration(actions: [revoke])
    }
}
```

`MachineListViewController` 的两个占位 action 接通：

```swift
@objc private func openPairing() {
    present(UINavigationController(rootViewController: PairingViewController()), animated: true)
}

@objc private func openInbox() {
    navigationController?.pushViewController(InboxViewController(source: source), animated: true)
}
```

- [ ] **Step 3: 测试 + 目检 + Commit**

Run: `xcodebuild ... test` → `** TEST SUCCEEDED **`；模拟器：收件箱有 1 条「等待审批」，点击跳详情；配对屏可粘贴假码新增设备并左滑撤销。

```bash
git add ios/AgentDeckMobile/Screens ios/AgentDeckMobileTests/InboxViewModelTests.swift
git commit -m "feat(ios): 配对屏骨架与收件箱"
```

---

### Task 15: 文档收口与全量验证

**Files:**
- Modify: `AGENTS.md`（验证入口加 iOS 命令；项目边界补 `ios/` 一句）
- Modify: `README.md`（新增 iOS companion 小节：定位、目录、fixture 模式说明、构建命令）
- Modify: `docs/index.md`（如有计划文档索引，补两份 iOS 文档链接）
- Modify: `docs/plans/2026-07-03-ios-uikit-frontend-design.md`（状态改为 Implemented，若实现有偏差补决策记录）

- [ ] **Step 1: AGENTS.md 验证入口追加**

在「验证入口」代码块后补：

```markdown
### iOS 前端验证

```bash
# iOS 工程生成 + 构建 + 单测（fixture 驱动，无真实链路）
cd ios && xcodegen generate && \
  xcodebuild -project AgentDeckMobile.xcodeproj -scheme AgentDeckMobile \
    -destination 'platform=iOS Simulator,name=iPhone 17' test
```

涉及 `Sources/AgentDeckCore/` 或 `ios/` 时至少运行 `swift test` 与上述 iOS 测试。
```

「项目边界」追加一条：

```markdown
- `Sources/AgentDeckCore/` 是 macOS/iOS 共享的平台无关层，禁止 import AppKit/UIKit；`ios/` 是 fixture 驱动的 UIKit companion 前端，唯一数据入口是 `MobileSessionSource`，本期不含网络代码（设计见 `docs/plans/2026-07-03-ios-uikit-frontend-design.md`）。
```

- [ ] **Step 2: README.md 增加 iOS 小节**（位置放在 macOS 构建说明之后；内容：companion 定位一句、`ios/` 目录说明、xcodegen 依赖、上面同款构建命令、fixture 模式说明一句）

- [ ] **Step 3: 全量验证**

```bash
swift test 2>&1 | tail -3                       # macOS 126 全绿
cd ios && xcodegen generate && xcodebuild ... test 2>&1 | tail -3   # iOS 全绿
cd .. && scripts/verify-agent-docs.sh            # 文档结构 ok
git status --short --branch                      # 工作区干净（除已知未跟踪目录）
```

- [ ] **Step 4: Commit**

```bash
git add AGENTS.md README.md docs/
git commit -m "docs: iOS UIKit 前端收口（验证入口 + 边界 + README）"
```

---

## 验收清单（对照设计文档第 10 节）

- [ ] 机器列表 → 会话列表 → 会话详情全链路可导航，fixture 数据渲染正确
- [ ] Codex 与 Claude Code 两条会话流均能流式回放，折叠元素可展开
- [ ] 审批卡可 approve / deny，卡片状态变化且流继续，会话分组同步
- [ ] prompt 输入后用户消息乐观出现，假响应回流
- [ ] 配对屏与收件箱骨架可进入、可返回
- [ ] `swift test` 全绿（macOS 无回归）、iOS 单测全绿、`scripts/verify-agent-docs.sh` 通过
- [ ] `Sources/AgentDeckCore/` 无 AppKit/UIKit import；`ios/` 无 SwiftUI import；渲染路径无 agentKind 分支
