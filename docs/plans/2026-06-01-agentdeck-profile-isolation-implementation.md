# AgentDeck Profile Isolation Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 支持 `stable` / `dev` 两个 AgentDeck profile，让开发调试实例和稳定工作实例使用不同的 AgentDeck 数据目录。

**Architecture:** Swift 启动层解析 `--profile` 并在启动 daemon 时注入 `AGENTDECK_PROFILE`。Rust daemon 在 `record::app_data_dir()` 统一解析 `AGENTDECK_DATA_DIR` 与 `AGENTDECK_PROFILE`，让 run record、diagnostic log、selfcheck 和 diagnostics report 自然复用同一目录规则。Codex 登录状态和 Codex 历史保持共享，不进入本次隔离范围。

**Tech Stack:** Swift 6 / Swift Testing、Rust / cargo test、macOS Application Support、stdio JSONL IPC。

---

## 前置约束

- 先阅读 `docs/plans/2026-06-01-agentdeck-profile-isolation-design.md`。
- 不改 IPC schema。
- 不改 Codex adapter 登录、认证或历史读取逻辑。
- 不提交本地 run record、diagnostic log、`.env` 或构建产物。
- 工作区如有无关改动，不要回滚；本计划只提交本功能相关文件。

## Task 1: Rust 数据目录支持 profile

**Files:**
- Modify: `agentdeckd/src/record.rs`
- Test: `agentdeckd/src/record.rs`

**Step 1: 写失败测试**

在 `agentdeckd/src/record.rs` 的 `tests` 模块新增测试：

```rust
#[test]
fn app_data_dir_uses_dev_profile() {
    let home = std::ffi::OsStr::new("/Users/example");
    let dir = app_data_dir_from(None, Some(std::ffi::OsStr::new("dev")), Some(home)).unwrap();

    assert_eq!(
        dir.to_string_lossy(),
        "/Users/example/Library/Application Support/AgentDeck-Dev"
    );
}

#[test]
fn app_data_dir_uses_stable_by_default() {
    let home = std::ffi::OsStr::new("/Users/example");
    let dir = app_data_dir_from(None, None, Some(home)).unwrap();

    assert_eq!(
        dir.to_string_lossy(),
        "/Users/example/Library/Application Support/AgentDeck"
    );
}

#[test]
fn app_data_dir_override_wins_over_profile() {
    let override_dir = std::ffi::OsStr::new("/tmp/agentdeck-custom");
    let home = std::ffi::OsStr::new("/Users/example");
    let dir = app_data_dir_from(
        Some(override_dir),
        Some(std::ffi::OsStr::new("dev")),
        Some(home),
    )
    .unwrap();

    assert_eq!(dir.to_string_lossy(), "/tmp/agentdeck-custom");
}
```

**Step 2: 运行测试确认失败**

Run:

```bash
cargo test app_data_dir_uses_dev_profile app_data_dir_uses_stable_by_default app_data_dir_override_wins_over_profile
```

Expected: FAIL，原因是 `app_data_dir_from` 当前只接受 `AGENTDECK_DATA_DIR` 和 `HOME` 两个参数。

**Step 3: 实现最小代码**

把 `app_data_dir()` 改成读取 `AGENTDECK_PROFILE`：

```rust
pub fn app_data_dir() -> Option<PathBuf> {
    app_data_dir_from(
        std::env::var_os("AGENTDECK_DATA_DIR").as_deref(),
        std::env::var_os("AGENTDECK_PROFILE").as_deref(),
        std::env::var_os("HOME").as_deref(),
    )
}
```

调整 helper 签名：

```rust
pub fn app_data_dir_from(
    agentdeck_data_dir: Option<&OsStr>,
    agentdeck_profile: Option<&OsStr>,
    home: Option<&OsStr>,
) -> Option<PathBuf> {
    if let Some(root) = agentdeck_data_dir
        && !root.is_empty()
    {
        return Some(PathBuf::from(root));
    }

    let profile = agentdeck_profile
        .and_then(|p| p.to_str())
        .filter(|p| !p.is_empty())
        .unwrap_or("stable");

    let app_dir_name = match profile {
        "stable" => "AgentDeck",
        "dev" => "AgentDeck-Dev",
        _ => return None,
    };

    let home = home?;
    let mut p = PathBuf::from(home);
    p.push("Library");
    p.push("Application Support");
    p.push(app_dir_name);
    Some(p)
}
```

同步更新 `record_dir_from(...)` 调用点，签名变为：

```rust
fn record_dir_from(
    agentdeck_data_dir: Option<&OsStr>,
    agentdeck_profile: Option<&OsStr>,
    home: Option<&OsStr>,
) -> Option<PathBuf>
```

**Step 4: 跑测试确认通过**

Run:

```bash
cargo test app_data_dir_uses_dev_profile app_data_dir_uses_stable_by_default app_data_dir_override_wins_over_profile
```

Expected: PASS。

**Step 5: 提交**

```bash
git add agentdeckd/src/record.rs
git commit -m "feat: resolve AgentDeck data dir by profile"
```

## Task 2: Rust 诊断路径复用 profile helper

**Files:**
- Modify: `agentdeckd/src/diag.rs`
- Test: `agentdeckd/src/diag.rs`

**Step 1: 写失败测试**

在 `agentdeckd/src/diag.rs` 的 `tests` 模块新增：

```rust
#[test]
fn log_path_uses_dev_profile() {
    let home = std::ffi::OsStr::new("/Users/example");
    let path = log_path_from(None, Some(std::ffi::OsStr::new("dev")), Some(home)).unwrap();

    assert_eq!(
        path.to_string_lossy(),
        "/Users/example/Library/Application Support/AgentDeck-Dev/diagnostic.log"
    );
}
```

**Step 2: 运行测试确认失败**

Run:

```bash
cargo test log_path_uses_dev_profile
```

Expected: FAIL，原因是 `log_path_from` 尚未传入 profile。

**Step 3: 实现最小代码**

更新 test-only helper：

```rust
fn log_path_from(
    agentdeck_data_dir: Option<&std::ffi::OsStr>,
    agentdeck_profile: Option<&std::ffi::OsStr>,
    home: Option<&std::ffi::OsStr>,
) -> Option<PathBuf> {
    let mut p = crate::record::app_data_dir_from(agentdeck_data_dir, agentdeck_profile, home)?;
    p.push("diagnostic.log");
    Some(p)
}
```

同步修正已有 `log_path_from(...)` 测试调用。

**Step 4: 跑诊断路径测试**

Run:

```bash
cargo test log_path
```

Expected: PASS。

**Step 5: 提交**

```bash
git add agentdeckd/src/diag.rs
git commit -m "test: cover diagnostic log path profiles"
```

## Task 3: Swift 增加 profile 解析模型

**Files:**
- Modify: `Sources/AgentDeck/main.swift`
- Test: `Tests/AgentDeckTests/IpcTests.swift`

**Step 1: 写失败测试**

在 `Tests/AgentDeckTests/IpcTests.swift` 增加测试套件或加入现有 IPC suite：

```swift
@Test("app launch profile defaults to stable")
func appLaunchProfileDefaultsToStable() throws {
    let profile = try AgentDeckProfile.parse(arguments: ["AgentDeck"])
    #expect(profile == .stable)
}

@Test("app launch profile parses dev")
func appLaunchProfileParsesDev() throws {
    let profile = try AgentDeckProfile.parse(arguments: ["AgentDeck", "--profile", "dev"])
    #expect(profile == .dev)
}

@Test("app launch profile rejects unknown values")
func appLaunchProfileRejectsUnknownValues() throws {
    #expect(throws: AgentDeckProfileError.self) {
        _ = try AgentDeckProfile.parse(arguments: ["AgentDeck", "--profile", "prod"])
    }
}
```

**Step 2: 运行测试确认失败**

Run:

```bash
swift test --filter appLaunchProfile
```

Expected: FAIL，原因是 `AgentDeckProfile` 尚不存在。

**Step 3: 实现最小代码**

在 `Sources/AgentDeck/main.swift` 顶部附近新增：

```swift
enum AgentDeckProfile: String, Equatable {
    case stable
    case dev

    static func parse(arguments: [String] = CommandLine.arguments) throws -> AgentDeckProfile {
        guard let raw = argumentValue(after: "--profile", in: arguments) else {
            return .stable
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

func argumentValue(after flag: String, in args: [String] = CommandLine.arguments) -> String? {
    guard let idx = args.firstIndex(of: flag), args.indices.contains(idx + 1) else {
        return nil
    }
    return args[idx + 1]
}
```

删除或替换原有只读 `CommandLine.arguments` 的 `argumentValue(after:)`，让 headless 命令继续调用默认参数版本。

**Step 4: 跑 Swift profile 测试**

Run:

```bash
swift test --filter appLaunchProfile
```

Expected: PASS。

**Step 5: 提交**

```bash
git add Sources/AgentDeck/main.swift Tests/AgentDeckTests/IpcTests.swift
git commit -m "feat: parse AgentDeck launch profiles"
```

## Task 4: Swift 启动 daemon 时注入 profile

**Files:**
- Modify: `Sources/AgentDeck/DaemonClient.swift`
- Modify: `Sources/AgentDeck/main.swift`
- Test: `Tests/AgentDeckTests/IpcTests.swift`

**Step 1: 写失败测试**

新增测试：

```swift
@Test("daemon environment includes selected profile")
func daemonEnvironmentIncludesSelectedProfile() {
    let env = DaemonClient.daemonEnvironment(profile: .dev, base: ["PATH": "/bin"])

    #expect(env["PATH"] == "/bin")
    #expect(env["AGENTDECK_PROFILE"] == "dev")
}
```

**Step 2: 运行测试确认失败**

Run:

```bash
swift test --filter daemonEnvironmentIncludesSelectedProfile
```

Expected: FAIL，原因是 `DaemonClient.daemonEnvironment` 和 profile 注入尚不存在。

**Step 3: 实现最小代码**

给 `DaemonClient` 增加 profile 属性和初始化：

```swift
final class DaemonClient {
    private let profile: AgentDeckProfile

    init(profile: AgentDeckProfile = .stable) {
        self.profile = profile
    }
}
```

在 `start()` 的 `try process.run()` 前设置环境：

```swift
process.environment = Self.daemonEnvironment(
    profile: profile,
    base: ProcessInfo.processInfo.environment
)
```

新增 helper：

```swift
static func daemonEnvironment(
    profile: AgentDeckProfile,
    base: [String: String] = ProcessInfo.processInfo.environment
) -> [String: String] {
    var env = base
    env["AGENTDECK_PROFILE"] = profile.rawValue
    return env
}
```

在 `main.swift` 中启动前解析 profile：

```swift
let launchProfile: AgentDeckProfile
do {
    launchProfile = try AgentDeckProfile.parse()
} catch {
    FileHandle.standardError.write(Data("AgentDeck FATAL: \(error)\n".utf8))
    exit(1)
}
```

把 headless client 构造改为：

```swift
let client = DaemonClient(profile: launchProfile)
```

**Step 4: 跑测试确认通过**

Run:

```bash
swift test --filter daemonEnvironmentIncludesSelectedProfile
swift test --filter appLaunchProfile
```

Expected: PASS。

**Step 5: 提交**

```bash
git add Sources/AgentDeck/DaemonClient.swift Sources/AgentDeck/main.swift Tests/AgentDeckTests/IpcTests.swift
git commit -m "feat: pass AgentDeck profile to daemon"
```

## Task 5: UI 标识 dev profile

**Files:**
- Modify: `Sources/AgentDeck/main.swift`
- Test: `Tests/AgentDeckTests/IpcTests.swift`

**Step 1: 写失败测试**

新增测试：

```swift
@Test("window title marks dev profile")
func windowTitleMarksDevProfile() {
    #expect(AgentDeckProfile.stable.windowTitle == "AgentDeck")
    #expect(AgentDeckProfile.dev.windowTitle == "AgentDeck Dev")
}
```

**Step 2: 运行测试确认失败**

Run:

```bash
swift test --filter windowTitleMarksDevProfile
```

Expected: FAIL，原因是 `windowTitle` 尚不存在。

**Step 3: 实现最小代码**

给 `AgentDeckProfile` 增加：

```swift
var windowTitle: String {
    switch self {
    case .stable:
        return "AgentDeck"
    case .dev:
        return "AgentDeck Dev"
    }
}
```

把 `WindowGroup("AgentDeck")` 改为：

```swift
WindowGroup(launchProfile.windowTitle) {
    SessionView()
}
```

**Step 4: 跑测试确认通过**

Run:

```bash
swift test --filter windowTitleMarksDevProfile
```

Expected: PASS。

**Step 5: 提交**

```bash
git add Sources/AgentDeck/main.swift Tests/AgentDeckTests/IpcTests.swift
git commit -m "feat: label AgentDeck dev profile window"
```

## Task 6: headless selfcheck / diagnostics 验证 profile

**Files:**
- Modify: `Sources/AgentDeck/main.swift` if needed
- Modify: `agentdeckd/src/main.rs` only if diagnostics report needs extra validation
- Test: existing headless commands

**Step 1: 运行 dev selfcheck**

Run:

```bash
swift run AgentDeck -- --selfcheck --profile dev
```

Expected: PASS，输出 `selfcheck OK: IPC lifecycle + logging clean.`。

**Step 2: 运行 dev diagnostics report**

Run:

```bash
swift run AgentDeck -- --diagnostics-report --json --profile dev
```

Expected: PASS，JSON 中：

```json
{
  "dataDir": ".../Library/Application Support/AgentDeck-Dev",
  "runsDir": ".../Library/Application Support/AgentDeck-Dev/runs",
  "diagnosticLog": ".../Library/Application Support/AgentDeck-Dev/diagnostic.log"
}
```

**Step 3: 如失败则修正启动参数顺序**

如果 headless 命令仍写入 stable 目录，检查 `main.swift` 是否在创建 `DaemonClient` 前解析了 `launchProfile`，并确认 `DaemonClient.start()` 在 `process.run()` 前设置 `process.environment`。

**Step 4: 提交**

仅当本任务产生代码修正时提交：

```bash
git add Sources/AgentDeck/main.swift Sources/AgentDeck/DaemonClient.swift agentdeckd/src/main.rs
git commit -m "fix: apply profiles to headless diagnostics"
```

## Task 7: 更新用户文档和诊断文档

**Files:**
- Modify: `README.md`
- Modify: `ARCHITECTURE.md`
- Modify: `docs/AGENT_DIAGNOSTICS.md`
- Modify: `docs/QUALITY.md`

**Step 1: 更新 README**

在运行命令附近加入：

```markdown
Profile:

```bash
swift run AgentDeck -- --profile stable
swift run AgentDeck -- --profile dev
swift run AgentDeck -- --selfcheck --profile dev
swift run AgentDeck -- --diagnostics-report --json --profile dev
```

- `stable` 是默认 profile，写入 `~/Library/Application Support/AgentDeck/`。
- `dev` 写入 `~/Library/Application Support/AgentDeck-Dev/`。
- `AGENTDECK_DATA_DIR` 仍只作为测试/诊断覆盖入口，优先于 profile。
```

**Step 2: 更新 ARCHITECTURE**

在数据目录不变量附近补充：

```markdown
- profile 只影响 AgentDeck 管理的数据目录；不影响 Codex 登录状态、token 或 Codex app-server 历史。
```

**Step 3: 更新诊断文档**

在 `docs/AGENT_DIAGNOSTICS.md` 快速命令中加入：

```bash
swift run AgentDeck -- --selfcheck --profile dev
swift run AgentDeck -- --diagnostics-report --json --profile dev
```

**Step 4: 更新质量文档**

在数据目录 / diagnostics 行补充 profile 变更需要跑 dev selfcheck 和 diagnostics report。

**Step 5: 跑文档检查**

Run:

```bash
scripts/verify-agent-docs.sh
```

Expected: PASS。

**Step 6: 提交**

```bash
git add README.md ARCHITECTURE.md docs/AGENT_DIAGNOSTICS.md docs/QUALITY.md
git commit -m "docs: document AgentDeck profiles"
```

## Task 8: 最终验证和收口

**Files:**
- Verify only

**Step 1: Rust 全量测试**

Run:

```bash
cargo test
```

Expected: PASS。

**Step 2: Swift 全量测试**

Run:

```bash
swift test
```

Expected: PASS。

**Step 3: Headless profile 验证**

Run:

```bash
swift run AgentDeck -- --selfcheck --profile dev
swift run AgentDeck -- --diagnostics-report --json --profile dev
```

Expected: PASS，diagnostics report 指向 `AgentDeck-Dev`。

**Step 4: 文档验证**

Run:

```bash
scripts/verify-agent-docs.sh
```

Expected: PASS。

**Step 5: 检查工作区**

Run:

```bash
git status --short --branch
```

Expected: 只剩用户已有的无关改动，或工作区干净。

**Step 6: 汇总**

最终回复需要包含：

- 实现了 `--profile stable|dev`。
- `dev` 数据目录是 `~/Library/Application Support/AgentDeck-Dev/`。
- `AGENTDECK_DATA_DIR` 仍优先。
- 已运行的验证命令和结果。
- 是否有未处理的无关工作区改动。

