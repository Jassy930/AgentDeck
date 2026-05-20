# AgentDeck Logging Hardening Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 完善 AgentDeck 的日志、留痕和自检闭环，让没有历史上下文的 agent 也能靠本地证据判断 IPC、daemon、Codex adapter、run record 和 UI 可见错误链路是否健康，并能按机器可读结果继续自主复验。

**Architecture:** 保持现有两层可观测性：`runs/*.jsonl` 记录每次 turn 的可回放事实，`diagnostic.log` 改为结构化 JSONL，记录进程、IPC、协议和持久化异常。daemon 仍是日志和留痕唯一写入点；Swift 只消费中立 IPC 并把 warning/error 明确展示出来。所有诊断事件和 run record 共享 `runId` / `threadId` / `requestId` / `eventSeq` 等 correlation 字段，并提供 `diagnostics/report` 机器可读接口和 `docs/AGENT_DIAGNOSTICS.md` 自查手册。测试通过 Rust 单测、Swift 单测和 headless `--selfcheck` 覆盖，不引入数据库或外部日志系统。

**Tech Stack:** Swift 6 / SwiftUI / Testing，Rust 2024 / serde / serde_json，JSONL IPC，Codex app-server adapter。

---

## 执行前置条件

- 执行本计划时使用 @superpowers:executing-plans 逐任务推进。
- 每个实现任务使用 @superpowers:test-driven-development：先写失败测试，再做最小实现。
- 完成每个提交前使用 @superpowers:verification-before-completion 跑对应验证命令。
- 执行前先跑 `git status --short --branch`，确认当前未提交改动归属。
- 不添加 co-author / codex 合作者信息。
- Python 不涉及；JS/TS 不涉及。
- Rust 使用 `cargo test` / `cargo fmt --check` / `cargo clippy --all-targets -- -D warnings`。
- Swift 使用 `swift test` 和 `swift run AgentDeck -- --selfcheck`。
- 本计划按 TDD 执行：先写失败测试，再实现最小代码，再跑相关测试。

## 目标行为

- run record 写入失败必须在 UI 可见，不能只写 diagnostic log。
- diagnostic log 写入和 run record 写入有可测试路径，不依赖真实用户目录。
- `--selfcheck` 能验证 IPC 生命周期、run record 写入、diagnostic log 写入、redaction 和 warning 解码。
- 未识别的 Codex/app-server 消息至少进入 diagnostic log 或 raw run record，不能静默丢失。
- run id 在快速连续 turn 中不会碰撞。
- diagnostic log 每行都是可解析 JSON，并带固定 `schemaVersion` / `ts` / `level` / `event` / `code` / `runId` / `threadId` / `requestId` / `eventSeq` / `message` / `detail` 字段。
- run record 与 diagnostic log 可通过 `runId` 和 `eventSeq` 关联，agent 不需要猜“哪条日志对应哪次 turn”。
- daemon 提供 agent 友好的 `diagnostics/report` IPC 接口；Swift 提供 headless `--diagnostics-report --json` 命令，输出机器可读健康报告。
- 健康报告必须包含 `failures[]` 和 `nextChecks[]`，每个 failure 带 `code`、`severity`、`message`、`pathHint`、`runId` 和 `suggestedNextCheck`。
- 新增 `docs/AGENT_DIAGNOSTICS.md`，让没有历史上下文的 agent 能 5 分钟内知道日志在哪、如何跑自检、如何根据 failure code 继续查。
- README 对日志位置、失败语义和自检范围的描述与代码一致。

## 非目标

- 不做远程日志、dashboard、metrics、alerting。
- 不引入数据库或后台常驻日志服务。
- 不把日志写进用户项目目录。
- 不在本轮重做 approval / deny 产品交互，只保证未知协议和失败可追踪。
- 不做破坏性自动修复；agent-friendly 接口只给证据、分类和下一步检查建议，是否修复仍由执行计划控制。

---

### Task 1: Swift 端显示 daemon warning

**Files:**
- Modify: `Sources/AgentDeck/SessionModel.swift`
- Modify: `Sources/AgentDeck/SessionView.swift`
- Test: `Tests/AgentDeckTests/IpcTests.swift`

**Step 1: 写失败的 Swift 测试**

在 `SessionRenderThrottlingTests` 中新增：

```swift
@Test("daemon warning is visible without failing the turn")
func daemonWarningIsVisibleWithoutFailingTheTurn() {
    let model = SessionModel()
    model.phase = .running

    model.ingest(IpcMessage(
        kind: "warning",
        id: nil,
        payload: AnyCodable(["message": "本次未留痕: HOME not set"])
    ))

    #expect(model.warningMessage == "本次未留痕: HOME not set")
    #expect(model.errorMessage == nil)
    #expect(model.phase == .running)
}
```

**Step 2: 运行测试确认失败**

Run:

```bash
swift test --filter daemonWarningIsVisibleWithoutFailingTheTurn
```

Expected: FAIL，`SessionModel` 没有 `warningMessage`，`warning` 被 default 分支吞掉。

**Step 3: 实现最小 UI 状态**

- 在 `SessionModel` 增加 `var warningMessage: String?`。
- 在 `ingest(_:)` 增加 `case "warning"`，读取 payload.message，写入 `warningMessage`，不改变 `phase`。
- 在新会话开始时清掉 `warningMessage`，避免旧 warning 残留。
- 在 `SessionView` 的错误展示附近增加 warning row，使用系统 warning 色，不把 warning 当 failed。

**Step 4: 运行测试确认通过**

Run:

```bash
swift test --filter daemonWarningIsVisibleWithoutFailingTheTurn
swift test
```

Expected: PASS。

**Step 5: 提交**

```bash
git add Sources/AgentDeck/SessionModel.swift Sources/AgentDeck/SessionView.swift Tests/AgentDeckTests/IpcTests.swift
git commit -m "fix: surface daemon warnings in session UI"
```

---

### Task 2: 所有 run record 写失败都发 warning

**Files:**
- Modify: `agentdeckd/src/main.rs`
- Test: `agentdeckd/src/main.rs`

**Step 1: 写失败的 Rust 测试**

把 `record_or_warn` 抽成可直接测试的辅助路径，不直接修改全局 `HOME`。新增一个可注入的写入函数，例如 `record_or_warn_with_writer(stdout, run_id, line, append_fn)`：

```rust
#[test]
fn streaming_record_failure_emits_warning() {
    let mut out = Vec::new();
    let append = |_run_id: &str, _line: &str| Err("HOME not set".to_string());
    record_or_warn_with_writer(&mut out, "run-test", r#"{"event":"probe"}"#, append).unwrap();

    let wire = String::from_utf8(out).unwrap();
    assert!(wire.contains(r#""kind":"warning""#));
    assert!(wire.contains("本次未留痕"));
}
```

**Step 2: 运行测试确认当前关键缺口**

Run:

```bash
cargo test streaming_record_failure_emits_warning
```

Expected: 当前只能覆盖 `record_or_warn`，不能覆盖 turn callback 里的直接 `record::try_append`。

**Step 3: 收敛写入入口**

- 新增 `record_item_or_warn(stdout, run_id, item_json, warning_emitted, append_fn)`，生产代码传 `record::try_append`，测试传失败 stub。
- `run_session` 和 `run_turn_on_existing_thread` 的 streaming callback 不再直接调用 `record::try_append`。
- 首次 item 写入失败时发一个 warning；后续同 turn 不重复刷屏，但继续 `diag::log("record_failed", ...)`。
- 保持 record 写失败不影响 agent stream。

**Step 4: 增加纯函数/小 helper 测试**

测试同一 turn 中多次失败只发一次 warning：

```rust
#[test]
fn record_failure_warning_is_emitted_once_per_turn() {
    let mut out = Vec::new();
    let mut emitted = false;
    let append = |_run_id: &str, _line: &str| Err("permission denied".to_string());
    record_item_or_warn(&mut out, "run-test", "{}", &mut emitted, append).unwrap();
    record_item_or_warn(&mut out, "run-test", "{}", &mut emitted, append).unwrap();

    let wire = String::from_utf8(out).unwrap();
    assert_eq!(wire.matches(r#""kind":"warning""#).count(), 1);
}
```

**Step 5: 运行测试确认通过**

Run:

```bash
cargo test record_failure_warning
cargo test
```

Expected: PASS。

**Step 6: 提交**

```bash
git add agentdeckd/src/main.rs
git commit -m "fix: warn when run recording fails during streams"
```

---

### Task 3: 引入可测试的数据目录覆盖，避免并发测试污染

**Files:**
- Modify: `agentdeckd/src/record.rs`
- Modify: `agentdeckd/src/diag.rs`
- Test: `agentdeckd/src/record.rs`
- Test: `agentdeckd/src/diag.rs`

**Step 1: 写失败测试**

新增环境变量 `AGENTDECK_DATA_DIR`，但单元测试优先测纯函数，不直接 `set_var/remove_var`，避免并发测试污染：

```rust
#[test]
fn record_dir_respects_agentdeck_data_dir_override() {
    let root = std::env::temp_dir().join(format!("agentdeck-test-{}", std::process::id()));
    let dir = record_dir_from(Some(root.as_os_str()), None).unwrap();

    assert!(dir.starts_with(&root));
    assert!(dir.ends_with("runs"));
}
```

`diag.rs` 增加类似测试，期望 `diagnostic.log` 写到 override 目录下。

**Step 2: 运行测试确认失败**

Run:

```bash
cargo test agentdeck_data_dir_override
```

Expected: FAIL，当前只读 `HOME`。

**Step 3: 实现 shared app data dir**

- 在 `record.rs` 新增 `pub fn app_data_dir() -> Option<PathBuf>`。
- 新增纯函数 `app_data_dir_from(agentdeck_data_dir: Option<&OsStr>, home: Option<&OsStr>) -> Option<PathBuf>`。
- 优先使用 `AGENTDECK_DATA_DIR`；否则使用 `~/Library/Application Support/AgentDeck`。
- `record_dir()` 基于 `app_data_dir()/runs`。
- `diag::log_path()` 基于同一个 `app_data_dir()`。
- 保持默认行为不变。

**Step 4: 运行测试确认通过**

Run:

```bash
cargo test record::tests
cargo test diag::tests
cargo test
```

Expected: PASS。

**Step 5: 提交**

```bash
git add agentdeckd/src/record.rs agentdeckd/src/diag.rs
git commit -m "test: make AgentDeck data dir configurable"
```

---

### Task 4: diagnostic log 改为结构化 JSONL 并加入 correlation 字段

**Files:**
- Modify: `agentdeckd/src/diag.rs`
- Modify: `agentdeckd/src/main.rs`
- Test: `agentdeckd/src/diag.rs`

**Step 1: 写失败的结构化日志测试**

在 `diag.rs` 新增可直接构造事件的测试：

```rust
#[test]
fn diagnostic_event_serializes_as_jsonl_with_correlation_fields() {
    let event = DiagnosticEvent::new("session_start")
        .level("info")
        .code("session_start")
        .run_id("run_1")
        .thread_id("thread_1")
        .request_id(7)
        .event_seq(3)
        .message("session started");

    let line = event.to_json_line();
    let value: serde_json::Value = serde_json::from_str(&line).unwrap();

    assert_eq!(value["schemaVersion"], 1);
    assert_eq!(value["event"], "session_start");
    assert_eq!(value["level"], "info");
    assert_eq!(value["code"], "session_start");
    assert_eq!(value["runId"], "run_1");
    assert_eq!(value["threadId"], "thread_1");
    assert_eq!(value["requestId"], 7);
    assert_eq!(value["eventSeq"], 3);
}
```

**Step 2: 运行测试确认失败**

Run:

```bash
cargo test diagnostic_event_serializes_as_jsonl_with_correlation_fields
```

Expected: FAIL，当前 `diag::log(event, detail)` 只写自由文本。

**Step 3: 实现结构化事件**

- 新增 `DiagnosticEvent` struct，字段：
  - `schemaVersion: 1`
  - `ts`
  - `level`
  - `event`
  - `code`
  - `runId`
  - `threadId`
  - `requestId`
  - `eventSeq`
  - `message`
  - `detail`
- `detail` 仍经过 `record::redact`。
- 保留兼容函数 `diag::log(event, detail)`，内部转换为 JSONL，但新代码优先使用 builder，避免丢 correlation。
- 在 `run_session` / `run_turn_on_existing_thread` 中引入本 turn 内递增 `eventSeq`，所有 session_start / record_failed / turn_failed / complete 都带 `runId`。

**Step 4: 运行测试确认通过**

Run:

```bash
cargo test diag::tests
cargo test
```

Expected: PASS。

**Step 5: 提交**

```bash
git add agentdeckd/src/diag.rs agentdeckd/src/main.rs
git commit -m "feat: structure diagnostic logs for agent triage"
```

---

### Task 5: 加强 redaction 并修正弱断言

**Files:**
- Modify: `agentdeckd/src/record.rs`
- Test: `agentdeckd/src/record.rs`

**Step 1: 写失败测试**

```rust
#[test]
fn redact_masks_bearer_value_after_space() {
    let r = redact("Authorization: Bearer xyzToken99");
    assert!(!r.contains("xyzToken99"));
    assert!(r.contains("Bearer <REDACTED>") || r.contains("<REDACTED>"));
}

#[test]
fn redact_masks_json_authorization_header() {
    let r = redact(r#"{"authorization":"Bearer xyzToken99"}"#);
    assert!(!r.contains("xyzToken99"));
}
```

**Step 2: 运行测试确认失败**

Run:

```bash
cargo test redact_masks_bearer
```

Expected: 至少 Bearer value 场景失败。

**Step 3: 实现最小 redaction**

- 继续保持无额外依赖。
- 先处理 `Bearer <token>` 形式，再做现有 token 级 redaction。
- 覆盖 JSON 字符串中的 `Bearer xxx`。
- 修正旧测试，把弱断言改成必须不包含原 token。

**Step 4: 运行测试确认通过**

Run:

```bash
cargo test redact
cargo test
```

Expected: PASS。

**Step 5: 提交**

```bash
git add agentdeckd/src/record.rs
git commit -m "fix: strengthen log redaction coverage"
```

---

### Task 6: run id 改为不可碰撞

**Files:**
- Modify: `agentdeckd/src/main.rs`
- Test: `agentdeckd/src/main.rs`

**Step 1: 写失败测试**

抽出 `new_run_id()` 后新增：

```rust
#[test]
fn new_run_id_is_unique_for_rapid_calls() {
    let mut ids = std::collections::HashSet::new();
    for _ in 0..1000 {
        assert!(ids.insert(new_run_id()));
    }
}
```

**Step 2: 运行测试确认失败或暴露当前风险**

Run:

```bash
cargo test new_run_id_is_unique_for_rapid_calls
```

Expected: 如果仍用秒级时间戳会失败。

**Step 3: 实现唯一 run id**

- 新增 `new_run_id()`。
- 使用 `SystemTime::now().duration_since(UNIX_EPOCH).as_nanos()` + `std::process::id()`。
- 两处 `run_id = format!("run-{}"...` 都改为调用 `new_run_id()`。

**Step 4: 运行测试确认通过**

Run:

```bash
cargo test new_run_id
cargo test
```

Expected: PASS。

**Step 5: 提交**

```bash
git add agentdeckd/src/main.rs
git commit -m "fix: avoid run record id collisions"
```

---

### Task 7: 未识别 Codex 消息进入诊断日志和 raw 留痕

**Files:**
- Modify: `agentdeckd/src/codex.rs`
- Modify: `agentdeckd/src/ipc.rs`
- Test: `agentdeckd/src/codex.rs`

**Step 1: 写失败测试**

在 `codex.rs` 的测试里新增：

```rust
#[test]
fn unknown_notification_becomes_raw_agent_item() {
    let params = serde_json::json!({
        "item": {
            "id": "unknown_1",
            "type": "newFutureItem",
            "payload": {"x": 1}
        }
    });

    let item = translate("item/newFutureItem/completed", &params).unwrap();

    assert_eq!(item.id, "unknown_1");
    assert_eq!(item.lifecycle, AgentItemLifecycle::Completed);
    assert!(matches!(item.kind, AgentItemKind::Raw { .. }));
}
```

**Step 2: 运行测试确认失败**

Run:

```bash
cargo test unknown_notification_becomes_raw_agent_item
```

Expected: 当前未知 method 很可能返回 `None`。

**Step 3: 实现 raw fallback**

- 对 `item/*` 且能解析出 item id/type 的未知通知，返回 `AgentItemKind::Raw`。
- raw description 包含 method、item type、简短 payload 摘要，并写入 run record。
- 对完全无法识别的 method，至少写结构化 diagnostic event：`code = "adapter_unhandled_method"`，`level = "warning"`。
- diagnostic event 必须带当前 `runId` / `threadId` / `eventSeq`；如果当前 adapter helper 拿不到这些字段，先在 `turn_start` callback 外层补一条 `adapter_unhandled_method` 诊断，不把事件静默吞掉。
- 注意 raw 仍是中立 item，不把 Swift 协议字段命名成 Codex。

**Step 4: 运行测试确认通过**

Run:

```bash
cargo test unknown_notification
cargo test
```

Expected: PASS。

**Step 5: 提交**

```bash
git add agentdeckd/src/codex.rs agentdeckd/src/ipc.rs
git commit -m "fix: preserve unknown adapter events as raw records"
```

---

### Task 8: 扩展 headless logging selfcheck，必须读回落盘结果

**Files:**
- Modify: `agentdeckd/src/main.rs`
- Modify: `Sources/AgentDeck/DaemonClient.swift`
- Modify: `Sources/AgentDeck/main.swift`
- Test: `Tests/AgentDeckTests/IpcTests.swift`

**Step 1: 写失败的 Swift 请求编码测试**

```swift
@Test("logging selfcheck request is neutral")
func loggingSelfcheckRequestIsNeutral() throws {
    let msg = IpcMessage(kind: "selfcheck/logging", id: 8, payload: nil)
    let wire = String(data: try JSONEncoder().encode(msg), encoding: .utf8)!.lowercased()
    #expect(wire.contains("selfcheck/logging"))
    #expect(!wire.contains("codex"))
    #expect(!wire.contains("openai"))
}
```

**Step 2: 运行测试确认基础通过但 daemon 未实现**

Run:

```bash
swift test --filter loggingSelfcheckRequestIsNeutral
```

Expected: PASS；随后手动发 daemon 请求会返回 unknown kind。

**Step 3: daemon 实现 `selfcheck/logging`**

在 `main.rs` 增加 handler：

- 生成唯一 `probeId` 和 `runId`。
- 写一条 diagnostic probe，detail 含测试 secret：`sk-agentdeck-selfcheck` 和 `Bearer agentdeck-selfcheck-token`。
- 写一条 run record probe，payload 含同样测试 secret。
- 立即读回对应 `diagnostic.log` 和 `runs/<runId>.jsonl`。
- 断言 `probeId` 存在，测试 secret 明文不存在。
- 返回 `kind: "loggingSelfcheck"`，payload 至少包含：
  - `recordOk: Bool`
  - `diagnosticOk: Bool`
  - `redactionOk: Bool`
  - `probeId: String`
  - `runId: String`
  - `recordPathHint: String`
  - `diagnosticPathHint: String`
  - `failures: [{ "code": String, "message": String, "pathHint": String, "suggestedNextCheck": String }]`

**Step 4: Swift selfcheck 调用 logging selfcheck**

- `DaemonClient` 增加 `loggingSelfcheck()`。
- `main.swift --selfcheck` 在 ping/pong 后调用 logging selfcheck。
- 失败时输出明确错误，例如 `selfcheck FATAL: logging selfcheck failed: ...`。
- 成功文案改为 `selfcheck OK: IPC lifecycle + logging clean.`

**Step 5: 运行验证**

Run:

```bash
cargo build
AGENTDECK_DATA_DIR="$(mktemp -d)" swift run AgentDeck -- --selfcheck
```

Expected: PASS，输出新的 OK 文案；临时目录下存在 `runs/` 和 `diagnostic.log`，且没有明文 `sk-test` / `Bearer token`。

**Step 6: 提交**

```bash
git add agentdeckd/src/main.rs Sources/AgentDeck/DaemonClient.swift Sources/AgentDeck/main.swift Tests/AgentDeckTests/IpcTests.swift
git commit -m "test: extend selfcheck to cover logging"
```

---

### Task 9: 增加 agent 友好的 diagnostics report 接口

**Files:**
- Modify: `agentdeckd/src/main.rs`
- Modify: `agentdeckd/src/diag.rs`
- Modify: `Sources/AgentDeck/DaemonClient.swift`
- Modify: `Sources/AgentDeck/main.swift`
- Test: `agentdeckd/src/main.rs`
- Test: `Tests/AgentDeckTests/IpcTests.swift`

**Step 1: 写失败的 Swift CLI/IPC 编码测试**

```swift
@Test("diagnostics report request is neutral and machine readable")
func diagnosticsReportRequestIsNeutral() throws {
    let msg = IpcMessage(
        kind: "diagnostics/report",
        id: 9,
        payload: AnyCodable(["limit": 20, "sinceSeconds": 3600])
    )

    let wire = String(data: try JSONEncoder().encode(msg), encoding: .utf8)!.lowercased()
    #expect(wire.contains("diagnostics/report"))
    #expect(!wire.contains("codex"))
    #expect(!wire.contains("openai"))
}
```

**Step 2: 运行测试确认基础通过但 daemon 未实现**

Run:

```bash
swift test --filter diagnosticsReportRequestIsNeutral
```

Expected: PASS；daemon 端此时仍会返回 `unknown kind`。

**Step 3: daemon 实现 `diagnostics/report`**

新增 IPC request：

```json
{
  "kind": "diagnostics/report",
  "id": 9,
  "payload": {
    "runId": "optional-run-id",
    "sinceSeconds": 3600,
    "limit": 50
  }
}
```

返回：

```json
{
  "kind": "diagnosticsReport",
  "id": 9,
  "payload": {
    "schemaVersion": 1,
    "dataDir": "...",
    "runsDir": "...",
    "diagnosticLog": "...",
    "latestRuns": [
      {"runId": "run_...", "path": "...", "updatedAt": 123, "lineCount": 42}
    ],
    "failures": [
      {
        "code": "record_write_failed",
        "severity": "warning",
        "message": "run record write failed",
        "runId": "run_...",
        "threadId": "thread_...",
        "eventSeq": 12,
        "pathHint": ".../runs/run_....jsonl",
        "suggestedNextCheck": "检查 AGENTDECK_DATA_DIR 或用户 Application Support 目录权限"
      }
    ],
    "nextChecks": [
      "运行 swift run AgentDeck -- --selfcheck",
      "按 runId 过滤 diagnostic.log 与 runs/*.jsonl"
    ]
  }
}
```

**Step 4: 实现失败分类**

最少支持这些 `code`：

- `record_write_failed`
- `diagnostic_write_failed`
- `redaction_failed`
- `adapter_unhandled_method`
- `ipc_malformed_jsonl`
- `daemon_spawn_failed`
- `app_server_handshake_failed`
- `turn_failed`

每个 code 必须有稳定含义，不能把底层自由文本当唯一分类。

**Step 5: Swift 增加 headless JSON 命令**

- `DaemonClient` 增加 `diagnosticsReport(limit:sinceSeconds:runId:)`。
- `main.swift` 增加：

```bash
swift run AgentDeck -- --diagnostics-report --json
swift run AgentDeck -- --diagnostics-report --json --run-id run_123
```

- 命令只打印 JSON 到 stdout；失败打印明确错误到 stderr 并返回非 0。

**Step 6: 运行验证**

Run:

```bash
cargo build
diag_dir="$(mktemp -d)"
AGENTDECK_DATA_DIR="$diag_dir" swift run AgentDeck -- --selfcheck
AGENTDECK_DATA_DIR="$diag_dir" swift run AgentDeck -- --diagnostics-report --json
```

Expected: 第二条命令输出合法 JSON，含 `schemaVersion`、路径 hint、`failures[]`、`nextChecks[]`。

**Step 7: 提交**

```bash
git add agentdeckd/src/main.rs agentdeckd/src/diag.rs Sources/AgentDeck/DaemonClient.swift Sources/AgentDeck/main.swift Tests/AgentDeckTests/IpcTests.swift
git commit -m "feat: add agent diagnostics report"
```

---

### Task 10: 新增无上下文 agent 自查手册

**Files:**
- Create: `docs/AGENT_DIAGNOSTICS.md`
- Modify: `README.md`

**Step 1: 创建文档**

新增 `docs/AGENT_DIAGNOSTICS.md`，内容必须短、可执行、机器友好：

````markdown
# AgentDeck Agent Diagnostics

本页给没有历史上下文的 agent 使用。目标是在 5 分钟内判断 AgentDeck 当前是否能记录、诊断和复验问题。

## 快速入口

```bash
swift run AgentDeck -- --selfcheck
swift run AgentDeck -- --diagnostics-report --json
```

## 日志位置

- run record: `~/Library/Application Support/AgentDeck/runs/*.jsonl`
- diagnostic log: `~/Library/Application Support/AgentDeck/diagnostic.log`
- 测试覆盖目录: 设置 `AGENTDECK_DATA_DIR=/tmp/agentdeck-diag`

## 关联规则

优先用 `runId` 关联 `diagnostic.log` 与 `runs/*.jsonl`。
同一个 `runId` 内用 `eventSeq` 排序。
没有 `runId` 的诊断只作为进程级问题处理。

## 标准自查流程

1. 跑 `swift run AgentDeck -- --selfcheck`。
2. 如果失败，先看 stderr 的 failure code。
3. 跑 `swift run AgentDeck -- --diagnostics-report --json`。
4. 优先处理 `failures[]` 中 severity 最高的项目。
5. 按 `suggestedNextCheck` 继续执行只读检查。

## Failure Codes

| code | 含义 | 下一步 |
| --- | --- | --- |
| `record_write_failed` | run record 写入失败 | 检查 data dir 路径和权限 |
| `diagnostic_write_failed` | diagnostic log 写入失败 | 检查 data dir 路径和权限 |
| `redaction_failed` | 测试 secret 明文落盘 | 停止分享日志，修 redaction |
| `adapter_unhandled_method` | app-server 协议出现未识别事件 | 查看 raw record 和 schema |
| `ipc_malformed_jsonl` | Swift/Rust IPC 收到坏 JSONL | 查看上一条 IPC line |
| `daemon_spawn_failed` | Swift 无法启动 daemon | 检查 `agentdeckd` 路径 |
| `app_server_handshake_failed` | Codex app-server 握手失败 | 检查 `codex` 登录和版本 |
| `turn_failed` | turn 执行失败 | 按 runId 查看 run record |
````

**Step 2: README 增加导航**

在 README 的“本地数据”或“测试”附近增加链接：

```markdown
Agent 自查流程见 [docs/AGENT_DIAGNOSTICS.md](docs/AGENT_DIAGNOSTICS.md)。
```

**Step 3: 文档一致性检查**

Run:

```bash
rg -n "diagnostics-report|AGENT_DIAGNOSTICS|Failure Codes|runId|eventSeq" README.md docs/AGENT_DIAGNOSTICS.md
```

Expected: README 有入口，手册包含快速命令、日志路径、关联规则、failure code。

**Step 4: 提交**

```bash
git add README.md docs/AGENT_DIAGNOSTICS.md
git commit -m "docs: add agent diagnostics guide"
```

---

### Task 11: 更新 README 日志与自检说明

**Files:**
- Modify: `README.md`
- Optional Modify: `AgentDeck_v0.1_Product_Definition_Workbench.md`

**Step 1: 更新 README**

把 `本地数据` 和 `测试` 段落改成当前真实语义：

- `runs/*.jsonl` 是 per-turn 中立 item 留痕。
- `diagnostic.log` 是进程、IPC、adapter 和 record 失败诊断。
- 写入失败不阻塞会话；run record 失败通过 UI warning 暴露。
- `--selfcheck` 覆盖 IPC lifecycle + logging probe + redaction probe。
- `--diagnostics-report --json` 输出 agent 友好的机器可读诊断报告。
- `AGENTDECK_DATA_DIR` 是测试/诊断覆盖目录，不是普通用户配置。

**Step 2: 运行文档一致性检查**

Run:

```bash
rg -n "\\.agentdeck|diagnostic|selfcheck|diagnostics-report|AGENTDECK_DATA_DIR|runs" README.md AgentDeck_v0.1_Product_Definition_Workbench.md docs
```

Expected: 没有过时的 `.agentdeck/runs` 作为当前实现路径；如历史产品定义保留旧路径，必须标注为旧草案或更新。

**Step 3: 提交**

```bash
git add README.md AgentDeck_v0.1_Product_Definition_Workbench.md
git commit -m "docs: document logging diagnostics behavior"
```

---

## 最终验证

执行完整门禁：

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
swift test
cargo build
diag_dir="$(mktemp -d)"
AGENTDECK_DATA_DIR="$diag_dir" swift run AgentDeck -- --selfcheck
AGENTDECK_DATA_DIR="$diag_dir" swift run AgentDeck -- --diagnostics-report --json
git status --short --branch
```

Expected:

- fmt / clippy / Rust tests / Swift tests 全部通过。
- selfcheck 输出 `selfcheck OK: IPC lifecycle + logging clean.` 或等价明确成功文案。
- diagnostics report 输出合法 JSON，包含 `schemaVersion`、`failures[]`、`nextChecks[]` 和路径 hint。
- 临时 `AGENTDECK_DATA_DIR` 下出现 `runs/*.jsonl` 和结构化 JSONL `diagnostic.log`。
- 临时日志里不出现 `sk-agentdeck-selfcheck` 或 `Bearer agentdeck-selfcheck-token` 明文。
- `git status` 只剩预期提交，工作区干净。

## 推荐提交顺序

1. `fix: surface daemon warnings in session UI`
2. `fix: warn when run recording fails during streams`
3. `test: make AgentDeck data dir configurable`
4. `feat: structure diagnostic logs for agent triage`
5. `fix: strengthen log redaction coverage`
6. `fix: avoid run record id collisions`
7. `fix: preserve unknown adapter events as raw records`
8. `test: extend selfcheck to cover logging`
9. `feat: add agent diagnostics report`
10. `docs: add agent diagnostics guide`
11. `docs: document logging diagnostics behavior`

## Execution Handoff

Plan complete and saved to `docs/plans/2026-05-20-agentdeck-logging-hardening-implementation.md`.

Two execution options:

1. **Subagent-Driven (this session)** - dispatch a fresh subagent per task, review between tasks, and iterate quickly.
2. **Parallel Session (separate)** - open a new session with @superpowers:executing-plans and execute the plan with checkpoints.

Before either option, create or switch to a dedicated worktree/branch for this feature so the existing uncommitted work is not mixed with logging changes.
