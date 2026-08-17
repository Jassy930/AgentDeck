# AgentDeck 质量与验证

本页集中当前仍有效、可机械执行的质量入口。桌面端已经重置为 GPUI 最小壳，旧
AppKit 功能对等清单和覆盖率基线不再适用。

## 常用验证命令

```bash
# GPUI 桌面
cargo check -p agentdeck-desktop
cargo test -p agentdeck-desktop
cargo run -p agentdeck-desktop -- --selfcheck
bash -n script/build_and_run.sh
./script/build_and_run.sh --verify

# iOS 共用 Swift Core
swift test

# backend / protocol（改到对应层时）
cargo test
cargo run -p agentdeck-cli -- selfcheck
scripts/verify-agent-docs.sh
```

## GPUI 桌面 P0 门禁

涉及 `agentdeck-desktop/`、Cargo workspace 或桌面打包脚本时至少运行：

```bash
cargo fmt --check -p agentdeck-desktop
cargo test -p agentdeck-desktop
cargo run -p agentdeck-desktop -- --selfcheck
bash -n script/build_and_run.sh
./script/build_and_run.sh --verify
```

selfcheck 的成功输出必须是单行 JSON，并明确包含：

```json
{"status":"ok","surface":"desktop","ui":"gpui"}
```

该 selfcheck 只验证 GPUI application、Metal renderer、隐藏窗口、
`gpui-component::init` 和 `Root`。它不能证明 daemon、IPC 或 vendor CLI
健康。

`--verify` 必须读回：

- 实际启动进程的 executable path 等于 `dist/AgentDeck.app/Contents/MacOS/AgentDeck`。
- `Info.plist` 的 `LSMinimumSystemVersion` 为 15.0。
- Mach-O 的 `minos` 为 15.0。

当前 P0 bundle 不携带、也不启动 `agentdeckd`。

## 桌面人工冒烟

每个可交互桌面切片完成前至少确认：

- [ ] `AgentDeck.app` 打开真实窗口并成为前台应用。
- [ ] 窗口能看到“AgentDeck”和“GPUI 桌面端已启动”。
- [ ] “关闭”按钮能退出应用。
- [ ] 重新运行统一脚本能停止旧 bundle 实例并启动最新二进制。
- [ ] 未实现的 daemon、会话和历史能力没有伪 UI 或成功提示。

只有实际检查过窗口后才能勾选；进程存在不能替代视觉和点击证据。

## Swift Core 门禁

`Package.swift` 只承载 iOS 使用的 `AgentDeckMobileCore`。改动
`Sources/AgentDeckMobileCore/`、协议 Swift mirror 或 `Tests/AgentDeckMobileCoreTests/` 时运行：

```bash
swift test
```

macOS 桌面不得重新依赖 Swift target；共享 Core 测试也不得重新导入已经删除的
`AgentDeck` executable。

## 按变更范围选择验证

| 变更范围 | 最小验证 |
| --- | --- |
| GPUI 视图、状态或组件 | `cargo test -p agentdeck-desktop`、desktop selfcheck、真实窗口冒烟 |
| 桌面 bundle 或启动脚本 | `bash -n script/build_and_run.sh`、`./script/build_and_run.sh --verify` |
| Swift Core / iOS 共享模型 | `swift test`；涉及 iOS 时再跑 iOS Simulator 测试 |
| daemon、adapter、record、diagnostics | 对应 focused test，再跑 `cargo test` 和 CLI selfcheck |
| agentdeck-protocol | `cargo test`；漂移时按下文重生成 schema |
| 文档、AGENTS、计划规则 | `scripts/verify-agent-docs.sh` |
| 全局依赖或 workspace | `cargo test`、`swift test`、desktop selfcheck、doc check |

## Codex vendor schema 快照

`protocol/ClientRequest.json` 等文件是 Codex app-server 的 vendor 协议快照，
与 AgentDeck 自身 schemars 生成的
`protocol/agentdeck/agentdeck-protocol.schema.json` 是两套独立门禁。
`cargo test` 通过不能证明本机 Codex 版本与 vendor 快照一致。

升级刷新或同版本复验时，都先在临时目录 fail-closed 生成，并记录本机
Codex 的实际版本：

```bash
CODEX_BIN="$(command -v codex)"
ACTUAL_VERSION="$("$CODEX_BIN" --version)"
SCHEMA_DIR="$(mktemp -d /tmp/agentdeck-codex-schema.XXXXXX)"
"$CODEX_BIN" app-server generate-json-schema --out "$SCHEMA_DIR"

jq -er '
  .oneOf as $requests
  | if (($requests | type) != "array") or (($requests | length) == 0) then
      error("ClientRequest.oneOf missing or empty")
    elif any($requests[];
      ((.properties.method.enum | type) != "array")
      or ((.properties.method.enum | length) != 1)
      or ((.properties.method.enum[0] | type) != "string")) then
      error("unexpected ClientRequest method schema")
    else
      [$requests[].properties.method.enum[0]] as $methods
      | if (($methods | length) != ($methods | unique | length)) then
          error("duplicate ClientRequest methods")
        else $methods | sort[] end
    end
' "$SCHEMA_DIR/ClientRequest.json" > "$SCHEMA_DIR/client-methods.txt"
```

升级刷新时，将 `ClientRequest.json`、`JSONRPCMessage.json`、
`ServerNotification.json`、`ServerRequest.json`、
`codex_app_server_protocol.v2.schemas.json` 与 `client-methods.txt` 复制到
`protocol/`，再把 `ACTUAL_VERSION` 写入 `CODEX_VERSION.txt`。同版本复验时先运行：

```bash
test "$ACTUAL_VERSION" = "$(cat protocol/CODEX_VERSION.txt)"
```

四个独立 schema 与 `client-methods.txt` 的输出顺序稳定，提交前逐文件运行
`cmp`。聚合的 `codex_app_server_protocol.v2.schemas.json` 中 definitions 顺序
可能在相同版本的两次官方生成之间变化，必须用 `jq -S` 规范化后比较，不能把
raw byte 顺序差异误判成协议漂移：

```bash
jq -S . protocol/codex_app_server_protocol.v2.schemas.json \
  > "$SCHEMA_DIR/committed-v2.normalized.json"
jq -S . "$SCHEMA_DIR/codex_app_server_protocol.v2.schemas.json" \
  > "$SCHEMA_DIR/generated-v2.normalized.json"
cmp "$SCHEMA_DIR/committed-v2.normalized.json" \
  "$SCHEMA_DIR/generated-v2.normalized.json"
```

确认 method 表行数和内容一致后，再运行 `cargo test`、
`scripts/verify-agent-docs.sh` 和 `git diff --check`。当前稳定合约不使用
`--experimental`；只有客户端显式启用 `experimentalApi` 时才建立独立实验基线。

## AgentDeck IPC schema 漂移测试

`cargo test` 会在 `agentdeck-protocol` 测试套件中运行
`schema_matches_committed_snapshot`：比较 schemars 从 Rust 类型实时生成的
JSON Schema 与 `protocol/agentdeck/agentdeck-protocol.schema.json` 快照。若两者
不一致，说明 AgentDeck IPC 类型已变更但快照未更新，测试失败。

重新生成快照：

```bash
UPDATE_SCHEMA=1 cargo test -p agentdeck-protocol schema_matches_committed_snapshot
```

重新生成后须将快照提交进仓库（`git add protocol/agentdeck/agentdeck-protocol.schema.json`）。

核对快照与当前代码是否同步（独立验证，无需构建测试二进制）：

```bash
cargo run -q -p agentdeck-cli -- protocol schema \
  | diff - protocol/agentdeck/agentdeck-protocol.schema.json \
  && echo "schema in sync"
```

## 门控 E2E 测试

`agentdeck-cli/tests/e2e_codex.rs`、`e2e_claude_code.rs` 和
`e2e_cross_agent_history.rs` 是真实 daemon / vendor CLI 的 E2E 集成测试。
启用方式：

```bash
AGENTDECK_E2E=1 cargo test -p agentdeck-cli --test e2e_codex -- --nocapture
AGENTDECK_E2E=1 cargo test -p agentdeck-cli --test e2e_claude_code -- --nocapture
AGENTDECK_E2E=1 cargo test -p agentdeck-cli --test e2e_cross_agent_history -- --nocapture --test-threads=1
```

**门控机制：** 每个测试在未设置环境变量 `AGENTDECK_E2E` 时 `eprintln!("skipped...")` 后直接早返回（不是 `#[ignore]`，因此不能用 `--ignored` 启用；标准 `cargo test` 中显示为 passed 而非 ignored）。设 `AGENTDECK_E2E=1`（需 `codex login`）才真正运行。

**前置条件：** `codex login` 已完成（测试会真实 spawn daemon 并发送 IPC）。

**断言策略：** E2E 测试只断言响应的契约形态（消息 kind、必要字段存在、退出码等），不断言 agent 返回的具体文本内容，以避免测试因模型输出变化而 flaky。

**CI 默认跳过：** 不设置 `AGENTDECK_E2E=1` 时，标准 `cargo test` 不触发真实 E2E，不需要 `codex login`。

## 文档结构检查

`scripts/verify-agent-docs.sh` 是当前最小 doc-gardening 检查。它验证：

- 关键文档入口存在。
- `AGENTS.md` 链接到项目北极星、README、架构、诊断、质量、计划和协议事实源。
- `README.md` 链接到架构、文档索引和质量文档。
- 项目没有重新引入已剥离的外部 skill 强制绑定。
- `docs/plans/README.md` 存在，计划文档不再只是散落文件。

后续接入 CI 时，先把这个脚本作为独立 job，再逐步增加更严格的结构检查。

## 失败处理

- 验证失败时，不要只重跑。先读失败输出，定位是哪条不变量被破坏。
- 如果失败来自文档漂移，优先更新真实文档或检查脚本，不要绕过规则。
- 如果失败来自 flaky 外部条件，记录命令、错误和复验结果到对应计划文档。

## GPUI P0 收口清单

1. 更新与行为变化直接相关的文档。
2. 运行桌面测试、selfcheck、bundle verify 和 Swift Core 测试。
3. 真实查看并点击新窗口。
4. 运行 `git diff --check` 与 `git status --short --branch`。
5. 报告未实现的 backend 边界，不把 P0 描述为完整客户端。
