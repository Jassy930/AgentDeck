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

# 默认离线的 Rust workspace 门禁
scripts/verify-offline-tests.sh

# 上述 tripwire 内执行的标准 Cargo 命令
env -u AGENTDECK_E2E cargo test --workspace --locked

# 绑定当前 checkout daemon 的 CLI selfcheck
cargo build --locked \
  -p agentdeckd --bin agentdeckd \
  -p agentdeck-cli --bin agentdeck
AGENTDECK_DAEMON_BIN="$PWD/target/debug/agentdeckd" \
  ./target/debug/agentdeck \
  --data-dir /tmp/agentdeck-selfcheck selfcheck

scripts/verify-agent-docs.sh
```

`scripts/verify-offline-tests.sh` 在临时目录创建会写 marker 并失败的 `codex` / `claude`
shim，把它们放到 PATH 首位，并使用临时 HOME 隔离用户 vendor history 与
默认 AgentDeck data dir。脚本分别在
`AGENTDECK_E2E` 未设置和等于 `0` 时运行完整 workspace 测试；空值、`false` 和其他值
运行所有 gated integration targets，每次都断言 marker 不存在。Rust gate 单测另行覆盖
纯值矩阵；version/auth probe 的普通单测使用可注入 fake，不探测用户 PATH 中的真实
vendor。标准 Cargo 测试因此可作为默认离线门禁，但其中提前跳过的 E2E 显示 passed
不构成真实 vendor 证据。

## 默认离线 CI

`.github/workflows/offline-ci.yml` 在 pull request 和 `master` push 上运行。稳定 required
check 名称是 `Offline CI / offline`，使用 `macos-15`，按顺序执行：

1. `cargo fmt --all -- --check`。
2. `node designs/agentdeck-design-system/tools/build.mjs --check-desktop`，只读比对
   SSOT 应生成的 Rust 颜色与 `agentdeck-desktop/src/theme_tokens.rs`，漂移时失败。
3. `scripts/verify-offline-tests.sh`，且入口显式 unset `AGENTDECK_E2E`。
4. 构建当前 checkout 的 `agentdeckd` 与 `agentdeck`。
5. 显式 unset `AGENTDECK_E2E`，以
   `AGENTDECK_DAEMON_BIN=$GITHUB_WORKSPACE/target/debug/agentdeckd` 和临时 data dir 运行
   CLI selfcheck，禁止命中旧 sibling 或系统安装；显式路径无效时必须 fail fast，不得
   fallback。
6. 再次显式 unset gate，通过同一对当前 checkout 二进制输出 AgentDeck protocol schema
   并与快照比较。
7. `swift test` 和 `scripts/verify-agent-docs.sh`。

该 workflow 不设置 `AGENTDECK_E2E=1`，不运行真实 Codex / Claude Code，也不运行 iOS
Simulator。`swift test` 只覆盖平台无关的 `AgentDeckMobileCore`；UIKit Simulator 仍按
iOS 变更范围在本地单独执行。

## GPUI 桌面 P0 门禁

涉及 `agentdeck-desktop/`、Cargo workspace 或桌面打包脚本时至少运行：

```bash
cargo fmt --check -p agentdeck-desktop
cargo test -p agentdeck-desktop
cargo run -p agentdeck-desktop -- --selfcheck
bash -n script/build_and_run.sh
./script/build_and_run.sh --verify
```

颜色来自 `designs/agentdeck-design-system/tokens/tokens.json`。修改源 token 或生成器后，
在设计系统目录运行 `bun run check` 生成并验证 Web / iOS / GPUI 产物；Rust 漂移检查
使用上面的只读命令。配色实窗验收覆盖正文、行内与 fenced code、警告展开、侧栏选中
和输入选区；共享 token 改动涉及 iOS 生成物时，同时执行 Swift 与 iOS Simulator 测试。

selfcheck 的成功输出必须是单行 JSON，并明确包含：

```json
{"status":"ok","surface":"desktop","ui":"gpui"}
```

该 selfcheck 只验证 GPUI application、Metal renderer、隐藏窗口、
`gpui-component::init` 和 `Root`；它显式不连接 daemon，因此也不能证明 daemon、IPC
或 vendor CLI 健康。selfcheck 路径一旦开始 spawn daemon，子进程的 stderr 会破坏
「单行 JSON」这条门禁。

`--verify` 必须读回：

- 实际启动进程的 executable path 等于 `dist/AgentDeck.app/Contents/MacOS/AgentDeck`。
- `Contents/MacOS/agentdeckd` 存在且可执行（桌面的历史数据靠它）。
- `Info.plist` 的 `LSMinimumSystemVersion` 为 15.0。
- Mach-O 的 `minos` 为 15.0。
- `CFBundleIconFile` 指向 `AgentDeck.icns`，bundle 内图标与 `assets/brand/AgentDeck.icns` 一致。

`cargo` 不把 `MACOSX_DEPLOYMENT_TARGET` 计入 fingerprint，普通 `cargo build` /
`cargo test` 会留下 `minos=11.0` 的产物；脚本因此在构建前 touch 桌面入口文件强制
重新链接。改动构建脚本后必须重跑 `--verify` 确认这条仍然成立。

## 桌面人工冒烟

每个可交互桌面切片完成前至少确认：

- [ ] `AgentDeck.app` 打开真实窗口并成为前台应用。
- [ ] 侧栏渲染出品牌行、快捷入口、最近会话和本机 Agent 状态四段结构。
- [ ] 侧栏的会话来自 daemon：按来源与 `agentdeck history list --agent <kind> --limit 50`
      对比条目标题、数量（CLI 不指定 limit 时默认总上限为 500）；
      加载中显示“正在读取会话…”，失败显示 daemon 返回的错误，无结果显示“没有可显示的会话”。
- [ ] 部分来源失败时，成功来源仍可打开；失败来源在侧栏显示“读取失败”与错误原因，
      空态卡片同样显示失败，不把它当作 0 条。A→B→A 切换时旧读取结果不覆盖新结果。
- [ ] 快速切换 A→B→C 时最多一个历史读取在执行，等待中的 B 被 C 替换；切回空态
      不再启动待查会话。所有来源完成且列表为空时，显示“没有可显示的会话”。
- [ ] 空态渲染居中标题、composer 和按已注册 agent 生成的卡片；激活侧栏条目切到会话态并
      加载该会话记录，激活“新建会话”切回空态；焦点移入 composer 后，当前条目仍显示选中态。
- [ ] composer 可直接键入、粘贴中文多行文本；切换形态保留草稿，并显示当前会话的项目
      与 agent（空态显示“未选择”）。
- [ ] 发送和搜索禁用，模型、审批和沙箱标明暂不可用；空态卡片与侧栏 agent 区计数一致。
- [ ] 空态与会话态顶部双击均遵循系统设置；窗口拖动单独验收。
- [ ] 最小窗口中的长会话标题省略显示，右侧 agent / 项目信息仍可见。
- [ ] Tab 聚焦虚拟会话列表后，上下键能越过可见区并滚到目标，Return 打开该会话；
      Tab / Shift-Tab 能离开列表，composer 中的方向键不触发会话导航。
- [ ] composer 输入框聚焦时，`Command+Q` 能退出整个桌面进程；AgentDeck 菜单中的
      “退出 AgentDeck”同样生效。
- [ ] 重新运行统一脚本能停止旧 bundle 实例并启动最新二进制。
- [ ] 未实现的会话启动、turn、streaming 和审批能力没有伪 UI 或成功提示；桌面显示的
      历史必须与 daemon 返回一致，不得在 UI 侧补数据或掩盖空结果。

只有实际检查过窗口后才能勾选；进程存在不能替代视觉和交互证据。

布局类改动用**窗口级截图**留证，避免其他应用遮挡。先确认 AgentDeck 已成为前台，
优先通过真实 UI 的 Tab / Shift-Tab / Return 导航切换形态；不要以 AX click 成功返回
代替实际交互结果。窗口截图示例：

```bash
# 取窗口 ID
cd /tmp && uv run --quiet --with pyobjc-framework-Quartz python -c "
import Quartz
wins = Quartz.CGWindowListCopyWindowInfo(
    Quartz.kCGWindowListOptionOnScreenOnly | Quartz.kCGWindowListExcludeDesktopElements,
    Quartz.kCGNullWindowID)
for w in wins:
    if 'AgentDeck' in str(w.get('kCGWindowOwnerName', '')):
        print(w.get('kCGWindowNumber'))
"
screencapture -x -o -l <WINID> /tmp/agentdeck-shot.png
```

截图使用最终代码构建的窗口，通过真实 UI 进入目标形态，不改初始 `stage`。
环境限制导致键入、导航、双击或拖动无法实际完成时，对应项目如实标为未验证。

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
| daemon、adapter、record、diagnostics | `scripts/verify-offline-tests.sh`、对应 focused test，以及通过 `AGENTDECK_DAEMON_BIN` 绑定当前 checkout 的 CLI selfcheck |
| agentdeck-protocol | `cargo test -p agentdeck-protocol`；漂移时按下文重生成 schema |
| 文档、AGENTS、计划规则 | `scripts/verify-agent-docs.sh` |
| 全局依赖或 workspace | `scripts/verify-offline-tests.sh`、`swift test`、desktop selfcheck 和 doc check；真实 vendor E2E 仍需单独授权和记录 |

Issue #3 Codex 生命周期切片的 focused 离线入口为：

```bash
cargo test -p agentdeck-protocol
cargo test -p agentdeck-cli --bin agentdeck
cargo test -p agentdeckd --lib codex::
cargo test -p agentdeckd --lib runtime::hub
cargo test -p agentdeckd --lib runtime::router
cargo test -p agentdeckd --test codex_adapter_shape
swift test
```

它们具体检测 protocol v4/schema 与 Swift mirror 漂移、不同 binary probe/spawn、错误
`app-server --listen stdio://` argv、`initialized` 乱序、RPC/turn/session 状态机和
`SessionClosed` 清理顺序。当前确定性覆盖还包括同 connection 两轮、interrupt 后复用、
running close、malformed/unmatched/EOF、handshake failure、unsupported request、terminal
status、resume 固定参数、terminal 先于 rejected interrupt response 的 cancel/close 竞态、
accepted turnId 不可复用、session-admission 守住旧 `SessionClosed` 与 replacement start 的
先后、Initializing/Stopping 命令及时拒绝、direct child wait 后进程组消失确认与 stderr pump join，
stdin EOF、stdout writer failure，以及 cleanup failure 的 poison→daemon exit。出现失败时应分别回到协议类型、Codex factory/session owner 或
RuntimeHub/router 修正；这些离线证据不能升级为真实 Codex E2E。

## Codex vendor schema 快照

`protocol/ClientRequest.json` 等文件是 Codex app-server 的 vendor 协议快照，当前固定为
`codex-cli 0.155.0-alpha.16`，包含完整版本后缀。live session 与 short-lived history
path 都发送规范的 `initialized`，fake 测试守护 initialize response
→ initialized → thread request 顺序。这套 vendor 快照与 AgentDeck 自身 schemars 生成的
`protocol/agentdeck/agentdeck-protocol.schema.json` 是两套独立门禁。
`cargo test` 通过不能证明本机 Codex 版本与 vendor 快照一致。

历史正文使用稳定的 `thread/turns/list`，参数与响应保存在同一套官方默认生成物中，
无需 `experimentalApi` 或单独的 experimental 快照。真实读取验收必须覆盖 paginated
历史，只验证 `kind=list` 或合法空列表不足以证明正文可读；后续页面失败不能算完整
读取通过。历史读回也不能替代升级后的真实 lifecycle E2E 与桌面正文点击验收。

daemon 在 macOS 先探测桌面端 App 自带 executable，再探测 PATH 和常见 CLI 安装位置。
历史 list/read 使用首个探测成功的候选，版本不同时携带 warning；live session 仍跳过
不匹配候选，要求精确匹配。`command -v codex` 不代表 daemon 实际使用的路径。
离线 locator 用例须分别验证两种策略，以及
非零退出与非法输出停止查找、慢探测不阻塞 runtime，以及候选共享 5 秒探测预算；
history 候选查找与 RPC 须共享 28 秒工作预算并预留清理。probe 与 spawn 始终绑定同一
规范化绝对路径，CLI fake 用例覆盖探测失败不会启动后续系统候选。
`AGENTDECK_CODEX_BIN` 显式绝对路径覆盖自动查找，错误时不回退；CLI fake 必须用它绑定
假程序，离线门禁用它绑定 Codex marker，防止桌面端优先查找绕过 PATH 中的 shim。
历史 warning 测试覆盖未验证版本仍成功、匹配版本无 warning、跨来源空列表保留 warning、
CLI stdout 不变与 stderr 提示、桌面来源和正文提示，以及实际 RPC/解码失败不返回残缺结果。
IPC v5 的 warning 类型须同步 schema；真实只读验收仍需本机列表、分页正文与实际窗口。
回归测试同时覆盖完整 admin 成功回复的 Rust/Swift 解码、warnings 缺省与编码省略、
列表失败清除旧 warning，以及正文 warning 的默认折叠与展开状态。

升级刷新或同版本复验时，都先在临时目录 fail-closed 生成，并记录本机
Codex 的实际版本。显式指定要生成快照的 executable，不依赖 PATH 首项：

```bash
CODEX_BIN="/Applications/ChatGPT.app/Contents/Resources/codex"
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

升级刷新时，将 `ClientRequest.json`、`ClientNotification.json`、`JSONRPCMessage.json`、
`ServerNotification.json`、`ServerRequest.json`、
`codex_app_server_protocol.v2.schemas.json` 与 `client-methods.txt` 复制到
`protocol/`，再把 `ACTUAL_VERSION` 写入 `CODEX_VERSION.txt`。同版本复验时先运行：

```bash
test "$ACTUAL_VERSION" = "$(cat protocol/CODEX_VERSION.txt)"
```

五个独立 schema 与 `client-methods.txt` 的输出顺序稳定，提交前逐文件运行
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

当前稳定 method 表为 101 项；旧 `thread/rollback` 已替换为 `thread/revert`，正文
分页进入稳定表。确认 method 表行数和内容一致后，运行 `scripts/verify-offline-tests.sh`、
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
cargo build --locked \
  -p agentdeckd --bin agentdeckd \
  -p agentdeck-cli --bin agentdeck
AGENTDECK_DAEMON_BIN="$PWD/target/debug/agentdeckd" \
  ./target/debug/agentdeck \
  --data-dir /tmp/agentdeck-schema protocol schema \
  | diff - protocol/agentdeck/agentdeck-protocol.schema.json \
  && echo "schema in sync"
```

## 门控 E2E 测试

`agentdeck-cli/tests/e2e_codex.rs`、`e2e_claude_code.rs` 和
`e2e_cross_agent_history.rs` 是真实 daemon / vendor CLI 的 E2E 集成测试。
启用方式：

```bash
cargo build --locked -p agentdeckd --bin agentdeckd
AGENTDECK_DAEMON_BIN="$PWD/target/debug/agentdeckd" AGENTDECK_E2E=1 \
  cargo test -p agentdeck-cli --test e2e_codex -- --nocapture
AGENTDECK_DAEMON_BIN="$PWD/target/debug/agentdeckd" AGENTDECK_E2E=1 \
  cargo test -p agentdeck-cli --test e2e_claude_code -- --nocapture
AGENTDECK_DAEMON_BIN="$PWD/target/debug/agentdeckd" AGENTDECK_E2E=1 \
  cargo test -p agentdeck-cli --test e2e_cross_agent_history -- \
  --nocapture --test-threads=1
```

**当前门控机制：** 所有真实 session、prompt、history、auth 和 vendor process 测试只在
环境变量 `AGENTDECK_E2E` 的值严格等于 `1` 时进入。未设置、空值、`0`、`false` 和
其他值都会在任何真实 vendor I/O 前提前返回；这些测试不是 `#[ignore]`，因此在标准
Cargo 测试中显示为 passed 而非 ignored。

**前置条件：** `codex login` 已完成（测试会真实 spawn daemon 并发送 IPC）。
Codex E2E 在显式门控后使用 daemon 的候选定位，不因 PATH 中没有 `codex` 而跳过；
仅安装在受支持 App 路径中的匹配版本也能进入验收。

**断言策略：** E2E 测试只断言响应的契约形态（消息 kind、必要字段存在、退出码等），不断言 agent 返回的具体文本内容，以避免测试因模型输出变化而 flaky。

**持久 CLI 门禁：** `session live` 读取 typed ClientCommand JSONL，并持有一个 daemon。
`session_live` integration 用 fake Codex 驱动真实 CLI/daemon 子进程，验证四轮、Ping、取消恢复、EOF、坏输入清理，以及记录 open/append/close 失败不阻断会话。
离线脚本会先构建当前 daemon 并以绝对路径绑定这些用例。

真实生命周期只运行显式门控的用例：

```bash
AGENTDECK_DAEMON_BIN="$PWD/target/debug/agentdeckd" AGENTDECK_E2E=1 \
  cargo test --locked -p agentdeck-cli --test e2e_codex \
  e2e_codex_live_four_turn_lifecycle -- --nocapture
```

该用例经实际 CLI 验证同一 child PID/threadId 的两轮、第三轮取消、第四轮成功、
SessionClosed 与进程组消失，再读回一个包含全部事件和 footer 的 run record。
原 run/continue E2E 仍只证明 one-shot/resume，不能替代持久会话验收。

**CI 默认跳过：** workflow 显式 unset `AGENTDECK_E2E`；三组 CLI E2E 和 adapter
real-vendor shape 路径都会在 vendor I/O 前返回，不需要 vendor 登录。普通 CI passed
只证明默认路径保持离线，不证明真实 Codex / Claude Code 链路可用。

## 文档结构检查

`scripts/verify-agent-docs.sh` 是当前最小 doc-gardening 检查。它验证：

- 关键文档入口存在。
- `AGENTS.md` 链接到项目北极星、README、架构、诊断、质量、计划和协议事实源。
- `README.md` 链接到架构、文档索引和质量文档。
- 项目没有重新引入已剥离的外部 skill 强制绑定。
- `docs/plans/README.md` 存在，计划文档不再只是散落文件。

默认 `Offline CI / offline` check 会执行该脚本；新增或移动事实源文档时必须同步更新
脚本及本页入口。

## 失败处理

- 验证失败时，不要只重跑。先读失败输出，定位是哪条不变量被破坏。
- 如果失败来自文档漂移，优先更新真实文档或检查脚本，不要绕过规则。
- 如果失败来自 flaky 外部条件，记录命令、错误和复验结果到对应计划文档。

## GPUI P0 收口清单

1. 更新与行为变化直接相关的文档。
2. 运行 `cargo fmt --check -p agentdeck-desktop`、桌面测试、selfcheck、bundle verify
   和 Swift Core 测试。`cargo check` 通过不代表 fmt 通过，两者都要跑。
3. 真实查看并点击新窗口，布局改动留窗口级截图。
4. 运行 `git diff --check` 与 `git status --short --branch`。
5. 报告未实现的 backend 边界，不把 P0 描述为完整客户端。
