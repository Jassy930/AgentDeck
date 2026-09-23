# GPUI 桌面接入真实会话（只读历史）实施记录

日期：2026-09-22

## Goal

把 GPUI 桌面端的示例会话换成本机 `agentdeckd` 返回的真实历史：侧栏显示真实会话
列表，点击后在主区渲染该会话的真实记录。本切片只读，不启动 session、不发 turn。

## Architecture

- `agentdeck-desktop/src/daemon.rs`：桌面自己的 typed local client。每次请求
  spawn 一个 `agentdeckd` 子进程，写一行 `ClientCommand`，关闭 stdin，读到匹配的
  admin reply 后最多等待 2 秒让 daemon 正常退出，超时则终止并回收进程。
  - 不复用 `agentdeck-cli`：CLI 是 bin-only、依赖 clap/tokio，且架构上与 GUI 互相独立。
  - 不维护长连接：history 在 daemon 内部本来就是短生命周期调用（Codex 每次另起
    app-server，CC 每次扫描本地 JSONL），一个连接只发一条命令。每次历史请求仍按
    K11 生成唯一 `requestId`，成功与错误回复都必须严格匹配。session streaming
    需要长连接时再单独引入。
  - daemon 定位：`AGENTDECK_DAEMON_BIN`（必须是绝对可执行路径，不回退）→
    可执行文件同目录（`.app` bundle 内）→ `target/debug` / `target/release`。
  - macOS 在 child `pre_exec` 中用 `sigemptyset` / `sigprocmask` 恢复空 signal mask，
    让 daemon 的 Tokio child wait 能接收 `SIGCHLD`，不改变父 GCD worker 的 mask。
- `agentdeck-desktop/src/shell.rs`：`Shell` 保存合并后的会话与各 agent 的加载结果；
  加载中、成功计数和失败原因分别保留，侧栏与空态共用状态文案。
  `Stage::Session` 持有 `HistoryListItem`、`Transcript`（Loading / Ready / Failed）与
  本次读取序号，切走后重开同一会话也只接受最新读取结果。加载顺序是先 `AgentList`，
  再按 agent 各发一次 `History::List`，谁先返回谁先进侧栏，慢的来源不挡快的。
  各来源首批显示 50 条，查询时多取 1 条判断是否还有更多；“加载更多”将该来源的
  显示目标增加 50 条，复用现有 `limit` 查询重读列表，成功后替换同来源条目以避免
  重复，保留其他来源。加载中或失败时保留已有列表与计数；重试沿用失败请求的目标
  数量。读完显示“已全部加载”，达到中立协议的每来源 2,000 条上限时明确提示。
  阻塞 IPC 全部走 `cx.background_executor()`。
  `AgentList`、`History::List` 与 `History::Read` 失败后在后台等待 1 秒自动重试一次；
  仍失败时分别提供 daemon 连接、来源列表与正文的重试按钮。加载期间不重复触发
  同一请求；来源重试保留其他来源的列表，正文重试沿用 `ReadQueue` 与 `read_id`，
  只接受当前会话的最新读取结果。
  会话读取最多执行一个，等待期间只保留最新待查会话；切回空态清空待查项，正在
  执行的读取仍由 daemon 按自身时限完成并清理。
- `agentdeck-desktop/src/transcript.rs`：把中立 `AgentItem` 映射成「标签 + 正文」
  文本块，单条正文上限 2000 字符；后台读取完成时转换一次，渲染复用最终文本。
- `script/build_and_run.sh`：bundle 内同时装配 `agentdeckd`，`--verify` 额外断言它存在。

## 关键决策与坑点

- **selfcheck 不连 daemon**。`Shell::new(window, connect_daemon, cx)` 由 `--selfcheck`
  传 `false`，否则隐藏窗口也会 spawn daemon，stderr 会多出 `Broken pipe`，污染
  「成功输出必须是单行 JSON」的门禁。
- **侧栏每个 agent 首批显示 50 条，按需扩展 50 条**。沿用已有 `limit` 查询与
  中立协议的 2,000 条上限，没有新增 IPC 字段或依赖。每次多查 1 条判断“加载更多”
  是否可用，上限处停止扩展并明确提示。Codex 的 `thread/list` 按页聚合，500 条曾
  实测约 27 秒、逼近 daemon 的历史超时；扩展加载仍受该预算约束，失败保留已有列表。
- Codex 的候选查找使用异步版本探测，所有候选共享 5 秒探测预算，结束后终止独立
  进程组，并最多用 2 秒确认直接子进程已回收。history 从候选查找开始计入 28 秒
  工作预算，另预留 2 秒清理；超时与清理失败分别返回稳定 failure code。
- **GPUI 的 macOS GCD worker 会屏蔽 `SIGCHLD`**，`std::process::Command` 会将 mask
  传给 daemon，导致版本子进程已退出为 defunct，Tokio 仍等到 5 秒超时。2026-09-23
  对照中，相同环境、cwd 和 stdin EOF 的历史 list 在普通父线程下 1.58 秒成功；
  Python 父线程屏蔽 `SIGCHLD` 后，同一 daemon 在 5.02 秒返回版本探测超时。
  修复放在桌面启动子进程的边界；自动重试用于失败后的恢复，不能消除继承的 signal mask。
- **flex 滚动要 `min_h(0)`**。GPUI 用 taffy，flex item 默认按内容撑高，`overflow_y_scroll`
  单独用不会限制高度，长记录会顶穿底部 composer。transcript 和侧栏列表都加了
  `min_h(px(0.))`，会话区外层再加 `overflow_hidden` 兜底。
- 会话标题允许收缩并以省略号截断，右侧 agent / 项目不收缩，长标题不会挤出环境信息。
- **`cargo` 不把 `MACOSX_DEPLOYMENT_TARGET` 计入 fingerprint**。普通 `cargo build` /
  `cargo test` 会留下 `minos=11.0` 的产物，脚本直接拷会让 `--verify` 失败；脚本现在
  先 `touch agentdeck-desktop/src/main.rs` 强制重新链接。
- **`cargo build -p A -p B --bin X` 会把 target 过滤到只剩 `X`**，A 根本不构建。脚本
  里两个包只能各自用 `-p`，不能加 `--bin`。
- UI 不硬编码 vendor：agent 展示名由 `AgentKind::as_str()` 派生（`claude_code` →
  `Claude Code`），空态卡片与侧栏 agent 区都按 daemon 返回的列表迭代。

## 验证结果

2026-09-22 在 macOS 15 arm64 本机完成：

```bash
cargo fmt --check -p agentdeck-desktop
cargo test -p agentdeck-desktop          # 9 passed
cargo run -p agentdeck-desktop -- --selfcheck
bash -n script/build_and_run.sh
./script/build_and_run.sh --verify
scripts/verify-offline-tests.sh          # verify-offline-tests: ok
scripts/verify-agent-docs.sh
```

- selfcheck 输出仍是 `{"status":"ok","surface":"desktop","ui":"gpui"}`，无额外 stderr。
- `--verify` 读回当前 bundle 的 pid、自带 `agentdeckd`、`LSMinimumSystemVersion=15.0`
  与 Mach-O `minos=15.0`。
- 真实链路目视验证：侧栏显示 42 条 Claude Code 会话（真实标题、按最近活动排序），
  底部 agent 区显示 `Codex 0 / Claude Code 42`；打开会话后主区渲染该会话的真实
  user / 命令 / 工具条目。截图通过 `screencapture -l <windowId>` 取窗口，不模拟鼠标点击。
- 本机 Codex `history list` 返回空列表（CLI 复验同样为 `{"kind":"list","value":[]}`），
  桌面显示的 0 条是对 daemon 返回的忠实反映，不是 desktop 侧的解析问题。

当前代码在 macOS 27 arm64 上补充完成离线验收：

- `cargo fmt --all -- --check`、13 项 desktop 单测、`scripts/verify-offline-tests.sh`、
  `swift test`、desktop selfcheck、绑定当前 checkout daemon 的 CLI selfcheck、
  临时数据目录 diagnostics report、文档检查与 `git diff --check` 均通过。
- 通过 `AGENTDECK_DAEMON_BIN` 注入 fake daemon，以 `/bin/bash script/build_and_run.sh --verify`
  验证最终 bundle 路径、自带 daemon、Info.plist 与 Mach-O 最低版本。本机 Homebrew Bash
  在 heredoc 写入处挂起，验证使用系统 Bash；脚本未因此修改。
- fake 窗口验收使用同一可执行文件的临时独立 bundle 标识，以区分其他 worktree 实例。
  键盘操作 A→B→A，先完成新 A 再返回旧 A 错误，窗口仍显示新 A；侧栏保留失败来源
  的错误原因与成功来源的会话，空态卡片同样区分失败和数量。fake 回执含错 ID 错误和
  缺 ID 成功回复，均未截断当前请求；请求日志确认所有历史请求 ID 唯一。
- 长中文标题下右侧 agent / 项目信息可见。自动化鼠标接口返回 `noWindowsAvailable`，
  未完成真实窗口缩至 900px 或拖动验证；窗口交互使用键盘与原生 zoom 动作。
  使用当前 Taffy 样式对 900px 窗口对应的 652px header 做布局测量，右侧信息结束于
  632px，保留 20px 内边距，没有收缩或越界。
- 本次未启用 `AGENTDECK_E2E=1`，以上 fake 验收不构成新增真实 vendor 证据。

PR 评论修复后的验证：

- 17 项 desktop 单测、10 项 Codex capabilities 与 7 项 app-server focused 测试、
  全量离线门禁、desktop selfcheck、绑定当前 checkout daemon 的 CLI selfcheck、
  diagnostics report、格式与文档检查通过。版本探测的假 launcher 覆盖正常结束后
  子进程仍持有管道及探测超时两条路径，均确认直接子进程与已记录 helper PID 消失。
- 最终 bundle 经系统 Bash 的 `--verify` 通过。相同可执行文件的独立测试 bundle
  使用 fake daemon 验证 A→B→C；日志顺序为 A 开始、A 结束、C 开始、C 结束，B
  未执行，窗口显示 C 正文。侧栏与会话顶部的长标题显示省略号；失败来源加成功零条
  时，侧栏和主区均显示“没有可显示的会话”，来源错误仍可见。
- 未运行真实 vendor E2E；900px 实窗缩放和窗口拖动仍未取得验收证据。

## 已知缺口与后续

- Claude Code 会话标题常常是 `<local-command-caveat>Caveat: …`。这是
  `agentdeckd/src/claude_code/history.rs` 的标题抽取问题，应在 daemon 侧修，不要在
  desktop 打补丁。
- Codex 列表为空已定位为 provider 默认过滤，查询现在显式使用 `modelProviders=[]`。
  正文已适配稳定分页接口，版本与官方 schema 同步升级至 `0.155.0-alpha.16`；
  桌面正文点击已在 2026-09-23 补齐验收；升级后的真实 lifecycle E2E 尚未重跑。
- transcript 打开后停在顶部，没有自动滚到最新；同一 `toolUseId` 的 inProgress /
  completed 两条都会渲染。
- 没有客户端侧超时，依赖 daemon 自己的历史硬超时（见 `daemon.rs` 的 `ponytail:` 注释）。
- 仍属后续独立切片：启动/继续会话、turn 与 streaming、审批、Markdown 与 diff 渲染、
  会话搜索、按项目分组（CC 的 `cwd` 是从目录名还原的，带 `-` 的路径会还原错，不能
  直接拿来分组）。

## 2026-09-22：Codex 分页正文与版本升级

Goal：读取已存在的 legacy 与 paginated 历史，保持桌面/CLI 的中立历史响应不变。

- `agentdeckd/src/codex/app_server.rs` 与 `capabilities.rs`：在共享 5 秒预算内依次异步
  探测 PATH 和常见安装位置，只跳过成功读出但不匹配的版本；执行失败或非法输出返回
  `codex-version-probe-failed`，超时与清理失败也立即返回，不继续寻找候选。
  使用首个精确匹配版本的规范化绝对路径；probe 与 spawn 使用同一 executable。
  探测期间的 SessionClose 立即回执，owner 等待探测子进程与进程组清理后才确认退出；
  清理失败保持 `cleanup_confirmed=false`。
  macOS 增加 `/Applications/ChatGPT.app/Contents/Resources/codex` 候选，Homebrew
  0.145.0 安装保留不动。history 与 live 均使用稳定 API 握手，不启用 `experimentalApi`。
- `agentdeckd/src/codex/history.rs`：先 `thread/read(includeTurns=false)` 核对 threadId，
  再以 `thread/turns/list(itemsView=full, sortDirection=asc, limit=100)` 逐页追加轮次，
  直到 `nextCursor` 为空或缺失。候选查找与 RPC 共用 28 秒工作预算，另预留 2 秒清理；
  任一页失败不返回部分历史。
- `agentdeckd/src/codex/translate.rs`：把稳定 schema 的 `functionCallOutput` 映射为
  中立工具结果；`session.rs` 的 resume 使用 `excludeTurns=true`，仅消费 thread ID。
- `protocol/`：固定完整版本 `codex-cli 0.155.0-alpha.9.2`，同步更新官方默认生成的
  schema 与 101 项稳定方法枚举。`thread/turns/list` 已进入稳定 API，使用同一套
  快照；AgentDeck 自身 IPC v4 不变，没有手写 vendor schema。
- focused fake 子进程用例覆盖完整握手、两页顺序、游标传递/停滞、第二页解码/上游错误，
  并确认错误不包含 vendor 自由文本。CLI fake 用例验证非零版本探测会结束 session，
  不启动后续系统候选；真实 Codex E2E 保留显式门控，取消仅依据 PATH 的安装前置判断。

验收命令：`cargo test --locked -p agentdeckd --lib codex::`、
`scripts/verify-offline-tests.sh`、绑定当前 checkout daemon 的 CLI selfcheck、
desktop selfcheck 与真实 bundle verify。历史验收使用 list/read。

升级前 0.145.0 的真实 CLI 读回：legacy 样本 4 轮 / 8 条目，paginated 样本 1 轮 / 1 条目，
Claude Code 样本 9 轮 / 147 条目。分页历史的另一实测样本前两页可读，但后续页面
包含固定版本不认识的子代理 `completed` 记录，整次读取按 `codex-protocol-error`
失败；这不是完整历史读取通过。

升级前上述 focused 测试、完整离线门禁、CLI/desktop selfcheck、格式/文档检查及 bundle verify
均通过。最终 App 从没有 daemon/data-dir 覆盖的环境启动，CLI 绑定 bundle 内 daemon
读回 Codex 50 条、Claude Code 46 条。桌面正文尚无本次点击验收证据。

独立对照本机 App 自带的 `0.155.0-alpha.9.2`：相同分页请求成功读取上述新版
子代理记录，两个 paginated 会话分别返回 3 轮 / 223 条目、30 轮 / 505 条目，
均无下一页。这证明新版原生接口能读取该批样本；项目已据此同步升级版本与协议基线。
升级后的 AgentDeck CLI 绑定当前 checkout daemon，显式 `AGENTDECK_E2E=1`：

| 样本 | 读取结果 |
| --- | --- |
| legacy 会话样本 | 4 轮 / 8 条目；读回文件 `/tmp/agentdeck-codex-0155-legacy.json` |
| 近期分页会话样本 | 4 轮 / 318 条目，127 项非空文本，7 项子代理完成事件 |
| 较长分页会话样本 | 30 轮 / 505 条目，364 项非空文本，4 项子代理完成事件 |

`subAgentActivity.kind=completed` 已在共享 translator 中保留为 `activityEvent`。
Codex 列表请求也成功返回 3 条。新 bundle 内 daemon 重读长会话得到相同的
30 轮 / 505 条目；桌面 bundle 已启动，但正文点击尚无目视验收证据。

升级后 Codex focused 85 项、完整离线门禁（含 desktop tests）、CLI/desktop selfcheck、
diagnostics report、格式/文档检查及真实 bundle verify 通过。离线门禁首次暴露旧失败
fixture 的版本不匹配会触发系统候选回退，曾误启动真实 Codex 并进入 `turnStarted`，
随后由测试退出回收；失败 fixture 已改为受支持版本返回握手错误，最终 marker 门禁通过。
另一次运行的记录写失败用例遇到空 diagnosticRef，单项及后续完整门禁复跑通过，未改动
该诊断逻辑。以上均不能替代升级后完整的真实 lifecycle E2E，后者尚未重跑。

PR #19 修复后的验证：Codex focused 88 项、CLI session live fake 9 项通过；完整离线
门禁（含 desktop tests）、CLI selfcheck、diagnostics report、desktop selfcheck 和真实
bundle verify 均通过。分页 fake 的最后一页省略 `nextCursor`，仍成功返回完整历史。
当前 checkout daemon 的真实 list 返回 3 条、legacy read 返回 4 轮 / 8 条目；
重建 bundle 内 daemon 的长会话 read 返回 30 轮 / 505 条目。此次只执行真实历史
list/read，未发送模型 prompt；新版完整 lifecycle 与桌面正文点击的验收边界不变。

macOS 进程组存在性查询在组仅剩僵尸进程时可能返回 `EPERM`；将其视为仍存在，
继续在原清理预算内等待 `ESRCH`。发送 SIGKILL 的权限错误仍立即报错。CI 的探测
清理用例捕获了此问题，本地 100 次子进程对照中复现 4 次查询 `EPERM`，最终均确认
进程组消失；该修复同时用于版本探测与 live session 的进程组退出确认。
修复后的 88 项 Codex focused、完整离线门禁、CLI/desktop selfcheck、diagnostics report
与真实 bundle verify 均通过。

## 2026-09-23：桌面子进程信号与读取重试验收

- 信号继承回归测试先复现失败，再验证 child 恢复 signal mask 后通过；20 项 desktop
  单测、完整离线门禁、desktop selfcheck、绑定当前 checkout daemon 的 CLI selfcheck、
  格式与文档检查均通过。真实 bundle verify 从无 daemon/data-dir/profile 覆盖的环境
  启动 `dist/AgentDeck.app`，使用 bundle 内 daemon。
- fake daemon 实窗验证了自动重试，以及“重试连接”、来源“重试”和正文“重试读取”
  三个入口。连续双击没有重复请求，来源重试保留其他来源条目；请求日志确认同一
  operation/source 没有重叠，requestId 唯一。
- 切回真实 bundle 后，窗口显示 Codex 50 条、Claude Code 49 条；点击 Codex 会话
  成功显示用户文本、助手文本和工具内容，补齐此前缺失的桌面正文点击证据。
- 本次真实验证仅执行历史 list/read，未发送模型 prompt；升级后的完整 lifecycle E2E
  仍未验收。

## 2026-09-23：加载更多验收

- 本轮仅改桌面加载状态、来源按钮及相关文档，保留此前信号与重试修复。
  `cargo test --locked -p agentdeck-desktop` 的 22 项测试通过，覆盖恰好 50/100 条、
  不足一批、2,000 条上限、失败保留计数及按相同目标重试。desktop selfcheck、
  bundle verify、格式与文档检查通过。
- fake daemon 的真实窗口验证了 Codex 50 → 加载失败 → 重试至 100 → 125 并显示
  “已全部加载”；Claude Code 恰好 50 条时直接显示“已全部加载”。已有列表和选中正文
  始终保留，滚动可见新增的第 125 条。请求日志确认连续双击未重复发起请求，失败
  自动重试与手动重试均请求 101 条（显示 100 条），下一批才请求 151 条。
- 最终切回无 daemon/data-dir/profile 覆盖的真实 bundle，Claude Code 返回 49 条。
  本机 ChatGPT.app 自带 Codex 已变为 `0.155.0-alpha.16`，PATH 中仍为 `0.145.0`；
  两者均不匹配项目固定的 `0.155.0-alpha.9.2`，窗口显示 `codex-version-unsupported`。
  因此本轮真实 Codex 增量读取尚未验收，需另行完成版本适配；此前成功读取的回执
  不代表当前安装环境仍匹配。本轮未发送模型 prompt。

## 2026-09-23：Codex alpha.16 升级验收

- 固定版本同步到本机 `codex-cli 0.155.0-alpha.16`，用该 executable 的官方
  `app-server generate-json-schema` 在临时目录生成并核对快照。101 个稳定方法及
  五个独立 schema 不变；聚合 schema 仅新增 `AppConfig.omit_tools_from` 和
  `ToolExposureSurface`，当前历史与 lifecycle 使用的字段不变，无需调整生产翻译逻辑。
  版本断言与 fake 数据同步，AgentDeck IPC 仍为 v4。
- 88 项 Codex focused 测试、完整离线门禁（含 22 项 desktop 测试）、绑定当前 checkout
  daemon 的 CLI selfcheck、diagnostics report、desktop selfcheck、真实 bundle verify、
  格式与文档检查均通过。
- 显式 `AGENTDECK_E2E=1` 的 CLI 真实 list 在约 2.9 秒返回 101 条，选取第 61 条
  成功读回 4 轮 / 120 条目。重建后的真实窗口先显示 Codex 50 条、Claude Code 49 条，
  再通过“加载更多”按钮（键盘激活）扩展到 Codex 100 条；点击 Codex 会话正文成功
  显示，扩展列表后仍保留当前正文。
- 本轮仅真实历史 list/read，未发送模型 prompt；alpha.16 的完整 lifecycle E2E
  仍未验收。上述回执补齐上一节因版本不匹配而未完成的真实增量读取验证。

## 2026-09-23：桌面端 Codex 优先

- Goal：继续复用本机运行时，macOS 自动查找先探测桌面端的
  `/Applications/ChatGPT.app/Contents/Resources/codex`，再探测 PATH 与常见 CLI 位置。
  不存在或版本不匹配时继续查找；执行失败、非法输出、超时与清理失败仍立即报错。
  `app_server.rs` 的共享定位器同时作用于 history 与 live session。
- `AGENTDECK_CODEX_BIN` 可显式指定绝对路径，设置后不回退。CLI fake 与离线 marker
  通过它绑定测试程序，避免桌面端优先后绕过 PATH shim。三个真实测试移除仅凭 PATH
  判断 Codex 不存在的跳过条件，仍保留 `AGENTDECK_E2E=1` 门禁。
- 11 项 app-server 定向测试、完整离线门禁、CLI selfcheck、diagnostics report、
  真实 bundle verify、格式与文档检查通过。真实 list 在 PATH 首位放置执行即失败的
  marker 时仍返回 3 条且 marker 未执行，证明选择了桌面端运行时；未发送模型 prompt。
- 离线门禁前两次遇到既有 record-warning 诊断引用用例失败，单项通过；并行测试的
  临时目录名只依赖 PID 与时钟，存在同名前缀碰撞可能。共享测试 helper 增加进程内
  序号、失败断言补充目录证据后，完整门禁通过。未修改生产诊断逻辑，旧日志不足以
  确证前两次失败是否由目录碰撞引起。

## 2026-09-23：外部运行时兼容提示

- Goal：沿用桌面端优先、系统 CLI 兜底与显式路径覆盖，不自带或下载 Codex。
  继续精确匹配 alpha.16，AgentDeck IPC 仍为 v4。版本不匹配表示“尚未验证”，
  不能据此宣称协议一定不兼容；版本先后使用已有的 `semver` crate 判断。
- `capabilities.rs` 与共享定位器保留候选实际版本、规范化路径、已验证版本和中文
  指引：旧版升级 Codex，新版升级 AgentDeck 或显式选择已验证版本，构建差异使用
  匹配构建。未安装、非法输出、执行失败与超时仍分别说明，不伪装成空历史。
- 历史 RPC/解码错误保留方法、错误码与实际运行时信息；`-32601` 提示方法不支持，
  其他 RPC 错误保留配置、数据与协议几种可能性。跨来源全部失败时完整保留底层
  message，不改变部分成功时的 best-effort 行为。没有修改 IPC schema。
- 桌面错误区可滚动查看详情，按钮独立于滚动区；未知历史条目显示中立中文提示与
  类型，保留前后正常内容。生产代码不展示 vendor 原始错误正文或 raw payload。
- 90 项 Codex focused、22 项 desktop 单测、完整离线门禁、绑定当前 checkout daemon
  的 CLI selfcheck、diagnostics report、desktop selfcheck 与 bundle verify 通过。
  fake CLI 覆盖新旧版本错误的 JSON code/message 与 stderr 指引；fake 分页响应覆盖
  方法不支持、内部错误与解码失败，均拒绝残缺正文并隐藏 vendor 错误原文。
- 实窗通过 bundle 内真实 daemon 连接临时 fake Codex：未验证版本提示可滚动读全，
  改为匹配版本后点击来源重试恢复列表；未知条目中文提示与前后正常文本均已读回。
- 正文错误区完整显示 `thread/turns/list`、`-32601`、Codex 版本、运行时完整路径与
  `codex-protocol-error`，重试按钮保持可见；`PRIVATE_VENDOR_DETAIL` 未展示。
- 已终止临时 fake 实例，清除 Codex、daemon、data-dir 与 profile 覆盖后打开最终
  bundle。真实窗口显示 Codex 50 条、Claude Code 49 条；点击真实 Codex 会话成功
  展示用户、助手与工具正文。
  本轮不发送模型 prompt，alpha.16 完整 lifecycle E2E 仍未验收；也不承诺识别所有
  不触发 RPC/解码错误的语义漂移。
