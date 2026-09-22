# GPUI 桌面接入真实会话（只读历史）实施记录

日期：2026-09-22

## Goal

把 GPUI 桌面端的示例会话换成本机 `agentdeckd` 返回的真实历史：侧栏显示真实会话
列表，点击后在主区渲染该会话的真实记录。本切片只读，不启动 session、不发 turn。

## Architecture

- `agentdeck-desktop/src/daemon.rs`：桌面自己的 typed local client。每次请求
  spawn 一个 `agentdeckd` 子进程，写一行 `ClientCommand`，关闭 stdin，读到匹配的
  admin reply 即返回并回收进程。
  - 不复用 `agentdeck-cli`：CLI 是 bin-only、依赖 clap/tokio，且架构上与 GUI 互相独立。
  - 不维护长连接：history 在 daemon 内部本来就是短生命周期调用（Codex 每次另起
    app-server，CC 每次扫描本地 JSONL），一个连接只发一条命令，因此也不需要
    requestId 关联。session streaming 需要长连接时再单独引入。
  - daemon 定位：`AGENTDECK_DAEMON_BIN`（必须是绝对可执行路径，不回退）→
    可执行文件同目录（`.app` bundle 内）→ `target/debug` / `target/release`。
- `agentdeck-desktop/src/shell.rs`：`Shell` 持有 `agents` / `sessions` / `pending` /
  `error`，`Stage::Session` 持有 `HistoryListItem` 和 `Transcript`（Loading / Ready /
  Failed）。加载顺序是先 `AgentList`，再按 agent 各发一次 `History::List`，谁先返回谁
  先进侧栏，慢的来源不挡快的。阻塞 IPC 全部走 `cx.background_executor()`。
- `agentdeck-desktop/src/transcript.rs`：把中立 `AgentItem` 映射成「标签 + 正文」
  文本块，单条正文上限 2000 字符。
- `script/build_and_run.sh`：bundle 内同时装配 `agentdeckd`，`--verify` 额外断言它存在。

## 关键决策与坑点

- **selfcheck 不连 daemon**。`Shell::new(window, connect_daemon, cx)` 由 `--selfcheck`
  传 `false`，否则隐藏窗口也会 spawn daemon，stderr 会多出 `Broken pipe`，污染
  「成功输出必须是单行 JSON」的门禁。
- **侧栏每个 agent 只取 50 条**（`SIDEBAR_LIMIT`）。Codex 的 `thread/list` 按页聚合，
  500 条实测约 27 秒、逼近 daemon 的历史超时；50 条把首屏延迟压回一页。
- **flex 滚动要 `min_h(0)`**。GPUI 用 taffy，flex item 默认按内容撑高，`overflow_y_scroll`
  单独用不会限制高度，长记录会顶穿底部 composer。transcript 和侧栏列表都加了
  `min_h(px(0.))`，会话区外层再加 `overflow_hidden` 兜底。
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

## 已知缺口与后续

- Claude Code 会话标题常常是 `<local-command-caveat>Caveat: …`。这是
  `agentdeckd/src/claude_code/history.rs` 的标题抽取问题，应在 daemon 侧修，不要在
  desktop 打补丁。
- 本机 Codex 历史为空的原因未定位（`AGENTDECKD_STATUS.md` 已记录 Codex history 的
  超时与配置风险）。
- transcript 打开后停在顶部，没有自动滚到最新；同一 `toolUseId` 的 inProgress /
  completed 两条都会渲染。
- 没有客户端侧超时，依赖 daemon 自己的历史硬超时（见 `daemon.rs` 的 `ponytail:` 注释）。
- 仍属后续独立切片：启动/继续会话、turn 与 streaming、审批、Markdown 与 diff 渲染、
  会话搜索、按项目分组（CC 的 `cwd` 是从目录名还原的，带 `-` 的路径会还原错，不能
  直接拿来分组）。
