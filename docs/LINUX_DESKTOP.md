# Linux 桌面端

发布流水线为 GPUI 桌面端提供 Ubuntu 24.04 x86_64 / ARM64 的归档包和配套 GNU daemon；
安装与验收边界见 [RELEASE.md](RELEASE.md)。两个架构均使用原生 runner 构建，
其他发行版、GPU 和 Wayland 组合需要单独验收。平台适配缺口统一记录在 issue #52。

## 当前平台边界

本期增加 release 构建、打包和归档启动烟测，并修复 Linux `--selfcheck` 在事件循环开始前
调用退出导致挂起的问题；不代表 Linux 交互体验已全面验收。

- 第二期将远端机器列表改为 `~/.local/share/AgentDeck/desktop-remotes`，与 daemon 的
  默认记录和诊断目录一致。旧 macOS 风格路径中的列表不会自动迁移；需要保留旧列表时，
  应在退出应用后人工确认内容并迁移。
  `AGENTDECK_DATA_DIR` 可显式覆盖目录，dev profile 的应用目录名为 `AgentDeck-Dev`。
- 退出快捷键使用平台 secondary 修饰键（Linux 为 Ctrl+Q），输入框显示 Ctrl+Enter 换行。
  X11 / Wayland 的窗口装饰、真实 GPU 和
  桌面环境行为需要单独检查。发布 CI 的 Xvfb 隐藏窗口 selfcheck 不覆盖这些交互。
- Linux ARM64 桌面使用 Ubuntu 24.04 ARM 的 Xvfb/Mesa 软件 Vulkan 烟测；保留双架构
  独立 musl daemon。各平台是否通过，以最终提交的原生 CI 结果为准。

## 平台差异与适配状态

- **数据目录**：desktop 的 `desktop-remotes` 与 daemon 共用 `~/.local/share/AgentDeck/`（macOS 为 `~/Library/Application Support/AgentDeck/`）。`AGENTDECK_DATA_DIR` 可以覆盖；不读 `XDG_DATA_HOME`，和 daemon 保持一致。
- **快捷键**：
  - 退出：`secondary-q`，即 macOS 上 ⌘Q、Linux 上 Ctrl+Q。
  - 输入框：gpui-component 已按平台绑定，Linux 上 Ctrl+Enter 换行、Ctrl+V 粘贴。
- **菜单**：`set_menus` 在 Linux 上不生效，不另做菜单。退出可以用 Ctrl+Q 或关闭窗口；gpui 在 Linux 上关掉最后一个窗口时会自动停止事件循环。
- **`--selfcheck`**：Linux 上 gpui 的启动回调先于事件循环执行，回调里直接 `cx.quit()` 会被丢弃，所以退出改为放在前台任务里执行。在无显示的环境下用 `xvfb-run -a` 配合 lavapipe 运行。
- **窗口装饰**：
  - X11 上 gpui 请求服务端装饰，标题栏和关闭按钮由窗口管理器绘制。
  - GNOME Wayland 不支持服务端装饰，gpui 会退回客户端装饰，而桌面端目前没有绘制，所以窗口没有标题栏和控制按钮。这种情况下只能用 Super+拖动移动窗口，用 Alt+F4 或 Ctrl+Q 关闭。待定。

## 中文输入法崩溃（X11 + ibus，已修复）

**现象**：Ubuntu 上用 ibus 输入中文时，一出现预编辑文本，桌面端就退出。backtrace 停在
`zed-xim-0.4.0-zed/src/client.rs:237`，报错信息是 `Encoding Error: UnsupportedEncoding`。

**根因**：

- gpui 0.2.2 在 X11 上通过 XIM 和输入法通信，用的是 `zed-xim 0.4.0-zed`。它依赖的 `xim-ctext 0.3.0` 负责解码 COMPOUND_TEXT，但只支持「整段 UTF-8」和「以 JIS X 0208 开头」这两种情况。
- ibus-x11 用 Xlib 把预编辑和上屏文本编码成 ISO-2022 形式的 COMPOUND_TEXT，字符集由 locale 决定：
  - `zh_CN.UTF-8` 下整段编码为 GB2312（`ESC $ ( A`）。
  - `en_US.UTF-8` 下 JIS X 0208 段和 GB2312 段交替出现，例如「中文输入法」。
- 遇到上面这些编码时，`xim-ctext` 返回错误，`zed-xim` 再对结果调用 `expect`，主线程就 panic 了。

**不受影响的情况**：

- fcitx5 走 XIM 时发送 UTF-8 段（`ESC % G`），所以不会崩。
- fcitx4（搜狗输入法 Linux 版基于它）的 XIM 前端和 ibus 一样按 locale 编码，修复前同样崩溃。
- Wayland 会话下，gpui 走 text-input-v3，不经过 XIM，也不会崩。

**修复**：

- 根 `Cargo.toml` 里的 `[patch.crates-io]` 把 `xim-ctext` 指向 `third_party/xim-ctext`。
- 这个本地版本保留 0.3.0 的公开 API，把解码重写成完整的 ISO-2022 状态机：
  - 字符集：GL/GR 指派、ASCII、ISO-8859 系列、GB2312、JIS X 0208、KS C 5601，以及 UTF-8 段。
  - 遇到无法识别的内容时，用 U+FFFD 替代，保证不会返回 Err。这样 zed-xim 里那 3 处 `expect` 永远不会触发。
- 不直接换成上游 `xim-ctext 0.4.1` 的原因有两个：一是 zed-xim 要求 `^0.3`，0.4.1 没法直接 patch 进来；二是 0.4.1 遇到未知转义时仍会返回 `Err(InvalidEncoding)`，zed-xim 的 `expect` 照样会 panic。另外，0.4.1 只识别 GL 形式的 GB2312（`ESC $ ( A`），GR 形式（`ESC $ ) A`）会被当成 Latin-1 解码，产生乱码。
- 实测中 ibus 发来的都是 GL 形式。补丁里对 GR 形式的处理是防御性的，只有单测覆盖。
- 等 gpui 依赖的 zed-xim 不再对解码结果 `expect`，并且换用了能正确解中文的 xim-ctext，就可以删掉这个补丁。

单测见 `third_party/xim-ctext/src/lib.rs`，其中包含在 Ubuntu 上实际抓到的 ibus 字节：

```bash
cargo test -p xim-ctext
```

## 无头输入法回归（dt）

`scripts/linux-ime/` 下的脚本在 Linux 主机上无头运行桌面端，并模拟拼音输入。脚本不触碰真实桌面会话，隔离方式如下：

- 私有 `dbus-run-session`
- 独立的 HOME 和 XDG 目录
- 独立的 X display 或 Wayland socket

| 脚本 | 会话 | 按键注入 | 截图 |
|---|---|---|---|
| `x11.sh <ibus\|fcitx5\|fcitx4> [display]` | Xvfb + XIM | xdotool | ImageMagick `import`，每步一张 |
| `wayland.sh [名称]` | `gnome-shell --headless --no-x11` + ibus | Mutter RemoteDesktop D-Bus | Mutter ScreenCast + PipeWire，每秒一帧 |

```bash
# 在 dt 的仓库副本里
cargo build -p agentdeck-desktop
LANG=zh_CN.UTF-8 scripts/linux-ime/x11.sh ibus 90      # 输出 ALIVE 或 APP DIED at step N
LANG=zh_CN.UTF-8 scripts/linux-ime/x11.sh fcitx5 91
LANG=zh_CN.UTF-8 scripts/linux-ime/wayland.sh zh
```

fcitx4 不装在 dt 主机上（避免和主机的 fcitx5/ibus 配置互相影响），放在容器里跑（镜像 `agentdeck-ime-fcitx4`，`scripts/linux-ime/fcitx4.Dockerfile`）：

```bash
docker run --rm -v ~/agentdeck-ime:/work -v /tmp/ime-out:/out -e LANG=zh_CN.UTF-8 \
  -e OUT_DIR=/out/fcitx4 agentdeck-ime-fcitx4 /work/scripts/linux-ime/x11.sh fcitx4 95
```

坑点：

- **Vulkan**：Xvfb 不支持 DRI3，默认的硬件 Vulkan ICD 会报 `Failed to create surface: PlatformNotSupported`。脚本通过 `VK_DRIVER_FILES` 强制使用 lavapipe 软件渲染。
- **locale**：COMPOUND_TEXT 的字符集取决于 locale，必须覆盖 `zh_CN.UTF-8`（需要先 `sudo locale-gen zh_CN.UTF-8`）。只测 en_US 不能代表中文用户的实际编码路径。
- **fcitx5**：需要 `[Behavior] ActiveByDefault=True`，否则按键直接以英文上屏，等于没测输入法。
- **Wayland 截图**：GNOME 的 `org.gnome.Shell.Screenshot` 在 headless 模式下拒绝调用，所以改用 ScreenCast。
- **Wayland 按键**：RemoteDesktop 的按键必须在同一个会话里连续发送，每次新建会话发出的按键会丢失。
- **Xvfb 首帧**：Xvfb 下没有窗口管理器，窗口要收到第一个输入事件才会开始绘制。只看启动画面时，先用 `xdotool mousemove` 触发一次。
- **改脚本时**：脚本里覆盖了 HOME，引用仓库外的文件要用绝对路径。

依赖（Ubuntu 24.04）：`xvfb xdotool imagemagick mesa-vulkan-drivers ibus-libpinyin fcitx5 fcitx5-chinese-addons`；Wayland 还需要 `pipewire wireplumber gstreamer1.0-pipewire python3-gi`。

2026-10-23 在 dt 上又做了一次只读启动：真实的 `~/.codex`、`~/.claude` 以符号链接放进隔离 HOME，并指定 `AGENTDECK_DAEMON_BIN`。本地 daemon 正常读出 Codex 和 Claude Code 历史，侧栏和主页显示正常。

2026-10-23 在 dt（Ubuntu 24.04.4）上的验证结果：

- **未打补丁的 master**：zh_CN + ibus 在第 3 步（第一次出现中文预编辑）就崩溃；en_US + ibus 在第 5 步崩溃。
- **打补丁后**：zh_CN 和 en_US 下，ibus 和 fcitx5 的 X11 组合，以及 zh_CN 下 ibus 的 Wayland 组合，都跑完了全部步骤，截图里的预编辑和上屏文字正确。

2026-10-28 在 dt 上用 fcitx4 + fcitx-pinyin（容器）补测：未打补丁时 zh_CN 在第 3 步、en_US 在第 5 步崩溃（`client.rs:237`，和 ibus 完全一致）；当前 master 两个 locale 都跑完全部步骤，文字正确。
