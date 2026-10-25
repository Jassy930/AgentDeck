# Release 构建与安装

第一期为以下目标构建 release 包。表格描述流水线覆盖范围；某个版本是否已有可用下载，
以该版本的 [GitHub Release](https://github.com/Jassy930/AgentDeck/releases) 及关联 CI 结果为准。
PR 中的 Actions artifacts 是候选产物，不代表已正式发布或完成全部人工验收。

## 产物矩阵

| 平台与基线 | 桌面归档 | 独立 daemon 归档 |
| --- | --- | --- |
| macOS 15+，Apple Silicon | `AgentDeck-aarch64-apple-darwin.tar.gz` | `agentdeckd-aarch64-apple-darwin.tar.gz` |
| macOS 15+，Intel | `AgentDeck-x86_64-apple-darwin.tar.gz` | `agentdeckd-x86_64-apple-darwin.tar.gz` |
| Ubuntu 24.04，x86_64 | `AgentDeck-x86_64-unknown-linux-gnu.tar.gz` | `agentdeckd-x86_64-unknown-linux-gnu.tar.gz` |
| Linux，x86_64，musl 静态 daemon | — | `agentdeckd-x86_64-unknown-linux-musl.tar.gz` |
| Linux，ARM64，musl 静态 daemon | — | `agentdeckd-aarch64-unknown-linux-musl.tar.gz` |

完整发布包含这 8 个归档和 `SHA256SUMS`。桌面归档携带同版本、同架构的 daemon，
Linux GNU 桌面包携带 GNU daemon。Linux 远端自动安装继续选择 musl daemon；macOS
远端按 `uname -sm` 选择 Darwin 目标。Linux ARM64 桌面、Windows 桌面和 Windows daemon
留作第二期，本期没有对应产物。Ubuntu 以外发行版、其他 GPU 和 Wayland 组合须单独验收。

版本来自根 `Cargo.toml` 的 `[workspace.package].version`。归档包含 `RELEASE-VERSION`
和 `RELEASE-INFO.txt`；macOS 放在 `AgentDeck.app/Contents/Resources/`，其他归档放在其根目录。
`--version` 可读取桌面与 daemon 的实际二进制版本，不初始化 GUI 或启动模型会话。

## 下载与 SHA256 校验

从同一个版本的 Release 下载所需归档与 `SHA256SUMS`，放在同一目录。
例如，下载 Apple Silicon 桌面包后：

```bash
grep '  AgentDeck-aarch64-apple-darwin.tar.gz$' SHA256SUMS > selected.sha256
test -s selected.sha256
shasum -a 256 -c selected.sha256
```

Linux 对所需文件同样筛选，再用 `sha256sum -c selected.sha256`。若下载完整产物集，
可直接执行 `shasum -a 256 -c SHA256SUMS`（macOS）或 `sha256sum -c SHA256SUMS`（Linux）。
校验失败时不要解包运行。SHA256 用于发现下载损坏或归档与清单不符，不代替 macOS
Developer ID 签名、公证或对下载来源的信任。

## macOS 桌面

选择机器本身的架构：Apple Silicon 为 `aarch64-apple-darwin`，Intel 为
`x86_64-apple-darwin`。校验后解包：

```bash
tar -xzf AgentDeck-aarch64-apple-darwin.tar.gz
./AgentDeck.app/Contents/MacOS/AgentDeck --version
./AgentDeck.app/Contents/MacOS/agentdeckd --version
```

用 Finder 将整个 `AgentDeck.app` 放入用户选择的应用目录，再打开应用。不要只移动
`Contents/MacOS/AgentDeck`，否则会丢失配套 daemon、图标和 bundle 元数据。

当前 CI 默认使用 **ad-hoc 签名，未公证**。这不是 Developer ID 发行签名，不能承诺
Gatekeeper 会允许从互联网下载后直接打开；本地网络授权也可能随重新构建而失效。
仅在确认来源与校验结果后，由用户处理系统提供的打开确认；若系统拒绝，不应关闭
Gatekeeper、修改系统安全策略或把未公证包当作已公证包分发。

打包脚本只接受显式设置的 `AGENTDECK_MACOS_SIGN_IDENTITY` 使用已配置的 Developer ID
Application 证书签名，不自动寻找、创建或导入证书。即使使用该变量，当前脚本也不提交
公证、不装订公证票据，产物仍标记未公证。正式发行前必须另行确认凭据和分发流程，
完成公证、票据与下载后的 Gatekeeper 验收；本期不配置 secrets 或改变安全设置。

## Linux 桌面（Ubuntu 24.04 x86_64）

Linux 桌面是动态链接的 GNU 构建，需要图形桌面、Vulkan 驱动以及系统动态库。
它不是静态包，也不承诺在比 Ubuntu 24.04 更旧的系统上运行。
Ubuntu 24.04 的运行依赖安装示例（不是最小依赖清单）：

```bash
sudo apt-get update
sudo apt-get install -y \
  libfontconfig1 libfreetype6 libx11-xcb1 libxcb1 libxcb-xkb1 \
  libxkbcommon0 libxkbcommon-x11-0 libwayland-client0 libwayland-cursor0 \
  libwayland-egl1 libvulkan1 mesa-vulkan-drivers libasound2t64 libssl3t64 \
  fonts-dejavu-core
```

Ubuntu 24.04 的 ALSA/OpenSSL 运行包名带 `t64`，见官方包页
[libasound2t64](https://packages.ubuntu.com/noble/libasound2t64) 和
[libssl3t64](https://packages.ubuntu.com/noble/libssl3t64)。

Mesa 包提供软件 Vulkan；使用硬件 GPU 时还需系统对应的 Vulkan 驱动。具备图形桌面后，
校验并解包：

```bash
tar -xzf AgentDeck-x86_64-unknown-linux-gnu.tar.gz
./AgentDeck/agentdeck-desktop --version
./AgentDeck/agentdeckd --version
./AgentDeck/agentdeck-desktop
```

保持 `agentdeck-desktop` 与 `agentdeckd` 在同一目录。需要菜单入口时，可将整个
`AgentDeck/` 放在 `~/.local/opt/AgentDeck/`，将桌面二进制链接到 `~/.local/bin/agentdeck-desktop`，
并确认该目录在图形会话的 PATH 中；把包内 `agentdeck.desktop` 安装到
`~/.local/share/applications/`，把 `agentdeck.png` 安装到
`~/.local/share/icons/hicolor/256x256/apps/agentdeck.png`。升级前由用户退出旧版本，再替换整个目录，
避免桌面和 daemon 版本混用。

若启动报告缺库，可用 `ldd ./AgentDeck/agentdeck-desktop` 检查 `not found` 项，按系统包名
补齐。CI 安装的构建与图形烟测依赖见 `.github/workflows/release.yml`；无头 CI 使用
Xvfb 和 Mesa 软件 Vulkan，不能代替目标机器的 GPU、输入法或 Wayland 人工验收。
已知 Linux 平台边界和输入法回归见 [LINUX_DESKTOP.md](LINUX_DESKTOP.md)。

## 独立 agentdeckd

macOS 选择对应 Darwin 架构。Linux 仅需要 daemon 时可选择 musl 归档；GNU daemon
供与 Ubuntu 桌面包配套或单独部署在兼容系统上。以下以 Linux x86_64 musl 为例：

```bash
tar -xzf agentdeckd-x86_64-unknown-linux-musl.tar.gz
./agentdeckd --version
mkdir -p "$HOME/.local/bin"
install -m755 agentdeckd "$HOME/.local/bin/agentdeckd"
```

覆盖已有 daemon 前，应先由用户结束使用它的连接。daemon 默认走 JSONL stdin/stdout，
不监听网络端口；不要把它当作系统后台服务直接启动。本机桌面使用包内 daemon，
无需另装独立版本。远端机器需要 `bash`、免密 SSH 和所需 vendor CLI；模型登录由官方
CLI 管理，AgentDeck 不创建或保存 vendor 凭据。

桌面内的远端安装按桌面版本下载同一 tag 的归档，执行版本检查成功后再替换远端文件。
该自动安装路径使用 HTTPS，但目前不读取 `SHA256SUMS`；需要校验归档时先按本页手动下载、
验证并安装。

## 从源码打包与验证

使用 Rust 1.96.0 和提交的 `Cargo.lock`。macOS 需相应 Xcode / Command Line Tools，
Linux 构建依赖以 workflow 中 Ubuntu 24.04 的安装步骤为准。脚本用于目标平台的原生构建；
Intel Mac 包在 Intel runner 上构建和启动验证，不能用 Apple Silicon 上的交叉编译代替。

```bash
# 在 Apple Silicon Mac 上；输出默认是 dist/release/
scripts/release/package.sh aarch64-apple-darwin desktop
scripts/release/smoke.sh aarch64-apple-darwin desktop

# 在对应 Linux x86_64 构建机上
scripts/release/package.sh x86_64-unknown-linux-gnu desktop
lavapipe=(/usr/share/vulkan/icd.d/lvp_icd*.json)
test -f "${lavapipe[0]}"
xvfb-run -a env -u WAYLAND_DISPLAY VK_DRIVER_FILES="${lavapipe[0]}" \
  dbus-run-session -- scripts/release/smoke.sh x86_64-unknown-linux-gnu desktop

# daemon-only 目标
scripts/release/package.sh x86_64-unknown-linux-musl daemon
scripts/release/smoke.sh x86_64-unknown-linux-musl daemon
```

Linux 无头烟测还需 `xvfb xauth dbus-x11 mesa-vulkan-drivers`；`VK_DRIVER_FILES` 显式
选用 lavapipe，不能只用 OpenGL 的软件渲染变量代替 Vulkan 配置。

打包入口使用 `cargo build --release --locked`，独立于会停止并启动开发应用的
`script/build_and_run.sh`。烟测解包实际归档，隔离 HOME 和数据目录，验证架构、版本、
daemon 自检与诊断报告、桌面隐藏窗口 selfcheck。它不启动真实模型会话、不读取用户历史。

## CI 与发布门禁

`Release packages` 在 PR 和手动触发时只构建、测试、烟测和上传 Actions artifacts。
`build` 使用 5 个原生 target 组合，分别上传 `package-<target>`；`collect` 要求精确包含
上述 8 个归档，校验版本、target 与提交 SHA 一致并生成 `SHA256SUMS`，完整候选集上传为
`release-assets`。

`v*` tag 必须与 workspace 版本严格相等，例如版本 `0.1.2` 对应 `v0.1.2`。
tag 发布还需既有 Offline CI 通过。只有所有构建、烟测和集合校验成功，统一 `publish`
job 才有写权限：先建立 draft Release，上传完整集合，下载回验后再公开。公开的 Release
不覆写；中途失败保留 draft，避免出现半套公开资产。PR 和手动运行没有发布权限入口。

验收记录应分别列出静态检查、实际 release 构建、归档启动烟测和人工图形验收。
CI selfcheck 成功只证明对应 runner 上的初始化和本地 plumbing，不证明真实模型交互、
所有发行版/GPU 兼容性、macOS 公证或用户现有会话行为。真实 vendor E2E 仍须单独授权。
