# Release 构建与安装

发布流水线为以下目标构建 release 包。表格描述构建覆盖范围；某个版本是否已有可用下载，
以该版本的 [GitHub Release](https://github.com/Jassy930/AgentDeck/releases) 及关联 CI 结果为准。
PR 中的 Actions artifacts 是候选产物，不代表已正式发布或完成全部人工验收。

## 产物矩阵

| 平台与基线 | 桌面归档 | 独立 daemon 归档 |
| --- | --- | --- |
| macOS 15+，Apple Silicon | `AgentDeck-aarch64-apple-darwin.tar.gz` | `agentdeckd-aarch64-apple-darwin.tar.gz` |
| macOS 15+，Intel | `AgentDeck-x86_64-apple-darwin.tar.gz` | `agentdeckd-x86_64-apple-darwin.tar.gz` |
| Ubuntu 24.04，x86_64 | `AgentDeck-x86_64-unknown-linux-gnu.tar.gz` | `agentdeckd-x86_64-unknown-linux-gnu.tar.gz` |
| Ubuntu 24.04，ARM64 | `AgentDeck-aarch64-unknown-linux-gnu.tar.gz` | `agentdeckd-aarch64-unknown-linux-gnu.tar.gz` |
| Windows，x64（MSVC；CI 为 Windows Server 2025） | `AgentDeck-x86_64-pc-windows-msvc.zip` | `agentdeckd-x86_64-pc-windows-msvc.zip` |
| Linux，x86_64，musl 静态 daemon | — | `agentdeckd-x86_64-unknown-linux-musl.tar.gz` |
| Linux，ARM64，musl 静态 daemon | — | `agentdeckd-aarch64-unknown-linux-musl.tar.gz` |

完整发布包含这 12 个归档和 `SHA256SUMS`。桌面归档携带同版本、同架构的 daemon，
Linux GNU 桌面包携带 GNU daemon。Linux 远端自动安装继续选择 musl daemon；macOS
远端按 `uname -sm` 选择 Darwin 目标。第二期增加 ARM64 GNU 桌面和 Windows x64 包。
Windows ARM64 不在当前矩阵中；Ubuntu 以外发行版、其他 GPU 和 Wayland 组合须单独验收。

版本来自根 `Cargo.toml` 的 `[workspace.package].version`。归档包含 `RELEASE-VERSION`
和 `RELEASE-INFO.txt`；macOS 放在 `AgentDeck.app/Contents/Resources/`，Linux/Windows
桌面放在 `AgentDeck/`，独立 daemon 放在归档根目录。
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
Developer ID 签名、公证、Windows Authenticode 签名或对下载来源的信任。

每个 tag 发布的归档都附带 GitHub 构建来源证明（build provenance），可确认归档由本仓库
对应 tag 的 Release workflow 构建：

```bash
gh attestation verify AgentDeck-aarch64-apple-darwin.tar.gz --repo Jassy930/AgentDeck
```

来源证明只说明归档出自哪次 CI 构建，不代替上述平台签名或公证。

Windows 可在 PowerShell 中核验所下载 ZIP，例如：

```powershell
$archive = 'AgentDeck-x86_64-pc-windows-msvc.zip'
$lines = @(Get-Content -LiteralPath SHA256SUMS | Where-Object { $_.EndsWith("  $archive") })
if ($lines.Count -ne 1) { throw 'SHA256SUMS 中没有唯一的目标记录' }
$match = [regex]::Match($lines[0], '^([0-9a-f]{64})  ')
if (-not $match.Success) {
    throw 'SHA256SUMS 中没有唯一、有效的目标记录'
}
$expected = $match.Groups[1].Value
if ((Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash -ine $expected) {
    throw 'SHA256 校验失败'
}
```

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

## Linux 桌面（Ubuntu 24.04 x86_64 / ARM64）

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

ARM64 使用 `AgentDeck-aarch64-unknown-linux-gnu.tar.gz`，其余目录布局和命令相同。
不要混用 x86_64 与 ARM64 的桌面或 daemon。

保持 `agentdeck-desktop` 与 `agentdeckd` 在同一目录。需要菜单入口时，可将整个
`AgentDeck/` 放在 `~/.local/opt/AgentDeck/`，将桌面二进制链接到 `~/.local/bin/agentdeck-desktop`，
并确认该目录在图形会话的 PATH 中；把包内 `agentdeck.desktop` 安装到
`~/.local/share/applications/`，把 `agentdeck.png` 安装到
`~/.local/share/icons/hicolor/256x256/apps/agentdeck.png`。可用应用内自动更新（见下文）；手动升级时
由用户退出旧版本，再替换整个目录，避免桌面和 daemon 版本混用。

若启动报告缺库，可用 `ldd ./AgentDeck/agentdeck-desktop` 检查 `not found` 项，按系统包名
补齐。CI 安装的构建与图形烟测依赖见 `.github/workflows/release.yml`；无头 CI 使用
Xvfb 和 Mesa 软件 Vulkan，不能代替目标机器的 GPU、输入法或 Wayland 人工验收。
已知 Linux 平台边界和输入法回归见 [LINUX_DESKTOP.md](LINUX_DESKTOP.md)。

## Windows 桌面（x64）

Windows 包是便携 ZIP，不包含安装器。校验后解压整个目录：

```powershell
Expand-Archive -LiteralPath AgentDeck-x86_64-pc-windows-msvc.zip -DestinationPath .\agentdeck-release
& .\agentdeck-release\AgentDeck\AgentDeck.exe --version
& .\agentdeck-release\AgentDeck\agentdeckd.exe --version
& .\agentdeck-release\AgentDeck\AgentDeck.exe
```

保持 `AgentDeck.exe` 与 `agentdeckd.exe` 在同一目录，可把整个 `AgentDeck/` 移到用户选择的
位置，并为 `AgentDeck.exe` 创建快捷方式。可用应用内自动更新（见下文）；手动升级时先退出旧版本，再替换整个目录。
桌面使用 Direct3D 11 图形后端；release 将 FXC 编译的 shader 嵌入二进制，使用静态 CRT，
打包门禁拒绝未捆绑的非系统 DLL 依赖。用户运行包不需要安装 Rust、Windows SDK 或 FXC。
GPUI 使用 Windows 自带的 `icuuc.dll`；打包时同时核对允许的系统库名称与 System32 中的
实际文件，不从开发工具目录复制 DLL。[系统 ICU 说明](https://learn.microsoft.com/en-us/windows/win32/intl/international-components-for-unicode--icu-)

当前 CI 的原生验证环境是 `windows-2025`（Windows Server 2025）。它不等于 Windows 10/11
真实桌面、硬件 GPU、输入法和交互已验收；具体构建、fixture 与启动烟测结果应查对应提交的
PR CI。包**没有 Authenticode 发行签名**，也没有 SmartScreen 验收，系统可能阻止或提示
未知来源。不要关闭 SmartScreen、修改执行策略或把未签名产物当作可信签名发行版。

Windows 上只支持原生 `codex.exe` / `claude.exe`；npm 等渠道的 `.cmd` / `.bat` wrapper
不能用作 daemon 的 vendor 可执行文件。发现顺序覆盖 PATH 和用户目录下的 `.local\bin`、
`.bun\bin`；Codex 还检查官方安装器的 `%LOCALAPPDATA%\Programs\OpenAI\Codex\bin\codex.exe`。
显式 `AGENTDECK_CODEX_BIN` 必须指向原生 EXE。机器页安装使用官方 PowerShell 脚本：
[Codex](https://chatgpt.com/codex/install.ps1)、[Claude Code](https://claude.ai/install.ps1)，
通过 `powershell.exe -NoProfile -NonInteractive` 执行；不设置 `ExecutionPolicy`，不自动登录。
Codex 安装器使用 `CODEX_NON_INTERACTIVE=1`。安装/更新仍须界面确认，真实 vendor 安装、登录和
模型会话不属于离线 CI 证据。

Windows 客户端可以调用已安装的 OpenSSH `ssh.exe` 连接 Linux/macOS；远端 bootstrap 仍要求
Unix `bash`、`uname` 和 tar，因此 Windows 主机作为 SSH 目标不在当前自动安装/启动范围。
真实 SSH 联通性仍须单独验收。

## 用户数据目录

| 平台 | 默认 stable 数据目录 |
| --- | --- |
| macOS | `~/Library/Application Support/AgentDeck/` |
| Linux | `~/.local/share/AgentDeck/` |
| Windows | `%LOCALAPPDATA%\AgentDeck\` |

远端机器列表 `desktop-remotes`、daemon 的 `runs/` 和 `diagnostic.log` 使用上述平台目录。
Windows 用户目录优先取非空 `USERPROFILE`，缺失时回退 `HOME`；`LOCALAPPDATA` 缺失时使用
该用户目录下的 `AppData\Local`。`AGENTDECK_DATA_DIR` 显式覆盖优先，`AGENTDECK_PROFILE=dev`
将默认应用目录名改为 `AgentDeck-Dev`，这些设置不改变 vendor 的登录状态或原始历史。

## 应用内自动更新

只有从 Release 归档安装的桌面端启用（安装根带 `RELEASE-VERSION`：macOS 为
`AgentDeck.app/Contents/Resources/`，Linux / Windows 为 `AgentDeck/` 目录）；本地
`build_and_run.sh` 构建和单独拷走的二进制不检查更新。

- 检测：启动时及之后每 6 小时请求一次 `releases/latest`，只读 302 跳转里的 tag，不调用
  GitHub API；失败静默。有新版本时侧栏「机器」入口上方出现「更新到 vX」。
- 安装：点击后下载本平台桌面归档和 `SHA256SUMS`，校验通过才在安装根旁的
  `.agentdeck-update-<pid>/` 里解压，再替换安装根：macOS / Linux 整目录改名交换，
  Windows 逐个文件改名（运行中的 EXE 只能改名不能覆盖）。旧文件留在该暂存目录，
  更新后自动重启的那次不清理，用户下次手动启动时才删除，在此之前可手动挪回回滚。
  安装位置不可写时提示手动下载。
- 重启：按钮变为「重启以更新」；有会话在工作或待确认时先等它们空闲，再点一次立即重启。
  新版本启动后自动打开重启前停留的会话（续聊照常使用原 thread）。重启会结束 daemon 及
  其 vendor 子进程，进行中的轮次会被打断。
- 安全边界：`SHA256SUMS` 与归档出自同一个 Release，只能发现下载损坏，不能防止 Release
  本身被篡改；需要核验来源时按上文手动下载并用 `gh attestation verify`。macOS 包为
  ad-hoc 签名，更新后本地网络等系统授权可能需要重新确认。
- 远端机器的 `agentdeckd` 不随桌面端自动更新，仍在机器页按桌面配套版本升级。
- 测试时可用 `AGENTDECK_UPDATE_URL` 把 Release 根地址（默认
  `https://github.com/Jassy930/AgentDeck/releases`）指向本地服务；被测安装根同样需要
  `RELEASE-VERSION`，本地服务要对 `HEAD /latest` 返回指向 `…/tag/v<版本>` 的 302。

## 独立 agentdeckd

macOS 选择对应 Darwin 架构。Linux 仅需要 daemon 时可选择 musl 归档；GNU daemon
供与 Ubuntu 桌面包配套或单独部署在兼容系统上。以下以 Linux x86_64 musl 为例：

```bash
tar -xzf agentdeckd-x86_64-unknown-linux-musl.tar.gz
./agentdeckd --version
mkdir -p "$HOME/.local/bin"
install -m755 agentdeckd "$HOME/.local/bin/agentdeckd"
```

Windows 选择 `agentdeckd-x86_64-pc-windows-msvc.zip`。核验 SHA256 后解压，根目录包含
`agentdeckd.exe`、版本/构建信息和 LICENSE：

```powershell
Expand-Archive -LiteralPath agentdeckd-x86_64-pc-windows-msvc.zip -DestinationPath .\agentdeckd-release
& .\agentdeckd-release\agentdeckd.exe --version
```

将该目录放到用户选定位置，供客户端以明确路径使用；若手动加入 PATH，需重新启动客户端
以读取新环境。Windows 独立 daemon 同样未签名，且不代表支持 Windows SSH bootstrap。

覆盖已有 daemon 前，应先由用户结束使用它的连接。daemon 默认走 JSONL stdin/stdout，
不监听网络端口；不要把它当作系统后台服务直接启动。本机桌面使用包内 daemon，
无需另装独立版本。当前远端机器限 Linux/macOS，需要 `bash`、免密 SSH 和所需 vendor CLI；模型登录由官方
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
Linux ARM64 在 Ubuntu 24.04 ARM 构建机上把上述 GNU target 改为
`aarch64-unknown-linux-gnu`，以相同 Xvfb/Mesa 门禁验证实际归档。

Windows 构建需原生 Windows x64、PowerShell 7、Rust 1.96.0 的
`x86_64-pc-windows-msvc` target、Visual Studio C++ x64 开发工具、Windows SDK、CMake 和 LLVM。
在已配置 `cl.exe`、`link.exe`、`rc.exe`、`dumpbin.exe` 的开发命令环境中执行：

```powershell
./scripts/release/test-windows.ps1
./scripts/release/package-windows.ps1 -OutputDir dist/release
./scripts/release/smoke-windows.ps1 -OutputDir dist/release
```

`package-windows.ps1` 查找现有 Windows SDK 的 `fxc.exe`，可用 `GPUI_FXC_PATH` 指向已安装
的编译器。构建使用 target 专用 `-C target-feature=+crt-static`，不允许全局 `RUSTFLAGS`
或 `CARGO_ENCODED_RUSTFLAGS` 覆盖。脚本不安装证书、不签名、不更改 PowerShell 执行策略。
Windows 烟测隔离 `HOME`、`USERPROFILE`、`APPDATA`、`LOCALAPPDATA`、PATH 与数据目录，
用原生 EXE tripwire 阻止真实 vendor 被调用，以 Windows Job 管理超时进程树。

打包入口使用 `cargo build --release --locked`，独立于会停止并启动开发应用的
`script/build_and_run.sh`。烟测解包实际归档，隔离 HOME 和数据目录，验证架构、版本、
daemon 自检与诊断报告、桌面隐藏窗口 selfcheck。它不启动真实模型会话、不读取用户历史。

## CI 与发布门禁

`Release packages` 在 PR 和手动触发时只构建、测试、烟测和上传 Actions artifacts。
`build` 使用 7 个原生 target 组合，分别上传 `package-<target>`；`collect` 要求精确包含
上述 12 个归档，校验版本、target 与提交 SHA 一致并生成 `SHA256SUMS`，完整候选集上传为
`release-assets`。

`v*` tag 必须与 workspace 版本严格相等，例如版本 `0.1.2` 对应 `v0.1.2`。
tag 发布还需既有 Offline CI 通过。只有所有构建、烟测和集合校验成功，统一 `publish`
job 才有写权限：先建立 draft Release，上传完整集合，下载回验后再公开。公开的 Release
不覆写；中途失败保留 draft，避免出现半套公开资产。PR 和手动运行没有发布权限入口。

发版的操作步骤（前置检查、升版、推 tag、监控、失败重打、验收与变更说明）只写在仓库自有
skill `.agents/skills/agentdeck-release/SKILL.md`，Claude Code 经 `.claude/skills/` 下的
符号链接读取同一份。

验收记录应分别列出静态检查、实际 release 构建、归档启动烟测和人工图形验收。
CI selfcheck 成功只证明对应 runner 上的初始化和本地 plumbing，不证明真实模型交互、
所有发行版/GPU 兼容性、Windows 10/11 人工 GUI、真实 SSH、macOS 公证、Windows
Authenticode/SmartScreen 或用户现有会话行为。真实 vendor E2E 仍须单独授权。
