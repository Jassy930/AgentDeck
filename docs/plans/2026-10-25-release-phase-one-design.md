# 第一期多平台 release 设计

## 背景与目标

现有 tag workflow 只发布 Linux 双架构 musl daemon，无法提供桌面与 daemon 同版本的
完整安装集；各矩阵任务直接上传 Release，还会让部分成功的资产先行公开。

本期增加 macOS 15+ Apple Silicon / Intel 桌面和 daemon、Ubuntu 24.04 x86_64 桌面和
GNU daemon，保留 Linux x86_64 / ARM64 musl daemon。Linux ARM64 桌面和 Windows 留待第二期。
产物名称、安装及签名边界的事实源为 [RELEASE.md](../RELEASE.md)。

## 架构与边界

- 所有桌面包携带同版本、同架构 daemon；保留每个平台 daemon 的独立归档。
- 使用 `scripts/release/` 独立 release 构建与烟测，不调用会停止和打开应用的开发脚本。
- 版本取 workspace 版本；tag、二进制和归档元数据必须一致。所有归档统一生成 SHA256 清单。
- PR/手动运行只上传 Actions artifacts。tag 的统一 publish 等待所有目标和离线门禁通过，
  draft 上传、回读核验成功后才公开；拒绝覆盖公开 Release。
- 默认 macOS ad-hoc 签名并明确未公证；只提供显式使用既有 Developer ID 证书的入口，
  不生成/导入凭据、不修改安全设置、不配置 secrets。
- 远端安装识别增加 macOS 架构，并校验待安装 daemon 版本；本期不重写既有 HTTPS 下载传输。

## 失败与验证

架构/版本不符、归档缺失或额外资产、构建/烟测失败均阻止发布。烟测从归档解包，
在隔离 HOME 和数据目录中运行 daemon selfcheck/diagnostics 与桌面隐藏窗口 selfcheck，
不访问真实 vendor 会话。Linux selfcheck 必须在事件循环启动后退出，避免 CI 挂起。

各平台由原生 PR runner 构建并启动；本机能执行的检查先在隔离副本执行。
结果必须区分静态检查、实际构建、启动烟测、人工 GUI 和签名/公证验收，不以
本地单平台通过代替其他平台证据，也不以离线测试代替真实模型 E2E。
