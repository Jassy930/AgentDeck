# 第二期多平台 release 设计

## 背景与目标

第一期 PR #58 已为 macOS 双架构、Ubuntu x86_64 桌面和 Linux 双架构 musl daemon
建立完整归档门禁。本期在它之上增加 Linux ARM64 GNU 桌面、Windows x64 桌面和独立
daemon；第二期使用独立分支，以第一期分支为 base 提交增量 draft PR。

## 平台边界

- Linux ARM64 使用 Ubuntu 24.04 ARM runner 原生构建，Xvfb/Mesa 软件 Vulkan 烟测。
- Windows 使用 MSVC x64 原生构建，桌面与 daemon 以便携 ZIP 分发；无发行签名凭据，
  明确标记未签名。固定 GPUI 版本已有 Windows D3D11 backend，不引入第二套界面。
- Windows 适配必须包括原生 EXE 定位、用户数据路径、官方安装命令、进程树回收与
  超时语义，不能仅增加 CI matrix。原生 CLI 与 shell wrapper 的支持边界需显式说明。
- Windows ARM64、不带图形环境的桌面使用、真实模型/SSH 会话验收不在本期范围。

## 实现与发布边界

保持 desktop → typed client → daemon 的既有分层。平台路径和子进程设施使用明确
的平台分支；vendor 安装及发现仍留在各 adapter 边界。IPC schema 不因打包改变。
Windows 子进程树应有明确所有权，退出或超时必须回收后再报告成功，不能把只杀父进程
当作完整 cleanup。测试使用本地 fixture，不启动用户的 vendor 或读取其历史。

所有桌面包携带同版本、同架构 daemon，并提供字节一致的独立 daemon 归档。统一集合
增加到 12 个归档及 SHA256SUMS；保留第一期的版本、架构、完整集合和 tag 发布门禁。
PR/手动运行只生成候选 artifacts；本次不合并、不打 tag、不发布、不配置凭据或安全策略。

## 验收

分别记录静态检查、最终提交的离线单测、原生构建、解包启动烟测和人工验收。
Windows fake 子进程生命周期和路径负例必须有实际 Windows CI 证据。Linux ARM64 与
Windows 的构建、测试和烟测全部成功后，才可把对应矩阵标为已通过。软件图形烟测不能
代替真实 GPU、输入法、桌面交互或模型会话验收。
