# 第一期多平台 release 实施

## Goal / Architecture / Tech Stack

Goal：生成并验证完整的第一期桌面与独立 daemon 安装集，再由单一 job 发布。
Architecture：原生目标矩阵 → 归档烟测 → 精确资产集与 SHA256 校验 → tag 专用 publish。
Tech Stack：Rust 1.96.0、Cargo.lock、Bash、GitHub Actions、macOS codesign、Linux Xvfb/Mesa。
范围与边界见[设计](2026-10-25-release-phase-one-design.md)和[安装说明](../RELEASE.md)。

## 实施与检查入口

| 文件 | 工作 | 验证及预期 |
| --- | --- | --- |
| `scripts/release/` | release 构建、归档、版本/架构/资产集合校验与烟测 | shell 静态检查、自检拒绝错版本/缺资产；原生打包和解包 selfcheck 成功 |
| `.github/workflows/release.yml` | 5 目标矩阵、统一收集、仅 tag 发布 | PR 产生完整 `release-assets`，无 Release 写操作；全部目标失败均阻止 publish |
| `.github/workflows/offline-ci.yml` | 保留离线门禁供 tag 发布依赖 | 离线 workspace、当前 daemon/CLI selfcheck、schema 和文档检查成功 |
| `agentdeck-desktop/src/main.rs` | 无 GUI `--version` 与 Linux selfcheck 正常退出 | desktop 单测、打包后的版本读取与限时 selfcheck |
| `agentdeck-desktop/src/remotes.rs` | Darwin 架构识别与待安装版本一致性 | 映射/安装脚本单测，不访问真实 SSH 目标 |
| `README.md`、`docs/` | 安装、限制、质量入口与计划 | `scripts/verify-agent-docs.sh` 成功，与实际脚本接口相符 |

本机原生构建示例：

```bash
env -u AGENTDECK_E2E scripts/verify-offline-tests.sh
scripts/release/package.sh aarch64-apple-darwin desktop
scripts/release/smoke.sh aarch64-apple-darwin desktop
scripts/verify-agent-docs.sh
```

仅在相应平台执行对应 target；完整候选集的校验使用
`scripts/release/verify-set.sh <asset-dir>`，生成 `SHA256SUMS` 后以 `--check` 回验。
本期不创建 tag 或实际 Release、不部署、不执行真实付费模型会话、不操作用户现有会话。
实际检查状态、提交 SHA、PR CI 链接和未完成验收应随 draft PR 记录，不能把本计划当作通过证明。
