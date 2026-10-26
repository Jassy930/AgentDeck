# 第二期多平台 release 实施

Goal：补齐 Linux ARM64 GNU 和 Windows x64 的桌面及 daemon 发布候选集。
Architecture：平台适配 → 原生构建/fixture 测试 → 实际归档 smoke → 12 归档统一校验。
Tech Stack：Rust 1.96.0、GPUI 0.2.2、Bash/PowerShell、Windows Job Objects、GitHub Actions。

## 文件与验证

| 范围 | 实施 | 验证 |
| --- | --- | --- |
| `agentdeckd/src/` | Windows 数据目录、原生 CLI 发现/安装、进程树生命周期 | 纯路径/命令单测及 Windows fixture 进程测试 |
| `agentdeck-desktop/src/`、`agentdeck-cli/src/` | EXE 查找、路径、子进程与桌面平台行为 | desktop 单测、当前 daemon CLI selfcheck、Windows 原生烟测 |
| `scripts/release/` | ARM64 GNU 打包、Windows ZIP/PE 校验与隔离烟测 | 脚本正负例、解包版本/架构/依赖检查 |
| `.github/workflows/release.yml` | 7 个原生 target、12 归档聚合 | 最终提交所有 jobs 成功，PR publish skipped |
| `README.md`、`docs/` | 安装步骤、平台限制、验证边界 | 文档结构检查与实现相符 |

第一期 PR #58 保持独立；第二期 draft PR 以 `codex/release-phase-one` 为 base，
合并或重定向仍由后续明确授权决定。所有实际验证结果、最终提交 SHA 和候选资产链接
记录在第二期 PR，本文不是验收通过证明。
