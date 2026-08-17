# Rust 构建产物与磁盘治理

AgentDeck 的每个 Git worktree 使用独立 `target/`。这隔离了并行分支，但长时间测试会让
`target/debug/deps` 和 `target/debug/incremental` 快速增长。治理目标是在不共享可写
target-dir 的前提下，通过容量受限的 sccache 复用编译结果，并用 Cargo 官方入口清理。

## 日常检查与清理

仓库脚本默认只预览；真正删除必须显式传 `--execute`：

```bash
scripts/clean-rust-artifacts.sh
scripts/clean-rust-artifacts.sh --execute
```

脚本只处理当前 worktree 的 dev/debug 产物，保留 release。它会在发现仍使用当前
target-dir 的 Cargo/rustc 进程时 fail closed。主仓和每个 worktree 必须分别执行。

清理前后用两个口径验证：

```bash
du -sh target
df -h /System/Volumes/Data
```

Cargo `--dry-run` 报告的是逻辑文件大小；APFS 克隆、压缩或仍打开的已删除文件会让
实际可用空间增量更小，最终以 `df` 为准。

## 长期配置

开发机推荐配置 Cargo 使用 sccache，并给缓存设置硬上限。当前约定：

- `rustc-wrapper = /opt/homebrew/bin/sccache`
- `SCCACHE_DIR = ~/.cache/sccache`
- `SCCACHE_CACHE_SIZE = 20G`
- dev/test 关闭 incremental；项目代码 `debug=1`，依赖 `debug=0`

仓库 `Cargo.toml` 固化了 profile；sccache 安装与缓存目录仍是开发机配置，不是项目
运行前提。需要项目代码完整调试符号时可临时覆盖：

```bash
CARGO_PROFILE_DEV_DEBUG=2 cargo build
```

不要使用 `find target -mtime ... -delete` 删除 Cargo 图中的零散文件，也不要让多个活跃
worktree 共享同一个可写 target-dir；前者会破坏 fingerprint，后者会造成锁竞争和分支
之间的频繁失效。
