---
name: agentdeck-release
description: AgentDeck 发版流程：检查 master 与 CI、升 workspace 版本、本地门禁、推送 v* tag 触发多平台 Release、监控、验收并补写变更说明。用户说「发版」「发布新版本」「打 tag」「release」「出一个 vX.Y.Z」时使用。
---

# AgentDeck 发版

打 `v*` tag 后，`.github/workflows/release.yml`（Release packages）会在原生 runner 上构建 7 个目标、生成 12 个归档和 `SHA256SUMS`，重跑 Offline CI，为归档生成 build provenance，全部通过后再发布 GitHub Release。打包细节、平台矩阵和证据边界见 `docs/RELEASE.md`，这里只写发版操作。

推送 master 和推送 tag 都是对外操作，第 5 步之前必须先让用户确认。

## 1. 前置检查

```bash
git fetch -q origin
git status -sb                      # 首行必须是 "## master...origin/master"，不能有 ahead/behind，也不能有未提交改动
gh pr list --state open             # 确认没有应该随本版一起发布、却还没合入的 PR
gh run list --branch master --workflow "Offline CI" --limit 3   # master 最近一次运行应为 success
```

- 本地 master 比远端多出提交时，先问用户这些提交是否随本版发布；需要的话 rebase 到 `origin/master` 并处理冲突，不要直接推。
- 主工作区可能有其他会话的改动，只 `git add` 本流程改动的文件，禁止 `git add -A`。

## 2. 选版本

```bash
grep -A1 '^\[workspace.package\]' Cargo.toml
git tag --sort=-v:refname | head -3
git log "$(git describe --tags --abbrev=0)"..origin/master --first-parent --oneline
```

版本号要问用户选 patch 还是 minor，不要自己决定。tag 必须和 workspace 版本完全一致：版本 `X.Y.Z` 对应 tag `vX.Y.Z`。

## 3. 升版并跑本地门禁

```bash
sed -i '' 's/^version = "<旧版本>"$/version = "X.Y.Z"/' Cargo.toml   # 只改 [workspace.package] 那一行，改完看一眼 diff
cargo update -w --offline
scripts/release/check-version.sh vX.Y.Z          # 必须打印 X.Y.Z
cargo fmt --all -- --check
scripts/verify-agent-docs.sh
env -u AGENTDECK_E2E scripts/verify-offline-tests.sh
```

tag 运行会再跑一遍这些检查，但本地几分钟就能发现的问题，没必要等 CI 跑十分钟才失败。

## 4. 提交

```bash
git add Cargo.toml Cargo.lock
git commit -m "发布版本更新至 X.Y.Z"      # 不加 co-author
```

## 5. 确认后推送并打 tag

先把版本号、即将推送的提交（`git log origin/master..HEAD --oneline`）和本版变更概要给用户看，得到明确同意后再执行：

```bash
git push origin master
git tag -a vX.Y.Z -m "AgentDeck vX.Y.Z"
git push origin vX.Y.Z
```

## 6. 监控 Release packages

```bash
gh run list --workflow "Release packages" --branch vX.Y.Z --limit 1   # 取 run id
until gh run view <run-id> --json status --jq .status 2>/dev/null | grep -q completed; do sleep 60; done
gh run view <run-id> --json conclusion,jobs --jq '{conclusion, jobs: [.jobs[] | {name, conclusion}]}'
```

不要用 `gh run watch`，它遇到网络抖动就会退出。上面的轮询放在后台运行，正常一轮大约 10 到 15 分钟。

## 7. 失败处理

用 `gh run view <run-id> --log-failed` 定位原因，先修好再重新发布：

- **publish 之前失败**（还没有 Release，或者只有草稿）：修复并推送到 master，然后把 tag 移到新提交上：
  ```bash
  git tag -d vX.Y.Z && git push origin :refs/tags/vX.Y.Z
  gh release delete vX.Y.Z --yes 2>/dev/null || true   # 删掉指向旧提交的草稿；publish 只复用指向同一提交的草稿
  git tag -a vX.Y.Z -m "AgentDeck vX.Y.Z" && git push origin vX.Y.Z
  ```
  也可以直接升一个 patch 版本重新走流程。
- **Release 已发布**（`isDraft: false`）：禁止移动或删除 tag，只能升 patch 版本重新发布。

## 8. 验收

```bash
gh release view vX.Y.Z --json isDraft,assets --jq '{isDraft, n: (.assets | length)}'   # 期望 false 和 13
dir=$(mktemp -d)
gh release download vX.Y.Z --pattern 'agentdeckd-x86_64-unknown-linux-musl.tar.gz' --dir "$dir"
gh attestation verify "$dir/agentdeckd-x86_64-unknown-linux-musl.tar.gz" --repo Jassy930/AgentDeck --format json \
  --jq '.[].verificationResult.signature.certificate | {buildSignerURI, sourceRepositoryDigest}'
```

非终端环境下，校验成功时默认格式什么都不输出，所以要用 `--format json` 看结果：`buildSignerURI` 应为 `.../release.yml@refs/tags/vX.Y.Z`，`sourceRepositoryDigest` 应为发版提交的 SHA。provenance 校验失败要当作发版问题向用户报告，不能跳过。

## 9. 补写变更说明

workflow 用固定模板生成说明，写的是平台范围和签名限制。发布后在模板前面加上本版变更：

```bash
prev=$(git tag --sort=-v:refname | sed -n 2p)
git log "$prev"..vX.Y.Z --first-parent --oneline
```

根据上面的提交整理一份中文变更摘要，按「新功能 / 修复 / 发行与构建」分组，附上 PR 和 issue 编号，不要直接贴 commit 列表，写到 `$tmp/changes.md`（`tmp=$(mktemp -d)`，别写进仓库目录）。摘要可以在等 CI 的时候提前写好。然后：

```bash
{ cat "$tmp/changes.md"; printf '\n\n'; gh release view vX.Y.Z --json body --jq .body; } > "$tmp/notes.md"
gh release edit vX.Y.Z --notes-file "$tmp/notes.md"
gh release view vX.Y.Z --json body --jq .body   # 确认模板里的平台范围和签名限制还在
```

## 10. 收尾

- `git status --short --branch` 应该是干净的，并且和 origin 同步。
- 向用户报告：版本号、Release 链接、各 job 结果、资产数量、provenance 校验结果，以及没有验证的部分。目前的已知限制：macOS 包未公证，Windows 包未做 Authenticode 签名。
