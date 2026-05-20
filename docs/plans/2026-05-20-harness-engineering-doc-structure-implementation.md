# Harness Engineering 文档结构 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 按 OpenAI harness engineering 经验，把 AgentDeck 仓库整理成短入口、结构化记录系统和可机械检查的文档治理结构。

**Architecture:** `AGENTS.md` 只保留仓库地图和高层规则；稳定架构放入 `ARCHITECTURE.md`；文档索引、质量规则和计划规则放入 `docs/`。新增一个轻量 shell 检查脚本验证关键文档入口存在且被交叉链接，先作为本地工具，后续可接 CI。

**Tech Stack:** Markdown、POSIX shell、现有 Swift/Rust 验证命令。

---

### Task 1: 建立稳定文档入口

**Files:**
- Create: `ARCHITECTURE.md`
- Create: `docs/index.md`
- Create: `docs/QUALITY.md`
- Create: `docs/plans/README.md`

**Steps:**
1. 从 `README.md`、`NORTH_STAR.md` 和既有计划文档提取稳定事实。
2. 把产品说明留在 README，把架构边界放入 `ARCHITECTURE.md`。
3. 用 `docs/index.md` 作为 `docs/` 导航入口。
4. 用 `docs/QUALITY.md` 记录验证命令和适用范围。
5. 用 `docs/plans/README.md` 记录计划文档规则。

**Verify:**
```bash
test -f ARCHITECTURE.md
test -f docs/index.md
test -f docs/QUALITY.md
test -f docs/plans/README.md
```

### Task 2: 更新仓库地图

**Files:**
- Modify: `AGENTS.md`
- Modify: `README.md`

**Steps:**
1. 在 `AGENTS.md` 的必读顺序里加入新增文档。
2. 在 `README.md` 链接 `ARCHITECTURE.md`、`docs/index.md` 和 `docs/QUALITY.md`，避免 README 膨胀成百科。

**Verify:**
```bash
rg -n "ARCHITECTURE.md|docs/index.md|docs/QUALITY.md|docs/plans/README.md" AGENTS.md README.md
```

### Task 3: 增加机械检查

**Files:**
- Create: `scripts/verify-agent-docs.sh`
- Modify: `docs/QUALITY.md`

**Steps:**
1. 编写只读 shell 脚本，检查关键文档存在、入口文档交叉链接、项目级外部 skill 绑定不存在。
2. 在 `docs/QUALITY.md` 记录脚本用途。

**Verify:**
```bash
scripts/verify-agent-docs.sh
```

### Task 4: 收口

**Files:**
- All touched docs/scripts.

**Steps:**
1. 运行文档结构检查，确认旧外部 skill 绑定没有回流。
2. 运行文档结构检查。
3. 查看 git 状态。

**Verify:**
```bash
scripts/verify-agent-docs.sh
git status --short --branch
```
