# 原生 Markdown 表格渲染实施计划

> 状态：已完成
>
> 日期：2026-07-23

## Goal

让 macOS 会话流把 agent 输出中的 GitHub Flavored Markdown 表格渲染成可选择、可复制、可自动换行的原生表格，而不是显示 `|` 与 `---` 原文；同时保持现有流式重算、统一行高测量和 TextKit 选择协调不变量。

## Architecture

保持现有 `StreamingTextBuffer → MarkdownAttributedStringBuilder → NSAttributedString → NSTextView` 管线不变，只在 Swift 渲染层增加表格 block：

1. `MarkdownAttributedStringBuilder` 识别“表头行 + 合法分隔行 + 连续数据行”。
2. 分隔行中的 `:---`、`:---:`、`---:` 分别映射为左、中、右对齐。
3. 每个单元格继续走现有 inline Markdown 解析，保留强调、行内代码和链接。
4. 单元格通过共享 `NSTextTable` 的 `NSTextTableBlock` 进入同一份 attributed string；渲染与 `measuredTextHeight` 因而继续同源。
5. 不完整、表头与分隔行列数不匹配或尚未收到合法分隔行的流式内容保持可读原文，下一次 buffer 重算时再升级成原生表格；数据行缺少单元格时按 GFM 语义补空，超出声明列数的单元格忽略。

Rust daemon、IPC、`AgentDeckCore` 和 iOS fixture 渲染均不变。

## Tech Stack

- Swift 6
- AppKit TextKit 1：`NSTextView`、`NSLayoutManager`
- `NSTextTable` / `NSTextTableBlock`
- XCTest + 现有 PNG render snapshot harness

## 实施步骤

1. 在 `MarkdownAttributedStringBuilderTests` 增加 GFM 结构、列对齐、inline Markdown、转义管道符、空单元格和流式降级测试。
2. 在 builder 中增加轻量 GFM 表格预解析与原生 table block 构造，不引入第三方 Markdown 依赖。
3. 把表格 fixture 加入 `StreamingTextCoreTests`，验证窄/宽布局下真实 TextKit 测高与共享测量一致。
4. 增加 AppKit PNG 快照，人工检查表头层级、边框、CJK 内容、数字右对齐及表格后正文。
5. 更新 `README.md`、`docs/QUALITY.md` 和历史 AppKit 设计决策说明。

## 本切片非目标

- 表格排序、筛选、转置。
- 独立“复制 Markdown / TSV”工具栏；本切片先保留 `NSTextView` 原生选择与复制。
- HTML table、跨行、跨列。
- 超宽表格的独立横向滚动容器；当前优先在会话内容宽度内自动分栏和换行。

## 验证命令

```bash
swift test --filter MarkdownAttributedStringBuilderTests
swift test --filter StreamingTextCoreTests
swift test --filter RenderSnapshotTests/testRenderMarkdownTable
swift test
scripts/verify-agent-docs.sh
git diff --check
git status --short --branch
```

## 验收标准

- 合法 GFM 表格不显示结构管道符或分隔行。
- 表头有稳定视觉层级；左、中、右对齐与 Markdown 分隔行一致。
- 单元格支持强调、行内代码、链接、转义管道符和代码内管道符。
- 窄宽度下内容自动换行且行高无裁切、覆盖或异常留白。
- 不完整表格不崩溃、不吞内容，并可在后续流式重算时升级。
- 表格前后普通 Markdown、选择协调和现有富文本测试不回归。

## 完成证据

- `swift test --filter MarkdownAttributedStringBuilderTests`：14 项通过。
- `swift test --filter RenderSnapshotTests/testRenderMarkdownTable`：通过，并人工检查 `/tmp/adk-markdown-table.png` 的表头、网格、数字右对齐及表格后正文。
- `swift test`：331 个 XCTest 与 48 个 Swift Testing 用例全部通过。
- `scripts/verify-agent-docs.sh`：通过。
- `git diff --check`：通过。
