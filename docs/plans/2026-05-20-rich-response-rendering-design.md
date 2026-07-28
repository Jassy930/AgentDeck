# Rich Response Rendering 设计

> 状态说明：本文记录早期 SwiftUI/Textual 方案；2026-06-29 AppKit 重写后，
> 当前主路径已改为 `NSTextView` + `MarkdownAttributedStringBuilder`。表格基础渲染
> 于 2026-07-23 采用 `NSTextTable` 落地；本文列出的复制 Markdown/TSV、宽表横向
> 滚动和转置仍是后续增强，不属于基础渲染完成边界。

## 背景

AgentDeck 当前已经把 Codex 返回的 `message`、`reasoning`、`shell` 和
`fileEdit` 转成中立 UI item。Swift 侧为了流式性能，使用
`StreamingTextBuffer` 和 AppKit `NSTextView` 增量追加长文本。

这个实现解决了 token 流性能问题，但 `message` 仍按纯文本显示。Codex
经常返回 GitHub Flavored Markdown，尤其是代码块、diff、表格、列表和
链接。只做基础 Markdown 渲染不足以支撑 AgentDeck 的工作台定位；代码块和
表格应成为可操作的原生组件。

## 目标

- 把 agent 回复从“纯文本”升级为结构化富文本渲染。
- 保留现有中立 IPC 边界；Rust daemon 不解析 Markdown。
- 保留现有流式性能边界；Swift 侧继续按批次合并 delta。
- 优先优化代码块和表格，而不是追求一次覆盖所有 Markdown 扩展。
- 渲染行为可测试、可回退，并能在后续替换底层渲染库。

## 非目标

- 第一版不做 Mermaid、LaTeX、HTML block、图片远程加载。
- 第一版不引入 WebView 作为主渲染路径。
- 第一版不把代码块升级成完整编辑器。
- 第一版不改变 shell 输出和 file diff 的中立 IPC schema。

## 推荐方案

采用 `RichResponseRenderer` 分层方案：

```text
StreamingTextBuffer(raw markdown)
      │
      ▼
Textual StructuredText(markdown:)
      │
      ▼
Textual block renderer
      ├── paragraph / heading / list / quote
      ├── codeBlock / diffBlock styles
      └── table styles
```

第一轮采用 Textual-first 路线，并把 AgentDeck 平台下限提升到 macOS 15。
Textual 是 MarkdownUI 的后续方向，定位是 SwiftUI rich text rendering
engine，而不是单纯 Markdown view；它提供 `StructuredText(markdown:)`、
代码块、表格、文本选择、语法高亮和 block style 定制能力，和 AgentDeck 的
原生工作台定位匹配。

Textual 负责普通 Markdown、代码块和表格的基础结构化渲染；AgentDeck 在它之上
定制工作台体验：代码块复制、wrap、长代码折叠、diff 专用样式，以及表格复制
Markdown/TSV、宽表转置等操作能力。若 Textual 某个 block 的数据访问不足，
再针对该 block 增加 `AgentDeckRichBlock` 预解析层，而不是回退整条渲染路径。

## 选型结论

| 方案 | 结论 |
| --- | --- |
| SwiftUI `Text` / `AttributedString` | 只适合 inline Markdown，不适合代码块和表格主路径。 |
| MarkdownUI | 支持 GFM、代码块、表格和 block style，但已进入维护模式，仅作为历史参考。 |
| Textual | 第一版主路径；要求 macOS 15+，但带来原生选择、表格、代码块、高亮和样式扩展。 |
| `swift-markdown` AST + 自绘 | 作为特定 block 数据访问不足时的 fallback，不再作为默认主路径。 |
| WebView + Shiki | 视觉能力强，但破坏原生路线，安全、复制、选择和资源管理成本高，只作为后备。 |
| Tree-sitter 编辑器组件 | 对只读回复渲染过重；后续若要代码语义交互再评估。 |

## 代码块体验

`RichCodeBlockView` 是第一版的重点组件。

必须支持：

- 语言 badge。
- Copy 按钮，复制纯代码。
- 横向滚动，默认不强制折行。
- Wrap toggle。
- 长代码块折叠。
- 深浅色适配。

优先支持：

- `HighlightSwift` 语法高亮。
- 行号 toggle。
- diff 专用渲染：新增、删除、hunk header 使用不同弱背景。

暂不支持：

- 代码编辑。
- symbol 跳转。
- Tree-sitter 语义级高亮。

## 表格体验

`RichMarkdownTableView` 是第二个重点组件。

必须支持：

- 横向滚动。
- 表头固定样式。
- 列宽按内容测量，并设置最小 / 最大宽度。
- 数字列右对齐，文本列左对齐。
- 单元格 inline markdown 的基础渲染。
- 复制为 Markdown 和 TSV。
- 行列计数。

优先支持：

- 长单元格展开。
- 宽表转置视图。

暂不支持：

- 排序和筛选。
- 复杂 HTML table。
- 单元格跨行 / 跨列。

## 流式策略

渲染不能随每个 token 全量解析。第一版使用三层策略：

1. `SessionModel` 继续按当前 30fps 合并 agent item delta。
2. 富文本解析增加 100-200ms debounce。
3. `turnComplete` 时强制 final parse，修正未闭合 fence、半截表格等中间态。

未闭合代码块按宽容模式渲染：在流式阶段可先显示为临时代码块；完成后按最终
Markdown AST 重新渲染。

## 架构边界

- Rust daemon 只负责 agent adapter 和中立 IPC，不解析 Markdown。
- Swift model 保留原始 Markdown 文本，便于复制、重渲染和回退。
- 富文本渲染只作用于 `message`，`shell` 和 `fileEdit` 保持现有专用路径。
- `reasoning` 是否启用富文本由实现阶段评估，第一版可继续纯文本。

## 测试策略

- Textual compatibility：`StructuredText(markdown:)` 能编译并接受代码块和表格 fixture。
- Parser / style fixture：标题、列表、引用、代码块、diff、表格、未闭合 fence。
- Code block view model：语言识别、复制内容、折叠阈值、wrap 状态。
- Table view model：列宽、对齐、Markdown/TSV 复制、宽表转置。
- Swift 测试：`swift test`。
- Rust 回归：`cargo test`，确保中立 IPC 不受影响。
- 手动 UI 验证：真实 Codex 回复中包含代码块和表格的会话。

## 文档同步

实施完成后更新：

- `README.md`：说明富文本回复渲染能力。
- 本计划对应的 implementation plan：记录任务、验证命令和提交边界。
