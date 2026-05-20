# Rich Response Rendering Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 让 AgentDeck 对 Codex 返回的 Markdown 回复进行结构化原生渲染，重点优化代码块、diff 和表格。

**Architecture:** Swift 侧新增 `RichResponseRenderer` 管线，把原始 Markdown 文本解析成 `AgentDeckRichBlock`，再交给 SwiftUI 原生 block views。Rust daemon 和中立 IPC 不变；`message` 使用富文本渲染，`shell` 和 `fileEdit` 继续走现有专用纯文本路径。

**Tech Stack:** Swift 6 / SwiftUI / AppKit / Swift Testing，`swift-markdown`，后续可选 `HighlightSwift`。

---

### Task 0: 记录依赖约束并建立当前测试基线

**Files:**
- Read: `Package.swift`
- Read: `docs/plans/2026-05-20-rich-response-rendering-design.md`

**Step 1: Verify gstack and current toolchain**

Run:

```bash
test -d ~/.claude/skills/gstack/bin && echo GSTACK_OK || echo GSTACK_MISSING
swift --version
```

Expected: `GSTACK_OK` and Swift 6+.

**Step 2: Verify baseline tests**

Run:

```bash
swift test
cargo test
```

Expected: both pass before any implementation change. If either fails, stop and fix or document the pre-existing failure before continuing.

**Step 3: Confirm Textual is not first-version dependency**

Check `https://raw.githubusercontent.com/gonzalezreal/textual/main/Package.swift` or the resolved package manifest if already vendored.

Expected: Textual currently declares `.macOS(.v15)`, while AgentDeck declares `.macOS(.v14)`. Do not add Textual unless the product requirement explicitly changes to macOS 15+.

**Step 4: Commit only if docs changed**

If no files changed, do not commit. If the design doc needed a correction, commit:

```bash
git add docs/plans/2026-05-20-rich-response-rendering-design.md
git commit -m "docs: clarify rich response dependency path"
```

### Task 1: Add Markdown parser dependency and AST fixture tests

**Files:**
- Modify: `Package.swift`
- Create: `Tests/AgentDeckTests/RichResponseRenderingTests.swift`

**Step 1: Add `swift-markdown` dependency**

Modify `Package.swift`:

```swift
let package = Package(
    name: "AgentDeck",
    platforms: [.macOS(.v14)],
    dependencies: [
        .package(url: "https://github.com/swiftlang/swift-markdown.git", from: "0.8.0"),
    ],
    targets: [
        .executableTarget(
            name: "AgentDeck",
            dependencies: [
                .product(name: "Markdown", package: "swift-markdown"),
            ],
            path: "Sources/AgentDeck"
        ),
        .testTarget(
            name: "AgentDeckTests",
            dependencies: ["AgentDeck"],
            path: "Tests/AgentDeckTests"
        ),
    ]
)
```

If `swift package resolve` reports a toolchain mismatch, pin the latest Swift-6-compatible tag and record that in this plan before continuing.

**Step 2: Write parser smoke tests**

Create `Tests/AgentDeckTests/RichResponseRenderingTests.swift`:

```swift
import Markdown
import Testing
@testable import AgentDeck

@Suite("Rich response markdown parser")
struct RichResponseMarkdownParserTests {
    @Test("swift-markdown recognizes fenced code blocks")
    func recognizesFencedCodeBlocks() {
        let source = """
        Before

        ```swift
        let value = 42
        ```
        """
        let document = Document(parsing: source)
        #expect(document.debugDescription().contains("CodeBlock"))
    }

    @Test("swift-markdown recognizes GFM tables")
    func recognizesTables() {
        let source = """
        | Name | Count |
        | --- | ---: |
        | Build | 12 |
        """
        let document = Document(parsing: source)
        #expect(document.debugDescription().lowercased().contains("table"))
    }
}
```

**Step 3: Resolve and run the new tests**

Run:

```bash
swift package resolve
swift test --filter RichResponseMarkdownParserTests
```

Expected: PASS. If the table fixture does not parse as a table, stop and decide whether to add a small GFM table parser for tables only.

**Step 4: Run full Swift tests**

Run:

```bash
swift test
```

Expected: PASS.

**Step 5: Commit**

```bash
git add Package.swift Package.resolved Tests/AgentDeckTests/RichResponseRenderingTests.swift
git commit -m "build: add rich response markdown parser"
```

### Task 2: Define `AgentDeckRichBlock` models

**Files:**
- Create: `Sources/AgentDeck/RichResponseBlocks.swift`
- Modify: `Tests/AgentDeckTests/RichResponseRenderingTests.swift`

**Step 1: Write failing model tests**

Append:

```swift
@Suite("Rich response block model")
struct RichResponseBlockModelTests {
    @Test("code blocks preserve language and raw code")
    func codeBlockPreservesLanguageAndCode() {
        let block = AgentDeckRichBlock.code(
            RichCodeBlock(language: "swift", code: "let value = 42\n")
        )
        #expect(block.copyPlainText == "let value = 42\n")
    }

    @Test("tables can copy markdown and tsv")
    func tableCopyFormats() {
        let table = RichMarkdownTable(
            headers: ["Name", "Count"],
            alignments: [.leading, .trailing],
            rows: [["Build", "12"]]
        )
        #expect(table.markdownString.contains("| Name | Count |"))
        #expect(table.tsvString == "Name\tCount\nBuild\t12")
    }
}
```

**Step 2: Run test to verify it fails**

Run:

```bash
swift test --filter RichResponseBlockModelTests
```

Expected: FAIL because the model types are missing.

**Step 3: Add the minimal models**

Create `Sources/AgentDeck/RichResponseBlocks.swift`:

```swift
import Foundation

enum AgentDeckRichBlock: Equatable, Identifiable {
    case markdown(id: UUID = UUID(), text: String)
    case code(RichCodeBlock)
    case table(RichMarkdownTable)

    var id: UUID {
        switch self {
        case .markdown(let id, _): return id
        case .code(let block): return block.id
        case .table(let table): return table.id
        }
    }

    var copyPlainText: String {
        switch self {
        case .markdown(_, let text): return text
        case .code(let block): return block.code
        case .table(let table): return table.markdownString
        }
    }
}

struct RichCodeBlock: Equatable, Identifiable {
    let id = UUID()
    var language: String?
    var code: String

    static func == (lhs: RichCodeBlock, rhs: RichCodeBlock) -> Bool {
        lhs.language == rhs.language && lhs.code == rhs.code
    }

    var isDiff: Bool {
        language?.lowercased() == "diff" || code.contains("\n@@ ")
    }
}

enum RichTableAlignment: Equatable {
    case leading
    case center
    case trailing
}

struct RichMarkdownTable: Equatable, Identifiable {
    let id = UUID()
    var headers: [String]
    var alignments: [RichTableAlignment]
    var rows: [[String]]

    static func == (lhs: RichMarkdownTable, rhs: RichMarkdownTable) -> Bool {
        lhs.headers == rhs.headers
            && lhs.alignments == rhs.alignments
            && lhs.rows == rhs.rows
    }

    var markdownString: String {
        let header = "| " + headers.joined(separator: " | ") + " |"
        let separator = "| " + alignments.map { alignment in
            switch alignment {
            case .leading: return "---"
            case .center: return ":---:"
            case .trailing: return "---:"
            }
        }.joined(separator: " | ") + " |"
        let body = rows.map { "| " + $0.joined(separator: " | ") + " |" }
        return ([header, separator] + body).joined(separator: "\n")
    }

    var tsvString: String {
        ([headers.joined(separator: "\t")] + rows.map { $0.joined(separator: "\t") })
            .joined(separator: "\n")
    }
}
```

**Step 4: Verify**

Run:

```bash
swift test --filter RichResponseBlockModelTests
swift test
```

Expected: PASS.

**Step 5: Commit**

```bash
git add Sources/AgentDeck/RichResponseBlocks.swift Tests/AgentDeckTests/RichResponseRenderingTests.swift
git commit -m "feat: add rich response block models"
```

### Task 3: Implement Markdown-to-block parsing

**Files:**
- Create: `Sources/AgentDeck/RichResponseParser.swift`
- Modify: `Tests/AgentDeckTests/RichResponseRenderingTests.swift`

**Step 1: Write failing parser tests**

Append:

```swift
@Suite("Rich response block parser")
struct RichResponseBlockParserTests {
    @Test("splits prose and code blocks")
    func splitsProseAndCodeBlocks() {
        let blocks = RichResponseParser.parse("""
        Here is code:

        ```swift
        let value = 42
        ```

        Done.
        """)

        #expect(blocks.count == 3)
        #expect(blocks[1] == .code(RichCodeBlock(language: "swift", code: "let value = 42\n")))
    }

    @Test("parses markdown table into structured table block")
    func parsesTable() {
        let blocks = RichResponseParser.parse("""
        | Name | Count |
        | --- | ---: |
        | Build | 12 |
        """)

        guard case .table(let table) = blocks.first else {
            Issue.record("expected table block")
            return
        }
        #expect(table.headers == ["Name", "Count"])
        #expect(table.alignments == [.leading, .trailing])
        #expect(table.rows == [["Build", "12"]])
    }

    @Test("streams incomplete code fence as a code block")
    func incompleteFenceIsTolerated() {
        let blocks = RichResponseParser.parse("""
        ```bash
        echo hi
        """)

        guard case .code(let block) = blocks.first else {
            Issue.record("expected code block")
            return
        }
        #expect(block.language == "bash")
        #expect(block.code == "echo hi\n")
    }
}
```

**Step 2: Run test to verify it fails**

Run:

```bash
swift test --filter RichResponseBlockParserTests
```

Expected: FAIL because `RichResponseParser` is missing.

**Step 3: Implement parser**

Create `Sources/AgentDeck/RichResponseParser.swift`.

Implementation rules:

- Use `swift-markdown` for completed Markdown validation and future AST traversal.
- For first version, split high-value streaming blocks with a small line-based state machine:
  - fenced code block start: `^```([A-Za-z0-9_+.#-]+)?\\s*$`
  - fenced code block end: `^```\\s*$`
  - GFM table: header line + separator line + body lines.
- Preserve all non-code/table text as `.markdown(text:)` blocks, so normal Markdown rendering can evolve independently.
- Treat unterminated code fences as valid temporary code blocks during streaming.

**Step 4: Verify parser tests**

Run:

```bash
swift test --filter RichResponseBlockParserTests
swift test
```

Expected: PASS.

**Step 5: Commit**

```bash
git add Sources/AgentDeck/RichResponseParser.swift Tests/AgentDeckTests/RichResponseRenderingTests.swift
git commit -m "feat: parse rich response blocks"
```

### Task 4: Add code block rendering

**Files:**
- Create: `Sources/AgentDeck/RichCodeBlockView.swift`
- Modify: `Tests/AgentDeckTests/RichResponseRenderingTests.swift`

**Step 1: Write view-model tests**

Append:

```swift
@Suite("Rich code block presentation")
struct RichCodeBlockPresentationTests {
    @Test("long code blocks collapse by default")
    func longCodeBlocksCollapse() {
        let code = (1...90).map { "line \\($0)" }.joined(separator: "\n")
        let state = RichCodeBlockPresentation(block: RichCodeBlock(language: "text", code: code))
        #expect(state.isLong)
        #expect(state.visibleLineCount(expanded: false) == 40)
    }

    @Test("diff blocks classify line styles")
    func diffLineStyles() {
        #expect(RichCodeLineStyle.classify("+added") == .inserted)
        #expect(RichCodeLineStyle.classify("-removed") == .deleted)
        #expect(RichCodeLineStyle.classify("@@ hunk") == .hunk)
        #expect(RichCodeLineStyle.classify("context") == .context)
    }
}
```

**Step 2: Run test to verify it fails**

Run:

```bash
swift test --filter RichCodeBlockPresentationTests
```

Expected: FAIL because presentation types are missing.

**Step 3: Implement `RichCodeBlockView` and helpers**

Create `Sources/AgentDeck/RichCodeBlockView.swift` with:

- `RichCodeBlockPresentation`
- `RichCodeLineStyle`
- `RichCodeBlockView`

UI requirements:

- Header row: language badge on the left, copy and wrap controls on the right.
- Body: `ScrollView(.horizontal)` when wrap is off.
- Font: `NSFont.monospacedSystemFont`.
- Diff mode: weak background color per inserted/deleted/hunk/context line.
- Long code: default collapsed at 40 lines, button to expand.

Use `NSPasteboard.general` for copy.

**Step 4: Verify**

Run:

```bash
swift test --filter RichCodeBlockPresentationTests
swift test
```

Expected: PASS.

**Step 5: Commit**

```bash
git add Sources/AgentDeck/RichCodeBlockView.swift Tests/AgentDeckTests/RichResponseRenderingTests.swift
git commit -m "feat: render rich code blocks"
```

### Task 5: Add table rendering

**Files:**
- Create: `Sources/AgentDeck/RichMarkdownTableView.swift`
- Modify: `Tests/AgentDeckTests/RichResponseRenderingTests.swift`

**Step 1: Write table presentation tests**

Append:

```swift
@Suite("Rich markdown table presentation")
struct RichMarkdownTablePresentationTests {
    @Test("numeric columns are right aligned when detected")
    func detectsNumericColumns() {
        let table = RichMarkdownTable(
            headers: ["Name", "Count"],
            alignments: [.leading, .leading],
            rows: [["Build", "12"], ["Test", "9"]]
        )
        let presentation = RichMarkdownTablePresentation(table: table)
        #expect(presentation.effectiveAlignment(forColumn: 1) == .trailing)
    }

    @Test("wide tables can transpose")
    func transposesWideTable() {
        let table = RichMarkdownTable(
            headers: ["A", "B", "C"],
            alignments: [.leading, .leading, .leading],
            rows: [["1", "2", "3"]]
        )
        let transposed = RichMarkdownTablePresentation(table: table).transposed()
        #expect(transposed.headers == ["Field", "Row 1"])
        #expect(transposed.rows[0] == ["A", "1"])
    }
}
```

**Step 2: Run test to verify it fails**

Run:

```bash
swift test --filter RichMarkdownTablePresentationTests
```

Expected: FAIL because presentation types are missing.

**Step 3: Implement table view**

Create `Sources/AgentDeck/RichMarkdownTableView.swift` with:

- `RichMarkdownTablePresentation`
- `RichMarkdownTableView`

UI requirements:

- `ScrollView(.horizontal)` around a grid-like layout.
- Header row with weak system fill.
- Cell padding and 1px separators.
- Alignment from Markdown separator row, with numeric heuristic fallback.
- Toolbar with row/column count, copy Markdown, copy TSV, transpose toggle.
- Long cell text capped to two lines by default, expandable by click.

**Step 4: Verify**

Run:

```bash
swift test --filter RichMarkdownTablePresentationTests
swift test
```

Expected: PASS.

**Step 5: Commit**

```bash
git add Sources/AgentDeck/RichMarkdownTableView.swift Tests/AgentDeckTests/RichResponseRenderingTests.swift
git commit -m "feat: render rich markdown tables"
```

### Task 6: Wire rich rendering into message rows

**Files:**
- Create: `Sources/AgentDeck/RichMessageView.swift`
- Modify: `Sources/AgentDeck/SessionView.swift`
- Modify: `Tests/AgentDeckTests/RichResponseRenderingTests.swift`

**Step 1: Write integration tests for parser update behavior**

Append:

```swift
@MainActor
@Suite("Rich message rendering state")
struct RichMessageRenderingStateTests {
    @Test("message state reparses after text replacement")
    func reparsesAfterReplacement() {
        let state = RichMessageRenderState()
        state.replace("plain")
        #expect(state.blocks.count == 1)
        state.replace("```swift\nlet x = 1\n```")
        #expect(state.blocks.count == 1)
        guard case .code = state.blocks[0] else {
            Issue.record("expected code block")
            return
        }
    }
}
```

**Step 2: Run test to verify it fails**

Run:

```bash
swift test --filter RichMessageRenderingStateTests
```

Expected: FAIL because state type is missing.

**Step 3: Implement `RichMessageView`**

Create `Sources/AgentDeck/RichMessageView.swift`:

- Observes a `StreamingTextBuffer`.
- Debounces parse by 100-200ms during streaming.
- Exposes `forceRefresh()` for final parse if needed later.
- Renders:
  - `.markdown` via basic Markdown text view.
  - `.code` via `RichCodeBlockView`.
  - `.table` via `RichMarkdownTableView`.

Modify `Sources/AgentDeck/SessionView.swift`:

```swift
RichMessageView(buffer: item.textBuffer)
    .frame(maxWidth: .infinity, alignment: .leading)
```

Only replace the `"message"` branch. Leave `reasoning`, `shell`, and `fileEdit` unchanged.

**Step 4: Verify**

Run:

```bash
swift test --filter RichMessageRenderingStateTests
swift test
```

Expected: PASS.

**Step 5: Commit**

```bash
git add Sources/AgentDeck/RichMessageView.swift Sources/AgentDeck/SessionView.swift Tests/AgentDeckTests/RichResponseRenderingTests.swift
git commit -m "feat: render markdown agent messages"
```

### Task 7: Add syntax highlighting as an isolated enhancement

**Files:**
- Modify: `Package.swift`
- Modify: `Sources/AgentDeck/RichCodeBlockView.swift`
- Modify: `Tests/AgentDeckTests/RichResponseRenderingTests.swift`

**Step 1: Add dependency**

Modify `Package.swift`:

```swift
.package(url: "https://github.com/appstefan/HighlightSwift.git", from: "1.0.9")
```

Add target dependency:

```swift
.product(name: "HighlightSwift", package: "HighlightSwift")
```

If a newer stable semver tag is verified compatible, update this plan and use that tag.

**Step 2: Add tests for highlighter fallback**

Test that unknown languages still render plain monospaced code and do not throw into UI state.

**Step 3: Implement highlighter adapter**

Keep highlighting behind a small protocol:

```swift
protocol CodeSyntaxHighlighting {
    func attributedCode(_ code: String, language: String?) async throws -> AttributedString
}
```

`RichCodeBlockView` must render immediately with plain code, then replace with highlighted attributed text when the async result arrives.

**Step 4: Verify**

Run:

```bash
swift package resolve
swift test
```

Expected: PASS.

**Step 5: Commit**

```bash
git add Package.swift Package.resolved Sources/AgentDeck/RichCodeBlockView.swift Tests/AgentDeckTests/RichResponseRenderingTests.swift
git commit -m "feat: highlight rich code blocks"
```

### Task 8: Update documentation and run full verification

**Files:**
- Modify: `README.md`
- Modify: `docs/plans/2026-05-20-rich-response-rendering-implementation.md` if actual dependency versions differ.

**Step 1: Update README**

Add a short paragraph under architecture or v0.1 scope:

```markdown
Agent messages render Markdown as structured native blocks. Code fences get
copyable code views, diff-aware styling and optional wrapping; Markdown tables
render as horizontally scrollable data grids with Markdown/TSV copy actions.
```

**Step 2: Run full verification**

Run:

```bash
swift test
cargo test
git status --short
```

Expected:

- Swift tests pass.
- Rust tests pass.
- Working tree only contains intended docs changes before commit.

**Step 3: Manual UI smoke test**

Run:

```bash
swift run AgentDeck
```

Send a prompt that produces:

- a fenced Swift code block;
- a fenced diff block;
- a Markdown table with numeric columns.

Expected:

- message row renders code/table blocks;
- shell output and file diffs still render through their previous paths;
- no visible overlap in a 560px wide window.

**Step 4: Commit**

```bash
git add README.md docs/plans/2026-05-20-rich-response-rendering-implementation.md
git commit -m "docs: document rich response rendering"
```

### Task 9: Final status

**Files:**
- Read: `git status --short --branch`
- Read: `git log --oneline -8`

**Step 1: Inspect status**

Run:

```bash
git status --short --branch
git log --oneline -8
```

Expected: clean working tree, branch ahead by the new commits.

**Step 2: Report**

Summarize:

- commits created;
- verification commands and results;
- any skipped manual UI checks;
- dependency versions actually resolved.
