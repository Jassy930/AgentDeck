# Rich Response Rendering Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 让 AgentDeck 用 Textual 原生渲染 Codex Markdown 回复，并重点强化代码块、diff 和表格体验。

**Architecture:** Swift 侧把 `message` 从纯文本 `StreamingTextView` 替换为 Textual-backed `RichMessageView`。Rust daemon 和中立 IPC 不变；`shell` 和 `fileEdit` 继续走现有专用路径。AgentDeck 平台下限提升到 macOS 15，以匹配 Textual 0.3.1。

**Tech Stack:** Swift 6 / SwiftUI / AppKit / Swift Testing，Textual 0.3.1。

---

### Task 0: 接入 Textual 并验证平台约束

**Files:**
- Modify: `Package.swift`
- Create: `Tests/AgentDeckTests/TextualCompatibilityTests.swift`

**Step 1: Verify repository prerequisites**

Run:

```bash
test -d ~/.claude/skills/gstack/bin && echo GSTACK_OK || echo GSTACK_MISSING
swift --version
git status --short --branch
```

Expected: `GSTACK_OK`, Swift 6+, and a clean or understood working tree.

**Step 2: Confirm Textual package requirements**

Run:

```bash
curl -L https://raw.githubusercontent.com/gonzalezreal/textual/main/Package.swift | sed -n '1,80p'
git ls-remote --tags https://github.com/gonzalezreal/textual.git | tail -20
```

Expected: Textual declares `.macOS(.v15)` and has stable tag `0.3.1`.

**Step 3: Add dependency**

Update `Package.swift`:

```swift
let package = Package(
    name: "AgentDeck",
    platforms: [.macOS(.v15)],
    dependencies: [
        .package(url: "https://github.com/gonzalezreal/textual", from: "0.3.1"),
    ],
    targets: [
        .executableTarget(
            name: "AgentDeck",
            dependencies: [
                .product(name: "Textual", package: "textual"),
            ],
            path: "Sources/AgentDeck"
        ),
        .testTarget(
            name: "AgentDeckTests",
            dependencies: [
                "AgentDeck",
                .product(name: "Textual", package: "textual"),
            ],
            path: "Tests/AgentDeckTests"
        ),
    ]
)
```

**Step 4: Add compatibility test**

Create `Tests/AgentDeckTests/TextualCompatibilityTests.swift`:

```swift
import Testing
import Textual

@Suite("Textual compatibility")
struct TextualCompatibilityTests {
    @MainActor
    @Test("StructuredText accepts markdown with code block and table")
    func structuredTextAcceptsMarkdownBlocks() {
        let markdown = """
        ## Result

        ```swift
        let value = 42
        ```

        | Name | Count |
        | --- | ---: |
        | Build | 12 |
        """

        _ = StructuredText(markdown: markdown)
    }
}
```

**Step 5: Verify**

Run:

```bash
swift package resolve
swift test --filter TextualCompatibilityTests
```

Expected: dependency resolution succeeds and the compatibility test passes.

**Step 6: Commit**

```bash
git add Package.swift Tests/AgentDeckTests/TextualCompatibilityTests.swift
git commit -m "build: verify Textual rich rendering dependency"
```

### Task 1: Add `RichMessageView` behind Textual

**Files:**
- Create: `Sources/AgentDeck/RichMessageView.swift`
- Modify: `Tests/AgentDeckTests/TextualCompatibilityTests.swift`

**Step 1: Write a state test**

Add:

```swift
@MainActor
@Suite("Rich message render state")
struct RichMessageRenderStateTests {
    @Test("stores raw markdown for reparsing")
    func storesRawMarkdown() {
        let state = RichMessageRenderState()
        state.replace("## Title")
        #expect(state.markdown == "## Title")
    }
}
```

**Step 2: Run to verify failure**

Run:

```bash
swift test --filter RichMessageRenderStateTests
```

Expected: FAIL because `RichMessageRenderState` does not exist.

**Step 3: Implement minimal state and view**

Create `Sources/AgentDeck/RichMessageView.swift`:

- `RichMessageRenderState` stores raw Markdown.
- `RichMessageView` observes `StreamingTextBuffer`.
- It debounces updates by 100-200ms during streaming.
- It renders `StructuredText(markdown: state.markdown)`.
- Apply `.textual.structuredTextStyle(.gitHub)` and `.textual.textSelection(.enabled)`.

**Step 4: Verify**

Run:

```bash
swift test --filter RichMessageRenderStateTests
swift test
```

Expected: PASS.

**Step 5: Commit**

```bash
git add Sources/AgentDeck/RichMessageView.swift Tests/AgentDeckTests/TextualCompatibilityTests.swift
git commit -m "feat: add Textual rich message view"
```

### Task 2: Wire Textual rendering into message rows

**Files:**
- Modify: `Sources/AgentDeck/SessionView.swift`
- Modify: `Tests/AgentDeckTests/IpcTests.swift` if message rendering state needs additional coverage.

**Step 1: Replace only the `message` branch**

In `SessionView.itemRow(_:)`, replace the `StreamingTextView` used for `case "message"` with:

```swift
RichMessageView(buffer: item.textBuffer)
    .frame(maxWidth: .infinity, alignment: .leading)
```

Leave `reasoning`, `shell`, and `fileEdit` unchanged.

**Step 2: Verify**

Run:

```bash
swift test
```

Expected: PASS.

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

- `message` row renders via Textual;
- shell output and file diffs still use existing monospaced paths;
- selection/copy works in normal text and code blocks;
- no overlap at the 560px minimum window width.

**Step 4: Commit**

```bash
git add Sources/AgentDeck/SessionView.swift
git commit -m "feat: render agent messages with Textual"
```

### Task 3: Customize code block rendering

**Files:**
- Create: `Sources/AgentDeck/RichCodeBlockStyle.swift`
- Modify: `Sources/AgentDeck/RichMessageView.swift`
- Modify: `Tests/AgentDeckTests/TextualCompatibilityTests.swift`

**Step 1: Add presentation tests**

Add tests for:

- language label normalization;
- long code collapse threshold;
- diff line classification for `+`, `-`, and `@@`.

**Step 2: Implement Textual code block style**

Use Textual's `StructuredText.CodeBlockStyle` customization point.

Requirements:

- language badge;
- copy button;
- wrap toggle;
- long code collapse;
- diff-specific line background for inserted/deleted/hunk lines.

If Textual's style configuration does not expose raw code text, introduce a small `AgentDeckCodeBlockIndex` preprocessing layer for code fences only, and document the fallback.

**Step 3: Verify**

Run:

```bash
swift test
```

Expected: PASS.

**Step 4: Commit**

```bash
git add Sources/AgentDeck/RichCodeBlockStyle.swift Sources/AgentDeck/RichMessageView.swift Tests/AgentDeckTests/TextualCompatibilityTests.swift
git commit -m "feat: customize Textual code blocks"
```

### Task 4: Customize table rendering

**Files:**
- Create: `Sources/AgentDeck/RichTableStyle.swift`
- Modify: `Sources/AgentDeck/RichMessageView.swift`
- Modify: `Tests/AgentDeckTests/TextualCompatibilityTests.swift`

**Step 1: Add presentation tests**

Add tests for:

- numeric column right alignment;
- Markdown copy output;
- TSV copy output;
- wide-table transpose view model.

**Step 2: Implement Textual table style**

Use Textual's `StructuredText.TableStyle` / `TableCellStyle` customization points.

Requirements:

- horizontal overflow handling;
- header styling;
- row/column count;
- copy Markdown;
- copy TSV;
- optional transpose toggle for wide tables.

If Textual's style configuration does not expose enough table cell data, add a small table-only pre-parser and keep ordinary Markdown rendering on Textual.

**Step 3: Verify**

Run:

```bash
swift test
```

Expected: PASS.

**Step 4: Commit**

```bash
git add Sources/AgentDeck/RichTableStyle.swift Sources/AgentDeck/RichMessageView.swift Tests/AgentDeckTests/TextualCompatibilityTests.swift
git commit -m "feat: customize Textual markdown tables"
```

### Task 5: Update docs and full verification

**Files:**
- Modify: `README.md`
- Modify: `docs/plans/2026-05-20-rich-response-rendering-design.md`
- Modify: `docs/plans/2026-05-20-rich-response-rendering-implementation.md`

**Step 1: Update README**

Document:

- macOS 15+ requirement;
- Textual-backed Markdown message rendering;
- code block and table enhancement scope.

**Step 2: Run full verification**

Run:

```bash
swift test
cargo test
git status --short --branch
```

Expected:

- Swift tests pass.
- Rust tests pass.
- Working tree only has intended files before final commit.

**Step 3: Commit**

```bash
git add README.md docs/plans/2026-05-20-rich-response-rendering-design.md docs/plans/2026-05-20-rich-response-rendering-implementation.md
git commit -m "docs: align rich rendering plan with Textual"
```
