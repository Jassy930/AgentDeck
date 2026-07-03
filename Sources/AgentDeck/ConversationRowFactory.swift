import AppKit
import AgentDeckCore

// MARK: - ConversationRowFactory (Task 7)
//
// Maps a `ConversationDisplayRow` to:
//   • a reuse identifier (one for the userPrompt role, one per assistant kind),
//   • a freshly made `NSTableCellView` for that identifier,
//   • a measured row height for a given width.
//
// Approval is NOT a DisplayRow kind — it lives on `ThreadRuntimeModel` and is
// rendered by Task 8's ConversationViewController, so it never appears here.
enum ConversationRowFactory {

    // MARK: Reuse identifiers

    /// Reuse identifier: userPrompt → a single id; assistantItem → per-kind id
    /// (`assistant.<kind>`) so the table recycles cells per kind, never mixing
    /// a shell cell into a message slot.
    static func reuseIdentifier(for row: ConversationDisplayRow) -> NSUserInterfaceItemIdentifier {
        switch row.role {
        case .userPrompt:
            return NSUserInterfaceItemIdentifier("userPrompt")
        case .assistantItem:
            return NSUserInterfaceItemIdentifier("assistant.\(row.item.kind)")
        }
    }

    // MARK: Cell construction

    /// Build a cell for the row and stamp its `identifier` so the caller can
    /// register it for reuse. The cell is unconfigured — call `configure` after
    /// dequeuing.
    @MainActor
    static func makeCell(for row: ConversationDisplayRow) -> NSTableCellView {
        let cell = makeBareCell(for: row)
        cell.identifier = reuseIdentifier(for: row)
        return cell
    }

    @MainActor
    private static func makeBareCell(for row: ConversationDisplayRow) -> NSTableCellView {
        switch row.role {
        case .userPrompt:
            return UserPromptCellView()
        case .assistantItem:
            return makeAssistantCell(kind: row.item.kind)
        }
    }

    @MainActor
    private static func makeAssistantCell(kind: String) -> ConversationRowCellView {
        switch kind {
        case "message": return MessageCellView()
        case "reasoning": return ReasoningCellView()
        case "shell": return ShellCellView()
        case "fileEdit": return FileEditCellView()
        case "webSearch": return WebSearchCellView()
        case "plan", "reviewMode": return LabelledBlockCellView()
        case "hookPrompt": return HookPromptCellView()
        case "toolCall": return ToolCallCellView()
        case "collabAgentToolCall": return CollabAgentCellView()
        case "media": return MediaCellView()
        case "contextCompaction": return ContextCompactionCellView()
        default: return RawCellView() // raw / unknown
        }
    }

    // MARK: Height

    /// Row height for the given width: vertical padding (× 2) + the sum of the
    /// kind's fixed element heights + measured text height. Collapsible bodies
    /// (shell output, fileEdit diff, reasoning) count ONLY the collapsed header
    /// — the table never reserves height for hidden disclosure content.
    @MainActor
    static func height(for row: ConversationDisplayRow, width: CGFloat) -> CGFloat {
        switch row.role {
        case .userPrompt:
            return userPromptHeight(row: row, width: width)
        case .assistantItem:
            return assistantHeight(row: row, width: width)
        }
    }

    // MARK: - Height: per role/kind

    private static let verticalGap: CGFloat = 5
    private static let tightGap: CGFloat = 4

    private static func userPromptHeight(row: ConversationDisplayRow, width: CGFloat) -> CGFloat {
        // padding(.vertical, 8) outer + bubble inner padding (10 top + 10 bottom)
        let outer: CGFloat = 8 * 2
        let bubbleInset: CGFloat = 10 * 2
        let you = ConversationRowMetrics.lineHeight(ConversationRowMetrics.captionSemiboldFont)
        let bodyWidth = UserPromptCellView.bodyWidth(forRowWidth: width)
        let body = measuredTextHeight(
            MarkdownAttributedStringBuilder.attributedString(from: row.item.text),
            width: bodyWidth
        )
        return outer + bubbleInset + you + verticalGap + body
    }

    private static func assistantHeight(row: ConversationDisplayRow, width: CGFloat) -> CGFloat {
        let item = row.item
        let contentW = max(width - ConversationRowCellView.horizontalInset * 2, 1)

        switch item.kind {
        case "message":
            // padding(.vertical, 4) + streaming RICH markdown. Measured from the
            // SAME markdown attributed string the cell renders (design §5), so
            // measurement and rendering can never diverge.
            let pad: CGFloat = 4 * 2
            let attributed = MarkdownAttributedStringBuilder.attributedString(from: item.text, style: .standard)
            return pad + max(measuredTextHeight(attributed, width: contentW),
                             ConversationRowMetrics.lineHeight(ConversationRowMetrics.calloutFont))

        case "reasoning":
            // padding(.vertical, 8) + the "Reasoning" disclosure header. The
            // streamed body is collapsed by default, so it is NOT counted here.
            let pad: CGFloat = 8 * 2
            return pad + disclosureHeaderHeight

        case "shell":
            // padding(.vertical, 10) + command + (metadata?) + (disclosure?) + (exit?)
            var h: CGFloat = 10 * 2
            h += textHeight("$ \(item.command)", font: ConversationRowMetrics.monoCalloutFont, width: contentW)
            let metadata = ToolPresentation.shellMetadata(item)
            if !metadata.isEmpty {
                h += tightGap + ConversationRowMetrics.lineHeight(ConversationRowMetrics.monoCaptionFont)
            }
            if !item.output.isEmpty {
                h += tightGap + disclosureHeaderHeight  // collapsed: header only
            }
            if let code = item.exitCode, code != 0 {
                h += tightGap + ConversationRowMetrics.lineHeight(ConversationRowMetrics.monoCaptionFont)
            }
            return h

        case "fileEdit":
            var h: CGFloat = 10 * 2
            h += textHeight(item.path, font: ConversationRowMetrics.monoCalloutMediumFont, width: contentW)
            if !item.statusName.isEmpty {
                h += tightGap + ConversationRowMetrics.lineHeight(ConversationRowMetrics.monoCaptionFont)
            }
            if !item.diff.isEmpty {
                h += tightGap + disclosureHeaderHeight  // collapsed: header only
            }
            return h

        case "webSearch":
            var h: CGFloat = 10 * 2
            h += ConversationRowMetrics.lineHeight(ConversationRowMetrics.captionSemiboldFont)  // header
            if !item.query.isEmpty {
                h += verticalGap + textHeight(item.query, font: ConversationRowMetrics.calloutFont, width: contentW)
            }
            var detailLines: [String] = []
            if !item.actionQuery.isEmpty { detailLines.append("query  \(item.actionQuery)") }
            if !item.queries.isEmpty { detailLines.append("queries  \(item.queries.joined(separator: ", "))") }
            if !item.url.isEmpty { detailLines.append("url  \(item.url)") }
            if !item.pattern.isEmpty { detailLines.append("pattern  \(item.pattern)") }
            if !detailLines.isEmpty {
                h += verticalGap + textHeight(detailLines.joined(separator: "\n"),
                                              font: ConversationRowMetrics.monoCaptionFont, width: contentW)
            }
            return h

        case "plan", "reviewMode":
            var h: CGFloat = 10 * 2
            h += ConversationRowMetrics.lineHeight(ConversationRowMetrics.captionSemiboldFont)  // header
            let body = item.kind == "plan" ? item.text : item.review
            if !body.isEmpty {
                h += verticalGap + textHeight(body, font: ConversationRowMetrics.calloutFont, width: contentW)
            }
            return h

        case "hookPrompt":
            var h: CGFloat = 10 * 2
            h += ConversationRowMetrics.lineHeight(ConversationRowMetrics.captionSemiboldFont)  // header
            for fragment in item.fragments {
                h += verticalGap
                h += textHeight(fragment.hookRunId, font: ConversationRowMetrics.monoCaptionFont, width: contentW)
                h += 2
                h += textHeight(fragment.text, font: ConversationRowMetrics.calloutFont, width: contentW)
            }
            return h

        case "toolCall":
            var h: CGFloat = 10 * 2
            h += ConversationRowMetrics.lineHeight(ConversationRowMetrics.captionSemiboldFont)  // header
            h += verticalGap + textHeight(ToolPresentation.toolName(item),
                                          font: ConversationRowMetrics.monoCalloutMediumFont, width: contentW)
            let metadata = ToolPresentation.toolMetadata(item)
            if !metadata.isEmpty {
                h += verticalGap + ConversationRowMetrics.lineHeight(ConversationRowMetrics.monoCaptionFont)
            }
            // 参数/结果默认折叠：只算 disclosure 头（展开后的载荷高度由控制器补上）。
            if !ToolPresentation.toolPayload(item).isEmpty {
                h += verticalGap + disclosureHeaderHeight
            }
            return h

        case "collabAgentToolCall":
            var h: CGFloat = 10 * 2
            h += ConversationRowMetrics.lineHeight(ConversationRowMetrics.captionSemiboldFont)  // header
            let metadata = [item.tool, item.statusName, item.model, item.reasoningEffort].filter { !$0.isEmpty }
            if !metadata.isEmpty {
                h += verticalGap + ConversationRowMetrics.lineHeight(ConversationRowMetrics.monoCaptionFont)
            }
            if !item.prompt.isEmpty {
                h += verticalGap + textHeight(item.prompt, font: ConversationRowMetrics.calloutFont, width: contentW)
            }
            if !item.receiverThreadIds.isEmpty {
                h += verticalGap + ConversationRowMetrics.lineHeight(ConversationRowMetrics.monoCaptionFont)
            }
            return h

        case "media":
            var h: CGFloat = 10 * 2
            h += ConversationRowMetrics.lineHeight(ConversationRowMetrics.captionSemiboldFont)  // header
            let preview = MediaPreviewPresentation(item: item)
            if let image = preview.localImage {
                h += verticalGap + MediaCellView.fittedImageHeight(for: image)
            }
            let metadata = [item.statusName, item.path, item.savedPath].filter { !$0.isEmpty }
            if !metadata.isEmpty {
                h += verticalGap + ConversationRowMetrics.lineHeight(ConversationRowMetrics.monoCaptionFont)
            }
            if !item.revisedPrompt.isEmpty {
                h += verticalGap + textHeight("revised prompt  \(item.revisedPrompt)",
                                              font: ConversationRowMetrics.monoCaptionFont, width: contentW)
            }
            return h

        case "contextCompaction":
            // padding(.vertical, 10) + lone header.
            return 10 * 2 + ConversationRowMetrics.lineHeight(ConversationRowMetrics.captionSemiboldFont)

        default: // raw
            let pad: CGFloat = 8 * 2
            return pad + max(textHeight(item.descriptionText, font: ConversationRowMetrics.calloutFont, width: contentW),
                             ConversationRowMetrics.lineHeight(ConversationRowMetrics.calloutFont))
        }
    }

    /// Disclosure header line height (the triangle/caption row). The caption
    /// font drives the visible height.
    private static var disclosureHeaderHeight: CGFloat {
        max(ConversationRowMetrics.lineHeight(ConversationRowMetrics.monoCaptionFont), 16)
    }

    /// Measured wrapped height for plain text in a font, or zero for empty text.
    private static func textHeight(_ text: String, font: NSFont, width: CGFloat) -> CGFloat {
        guard !text.isEmpty else { return 0 }
        let attributed = NSAttributedString(string: text, attributes: [.font: font])
        return measuredTextHeight(attributed, width: width)
    }
}
