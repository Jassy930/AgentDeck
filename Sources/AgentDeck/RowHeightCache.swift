import AppKit

/// 在受限宽度下测量 attributed string 的排版高度（高度无限）。
func measuredTextHeight(_ attributed: NSAttributedString, width: CGFloat) -> CGFloat {
    let textStorage = NSTextStorage(attributedString: attributed)
    let container = NSTextContainer(size: NSSize(width: max(width, 1), height: .greatestFiniteMagnitude))
    container.lineFragmentPadding = 0
    let layoutManager = NSLayoutManager()
    layoutManager.addTextContainer(container)
    textStorage.addLayoutManager(layoutManager)
    layoutManager.ensureLayout(for: container)
    return ceil(layoutManager.usedRect(for: container).height)
}

/// 行高缓存：键 = rowId × version × width。版本或宽度变化即未命中。
final class RowHeightCache {
    private struct Key: Hashable {
        let rowId: String
        let version: AnyHashable
        let width: CGFloat
    }
    private var store: [Key: CGFloat] = [:]

    func height<Version: Hashable>(
        rowId: String,
        version: Version,
        width: CGFloat,
        compute: () -> CGFloat
    ) -> CGFloat {
        let key = Key(rowId: rowId, version: AnyHashable(version), width: width)
        if let cached = store[key] { return cached }
        let value = compute()
        store[key] = value
        return value
    }

    func invalidate(rowId: String) {
        store = store.filter { $0.key.rowId != rowId }
    }

    func invalidateAll() {
        store.removeAll()
    }
}
