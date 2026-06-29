import AppKit

/// Resolves the on-disk path used to preview a media item and loads it as an
/// `NSImage`. Prefers the saved path (the durable, user-visible artifact) over
/// the transient generation path. Moved out of the former SwiftUI `SessionView`
/// during the AppKit cutover; consumed by the AppKit row views/factory.
struct MediaPreviewPresentation: Equatable {
    let previewPath: String

    init(item: UIItem) {
        let saved = item.savedPath.trimmingCharacters(in: .whitespacesAndNewlines)
        let path = item.path.trimmingCharacters(in: .whitespacesAndNewlines)
        previewPath = saved.isEmpty ? path : saved
    }

    var localImage: NSImage? {
        guard !previewPath.isEmpty else { return nil }
        return NSImage(contentsOfFile: previewPath)
    }
}
