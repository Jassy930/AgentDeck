import AppKit
import AgentDeckCore

// MARK: - AgentKindIcon (Task 6B)
//
// 将 `AgentKind` 映射到 AppKit 可用的图标 NSImage。
// 资源以 SVG 形式存放在 `Resources/Assets.xcassets/<Kind>Icon.imageset/`
// 内部（SPM `.process` 资源会保留目录结构），通过 `Bundle.module.url(...)`
// 直接加载 SVG 文件 —— 不依赖 actool 编译后的 catalog（在 `swift run`
// 命令行场景下未编译，无法用 `NSImage(named:)`）。
@MainActor
public enum AgentKindIcon {
    private static let codexImage = loadImage(
        filename: "codex",
        subdirectory: "Assets.xcassets/CodexIcon.imageset"
    )
    private static let claudeCodeImage = loadImage(
        filename: "claudecode",
        subdirectory: "Assets.xcassets/ClaudeCodeIcon.imageset"
    )
    private static let compactCodexImage = compactCopy(of: codexImage)
    private static let compactClaudeCodeImage = compactCopy(of: claudeCodeImage)

    /// 返回对应 agentKind 的图标。资源缺失时返回 `nil`（调用方可降级为
    /// 系统占位）。
    public static func image(for kind: AgentKind) -> NSImage? {
        switch kind {
        case .codex:
            return codexImage
        case .claudeCode:
            return claudeCodeImage
        }
    }

    private static func loadImage(filename: String, subdirectory: String) -> NSImage? {
        guard let url = Bundle.module.url(
            forResource: filename,
            withExtension: "svg",
            subdirectory: subdirectory
        ) else {
            return nil
        }
        let image = NSImage(contentsOf: url)
        // SVG 用 fill="currentColor"（单色），经 NSImage 加载时 currentColor 解析为黑，
        // 暗背景下不可见。标记为模板图，让它跟随显示处的 contentTintColor 着色。
        image?.isTemplate = true
        return image
    }

    /// 提供 18×18 的展示图。SVG 加载后默认尺寸为 24，这里统一缩放到 18，
    /// 以适配工具栏/控制条等紧凑布局。
    public static func compactImage(for kind: AgentKind) -> NSImage? {
        switch kind {
        case .codex:
            return compactCodexImage
        case .claudeCode:
            return compactClaudeCodeImage
        }
    }

    private static func compactCopy(of image: NSImage?) -> NSImage? {
        guard let image else { return nil }
        let compact = (image.copy() as? NSImage) ?? image
        compact.size = NSSize(width: 18, height: 18)
        compact.isTemplate = true
        return compact
    }
}
