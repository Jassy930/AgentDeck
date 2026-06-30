import AppKit

// MARK: - AgentKindIcon (Task 6B)
//
// 将 `AgentKind` 映射到 AppKit 可用的图标 NSImage。
// 资源以 SVG 形式存放在 `Resources/Assets.xcassets/<Kind>Icon.imageset/`
// 内部（SPM `.process` 资源会保留目录结构），通过 `Bundle.module.url(...)`
// 直接加载 SVG 文件 —— 不依赖 actool 编译后的 catalog（在 `swift run`
// 命令行场景下未编译，无法用 `NSImage(named:)`）。
public enum AgentKindIcon {
    /// 返回对应 agentKind 的图标。资源缺失时返回 `nil`（调用方可降级为
    /// 系统占位）。
    public static func image(for kind: AgentKind) -> NSImage? {
        let resource: (subdirectory: String, filename: String)
        switch kind {
        case .codex:
            resource = ("Assets.xcassets/CodexIcon.imageset", "codex")
        case .claudeCode:
            resource = ("Assets.xcassets/ClaudeCodeIcon.imageset", "claudecode")
        }
        guard let url = Bundle.module.url(
            forResource: resource.filename,
            withExtension: "svg",
            subdirectory: resource.subdirectory
        ) else {
            return nil
        }
        return NSImage(contentsOf: url)
    }

    /// 提供 18×18 的展示图。SVG 加载后默认尺寸为 24，这里统一缩放到 18，
    /// 以适配工具栏/控制条等紧凑布局。
    public static func compactImage(for kind: AgentKind) -> NSImage? {
        guard let img = image(for: kind) else { return nil }
        img.size = NSSize(width: 18, height: 18)
        return img
    }
}
