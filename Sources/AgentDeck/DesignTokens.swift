// 生成物 · 由设计系统 SSOT 生成（designs/agentdeck-design-system/tokens/tokens.json，codex 主题）。
// 禁止手改；改 SSOT 后在 designs/agentdeck-design-system 跑 `node tools/build.mjs` 重生成。
import AppKit

enum DesignTokens {
    // 颜色（sRGB，来自设计系统语义 token）
    static let bg = NSColor(srgbRed: 0.0745, green: 0.0745, blue: 0.0745, alpha: 1)
    static let bgElevated = NSColor(srgbRed: 0.0863, green: 0.0863, blue: 0.0863, alpha: 1)
    static let surface = NSColor(srgbRed: 0.1098, green: 0.1098, blue: 0.1098, alpha: 1)
    static let surface2 = NSColor(srgbRed: 0.149, green: 0.149, blue: 0.149, alpha: 1)
    static let surfaceInset = NSColor(srgbRed: 0.0588, green: 0.0588, blue: 0.0588, alpha: 1)
    static let sidebarBg = NSColor(srgbRed: 0.1255, green: 0.1294, blue: 0.1294, alpha: 1)
    static let border = NSColor(srgbRed: 0.1843, green: 0.1843, blue: 0.1843, alpha: 1)
    static let borderStrong = NSColor(srgbRed: 0.2706, green: 0.2706, blue: 0.2706, alpha: 1)
    static let separator = NSColor(srgbRed: 0.1294, green: 0.1294, blue: 0.1294, alpha: 1)
    static let text = NSColor(srgbRed: 1, green: 1, blue: 1, alpha: 0.93)
    static let text2 = NSColor(srgbRed: 1, green: 1, blue: 1, alpha: 0.6)
    static let text3 = NSColor(srgbRed: 1, green: 1, blue: 1, alpha: 0.4)
    static let textOnAccent = NSColor(srgbRed: 0.1098, green: 0.0588, blue: 0.0157, alpha: 1)
    static let accent = NSColor(srgbRed: 1, green: 0.4902, blue: 0.1804, alpha: 1)
    static let accentWeak = NSColor(srgbRed: 1, green: 0.4902, blue: 0.1804, alpha: 0.14)
    static let warn = NSColor(srgbRed: 1, green: 0.4902, blue: 0.1804, alpha: 1)
    static let warnWeak = NSColor(srgbRed: 1, green: 0.4902, blue: 0.1804, alpha: 0.14)
    static let danger = NSColor(srgbRed: 1, green: 0.3608, blue: 0.3608, alpha: 1)
    static let dangerWeak = NSColor(srgbRed: 1, green: 0.3608, blue: 0.3608, alpha: 0.13)
    static let success = NSColor(srgbRed: 0.3412, green: 0.8118, blue: 0.4863, alpha: 1)
    static let successWeak = NSColor(srgbRed: 0.3412, green: 0.8118, blue: 0.4863, alpha: 0.13)
    static let info = NSColor(srgbRed: 0.2902, green: 0.6078, blue: 1, alpha: 1)
    static let infoWeak = NSColor(srgbRed: 0.2902, green: 0.6078, blue: 1, alpha: 0.14)
    static let running = NSColor(srgbRed: 0.2902, green: 0.6078, blue: 1, alpha: 1)

    // 圆角
    static let radiusLg: CGFloat = 18
    static let radiusMd: CGFloat = 10
    static let radiusSm: CGFloat = 6

    // 间距（4pt 基准）
    static let sp1: CGFloat = 4
    static let sp2: CGFloat = 8
    static let sp3: CGFloat = 12
    static let sp4: CGFloat = 16
    static let sp5: CGFloat = 20
    static let sp6: CGFloat = 24
    static let sp8: CGFloat = 32
    static let sp10: CGFloat = 40
    static let sp12: CGFloat = 48

    // 排版（字号与行高倍率）
    static let typeDisplayXl: CGFloat = 34
    static let typeDisplay: CGFloat = 24
    static let typeTitle: CGFloat = 16
    static let typeBody: CGFloat = 14
    static let typeCallout: CGFloat = 13
    static let typeCaption: CGFloat = 11
    static let typeMono: CGFloat = 12.5
    static let lineHeightCJK: CGFloat = 1.72
    static let lineHeightLatin: CGFloat = 1.45

    // 阴影（分层柔光，供 roundedPanel 使用）
    static let panelShadowColor = NSColor(srgbRed: 0, green: 0, blue: 0, alpha: 0.42)
    static let panelShadowBlur: CGFloat = 26
    static let panelShadowOffset = CGSize(width: 0, height: -8)
}
