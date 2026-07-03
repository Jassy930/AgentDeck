// 生成物 · 由设计系统 SSOT 生成（designs/agentdeck-design-system/tokens/tokens.json，codex 主题）。
// 禁止手改；改 SSOT 后在 designs/agentdeck-design-system 跑 `node tools/build.mjs` 重生成。
import UIKit

enum DesignTokens {
    // 颜色（sRGB，来自设计系统语义 token）
    static let bg = UIColor(red: 0.0745, green: 0.0745, blue: 0.0745, alpha: 1)
    static let bgElevated = UIColor(red: 0.0863, green: 0.0863, blue: 0.0863, alpha: 1)
    static let surface = UIColor(red: 0.1098, green: 0.1098, blue: 0.1098, alpha: 1)
    static let surface2 = UIColor(red: 0.149, green: 0.149, blue: 0.149, alpha: 1)
    static let surfaceInset = UIColor(red: 0.0588, green: 0.0588, blue: 0.0588, alpha: 1)
    static let sidebarBg = UIColor(red: 0.1255, green: 0.1294, blue: 0.1294, alpha: 1)
    static let border = UIColor(red: 0.1843, green: 0.1843, blue: 0.1843, alpha: 1)
    static let borderStrong = UIColor(red: 0.2706, green: 0.2706, blue: 0.2706, alpha: 1)
    static let separator = UIColor(red: 0.1294, green: 0.1294, blue: 0.1294, alpha: 1)
    static let text = UIColor(red: 1, green: 1, blue: 1, alpha: 0.93)
    static let text2 = UIColor(red: 1, green: 1, blue: 1, alpha: 0.6)
    static let text3 = UIColor(red: 1, green: 1, blue: 1, alpha: 0.4)
    static let textOnAccent = UIColor(red: 0.1098, green: 0.0588, blue: 0.0157, alpha: 1)
    static let accent = UIColor(red: 1, green: 0.4902, blue: 0.1804, alpha: 1)
    static let accentWeak = UIColor(red: 1, green: 0.4902, blue: 0.1804, alpha: 0.14)
    static let warn = UIColor(red: 1, green: 0.4902, blue: 0.1804, alpha: 1)
    static let warnWeak = UIColor(red: 1, green: 0.4902, blue: 0.1804, alpha: 0.14)
    static let danger = UIColor(red: 1, green: 0.3608, blue: 0.3608, alpha: 1)
    static let dangerWeak = UIColor(red: 1, green: 0.3608, blue: 0.3608, alpha: 0.13)
    static let success = UIColor(red: 0.3412, green: 0.8118, blue: 0.4863, alpha: 1)
    static let successWeak = UIColor(red: 0.3412, green: 0.8118, blue: 0.4863, alpha: 0.13)
    static let info = UIColor(red: 0.2902, green: 0.6078, blue: 1, alpha: 1)
    static let infoWeak = UIColor(red: 0.2902, green: 0.6078, blue: 1, alpha: 0.14)
    static let running = UIColor(red: 0.2902, green: 0.6078, blue: 1, alpha: 1)

    // 圆角
    static let radiusLg: CGFloat = 18
    static let radiusMd: CGFloat = 10
    static let radiusSm: CGFloat = 6
    static let radiusPill: CGFloat = 999

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
}
