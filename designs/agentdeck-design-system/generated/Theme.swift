// 生成物 · 由 tools/build.mjs 从 tokens/tokens.json 生成，禁止手改。
// AppKit 主题契约：视图读 Theme / Platform，禁止 `if theme == .x`。
import AppKit

public enum StatusShape: String { case dot, square, pill }
public enum SurfaceMode: String { case float, boxed, flat, hairline }
public enum ComposerForm: String { case card, cli, editorial }
public enum IconMode: String { case line, glyph, minimal }
public enum LabelCase: String { case normal, upper, smallCaps }

public struct Palette {
  public let bg, bgElevated, surface, surface2, surfaceInset, sidebarBg, border, borderStrong, separator, text, text2, text3, textOnAccent, accent, accentWeak, warn, warnWeak, danger, dangerWeak, success, successWeak, info, infoWeak, running: NSColor
}
public struct Radii { public let lg, md, sm, pill: CGFloat }
public struct Fonts { public let ui, display, mono: [String] }
public struct Typography {
  public let displayXl, display, title, body, callout, caption, mono: CGFloat
  public let lineHeightCJK, lineHeightLatin: CGFloat
}
public struct Structure {
  public let statusShape: StatusShape
  public let surfaceMode: SurfaceMode
  public let composerForm: ComposerForm
  public let iconMode: IconMode
  public let labelCase: LabelCase
}
public struct Theme {
  public let id: String
  public let isDark: Bool
  public let color: Palette
  public let radius: Radii
  public let font: Fonts
  public let typography: Typography
  public let structure: Structure
}

public extension Theme {
  static let codex = Theme(
    id: "codex", isDark: true,
    color: Palette(
      bg: NSColor(srgbRed: 0.0745, green: 0.0745, blue: 0.0745, alpha: 1),
      bgElevated: NSColor(srgbRed: 0.0863, green: 0.0863, blue: 0.0863, alpha: 1),
      surface: NSColor(srgbRed: 0.1098, green: 0.1098, blue: 0.1098, alpha: 1),
      surface2: NSColor(srgbRed: 0.149, green: 0.149, blue: 0.149, alpha: 1),
      surfaceInset: NSColor(srgbRed: 0.0588, green: 0.0588, blue: 0.0588, alpha: 1),
      sidebarBg: NSColor(srgbRed: 0.1255, green: 0.1294, blue: 0.1294, alpha: 1),
      border: NSColor(srgbRed: 0.1843, green: 0.1843, blue: 0.1843, alpha: 1),
      borderStrong: NSColor(srgbRed: 0.2706, green: 0.2706, blue: 0.2706, alpha: 1),
      separator: NSColor(srgbRed: 0.1294, green: 0.1294, blue: 0.1294, alpha: 1),
      text: NSColor(srgbRed: 1, green: 1, blue: 1, alpha: 0.93),
      text2: NSColor(srgbRed: 1, green: 1, blue: 1, alpha: 0.6),
      text3: NSColor(srgbRed: 1, green: 1, blue: 1, alpha: 0.4),
      textOnAccent: NSColor(srgbRed: 0.1098, green: 0.0588, blue: 0.0157, alpha: 1),
      accent: NSColor(srgbRed: 1, green: 0.4902, blue: 0.1804, alpha: 1),
      accentWeak: NSColor(srgbRed: 1, green: 0.4902, blue: 0.1804, alpha: 0.14),
      warn: NSColor(srgbRed: 1, green: 0.4902, blue: 0.1804, alpha: 1),
      warnWeak: NSColor(srgbRed: 1, green: 0.4902, blue: 0.1804, alpha: 0.14),
      danger: NSColor(srgbRed: 1, green: 0.3608, blue: 0.3608, alpha: 1),
      dangerWeak: NSColor(srgbRed: 1, green: 0.3608, blue: 0.3608, alpha: 0.13),
      success: NSColor(srgbRed: 0.3412, green: 0.8118, blue: 0.4863, alpha: 1),
      successWeak: NSColor(srgbRed: 0.3412, green: 0.8118, blue: 0.4863, alpha: 0.13),
      info: NSColor(srgbRed: 0.2902, green: 0.6078, blue: 1, alpha: 1),
      infoWeak: NSColor(srgbRed: 0.2902, green: 0.6078, blue: 1, alpha: 0.14),
      running: NSColor(srgbRed: 0.2902, green: 0.6078, blue: 1, alpha: 1)
    ),
    radius: Radii(lg: 18, md: 10, sm: 6, pill: 999),
    font: Fonts(ui: ["-apple-system", "SF Pro Text", "PingFang SC", "Noto Sans SC", "sans-serif"], display: ["-apple-system", "SF Pro Display", "PingFang SC", "Noto Sans SC", "sans-serif"], mono: ["SF Mono", "JetBrains Mono", "ui-monospace", "PingFang SC", "monospace"]),
    typography: Typography(displayXl: 34, display: 24, title: 16, body: 14, callout: 13, caption: 11, mono: 12.5, lineHeightCJK: 1.72, lineHeightLatin: 1.45),
    structure: Structure(statusShape: .dot, surfaceMode: .float, composerForm: .card, iconMode: .line, labelCase: .normal)
  )
  static let terminal = Theme(
    id: "terminal", isDark: true,
    color: Palette(
      bg: NSColor(srgbRed: 0.0275, green: 0.0314, blue: 0.0275, alpha: 1),
      bgElevated: NSColor(srgbRed: 0.0392, green: 0.0471, blue: 0.0392, alpha: 1),
      surface: NSColor(srgbRed: 0.051, green: 0.0627, blue: 0.051, alpha: 1),
      surface2: NSColor(srgbRed: 0.0784, green: 0.102, blue: 0.0784, alpha: 1),
      surfaceInset: NSColor(srgbRed: 0.0196, green: 0.0235, blue: 0.0196, alpha: 1),
      sidebarBg: NSColor(srgbRed: 0.0392, green: 0.0471, blue: 0.0392, alpha: 1),
      border: NSColor(srgbRed: 0.1137, green: 0.1451, blue: 0.1137, alpha: 1),
      borderStrong: NSColor(srgbRed: 0.1725, green: 0.2196, blue: 0.1725, alpha: 1),
      separator: NSColor(srgbRed: 0.0824, green: 0.1059, blue: 0.0824, alpha: 1),
      text: NSColor(srgbRed: 0.8118, green: 0.9098, blue: 0.8118, alpha: 1),
      text2: NSColor(srgbRed: 0.498, green: 0.6431, blue: 0.498, alpha: 1),
      text3: NSColor(srgbRed: 0.298, green: 0.3922, blue: 0.298, alpha: 1),
      textOnAccent: NSColor(srgbRed: 0.0157, green: 0.0627, blue: 0.0157, alpha: 1),
      accent: NSColor(srgbRed: 0.2902, green: 0.8706, blue: 0.502, alpha: 1),
      accentWeak: NSColor(srgbRed: 0.2902, green: 0.8706, blue: 0.502, alpha: 0.12),
      warn: NSColor(srgbRed: 0.9608, green: 0.7098, blue: 0.2667, alpha: 1),
      warnWeak: NSColor(srgbRed: 0.9608, green: 0.7098, blue: 0.2667, alpha: 0.14),
      danger: NSColor(srgbRed: 1, green: 0.4196, blue: 0.4196, alpha: 1),
      dangerWeak: NSColor(srgbRed: 1, green: 0.4196, blue: 0.4196, alpha: 0.13),
      success: NSColor(srgbRed: 0.2902, green: 0.8706, blue: 0.502, alpha: 1),
      successWeak: NSColor(srgbRed: 0.2902, green: 0.8706, blue: 0.502, alpha: 0.13),
      info: NSColor(srgbRed: 0.3451, green: 0.7843, blue: 1, alpha: 1),
      infoWeak: NSColor(srgbRed: 0.3451, green: 0.7843, blue: 1, alpha: 0.14),
      running: NSColor(srgbRed: 0.2902, green: 0.8706, blue: 0.502, alpha: 1)
    ),
    radius: Radii(lg: 4, md: 3, sm: 2, pill: 3),
    font: Fonts(ui: ["JetBrains Mono", "SF Mono", "ui-monospace", "PingFang SC", "monospace"], display: ["JetBrains Mono", "ui-monospace", "monospace"], mono: ["JetBrains Mono", "SF Mono", "ui-monospace", "monospace"]),
    typography: Typography(displayXl: 34, display: 24, title: 16, body: 14, callout: 13, caption: 11, mono: 12.5, lineHeightCJK: 1.72, lineHeightLatin: 1.45),
    structure: Structure(statusShape: .square, surfaceMode: .boxed, composerForm: .cli, iconMode: .glyph, labelCase: .upper)
  )
  static let linear = Theme(
    id: "linear", isDark: true,
    color: Palette(
      bg: NSColor(srgbRed: 0.0392, green: 0.0431, blue: 0.0588, alpha: 1),
      bgElevated: NSColor(srgbRed: 0.0549, green: 0.0588, blue: 0.0784, alpha: 1),
      surface: NSColor(srgbRed: 0.0784, green: 0.0863, blue: 0.1137, alpha: 1),
      surface2: NSColor(srgbRed: 0.1059, green: 0.1176, blue: 0.1529, alpha: 1),
      surfaceInset: NSColor(srgbRed: 0.0431, green: 0.0471, blue: 0.0667, alpha: 1),
      sidebarBg: NSColor(srgbRed: 0.051, green: 0.0549, blue: 0.0745, alpha: 1),
      border: NSColor(srgbRed: 1, green: 1, blue: 1, alpha: 0.09),
      borderStrong: NSColor(srgbRed: 1, green: 1, blue: 1, alpha: 0.16),
      separator: NSColor(srgbRed: 1, green: 1, blue: 1, alpha: 0.05),
      text: NSColor(srgbRed: 0.9059, green: 0.9098, blue: 0.9333, alpha: 1),
      text2: NSColor(srgbRed: 0.6039, green: 0.6118, blue: 0.6706, alpha: 1),
      text3: NSColor(srgbRed: 0.3804, green: 0.3882, blue: 0.4353, alpha: 1),
      textOnAccent: NSColor(srgbRed: 1, green: 1, blue: 1, alpha: 1),
      accent: NSColor(srgbRed: 0.4863, green: 0.4549, blue: 1, alpha: 1),
      accentWeak: NSColor(srgbRed: 0.4863, green: 0.4549, blue: 1, alpha: 0.16),
      warn: NSColor(srgbRed: 0.9608, green: 0.651, blue: 0.1373, alpha: 1),
      warnWeak: NSColor(srgbRed: 0.9608, green: 0.651, blue: 0.1373, alpha: 0.14),
      danger: NSColor(srgbRed: 1, green: 0.3647, blue: 0.4235, alpha: 1),
      dangerWeak: NSColor(srgbRed: 1, green: 0.3647, blue: 0.4235, alpha: 0.14),
      success: NSColor(srgbRed: 0.298, green: 0.8314, blue: 0.4431, alpha: 1),
      successWeak: NSColor(srgbRed: 0.298, green: 0.8314, blue: 0.4431, alpha: 0.13),
      info: NSColor(srgbRed: 0.4863, green: 0.4549, blue: 1, alpha: 1),
      infoWeak: NSColor(srgbRed: 0.4863, green: 0.4549, blue: 1, alpha: 0.16),
      running: NSColor(srgbRed: 0.4863, green: 0.4549, blue: 1, alpha: 1)
    ),
    radius: Radii(lg: 12, md: 8, sm: 6, pill: 999),
    font: Fonts(ui: ["-apple-system", "SF Pro Text", "PingFang SC", "Noto Sans SC", "sans-serif"], display: ["Space Grotesk", "-apple-system", "PingFang SC", "Noto Sans SC", "sans-serif"], mono: ["JetBrains Mono", "ui-monospace", "monospace"]),
    typography: Typography(displayXl: 34, display: 24, title: 16, body: 14, callout: 13, caption: 11, mono: 12.5, lineHeightCJK: 1.72, lineHeightLatin: 1.45),
    structure: Structure(statusShape: .pill, surfaceMode: .float, composerForm: .card, iconMode: .line, labelCase: .normal)
  )
  static let warm = Theme(
    id: "warm", isDark: false,
    color: Palette(
      bg: NSColor(srgbRed: 0.9569, green: 0.9412, blue: 0.9059, alpha: 1),
      bgElevated: NSColor(srgbRed: 0.9373, green: 0.9137, blue: 0.8627, alpha: 1),
      surface: NSColor(srgbRed: 1, green: 0.9922, blue: 0.9725, alpha: 1),
      surface2: NSColor(srgbRed: 0.9608, green: 0.9412, blue: 0.8941, alpha: 1),
      surfaceInset: NSColor(srgbRed: 0.9373, green: 0.9137, blue: 0.8627, alpha: 1),
      sidebarBg: NSColor(srgbRed: 0.9373, green: 0.9098, blue: 0.851, alpha: 1),
      border: NSColor(srgbRed: 0.8902, green: 0.8588, blue: 0.7882, alpha: 1),
      borderStrong: NSColor(srgbRed: 0.8275, green: 0.7882, blue: 0.698, alpha: 1),
      separator: NSColor(srgbRed: 0.9176, green: 0.8863, blue: 0.8275, alpha: 1),
      text: NSColor(srgbRed: 0.1333, green: 0.1137, blue: 0.0824, alpha: 1),
      text2: NSColor(srgbRed: 0.4275, green: 0.3922, blue: 0.3294, alpha: 1),
      text3: NSColor(srgbRed: 0.6039, green: 0.5686, blue: 0.4902, alpha: 1),
      textOnAccent: NSColor(srgbRed: 1, green: 0.9725, blue: 0.9373, alpha: 1),
      accent: NSColor(srgbRed: 0.7098, green: 0.3137, blue: 0.1216, alpha: 1),
      accentWeak: NSColor(srgbRed: 0.7098, green: 0.3137, blue: 0.1216, alpha: 0.1),
      warn: NSColor(srgbRed: 0.7216, green: 0.4784, blue: 0.0706, alpha: 1),
      warnWeak: NSColor(srgbRed: 0.7216, green: 0.4784, blue: 0.0706, alpha: 0.13),
      danger: NSColor(srgbRed: 0.7333, green: 0.2235, blue: 0.1686, alpha: 1),
      dangerWeak: NSColor(srgbRed: 0.7333, green: 0.2235, blue: 0.1686, alpha: 0.1),
      success: NSColor(srgbRed: 0.2471, green: 0.4902, blue: 0.3098, alpha: 1),
      successWeak: NSColor(srgbRed: 0.2471, green: 0.4902, blue: 0.3098, alpha: 0.12),
      info: NSColor(srgbRed: 0.2471, green: 0.4314, blue: 0.6471, alpha: 1),
      infoWeak: NSColor(srgbRed: 0.2471, green: 0.4314, blue: 0.6471, alpha: 0.12),
      running: NSColor(srgbRed: 0.2471, green: 0.4314, blue: 0.6471, alpha: 1)
    ),
    radius: Radii(lg: 14, md: 10, sm: 7, pill: 999),
    font: Fonts(ui: ["-apple-system", "SF Pro Text", "PingFang SC", "Noto Sans SC", "sans-serif"], display: ["Newsreader", "Georgia", "Songti SC", "Noto Serif SC", "serif"], mono: ["JetBrains Mono", "ui-monospace", "monospace"]),
    typography: Typography(displayXl: 34, display: 24, title: 16, body: 14, callout: 13, caption: 11, mono: 12.5, lineHeightCJK: 1.72, lineHeightLatin: 1.45),
    structure: Structure(statusShape: .dot, surfaceMode: .hairline, composerForm: .editorial, iconMode: .minimal, labelCase: .smallCaps)
  )
  static let notion = Theme(
    id: "notion", isDark: false,
    color: Palette(
      bg: NSColor(srgbRed: 1, green: 1, blue: 1, alpha: 1),
      bgElevated: NSColor(srgbRed: 0.9843, green: 0.9843, blue: 0.9804, alpha: 1),
      surface: NSColor(srgbRed: 1, green: 1, blue: 1, alpha: 1),
      surface2: NSColor(srgbRed: 0.9451, green: 0.9451, blue: 0.9373, alpha: 1),
      surfaceInset: NSColor(srgbRed: 0.9686, green: 0.9647, blue: 0.9529, alpha: 1),
      sidebarBg: NSColor(srgbRed: 0.9843, green: 0.9843, blue: 0.9804, alpha: 1),
      border: NSColor(srgbRed: 0.9137, green: 0.9137, blue: 0.9059, alpha: 1),
      borderStrong: NSColor(srgbRed: 0.8667, green: 0.8627, blue: 0.8471, alpha: 1),
      separator: NSColor(srgbRed: 0.9373, green: 0.9373, blue: 0.9333, alpha: 1),
      text: NSColor(srgbRed: 0.2157, green: 0.2078, blue: 0.1843, alpha: 1),
      text2: NSColor(srgbRed: 0.4706, green: 0.4667, blue: 0.4549, alpha: 1),
      text3: NSColor(srgbRed: 0.6078, green: 0.6039, blue: 0.5922, alpha: 1),
      textOnAccent: NSColor(srgbRed: 1, green: 1, blue: 1, alpha: 1),
      accent: NSColor(srgbRed: 0.1373, green: 0.5137, blue: 0.8863, alpha: 1),
      accentWeak: NSColor(srgbRed: 0.1373, green: 0.5137, blue: 0.8863, alpha: 0.1),
      warn: NSColor(srgbRed: 0.7961, green: 0.4824, blue: 0.1451, alpha: 1),
      warnWeak: NSColor(srgbRed: 0.7961, green: 0.4824, blue: 0.1451, alpha: 0.13),
      danger: NSColor(srgbRed: 0.8784, green: 0.2431, blue: 0.2431, alpha: 1),
      dangerWeak: NSColor(srgbRed: 0.8784, green: 0.2431, blue: 0.2431, alpha: 0.1),
      success: NSColor(srgbRed: 0.0588, green: 0.4824, blue: 0.4235, alpha: 1),
      successWeak: NSColor(srgbRed: 0.0588, green: 0.4824, blue: 0.4235, alpha: 0.12),
      info: NSColor(srgbRed: 0.1373, green: 0.5137, blue: 0.8863, alpha: 1),
      infoWeak: NSColor(srgbRed: 0.1373, green: 0.5137, blue: 0.8863, alpha: 0.1),
      running: NSColor(srgbRed: 0.1373, green: 0.5137, blue: 0.8863, alpha: 1)
    ),
    radius: Radii(lg: 6, md: 4, sm: 3, pill: 999),
    font: Fonts(ui: ["-apple-system", "SF Pro Text", "Segoe UI", "PingFang SC", "Noto Sans SC", "sans-serif"], display: ["-apple-system", "SF Pro Display", "Segoe UI", "PingFang SC", "sans-serif"], mono: ["SF Mono", "JetBrains Mono", "ui-monospace", "monospace"]),
    typography: Typography(displayXl: 34, display: 24, title: 16, body: 14, callout: 13, caption: 11, mono: 12.5, lineHeightCJK: 1.72, lineHeightLatin: 1.45),
    structure: Structure(statusShape: .dot, surfaceMode: .flat, composerForm: .card, iconMode: .line, labelCase: .normal)
  )
  static let macos = Theme(
    id: "macos", isDark: false,
    color: Palette(
      bg: NSColor(srgbRed: 1, green: 1, blue: 1, alpha: 1),
      bgElevated: NSColor(srgbRed: 0.9608, green: 0.9608, blue: 0.9686, alpha: 1),
      surface: NSColor(srgbRed: 1, green: 1, blue: 1, alpha: 1),
      surface2: NSColor(srgbRed: 0.9255, green: 0.9255, blue: 0.9255, alpha: 1),
      surfaceInset: NSColor(srgbRed: 0.9608, green: 0.9608, blue: 0.9686, alpha: 1),
      sidebarBg: NSColor(srgbRed: 0.9647, green: 0.9647, blue: 0.9725, alpha: 0.82),
      border: NSColor(srgbRed: 0.851, green: 0.851, blue: 0.8627, alpha: 1),
      borderStrong: NSColor(srgbRed: 0.7725, green: 0.7725, blue: 0.7843, alpha: 1),
      separator: NSColor(srgbRed: 0.902, green: 0.902, blue: 0.9098, alpha: 1),
      text: NSColor(srgbRed: 0.1137, green: 0.1137, blue: 0.1216, alpha: 1),
      text2: NSColor(srgbRed: 0, green: 0, blue: 0, alpha: 0.52),
      text3: NSColor(srgbRed: 0, green: 0, blue: 0, alpha: 0.34),
      textOnAccent: NSColor(srgbRed: 1, green: 1, blue: 1, alpha: 1),
      accent: NSColor(srgbRed: 0, green: 0.4784, blue: 1, alpha: 1),
      accentWeak: NSColor(srgbRed: 0, green: 0.4784, blue: 1, alpha: 0.12),
      warn: NSColor(srgbRed: 1, green: 0.5843, blue: 0, alpha: 1),
      warnWeak: NSColor(srgbRed: 1, green: 0.5843, blue: 0, alpha: 0.16),
      danger: NSColor(srgbRed: 1, green: 0.2314, blue: 0.1882, alpha: 1),
      dangerWeak: NSColor(srgbRed: 1, green: 0.2314, blue: 0.1882, alpha: 0.12),
      success: NSColor(srgbRed: 0.2039, green: 0.7804, blue: 0.349, alpha: 1),
      successWeak: NSColor(srgbRed: 0.2039, green: 0.7804, blue: 0.349, alpha: 0.16),
      info: NSColor(srgbRed: 0, green: 0.4784, blue: 1, alpha: 1),
      infoWeak: NSColor(srgbRed: 0, green: 0.4784, blue: 1, alpha: 0.12),
      running: NSColor(srgbRed: 0, green: 0.4784, blue: 1, alpha: 1)
    ),
    radius: Radii(lg: 12, md: 8, sm: 6, pill: 999),
    font: Fonts(ui: ["-apple-system", "SF Pro Text", "Helvetica Neue", "PingFang SC", "Noto Sans SC", "sans-serif"], display: ["-apple-system", "SF Pro Display", "Helvetica Neue", "PingFang SC", "sans-serif"], mono: ["SF Mono", "JetBrains Mono", "ui-monospace", "monospace"]),
    typography: Typography(displayXl: 34, display: 24, title: 16, body: 14, callout: 13, caption: 11, mono: 12.5, lineHeightCJK: 1.72, lineHeightLatin: 1.45),
    structure: Structure(statusShape: .dot, surfaceMode: .float, composerForm: .card, iconMode: .line, labelCase: .normal)
  )
  static let all: [Theme] = [.codex, .terminal, .linear, .warm, .notion, .macos]
}

public struct Platform {
  public let id: String
  public let safeTop, safeBottom, navBlur: CGFloat
}
public extension Platform {
  static let ios = Platform(id: "ios", safeTop: 46, safeBottom: 22, navBlur: 12)
  static let android = Platform(id: "android", safeTop: 30, safeBottom: 12, navBlur: 0)
  static let all: [Platform] = [.ios, .android]
}
