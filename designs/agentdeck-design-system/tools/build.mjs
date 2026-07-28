#!/usr/bin/env node
/* ============================================================
   AgentDeck 设计系统 · Token 生成器
   单一数据源 tokens/tokens.json → generated/{tokens.css, Theme.swift, DesignTokens.ts}
   用法：node tools/build.mjs
   生成物禁止手改；改 tokens.json 后重跑本脚本。
   ============================================================ */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const src = JSON.parse(fs.readFileSync(path.join(root, "tokens/tokens.json"), "utf8"));
const componentsPath = path.join(root, "components/components.json");
const components = fs.existsSync(componentsPath)
  ? JSON.parse(fs.readFileSync(componentsPath, "utf8"))
  : null;
const outDir = path.join(root, "generated");
fs.mkdirSync(outDir, { recursive: true });

/* ---------- 工具 ---------- */
const kebab = (s) =>
  s.replace(/([a-z])([A-Z])/g, "$1-$2").replace(/([a-zA-Z])(\d)/g, "$1-$2").toLowerCase();

const fontCss = (arr) => arr.map((f) => (/\s/.test(f) ? `"${f}"` : f)).join(", ");

// 解析 #hex / rgba() → {r,g,b,a} in 0..1
function parseColor(v) {
  if (typeof v !== "string") return null;
  const s = v.trim();
  let m = s.match(/^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$/);
  if (m) {
    let h = m[1];
    if (h.length === 3) h = h.split("").map((c) => c + c).join("");
    return { r: parseInt(h.slice(0, 2), 16) / 255, g: parseInt(h.slice(2, 4), 16) / 255, b: parseInt(h.slice(4, 6), 16) / 255, a: 1 };
  }
  m = s.match(/^rgba?\(\s*([\d.]+)\s*,\s*([\d.]+)\s*,\s*([\d.]+)\s*(?:,\s*([\d.]+)\s*)?\)$/);
  if (m) return { r: +m[1] / 255, g: +m[2] / 255, b: +m[3] / 255, a: m[4] === undefined ? 1 : +m[4] };
  return null; // 非纯色（渐变/none）
}
const f4 = (n) => Math.round(n * 10000) / 10000;

const THEMES = src.$meta.themes;
const isPrimary = (id) => id === src.$meta.primaryTheme;

/* ============================================================
   1) tokens.css —— 与手写 tokens.css 等价（供展示页/Web 消费）
   ============================================================ */
function genCss() {
  const g = src.global;
  const L = [];
  L.push("/* 生成物 · 由 tools/build.mjs 从 tokens/tokens.json 生成，禁止手改 */\n");

  // 全局常量
  L.push(":root {");
  L.push(`  --lh-cjk: ${g.lineHeight.cjk};`);
  L.push(`  --lh-latin: ${g.lineHeight.latin};`);
  L.push(`  --ease: ${g.motion.ease};`);
  L.push(`  --ease-out: ${g.motion.easeOut};`);
  L.push(`  --dur: ${g.motion.durationMs / 1000}s;`);
  for (const [k, v] of Object.entries(g.spacing)) L.push(`  --sp-${k}: ${v}px;`);
  L.push("}\n");

  for (const id of THEMES) {
    const t = src.themes[id];
    const sel = isPrimary(id) ? `:root,\n[data-theme="${id}"]` : `[data-theme="${id}"]`;
    L.push(`${sel} {`);
    L.push(`  color-scheme: ${t.colorScheme};`);
    for (const [k, v] of Object.entries(t.color)) L.push(`  --${kebab(k)}: ${v};`);
    for (const [k, v] of Object.entries(t.radius)) L.push(`  --radius-${k}: ${v}px;`);
    for (const [k, v] of Object.entries(t.font)) L.push(`  --font-${k}: ${fontCss(v)};`);
    for (const [k, v] of Object.entries(t.shadow)) L.push(`  --shadow-${k}: ${v};`);
    for (const [k, v] of Object.entries(t.effect)) L.push(`  --${kebab(k)}: ${v};`);
    L.push(`  --label-transform: ${t.label.transform};`);
    L.push(`  --label-tracking: ${t.label.tracking};`);
    L.push(`  --disp-tracking: ${t.label.dispTracking};`);
    L.push("}\n");
  }

  // 平台轴
  for (const [id, p] of Object.entries(src.platform)) {
    const sel = id === "ios" ? `:root,\n[data-platform="${id}"]` : `[data-platform="${id}"]`;
    L.push(`${sel} {`);
    L.push(`  --p-safe-top: ${p.safeTop}px;`);
    L.push(`  --p-safe-bottom: ${p.safeBottom}px;`);
    L.push(`  --p-nav-blur: ${p.navBlur}px;`);
    L.push(`  --p-nav-solid: ${p.navSolid === "surface" ? "var(--surface)" : p.navSolid};`);
    L.push("}\n");
  }
  fs.writeFileSync(path.join(outDir, "tokens.css"), L.join("\n"));
}

/* ============================================================
   2) Theme.swift —— AppKit 原生契约（无 if theme== ；视图读 Theme）
   ============================================================ */
function swiftColor(v) {
  const c = parseColor(v);
  if (!c) return `/* 非纯色，见 CSS 层：${v} */ .clear`;
  return `NSColor(srgbRed: ${f4(c.r)}, green: ${f4(c.g)}, blue: ${f4(c.b)}, alpha: ${f4(c.a)})`;
}
function genSwift() {
  const g = src.global;
  const L = [];
  L.push("// 生成物 · 由 tools/build.mjs 从 tokens/tokens.json 生成，禁止手改。");
  L.push("// AppKit 主题契约：视图读 Theme / Platform，禁止 `if theme == .x`。");
  L.push("import AppKit\n");
  L.push("public enum StatusShape: String { case dot, square, pill }");
  L.push("public enum SurfaceMode: String { case float, boxed, flat, hairline }");
  L.push("public enum ComposerForm: String { case card, cli, editorial }");
  L.push("public enum IconMode: String { case line, glyph, minimal }");
  L.push("public enum LabelCase: String { case normal, upper, smallCaps }\n");

  const colorKeys = Object.keys(src.themes[src.$meta.primaryTheme].color);
  L.push("public struct Palette {");
  L.push("  public let " + colorKeys.map((k) => k).join(", ") + ": NSColor");
  L.push("}");
  L.push("public struct Radii { public let lg, md, sm, pill: CGFloat }");
  L.push("public struct Fonts { public let ui, display, mono: [String] }");
  L.push("public struct Typography {");
  L.push("  public let displayXl, display, title, body, callout, caption, mono: CGFloat");
  L.push("  public let lineHeightCJK, lineHeightLatin: CGFloat");
  L.push("}");
  L.push("public struct Structure {");
  L.push("  public let statusShape: StatusShape");
  L.push("  public let surfaceMode: SurfaceMode");
  L.push("  public let composerForm: ComposerForm");
  L.push("  public let iconMode: IconMode");
  L.push("  public let labelCase: LabelCase");
  L.push("}");
  L.push("public struct Theme {");
  L.push("  public let id: String");
  L.push("  public let isDark: Bool");
  L.push("  public let color: Palette");
  L.push("  public let radius: Radii");
  L.push("  public let font: Fonts");
  L.push("  public let typography: Typography");
  L.push("  public let structure: Structure");
  L.push("}\n");

  L.push("public extension Theme {");
  for (const id of THEMES) {
    const t = src.themes[id];
    const st = t.structure;
    const pal = colorKeys.map((k) => `${k}: ${swiftColor(t.color[k])}`).join(",\n      ");
    L.push(`  static let ${id} = Theme(`);
    L.push(`    id: "${id}", isDark: ${t.colorScheme === "dark"},`);
    L.push(`    color: Palette(\n      ${pal}\n    ),`);
    L.push(`    radius: Radii(lg: ${t.radius.lg}, md: ${t.radius.md}, sm: ${t.radius.sm}, pill: ${t.radius.pill}),`);
    L.push(`    font: Fonts(ui: [${t.font.ui.map((x) => `"${x}"`).join(", ")}], display: [${t.font.display.map((x) => `"${x}"`).join(", ")}], mono: [${t.font.mono.map((x) => `"${x}"`).join(", ")}]),`);
    L.push(`    typography: Typography(displayXl: ${g.type.displayXl}, display: ${g.type.display}, title: ${g.type.title}, body: ${g.type.body}, callout: ${g.type.callout}, caption: ${g.type.caption}, mono: ${g.type.mono}, lineHeightCJK: ${g.lineHeight.cjk}, lineHeightLatin: ${g.lineHeight.latin}),`);
    L.push(`    structure: Structure(statusShape: .${st.statusShape}, surfaceMode: .${st.surfaceMode}, composerForm: .${st.composerForm}, iconMode: .${st.iconMode}, labelCase: .${st.labelCase})`);
    L.push(`  )`);
  }
  L.push(`  static let all: [Theme] = [${THEMES.map((t) => "." + t).join(", ")}]`);
  L.push("}\n");

  L.push("public struct Platform {");
  L.push("  public let id: String");
  L.push("  public let safeTop, safeBottom, navBlur: CGFloat");
  L.push("}");
  L.push("public extension Platform {");
  for (const [id, p] of Object.entries(src.platform)) {
    L.push(`  static let ${id} = Platform(id: "${id}", safeTop: ${p.safeTop}, safeBottom: ${p.safeBottom}, navBlur: ${p.navBlur})`);
  }
  L.push(`  static let all: [Platform] = [${Object.keys(src.platform).map((p) => "." + p).join(", ")}]`);
  L.push("}");
  fs.writeFileSync(path.join(outDir, "Theme.swift"), L.join("\n") + "\n");
}

/* ============================================================
   3) DesignTokens.ts —— Web / RN 类型化消费
   ============================================================ */
function genTs() {
  const L = [];
  L.push("// 生成物 · 由 tools/build.mjs 从 tokens/tokens.json 生成，禁止手改。");
  L.push(`export const DesignTokens = ${JSON.stringify({ global: src.global, themes: src.themes, platform: src.platform }, null, 2)} as const;`);
  L.push(`export type ThemeId = ${THEMES.map((t) => `"${t}"`).join(" | ")};`);
  L.push(`export type PlatformId = ${Object.keys(src.platform).map((p) => `"${p}"`).join(" | ")};`);
  L.push(`export type ColorToken = keyof typeof DesignTokens.themes.${src.$meta.primaryTheme}.color;`);
  fs.writeFileSync(path.join(outDir, "DesignTokens.ts"), L.join("\n") + "\n");
}

/* ============================================================
   4) Sources/AgentDeck/DesignTokens.swift —— App 直接消费（codex 主题）
   仅当 App 源码树存在时生成，让 SSOT 直接驱动原生端。
   ============================================================ */
function genAppSwift() {
  const appDir = path.join(root, "../../Sources/AgentDeck");
  if (!fs.existsSync(appDir)) return null;
  const id = src.$meta.primaryTheme;
  const t = src.themes[id];
  const g = src.global;
  const L = [];
  L.push("// 生成物 · 由设计系统 SSOT 生成（designs/agentdeck-design-system/tokens/tokens.json，" + id + " 主题）。");
  L.push("// 禁止手改；改 SSOT 后在 designs/agentdeck-design-system 跑 `node tools/build.mjs` 重生成。");
  L.push("import AppKit\n");
  L.push("enum DesignTokens {");
  L.push("    // 颜色（sRGB，来自设计系统语义 token）");
  for (const [k, v] of Object.entries(t.color)) {
    const c = parseColor(v);
    if (!c) continue;
    L.push(`    static let ${k} = NSColor(srgbRed: ${f4(c.r)}, green: ${f4(c.g)}, blue: ${f4(c.b)}, alpha: ${f4(c.a)})`);
  }
  L.push("");
  L.push("    // 圆角");
  L.push(`    static let radiusLg: CGFloat = ${t.radius.lg}`);
  L.push(`    static let radiusMd: CGFloat = ${t.radius.md}`);
  L.push(`    static let radiusSm: CGFloat = ${t.radius.sm}`);
  L.push("");
  L.push("    // 间距（4pt 基准）");
  for (const [k, v] of Object.entries(g.spacing)) L.push(`    static let sp${k}: CGFloat = ${v}`);
  L.push("");
  L.push("    // 排版（字号与行高倍率）");
  for (const [k, v] of Object.entries(g.type)) {
    const swiftKey = k.charAt(0).toUpperCase() + k.slice(1);
    L.push(`    static let type${swiftKey}: CGFloat = ${v}`);
  }
  L.push(`    static let lineHeightCJK: CGFloat = ${g.lineHeight.cjk}`);
  L.push(`    static let lineHeightLatin: CGFloat = ${g.lineHeight.latin}`);
  L.push("");
  L.push("    // 阴影（分层柔光，供 roundedPanel 使用）");
  L.push("    static let panelShadowColor = NSColor(srgbRed: 0, green: 0, blue: 0, alpha: 0.42)");
  L.push("    static let panelShadowBlur: CGFloat = 26");
  L.push("    static let panelShadowOffset = CGSize(width: 0, height: -8)");
  L.push("}");
  fs.writeFileSync(path.join(appDir, "DesignTokens.swift"), L.join("\n") + "\n");
  return path.relative(path.join(root, "../.."), path.join(appDir, "DesignTokens.swift"));
}

/* ============================================================
   5) ios/AgentDeckMobile/DesignTokens.swift —— UIKit 消费（codex 主题）
   仅当 iOS 源码树存在时生成。
   ============================================================ */
function genMobileSwift() {
  const appDir = path.join(root, "../../ios/AgentDeckMobile");
  if (!fs.existsSync(appDir)) return null;
  const id = src.$meta.primaryTheme;
  const t = src.themes[id];
  const g = src.global;
  const L = [];
  L.push("// 生成物 · 由设计系统 SSOT 生成（designs/agentdeck-design-system/tokens/tokens.json，" + id + " 主题）。");
  L.push("// 禁止手改；改 SSOT 后在 designs/agentdeck-design-system 跑 `node tools/build.mjs` 重生成。");
  L.push("import UIKit\n");
  L.push("enum DesignTokens {");
  L.push("    // 颜色（sRGB，来自设计系统语义 token）");
  for (const [k, v] of Object.entries(t.color)) {
    const c = parseColor(v);
    if (!c) continue;
    L.push(`    static let ${k} = UIColor(red: ${f4(c.r)}, green: ${f4(c.g)}, blue: ${f4(c.b)}, alpha: ${f4(c.a)})`);
  }
  L.push("");
  L.push("    // 圆角");
  L.push(`    static let radiusLg: CGFloat = ${t.radius.lg}`);
  L.push(`    static let radiusMd: CGFloat = ${t.radius.md}`);
  L.push(`    static let radiusSm: CGFloat = ${t.radius.sm}`);
  L.push(`    static let radiusPill: CGFloat = ${t.radius.pill}`);
  L.push("");
  L.push("    // 间距（4pt 基准）");
  for (const [k, v] of Object.entries(g.spacing)) L.push(`    static let sp${k}: CGFloat = ${v}`);
  L.push("}");
  fs.writeFileSync(path.join(appDir, "DesignTokens.swift"), L.join("\n") + "\n");
  return "ios/AgentDeckMobile/DesignTokens.swift";
}

/* ============================================================
   6) Sources/AgentDeck/ComponentSpecs.swift —— 组件视觉骨架契约
   由 components/components.json 生成；供画廊结构断言测试消费。
   ============================================================ */
function swiftStringArray(arr) {
  return "[" + arr.map((s) => JSON.stringify(s)).join(", ") + "]";
}
function genComponentSpecs() {
  const appDir = path.join(root, "../../Sources/AgentDeck");
  if (!components || !fs.existsSync(appDir)) return null;
  const L = [];
  L.push("// 生成物 · 由设计系统 SSOT 生成（designs/agentdeck-design-system/components/components.json）。");
  L.push("// 禁止手改；改 SSOT 后在 designs/agentdeck-design-system 跑 `node tools/build.mjs` 重生成。");
  L.push("");
  L.push("/// 组件稳定视觉骨架契约：设计自有的静态标签与禁止元素（不含行为、不含 fixture 数据）。");
  L.push("enum ComponentSpecs {");
  L.push("    struct Spec {");
  L.push("        let key: String");
  L.push("        let title: String");
  L.push("        let requiredLabels: [String]");
  L.push("        let forbiddenLabels: [String]");
  L.push("        let forbidAccentBar: Bool");
  L.push("    }");
  L.push("");
  const entries = Object.entries(components.components);
  L.push("    static let all: [Spec] = [");
  for (const [key, c] of entries) {
    L.push("        Spec(");
    L.push(`            key: ${JSON.stringify(key)},`);
    L.push(`            title: ${JSON.stringify(c.title || key)},`);
    L.push(`            requiredLabels: ${swiftStringArray(c.requiredLabels || [])},`);
    L.push(`            forbiddenLabels: ${swiftStringArray(c.forbiddenLabels || [])},`);
    L.push(`            forbidAccentBar: ${c.forbidAccentBar ? "true" : "false"}`);
    L.push("        ),");
  }
  L.push("    ]");
  L.push("");
  L.push("    static func spec(_ key: String) -> Spec? { all.first { $0.key == key } }");
  L.push("}");
  fs.writeFileSync(path.join(appDir, "ComponentSpecs.swift"), L.join("\n") + "\n");
  return path.relative(path.join(root, "../.."), path.join(appDir, "ComponentSpecs.swift"));
}

genCss();
genSwift();
genTs();
const appOut = genAppSwift();
const mobileOut = genMobileSwift();
const specsOut = genComponentSpecs();
console.log("✓ 生成完成 → generated/tokens.css, generated/Theme.swift, generated/DesignTokens.ts");
if (appOut) console.log("✓ App 契约 → " + appOut);
if (mobileOut) console.log("✓ Mobile 契约 → " + mobileOut);
if (specsOut) console.log("✓ 组件契约 → " + specsOut);
