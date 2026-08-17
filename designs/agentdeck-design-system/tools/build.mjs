#!/usr/bin/env node
/* ============================================================
   AgentDeck 设计系统 · Token 生成器
   单一数据源 tokens/tokens.json → generated/{tokens.css, DesignTokens.ts}
   用法：node tools/build.mjs
   生成物禁止手改；改 tokens.json 后重跑本脚本。
   ============================================================ */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const src = JSON.parse(fs.readFileSync(path.join(root, "tokens/tokens.json"), "utf8"));
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
   2) DesignTokens.ts —— Web / RN 类型化消费
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
   3) ios/AgentDeckMobile/DesignTokens.swift —— UIKit 消费（codex 主题）
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

genCss();
genTs();
const mobileOut = genMobileSwift();
console.log("✓ 生成完成 → generated/tokens.css, generated/DesignTokens.ts");
if (mobileOut) console.log("✓ Mobile 契约 → " + mobileOut);
