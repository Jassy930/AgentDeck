#!/usr/bin/env node
/* ============================================================
   AgentDeck 设计系统 · 无障碍对比度核验（WCAG 2.1）
   逐主题计算关键前景/背景对的对比度（含 alpha over 背景合成）。
   门禁：正文 text/bg ≥ 4.5；强调 accent/bg 与次文 text2/bg ≥ 3.0。
   text3 为提示/装饰级，仅报告不拦截。用法：node tools/a11y.mjs
   ============================================================ */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const src = JSON.parse(fs.readFileSync(path.join(root, "tokens/tokens.json"), "utf8"));

function parse(v) {
  const s = String(v).trim();
  let m = s.match(/^#([0-9a-f]{3}|[0-9a-f]{6})$/i);
  if (m) { let h = m[1]; if (h.length === 3) h = h.split("").map((c) => c + c).join(""); return { r: parseInt(h.slice(0, 2), 16), g: parseInt(h.slice(2, 4), 16), b: parseInt(h.slice(4, 6), 16), a: 1 }; }
  m = s.match(/^rgba?\(([\d.]+),([\d.]+),([\d.]+)(?:,([\d.]+))?\)$/);
  if (m) return { r: +m[1], g: +m[2], b: +m[3], a: m[4] === undefined ? 1 : +m[4] };
  return null;
}
const over = (fg, bg) => ({ r: fg.r * fg.a + bg.r * (1 - fg.a), g: fg.g * fg.a + bg.g * (1 - fg.a), b: fg.b * fg.a + bg.b * (1 - fg.a), a: 1 });
const lin = (c) => { c /= 255; return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4); };
const lum = (c) => 0.2126 * lin(c.r) + 0.7152 * lin(c.g) + 0.0722 * lin(c.b);
const ratio = (fg, bg) => { const a = over(fg, bg); const L1 = lum(a), L2 = lum(bg); const hi = Math.max(L1, L2), lo = Math.min(L1, L2); return (hi + 0.05) / (lo + 0.05); };

let failures = 0;
const pairs = [
  ["text",  "bg",      4.5, "正文"],
  ["text2", "bg",      3.0, "次文"],
  ["text3", "bg",      0,   "提示(仅报告)"],
  ["accent","bg",      3.0, "强调/图标"],
  ["text",  "surface", 4.5, "卡面正文"],
];
console.log("主题        对         比值   门槛  判定  用途");
console.log("─".repeat(58));
for (const id of src.$meta.themes) {
  const c = src.themes[id].color;
  for (const [fgK, bgK, min, use] of pairs) {
    const fg = parse(c[fgK]), bg = parse(c[bgK]);
    const r = ratio(fg, bg);
    const pass = min === 0 ? true : r >= min;
    if (!pass) failures++;
    const mark = min === 0 ? "·" : pass ? "✓" : "✗";
    console.log(`${id.padEnd(10)} ${(fgK + "/" + bgK).padEnd(12)} ${r.toFixed(2).padStart(5)}  ${String(min || "-").padStart(4)}  ${mark}    ${use}`);
  }
  console.log("");
}
console.log(failures === 0 ? "✅ 关键对比度全部达标（AA）" : `⚠️  ${failures} 项未达标 —— 见 A11Y.md 的最低使用规则`);
process.exit(failures === 0 ? 0 : 1);
