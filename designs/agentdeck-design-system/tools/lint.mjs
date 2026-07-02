#!/usr/bin/env node
/* ============================================================
   AgentDeck 设计系统 · 约束门禁（CI 可接）
   校验：
     1) SSOT 一致 —— 手写 tokens.css ⊆ 生成 generated/tokens.css（设计=数据源）
     2) 组件层禁硬编码颜色 —— system.css 内非 token 的 hex 需在允许清单
     3) 开关默认值齐全 —— 所有 var(--k- / --p-) 使用都有 :root 默认
   失败退出码 1，供 CI 拦截。用法：node tools/lint.mjs
   ============================================================ */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const read = (p) => fs.readFileSync(path.join(root, p), "utf8");
let failures = 0;
const fail = (msg) => { failures++; console.log("  ✗ " + msg); };
const okline = (msg) => console.log("  ✓ " + msg);

/* ---- 1) SSOT 一致 ---- */
console.log("\n[1] SSOT 一致（tokens.css ⊆ generated/tokens.css）");
function decls(css) {
  const m = new Set();
  for (const x of css.matchAll(/--([a-z0-9-]+)\s*:\s*([^;]+);/g)) {
    m.add(x[1] + "|" + x[2].replace(/["']/g, "").replace(/\s+/g, " ").trim()); // 忽略字体引号差异
  }
  return m;
}
try {
  const hand = decls(read("tokens.css"));
  const gen = decls(read("generated/tokens.css"));
  const missing = [...hand].filter((d) => !gen.has(d));
  if (missing.length === 0) okline(`手写 tokens.css 全部 ${hand.size} 条声明均由 SSOT 生成，值一致`);
  else missing.slice(0, 12).forEach((d) => fail("生成物缺失/不一致: --" + d.replace("|", ": ")));
} catch (e) { fail("读取失败（先跑 node tools/build.mjs）: " + e.message); }

/* ---- 2) 组件层禁硬编码颜色 ---- */
console.log("\n[2] 组件层禁硬编码颜色（system.css）");
// 设备 chrome / 通用装饰允许清单（非主题表面色）
const ALLOW_HEX = new Set([
  "#fff", "#ffffff", "#000", "#000000",
  "#ff5f57", "#febc2e", "#28c840",           // macOS 交通灯
  "#1a1a1c", "#d8cfbd", "#b9ad96",           // 手机边框 / 暖色边框
  "#04120a",                                  // approve 按钮暗色文字
]);
{
  const css = read("system.css");
  const offenders = new Set();
  css.split("\n").forEach((line, i) => {
    if (/^\s*\/?\*/.test(line)) return;
    if (/\.sw-[a-z]+ \.dot/.test(line)) return; // 主题切换器色板：跨主题固定预览色，展示 chrome
    for (const m of line.matchAll(/#[0-9a-fA-F]{3,8}\b/g)) {
      if (!ALLOW_HEX.has(m[0].toLowerCase())) offenders.add(`L${i + 1}: ${m[0]}  «${line.trim().slice(0, 60)}»`);
    }
  });
  if (offenders.size === 0) okline("无越权硬编码 hex（仅允许设备 chrome + 切换器色板）");
  else [...offenders].slice(0, 15).forEach((o) => fail("硬编码颜色应改用 token: " + o));
}

/* ---- 3) 开关默认值齐全 ---- */
console.log("\n[3] 结构 / 平台开关默认值齐全（--k-* / --p-*）");
{
  const iface = read("interface.css");
  // 默认值定义在 interface.css 的 :root 及 :root,[data-platform=…] 组合选择器中：扫全文的定义即可
  const defined = new Set([...iface.matchAll(/--((?:k|p)-[a-z-]+)\s*:/g)].map((m) => m[1]));
  const files = ["interface.css", "system.css", "languages.css"].map(read).join("\n");
  const used = new Set([...files.matchAll(/var\(\s*--((?:k|p)-[a-z-]+)/g)].map((m) => m[1]));
  const undefined_ = [...used].filter((u) => !defined.has(u));
  if (undefined_.length === 0) okline(`所有 ${used.size} 个被使用的开关都有 :root 默认（空值零副作用）`);
  else undefined_.forEach((u) => fail("开关无默认值: --" + u));
}

/* ---- 汇总 ---- */
console.log("\n" + (failures === 0 ? "✅ 全部通过 — 设计系统约束成立" : `❌ ${failures} 项失败 — 违反设计系统约束`));
process.exit(failures === 0 ? 0 : 1);
