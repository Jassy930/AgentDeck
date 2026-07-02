# AgentDeck 设计系统 · 工程约束（ENGINEERING）

> 本文件是**具有约束力**的工程契约。凡消费本设计系统的代码（Web / AppKit / 其它），
> 都必须遵守下述规则；`tools/lint.mjs` + `tools/a11y.mjs` 是可接入 CI 的门禁。
> 违反约束 = 构建失败。

## 0. 一句话

**改设计走 `tokens/tokens.json`（单一数据源）→ 跑 `bun run build` 生成产物 → `bun run check` 过门禁。**
组件只读 token / 开关，绝不认识具体主题名，绝不硬编码颜色。

---

## 1. 分层（谁能改谁）

| 层 | 文件 | 谁维护 | 消费方 |
|---|---|---|---|
| **L0 单一数据源 SSOT** | `tokens/tokens.json` | 设计 + 工程共同 | 生成器 |
| **L1 生成物（禁手改）** | `generated/tokens.css`·`generated/Theme.swift`·`generated/DesignTokens.ts` | 生成器 | Web / AppKit / RN |
| **L2 皮肤（在用 CSS）** | `tokens.css` | 由 SSOT 镜像（lint 校验一致） | 组件 |
| **L3 结构引擎 + 平台轴** | `interface.css`（`--k-*` / `--p-*` 开关 + 消费规则 + 插槽） | 工程 | 组件 |
| **L3 主题赋值** | `languages.css`（每主题给开关赋值） | 设计 + 工程 | — |
| **L4 组件与布局** | `system.css` | 工程 | 界面 |
| **契约文档** | 本文件·`THEMING.md`·`COMPONENTS.md`·`A11Y.md` | — | 所有人 |

---

## 2. 硬性规则

### MUST（必须）
- **M1** 一切颜色/圆角/字体/间距/阴影，**只能引用 token**（Web：`var(--x)`；AppKit：`theme.color.x` / `theme.radius.x`）。
- **M2** 结构差异只能读**可枚举开关**（`--k-*` / Swift `theme.structure.*`）；平台差异只能读 `--p-*` / `Platform`。
- **M3** 新主题 = 在 `tokens.json` 增一套值 + 从开关菜单选值；跑 build。**不改任何组件**。
- **M4** 新开关（结构/平台）= 先进 `interface.css` 契约（定义默认 + 通用消费规则）并更新 `THEMING.md`，再赋值。
- **M5** 触控目标 ≥ **44pt**；可聚焦元素提供 `:focus-visible`；动画在 `prefers-reduced-motion` 下关停。
- **M6** 正文 `text/bg` 对比度 ≥ 4.5、`text2`/`accent` ≥ 3.0（`bun run a11y` 校验）。
- **M7** 改了 `tokens.json` 必须重跑 `bun run build` 并提交生成物；改了组件必须 `bun run lint` 通过。

### MUST NOT（禁止）
- **N1** ❌ 组件里**硬编码颜色**（hex/rgb 主题色）。例外仅：设备 chrome（交通灯/边框/打孔）、开关白色滑块、头像文字白 —— 见 `lint.mjs` 允许清单。
- **N2** ❌ 任何 `if theme == .terminal` / `if (theme === 'warm')` 式**主题分支**（与 `CapabilityRouter` 禁 vendor 分支同哲学）。视图只读 `theme.structure` 枚举。
- **N3** ❌ 手改 `generated/` 生成物或让 `tokens.css` 与 SSOT 漂移（lint 会拦）。
- **N4** ❌ 语义进 L3：状态含义/组件能力/交互属于 L4/产品，主题层只管"长什么样"。
- **N5** ❌ `text3`（提示级，对比度 < 4.5）承载必读信息；它只用于时间戳/次要提示。

---

## 3. 工作流与门禁

```bash
# 改 token / 主题 / 平台
vim tokens/tokens.json
bun run build          # → generated/tokens.css · Theme.swift · DesignTokens.ts
bun run check          # build + lint + a11y，一步过门禁

# CI（示例）
- run: bun run check   # 任一项失败即红
```

门禁三关（`tools/`）：
1. `lint.mjs` — ① SSOT 一致（`tokens.css` ⊆ 生成物）② 组件禁硬编码色 ③ 开关默认值齐全。
2. `a11y.mjs` — 六套主题关键对比度 ≥ AA。
3. （build 本身）— 生成器可跑通、产物新鲜。

---

## 4. AppKit 落地映射

生成物 `generated/Theme.swift` 已给出契约：

```swift
let t = Theme.codex                 // 六套之一（Theme.all）
view.layer?.backgroundColor = t.color.bg.cgColor
label.textColor = t.color.text
card.layer?.cornerRadius = t.radius.md
// 结构差异读枚举，禁 if theme ==
switch t.structure.statusShape { case .dot: …; case .square: …; case .pill: … }
// 平台
let p = Platform.ios                // Platform.all
topInset = p.safeTop
```

原则：**视图持有 `Theme` + `Platform`，从中取值**；切主题 = 换 `Theme` 值并重绘；**不写主题名分支**。这与你们 `CapabilityRouter`「禁 vendor 分支、按能力装配」是同一条路。

---

## 5. 扩展手册

- **加一套主题**：`tokens.json.themes.<id>` 填色板/圆角/字体/阴影 + `structure` 选枚举 → `bun run build` → 在 `showcase.js` 的 `THEMES` 与切换器登记（Web 展示可选）。零组件改动。
- **加一个结构开关**：`interface.css` 定义 `--k-x` 默认 + 通用消费规则 → 各主题在 `languages.css` 按需赋值 → 更新 `THEMING.md` 开关清单。
- **加一个平台**：`tokens.json.platform.<id>` 填安全区/导航参数 → build；设备框与 chrome 读 `--p-*`。
- **加一个组件**：只用 token/开关实现 → 在 `COMPONENTS.md` 补契约（props/状态/无障碍/token）→ `bun run lint`。

---

## 6. 现状与边界（诚实）

- ✅ 已工程化：SSOT + 生成器（CSS/Swift/TS）+ 三关门禁 + 无障碍核验 + 契约文档。
- 🚧 生成物是**骨架**：`Theme.swift` 覆盖色板/圆角/字体/结构枚举/平台；**阴影**目前保留在 CSS 层（Swift 侧未分解 `NSShadow`），**字体**只给族名栈（未映射具体 `NSFont`）—— 落地时补。
- 🚧 组件是 CSS 类 + 演示 HTML，非打包的 Swift/React 组件；`COMPONENTS.md` 给出契约，具体实现由各端按契约完成。
