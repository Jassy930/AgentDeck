# AgentDeck 设计系统

面向 Coding Agent 工作台的**跨桌面/手机端**可视化设计系统展示页。以 Codex Desktop 视觉范式为主基调，并额外提供三种可一键切换的设计语言。

## 打开方式

需通过 HTTP 预览（`<link>`/`<script>` 依赖外部文件）：

```bash
python3 -m http.server 4311 --directory designs
# 打开 http://localhost:4311/agentdeck-design-system/AgentDeck%20Design%20System.html
```

支持 `?t=<主题>` 参数直达指定主题，例如 `?t=terminal`、`?t=warm`。

## 六种设计语言（一键切换）

前四套是**语言级差异**（结构/构造/图标/母题各不相同）；后两套刻意**只填皮肤、结构全默认**，用来示范接口——加一套新主题可以零组件改动、零结构改动。

| 主题 | 定位 | 皮肤（token） | 结构母题（language） |
|---|---|---|---|
| **① Codex Desktop** | 主基调 | 近黑 `#131313`、暖橙 `#FF7D2E`、18pt 大圆角、SF 字体 | 柔和圆角、浮起卡片、安静克制 |
| **② Terminal** | 开发者终端 | 纯黑、JetBrains Mono、磷光绿、锐角 | `$` 标题栏、`▾项目/` + `├─` 树形侧栏、`#` 注释式推理、`>` 命令行 composer + 块光标、方形状态点、网格背景、`[ 括号 ]` 标签 |
| **③ Linear** | 精密产品感 | 蓝黑、靛紫、8pt 圆角、微渐变 | 顶部命令栏 + `⌘K`、`全部/运行中/待审批` 过滤芯片、`/唤起命令` + `⌘↵` 键位提示、pill 状态芯片、高光边 |
| **④ Warm** | 暖色编辑感（亮色） | 暖纸白、锈红、Newsreader 衬线 | 衬线标题、italic 左规线「旁注」式推理、带题注的代码图、`— small-caps —` 发丝规线标签、文本式按钮 |
| **⑤ Notion** | 极简文档感（亮色） | 纯白、Notion 蓝 `#2383e2`、暖灰发丝边、极小圆角 | 结构全默认（示范「只填皮肤」） |
| **⑥ macOS** | 系统原生（亮色 Aqua） | 系统蓝 `#007aff`、SF、系统灰、标准控件圆角、柔和系统阴影 | 结构全默认（原生感来自色/字/圆角/材质） |

> 前四套的结构母题施加在**共享组件类**上并按 `[data-theme]` 作用域覆盖，故自动传导到桌面工作台、移动端与组件库。⑤⑥ 未覆盖任何 `--k-*` 开关，仅靠 `tokens.css` 皮肤区分——正是「加新主题 = 填值」的实证。

## 架构（皮肤 + 结构接口 分层）

- **`tokens.css`** — L2 皮肤层。四套主题通过 `[data-theme]` 声明颜色/字体/圆角/阴影/动效（纯值）；中西文行高同样来自全局 token。
- **`system.css`** — L1 基座：与主题无关的组件与布局，只消费 Token。
- **`interface.css`** — L3 结构接口**引擎**：定义可枚举结构开关（`--k-*`）默认值 + 组件如何读开关。与主题无关。
- **`languages.css`** — L3 结构接口**赋值**：每套主题只对开关赋值一次 + 少量插槽组件样式。
- **`AgentDeck Design System.html`** — 展示页主体，含真实 Codex / Claude Code 图标 SVG 精灵。
- **`showcase.js`** — 主题切换（`?t=` 参数 / localStorage）、侧栏滚动高亮、Lucide 初始化。
- **`assets/`** — 产品自带的真实 Agent 图标（`codex.svg`、`claudecode.svg`）。
- **[`THEMING.md`](THEMING.md)** — **主题接口契约**：统一 vs 切换的接缝、结构开关清单、插槽机制、加新主题步骤、映射到 AppKit，以及 **iOS/Android 平台适配契约**（`data-platform` 轴，统一品牌化 + 薄平台层）。

> 依赖顺序：`tokens → system → interface → languages`。组件从不写 `if theme ==`，只读开关；加一套新主题 = 填 token + 从开关菜单选值，不改组件。详见 `THEMING.md`。

## 工程化 / 消费（能指导、能限制）

设计系统不止"看"，还能被工程直接吃、被 CI 拦。

```bash
bun run build   # tokens/tokens.json(SSOT) → generated/tokens.css · Theme.swift · DesignTokens.ts
bun run lint    # 门禁：SSOT 一致 · 组件禁硬编码色 · 开关默认值齐全
bun run a11y    # 六套主题关键对比度 ≥ AA
bun run check   # 以上一步到位（可接 CI）
```

- **[`tokens/tokens.json`](tokens/tokens.json)** — **单一数据源（SSOT）**：6 套主题的色板/圆角/字体/阴影/结构枚举，以及全局字号、行高与平台开关。改这里，其余生成。
- **`generated/`** — 生成物（**禁手改**）：`Theme.swift`（AppKit：`Palette`/`Radii`/`Typography`/`Structure`/`Platform`，视图读契约、禁主题分支）、`tokens.css`、`DesignTokens.ts`；macOS 生产端的 `Sources/AgentDeck/DesignTokens.swift` 也由同一生成器写入字号与行高倍率。
- **`tools/`** — `build.mjs`（生成器）· `lint.mjs`（约束门禁）· `a11y.mjs`（对比度核验）。
- **[`ENGINEERING.md`](ENGINEERING.md)** — **工程约束**（MUST/MUST NOT、分层、工作流、AppKit 落地、扩展手册）。
- **[`COMPONENTS.md`](COMPONENTS.md)** — 组件契约（变体/状态/token/无障碍/状态矩阵）。
- **[`A11Y.md`](A11Y.md)** — 无障碍结果与最低规则。

## 内容分区

1. **概览** — 品牌、四种设计语言导览、Token 层说明。
2. **基础规范** — 色板、字体、间距/圆角、层级、动效、图标。
3. **组件库** — 按钮 / 图标按钮、徽章标签（权限 / Plan Mode / effort / 队列）、运行状态点 + 加载环、只呈现已接通动作的 Composer；**表单控件**（开关 / 分段 / 芯片 / 输入 / 头像 / 用量条）；**导航与菜单**（Tab bar / 上下文菜单）；**覆盖层与反馈**（Toast / 对话框 / 底部弹层 / 空状态）；**卡片**（审批 / 连接器 / 环境面板）；**内容展示**（消息气泡 / 命令块 / Diff 行 / 设置行 / 图标块 / kbd）；列表行（历史线程 / 项目组）。
4. **桌面工作台** — 透明标题栏 + 216px 紧凑全高侧栏 + 共用内容轴的流式会话与悬浮 composer + 按数据折叠的环境面板 + 44px 轮次导航；真实尺寸 1280×820 可缩放预览；点击侧栏身份打开**设置窗口**（分类导航 + 身份/主机/Agent/… 内容面板）。
5. **移动端** — 以 iPhone 390×844pt 真机为基准；**三屏 · 列表↔详情导航**：会话列表（机器 + 项目平铺分组，会话经 relay 连接、标 relay 名）、会话页（未接管即监控、输入即介入且不显式标注状态；流内审批卡、去 tab、返回列表、最大化工作区）、我的（身份标识 / 主机管理 / GitHub 式用量热力图→详情）。触控目标 ≥ 44pt。**iOS 与 Android 两版**：同一套内容组件，仅设备 chrome 不同（刘海+home indicator ↔ punch-hole+手势条），由 `data-platform` 平台轴驱动。

## 排版基线

- 字号阶梯：`display-xl 34pt`、`display 24pt`、`title 16pt`、`body 14pt`、`callout 13pt`、`caption 11pt`、`mono 12.5pt`。
- 行高倍率：纯拉丁段落 `1.45`；包含中文、日文、韩文字符的段落（含中西混排）`1.72`。
- macOS 会话流：assistant 正文使用 `body`，reasoning 正文使用 `callout + text2`，命令与 diff 使用 `mono`；Markdown 正文与 reasoning 必须各自用同一 attributed string 完成渲染和行高测量。

## 说明与替代

- Agent 图标为产品自带真实资源；其余 UI 图标采用 **Lucide**（CDN）近似原生 SF Symbols 的线性观感。
- 字体：Space Grotesk / JetBrains Mono / Newsreader 走 Google Fonts CDN，中文回落到系统 PingFang / Songti / Noto。
- 展示页是**可视化规范**；工程消费走 **SSOT + 生成物 + 门禁**（见「工程化 / 消费」）。二者由 `tokens.json` 统一驱动，`lint` 保证不漂移。
- 尚未做成 baoyu compiler 的可 import 型 DS（`_ds_manifest.json` / bundle）；如需跨设计项目复用可再补。
