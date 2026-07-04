# 设计系统 ↔ AppKit 视觉保真方案（CSS→AppKit 对齐）

日期：2026-07-04
背景与根因：见 `2026-07-04-visual-fidelity-retrospective.md`

## 问题定义

设计系统 SSOT 是 Web 形态（`tokens.json` + `*.css` + HTML showcase），生产实现是 AppKit（macOS）与 UIKit（iOS）。两者**渲染模型根本不同，无法共享渲染**。核心问题：如何让「CSS 参照实现」与「AppKit 生产实现」在视觉上持续一致，且偏差能被机器发现、被人拿着 mockup 复核。

## 现状（可复用的成功范式）

token 层已经是成熟的多目标 codegen：

```
tokens/tokens.json  (SSOT)
   └─ tools/build.mjs ─┬─ generated/tokens.css        (showcase / Web)
                       ├─ generated/Theme.swift        (AppKit 契约)
                       ├─ generated/DesignTokens.ts    (Web / RN)
                       ├─ Sources/AgentDeck/DesignTokens.swift   (macOS，禁止手改)
                       └─ ios/AgentDeckMobile/DesignTokens.swift (iOS，禁止手改)
```

颜色/间距/圆角/字体因此机器强制一致——这是唯一没出偏差的层。**结论：把同一个「SSOT → codegen → 多端 + 校验」范式从 token 扩展到组件。**

## 核心原则

CSS 与 AppKit 不能共享渲染，所以：
1. 在两者**之上**共享一个结构化 SSOT（token 已做，组件规格新增）；
2. 加一道**比较两边渲染**的门禁（结构断言 + 图像快照）；
3. 给人一个**并排**看 mockup 与实现的复核面。

明确**不做**「把 CSS 编译成 AppKit」：CSS 子集布局引擎巨大、脆弱，自己也会漂移。

## 三种候选方案与取舍

### 方案 A：组件规格 SSOT → codegen（结构化，非 CSS）
把每个组件的**稳定视觉骨架**写成结构化 JSON（token 引用，非像素）：容器样式、包含哪些命名元素、各元素的 token 颜色/字体/关键内边距、以及**禁止出现**的元素。codegen 同时产出 showcase CSS 和一份 Swift `ComponentSpecs`，AppKit 视图消费它并被测试断言。
- 优点：组件构成变成机器可检。恰好能拦住我们踩的坑——「用户气泡多了 You 标签/边条」「环境面板是错的骨架」。
- 代价：富交互组件（流式、折叠、审批）无法完整数据化。**对策：规格只覆盖稳定视觉骨架，不覆盖行为。**

### 方案 B：视觉回归（参照图像 diff）
不共享源码，把渲染结果当契约：截 showcase 组件的参照图，再截 AppKit 同组件，做感知 diff。
- 优点：任何偏差（结构/颜色/间距）都能抓。
- 代价：浏览器与 AppKit 字体渲染不同，**像素级对 showcase 不可行**；须转为「AppKit vs 已提交的 AppKit 参照」自参照 diff + 容差，或改比对布局度量而非像素。

### 方案 C：度量/结构断言（非像素）
把每个组件的关键可测不变量写成断言（圆角=token、内边距=10/14、无 You 标签、envpanel 行序=[Changes 大数字, Git, 分支, 提交]、文字色=指定 token），遍历视图树断言。
- 优点：渲染器无关、稳、恰好抓我们踩的结构/样式坑、成本低。
- 代价：抓不到「一张图才看得出」的微妙间距/视觉重量。

## 推荐：A + C + B-lite 的混合栈

分层组合，各取所长：

1. **token codegen（已完成）** — 保留。
2. **组件规格 SSOT（方案 A）** — `tokens.json` 增加 `components` 段或新增 `components.json`，codegen 出 showcase CSS + `Sources/AgentDeck/generated/ComponentSpecs.swift`。只覆盖稳定视觉骨架。
3. **AppKit 组件画廊（`--gallery` 模式）** — 复用本次预览台基础设施，用固定 fixture 隔离渲染每个设计系统组件；既是结构断言的被测对象，也是人工 QA 面（AppKit 版 showcase）。
4. **结构快照测试（方案 C，主门禁）** — 遍历画廊每个组件视图树，断言其匹配 `ComponentSpecs`（元素齐全/无禁止元素/token 颜色/圆角/关键内边距）。渲染器无关、稳。**这是能拦住「You 标签 + 橙边条」「envpanel 错骨架」的那道门。**
5. **图像快照（方案 B-lite，自参照）** — 提交画廊组件的参照 PNG，CI 感知 diff，且在**刁钻宽度**（极小 + 真实）都渲染。抓布局回归（巨型气泡）和间距漂移。对比对象是已提交的 AppKit 参照，不是浏览器，故稳定。
6. **并排复核页** — 把 showcase HTML 截图与画廊 AppKit 截图并排生成一张对照物，让审查者/人第一次「手里同时有 mockup 和实现」，补上「审查者从没拿过 mockup」的缺口。

## 分阶段整改计划

- **Phase 0（低成本、与大方向无关，先做）**
  - 把 `RenderSnapshotTests` 变成真快照：提交参照 PNG + 加 diff 断言；会话流在**极小宽度 + 真实宽度**都渲染（覆盖巨型气泡这类布局 bug）。
  - 加 `--gallery` 模式（复用预览台基础设施）。
- **Phase 1（需确认方案后做）**
  - `components.json` 覆盖首批组件（用户气泡、envpanel、composer、shell/diff/reasoning cell），codegen `ComponentSpecs.swift`。
  - 对画廊写结构断言（方案 C）。
- **Phase 2**
  - 并排复核页；接入 `scripts/verify-agent-docs.sh` / CI；在 AGENTS.md 写死工作流：「每次 UI 改动 = 改规格 → 重生成 → 画廊 diff → 并排复核」。
- **Phase 3（可选）**
  - 拿被强制的规格回头对齐剩余组件缺口（diff 的 +64 -12 计数、reasoning 内联、状态蓝色圆点、气泡底色可见度等）。

## 错误处理与可观测性

- codegen 生成物一律「禁止手改」头注释，改 SSOT 后重生成；CI 跑一次 `build.mjs` 后 `git diff --exit-code` 校验生成物未漂移（沿用 token 现有守法）。
- 结构断言失败时报「哪个组件、哪个元素、期望 token vs 实际」，直接可定位。
- 图像 diff 失败时输出三联图（参照/当前/差异）到工件目录。

## 验收标准

- 首批组件的结构断言能拦住「新增禁止元素 / 换错骨架 / token 用错」——用本次已修的用户气泡/环境面板做回归基线。
- 巨型气泡类布局 bug 能被极小宽度渲染的快照 diff 抓到。
- 一次 `swift test` + 一次 `node tools/build.mjs && git diff --exit-code` 即覆盖「视觉保真」门禁。

## 待决策（开始 Phase 1 前需确认）

组件规格的表达形态：并入 `tokens.json` 的 `components` 段，还是独立 `components.json`？覆盖首批哪几个组件？结构断言用手写还是全部由 codegen 产出？
