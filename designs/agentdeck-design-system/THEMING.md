# AgentDeck 主题接口契约（THEMING）

本文件是设计系统「多主题切换」的契约：**哪些统一、哪些切换、切换通过什么接口**。目标是让多套设计语言长期共存、可维护地切换，并且**加一套新主题只需填值**，而不是再抄一遍覆盖规则。

---

## 1. 三层模型与接缝

| 层 | 内容 | 是否切换 | 载体 |
|---|---|---|---|
| **L1 语义 / 契约层** | 信息架构、界面清单、区域拓扑（侧栏 + 内容 + composer + 环境面板 + 轮次导航）、组件契约与状态、内容文案、交互逻辑、**状态语义**（running / awaiting / failed / done 的含义）、可访问性、≥44pt 触控、焦点顺序、reduced-motion 回退 | **统一，永不切换** | 固定（HTML 结构 + `system.css` 基座） |
| **L2 Token 层（皮肤）** | 颜色、字体、圆角、间距刻度、阴影、动效 | 切换（声明式值） | `tokens.css` |
| **L3 结构 / 语言层** | 词缀装饰、图标策略、状态形状、表面质感、composer 形态、大小写、密度、纹理、可选插槽 | 切换（**可枚举开关**） | `interface.css`（引擎）+ `languages.css`（赋值） |

**一句话接缝：** 「是什么、能做什么、状态含义」永远统一；「长什么样、用什么母题表达」才切换。
例：状态的*语义*（等待审批）统一，状态的*渲染*（橙点 / 橙方块 / 橙 pill）交给 L3 开关。

---

## 2. 文件职责

```
tokens.css      皮肤：每套主题声明颜色/字体/圆角/阴影/动效（纯值）
system.css      基座：与主题无关的组件与布局，只消费 token
interface.css   引擎：定义 L3 结构开关(--k-*)默认值 + 组件如何读开关（通用，与主题无关）
languages.css   赋值：每套主题只对开关赋值 + 少量插槽组件样式
showcase.js     运行时：主题切换（?t= 参数 / localStorage）、导航、图标
```

依赖顺序（`<link>`）：`tokens → system → interface → languages`。

---

## 3. 结构开关清单（L3 接口，可枚举）

组件在 `interface.css` 中统一消费这些开关；主题在 `languages.css` 中赋值。**这是有限且封闭的菜单**。

### 词缀 Affix（内容型；间距内嵌进字符串，空值零副作用）
| 开关 | 作用 | 默认 | 示例值（Terminal） |
|---|---|---|---|
| `--k-label-open` / `--k-label-close` | 区块标签前后缀 | `""` | `"[ "` / `" ]"` |
| `--k-reason-prefix` | 推理行前缀 | `""` | `"# "` |
| `--k-user-prefix` | 用户气泡前缀 | `""` | `"> "` |
| `--k-title-prefix` | 会话标题前缀 | `""` | `"$ "` |
| `--k-project-prefix` / `--k-project-suffix` | 项目名前后缀 | `""` | `"▾ "` / `"/"` |
| `--k-act-prefix` | 侧栏快捷入口前缀 | `""` | `"› "` |
| `--k-thread-tree` | 线程树枝符 | `""` | `"├─ "` |

### 形状 / 大小写 / 纹理
| 开关 | 值域 | 默认 |
|---|---|---|
| `--k-status-radius` | `50%`（圆点）\| `1px`（方块） | `50%` |
| `--k-chevron-display` | `inline-block` \| `none` | `inline-block` |
| `--k-avatar-radius` | 长度 | `50%` |
| `--k-stream-texture` | `none` \| `var(--grid-lines)` | `none` |
| `--k-icon-gutter-display` | `flex`（显示行首图标）\| `none`（隐藏，改用文本前缀/规线） | `flex` |
| `--k-label-variant` | `normal` \| `small-caps` | `normal` |

### 状态芯片（把 dot+label 装进 pill）
| 开关 | 默认 | 示例（Linear） |
|---|---|---|
| `--k-status-chip-bg` | `transparent` | `var(--surface-2)` |
| `--k-status-chip-border` | `0 solid transparent` | `1px solid var(--border)` |
| `--k-status-chip-pad` | `0` | `3px 9px 3px 8px` |

### 推理「旁注」模式
| 开关 | 默认 | 示例（Warm） |
|---|---|---|
| `--k-reason-font` | `var(--font-ui)` | `var(--font-display)` |
| `--k-reason-italic` | `normal` | `italic` |
| `--k-reason-size` | `13px` | `15px` |
| `--k-reason-border` | `0 solid transparent` | `2px solid var(--border-strong)` |
| `--k-reason-pad` | `0` | `14px` |

### 命令块 / 标题 / Composer
| 开关 | 默认 | 说明 |
|---|---|---|
| `--k-cmd-border` / `--k-cmd-border-left` / `--k-cmd-bg` | `1px solid var(--border)` / 同 / `var(--surface-inset)` | 命令块构造（Terminal 左描边 accent；Warm 代码图） |
| `--k-title-font` | `var(--font-display)` | 标题字体（Warm 衬线） |
| `--k-composer-bg` | `var(--surface)` | Composer 背景 |
| `--k-composer-prefix` | `""` | 输入前提示符（Terminal `"> "`） |
| `--k-composer-caret` | `""` | 行尾块光标（Terminal `"▊"`，自动闪烁） |
| `--k-composer-slash` | `""` | 占位符后的 slash 提示（Linear `"   /  唤起命令"`） |

---

## 4. 插槽机制 Slots（少数天生需要 DOM 的结构）

有些结构无法只靠一个开关表达（需要真实 DOM 或富样式），用「命名插槽」：页面里写好带 `l-<theme>` 类的元素，默认隐藏，仅在对应主题出现。

```html
<!-- 例：Linear 顶部命令栏，仅 linear 主题可见 -->
<div class="wb-cmdbar l-linear"> … ⌘K … 过滤芯片 … </div>
```

```css
/* interface.css 的插槽开关机制 */
.l-term, .l-linear, .l-warm { display: none !important; }
[data-theme="linear"] .l-linear { display: flex !important; }
```

当前已用插槽：`commandBar`（Linear）、`⌘↵` 键位芯片（Linear）、块光标（由 `--k-composer-caret` 开关驱动，无需 DOM）、区块标签发丝规线（Warm，覆盖通用 `::after`）。

---

## 5. 加一套新主题（只需填值）

> **Notion 风** 与 **macOS 原生风** 已按下述方法内置（见 `tokens.css` / `languages.css` 的 `[data-theme="notion"]` / `[data-theme="macos"]`）。二者都**未覆盖任何 `--k-*` 开关**，纯靠皮肤区分——即本节所述「只填值」的真实实证。

以 **Notion 风**（亮色、几何无衬线、克制）为例：

```css
/* tokens.css：声明皮肤 */
[data-theme="notion"] {
  color-scheme: light;
  --bg:#ffffff; --surface:#f7f6f3; --text:#37352f; --accent:#2383e2; /* … 其余同结构 … */
  --radius-md:6px; --font-display:"…"; /* … */
}
/* languages.css：从开关菜单里选（这套走极简，几乎全用默认，仅少量点缀）*/
[data-theme="notion"] {
  --k-status-radius: 3px;        /* 圆角小方块 */
  --k-label-variant: normal;
}
```

就这样——**不改任何组件、不写一条 `[data-theme] .someComponent` 覆盖**。想要它拥有某种清单外的结构母题时，先问：该结构是否值得进契约成为一个新开关？是 → 在 `interface.css` 新增一个 `--k-*` 及其通用消费规则（一次性，全主题受益）；否 → 它可能不该是一套新主题。

---

## 6. 治理原则

1. **开关清单封闭**：新增开关是有意的契约变更，需同步更新本文件。
2. **禁止组件里写 `if theme ==`**：组件只读开关，不认识具体主题名。
3. **空值零副作用**：所有开关默认值必须在「未启用」时不产生视觉/布局副作用（内容型用 `""`，边框型用 `0 solid transparent`）。
4. **语义不进 L3**：状态的含义、组件能力、交互永远在 L1；L3 只管表达。

---

## 7. 映射到 AppKit（原生落地）

同一契约可平移到 Swift，与现有 `CapabilityRouter`「禁止 vendor 分支」同philosophy——视图**读 theme 开关**，不写 `if theme == .terminal`：

```swift
struct Theme {
    // L2 皮肤
    let bg, surface, text, accent: NSColor
    let radiusMd: CGFloat
    let fontDisplay, fontMono: NSFont
    // L3 结构开关（枚举，对应 --k-*）
    let statusShape: StatusShape        // .dot | .square | .pill
    let surfaceMode: SurfaceMode        // .float | .flat | .hairline | .tuiBox
    let composerForm: ComposerForm      // .card | .cli | .editorial
    let iconMode: IconMode              // .line | .glyph | .minimal
    let affixes: Affixes                // title/reason/user/project 前后缀
}
```

视图从 `Theme` 取开关渲染；新增主题 = 新增一个 `Theme` 值 + 可选插槽视图，零分支。

**运行时范围**（待产品定）：全局唯一 / 跟随系统明暗（Warm ↔ Codex 自动）/ 每窗口或每会话可不同——建议至少支持「跟随系统明暗」。

---

## 8. 平台适配（iOS / Android）

策略：**统一品牌化 + 薄平台适配**。把「平台」做成与 `data-theme` 正交的第二根轴 `data-platform="ios|android"`——内容组件两端完全一致，平台只驱动「设备 chrome / 安全区 / 导航停靠」这几项。

**两端完全一致（不随平台变）**：所有内容组件（按钮 / 标签 / 状态 / 卡片 / 列表 / 设置行 / 开关 / 气泡 / tab 内容）、信息架构、交互逻辑、文案、全部主题与结构母题。品牌一致性优先于平台原生细节。

**仅平台适配（薄层，可枚举开关）**：

| 平台开关 | iOS | Android | 作用 |
|---|---|---|---|
| `--p-safe-top` | `46px` | `30px` | 状态栏 / 安全区高度（刘海 ↔ 打孔） |
| `--p-safe-bottom` | `22px` | `12px` | 底部导航余量（home indicator ↔ 手势条） |
| `--p-nav-blur` | `12px` | `0` | 底部导航材质（半透模糊 ↔ Material 实底） |
| `--p-nav-solid` | `transparent` | `var(--surface)` | 导航底色 |

此外约定（不都用 CSS 表达）：返回手势（iOS 左滑 ↔ Android 系统返回）、默认字体栈（SF ↔ Roboto，由 `--font-ui` 切换）、触感与滚动回弹随平台。

**落地**：`data-platform` 与 `data-theme` 正交，任意主题 × 任意平台自由组合；内容组件零改动。设备框（iPhone 刘海 / Android 打孔）与状态栏、底部导航消费上述开关。映射到原生：AppKit 走 iOS 值，未来 Android(Compose) 端复用同一 `Theme` + 一组 `Platform` 值。

> 规范已就位；Android 设备框与专属屏为后续工作，不影响现有 iOS 展示。
