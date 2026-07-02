# AgentDeck 设计系统 · 组件契约（COMPONENTS）

每个组件的**契约**：变体 / 状态 / 所用 token / 无障碍 / do·don't。
实现（Web CSS 类见 `system.css`；AppKit 按 `generated/Theme.swift` 落地）**必须**符合本契约。
通用约束见 `ENGINEERING.md`：只读 token/开关、禁硬编码色、禁主题分支。

图例：状态默认都含 `default / hover / active / disabled / focus-visible`（除非注明 N/A）。

---

## 原子

### Button · `.btn`
- **变体**：`primary`(--accent) · `secondary`(--surface-2/--border) · `ghost` · `text`(--accent) · `approve`(--success) · `danger`(--danger)
- **状态**：hover 提亮/变底；active `translateY(.5px) scale(.98)`；disabled `opacity .4` 且不可点；focus-visible accent 环
- **Token**：`--accent --success --danger --surface-2 --border --text-on-accent --radius-sm`
- **无障碍**：命中 ≥44pt（高度不足用内边距补）；图标须配文字或 `aria-label`
- **Don't**：不硬编码色；批准/拒绝不得只用颜色区分（须有图标 + 文案）

### IconButton · `.iconbtn`（含 `--send`）
- 28×28 默认；`--send` 圆形主操作。命中区须 ≥44pt（视觉可小，热区放大）。必带 `aria-label`。

### Tag / Badge · `.tag`
- **变体**：`perm`(--warn) · `plan`(--info) · `effort` · `queued`(--accent) · `vendor`
- 语义色承载含义时须同时有**文案**（色盲友好）。Token：对应语义色 + `--radius-pill`。

### Status dot · `.sdot` ＋ Ring · `.ring`
- **状态语义（固定，跨主题不变）**：`run`=运行(--running,脉冲) · `wait`=待审批(--warn) · `fail`=失败(--danger) · `done`=完成(--success) · `idle`=空闲(--text-3)
- 形状由开关 `--k-status-radius` 决定（点/方块）。**含义永不随主题变**，只变渲染。
- Ring=加载态；`prefers-reduced-motion` 下停转/停脉冲。

---

## 表单与控件

### Toggle · `.m-toggle`
- 状态：on(--success)/off(--border-strong)；滑块白色（允许硬编码 #fff）。须可键盘切换 + `role=switch aria-checked`。
### Segmented · `.seg` / Chip · `.chip`
- 单选段 / 过滤芯片；选中态 `--accent-weak`+`--accent`。`aria-pressed`。
### Field · `.field`
- 输入/搜索；focus-within accent 环。占位用 `--text-3`。真实输入须有 label。
### Avatar · `.avatar`（`--sm`/`--lg`）
- 圆形字母底色 `--info`，文字白。装饰性，须配可读名称。
### Meter · `.meter` / Heatmap · `.heatmap`
- 进度/用量。热力图 5 级由 `--accent` 混合生成（`.hm-1..4`）；**须配图例**（少→多）与可点击进详情；不得只用颜色传达数值——提供数字或 aria。

---

## 复合

### Composer · `.composer`
- 结构：输入区 + 工具栏（+ / 权限 tag / effort / mic / 发送）。形态由 `--k-composer-*`（card/cli/editorial）。
- **约束**：会话页不显式标注"监控中"——未发送即监控态由上下文体现；focus-within 高亮。
### Approval card · `.approval`
- 槽：head(图标+标题+来源) / body(命令或 diff) / foot(权限 tag + 拒绝 + 批准)。**可内联进会话流**就地选择。
- 高风险操作**必须**展示：将执行的命令/改动 + 权限范围 + 拒绝/批准双按钮（不可默认批准）。
### Environment panel · `.envpanel`
- 分节：变更(±delta,tabular-nums) / Git(分支·提交) / 来源(文件行)。度量数字须表格对齐。
### Connector card · `.connector`
- Agent 连接卡：真实 agent 图标 + 名称 + 状态点。hover 抬升。

## 列表与导航

### 会话行 · `.thread` / `.m-thread`
- 槽：状态点 + 标题(桌面侧栏单行省略 / 移动双行) + 元信息(agent 图标 + 状态 + 时间)。选中态 accent bar。
### 分组头 · `.m-grp`（移动会话列表）
- **项目名为主体** + 机器/relay 右侧小字，**不显示会话数**。可折叠 chevron。
### 设置行 · `.m-set__row` + 图标块 `.ico`
- 图标块(语义色底) + 标签 + 值/开关 + chevron。分组标题用 `.eyebrow`（随主题 `[ ]`/small-caps）。
### Tab bar · `.m-tabs`（组件库保留；当前移动 IA 用列表↔详情，未采用）
- 底部导航；`--p-safe-bottom`/`--p-nav-blur` 由平台轴驱动。激活态 `--accent`。
### Menu · `.menu`
- 右键/长按上下文菜单；危险项 `.danger`(--danger)。键盘可达。

## 覆盖层与反馈

### Toast · `.toast`
- 应用内通知；语义色图标块 + 文案。不承载唯一操作入口。
### Dialog · `.dialog`
- 确认对话框；标题 + 说明 + 动作条（主/危险）。焦点须落在对话框、Esc 关闭。
### Bottom Sheet · `.sheet`
- 移动底部弹层；grip + 标题 + 列表。可下滑关闭。
### Empty state · `.empty`
- 图标 + 标题 + 说明 + 主行动。首次连接/无历史用。

## 内容展示

### Message bubble · `.turn__user` / `.m-user`
- 用户气泡；右对齐(移动)。
### Command block · `.cmd` / `.m-cmd`
- `$` 提示符 + 命令 + 输出。等宽。构造由 `--k-cmd-*`。
### Diff / 文件行 · `.difftag` / `.env-file`
- `+新增`(--success)/`−删除`(--danger) 须同时有符号与数字（非仅色）。
### kbd · `.kbd` / Section header · `.eyebrow`
- 键位芯片 / 分组标题（随主题词缀与大小写）。

---

## 状态矩阵（最低要求）

任一交互组件交付前须覆盖：`default · hover · active/pressed · disabled · focus-visible`；
异步/数据组件另需：`loading(Ring/skeleton) · empty(Empty) · error(--danger + 文案) · success`。
缺失状态即视为组件未完成。
