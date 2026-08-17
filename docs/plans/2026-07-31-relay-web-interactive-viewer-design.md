# Relay Web 交互式会话查看器设计

状态：Approved for implementation（2026-07-31）

## 目标

在现有 Relay Web Test Companion 内增加一个显式的本机交互模式，让测试人员能够亲手启动 W2 业务链，并在页面中查看经真实临时 TLS Relay、真实 daemon、Relay v2、Runtime v5 与 E2EE v1 返回的会话目录和会话内容。

本模式只验证 Web 消费真实 Relay payload 的能力。当前 fixed-topology host 使用 synthetic vendor adapter；页面必须明确显示该数据源，禁止把结果描述为用户本机 Codex/Claude Code 历史或 production Relay 完成证据。

## 非目标

- 不增加第二套协议、SessionSource、密钥解析或 TypeScript wire codec。
- 不通过本地 HTTP/CLI 旁路读取用户历史来冒充 Relay。
- 不修改 Relay 持久化 schema、daemon Runtime schema 或 production composition。
- 不解决公网 WSS、production signing/SPKI、物理设备、第二台 Mac 或真实 vendor；这些仍属于 W4。
- 不把业务正文写入 Relay DB、日志、localStorage、sessionStorage 或 IndexedDB。

## 设计

### 数据所有权

`agentdeck-web-core` 继续唯一负责 Relay/Runtime/E2EE 解码和准入。W2 business core 在完成既有校验后，额外生成只读 UI 投影：

- Catalog：中立 conversation id、agent kind、title、last active、archived。
- Conversation：按接收顺序保存 canonical `AgentItem`。
- Approval：只保存已经验证的 summary 和最终状态。

TypeScript 只渲染上述 typed JSON 投影，不读取 raw frame、TBS、key、counter 或 vendor identity。

### 交互生命周期

1. runner 创建临时 Relay、daemon host、邀请、隔离 Chrome profile 和页面服务。
2. Playwright 只把邀请放入当前页面内存，不写 URL、DOM、日志或 Web Storage。
3. 用户点击“读取 Relay 会话”，页面执行既有 W2 pairing + business flow。
4. 页面展示 machine preview、Catalog 条目和 Conversation 内容。
5. 用户点击“结束并清理”，浏览器上下文退出；runner 读回 host ledger、扫描 Relay 明文并删除全部临时资源。

### 模式隔离

现有 `--business` 自动门禁保持“业务明文不进入 DOM/输出”。新增 `--interactive` 才允许正文存在于当前页面 DOM；它必须额外证明正文没有进入 Web Storage/IndexedDB、browser output 或 Relay persistence。两种模式使用独立测试入口和 terminal JSON，不改变既有 W0–W3 完成语义。

## 闭环验收

- 页面明确显示 `fixed-topology synthetic`，不得显示为 production/真实用户历史。
- 页面从后端读到恰好一个 Catalog 条目并显示其标题。
- 页面显示实际收到的 user message、assistant message 与 approval summary，不使用前端硬编码内容生成 DOM。
- host 读回 command/completed `1/1`、approval total/applied `1/1`。
- Relay DB/WAL/SHM 与 browser output 不含业务正文。
- localStorage、sessionStorage、IndexedDB 均不含业务正文。
- PairInvite 不进入 URL、DOM 或输出。
- 退出后 browser、host PID/root、invite、UDS、Playwright artifacts 与 `/tmp/ar4.*` 全部 absent。
- 既有 `--business` 与 W0 contract 门禁继续 PASS。

## 外部阻塞

个人真实 Codex/Claude Code 历史经 production Relay 展示需要 release-signed daemon/helper、可编译的 production remote identity、持久配对和真实 vendor 证据。当前开发构建返回 `remote.persistent.unsupported`，且 canonical production daemon socket 不存在，因此该目标保持 W4 `BLOCKED`。
