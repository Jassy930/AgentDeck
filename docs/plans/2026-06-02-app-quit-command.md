# App Quit Command

## 背景

2026-06-02 发现安装到 `/Applications/AgentDeck.app` 的手工 SwiftPM bundle 中，`Command-Q` 退出不稳定。标准 AppleScript `tell application "AgentDeck" to quit` 可以正常结束 app 和 daemon，说明问题不在 daemon shutdown 或 `SessionModel.teardown()`，而在键盘快捷键到 AppKit termination action 的菜单命令绑定。

## 处理

- 在 SwiftUI `WindowGroup` 上显式替换 `.appTermination` command。
- 新增 `Quit AgentDeck` 按钮，并绑定 `.keyboardShortcut("q", modifiers: .command)`。
- action 直接调用 `NSApp.terminate(nil)`，保持标准 AppKit 退出路径。

## 验证

- `swift test --filter appExposesExplicitQuitCommandShortcut`
- `swift test`
- release 重新构建后，用安装版执行 `--selfcheck`。
