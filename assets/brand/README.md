# AgentDeck 图标

正式图形为 04C / Workspace：橙色底、深色双层卡片和米白双栏。

- `agentdeck.png`：1024 × 1024 RGBA，圆角外透明；GPUI 侧栏编译期嵌入。
- `AgentDeck.icns`：macOS bundle 图标，包含 16、32、128、256、512 pt 的 1x / 2x 尺寸。
- [iOS AppIcon](../../ios/AgentDeckMobile/Assets.xcassets/AppIcon.appiconset/AppIcon.png)：1024 × 1024 不透明满版资源；由系统裁切圆角，Xcode 生成设备尺寸。

不透明的 iOS AppIcon 是两端共用母版，由内置 imagegen 制作，再用 macOS `sips` 归一到 1024 px；[生成提示词](PROMPTS.md)记录图形约束。
脚本用 CoreGraphics 将母版绘制到 1024 px 透明画布上的 824 px 圆角矩形内，再生成 macOS 各尺寸；内部图形和配色共用同一来源。

修改 iOS 母版后，在仓库根目录运行（需要 macOS 和 Xcode Command Line Tools）：

```bash
bash scripts/generate-app-icon.sh
./script/build_and_run.sh --verify
```

打包脚本复制 `.icns` 并设置 `CFBundleIconFile`；`--verify` 核对 bundle 引用和资源内容。
侧栏使用嵌入资源，不依赖启动目录。iOS 的 `AppIcon` 名称由 `ios/project.yml` 固定。
