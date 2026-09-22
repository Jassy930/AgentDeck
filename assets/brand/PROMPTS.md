# 04C 正式图标提示词

使用内置 imagegen，以已选定的 04C 图形为参考制作不透明满版母版，再通过资源脚本生成 macOS PNG 和 ICNS。

## 满版母版

```text
Use case: precise-object-edit. Production asset preparation, preserve the APPROVED 04C icon design in the input exactly.
Produce the iOS app-icon master: one 1024x1024 square, fully opaque and full bleed. Remove ONLY the off-white presentation margin and the pre-rounded outer silhouette: extend the warm orange tile material continuously to all four canvas edges and four square corners. This is a SQUARE orange full-bleed icon with NO rounded outer corners, because iOS will apply its own corner mask.
Preserve the exact dark double-card symbol and ivory split slabs from the input: rear graphite card offset toward upper-right, charcoal front card, same angle, same two white slabs, left narrow and right broad, same soft rounded edges and delicate shallow matte shading. Keep the symbol centered, and size it to occupy approximately 76% of canvas width and 70% of canvas height, preserving the original inner composition and generous orange breathing space. Match the approved orange and charcoal colors. No redesign, no new highlights or textures, no text, no marks, no other elements. No white border or margin, no mockup background, no transparent/checkerboard area. Orange must reach every corner.
```
