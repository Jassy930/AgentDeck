#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ICON_DIR="$(mktemp -d /tmp/agentdeck-icon.XXXXXX)"
trap 'rm -rf "$ICON_DIR"' EXIT
mkdir "$ICON_DIR/AgentDeck.iconset"

swift - "$ROOT_DIR" <<'SWIFT'
import CoreGraphics
import Foundation
import ImageIO
import UniformTypeIdentifiers

let root = URL(fileURLWithPath: CommandLine.arguments[1])
let input = root.appendingPathComponent("ios/AgentDeckMobile/Assets.xcassets/AppIcon.appiconset/AppIcon.png")
let output = root.appendingPathComponent("assets/brand/agentdeck.png")
guard let source = CGImageSourceCreateWithURL(input as CFURL, nil),
      let image = CGImageSourceCreateImageAtIndex(source, 0, nil),
      image.width == 1024, image.height == 1024,
      let context = CGContext(data: nil, width: 1024, height: 1024,
                              bitsPerComponent: 8, bytesPerRow: 0,
                              space: CGColorSpace(name: CGColorSpace.sRGB)!,
                              bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue) else {
    fatalError("AppIcon.png must be a readable 1024px image")
}
let tile = CGRect(x: 100, y: 100, width: 824, height: 824)
context.addPath(CGPath(roundedRect: tile, cornerWidth: 184, cornerHeight: 184, transform: nil))
context.clip()
context.interpolationQuality = .high
context.draw(image, in: tile)
guard let rendered = context.makeImage(),
      let destination = CGImageDestinationCreateWithURL(output as CFURL, UTType.png.identifier as CFString, 1, nil) else {
    fatalError("Cannot create macOS icon PNG")
}
CGImageDestinationAddImage(destination, rendered, nil)
guard CGImageDestinationFinalize(destination) else {
    fatalError("Cannot write macOS icon PNG")
}
SWIFT

for size in 16 32 128 256 512; do
  for scale in 1 2; do
    suffix=""
    [[ "$scale" == 1 ]] || suffix="@2x"
    pixels=$((size * scale))
    sips -z "$pixels" "$pixels" "$ROOT_DIR/assets/brand/agentdeck.png" \
      --out "$ICON_DIR/AgentDeck.iconset/icon_${size}x${size}${suffix}.png" >/dev/null
  done
done

iconutil -c icns "$ICON_DIR/AgentDeck.iconset" -o "$ROOT_DIR/assets/brand/AgentDeck.icns"
