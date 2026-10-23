#!/bin/bash
# Linux 桌面端中文输入法无头回归（Wayland/text-input-v3）。在 Ubuntu GNOME 主机（如 dt）上运行：
# 私有 dbus 会话里起无头 gnome-shell（--headless --no-x11）+ ibus + pipewire，
# 经 Mutter RemoteDesktop 注入按键，经 Mutter ScreenCast 每秒存一帧，不触碰真实桌面会话。
# GNOME 的 Screenshot 接口在此模式下拒绝调用，所以截图走 ScreenCast。
#
# 用法：scripts/linux-ime/wayland.sh [会话名] [步骤...]
#   步骤：type:<文本>  key:<键名，可带 ctrl+ 前缀>；省略时使用默认拼音序列。
# 环境变量：APP_BIN、OUT_DIR（默认 /tmp/agentdeck-ime-wl-<会话名>）。
# 输出：$OUT_DIR/result、app.log、steps（按键时间戳）、f*.png（逐秒帧）。
# 依赖（Ubuntu 24.04）：gnome-shell ibus-libpinyin pipewire wireplumber gstreamer1.0-pipewire
#   python3-gi mesa-vulkan-drivers。Python 助手必须用系统 /usr/bin/python3（需要 python3-gi）。
set -u
NAME=${1:-ime}
[ $# -gt 0 ] && shift
STEPS=${*:-key:Escape type:nihao key:space type:zhongwenshurufa key:space type:ni key:BackSpace key:BackSpace type:hao key:Escape type:ceshi key:Return}
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
APP_BIN=${APP_BIN:-$ROOT/target/debug/agentdeck-desktop}
OUT=${OUT_DIR:-/tmp/agentdeck-ime-wl-$NAME}
LVP=$(ls /usr/share/vulkan/icd.d/lvp_icd*.json | head -1)

rm -rf "$OUT"
mkdir -p "$OUT/home" "$OUT/run"
chmod 700 "$OUT/run"
export HOME=$OUT/home XDG_CONFIG_HOME=$OUT/home/.config XDG_DATA_HOME=$OUT/home/.local/share \
  XDG_CACHE_HOME=$OUT/home/.cache XDG_RUNTIME_DIR=$OUT/run
unset DISPLAY WAYLAND_DISPLAY
export OUT STEPS NAME HERE APP_BIN LVP

dbus-run-session -- bash -c '
gsettings set org.gnome.desktop.input-sources sources "[(\"ibus\", \"libpinyin\")]"
pipewire >"$OUT/pw.log" 2>&1 &
PW=$!
wireplumber >>"$OUT/pw.log" 2>&1 &
WP=$!
ibus-daemon --panel disable -r >"$OUT/im.log" 2>&1 &
sleep 2
gnome-shell --headless --wayland --no-x11 --virtual-monitor 1600x1000 \
  --wayland-display "wayland-$NAME" >"$OUT/shell.log" 2>&1 &
SHELL_PID=$!
sleep 8
/usr/bin/python3 "$HERE/caster.py" "$OUT" >"$OUT/cast.log" 2>&1 &
CAST=$!
WAYLAND_DISPLAY=wayland-$NAME VK_DRIVER_FILES=$LVP RUST_BACKTRACE=full "$APP_BIN" >"$OUT/app.log" 2>&1 &
APP=$!
sleep 8
/usr/bin/python3 "$HERE/rd_keys.py" $STEPS >"$OUT/steps" 2>&1
sleep 2
if kill -0 $APP 2>/dev/null; then echo ALIVE >"$OUT/result"; else echo "APP DIED" >"$OUT/result"; fi
kill $CAST $APP 2>/dev/null
sleep 1
kill $SHELL_PID $WP $PW 2>/dev/null
' 2>"$OUT/dbus.log"
cat "$OUT/result"
