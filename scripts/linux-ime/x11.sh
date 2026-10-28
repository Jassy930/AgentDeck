#!/bin/bash
# Linux 桌面端中文输入法无头回归（X11/XIM）。在带 ibus / fcitx5 的 Linux 主机（如 dt）上运行，
# 不触碰真实桌面会话：Xvfb 独立 display + 私有 dbus 会话 + 独立 HOME，输入法和应用都只活在其中。
#
# 用法：scripts/linux-ime/x11.sh <ibus|fcitx5|fcitx4> [display号] [步骤...]
#   步骤：type:<文本>  key:<xdotool 键名>  sleep:<秒>；省略时使用默认拼音序列。
# 环境变量：
#   APP_BIN  桌面端二进制，默认 target/debug/agentdeck-desktop
#   LANG     影响 ibus-x11 的 COMPOUND_TEXT 字符集（zh_CN.UTF-8 → GB2312），务必覆盖 zh_CN
#   FCITX4_IM  fcitx4 的引擎名，默认 pinyin；搜狗为 sogoupinyin
#   OUT_DIR  输出目录，默认 /tmp/agentdeck-ime-<im>-<display>
# 输出：$OUT_DIR/result（ALIVE 或 APP DIED at step N）、app.log（含 panic backtrace）、im.log、每步截图。
#
# 依赖（Ubuntu 24.04）：xvfb xdotool imagemagick mesa-vulkan-drivers dbus ibus-libpinyin
#   fcitx5 fcitx5-chinese-addons。Xvfb 没有 DRI3，必须用 lavapipe 软件 Vulkan（VK_DRIVER_FILES）。
set -u
IM=${1:?用法: $0 <ibus|fcitx5|fcitx4> [display] [步骤...]}
D=${2:-91}
shift $(($# >= 2 ? 2 : 1))
STEPS=${*:-type:nihao key:space type:zhongwenshurufa key:space type:ni key:BackSpace key:BackSpace type:hao key:Escape type:ceshi key:Return type:wo key:Left key:space key:ctrl+a type:ni key:1}
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
APP_BIN=${APP_BIN:-$ROOT/target/debug/agentdeck-desktop}
OUT=${OUT_DIR:-/tmp/agentdeck-ime-$IM-$D}
LVP=$(ls /usr/share/vulkan/icd.d/lvp_icd*.json | head -1)

rm -rf "$OUT"
mkdir -p "$OUT/home" "$OUT/run"
chmod 700 "$OUT/run"
export HOME=$OUT/home XDG_CONFIG_HOME=$OUT/home/.config XDG_DATA_HOME=$OUT/home/.local/share \
  XDG_CACHE_HOME=$OUT/home/.cache XDG_RUNTIME_DIR=$OUT/run DISPLAY=:$D
export IM OUT APP_BIN STEPS LVP FCITX4_IM=${FCITX4_IM:-pinyin}

Xvfb ":$D" -screen 0 1600x1000x24 >"$OUT/xvfb.log" 2>&1 &
XVFB=$!
trap 'kill $XVFB 2>/dev/null' EXIT
sleep 1

dbus-run-session -- bash -c '
if [ "$IM" = ibus ]; then
  export XMODIFIERS=@im=ibus GTK_IM_MODULE=ibus QT_IM_MODULE=ibus
  ibus-daemon --xim --panel disable -r >"$OUT/im.log" 2>&1 &
  sleep 3
  ibus engine libpinyin
elif [ "$IM" = fcitx4 ]; then
  export XMODIFIERS=@im=fcitx GTK_IM_MODULE=fcitx QT_IM_MODULE=fcitx
  mkdir -p "$XDG_CONFIG_HOME/fcitx"
  printf "[Profile]\nIMName=$FCITX4_IM\nEnabledIMList=fcitx-keyboard-us:True,$FCITX4_IM:True\n" >"$XDG_CONFIG_HOME/fcitx/profile"
  printf "[Program]\nDefaultInputMethodState=Active\nShareStateAmongWindow=All\n" >"$XDG_CONFIG_HOME/fcitx/config"
  fcitx -d >"$OUT/im.log" 2>&1
  sleep 5
else
  export XMODIFIERS=@im=fcitx GTK_IM_MODULE=fcitx QT_IM_MODULE=fcitx
  mkdir -p "$XDG_CONFIG_HOME/fcitx5"
  printf "[Groups/0]\nName=Default\nDefault Layout=us\nDefaultIM=pinyin\n\n[Groups/0/Items/0]\nName=keyboard-us\nLayout=\n\n[Groups/0/Items/1]\nName=pinyin\nLayout=\n\n[GroupOrder]\n0=Default\n" \
    >"$XDG_CONFIG_HOME/fcitx5/profile"
  printf "[Behavior]\nActiveByDefault=True\n" >"$XDG_CONFIG_HOME/fcitx5/config"
  fcitx5 -d >"$OUT/im.log" 2>&1
  sleep 3
fi
VK_DRIVER_FILES=$LVP RUST_BACKTRACE=full "$APP_BIN" >"$OUT/app.log" 2>&1 &
APP=$!
sleep 8
import -window root "$OUT/0.png"
i=1
for step in $STEPS; do
  case $step in
    type:*) xdotool type --delay 120 "${step#type:}" ;;
    key:*) xdotool key --delay 120 "${step#key:}" ;;
    sleep:*) sleep "${step#sleep:}" ;;
  esac
  sleep 1
  if ! kill -0 $APP 2>/dev/null; then
    echo "APP DIED at step $i ($step)" >"$OUT/result"
    exit 0
  fi
  import -window root "$OUT/$i.png"
  i=$((i + 1))
done
echo ALIVE >"$OUT/result"
kill $APP
' 2>"$OUT/dbus.log"
cat "$OUT/result"
