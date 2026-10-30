#!/bin/bash
# Linux 桌面端完整流程验收：起一个隔离、常驻的图形会话，再用 step.sh 逐步点击、输入、截图。
# 不触碰真实桌面会话：私有 dbus + 独立 HOME / XDG 目录 + 独立 X display 或 Wayland socket。
#
# 用法：scripts/linux-e2e/session.sh <x11|wayland> <start|stop>
#   x11      Xvfb :97 + gnome-shell --x11（真 GNOME 窗口管理器，服务端装饰）；NO_WM=1 时只起裸 Xvfb
#   wayland  无头 gnome-shell（--headless --wayland）+ pipewire；截图走 ScreenCast，输入走 RemoteDesktop
# 环境变量：
#   APP_BIN      桌面端二进制，默认 target/debug/agentdeck-desktop（同目录须有 agentdeckd）
#   VENDOR_HOME  把其中的 .claude / .claude.json / .codex 符号链接进隔离 HOME，默认 $HOME；
#                设为空则不链接（只能看空历史，不能发消息）
#   OUT_DIR      输出目录，默认 /tmp/agentdeck-e2e-<模式>
#
# 注意：链接的是真实 vendor 状态。测试会话会写进真实历史；Claude Code 启动时会按
# cleanupPeriodDays（默认 30 天）删除过期会话记录，长期没跑过 claude 的机器上第一次运行就会触发。
#
# 依赖（Ubuntu 24.04）：xvfb xdotool imagemagick mesa-vulkan-drivers gnome-shell；
#   wayland 另需 pipewire wireplumber gstreamer1.0-pipewire python3-gi。
set -u
MODE=${1:?用法: $0 <x11|wayland> <start|stop>}
ACTION=${2:?用法: $0 <x11|wayland> <start|stop>}
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
OUT=${OUT_DIR:-/tmp/agentdeck-e2e-$MODE}

if [ "$ACTION" = stop ]; then
  # 每个会话都用 setsid 起在自己的进程组里，按组整体结束。
  for f in "$OUT"/*.pgid; do [ -f "$f" ] && kill -- -"$(cat "$f")" 2>/dev/null; done
  sleep 1
  exit 0
fi

APP_BIN=${APP_BIN:-$ROOT/target/debug/agentdeck-desktop}
VENDOR_HOME=${VENDOR_HOME-$HOME}
LVP=$(ls /usr/share/vulkan/icd.d/lvp_icd*.json | head -1)
rm -rf "$OUT"
mkdir -p "$OUT/home/.config" "$OUT/run" "$OUT/shots"
chmod 700 "$OUT/run"
if [ -n "$VENDOR_HOME" ]; then
  for f in .claude .claude.json .codex; do
    [ -e "$VENDOR_HOME/$f" ] && ln -s "$VENDOR_HOME/$f" "$OUT/home/$f"
  done
fi
# 隔离 HOME 下拿不到登录 shell 的 PATH，常见的 vendor 安装位置显式带上。
VPATH=$VENDOR_HOME/.bun/bin:$VENDOR_HOME/.local/bin:$VENDOR_HOME/.npm-global/bin:/usr/local/bin:/usr/bin:/bin
export OUT APP_BIN LVP HERE
export HOME=$OUT/home XDG_CONFIG_HOME=$OUT/home/.config XDG_DATA_HOME=$OUT/home/.local/share \
  XDG_CACHE_HOME=$OUT/home/.cache XDG_RUNTIME_DIR=$OUT/run PATH=$VPATH
unset DISPLAY WAYLAND_DISPLAY

if [ "$MODE" = x11 ]; then
  export DISPLAY=:97 NO_WM=${NO_WM:-}
  setsid bash -c '
    ps -o pgid= $$ | tr -d " " >"$OUT/session.pgid"
    Xvfb :97 -screen 0 1600x1000x24 >"$OUT/xvfb.log" 2>&1 &
    sleep 1
    exec dbus-run-session -- bash -c "
      env | grep -E \"^(DISPLAY|DBUS_SESSION_BUS_ADDRESS|HOME|XDG_RUNTIME_DIR)=\" | sed \"s/^/export /\" >\"\$OUT/env\"
      [ -z \"\$NO_WM\" ] && gnome-shell --x11 --replace >\"\$OUT/shell.log\" 2>&1 &
      sleep 8
      VK_DRIVER_FILES=\$LVP RUST_BACKTRACE=full \"\$APP_BIN\" >\"\$OUT/app.log\" 2>&1 &
      echo \$! >\"\$OUT/app.pid\"
      wait
    "
  ' </dev/null >"$OUT/session.log" 2>&1 &
  sleep 16
  # gnome-shell 启动后停在概览，退出概览再开始。
  [ -z "$NO_WM" ] && DISPLAY=:97 xdotool key Escape
elif [ "$MODE" = wayland ]; then
  mkfifo "$OUT/cmd"
  setsid dbus-run-session -- bash -c '
    ps -o pgid= $$ | tr -d " " >"$OUT/session.pgid"
    pipewire >"$OUT/pw.log" 2>&1 &
    wireplumber >>"$OUT/pw.log" 2>&1 &
    sleep 2
    gnome-shell --headless --wayland --no-x11 --virtual-monitor 1600x1000 \
      --wayland-display wayland-agentdeck-e2e >"$OUT/shell.log" 2>&1 &
    sleep 8
    /usr/bin/python3 "$HERE/../linux-ime/caster.py" "$OUT/shots" >"$OUT/cast.log" 2>&1 &
    /usr/bin/python3 "$HERE/input.py" "$OUT/cmd" 1600 1000 >"$OUT/input.log" 2>&1 &
    WAYLAND_DISPLAY=wayland-agentdeck-e2e VK_DRIVER_FILES=$LVP RUST_BACKTRACE=full \
      "$APP_BIN" >"$OUT/app.log" 2>&1 &
    echo $! >"$OUT/app.pid"
    wait
  ' </dev/null >"$OUT/session.log" 2>&1 &
  sleep 20
  timeout 10 bash -c 'echo "key Escape" >"$1"' _ "$OUT/cmd"
else
  echo "未知模式：$MODE" >&2
  exit 2
fi
kill -0 "$(cat "$OUT/app.pid" 2>/dev/null)" 2>/dev/null && echo "STARTED $OUT" || { echo "APP NOT RUNNING，见 $OUT/app.log"; exit 1; }
