#!/bin/bash
# 在 session.sh 起好的会话里依次执行步骤，最后截图到 $OUT_DIR/<截图名>.png，并报告应用是否存活；
# 截图失败或应用已退出时以非零状态退出。
#
# 用法：scripts/linux-e2e/step.sh <x11|wayland> <截图名> [步骤...]
#   步骤：click:X,Y  move:X,Y  type:<文本>  key:<键名，可带 ctrl+ 前缀>  sleep:<秒>
#   坐标是 1600x1000 屏幕上的像素；文本只支持 ASCII（中文输入见 scripts/linux-ime/）。
# lavapipe 软件渲染下 debug 构建只有个位数帧率，每步后固定等待，截图前再多等几秒。
set -u
MODE=${1:?用法: $0 <x11|wayland> <截图名> [步骤...]}
NAME=${2:?用法: $0 <x11|wayland> <截图名> [步骤...]}
shift 2
OUT=${OUT_DIR:-/tmp/agentdeck-e2e-$MODE}
[ "$MODE" = x11 ] && . "$OUT/env"

for step in "$@"; do
  kind=${step%%:*} arg=${step#*:}
  if [ "$kind" = sleep ]; then
    sleep "$arg"
  elif [ "$MODE" = x11 ]; then
    case $kind in
      click) xdotool mousemove "${arg%,*}" "${arg#*,}" click 1 ;;
      move) xdotool mousemove "${arg%,*}" "${arg#*,}" ;;
      type) xdotool type --delay 80 "$arg" ;;
      key) xdotool key --delay 80 "$arg" ;;
    esac
  else
    # input.py 每读完一次 FIFO 就重新打开；它若已退出，这里的写会一直阻塞。
    case $kind in click | move) arg=${arg/,/ } ;; esac
    before=$(grep -c '^done ' "$OUT/input.log")
    timeout 10 bash -c 'echo "$1 $2" >"$3"' _ "$kind" "$arg" "$OUT/cmd" || { echo "input.py 无响应，见 $OUT/input.log"; exit 1; }
    # 写进 FIFO 只代表 input.py 收到；逐字输入每字符约 0.14 秒，等它打印 done 再计时和截图。
    for _ in $(seq 600); do
      [ "$(grep -c '^done ' "$OUT/input.log")" -gt "$before" ] && break
      sleep 0.2
    done
    [ "$(grep -c '^done ' "$OUT/input.log")" -gt "$before" ] || { echo "input.py 120 秒内未完成 $kind，见 $OUT/input.log"; exit 1; }
  fi
  sleep 1.5
done
sleep 3
# 截图是验收证据：拿不到就以非零退出，不能只凭应用存活报成功。
if [ "$MODE" = x11 ]; then
  import -window root "$OUT/$NAME.png" || { echo "截图失败"; exit 1; }
else
  frame=$(ls "$OUT"/shots/f*.png 2>/dev/null | tail -1)
  [ -n "$frame" ] && cp "$frame" "$OUT/$NAME.png" || { echo "没有 ScreenCast 帧，见 $OUT/cast.log"; exit 1; }
fi
kill -0 "$(cat "$OUT/app.pid")" 2>/dev/null && echo ALIVE || { echo "APP DIED"; exit 1; }
