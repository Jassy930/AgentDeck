#!/bin/sh
if [ "$1" = "--version" ]; then
  [ "${AGENTDECK_FIXTURE_VERSION_ERROR:-}" = 1 ] && exit 97
  printf '%s\n' "$AGENTDECK_FIXTURE_VERSION"
  exit 0
fi
[ "$*" = 'app-server --listen stdio://' ] || exit 10
turn=0
initialized=false
while IFS= read -r frame; do
  id=$(printf '%s' "$frame" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
  case "$frame" in
    *'"method":"initialize"'*)
      if [ "${AGENTDECK_FIXTURE_START_ERROR:-}" = 1 ]; then
        printf '{"id":%s,"error":{"code":-32600,"message":"fixture handshake failure"}}\n' "$id"
      else
        printf '{"id":%s,"result":{}}\n' "$id"
      fi ;;
    *'"method":"initialized"'*) initialized=true ;;
    *'"method":"thread/start"'*)
      [ "$initialized" = true ] || exit 11
      printf '{"id":%s,"result":{"thread":{"id":"fixture-thread"}}}\n' "$id" ;;
    *'"method":"turn/start"'*)
      turn=$((turn + 1))
      printf '{"id":%s,"result":{"turn":{"id":"vendor-%s"}}}\n' "$id" "$turn"
      printf '{"method":"item/agentMessage/delta","params":{"threadId":"fixture-thread","turnId":"vendor-%s","itemId":"message-%s","delta":"Hello"}}\n' "$turn" "$turn"
      if [ "$turn" != 3 ]; then
        printf '{"method":"item/agentMessage/delta","params":{"threadId":"fixture-thread","turnId":"vendor-%s","itemId":"message-%s","delta":" world"}}\n' "$turn" "$turn"
        printf '{"method":"item/completed","params":{"threadId":"fixture-thread","turnId":"vendor-%s","item":{"id":"message-%s","type":"agentMessage","text":"Hello world"}}}\n' "$turn" "$turn"
        printf '{"method":"turn/completed","params":{"threadId":"fixture-thread","turn":{"id":"vendor-%s","status":"completed"}}}\n' "$turn"
      fi ;;
    *'"method":"turn/interrupt"'*)
      printf '{"id":%s,"result":{}}\n' "$id"
      printf '{"method":"turn/completed","params":{"threadId":"fixture-thread","turn":{"id":"vendor-%s","status":"interrupted"}}}\n' "$turn" ;;
    *) exit 12 ;;
  esac
done
