#!/system/bin/sh
# WebUI HTTP 服务（nc 版，手机直跑）
MODDIR=/data/adb/modules/colamanga_mod
PORT=8799

while true; do
  REQ=$(nc -l -p $PORT -q 1 2>/dev/null)
  URL=$(echo "$REQ" | head -1 | awk '{print $2}')
  
  if echo "$URL" | grep -q "^/api/"; then
    CMD=$(echo "$URL" | sed 's|^/api/||;s|/| |g;s|%20| |g')
    BODY=$(sh "$MODDIR/control/control.sh" $CMD 2>&1)
    LEN=$(echo "$BODY" | wc -c)
    printf "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s" "$LEN" "$BODY"
  else
    BODY=$(cat "$MODDIR/webui/index.html" 2>/dev/null)
    LEN=$(echo "$BODY" | wc -c)
    printf "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n%s" "$LEN" "$BODY"
  fi
done