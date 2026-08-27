#!/system/bin/sh
# ====== Colamanga 破甲模块 - 控制服务 ======
# 监听 127.0.0.1:8799，提供 WebUI 控制面板
# 通过 service.sh 或手动启动

MODDIR=/data/adb/modules/colamanga_mod
PIDFILE=$MODDIR/run/webui.pid
LOGFILE=$MODDIR/logs/webui.log

case "$1" in
  start)
    # 杀掉旧进程
    [ -f "$PIDFILE" ] && kill "$(cat "$PIDFILE")" 2>/dev/null
    # 启动 HTTP 服务
    if command -v busybox >/dev/null 2>&1; then
      busybox httpd -h "$MODDIR/webui" -p 8799 2>&1 &
      echo $! > "$PIDFILE"
      echo "WebUI started (busybox) on :8799"
    elif command -v nc >/dev/null 2>&1; then
      nohup sh -c '
        while true; do
          (printf "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
           cat /data/adb/modules/colamanga_mod/webui/index.html) | nc -l -p 8799 -q 1 > /dev/null 2>&1
        done
      ' > /dev/null 2>&1 &
      echo $! > "$PIDFILE"
      echo "WebUI started (nc) on :8799"
    else
      echo "请安装 busybox 或使用 Magisk Manager 的 WebUI 按钮"
      exit 1
    fi
    ;;
  stop)
    [ -f "$PIDFILE" ] && kill "$(cat "$PIDFILE")" 2>/dev/null && echo "WebUI stopped"
    ;;
  *)
    echo "用法: $0 start|stop"
    ;;
esac