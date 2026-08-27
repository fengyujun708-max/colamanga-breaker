#!/system/bin/sh
# ====== Colamanga 破甲模块 - 卸载清理 ======
MODDIR=/data/adb/colamanga_mod
# 停止后台服务
for pidfile in "$MODDIR/run/"*.pid; do
  [ -f "$pidfile" ] && kill "$(cat "$pidfile")" 2>/dev/null
done
# 恢复原始属性（仅清除模块设置的）
resetprop --delete ro.serialno 2>/dev/null
resetprop --delete ro.boot.serialno 2>/dev/null
# 清理日志
rm -rf "$MODDIR/logs" "$MODDIR/run"
echo "Colamanga Ultimate Breaker uninstalled"