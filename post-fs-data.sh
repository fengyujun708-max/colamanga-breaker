#!/system/bin/sh
# ====== Colamanga 破甲模块 - 早期属性（安全版）======
# 不再做任何 resetprop！原因：
#   post-fs-data.sh 在 zygote 启动前执行，此时全局改 ro.build.fingerprint / ro.product.*
#   会污染整个系统，导致 Zygisk Next / LSPosed / surfaceflinger 等因指纹不一致而崩溃或失效。
#   属性伪造已完全由 Zygisk so 在目标进程内（postAppSpecialize）做进程级 hook 实现，
#   既安全又精准（只对 com.hswl.car_owner 系列生效），无需任何全局属性修改。

MODDIR=/data/adb/modules/colamanga_mod
CONF=$MODDIR/config
mkdir -p "$CONF" "$MODDIR/logs" "$MODDIR/run"

echo "[post-fs-data] 安全模式：跳过全局 resetprop（属性伪造由 Zygisk 进程级 hook 完成）" >> "$MODDIR/logs/boot.log" 2>/dev/null