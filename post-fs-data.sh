#!/system/bin/sh
# ====== Colamanga 破甲模块 - 早期属性伪造 ======
# post-fs-data.sh 在 zygote 启动前执行
# 仅设置最关键的早期属性（完整属性在 service.sh 中设置）

MODDIR=/data/adb/modules/colamanga_mod
CONF=$MODDIR/config
ACTIVE=$CONF/active_profile
PROFILES=$CONF/fake_device.conf
SETTINGS=$CONF/settings.conf

mkdir -p "$CONF" "$MODDIR/logs" "$MODDIR/run"

# 读取全局开关
GLOBAL_RP=$(grep '^global_resetprop=' "$SETTINGS" 2>/dev/null | cut -d= -f2)
[ "$GLOBAL_RP" = "1" ] || exit 0

# 读取当前方案
PROFILE=$(cat "$ACTIVE" 2>/dev/null || echo "profile_xiaomi")
get_prop() { grep -A30 "\[$1\]" "$PROFILES" 2>/dev/null | grep "^$2=" | head -1 | cut -d= -f2; }

# 早期关键属性（zygote 前设置，所有进程生效）
SN=$(get_prop "$PROFILE" serialno)
FP=$(get_prop "$PROFILE" fingerprint)
MODEL=$(get_prop "$PROFILE" model)
BRAND=$(get_prop "$PROFILE" brand)
HW=$(get_prop "$PROFILE" hardware)

[ -n "$SN" ] && { resetprop --persistent ro.serialno "$SN" 2>/dev/null || resetprop ro.serialno "$SN"; resetprop ro.boot.serialno "$SN"; }
[ -n "$FP" ] && { resetprop --persistent ro.build.fingerprint "$FP" 2>/dev/null || resetprop ro.build.fingerprint "$FP"; }
[ -n "$MODEL" ] && { resetprop --persistent ro.product.model "$MODEL" 2>/dev/null || resetprop ro.product.model "$MODEL"; }
[ -n "$BRAND" ] && { resetprop --persistent ro.product.brand "$BRAND" 2>/dev/null || resetprop ro.product.brand "$BRAND"; }
[ -n "$HW" ] && { resetprop --persistent ro.hardware "$HW" 2>/dev/null || resetprop ro.hardware "$HW"; }

echo "[post-fs-data] early props set: $PROFILE" >> "$MODDIR/logs/boot.log" 2>/dev/null