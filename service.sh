#!/system/bin/sh
# ====== Colamanga 破甲模块 - 开机服务 ======
# 功能：读取配置 → resetprop 全套属性(可选) → 启动日志监控 → 启动抓包
# 设计原则：默认只影响 colamanga(Zygisk per-process)，全局 resetprop 需手动开启

MODDIR=/data/adb/colamanga_mod
CONF=$MODDIR/config
LOGS=$MODDIR/logs
RUN=$MODDIR/run
PROFILES=$CONF/fake_device.conf
ACTIVE=$CONF/active_profile
SETTINGS=$CONF/settings.conf

# 初始化目录
mkdir -p "$CONF" "$LOGS" "$RUN" "$MODDIR/rules"
[ -f "$PROFILES" ] || cp "$MODDIR/config/fake_device.conf" "$PROFILES" 2>/dev/null
[ -f "$ACTIVE" ] || echo "profile_xiaomi" > "$ACTIVE"

# 默认设置
[ -f "$SETTINGS" ] || cat > "$SETTINGS" <<'EOF'
global_resetprop=0
zygisk_hook=1
anti_debug=1
hide_root=1
hide_xposed=1
packet_capture=1
app_log_monitor=1
signature_bypass=1
persistent_identity=1
target_packages=com.hswl.car_owner,com.hswl.cargo_owner.cargo_owner
EOF

# ===== 读取当前设备方案属性 =====
get_prop() { grep -A30 "\[$1\]" "$PROFILES" 2>/dev/null | grep "^$2=" | head -1 | cut -d= -f2; }
PROFILE=$(cat "$ACTIVE" 2>/dev/null || echo "profile_xiaomi")

# ===== 全局 resetprop（可选，默认关，避免影响其他 app） =====
GLOBAL_RP=$(grep '^global_resetprop=' "$SETTINGS" 2>/dev/null | cut -d= -f2)
if [ "$GLOBAL_RP" = "1" ]; then
    SN=$(get_prop "$PROFILE" serialno)
    BSN=$(get_prop "$PROFILE" boot_serialno)
    FP=$(get_prop "$PROFILE" fingerprint)
    MODEL=$(get_prop "$PROFILE" model)
    BRAND=$(get_prop "$PROFILE" brand)
    DEVICE=$(get_prop "$PROFILE" device)
    PRODUCT=$(get_prop "$PROFILE" product)
    MFR=$(get_prop "$PROFILE" manufacturer)
    HW=$(get_prop "$PROFILE" hardware)
    BOARD=$(get_prop "$PROFILE" board)
    HOST=$(get_prop "$PROFILE" host)
    BID=$(get_prop "$PROFILE" build_id)
    INC=$(get_prop "$PROFILE" incremental)
    SP=$(get_prop "$PROFILE" security_patch)
    REL=$(get_prop "$PROFILE" release)
    SDK=$(get_prop "$PROFILE" sdk)
    TYPE=$(get_prop "$PROFILE" type)
    TAGS=$(get_prop "$PROFILE" tags)
    [ -n "$SN" ] && resetprop ro.serialno "$SN" && resetprop ro.boot.serialno "$SN"
    [ -n "$FP" ] && resetprop ro.build.fingerprint "$FP"
    [ -n "$MODEL" ] && resetprop ro.product.model "$MODEL" && resetprop ro.product.system.model "$MODEL"
    [ -n "$BRAND" ] && resetprop ro.product.brand "$BRAND" && resetprop ro.product.system.brand "$BRAND"
    [ -n "$DEVICE" ] && resetprop ro.product.device "$DEVICE"
    [ -n "$PRODUCT" ] && resetprop ro.product.name "$PRODUCT"
    [ -n "$MFR" ] && resetprop ro.product.manufacturer "$MFR"
    [ -n "$HW" ] && resetprop ro.hardware "$HW" && resetprop ro.boot.hardware "$HW"
    [ -n "$BOARD" ] && resetprop ro.product.board "$BOARD" && resetprop ro.board.platform "$BOARD"
    [ -n "$HOST" ] && resetprop ro.build.host "$HOST"
    [ -n "$BID" ] && resetprop ro.build.id "$BID"
    [ -n "$INC" ] && resetprop ro.build.version.incremental "$INC"
    [ -n "$SP" ] && resetprop ro.build.version.security_patch "$SP"
    [ -n "$REL" ] && resetprop ro.build.version.release "$REL"
    [ -n "$SDK" ] && resetprop ro.build.version.sdk "$SDK"
    [ -n "$TYPE" ] && resetprop ro.build.type "$TYPE"
    [ -n "$TAGS" ] && resetprop ro.build.tags "$TAGS"
    echo "[service] global resetprop applied: $PROFILE" >> "$LOGS/service.log"
fi

# ===== 漫城日志监控（logcat 过滤 colamanga 相关） =====
LOG_MON=$(grep '^app_log_monitor=' "$SETTINGS" 2>/dev/null | cut -d= -f2)
if [ "$LOG_MON" = "1" ]; then
    TARGETS=$(grep '^target_packages=' "$SETTINGS" 2>/dev/null | cut -d= -f2 | tr ',' '|')
    nohup logcat --pid=$(pidof -s $TARGETS 2>/dev/null | tr ' ' ',') 2>/dev/null | \
        grep -iE 'cargo|mymanga|byazt|starlink|security|reward|unlock|device|adCount|reportAd' >> \
        "$LOGS/app.log" 2>/dev/null &
    echo $! > "$RUN/log_monitor.pid"
    echo "[service] app log monitor started" >> "$LOGS/service.log"
fi

# ===== 网络抓包监控（tcpdump 或 /proc/net 轮询） =====
CAP=$(grep '^packet_capture=' "$SETTINGS" 2>/dev/null | cut -d= -f2)
if [ "$CAP" = "1" ]; then
    # 用 /proc/net 轮询记录 colamanga 的网络连接（不需要 tcpdump）
    nohup sh -c '
        while true; do
            TARGETS="com.hswl.car_owner com.hswl.cargo_owner.cargo_owner"
            for pkg in $TARGETS; do
                PID=$(pidof $pkg 2>/dev/null | tr " " "\n" | head -1)
                [ -z "$PID" ] && continue
                UID=$(awk "/^Uid/{print \$2}" /proc/$PID/status 2>/dev/null)
                [ -z "$UID" ] && continue
                TS=$(date "+%H:%M:%S")
                cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | awk -v u=$UID -v t=$TS "{if(\$8==u && \$4!=\"0A\") print t, \$2, \$3, \$4}" >> /data/adb/colamanga_mod/logs/network.log 2>/dev/null
            done
            sleep 2
        done
    ' > /dev/null 2>&1 &
    echo $! > "$RUN/net_capture.pid"
    echo "[service] network capture monitor started" >> "$LOGS/service.log"
fi

echo "[service] colamanga_mod started at $(date), profile=$PROFILE" >> "$LOGS/service.log"