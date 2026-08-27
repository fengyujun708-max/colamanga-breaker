#!/system/bin/sh
# ====== Colamanga 破甲模块 - 开机服务 ======
# 功能：读取配置 → resetprop 全套属性(可选) → 启动日志监控 → 启动抓包
# 设计原则：默认只影响 colamanga(Zygisk per-process)，全局 resetprop 需手动开启

MODDIR=/data/adb/modules/colamanga_mod
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
hide_frida=1
packet_capture=1
app_log_monitor=1
signature_bypass=1
persistent_identity=1
identity_mode=locked
frida_enabled=0
safe_mode=0
target_packages=com.hswl.car_owner,com.hswl.cargo_owner.cargo_owner
webui_port=8799
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
    # 循环监控两个包（app 重启后 PID 变化，需定期重查）
    nohup sh -c '
        while true; do
            for pkg in com.hswl.car_owner com.hswl.cargo_owner.cargo_owner; do
                PID=$(pidof "$pkg" 2>/dev/null | tr " " "\n" | head -1)
                [ -z "$PID" ] && continue
                # 该 pid 若已有监控则跳过
                grep -q "$PID" /data/adb/modules/colamanga_mod/run/log_monitor_pids 2>/dev/null && continue
                echo "$PID" >> /data/adb/modules/colamanga_mod/run/log_monitor_pids 2>/dev/null
                ( logcat --pid="$PID" -v time 2>/dev/null | \
                  grep -iE "cargo|mymanga|byazt|starlink|security|reward|unlock|device|adCount|reportAd|ColaManga" >> \
                  /data/adb/modules/colamanga_mod/logs/app.log 2>/dev/null ) &
            done
            sleep 20
        done
    ' > /dev/null 2>&1 &
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
                cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | awk -v u=$UID -v t=$TS "{if(\$8==u && \$4!=\"0A\") print t, \$2, \$3, \$4}" >> /data/adb/modules/colamanga_mod/logs/network.log 2>/dev/null
            done
            sleep 2
        done
    ' > /dev/null 2>&1 &
    echo $! > "$RUN/net_capture.pid"
    echo "[service] network capture monitor started" >> "$LOGS/service.log"
fi

echo "[service] colamanga_mod started at $(date), profile=$PROFILE" >> "$LOGS/service.log"

# ===== WebUI HTTP 服务器（127.0.0.1:8799） =====
# 用 busybox httpd 或 sh 自建轻量服务
if command -v busybox >/dev/null 2>&1; then
    # busybox httpd 方式
    nohup busybox httpd -h "$MODDIR/webui" -p 8799 > "$LOGS/webui.log" 2>&1 &
    echo $! > "$RUN/webui.pid"
    echo "[service] WebUI (busybox) started on 127.0.0.1:8799" >> "$LOGS/service.log"
elif command -v nc >/dev/null 2>&1; then
    # nc 方式（简化版，只响应 index.html）
    nohup sh -c 'while true; do (printf "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"; cat /data/adb/modules/colamanga_mod/webui/index.html) | nc -l -p 8799 -q 1 > /dev/null 2>&1; done' > /dev/null 2>&1 &
    echo $! > "$RUN/webui.pid"
    echo "[service] WebUI (nc) started on 127.0.0.1:8799" >> "$LOGS/service.log"
else
    echo "[service] WebUI: 无 busybox/nc，请用 Magisk Manager 的 WebUI 按钮" >> "$LOGS/service.log"
fi

# ===== Frida server 集成 =====
FRIDA=$(grep '^frida_enabled=' "$SETTINGS" 2>/dev/null | cut -d= -f2)
if [ "$FRIDA" = "1" ]; then
    if [ -f "$MODDIR/frida/frida-server" ]; then
        # 反检测：复制为更名进程 zyncd + 非标准端口 8799，避免 frida 特征
        cp "$MODDIR/frida/frida-server" "$MODDIR/frida/zyncd" 2>/dev/null
        chmod 0755 "$MODDIR/frida/zyncd"
        nohup "$MODDIR/frida/zyncd" -l 127.0.0.1:8799 > "$LOGS/frida.log" 2>&1 &
        echo $! > "$RUN/frida.pid"
        echo "[service] frida(zyncd) started on 127.0.0.1:8799 (pid $(cat $RUN/frida.pid))" >> "$LOGS/service.log"
    fi
fi