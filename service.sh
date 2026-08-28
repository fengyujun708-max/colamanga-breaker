#!/system/bin/sh
# ====== Colamanga 破甲模块 - 开机服务（精简版，零后台进程，防发烫）======
# 只做 resetprop，不做任何后台监控（按需通过 control.sh 开启）
MODDIR=/data/adb/modules/colamanga_mod
CONF=$MODDIR/config
LOGS=$MODDIR/logs
RUN=$MODDIR/run
PROFILES=$CONF/fake_device.conf
ACTIVE=$CONF/active_profile
SETTINGS=$CONF/settings.conf

mkdir -p "$CONF" "$LOGS" "$RUN"
[ -f "$ACTIVE" ] || echo "profile_xiaomi" > "$ACTIVE"
[ -f "$SETTINGS" ] || cat > "$SETTINGS" <<'EOF'
global_resetprop=1
frida_enabled=0
app_log_monitor=0
packet_capture=0
EOF

get_prop() { grep -A40 "\[$1\]" "$PROFILES" 2>/dev/null | grep "^$2=" | head -1 | cut -d= -f2; }
PROFILE=$(cat "$ACTIVE" 2>/dev/null || echo "profile_xiaomi")
GLOBAL_RP=$(grep '^global_resetprop=' "$SETTINGS" 2>/dev/null | cut -d= -f2)

if [ "$GLOBAL_RP" = "1" ]; then
    # ===== 读取全套假设备属性 =====
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
    LINE1=$(get_prop "$PROFILE" line1)
    OP=$(get_prop "$PROFILE" operator)

    # ===== 序列号 =====
    [ -n "$SN" ] && resetprop ro.serialno "$SN"
    [ -n "$BSN" ] && resetprop ro.boot.serialno "$BSN"
    [ -n "$SN" ] && resetprop ro.frp.pst "$SN" 2>/dev/null

    # ===== Build 指纹（全分区覆盖）=====
    [ -n "$FP" ] && resetprop ro.build.fingerprint "$FP"
    [ -n "$FP" ] && resetprop ro.system.build.fingerprint "$FP" 2>/dev/null
    [ -n "$FP" ] && resetprop ro.bootimage.build.fingerprint "$FP" 2>/dev/null
    [ -n "$FP" ] && resetprop ro.vendor.build.fingerprint "$FP" 2>/dev/null

    # ===== 产品信息（全分区覆盖：main/system/vendor/odm/system_ext）=====
    for PART in "" "system." "vendor." "odm." "system_ext."; do
        [ -n "$MODEL" ] && resetprop "ro.product.${PART}model" "$MODEL" 2>/dev/null
        [ -n "$BRAND" ] && resetprop "ro.product.${PART}brand" "$BRAND" 2>/dev/null
        [ -n "$DEVICE" ] && resetprop "ro.product.${PART}device" "$DEVICE" 2>/dev/null
        [ -n "$PRODUCT" ] && resetprop "ro.product.${PART}name" "$PRODUCT" 2>/dev/null
        [ -n "$MFR" ] && resetprop "ro.product.${PART}manufacturer" "$MFR" 2>/dev/null
    done

    # ===== 硬件 =====
    [ -n "$HW" ] && resetprop ro.hardware "$HW"
    [ -n "$HW" ] && resetprop ro.boot.hardware "$HW"
    [ -n "$BOARD" ] && resetprop ro.product.board "$BOARD"
    [ -n "$BOARD" ] && resetprop ro.board.platform "$BOARD"
    [ -n "$MFR" ] && resetprop ro.soc.manufacturer "$MFR" 2>/dev/null
    [ -n "$HW" ] && resetprop ro.soc.model "$HW" 2>/dev/null

    # ===== Build 版本信息 =====
    [ -n "$HOST" ] && resetprop ro.build.host "$HOST"
    [ -n "$BID" ] && resetprop ro.build.id "$BID"
    [ -n "$BID" ] && resetprop ro.build.display.id "$BID" 2>/dev/null
    [ -n "$INC" ] && resetprop ro.build.version.incremental "$INC"
    [ -n "$SP" ] && resetprop ro.build.version.security_patch "$SP"
    [ -n "$REL" ] && resetprop ro.build.version.release "$REL"
    [ -n "$SDK" ] && resetprop ro.build.version.sdk "$SDK"
    [ -n "$TYPE" ] && resetprop ro.build.type "$TYPE"
    [ -n "$TAGS" ] && resetprop ro.build.tags "$TAGS"

    # ===== Boot 状态（让设备看起来正常锁定）=====
    resetprop ro.boot.verifiedbootstate "green" 2>/dev/null
    resetprop ro.boot.flash.locked "1" 2>/dev/null
    resetprop ro.boot.vbmeta.device_state "locked" 2>/dev/null
    resetprop ro.boot.veritymode "enforcing" 2>/dev/null
    resetprop ro.boot.bootmode "normal" 2>/dev/null
    resetprop ro.boot.warranty_bit "0" 2>/dev/null
    resetprop ro.warranty_bit "0" 2>/dev/null
    resetprop ro.boot_mode "normal" 2>/dev/null

    # ===== 运营商/电话（系统属性级）=====
    [ -n "$OP" ] && resetprop gsm.sim.operator.iso "cn" 2>/dev/null
    [ -n "$OP" ] && resetprop gsm.sim.operator.numeric "$OP" 2>/dev/null
    [ -n "$OP" ] && resetprop gsm.operator.numeric "$OP" 2>/dev/null
    [ -n "$OP" ] && resetprop gsm.sim.operator.alpha "China Mobile" 2>/dev/null

    echo "[service] resetprop applied: $PROFILE at $(date)" >> "$LOGS/service.log"
fi

# ===== Frida（默认关，按需开）=====
FRIDA=$(grep '^frida_enabled=' "$SETTINGS" 2>/dev/null | cut -d= -f2)
if [ "$FRIDA" = "1" ] && [ -f "$MODDIR/frida/frida-server" ]; then
    cp "$MODDIR/frida/frida-server" "$MODDIR/frida/zyncd" 2>/dev/null
    chmod 755 "$MODDIR/frida/zyncd"
    nohup "$MODDIR/frida/zyncd" -l 127.0.0.1:8799 > /dev/null 2>&1 &
    echo $! > "$RUN/frida.pid"
    echo "[service] frida(zyncd) started" >> "$LOGS/service.log"
fi

# 不启动任何后台监控进程（防发烫）
# 需要时通过 control.sh log start / capture start 手动开启
echo "[service] done $(date)" >> "$LOGS/service.log"