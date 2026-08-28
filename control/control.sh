#!/system/bin/sh
# ====== Colamanga 破甲模块 - 控制脚本 ======
# 被 WebUI 调用执行命令（通过 AndroidInterface/ksu exec）
MODDIR=/data/adb/modules/colamanga_mod
CONF=$MODDIR/config
SETTINGS=$CONF/settings.conf
ACTIVE=$CONF/active_profile
PROFILES=$CONF/fake_device.conf

case "$1" in
  status)
    # 返回模块状态 JSON
    PID1=$(pidof com.hswl.car_owner 2>/dev/null | head -1)
    PID2=$(pidof com.hswl.cargo_owner.cargo_owner 2>/dev/null | head -1)
    PROFILE=$(cat "$ACTIVE" 2>/dev/null || echo "profile_xiaomi")
    GLOBAL=$(grep '^global_resetprop=' "$SETTINGS" 2>/dev/null | cut -d= -f2)
    ZYGI=$(grep '^zygisk_hook=' "$SETTINGS" 2>/dev/null | cut -d= -f2)
    ANTI=$(grep '^anti_debug=' "$SETTINGS" 2>/dev/null | cut -d= -f2)
    CAP=$(grep '^packet_capture=' "$SETTINGS" 2>/dev/null | cut -d= -f2)
    MON=$(grep '^app_log_monitor=' "$SETTINGS" 2>/dev/null | cut -d= -f2)
    IDMODE=$(grep '^identity_mode=' "$SETTINGS" 2>/dev/null | cut -d= -f2)
    echo "{\"profile\":\"$PROFILE\",\"pid1\":\"$PID1\",\"pid2\":\"$PID2\",\"global_rp\":\"$GLOBAL\",\"zygisk\":\"$ZYGI\",\"anti_debug\":\"$ANTI\",\"capture\":\"$CAP\",\"monitor\":\"$MON\",\"identity_mode\":\"$IDMODE\"}"
    ;;
  toggle)
    # 切换开关: toggle <setting_name>
    KEY="$2"
    CUR=$(grep "^$KEY=" "$SETTINGS" 2>/dev/null | cut -d= -f2)
    [ "$CUR" = "1" ] && NEW=0 || NEW=1
    # 更新配置
    TMP=$MODDIR/run/.tmp_settings
    sed "s/^$KEY=.*/$KEY=$NEW/" "$SETTINGS" > "$TMP" 2>/dev/null && mv "$TMP" "$SETTINGS"
    echo "{\"$KEY\":\"$NEW\"}"
    # 如果切换了全局属性，立即应用/恢复
    if [ "$KEY" = "global_resetprop" ] && [ "$NEW" = "1" ]; then
      sh "$MODDIR/service.sh" 2>/dev/null
    fi
    ;;
  set_profile)
    # 切换设备方案: set_profile <profile_name>
    echo "$2" > "$ACTIVE"
    # 如果全局属性开启，立即应用
    GLOBAL=$(grep '^global_resetprop=' "$SETTINGS" 2>/dev/null | cut -d= -f2)
    [ "$GLOBAL" = "1" ] && sh "$MODDIR/service.sh" 2>/dev/null
    echo "{\"profile\":\"$2\"}"
    ;;
  randomize)
    # 生成全新随机设备身份并持久化
    NEW_SN=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 16)
    NEW_FP_PRE="Xiaomi/socrates/socrates:13/TKQ1.221114.001/V14.0.$(( RANDOM % 99 )).0.TLCCNXM"
    NEW_FP="$NEW_FP_PRE:user/release-keys"
    # 写入新方案到配置
    cat >> "$PROFILES" <<EOF
[profile_random_$(date +%s)]
serialno=$NEW_SN
boot_serialno=$NEW_SN
fingerprint=$NEW_FP
model=2201123C
brand=Xiaomi
device=socrates
product=socrates
manufacturer=Xiaomi
hardware=qcom
board=lahaina
host=srv04-13.miui.com
build_id=TKQ1.221114.001
incremental=V14.0.4.0.TLCCNXM
security_patch=2023-02-01
release=13
sdk=33
type=user
tags=release-keys
line1=+8613$(( RANDOM % 900000000 + 100000000 ))
operator=46000
EOF
    echo "profile_random_$(date +%s)" > "$ACTIVE"
    GLOBAL=$(grep '^global_resetprop=' "$SETTINGS" 2>/dev/null | cut -d= -f2)
    [ "$GLOBAL" = "1" ] && sh "$MODDIR/service.sh" 2>/dev/null
    echo "{\"status\":\"randomized\",\"serialno\":\"$NEW_SN\"}"
    ;;
  log)
    # 读取日志: log <type> <lines>
    TYPE="${2:-app}"
    LINES="${3:-50}"
    case "$TYPE" in
      app) cat "$MODDIR/logs/app.log" 2>/dev/null | tail -n "$LINES" ;;
      net) cat "$MODDIR/logs/network.log" 2>/dev/null | tail -n "$LINES" ;;
      service) cat "$MODDIR/logs/service.log" 2>/dev/null | tail -n "$LINES" ;;
      boot) cat "$MODDIR/logs/boot.log" 2>/dev/null | tail -n "$LINES" ;;
      *) echo "unknown log type: $TYPE" ;;
    esac
    ;;
  clear_log)
    # 清空日志: clear_log <type>
    TYPE="${2:-all}"
    case "$TYPE" in
      all) rm -f "$MODDIR/logs/"*.log 2>/dev/null ;;
      app) > "$MODDIR/logs/app.log" 2>/dev/null ;;
      net) > "$MODDIR/logs/network.log" 2>/dev/null ;;
    esac
    echo "{\"cleared\":\"$TYPE\"}"
    ;;
  kill_app)
    # 强制停止漫城
    su -c "am force-stop com.hswl.car_owner" 2>/dev/null
    su -c "am force-stop com.hswl.cargo_owner.cargo_owner" 2>/dev/null
    echo "{\"status\":\"killed\"}"
    ;;
  get_props)
    # 返回当前真实设备属性
    echo "{"
    echo "\"ro_serialno\":\"$(getprop ro.serialno)\","
    echo "\"ro_build_fingerprint\":\"$(getprop ro.build.fingerprint)\","
    echo "\"ro_product_model\":\"$(getprop ro.product.model)\","
    echo "\"ro_product_brand\":\"$(getprop ro.product.brand)\","
    echo "\"ro_hardware\":\"$(getprop ro.hardware)\""
    echo "}"
    ;;
  diagnosis)
    # 综合诊断：native so 生效状态 + 漫城解锁状态
    echo "===== 设备属性（判断 native hook 是否生效）====="
    echo "ro.serialno        = $(getprop ro.serialno)"
    echo "ro.boot.serialno   = $(getprop ro.boot.serialno)"
    echo "ro.build.fingerprint = $(getprop ro.build.fingerprint)"
    echo "ro.product.model   = $(getprop ro.product.model)"
    echo "ro.product.brand   = $(getprop ro.product.brand)"
    echo "ro.hardware        = $(getprop ro.hardware)"
    echo ""
    echo "===== 漫城进程 ====="
    for pkg in com.hswl.car_owner com.hswl.cargo_owner.cargo_owner; do
      PID=$(pidof $pkg 2>/dev/null | tr ' ' '\n' | head -1)
      if [ -n "$PID" ]; then
        echo "$pkg : PID=$PID UID=$(awk '/^Uid/{print $2}' /proc/$PID/status 2>/dev/null)"
        CNT=$(grep -c "libcolamanga_hook" /proc/$PID/maps 2>/dev/null)
        echo "  libcolamanga_hook.so 加载: $([ "$CNT" -gt 0 ] && echo YES || echo NO)"
      else
        echo "$pkg : 未运行"
      fi
    done
    echo ""
    echo "===== 漫城解锁状态(lastAdTime) ====="
    cat /data/data/com.hswl.cargo_owner.cargo_owner/shared_prefs/FlutterSharedPreferences.xml 2>/dev/null | grep -oE 'lastAdTime[^/]*' || echo "  无 lastAdTime"
    echo "当前时间戳: $(date +%s%3N)"
    echo ""
    echo "===== 模块日志 ====="
    tail -n 10 "$MODDIR/logs/service.log" 2>/dev/null
    ;;
  connections)
    # 返回目标进程当前网络连接
    for pkg in com.hswl.car_owner com.hswl.cargo_owner.cargo_owner; do
      PID=$(pidof $pkg 2>/dev/null | tr ' ' '\n' | head -1)
      [ -z "$PID" ] && continue
      UID=$(awk '/^Uid/{print $2}' /proc/$PID/status 2>/dev/null)
      cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | awk -v u=$UID '{if($8==u && $4!="0A") print $2" -> "$3" state="$4}'
    done
    ;;
  frida)
    # frida start/stop/status
    case "$2" in
      start)
        sed "s/^frida_enabled=.*/frida_enabled=1/" "$SETTINGS" > "$MODDIR/run/.tmp" && mv "$MODDIR/run/.tmp" "$SETTINGS"
        # 反检测：改名 zyncd + 非标准端口 8799
        cp "$MODDIR/frida/frida-server" "$MODDIR/frida/zyncd" 2>/dev/null
        chmod 0755 "$MODDIR/frida/zyncd"
        nohup "$MODDIR/frida/zyncd" -l 127.0.0.1:8799 > "$MODDIR/logs/frida.log" 2>&1 &
        echo $! > "$MODDIR/run/frida.pid"
        echo "{\"frida\":\"started\",\"pid\":\"$(cat $MODDIR/run/frida.pid)\",\"port\":8799,\"name\":\"zyncd\"}"
        ;;
      stop)
        sed "s/^frida_enabled=.*/frida_enabled=0/" "$SETTINGS" > "$MODDIR/run/.tmp" && mv "$MODDIR/run/.tmp" "$SETTINGS"
        [ -f "$MODDIR/run/frida.pid" ] && kill "$(cat "$MODDIR/run/frida.pid")" 2>/dev/null
        echo "{\"frida\":\"stopped\"}"
        ;;
      status)
        PID=$(cat "$MODDIR/run/frida.pid" 2>/dev/null)
        if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
          echo "{\"frida\":\"running\",\"pid\":\"$PID\",\"port\":8799,\"name\":\"zyncd\"}"
        else
          echo "{\"frida\":\"stopped\"}"
        fi
        ;;
      *) echo "{\"usage\":\"frida start|stop|status\"}" ;;
    esac
    ;;
  snapshot)
    SNAP="$MODDIR/snapshot"
    mkdir -p "$SNAP"
    for pkg in com.hswl.car_owner com.hswl.cargo_owner.cargo_owner; do
      D="/data/data/$pkg"
      [ -d "$D/shared_prefs" ] || continue
      rm -rf "$SNAP/$pkg" && mkdir -p "$SNAP/$pkg/shared_prefs"
      cp "$D"/shared_prefs/*.xml "$SNAP/$pkg/shared_prefs/" 2>/dev/null
      [ -f "$D/app_flutter/userbox.hive" ] && cp "$D/app_flutter/userbox.hive" "$SNAP/$pkg/" 2>/dev/null
    done
    echo "{\"snapshot\":\"saved\"}"
    ;;
  restore)
    SNAP="$MODDIR/snapshot"
    [ -d "$SNAP" ] || { echo "{\"error\":\"无快照，先 snapshot\"}"; exit 1; }
    for pkg in com.hswl.car_owner com.hswl.cargo_owner.cargo_owner; do
      D="/data/data/$pkg"
      [ -d "$SNAP/$pkg" ] || continue
      cp "$SNAP"/$pkg/shared_prefs/*.xml "$D/shared_prefs/" 2>/dev/null
      [ -f "$SNAP/$pkg/userbox.hive" ] && cp "$SNAP/$pkg/userbox.hive" "$D/app_flutter/" 2>/dev/null
    done
    echo "{\"restore\":\"done\"}"
    ;;
  safe_mode)
    case "$2" in
      on)
        for k in global_resetprop zygisk_hook anti_debug hide_root hide_xposed packet_capture signature_bypass; do
          sed "s/^$k=.*/$k=0/" "$SETTINGS" > "$MODDIR/run/.tmp" && cp "$MODDIR/run/.tmp" "$SETTINGS"
        done
        echo "{\"safe_mode\":\"on\",\"所有hook关闭\"}"
        ;;
      off)
        for k in zygisk_hook anti_debug hide_root hide_xposed packet_capture app_log_monitor signature_bypass; do
          sed "s/^$k=.*/$k=1/" "$SETTINGS" > "$MODDIR/run/.tmp" && cp "$MODDIR/run/.tmp" "$SETTINGS"
        done
        echo "{\"safe_mode\":\"off\",\"hook恢复\"}"
        ;;
      *) echo "{\"usage\":\"safe_mode on|off\"}" ;;
    esac
    ;;
  logmon)
    # 按需开启/停止日志监控（防发烫，不常驻）
    case "$2" in
      start)
        PID=$(pidof com.hswl.cargo_owner.cargo_owner 2>/dev/null | tr ' ' '\n' | head -1)
        [ -z "$PID" ] && PID=$(pidof com.hswl.car_owner 2>/dev/null | tr ' ' '\n' | head -1)
        [ -z "$PID" ] && { echo "{\"error\":\"漫城未运行\"}"; exit 1; }
        nohup logcat --pid=$PID -v time 2>/dev/null | grep -iE 'cargo|mymanga|byazt|starlink|security|reward|unlock|device|adCount|reportAd|ColaManga' >> "$MODDIR/logs/app.log" 2>/dev/null &
        echo $! > "$MODDIR/run/logmon.pid"
        echo "{\"logmon\":\"started\",\"pid\":\"$(cat $MODDIR/run/logmon.pid)\"}"
        ;;
      stop)
        [ -f "$MODDIR/run/logmon.pid" ] && kill "$(cat "$MODDIR/run/logmon.pid")" 2>/dev/null
        rm -f "$MODDIR/run/logmon.pid"
        echo "{\"logmon\":\"stopped\"}"
        ;;
      *) echo "{\"usage\":\"logmon start|stop\"}" ;;
    esac
    ;;
  capture)
    # 按需开启/停止网络抓包（防发烫，不常驻）
    case "$2" in
      start)
        nohup sh -c '
          while true; do
            for pkg in com.hswl.car_owner com.hswl.cargo_owner.cargo_owner; do
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
        echo $! > "$MODDIR/run/capture.pid"
        echo "{\"capture\":\"started\"}"
        ;;
      stop)
        [ -f "$MODDIR/run/capture.pid" ] && kill "$(cat "$MODDIR/run/capture.pid")" 2>/dev/null
        rm -f "$MODDIR/run/capture.pid"
        echo "{\"capture\":\"stopped\"}"
        ;;
      *) echo "{\"usage\":\"capture start|stop\"}" ;;
    esac
    ;;
  *)
    echo "Usage: control.sh <status|toggle|set_profile|randomize|log|clear_log|kill_app|get_props|connections|diagnosis|frida|snapshot|restore|safe_mode|logmon|capture>"
    ;;
esac