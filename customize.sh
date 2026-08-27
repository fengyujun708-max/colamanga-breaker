#!/system/bin/sh
# ====== Colamanga 破甲模块 - 安装脚本 ======
# customize.sh - Magisk 安装时执行

SKIPUNZIP=0

ui_print "==============================="
ui_print "Colamanga Ultimate Breaker"
ui_print "宇宙无敌破甲模块 v1.0.0"
ui_print "==============================="
ui_print "目标: com.hswl.car_owner"
ui_print "      com.hswl.cargo_owner.cargo_owner"
ui_print ""

# 创建工作目录
MODDIR=$MODPATH
mkdir -p "$MODDIR/config" "$MODDIR/logs" "$MODDIR/run" "$MODDIR/rules" "$MODDIR/webui"

# 复制核心文件
cp -f "$MODPATH/module.prop" "$MODDIR/module.prop" 2>/dev/null
cp -f "$MODPATH/service.sh" "$MODDIR/service.sh" 2>/dev/null
cp -f "$MODPATH/post-fs-data.sh" "$MODDIR/post-fs-data.sh" 2>/dev/null
cp -f "$MODPATH/config/fake_device.conf" "$MODDIR/config/fake_device.conf" 2>/dev/null

# 初始化配置（不覆盖已有）
[ -f "$MODDIR/config/settings.conf" ] || cat > "$MODDIR/config/settings.conf" <<'EOF'
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
target_packages=com.hswl.car_owner,com.hswl.cargo_owner.cargo_owner
webui_port=8799
EOF

# 初始化设备身份（持久化，首次安装生成）
[ -f "$MODDIR/config/active_profile" ] || echo "profile_xiaomi" > "$MODDIR/config/active_profile"

# 权限
set_perm_recursive "$MODDIR" 0 0 0755 0644
set_perm "$MODDIR/service.sh" 0 0 0755
set_perm "$MODDIR/post-fs-data.sh" 0 0 0755

ui_print "✓ 模块安装完成"
ui_print "✓ 默认设备方案: Xiaomi Redmi Note 12 Pro"
ui_print "✓ 身份模式: 持久锁定（防止广告重置）"
ui_print ""
ui_print "请在 Magisk Manager 中启用 Zygisk"
ui_print "然后在模块页面点击 WebUI 进入总控面板"
ui_print "或浏览器访问 http://127.0.0.1:8799"