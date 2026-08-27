#!/bin/sh
# ============ Colamanga Ultimate Breaker 打包脚本 ============
# 在沙箱或 PC 上运行，打包 Magisk 安装 zip（不含 Zygisk so）
# 使用: sh pack.sh

cd /var/minis/workspace/colamanga_mod || exit 1
rm -rf /tmp/cola_pkg
mkdir -p /tmp/cola_pkg/zygisk /tmp/cola_pkg/config /tmp/cola_pkg/control \
         /tmp/cola_pkg/webui /tmp/cola_pkg/META-INF/com/google/android

# 复制核心文件
cp module.prop customize.sh service.sh post-fs-data.sh uninstall.sh /tmp/cola_pkg/
cp config/fake_device.conf config/config.json /tmp/cola_pkg/config/
cp control/control.sh /tmp/cola_pkg/control/
cp webui/index.html /tmp/cola_pkg/webui/
cp META-INF/com/google/android/update-binary /tmp/cola_pkg/META-INF/com/google/android/
cp META-INF/com/google/android/updater-script /tmp/cola_pkg/META-INF/com/google/android/
[ -f zygisk/arm64-v8a.so ] && cp zygisk/arm64-v8a.so /tmp/cola_pkg/zygisk/ || \
  echo "WARNING: zygisk/arm64-v8a.so 不存在（需 GitHub Actions 编译）"

# 设置权限
chmod 0755 /tmp/cola_pkg/service.sh /tmp/cola_pkg/post-fs-data.sh /tmp/cola_pkg/customize.sh \
            /tmp/cola_pkg/uninstall.sh /tmp/cola_pkg/control/control.sh
chmod 0644 /tmp/cola_pkg/module.prop /tmp/cola_pkg/config/* /tmp/cola_pkg/webui/index.html

# 打包
cd /tmp/cola_pkg
rm -f /var/minis/workspace/ColamangaUltimateBreaker.zip
zip -r /var/minis/workspace/ColamangaUltimateBreaker.zip . -x ".*"
echo "=== 打包完成 ==="
ls -la /var/minis/workspace/ColamangaUltimateBreaker.zip
echo "=== 内容 ==="
unzip -l /var/minis/workspace/ColamangaUltimateBreaker.zip