#!/bin/sh
cd /var/minis/workspace/colamanga_mod || exit 1
rm -rf /tmp/cola_pkg && mkdir -p /tmp/cola_pkg/zygisk /tmp/cola_pkg/config /tmp/cola_pkg/control /tmp/cola_pkg/webroot /tmp/cola_pkg/frida /tmp/cola_pkg/META-INF/com/google/android
cp module.prop customize.sh service.sh post-fs-data.sh uninstall.sh /tmp/cola_pkg/
cp config/fake_device.conf config/config.json config/hooks.conf config/net_blocklist.txt /tmp/cola_pkg/config/ 2>/dev/null
cp control/control.sh /tmp/cola_pkg/control/
cp webroot/index.html /tmp/cola_pkg/webroot/
cp META-INF/com/google/android/update-binary /tmp/cola_pkg/META-INF/com/google/android/
cp META-INF/com/google/android/updater-script /tmp/cola_pkg/META-INF/com/google/android/
[ -f zygisk/arm64-v8a.so ] && cp zygisk/arm64-v8a.so /tmp/cola_pkg/zygisk/
[ -f zygisk/libcolamanga_hook.so ] && cp zygisk/libcolamanga_hook.so /tmp/cola_pkg/zygisk/
[ -f frida/frida-server ] && cp frida/frida-server /tmp/cola_pkg/frida/ && chmod 0755 /tmp/cola_pkg/frida/frida-server
chmod 0755 /tmp/cola_pkg/service.sh /tmp/cola_pkg/post-fs-data.sh /tmp/cola_pkg/customize.sh /tmp/cola_pkg/uninstall.sh /tmp/cola_pkg/control/control.sh
cd /tmp/cola_pkg
rm -f /var/minis/workspace/ColamangaUltimateBreaker.zip
zip -r /var/minis/workspace/ColamangaUltimateBreaker.zip . -x ".*"
echo "打包完成: $(stat -c%s /var/minis/workspace/ColamangaUltimateBreaker.zip) bytes"
unzip -l /var/minis/workspace/ColamangaUltimateBreaker.zip | tail -25
