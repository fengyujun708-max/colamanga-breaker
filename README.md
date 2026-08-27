# Colamanga Ultimate Breaker 🚀

宇宙无敌 colamanga 破甲 Magisk 模块

## 目标
- `com.hswl.car_owner`
- `com.hswh.cargo_owner.cargo_owner`

## 功能

| 功能 | 说明 | 默认 |
|------|------|------|
| 硬件属性伪造 | resetprop 全套 ro.* 属性（3 套方案）| 关 |
| Zygisk 原生 hook | so 层 __system_property_get/ptrace/openat/connect | 开 |
| 反调试屏蔽 | ptrace 返回失败 + TracerPid 清零 | 开 |
| Root 隐藏 | 隐藏 su/magisk/zygisk 文件（仅目标进程）| 开 |
| 超级抓包 | 记录所有网络连接 IP/端口 | 开 |
| 日志监控 | logcat 过滤漫城关键词 | 开 |
| 签名绕过 | hook PackageManager/Signature | 开 |
| 身份持久化 | 锁定设备指纹不变，防广告重置 | 开 |

## 安装

1. 下载 `ColamangaUltimateBreaker.zip`
2. Magisk Manager → 模块 → 从存储安装
3. 确保 Zygisk 已启用
4. 重启
5. 模块列表点击 WebUI 进入总控面板

## 编译 Zygisk so

GitHub Actions 自动编译，或本地：

```bash
NDK=/path/to/android-ndk-r25c
$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android21-clang++ \
  -shared -fPIC -O2 -std=c++17 -I. -o zygisk/arm64-v8a.so \
  zygisk/colamanga_hook.cpp -ldl -llog -landroid \
  -Wl,--exclude-libs,ALL -Wl,--gc-sections \
  -ffunction-sections -fdata-sections -DZYGISK_API_VERSION=4
```

## WebUI

Magisk Manager 模块页点击 WebUI，或浏览器访问 `http://127.0.0.1:8799`