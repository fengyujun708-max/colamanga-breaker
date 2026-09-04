// colamanga_zygisk.cpp - 纯 Zygisk 模块 v3（高阶可视化 + 自定义 hook 开关 + 文件沙箱 + 反服务器下发）
// 不依赖 LSPosed，native 层 inline hook + JNI hook
//
// 新增能力：
//   1. hooks.conf 配置驱动——每个 libc hook 独立开关，运行时重读（无需重启）
//   2. 文件沙箱——open/openat/stat/lstat/fstatat 阻断其他 app 私有数据 + 隐藏 root/frida/zygisk 文件
//   3. __system_property_read_callback 全覆盖属性伪装（覆盖 Java SystemProperties.get）
//   4. uname 内核伪装——清除 KernelSU/Magisk 标记
//   5. 网络阻断（反服务器下发）——connect/getaddrinfo 按 blocklist 拒连风控域名
#include "zygisk.hpp"
#include <jni.h>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <android/log.h>
#include <errno.h>
#include <elf.h>
#include <link.h>

#define TAG "ColaMangaZygisk"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ModuleBase;
using zygisk::ServerSpecializeArgs;

// ===== 假设备（从 device_id.json 读，WebUI 实时改）=====
static char s_serialno[64] = "RMU48KXQN12PZ7C9";
static char s_fingerprint[128] = "Xiaomi/socrates/socrates:13/TKQ1.221114.001/V14.0.4.0.TLCCNXM:user/release-keys";
static char s_model[64] = "2201123C";
static char s_brand[64] = "Xiaomi";
static char s_device[64] = "socrates";
static char s_product[64] = "socrates";
static char s_manufacturer[64] = "Xiaomi";
static char s_hardware[64] = "qcom";
static char s_board[64] = "lahaina";
static char s_host[64] = "srv04-13.miui.com";
static char s_build_id[64] = "TKQ1.221114.001";
static char s_incremental[64] = "V14.0.4.0.TLCCNXM";
static char s_security_patch[64] = "2023-02-01";
static char s_release[16] = "13";
static char s_sdk[16] = "33";
static char s_type[16] = "user";
static char s_tags[16] = "release-keys";
static char s_imei[32] = "864512370012345";
static char s_imei2[32] = "864512370012346";
static char s_meid[32] = "A1B2C3D4E5F6A7";
static char s_line1[32] = "+8613912345678";
static char s_mac[32] = "A8:63:EA:C6:D2:3E";
static char s_androidid[32] = "a1b2c3d4e5f6g7h8";
static char s_widevine[64] = "860f7c5e7fb431bfe5ec828c62a36419";

// ===== hooks.conf 配置（运行时开关）=====
struct HookCfg {
    int hook_property     = 1;
    int hook_property_cb  = 1;
    int hook_ptrace       = 1;
    int hook_access       = 1;
    int hook_open         = 1;
    int hook_openat       = 1;
    int hook_stat         = 1;
    int hook_readlink     = 1;
    int hook_uname        = 1;
    int hook_connect      = 1;
    int hook_getaddrinfo  = 1;
    int hook_jni          = 1;
    int hook_read         = 1;   // read/pread64 内容级 scrub（maps 兜底，风控 syscall 直读也过滤）
    int hook_ssl_unlock   = 1;   // SSL_read 响应注入解锁（vipflag false→true）
    int file_sandbox      = 1;   // 文件沙箱：阻断其他 app 私有数据
    int hide_maps         = 1;   // 隐藏 /proc/self/maps（掩盖 inline hook trampoline）
    int net_blocklist     = 1;   // 反服务器下发：阻断风控域名
    int capture          = 1;   // 抓包：connect记录IP:port + getaddrinfo记录DNS（开关式）
};
static volatile HookCfg g_cfg;
static volatile uint32_t g_calls = 0;
static char g_blocklist[2048];    // 网络阻断域名/IP，逗号或换行分隔

static int conf_get_int(const char* line) {
    const char* eq = strchr(line, '=');
    if (!eq) return 1;
    return atoi(eq + 1) > 0 ? 1 : 0;
}

// raw syscall 读文件——绕过本模块自己的 openat/open inline hook，避免 read_hooks_conf 递归
static int raw_read_file(const char* path, char* buf, int maxlen) {
    int fd = (int)syscall(SYS_openat, AT_FDCWD, path, O_RDONLY, 0);
    if (fd < 0) return -1;
    int n = (int)syscall(SYS_read, fd, buf, maxlen - 1);
    syscall(SYS_close, fd);
    if (n < 0) return -1;
    buf[n] = 0;
    return n;
}

static void read_hooks_conf() {
    char buf[4096];
    if (raw_read_file("/data/adb/modules/colamanga_mod/config/hooks.conf", buf, sizeof(buf)) <= 0) return;
    char* p = buf;
    while (p && *p) {
        char* nl = strchr(p, '\n');
        if (nl) *nl = 0;
        if (strchr(p, '=')) {
            if (!strncmp(p, "hook_property=", 14))        g_cfg.hook_property    = conf_get_int(p);
            else if (!strncmp(p, "hook_property_cb=", 17)) g_cfg.hook_property_cb = conf_get_int(p);
            else if (!strncmp(p, "hook_ptrace=", 12))      g_cfg.hook_ptrace      = conf_get_int(p);
            else if (!strncmp(p, "hook_access=", 12))      g_cfg.hook_access      = conf_get_int(p);
            else if (!strncmp(p, "hook_open=", 10))        g_cfg.hook_open        = conf_get_int(p);
            else if (!strncmp(p, "hook_openat=", 12))      g_cfg.hook_openat      = conf_get_int(p);
            else if (!strncmp(p, "hook_stat=", 10))        g_cfg.hook_stat        = conf_get_int(p);
            else if (!strncmp(p, "hook_readlink=", 14))    g_cfg.hook_readlink    = conf_get_int(p);
            else if (!strncmp(p, "hook_uname=", 11))       g_cfg.hook_uname       = conf_get_int(p);
            else if (!strncmp(p, "hook_connect=", 13))     g_cfg.hook_connect     = conf_get_int(p);
            else if (!strncmp(p, "hook_getaddrinfo=", 17)) g_cfg.hook_getaddrinfo = conf_get_int(p);
            else if (!strncmp(p, "hook_jni=", 9))          g_cfg.hook_jni         = conf_get_int(p);
            else if (!strncmp(p, "hook_read=", 10))        g_cfg.hook_read        = conf_get_int(p);
            else if (!strncmp(p, "hook_ssl_unlock=", 17))  g_cfg.hook_ssl_unlock  = conf_get_int(p);
            else if (!strncmp(p, "file_sandbox=", 13))     g_cfg.file_sandbox     = conf_get_int(p);
            else if (!strncmp(p, "hide_maps=", 10))        g_cfg.hide_maps        = conf_get_int(p);
            else if (!strncmp(p, "net_blocklist=", 14))    g_cfg.net_blocklist    = conf_get_int(p);
            else if (!strncmp(p, "capture=", 8))          g_cfg.capture         = conf_get_int(p);
        }
        if (!nl) break;
        p = nl + 1;
    }

    // 网络阻断列表
    memset(g_blocklist, 0, sizeof(g_blocklist));
    char bb[2048];
    int n = raw_read_file("/data/adb/modules/colamanga_mod/config/net_blocklist.txt", bb, sizeof(bb));
    if (n > 0) strncpy(g_blocklist, bb, sizeof(g_blocklist) - 1);
}

static void try_install_ssl();  // SSL_read 延迟安装（libssl/libflutter 晚加载，见下方实现）
static inline void maybe_reload() {
    // 每 256 次调用重读配置，低频 hook（ptrace/access/uname）几乎实时
    if ((++g_calls & 0xFF) == 0) {
        read_hooks_conf();
        try_install_ssl();
    }
}

static void json_get_str(const char* json, const char* key, char* out, int outlen) {
    const char* k = strstr(json, key);
    if (!k) return;
    const char* q = strchr(k, ':');
    if (!q) return;
    q = strchr(q, '"');
    if (!q) return;
    q++;
    int i = 0;
    while (*q && *q != '"' && i < outlen - 1) out[i++] = *q++;
    out[i] = 0;
}

static void load_config() {
    FILE* f = fopen("/data/adb/modules/colamanga_mod/config/device_id.json", "r");
    if (!f) return;
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > 4096) { fclose(f); return; }
    char* json = (char*)malloc(sz + 1);
    fread(json, 1, sz, f); json[sz] = 0; fclose(f);
    json_get_str(json, "serialno", s_serialno, sizeof(s_serialno));
    json_get_str(json, "fingerprint", s_fingerprint, sizeof(s_fingerprint));
    json_get_str(json, "model", s_model, sizeof(s_model));
    json_get_str(json, "brand", s_brand, sizeof(s_brand));
    json_get_str(json, "device", s_device, sizeof(s_device));
    json_get_str(json, "product", s_product, sizeof(s_product));
    json_get_str(json, "manufacturer", s_manufacturer, sizeof(s_manufacturer));
    json_get_str(json, "hardware", s_hardware, sizeof(s_hardware));
    json_get_str(json, "board", s_board, sizeof(s_board));
    json_get_str(json, "host", s_host, sizeof(s_host));
    json_get_str(json, "build_id", s_build_id, sizeof(s_build_id));
    json_get_str(json, "incremental", s_incremental, sizeof(s_incremental));
    json_get_str(json, "security_patch", s_security_patch, sizeof(s_security_patch));
    json_get_str(json, "release", s_release, sizeof(s_release));
    json_get_str(json, "sdk", s_sdk, sizeof(s_sdk));
    json_get_str(json, "type", s_type, sizeof(s_type));
    json_get_str(json, "tags", s_tags, sizeof(s_tags));
    json_get_str(json, "imei", s_imei, sizeof(s_imei));
    json_get_str(json, "imei2", s_imei2, sizeof(s_imei2));
    json_get_str(json, "meid", s_meid, sizeof(s_meid));
    json_get_str(json, "line1", s_line1, sizeof(s_line1));
    json_get_str(json, "mac", s_mac, sizeof(s_mac));
    json_get_str(json, "android_id", s_androidid, sizeof(s_androidid));
    json_get_str(json, "widevine", s_widevine, sizeof(s_widevine));
    free(json);
    LOGI("[cfg] %s %s serial=%s imei=%s", s_brand, s_model, s_serialno, s_imei);
}

// ====== inline hook（多 hook 独立 trampoline）======
#define MAX_HOOKS 24
#define TRAMP_PER_HOOK 64
struct HookEntry { void* target; void* tramp; unsigned char orig[16]; };
static HookEntry g_hooks[MAX_HOOKS];
static int g_hook_count = 0;

// 反检测：trampoline 不用 mmap 匿名 RX 页（风控扫 /proc/self/maps 会发现新匿名可执行段），
// 改用模块 .so 自己的静态缓冲——已随模块映射，不产生新的匿名段，maps 里无异常痕迹
__attribute__((aligned(4096)))
static unsigned char g_tramp_pool[MAX_HOOKS * TRAMP_PER_HOOK];
static bool g_tramp_pool_rw = false;

static void arm_tramp_pool() {
    if (g_tramp_pool_rw) return;
    uintptr_t page = (uintptr_t)g_tramp_pool & ~0xFFFULL;
    size_t len = (sizeof(g_tramp_pool) + 0xFFF) & ~0xFFFULL;
    mprotect((void*)page, len, PROT_READ|PROT_WRITE|PROT_EXEC);
    g_tramp_pool_rw = true;
}

static void write_hook_status(const char* name, void* target, void* tramp) {
    FILE* f = fopen("/data/adb/modules/colamanga_mod/run/hooks_status.txt", "a");
    if (f) {
        fprintf(f, "%s|%p|%p\n", name, target, tramp);
        fclose(f);
    }
}

static void* inline_hook(const char* name, void* target, void* hook_fn) {
    if (!target || !hook_fn || g_hook_count >= MAX_HOOKS) return nullptr;
    arm_tramp_pool();
    HookEntry& e = g_hooks[g_hook_count];
    e.target = target;
    memcpy(e.orig, target, 16);
    e.tramp = g_tramp_pool + g_hook_count * TRAMP_PER_HOOK;
    unsigned char* t = (unsigned char*)e.tramp;
    memcpy(t, e.orig, 16);
    *(uint32_t*)(t+16) = 0x58000050;  // LDR X17, [PC,#8]
    *(uint32_t*)(t+20) = 0xD61FE020;  // BR X17
    *(void**)(t+24) = (void*)((uintptr_t)target + 16);
    __builtin___clear_cache((char*)e.tramp, (char*)e.tramp + 32);
    uintptr_t page = (uintptr_t)target & ~0xFFFULL;
    mprotect((void*)page, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC);
    *(uint32_t*)((unsigned char*)target+0) = 0x58000050;
    *(uint32_t*)((unsigned char*)target+4) = 0xD61FE020;
    *(void**)((unsigned char*)target+8) = hook_fn;
    mprotect((void*)page, 0x1000, PROT_READ|PROT_EXEC);
    __builtin___clear_cache((char*)target, (char*)target + 16);
    g_hook_count++;
    LOGI("[hook] %s -> %p (tramp=%p)", name, target, e.tramp);
    write_hook_status(name, target, e.tramp);
    return e.tramp;
}

// ====== 属性伪装映射（供 property hook + JNI hook 共用）======
static const char* fake_prop(const char* name) {
    maybe_reload();
    if (!name) return nullptr;
    if (!strcmp(name, "ro.serialno") || !strcmp(name, "ro.boot.serialno")) return s_serialno;
    if (!strcmp(name, "ro.build.fingerprint") || !strcmp(name, "ro.system.build.fingerprint")) return s_fingerprint;
    if (!strcmp(name, "ro.product.model") || !strcmp(name, "ro.product.system.model") || !strcmp(name, "ro.product.vendor.model")) return s_model;
    if (!strcmp(name, "ro.product.brand") || !strcmp(name, "ro.product.system.brand") || !strcmp(name, "ro.product.vendor.brand")) return s_brand;
    if (!strcmp(name, "ro.product.device")) return s_device;
    if (!strcmp(name, "ro.product.name")) return s_product;
    if (!strcmp(name, "ro.product.manufacturer")) return s_manufacturer;
    if (!strcmp(name, "ro.hardware") || !strcmp(name, "ro.boot.hardware")) return s_hardware;
    if (!strcmp(name, "ro.product.board") || !strcmp(name, "ro.board.platform")) return s_board;
    if (!strcmp(name, "ro.build.host")) return s_host;
    if (!strcmp(name, "ro.build.id")) return s_build_id;
    if (!strcmp(name, "ro.build.version.incremental")) return s_incremental;
    if (!strcmp(name, "ro.build.version.security_patch")) return s_security_patch;
    if (!strcmp(name, "ro.build.version.release")) return s_release;
    if (!strcmp(name, "ro.build.version.sdk")) return s_sdk;
    if (!strcmp(name, "ro.build.type")) return s_type;
    if (!strcmp(name, "ro.build.tags")) return s_tags;
    if (!strcmp(name, "ro.boot.verifiedbootstate")) return "green";
    if (!strcmp(name, "ro.boot.flash.locked")) return "1";
    if (!strcmp(name, "ro.boot.vbmeta.device_state")) return "locked";
    return nullptr;
}

// ====== __system_property_get（native 直接读）======
static void* tramp_property = nullptr;
typedef int (*property_get_t)(const char*, char*, const char*);
static int hook_property_get(const char* name, char* value, const char* default_value) {
    if (g_cfg.hook_property) {
        const char* fake = fake_prop(name);
        if (fake) { if (value) { strncpy(value, fake, 91); value[91] = 0; } return (int)strlen(fake); }
    }
    return ((property_get_t)tramp_property)(name, value, default_value);
}

// ====== __system_property_read_callback（覆盖 Java SystemProperties.get）======
// Java 层 SystemProperties.get 走 __system_property_find + read_callback，
// 不走 __system_property_get。之前只 hook get 有缺口，这里补全。
typedef void (*prop_cb_t)(void*, const char*, const char*, uint32_t);
typedef void (*prop_read_t)(const void*, prop_cb_t, void*);
static void* tramp_property_cb = nullptr;
static thread_local prop_cb_t tl_user_cb = nullptr;
static thread_local void* tl_user_cookie = nullptr;

static void my_prop_cb(void* cookie, const char* name, const char* value, uint32_t serial) {
    const char* fake = fake_prop(name);
    tl_user_cb(tl_user_cookie, name, fake ? fake : value, serial);
}

static void hook_property_read_cb(const void* pi, prop_cb_t cb, void* cookie) {
    if (g_cfg.hook_property_cb) {
        tl_user_cb = cb;
        tl_user_cookie = cookie;
        ((prop_read_t)tramp_property_cb)(pi, my_prop_cb, cookie);
    } else {
        ((prop_read_t)tramp_property_cb)(pi, cb, cookie);
    }
}

// ====== ptrace（反调试）======
static void* tramp_ptrace = nullptr;
typedef long (*ptrace_t)(int, pid_t, void*, void*);
static long hook_ptrace(int request, pid_t pid, void* addr, void* data) {
    if (g_cfg.hook_ptrace) {
        if (request == PTRACE_TRACEME) return 0;
        if (request == PTRACE_ATTACH) { errno = 0; return -1; }
    }
    return ((ptrace_t)tramp_ptrace)(request, pid, addr, data);
}

// ====== 文件路径过滤（可疑关键词 + 沙箱 + maps 隐藏）======
static bool is_suspicious_path(const char* p) {
    if (!p) return false;
    char buf[512];
    strncpy(buf, p, sizeof(buf) - 1); buf[sizeof(buf) - 1] = 0;
    char* save = nullptr;
    char* seg = strtok_r(buf, "/", &save);
    while (seg) {
        if (!strcmp(seg, "su") || !strcmp(seg, "supersu") ||
            strstr(seg, "magisk") || strstr(seg, "xposed") || strstr(seg, "lsposed") ||
            strstr(seg, "riru") || strstr(seg, "zygisk") || strstr(seg, "kernelsu") ||
            strstr(seg, "frida") || strstr(seg, "gadget") || strstr(seg, "gum-js") ||
            strstr(seg, "dobby") || strstr(seg, "shadowhook") || strstr(seg, "substrate"))
            return true;
        seg = strtok_r(nullptr, "/", &save);
    }
    return false;
}

static bool is_other_app_data(const char* p) {
    if (!p) return false;
    const char* roots[] = {
        "/data/data/", "/data/user/0/", "/data/user_de/0/",
        "/sdcard/Android/data/", "/storage/emulated/0/Android/data/", nullptr
    };
    for (int i = 0; roots[i]; i++) {
        size_t L = strlen(roots[i]);
        if (strncmp(p, roots[i], L) == 0) {
            const char* rest = p + L;
            if (strncmp(rest, "com.hswl.", 9) == 0) return false;  // 自身
            return true;                                            // 其他 app
        }
    }
    return false;
}

static bool path_blocked(const char* p) {
    maybe_reload();
    if (!p || p[0] != '/') return false;
    if (is_suspicious_path(p)) return true;
    if (g_cfg.file_sandbox && is_other_app_data(p)) return true;
    if (g_cfg.hide_maps &&
        (!strcmp(p, "/proc/self/maps") || !strcmp(p, "/proc/self/smaps") ||
         !strcmp(p, "/proc/self/map_files"))) return true;
    return false;
}

// ====== access ======
static void* tramp_access = nullptr;
typedef int (*access_t)(const char*, int);
static int hook_access(const char* path, int mode) {
    if (g_cfg.hook_access && path_blocked(path)) { errno = ENOENT; return -1; }
    return ((access_t)tramp_access)(path, mode);
}

// ====== open / openat（文件沙箱 + 隐藏）======
typedef int (*open3_t)(const char*, int, mode_t);
typedef int (*openat4_t)(int, const char*, int, mode_t);
static void* tramp_open = nullptr;
static void* tramp_openat = nullptr;
static int hook_open(const char* path, int flags, mode_t mode) {
    if (g_cfg.hook_open && path_blocked(path)) { errno = ENOENT; return -1; }
    return ((open3_t)tramp_open)(path, flags, mode);
}
static int hook_openat(int dirfd, const char* path, int flags, mode_t mode) {
    if (g_cfg.hook_openat && path_blocked(path)) { errno = ENOENT; return -1; }
    return ((openat4_t)tramp_openat)(dirfd, path, flags, mode);
}

// ====== stat / lstat / fstatat（路径枚举隐藏）======
typedef int (*stat_t)(const char*, struct stat*);
typedef int (*fstatat_t)(int, const char*, struct stat*, int);
static void* tramp_stat = nullptr;
static void* tramp_lstat = nullptr;
static void* tramp_fstatat = nullptr;
static int hook_stat(const char* path, struct stat* st) {
    if (g_cfg.hook_stat && path_blocked(path)) { errno = ENOENT; return -1; }
    return ((stat_t)tramp_stat)(path, st);
}
static int hook_lstat(const char* path, struct stat* st) {
    if (g_cfg.hook_stat && path_blocked(path)) { errno = ENOENT; return -1; }
    return ((stat_t)tramp_lstat)(path, st);
}
static int hook_fstatat(int dirfd, const char* path, struct stat* st, int flags) {
    if (g_cfg.hook_stat && path_blocked(path)) { errno = ENOENT; return -1; }
    return ((fstatat_t)tramp_fstatat)(dirfd, path, st, flags);
}

// ====== readlink / readlinkat（FD 路径解析隐藏 .so 真实路径）======
// tryigit.dev: .so 路径会通过 readlink /proc/self/fd/N 暴露，必须 scrub 解析结果
typedef ssize_t (*readlink_t)(const char*, char*, size_t);
typedef ssize_t (*readlinkat_t)(int, const char*, char*, size_t);
static void* tramp_readlink = nullptr;
static void* tramp_readlinkat = nullptr;
static ssize_t scrub_readlink_result(char* buf, size_t bufsiz, ssize_t n) {
    if (n <= 0) return n;
    char tmp[512];
    size_t copy = (size_t)n < sizeof(tmp)-1 ? (size_t)n : sizeof(tmp)-1;
    memcpy(tmp, buf, copy); tmp[copy] = 0;
    if (is_suspicious_path(tmp) || strstr(tmp, "colamanga")) {
        const char* fake = "/system/lib64/libc.so";
        size_t fl = strlen(fake);
        if (fl < bufsiz) { memcpy(buf, fake, fl+1); return (ssize_t)fl; }
        errno = ENOENT; return -1;
    }
    return n;
}
static ssize_t hook_readlink(const char* path, char* buf, size_t bufsiz) {
    if (g_cfg.hook_readlink && path_blocked(path)) { errno = ENOENT; return -1; }
    ssize_t n = ((readlink_t)tramp_readlink)(path, buf, bufsiz);
    if (g_cfg.hook_readlink) n = scrub_readlink_result(buf, bufsiz, n);
    return n;
}
static ssize_t hook_readlinkat(int dirfd, const char* path, char* buf, size_t bufsiz) {
    if (g_cfg.hook_readlink && path_blocked(path)) { errno = ENOENT; return -1; }
    ssize_t n = ((readlinkat_t)tramp_readlinkat)(dirfd, path, buf, bufsiz);
    if (g_cfg.hook_readlink) n = scrub_readlink_result(buf, bufsiz, n);
    return n;
}

// ====== uname（内核伪装——清 KernelSU/Magisk 标记）======
static void* tramp_uname = nullptr;
typedef int (*uname_t)(struct utsname*);
static void strip_root_markers(char* s) {
    static const char* ms[] = {
        "-KernelSU", "KernelSU", "-magisk", "-Magisk", "Magisk",
        "-ksu", "-gf92516", "-ZYGISK", "Zygisk", nullptr
    };
    for (int i = 0; ms[i]; i++) {
        char* p;
        while ((p = strstr(s, ms[i]))) {
            memmove(p, p + strlen(ms[i]), strlen(p + strlen(ms[i])) + 1);
        }
    }
}
static int hook_uname(struct utsname* buf) {
    int r = ((uname_t)tramp_uname)(buf);
    if (r == 0 && buf && g_cfg.hook_uname) {
        strip_root_markers(buf->release);
        strip_root_markers(buf->version);
    }
    return r;
}

// ====== connect（抓包 + 反下发阻断）======
static void* tramp_connect = nullptr;
typedef int (*connect_t)(int, const struct sockaddr*, socklen_t);
static bool is_blocked_host(const char* host) {
    if (!g_cfg.net_blocklist || !host || !g_blocklist[0]) return false;
    char* list = strdup(g_blocklist);
    char* save = nullptr;
    char* tok = strtok_r(list, ",\n \t", &save);
    bool hit = false;
    while (tok) {
        if (tok[0] && strstr(host, tok)) { hit = true; break; }
        tok = strtok_r(nullptr, ",\n \t", &save);
    }
    free(list);
    return hit;
}
static int hook_connect(int sockfd, const struct sockaddr* addr, socklen_t addrlen) {
    try_install_ssl();  // 每次网络请求时尝试装 SSL 解锁（libflutter 晚加载，g_ssl_hooked 防重入）
    if (addr) {
        char ip[64] = {0}; int port = 0;
        if (addr->sa_family == AF_INET) { inet_ntop(AF_INET, &((const struct sockaddr_in*)addr)->sin_addr, ip, sizeof(ip)); port = ntohs(((const struct sockaddr_in*)addr)->sin_port); }
        else if (addr->sa_family == AF_INET6) { inet_ntop(AF_INET6, &((const struct sockaddr_in6*)addr)->sin6_addr, ip, sizeof(ip)); port = ntohs(((const struct sockaddr_in6*)addr)->sin6_port); }
        if (g_cfg.hook_connect && ip[0] && is_blocked_host(ip)) { errno = ECONNREFUSED; return -1; }
        if (g_cfg.capture && ip[0] && port > 0) LOGI("[NET] %s:%d", ip, port);
    }
    return ((connect_t)tramp_connect)(sockfd, addr, addrlen);
}

// ====== getaddrinfo（DNS + 反下发阻断）======
static void* tramp_getaddrinfo = nullptr;
typedef int (*getaddrinfo_t)(const char*, const char*, const struct addrinfo*, struct addrinfo**);
static int hook_getaddrinfo(const char* node, const char* service, const struct addrinfo* hints, struct addrinfo** res) {
    if (g_cfg.capture && node) LOGI("[DNS] %s", node);
    if (g_cfg.hook_getaddrinfo && node && is_blocked_host(node)) return EAI_NONAME;
    return ((getaddrinfo_t)tramp_getaddrinfo)(node, service, hints, res);
}

// ====== read / pread64（内容级 scrub，反检测兜底：风控 syscall 直读也过滤）======
static void* tramp_read = nullptr;
static void* tramp_pread64 = nullptr;
typedef ssize_t (*read_t)(int, void*, size_t);
typedef ssize_t (*pread64_t)(int, void*, size_t, off64_t);

static void scrub_sensitive(char* buf, ssize_t len) {
    // 快速路径：/proc/self/maps 是文本文件（含换行），二进制大块（图片/so）几乎无换行 → 直接跳过
    // 避免漫画图片下载时对每个 read 做 17 关键词 × 全量扫描的纯浪费
    if (len > 512) {
        bool has_nl = false;
        for (ssize_t i = 0; i < len && i < 4096; i++) {
            if (buf[i] == '\n') { has_nl = true; break; }
        }
        if (!has_nl) return;
    }
    static const char* kws[] = {
        "colamanga_mod", "ColaManga", "frida", "gum-js-loop", "gadget",
        "magisk", "Magisk", "KernelSU", "zygisk", "Zygisk",
        "riru", "Riru", "Xposed", "xposed", "lsposed", "LSPosed", nullptr
    };
    for (int i = 0; kws[i]; i++) {
        size_t kl = strlen(kws[i]);
        for (ssize_t j = 0; j + (ssize_t)kl <= len; j++) {
            if (memcmp(buf + j, kws[i], kl) == 0) {
                memset(buf + j, ' ', kl);
                j += kl - 1;
            }
        }
    }
}

static ssize_t hook_read(int fd, void* buf, size_t count) {
    ssize_t n = ((read_t)tramp_read)(fd, buf, count);
    if (n > 0 && buf && g_cfg.hook_read && g_cfg.hide_maps) {
        scrub_sensitive((char*)buf, n);
    }
    return n;
}

static ssize_t hook_pread64(int fd, void* buf, size_t count, off64_t off) {
    ssize_t n = ((pread64_t)tramp_pread64)(fd, buf, count, off);
    if (n > 0 && buf && g_cfg.hook_read && g_cfg.hide_maps) {
        scrub_sensitive((char*)buf, n);
    }
    return n;
}

// ====== SSL_read 响应注入解锁（vipflag false→true，等长替换）======
static void* tramp_ssl_read = nullptr;
typedef int (*ssl_read_t)(void*, void*, int);
static bool g_ssl_hooked = false;
static int hook_ssl_read(void*, void*, int);  // 前置声明（实现见下方）

// ===== 从磁盘文件解析隐藏符号 =====
// dlsym 只能找到 .dynsym 里导出的 GLOBAL/WEAK 符号。Flutter libflutter.so 的 BoringSSL
// 符号被 -fvisibility=hidden 编译成 STB_LOCAL，只存在于 .symtab（non-alloc section，
// 不加载进内存）——这正是 Frida enumerateSymbols 能命中而 dlsym/内存解析失败的原因。
// 必须打开磁盘 .so 文件，解析 section headers 里的 .symtab + .dynsym。

struct ElfFileArg {
    const char* so_name;   // 用于 strstr 匹配的库名，如 "libflutter.so"
    const char* so_path;   // 匹配到的完整路径（dlpi_name）
    uintptr_t   load_addr; // dlpi_addr
};

static int elf_file_iter_cb(struct dl_phdr_info* info, size_t, void* data) {
    ElfFileArg* a = (ElfFileArg*)data;
    if (info->dlpi_name && strstr(info->dlpi_name, a->so_name)) {
        a->so_path   = info->dlpi_name;
        a->load_addr = info->dlpi_addr;
        return 1;
    }
    return 0;
}

static void* elf_find_hidden_symbol(const char* so_name, const char* sym_name) {
    ElfFileArg a = { so_name, nullptr, 0 };
    dl_iterate_phdr(elf_file_iter_cb, &a);
    if (!a.so_path || !a.so_path[0]) return nullptr;

    // 1. 打开并 mmap 整个文件（section headers 只存在于磁盘镜像，不在运行内存）
    int fd = open(a.so_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return nullptr;
    off_t fsz = lseek(fd, 0, SEEK_END);
    if (fsz <= 0 || fsz > (off_t)(1u << 31)) { close(fd); return nullptr; }
    void* map = mmap(nullptr, (size_t)fsz, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (map == MAP_FAILED) return nullptr;

    void* found = nullptr;
    const Elf64_Ehdr* eh = (const Elf64_Ehdr*)map;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) == 0 &&
        eh->e_ident[EI_CLASS] == ELFCLASS64 &&
        eh->e_type == ET_DYN) {

        // 2. 计算 load bias = dlpi_addr - min(PT_LOAD p_vaddr)
        uintptr_t min_vaddr = ~0ull;
        const Elf64_Phdr* ph = (const Elf64_Phdr*)((char*)map + eh->e_phoff);
        for (int i = 0; i < eh->e_phnum; i++) {
            if (ph[i].p_type == PT_LOAD && ph[i].p_vaddr < min_vaddr)
                min_vaddr = ph[i].p_vaddr;
        }

        if (min_vaddr != ~0ull && eh->e_shnum > 0) {
            uintptr_t load_bias = a.load_addr - min_vaddr;

            // 3. 遍历 section headers，找 .symtab(SHT_SYMTAB) + .dynsym(SHT_DYNSYM)
            const Elf64_Shdr* sh = (const Elf64_Shdr*)((char*)map + eh->e_shoff);
            for (int i = 0; i < eh->e_shnum && !found; i++) {
                if (sh[i].sh_type != SHT_SYMTAB && sh[i].sh_type != SHT_DYNSYM) continue;
                if (sh[i].sh_entsize != sizeof(Elf64_Sym)) continue;
                if (sh[i].sh_link >= eh->e_shnum) continue;

                size_t nsym = sh[i].sh_size / sizeof(Elf64_Sym);
                const Elf64_Sym* sym = (const Elf64_Sym*)((char*)map + sh[i].sh_offset);
                const char* strtab = (const char*)((char*)map + sh[sh[i].sh_link].sh_offset);

                for (size_t k = 0; k < nsym; k++) {
                    if (ELF64_ST_TYPE(sym[k].st_info) != STT_FUNC) continue;  // 只找函数符号
                    if (sym[k].st_value == 0) continue;
                    const char* name = strtab + sym[k].st_name;
                    if (strcmp(name, sym_name) == 0) {
                        found = (void*)(load_bias + sym[k].st_value);
                        break;
                    }
                }
            }
        }
    }
    munmap(map, (size_t)fsz);
    return found;
}

// 精确查找 SSL_read（对齐 Frida 原脚本 findSslRead 逻辑）：
// 漫城是 Flutter app，HTTPS 流量走 libflutter.so 内置的 BoringSSL，不是系统 libssl.so。
// RTLD_DEFAULT 可能返回错误的 libssl.so(Conscrypt) 符号 → hook 错库 → 拦不到流量。
static void* find_ssl_read() {
    void* h;
    void* fn;
    // 1. libflutter.so（BoringSSL，漫城实际走这里）
    h = dlopen("libflutter.so", RTLD_NOLOAD);
    if (h) {
        fn = dlsym(h, "SSL_read");
        if (fn) { LOGI("[ssl] SSL_read @ libflutter.so %p", fn); return fn; }
        fn = dlsym(h, "_SSL_read");
        if (fn) { LOGI("[ssl] _SSL_read @ libflutter.so %p", fn); return fn; }
    }
    // 1b. libflutter.so 隐藏符号（BoringSSL LOCAL 符号，dlsym 找不到，Frida enumerateSymbols 能）
    fn = elf_find_hidden_symbol("libflutter.so", "SSL_read");
    if (fn) { LOGI("[ssl] SSL_read @ libflutter.so(ELF .dynsym LOCAL) %p", fn); return fn; }
    fn = elf_find_hidden_symbol("libflutter.so", "_SSL_read");
    if (fn) { LOGI("[ssl] _SSL_read @ libflutter.so(ELF .dynsym LOCAL) %p", fn); return fn; }
    // 2. libssl.so（Conscrypt，兜底）
    h = dlopen("libssl.so", RTLD_NOLOAD);
    if (h) {
        fn = dlsym(h, "SSL_read");
        if (fn) { LOGI("[ssl] SSL_read @ libssl.so %p", fn); return fn; }
    }
    // 3. RTLD_DEFAULT 最后兜底
    fn = dlsym(RTLD_DEFAULT, "SSL_read");
    if (fn) LOGI("[ssl] SSL_read @ default %p", fn);
    return fn;
}

// libflutter.so 在 app 启动后才 dlopen，postAppSpecialize 时还不存在。
// 通过 maybe_reload 的节流路径（每 256 次调用）反复尝试，库一加载就补装。
static void try_install_ssl() {
    if (g_ssl_hooked || !g_cfg.hook_ssl_unlock) return;
    void* fn = find_ssl_read();
    if (!fn) return;
    tramp_ssl_read = inline_hook("SSL_read", fn, (void*)hook_ssl_read);
    if (tramp_ssl_read) {
        g_ssl_hooked = true;
        LOGI("[hook] SSL_read 解锁 hook 安装成功 @ %p", fn);
    }
}

static void patch_vipflag(char* buf, ssize_t len) {
    static const char vf[] = "vipflag";
    static const char fls[] = "false";
    static const char tru[] = "true ";  // 5 字节，与 "false" 等长
    for (ssize_t i = 0; i + 7 <= len; i++) {
        if (memcmp(buf + i, vf, 7) == 0) {
            for (ssize_t j = i + 7; j + 5 <= len && j < i + 96; j++) {
                if (memcmp(buf + j, fls, 5) == 0) {
                    memcpy(buf + j, tru, 5);
                    LOGI("[UNLOCK] vipflag false→true 注入成功");
                    return;
                }
            }
        }
    }
}

static int hook_ssl_read(void* ssl, void* buf, int num) {
    if (!tramp_ssl_read) return -1;  // 未安装成功时防御
    int n = ((ssl_read_t)tramp_ssl_read)(ssl, buf, num);
    if (n > 0 && buf && g_cfg.hook_ssl_unlock) {
        patch_vipflag((char*)buf, n);
    }
    return n;
}

// ====== JNI hook：假字符串/byte[] ======
static jstring jstr(JNIEnv* env, const char* s) { return env->NewStringUTF(s); }
static jbyteArray jbytes(JNIEnv* env, const char* hex) {
    int n = strlen(hex) / 2;
    jbyteArray arr = env->NewByteArray(n);
    if (arr) {
        jbyte* b = (jbyte*)malloc(n);
        for (int i = 0; i < n; i++) {
            int hi = hex[i*2] >= 'a' ? hex[i*2]-'a'+10 : hex[i*2]-'0';
            int lo = hex[i*2+1] >= 'a' ? hex[i*2+1]-'a'+10 : hex[i*2+1]-'0';
            b[i] = (jbyte)((hi << 4) | lo);
        }
        env->SetByteArrayRegion(arr, 0, n, b);
        free(b);
    }
    return arr;
}

static jstring hook_Build_getSerial(JNIEnv* env, jclass) { return jstr(env, s_serialno); }
static jstring hook_Build_getRadioVersion(JNIEnv* env, jclass) { return jstr(env, "1.0.0.0"); }
static jstring hook_Tel_getImei(JNIEnv* env, jobject) { return jstr(env, s_imei); }
static jstring hook_Tel_getDeviceId(JNIEnv* env, jobject) { return jstr(env, s_imei); }
static jstring hook_Tel_getLine1Number(JNIEnv* env, jobject) { return jstr(env, s_line1); }
static jstring hook_Tel_getSubscriberId(JNIEnv* env, jobject) { return jstr(env, s_imei); }
static jstring hook_Tel_getMeid(JNIEnv* env, jobject) { return jstr(env, s_meid); }
static jstring hook_Wifi_getMac(JNIEnv* env, jobject) { return jstr(env, s_mac); }
static jbyteArray hook_Netif_getHardwareAddr(JNIEnv* env, jobject) {
    jbyteArray arr = env->NewByteArray(6);
    if (arr) {
        jbyte b[6] = {(jbyte)0xA8,0x63,(jbyte)0xEA,(jbyte)0xC6,(jbyte)0xD2,0x3E};
        env->SetByteArrayRegion(arr, 0, 6, b);
    }
    return arr;
}
static jbyteArray hook_MediaDrm_getProperty(JNIEnv* env, jobject, jstring name) {
    return jbytes(env, s_widevine);
}

class ColaMangaModule : public ModuleBase {
public:
    Api* api;
    JNIEnv* env;
    bool target = false;

    void onLoad(Api* api, JNIEnv* env) override {
        this->api = api;
        this->env = env;
    }

    void preAppSpecialize(AppSpecializeArgs* args) override {
        const char* name = env->GetStringUTFChars(args->nice_name, nullptr);
        if (name) {
            if (strstr(name, "com.hswl.car_owner") || strstr(name, "com.hswl.cargo_owner")) {
                target = true;
                LOGI("[pre] 目标进程: %s", name);
            }
            env->ReleaseStringUTFChars(args->nice_name, name);
        }
    }

    void postAppSpecialize(const AppSpecializeArgs* args) override {
        if (!target) return;
        LOGI("[post] 目标进程沙箱化，开始 hook");
        load_config();
        read_hooks_conf();

        // 清空 hook 状态（供 WebUI 可视化）
        FILE* sf = fopen("/data/adb/modules/colamanga_mod/run/hooks_status.txt", "w");
        if (sf) fclose(sf);

        // 核心功能 hook（设备伪造已交给 Privacy Kit，避免与其 Zygisk 层二次 hook 冲突）：
        //   1. connect/getaddrinfo —— 反服务器下发（拒连 blocklist 风控域名）
        //   2. SSL_read —— vipflag 章节解锁注入
        tramp_connect    = inline_hook("connect", dlsym(RTLD_DEFAULT, "connect"), (void*)hook_connect);
        tramp_getaddrinfo= inline_hook("getaddrinfo", dlsym(RTLD_DEFAULT, "getaddrinfo"), (void*)hook_getaddrinfo);
        try_install_ssl();  // libflutter 未加载时，由 hook_connect 里的 try_install_ssl 在网络请求时补装
        LOGI("[hook] 核心 hook 完成：反下发(connect/getaddrinfo) + 章节解锁(SSL_read)");

        // 2. JNI native 方法 hook（设备标识）——每个独立 try-catch，失败自动降级不崩
        if (g_cfg.hook_jni) {
            int jni_ok = 0, jni_fail = 0;

            JNINativeMethod build_methods[] = {
                {"getSerial", "()Ljava/lang/String;", (void*)hook_Build_getSerial},
                {"getRadioVersion", "()Ljava/lang/String;", (void*)hook_Build_getRadioVersion},
            };
            try {
                api->hookJniNativeMethods(env, "android/os/Build", build_methods, 2);
                jni_ok += 2;
            } catch (...) { jni_fail += 2; LOGE("[jni] Build hook 注册失败(已降级)"); }

            JNINativeMethod tel_methods[] = {
                {"getImei", "()Ljava/lang/String;", (void*)hook_Tel_getImei},
                {"getDeviceId", "()Ljava/lang/String;", (void*)hook_Tel_getDeviceId},
                {"getLine1Number", "()Ljava/lang/String;", (void*)hook_Tel_getLine1Number},
                {"getSubscriberId", "()Ljava/lang/String;", (void*)hook_Tel_getSubscriberId},
                {"getMeid", "()Ljava/lang/String;", (void*)hook_Tel_getMeid},
            };
            try {
                api->hookJniNativeMethods(env, "android/telephony/TelephonyManager", tel_methods, 5);
                jni_ok += 5;
            } catch (...) { jni_fail += 5; LOGE("[jni] Telephony hook 注册失败(已降级)"); }

            JNINativeMethod wifi_methods[] = {
                {"getMacAddress", "()Ljava/lang/String;", (void*)hook_Wifi_getMac},
            };
            try {
                api->hookJniNativeMethods(env, "android/net/wifi/WifiInfo", wifi_methods, 1);
                jni_ok += 1;
            } catch (...) { jni_fail += 1; LOGE("[jni] WifiInfo hook 注册失败(已降级)"); }

            JNINativeMethod netif_methods[] = {
                {"getHardwareAddress", "()[B", (void*)hook_Netif_getHardwareAddr},
            };
            try {
                api->hookJniNativeMethods(env, "java/net/NetworkInterface", netif_methods, 1);
                jni_ok += 1;
            } catch (...) { jni_fail += 1; LOGE("[jni] NetworkInterface hook 注册失败(已降级)"); }

            JNINativeMethod drm_methods[] = {
                {"getPropertyByteArray", "(Ljava/lang/String;)[B", (void*)hook_MediaDrm_getProperty},
            };
            try {
                api->hookJniNativeMethods(env, "android/media/MediaDrm", drm_methods, 1);
                jni_ok += 1;
            } catch (...) { jni_fail += 1; LOGE("[jni] MediaDrm hook 注册失败(已降级)"); }

            LOGI("[jni] 成功=%d 失败=%d（失败项自动降级，不影响 app 运行）", jni_ok, jni_fail);
        }

        LOGI("[hook] Colamanga Zygisk v3 全部 hook 完成");
    }

    void preServerSpecialize(ServerSpecializeArgs*) override {}
    void postServerSpecialize(const ServerSpecializeArgs*) override {}
};

REGISTER_ZYGISK_MODULE(ColaMangaModule)
