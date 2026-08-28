// colamanga_hook.cpp - v4 反检测版
// hook：__system_property_get(假属性) + ptrace(反调试) + access(隐藏frida/root文件) + connect/getaddrinfo(抓包)
// 全部安全透传，不 hook read/openat（避免闪退）
// 日志：logcat 直接输出
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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <android/log.h>
#include <errno.h>

#define TAG "ColaMangaHook"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// ===== 假属性（从 device_id.json 读取）=====
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

// 反检测开关（从 settings.conf 读取，WebUI 实时改）
static int anti_debug_enabled = 1;
static int hide_root_enabled = 1;

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

static void load_device_config() {
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
    free(json);
    LOGI("[cfg] 设备=%s %s serial=%s", s_brand, s_model, s_serialno);
}

// 每次 ptrace/access 调用时重读开关（实时生效）
static void refresh_flags() {
    FILE* f = fopen("/data/adb/modules/colamanga_mod/config/settings.conf", "r");
    if (!f) return;
    char line[128];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "anti_debug=0")) anti_debug_enabled = 0;
        else if (strstr(line, "anti_debug=1")) anti_debug_enabled = 1;
        else if (strstr(line, "hide_root=0")) hide_root_enabled = 0;
        else if (strstr(line, "hide_root=1")) hide_root_enabled = 1;
    }
    fclose(f);
}

// ====== inline hook 框架 ======
#define MAX_HOOKS 8
struct HookEntry { void* tramp; unsigned char orig[16]; };
static HookEntry g_h[MAX_HOOKS];
static int g_n = 0;

static void* hook_tramp(const char* name, void* target, void* hook_fn) {
    if (!target || !hook_fn || g_n >= MAX_HOOKS) return nullptr;
    HookEntry& e = g_h[g_n];
    memcpy(e.orig, target, 16);
    e.tramp = mmap(nullptr, 4096, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (e.tramp == MAP_FAILED) return nullptr;
    unsigned char* t = (unsigned char*)e.tramp;
    memcpy(t, e.orig, 16);
    *(uint32_t*)(t+16) = 0x58000050;
    *(uint32_t*)(t+20) = 0xD61FE020;
    *(void**)(t+24) = (void*)((uintptr_t)target + 16);
    __builtin___clear_cache((char*)e.tramp, (char*)e.tramp + 32);
    uintptr_t page = (uintptr_t)target & ~0xFFFULL;
    mprotect((void*)page, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC);
    *(uint32_t*)((unsigned char*)target+0) = 0x58000050;
    *(uint32_t*)((unsigned char*)target+4) = 0xD61FE020;
    *(void**)((unsigned char*)target+8) = hook_fn;
    mprotect((void*)page, 0x1000, PROT_READ|PROT_EXEC);
    __builtin___clear_cache((char*)target, (char*)target + 16);
    g_n++;
    LOGI("[hook] %s OK target=%p", name, target);
    return e.tramp;
}

// ====== __system_property_get ======
static void* tramp_property = nullptr;
typedef int (*property_get_t)(const char*, char*, const char*);
static int hook_property_get(const char* name, char* value, const char* default_value) {
    const char* fake = nullptr;
    if (name) {
        if (!strcmp(name, "ro.serialno") || !strcmp(name, "ro.boot.serialno")) fake = s_serialno;
        else if (!strcmp(name, "ro.build.fingerprint") || !strcmp(name, "ro.system.build.fingerprint")) fake = s_fingerprint;
        else if (!strcmp(name, "ro.product.model") || !strcmp(name, "ro.product.system.model") || !strcmp(name, "ro.product.vendor.model")) fake = s_model;
        else if (!strcmp(name, "ro.product.brand") || !strcmp(name, "ro.product.system.brand") || !strcmp(name, "ro.product.vendor.brand")) fake = s_brand;
        else if (!strcmp(name, "ro.product.device")) fake = s_device;
        else if (!strcmp(name, "ro.product.name")) fake = s_product;
        else if (!strcmp(name, "ro.product.manufacturer")) fake = s_manufacturer;
        else if (!strcmp(name, "ro.hardware") || !strcmp(name, "ro.boot.hardware")) fake = s_hardware;
        else if (!strcmp(name, "ro.product.board") || !strcmp(name, "ro.board.platform")) fake = s_board;
        else if (!strcmp(name, "ro.build.host")) fake = s_host;
        else if (!strcmp(name, "ro.build.id")) fake = s_build_id;
        else if (!strcmp(name, "ro.build.version.incremental")) fake = s_incremental;
        else if (!strcmp(name, "ro.build.version.security_patch")) fake = s_security_patch;
        else if (!strcmp(name, "ro.build.version.release")) fake = s_release;
        else if (!strcmp(name, "ro.build.version.sdk")) fake = s_sdk;
        else if (!strcmp(name, "ro.build.type")) fake = s_type;
        else if (!strcmp(name, "ro.build.tags")) fake = s_tags;
        else if (!strcmp(name, "ro.boot.verifiedbootstate")) fake = "green";
        else if (!strcmp(name, "ro.boot.flash.locked")) fake = "1";
        else if (!strcmp(name, "ro.boot.vbmeta.device_state")) fake = "locked";
    }
    if (fake) { if (value) { strncpy(value, fake, 91); value[91] = 0; } return (int)strlen(fake); }
    return ((property_get_t)tramp_property)(name, value, default_value);
}

// ====== ptrace（反调试，WebUI 实时开关）======
static void* tramp_ptrace = nullptr;
typedef long (*ptrace_t)(int, pid_t, void*, void*);
static long hook_ptrace(int request, pid_t pid, void* addr, void* data) {
    refresh_flags();
    if (anti_debug_enabled) {
        // 反调试：TRACEME/ATTACH 返回 0（假装成功，让检测以为没被调试），其余透传
        if (request == PTRACE_TRACEME) return 0;
        if (request == PTRACE_ATTACH) { errno = 0; return -1; }
        // PTRACE_KILL/其他：透传
    }
    return ((ptrace_t)tramp_ptrace)(request, pid, addr, data);
}

// ====== access（隐藏 frida/root 文件，WebUI 实时开关）======
static void* tramp_access = nullptr;
typedef int (*access_t)(const char*, int);
static int is_blacklisted_file(const char* path) {
    if (!path) return 0;
    const char* kws[] = {"frida", "gum-js-loop", "gmain", "linjector", "magisk", "/su", "supersu",
                          "kernelsu", "/ksu", "apatch", "xposed", "lsposed", "riru", "zygisk",
                          "re.frida", "gadget", nullptr};
    for (int i = 0; kws[i]; i++) {
        if (strstr(path, kws[i])) return 1;
    }
    return 0;
}
static int hook_access(const char* path, int mode) {
    refresh_flags();
    if (hide_root_enabled && is_blacklisted_file(path)) {
        errno = ENOENT;
        return -1;
    }
    return ((access_t)tramp_access)(path, mode);
}

// ====== connect（抓包记录到文件，capture 开关控制）======
static void* tramp_connect = nullptr;
typedef int (*connect_t)(int, const struct sockaddr*, socklen_t);
static int capture_enabled = 0;

static int hook_connect(int sockfd, const struct sockaddr* addr, socklen_t addrlen) {
    if (addr) {
        char ip[64] = {0}; int port = 0;
        if (addr->sa_family == AF_INET) { inet_ntop(AF_INET, &((const struct sockaddr_in*)addr)->sin_addr, ip, sizeof(ip)); port = ntohs(((const struct sockaddr_in*)addr)->sin_port); }
        else if (addr->sa_family == AF_INET6) { inet_ntop(AF_INET6, &((const struct sockaddr_in6*)addr)->sin6_addr, ip, sizeof(ip)); port = ntohs(((const struct sockaddr_in6*)addr)->sin6_port); }
        if (ip[0] && port > 0) {
            // 读 capture 开关（实时）
            FILE* sf = fopen("/data/adb/modules/colamanga_mod/config/settings.conf", "r");
            capture_enabled = 0;
            if (sf) {
                char line[128];
                while (fgets(line, sizeof(line), sf)) {
                    if (strstr(line, "packet_capture=1")) capture_enabled = 1;
                }
                fclose(sf);
            }
            if (capture_enabled) {
                // 写 IP:port 到文件（含时间戳）
                FILE* lf = fopen("/data/adb/modules/colamanga_mod/logs/network.log", "a");
                if (lf) {
                    fprintf(lf, "%s%s:%d\n", "", ip, port);
                    fclose(lf);
                }
            }
        }
    }
    return ((connect_t)tramp_connect)(sockfd, addr, addrlen);
}

// ====== getaddrinfo（DNS 记录）======
static void* tramp_getaddrinfo = nullptr;
typedef int (*getaddrinfo_t)(const char*, const char*, const struct addrinfo*, struct addrinfo**);
static int hook_getaddrinfo(const char* node, const char* service, const struct addrinfo* hints, struct addrinfo** res) {
    if (node) LOGI("[DNS] %s", node);
    return ((getaddrinfo_t)tramp_getaddrinfo)(node, service, hints, res);
}

JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* reserved) {
    char cmd[256] = {0};
    int fd = open("/proc/self/cmdline", O_RDONLY);
    if (fd >= 0) { read(fd, cmd, sizeof(cmd)-1); close(fd); }
    bool isTarget = (strstr(cmd, "com.hswl.car_owner") || strstr(cmd, "com.hswl.cargo_owner"));
    if (isTarget) {
        LOGI("[init] Target=%s 加载配置", cmd);
        load_device_config();
        refresh_flags();
        void* fn = dlsym(RTLD_DEFAULT, "__system_property_get");
        tramp_property = hook_tramp("__system_property_get", fn, (void*)hook_property_get);
        fn = dlsym(RTLD_DEFAULT, "ptrace");
        tramp_ptrace = hook_tramp("ptrace", fn, (void*)hook_ptrace);
        fn = dlsym(RTLD_DEFAULT, "access");
        tramp_access = hook_tramp("access", fn, (void*)hook_access);
        fn = dlsym(RTLD_DEFAULT, "connect");
        tramp_connect = hook_tramp("connect", fn, (void*)hook_connect);
        fn = dlsym(RTLD_DEFAULT, "getaddrinfo");
        tramp_getaddrinfo = hook_tramp("getaddrinfo", fn, (void*)hook_getaddrinfo);
        LOGI("[init] 5 hook 完成: property=%p ptrace=%p access=%p net=%p dns=%p",
             tramp_property, tramp_ptrace, tramp_access, tramp_connect, tramp_getaddrinfo);
    }
    return JNI_VERSION_1_6;
}