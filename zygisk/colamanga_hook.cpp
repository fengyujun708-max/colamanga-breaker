// colamanga_hook.cpp - 安全版 v3
// hook：__system_property_get（假属性，从 device_id.json 读取）+ connect/getaddrinfo（抓包）
// 日志：直接输出 logcat（不依赖 LSPosed 日志系统，绕过 zygisk next 问题）
#include <jni.h>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <android/log.h>
#include <errno.h>

#define TAG "ColaMangaHook"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// 假属性（从 device_id.json 读取，失败用默认）
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

// 从 JSON 读取字符串值（简单解析）
static void json_get_str(const char* json, const char* key, char* out, int outlen) {
    char pat[128];
    snprintf(pat, sizeof(pat), "\"%s\"\\s*:\\s*\"", key);
    const char* p = json;
    // 找 key
    const char* k = strstr(p, key);
    if (!k) return;
    // 找冒号后的引号
    const char* q = strchr(k, ':');
    if (!q) return;
    q = strchr(q, '"');
    if (!q) return;
    q++; // 跳到值的开头
    int i = 0;
    while (*q && *q != '"' && i < outlen - 1) {
        out[i++] = *q++;
    }
    out[i] = 0;
}

static void load_device_config() {
    FILE* f = fopen("/data/adb/modules/colamanga_mod/config/device_id.json", "r");
    if (!f) { LOGI("[cfg] 无 device_id.json，用默认假属性"); return; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > 4096) { fclose(f); return; }
    char* json = (char*)malloc(sz + 1);
    fread(json, 1, sz, f);
    json[sz] = 0;
    fclose(f);
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
    LOGI("[cfg] 已加载 device_id.json: %s %s serial=%s", s_brand, s_model, s_serialno);
}

// ====== inline hook ======
#define MAX_HOOKS 4
struct HookEntry { void* tramp; unsigned char orig[16]; };
static HookEntry g_h[4];
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
    if (fake) {
        if (value) { strncpy(value, fake, 91); value[91] = 0; }
        return (int)strlen(fake);
    }
    return ((property_get_t)tramp_property)(name, value, default_value);
}

// ====== connect（抓包）====== 
static void* tramp_connect = nullptr;
typedef int (*connect_t)(int, const struct sockaddr*, socklen_t);
static int hook_connect(int sockfd, const struct sockaddr* addr, socklen_t addrlen) {
    if (addr) {
        char ip[64] = {0}; int port = 0;
        if (addr->sa_family == AF_INET) { inet_ntop(AF_INET, &((const struct sockaddr_in*)addr)->sin_addr, ip, sizeof(ip)); port = ntohs(((const struct sockaddr_in*)addr)->sin_port); }
        else if (addr->sa_family == AF_INET6) { inet_ntop(AF_INET6, &((const struct sockaddr_in6*)addr)->sin6_addr, ip, sizeof(ip)); port = ntohs(((const struct sockaddr_in6*)addr)->sin6_port); }
        if (ip[0] && port > 0) LOGI("[NET] %s:%d", ip, port);
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
        LOGI("[init] Target=%s 加载设备配置并安装hook", cmd);
        load_device_config();
        void* fn = dlsym(RTLD_DEFAULT, "__system_property_get");
        tramp_property = hook_tramp("__system_property_get", fn, (void*)hook_property_get);
        fn = dlsym(RTLD_DEFAULT, "connect");
        tramp_connect = hook_tramp("connect", fn, (void*)hook_connect);
        fn = dlsym(RTLD_DEFAULT, "getaddrinfo");
        tramp_getaddrinfo = hook_tramp("getaddrinfo", fn, (void*)hook_getaddrinfo);
        LOGI("[init] hook 安装完成: property=%p net=%p dns=%p", tramp_property, tramp_connect, tramp_getaddrinfo);
    }
    return JNI_VERSION_1_6;
}