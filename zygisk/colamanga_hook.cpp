// colamanga_hook.cpp - 安全版 v2
// 只 hook：__system_property_get（假属性）+ getaddrinfo/connect（抓包记录，不篡改不闪退）
// 不 hook read/ptrace/openat（避免闪退）
// 编译: aarch64-linux-android21-clang++ -shared -fPIC -O2 -std=c++17 -o libcolamanga_hook.so

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

static const char* FAKE_PROPS[][2] = {
    {"ro.serialno", "RMU48KXQN12PZ7C9"},
    {"ro.boot.serialno", "RMU48KXQN12PZ7C9"},
    {"ro.build.fingerprint", "Xiaomi/socrates/socrates:13/TKQ1.221114.001/V14.0.4.0.TLCCNXM:user/release-keys"},
    {"ro.product.model", "2201123C"},
    {"ro.product.system.model", "2201123C"},
    {"ro.product.vendor.model", "2201123C"},
    {"ro.product.brand", "Xiaomi"},
    {"ro.product.system.brand", "Xiaomi"},
    {"ro.product.vendor.brand", "Xiaomi"},
    {"ro.product.device", "socrates"},
    {"ro.product.name", "socrates"},
    {"ro.product.manufacturer", "Xiaomi"},
    {"ro.hardware", "qcom"},
    {"ro.boot.hardware", "qcom"},
    {"ro.product.board", "lahaina"},
    {"ro.board.platform", "lahaina"},
    {"ro.build.host", "srv04-13.miui.com"},
    {"ro.build.id", "TKQ1.221114.001"},
    {"ro.build.version.incremental", "V14.0.4.0.TLCCNXM"},
    {"ro.build.version.security_patch", "2023-02-01"},
    {"ro.build.version.release", "13"},
    {"ro.build.version.sdk", "33"},
    {"ro.build.type", "user"},
    {"ro.build.tags", "release-keys"},
    {"ro.boot.verifiedbootstate", "green"},
    {"ro.boot.flash.locked", "1"},
    {"ro.boot.vbmeta.device_state", "locked"},
    {nullptr, nullptr}
};

// ====== ARM64 inline hook（支持多个 hook，每个独立 trampoline）======
#define MAX_HOOKS 8

struct HookEntry {
    void* target;
    void* tramp;
    unsigned char orig[16];
};

static HookEntry g_hooks[MAX_HOOKS];
static int g_hook_count = 0;

static void* hook_tramp(const char* name, void* target, void* hook_fn) {
    if (!target || !hook_fn || g_hook_count >= MAX_HOOKS) return nullptr;
    HookEntry& e = g_hooks[g_hook_count];
    memcpy(e.orig, target, 16);
    e.target = target;
    e.tramp = mmap(nullptr, 4096, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (e.tramp == MAP_FAILED) return nullptr;
    unsigned char* t = (unsigned char*)e.tramp;
    memcpy(t, e.orig, 16);
    *(uint32_t*)(t+16) = 0x58000050;   // LDR X17, [PC, #8]
    *(uint32_t*)(t+20) = 0xD61FE020;   // BR X17
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
    LOGI("hook %s OK: target=%p", name, target);
    return e.tramp;
}

// ====== __system_property_get ======
static void* tramp_property = nullptr;
typedef int (*property_get_t)(const char*, char*, const char*);
static int hook_property_get(const char* name, char* value, const char* default_value) {
    if (name) {
        for (int i = 0; FAKE_PROPS[i][0]; i++) {
            if (strcmp(name, FAKE_PROPS[i][0]) == 0) {
                if (value) { strncpy(value, FAKE_PROPS[i][1], 91); value[91] = 0; }
                return (int)strlen(FAKE_PROPS[i][1]);
            }
        }
    }
    return ((property_get_t)tramp_property)(name, value, default_value);
}

// ====== connect（抓包记录）=====
static void* tramp_connect = nullptr;
typedef int (*connect_t)(int, const struct sockaddr*, socklen_t);
static int hook_connect(int sockfd, const struct sockaddr* addr, socklen_t addrlen) {
    if (addr) {
        char ip[64] = {0}; int port = 0;
        if (addr->sa_family == AF_INET) {
            inet_ntop(AF_INET, &((const struct sockaddr_in*)addr)->sin_addr, ip, sizeof(ip));
            port = ntohs(((const struct sockaddr_in*)addr)->sin_port);
        } else if (addr->sa_family == AF_INET6) {
            inet_ntop(AF_INET6, &((const struct sockaddr_in6*)addr)->sin6_addr, ip, sizeof(ip));
            port = ntohs(((const struct sockaddr_in6*)addr)->sin6_port);
        }
        if (ip[0] && port > 0) LOGI("[NET] %s:%d", ip, port);
    }
    return ((connect_t)tramp_connect)(sockfd, addr, addrlen);
}

// ====== getaddrinfo（DNS 解析记录）=====
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
        LOGI("Target: %s — installing hooks (property + net capture)", cmd);
        void* fn = dlsym(RTLD_DEFAULT, "__system_property_get");
        tramp_property = hook_tramp("__system_property_get", fn, (void*)hook_property_get);
        fn = dlsym(RTLD_DEFAULT, "connect");
        tramp_connect = hook_tramp("connect", fn, (void*)hook_connect);
        fn = dlsym(RTLD_DEFAULT, "getaddrinfo");
        tramp_getaddrinfo = hook_tramp("getaddrinfo", fn, (void*)hook_getaddrinfo);
        LOGI("hooks installed: property=%p connect=%p getaddrinfo=%p", tramp_property, tramp_connect, tramp_getaddrinfo);
    }
    return JNI_VERSION_1_6;
}