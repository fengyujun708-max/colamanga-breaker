// colamanga_hook_minimal.cpp - 安全版（只 hook 最关键的 __system_property_get）
// 不 hook read/ptrace/openat/connect（避免闪退）
// 编译: aarch64-linux-android21-clang++ -shared -fPIC -O2 -std=c++17 -o libcolamanga_hook.so

#include <jni.h>
#include <cstring>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/mman.h>
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
    {"ro.product.brand", "Xiaomi"},
    {"ro.product.system.brand", "Xiaomi"},
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
    {nullptr, nullptr}
};

// ARM64 inline hook（只 hook 一个函数，最安全）
static unsigned char orig_bytes[16];
static void* tramp = nullptr;

static bool do_hook(const char* name, void* target, void* hook_fn) {
    if (!target || !hook_fn) return false;
    memcpy(orig_bytes, target, 16);
    tramp = mmap(nullptr, 4096, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (tramp == MAP_FAILED) return false;
    unsigned char* t = (unsigned char*)tramp;
    memcpy(t, orig_bytes, 16);
    *(uint32_t*)(t+16) = 0x58000050;
    *(uint32_t*)(t+20) = 0xD61FE020;
    *(void**)(t+24) = (void*)((uintptr_t)target + 16);
    __builtin___clear_cache((char*)tramp, (char*)tramp + 32);
    uintptr_t page = (uintptr_t)target & ~0xFFFULL;
    mprotect((void*)page, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC);
    *(uint32_t*)((unsigned char*)target+0) = 0x58000050;
    *(uint32_t*)((unsigned char*)target+4) = 0xD61FE020;
    *(void**)((unsigned char*)target+8) = hook_fn;
    mprotect((void*)page, 0x1000, PROT_READ|PROT_EXEC);
    __builtin___clear_cache((char*)target, (char*)target + 16);
    LOGI("hook %s OK: target=%p hook=%p", name, target, hook_fn);
    return true;
}

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
    return ((property_get_t)tramp)(name, value, default_value);
}

JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* reserved) {
    char cmd[256] = {0};
    int fd = open("/proc/self/cmdline", O_RDONLY);
    if (fd >= 0) { read(fd, cmd, sizeof(cmd)-1); close(fd); }
    bool isTarget = (strstr(cmd, "com.hswl.car_owner") || strstr(cmd, "com.hswl.cargo_owner"));
    if (isTarget) {
        LOGI("Target: %s — installing property hook only (safe mode)", cmd);
        void* fn = dlsym(RTLD_DEFAULT, "__system_property_get");
        if (fn) do_hook("__system_property_get", fn, (void*)hook_property_get);
        else LOGE("__system_property_get not found");
    }
    return JNI_VERSION_1_6;
}