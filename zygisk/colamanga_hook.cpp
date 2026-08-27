// colamanga_hook.cpp - 原生层破甲（JNI .so，非 Zygisk 模块）
// 通过 LSPosed 模块 System.loadLibrary 加载，仅目标进程生效
// inline hook libc 函数本体：__system_property_get / ptrace / openat / connect
// 编译: aarch64-linux-android21-clang++ -shared -fPIC -O2 -std=c++17 -o libcolamanga_hook.so

#include <jni.h>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <android/log.h>
#include <errno.h>
#include <pthread.h>

#define TAG "ColaMangaHook"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// ====== 假设备属性 ======
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

// ====== ARM64 inline hook 实现 ======
// 标准 ARM64 trampoline hook：函数入口写 LDR X17,[PC,#8]; BR X17; <addr>
// trampoline 保存原始指令 + 跳回 original+16

// 原始字节缓冲（每个 hook 一个）
static unsigned char orig_property[16], orig_ptrace[16], orig_openat[16], orig_connect[16];
static void* tramp_property = nullptr;
static void* tramp_ptrace = nullptr;
static void* tramp_openat = nullptr;
static void* tramp_connect = nullptr;

// 改进版 install（每个 hook 独立保存）
static bool do_hook(const char* name, void* target, void* hook_fn, void** tramp_out, unsigned char* orig_buf) {
    if (!target || !hook_fn) { LOGE("hook %s: null ptr", name); return false; }
    memcpy(orig_buf, target, 16);
    void* tramp = mmap(nullptr, 4096, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (tramp == MAP_FAILED) { LOGE("hook %s: mmap failed", name); return false; }
    unsigned char* t = (unsigned char*)tramp;
    memcpy(t, orig_buf, 16);
    *(uint32_t*)(t+16) = 0x58000050; *(uint32_t*)(t+20) = 0xD61FE020;
    *(void**)(t+24) = (void*)((uintptr_t)target + 16);
    __builtin___clear_cache((char*)tramp, (char*)tramp + 32);
    uintptr_t page = (uintptr_t)target & ~0xFFFULL;
    mprotect((void*)page, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC);
    *(uint32_t*)((unsigned char*)target+0) = 0x58000050;
    *(uint32_t*)((unsigned char*)target+4) = 0xD61FE020;
    *(void**)((unsigned char*)target+8) = hook_fn;
    mprotect((void*)page, 0x1000, PROT_READ|PROT_EXEC);
    __builtin___clear_cache((char*)target, (char*)target + 16);
    *tramp_out = tramp;
    LOGI("hook %s OK: target=%p hook=%p tramp=%p", name, target, hook_fn, tramp);
    return true;
}

// ====== Hook 函数实现 ======

// __system_property_get
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
    // 调用原始
    return ((property_get_t)tramp_property)(name, value, default_value);
}

// ptrace（反调试）
typedef long (*ptrace_t)(int, pid_t, void*, void*);
static long hook_ptrace(int request, pid_t pid, void* addr, void* data) {
    // 返回成功让风控以为没被调试
    if (request == PTRACE_TRACEME || request == PTRACE_ATTACH) {
        return 0;
    }
    errno = 0;
    return ((ptrace_t)tramp_ptrace)(request, pid, addr, data);
}

// openat（隐藏 root/xposed/frida 文件）
typedef int (*openat_t)(int, const char*, int, ...);
static int hook_openat(int dirfd, const char* path, int flags, ...) {
    if (path) {
        if (strstr(path, "magisk") || strstr(path, "/su") || strstr(path, "supersu") ||
            strstr(path, "kernelsu") || strstr(path, "/ksu") || strstr(path, "apatch") ||
            strstr(path, "xposed") || strstr(path, "lsposed") || strstr(path, "riru") ||
            strstr(path, "zygisk") || strstr(path, "frida") || strstr(path, "/sbin/.magisk")) {
            errno = ENOENT;
            return -1;
        }
    }
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list ap; va_start(ap, flags); mode = va_arg(ap, int); va_end(ap); }
    return ((openat_t)tramp_openat)(dirfd, path, flags, mode);
}

// connect（抓包记录）
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
        if (ip[0] && strcmp(ip, "127.0.0.1") != 0 && strcmp(ip, "::1") != 0) {
            LOGI("[CAPTURE] %s:%d fd=%d", ip, port, sockfd);
        }
    }
    return ((connect_t)tramp_connect)(sockfd, addr, addrlen);
}

// ====== 安装所有 hook ======
static void install_all_hooks() {
    // __system_property_get 在 libc.so
    void* fn = dlsym(RTLD_DEFAULT, "__system_property_get");
    if (fn) do_hook("__system_property_get", fn, (void*)hook_property_get, &tramp_property, orig_property);
    else LOGE("__system_property_get not found");
    
    // ptrace
    fn = dlsym(RTLD_DEFAULT, "ptrace");
    if (fn) do_hook("ptrace", fn, (void*)hook_ptrace, &tramp_ptrace, orig_ptrace);
    else LOGE("ptrace not found");
    
    // openat
    fn = dlsym(RTLD_DEFAULT, "openat");
    if (fn) do_hook("openat", fn, (void*)hook_openat, &tramp_openat, orig_openat);
    else LOGE("openat not found");
    
    // connect
    fn = dlsym(RTLD_DEFAULT, "connect");
    if (fn) do_hook("connect", fn, (void*)hook_connect, &tramp_connect, orig_connect);
    else LOGE("connect not found");
    
    LOGI("All inline hooks installed");
}

// ====== JNI 入口 ======
JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* reserved) {
    // 检查是否是目标进程
    char cmd[256] = {0};
    int fd = open("/proc/self/cmdline", O_RDONLY);
    if (fd >= 0) { read(fd, cmd, sizeof(cmd)-1); close(fd); }
    
    bool isTarget = (strstr(cmd, "com.hswl.car_owner") != nullptr ||
                     strstr(cmd, "com.hswl.cargo_owner") != nullptr);
    
    if (isTarget) {
        LOGI("Target process detected: %s — installing inline hooks", cmd);
        // 确保 logs 目录存在
        mkdir("/data/adb/colamanga_mod/logs", 0755);
        install_all_hooks();
    } else {
        // 非目标进程，不做任何 hook
    }
    
    return JNI_VERSION_1_6;
}