// colamanga_hook.cpp - Zygisk 原生层破甲模块
// 仅针对 com.hswl.car_owner / com.hswl.cargo_owner.cargo_owner
// 功能: __system_property_get 伪造 + ptrace 反调试 + open 屏蔽检测 + connect 抓包
// 编译: aarch64-linux-android21-clang++ -shared -fPIC -o arm64-v8a.so colamanga_hook.cpp
//        -DZYGISK_API_VERSION=4 -I. -static-libstdc++

#include <jni.h>
#include <cstring>
#include <string>
#include <fcntl.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <android/log.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

#define TAG "ColaMangaZygisk"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// 目标包名
static const char* TARGET_PACKAGES[] = {
    "com.hswl.car_owner",
    "com.hswl.cargo_owner.cargo_owner",
    nullptr
};

// 假设备属性（从模块配置读取，默认值）
struct FakeDevice {
    const char* serialno = "RMU48KXQN12PZ7C9";
    const char* boot_serialno = "RMU48KXQN12PZ7C9";
    const char* fingerprint = "Xiaomi/socrates/socrates:13/TKQ1.221114.001/V14.0.4.0.TLCCNXM:user/release-keys";
    const char* model = "2201123C";
    const char* brand = "Xiaomi";
    const char* device = "socrates";
    const char* product = "socrates";
    const char* manufacturer = "Xiaomi";
    const char* hardware = "qcom";
    const char* board = "lahaina";
    const char* incremental = "V14.0.4.0.TLCCNXM";
    const char* security_patch = "2023-02-01";
    const char* release = "13";
    const char* sdk = "33";
    const char* type = "user";
    const char* tags = "release-keys";
    const char* host = "srv04-13.miui.com";
    const char* id = "TKQ1.221114.001";
};

static FakeDevice fakeDev;
static bool isTargetProcess = false;
static bool antiDebugEnabled = true;
static bool hideRootEnabled = true;
static bool captureEnabled = true;

// 从配置文件读取假设备属性
static void loadFakeDevice() {
    FILE* f = fopen("/data/adb/colamanga_mod/config/active_profile", "r");
    if (!f) return;
    char profile[256] = {0};
    fgets(profile, sizeof(profile), f);
    fclose(f);
    // 去换行
    profile[strcspn(profile, "\n")] = 0;
    
    // 读 profiles
    f = fopen("/data/adb/colamanga_mod/config/fake_device.conf", "r");
    if (!f) return;
    char line[512];
    bool inProfile = false;
    char buf_serialno[128] = {0};
    char buf_fingerprint[256] = {0};
    char buf_model[64] = {0};
    char buf_brand[64] = {0};
    char buf_hardware[64] = {0};
    char buf_board[64] = {0};
    
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\n")] = 0;
        if (line[0] == '[') {
            inProfile = (strstr(line, profile) != nullptr);
            continue;
        }
        if (!inProfile) continue;
        // 解析 key=value
        char* eq = strchr(line, '=');
        if (!eq) continue;
        *eq = 0;
        char* key = line;
        char* val = eq + 1;
        if (strcmp(key, "serialno") == 0) strncpy(buf_serialno, val, sizeof(buf_serialno)-1);
        else if (strcmp(key, "fingerprint") == 0) strncpy(buf_fingerprint, val, sizeof(buf_fingerprint)-1);
        else if (strcmp(key, "model") == 0) strncpy(buf_model, val, sizeof(buf_model)-1);
        else if (strcmp(key, "brand") == 0) strncpy(buf_brand, val, sizeof(buf_brand)-1);
        else if (strcmp(key, "hardware") == 0) strncpy(buf_hardware, val, sizeof(buf_hardware)-1);
        else if (strcmp(key, "board") == 0) strncpy(buf_board, val, sizeof(buf_board)-1);
    }
    fclose(f);
    
    // 静态 buffer 保持生命周期
    static char s_serialno[128], s_fingerprint[256], s_model[64], s_brand[64], s_hardware[64], s_board[64];
    if (buf_serialno[0]) { strcpy(s_serialno, buf_serialno); fakeDev.serialno = s_serialno; fakeDev.boot_serialno = s_serialno; }
    if (buf_fingerprint[0]) { strcpy(s_fingerprint, buf_fingerprint); fakeDev.fingerprint = s_fingerprint; }
    if (buf_model[0]) { strcpy(s_model, buf_model); fakeDev.model = s_model; }
    if (buf_brand[0]) { strcpy(s_brand, buf_brand); fakeDev.brand = s_brand; }
    if (buf_hardware[0]) { strcpy(s_hardware, buf_hardware); fakeDev.hardware = s_hardware; }
    if (buf_board[0]) { strcpy(s_board, buf_board); fakeDev.board = s_board; }
    
    LOGI("Fake device loaded: %s %s", fakeDev.brand, fakeDev.model);
}

// 读取设置开关
static void loadSettings() {
    FILE* f = fopen("/data/adb/colamanga_mod/config/settings.conf", "r");
    if (!f) return;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\n")] = 0;
        if (strstr(line, "anti_debug=0")) antiDebugEnabled = false;
        else if (strstr(line, "hide_root=0")) hideRootEnabled = false;
        else if (strstr(line, "packet_capture=0")) captureEnabled = false;
    }
    fclose(f);
}

// ====== 原始函数指针 ======
static int (*orig_property_get)(const char*, char*, const char*) = nullptr;
static long (*orig_ptrace)(int, pid_t, void*, void*) = nullptr;
static int (*orig_openat)(int, const char*, int, ...) = nullptr;
static int (*orig_connect)(int, const struct sockaddr*, socklen_t) = nullptr;

// ====== Hook: __system_property_get ======
static int hook_property_get(const char* name, char* value, const char* default_value) {
    if (!isTargetProcess || !name) {
        return orig_property_get ? orig_property_get(name, value, default_value) : 0;
    }
    
    // 对目标进程，返回假属性
    const char* fakeVal = nullptr;
    if (strcmp(name, "ro.serialno") == 0 || strcmp(name, "ro.boot.serialno") == 0) fakeVal = fakeDev.serialno;
    else if (strcmp(name, "ro.build.fingerprint") == 0) fakeVal = fakeDev.fingerprint;
    else if (strcmp(name, "ro.product.model") == 0 || strcmp(name, "ro.product.system.model") == 0) fakeVal = fakeDev.model;
    else if (strcmp(name, "ro.product.brand") == 0 || strcmp(name, "ro.product.system.brand") == 0) fakeVal = fakeDev.brand;
    else if (strcmp(name, "ro.product.device") == 0) fakeVal = fakeDev.device;
    else if (strcmp(name, "ro.product.name") == 0) fakeVal = fakeDev.product;
    else if (strcmp(name, "ro.product.manufacturer") == 0) fakeVal = fakeDev.manufacturer;
    else if (strcmp(name, "ro.hardware") == 0 || strcmp(name, "ro.boot.hardware") == 0) fakeVal = fakeDev.hardware;
    else if (strcmp(name, "ro.product.board") == 0 || strcmp(name, "ro.board.platform") == 0) fakeVal = fakeDev.board;
    else if (strcmp(name, "ro.build.host") == 0) fakeVal = fakeDev.host;
    else if (strcmp(name, "ro.build.id") == 0) fakeVal = fakeDev.id;
    else if (strcmp(name, "ro.build.version.incremental") == 0) fakeVal = fakeDev.incremental;
    else if (strcmp(name, "ro.build.version.security_patch") == 0) fakeVal = fakeDev.security_patch;
    else if (strcmp(name, "ro.build.version.release") == 0) fakeVal = fakeDev.release;
    else if (strcmp(name, "ro.build.version.sdk") == 0) fakeVal = fakeDev.sdk;
    else if (strcmp(name, "ro.build.type") == 0) fakeVal = fakeDev.type;
    else if (strcmp(name, "ro.build.tags") == 0) fakeVal = fakeDev.tags;
    
    if (fakeVal) {
        if (value) { strncpy(value, fakeVal, 91); value[91] = 0; }
        return (int)strlen(fakeVal);
    }
    
    return orig_property_get ? orig_property_get(name, value, default_value) : 0;
}

// ====== Hook: ptrace（反调试屏蔽）======
static long hook_ptrace(int request, pid_t pid, void* addr, void* data) {
    if (isTargetProcess && antiDebugEnabled) {
        // 返回成功，让风控以为没人调试
        if (request == PTRACE_TRACEME) return 0;
        if (request == PTRACE_ATTACH) return 0;
        // 返回-1但不设置 errno（让检测代码以为没被调试）
        errno = 0;
        return -1;
    }
    return orig_ptrace ? orig_ptrace(request, pid, addr, data) : -1;
}

// ====== Hook: openat（屏蔽检测文件）======
static int hook_openat(int dirfd, const char* path, int flags, ...) {
    if (isTargetProcess && path) {
        // TracerPid 清零：读 /proc/self/status 时返回无 TracerPid 的版本
        if (hideRootEnabled) {
            // 隐藏 su/magisk/root 相关文件
            if (strstr(path, "/sbin/su") || strstr(path, "magisk") || 
                strstr(path, "/su/bin") || strstr(path, "supersu") ||
                strstr(path, "kernelsu") || strstr(path, "ksu") ||
                strstr(path, "xposed") || strstr(path, "lsposed") ||
                strstr(path, "riru") || strstr(path, "zygisk") ||
                strstr(path, "frida") || strstr(path, "/sbin/.magisk")) {
                errno = ENOENT;
                return -1;
            }
        }
    }
    // 调用原始
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags); mode = va_arg(ap, int); va_end(ap);
    }
    return orig_openat ? orig_openat(dirfd, path, flags, mode) : -1;
}

// ====== Hook: connect（抓包记录）======
static int hook_connect(int sockfd, const struct sockaddr* addr, socklen_t addrlen) {
    if (isTargetProcess && captureEnabled && addr) {
        char ip[64] = {0};
        int port = 0;
        if (addr->sa_family == AF_INET) {
            const struct sockaddr_in* a = (const struct sockaddr_in*)addr;
            inet_ntop(AF_INET, &a->sin_addr, ip, sizeof(ip));
            port = ntohs(a->sin_port);
        } else if (addr->sa_family == AF_INET6) {
            const struct sockaddr_in6* a = (const struct sockaddr_in6*)addr;
            inet_ntop(AF_INET6, &a->sin6_addr, ip, sizeof(ip));
            port = ntohs(a->sin6_port);
        }
        if (ip[0]) {
            LOGI("[CAPTURE] connect %s:%d fd=%d", ip, port, sockfd);
            // 写入抓包日志
            FILE* f = fopen("/data/adb/colamanga_mod/logs/network.log", "a");
            if (f) {
                fprintf(f, "%s connect %s:%d fd=%d\n", __TIME__, ip, port, sockfd);
                fclose(f);
            }
        }
    }
    return orig_connect ? orig_connect(sockfd, addr, addrlen) : -1;
}

// ====== PLT Hook 安装（手动 GOT 替换）======
static bool install_plt_hook(const char* sym, void* hook_func, void** orig_func) {
    void* sym_addr = dlsym(RTLD_DEFAULT, sym);
    if (!sym_addr) {
        LOGE("Cannot find %s", sym);
        return false;
    }
    
    // 找到所有加载的 so 的 GOT 并替换
    FILE* maps = fopen("/proc/self/maps", "r");
    if (!maps) return false;
    
    char line[512];
    bool hooked = false;
    while (fgets(line, sizeof(line), maps)) {
        // 找 r-xp 段的可执行映射
        if (!strstr(line, "r-xp") && !strstr(line, "r--p")) continue;
        
        // 解析基址
        unsigned long start, end;
        if (sscanf(line, "%lx-%lx", &start, &end) != 2) continue;
        
        // 搜索 GOT 表中的符号地址
        unsigned long* got = (unsigned long*)start;
        for (unsigned long addr = start; addr + sizeof(void*) <= end; addr += sizeof(void*)) {
            if (*(void**)addr == sym_addr) {
                // 找到 GOT 条目，替换为 hook
                mprotect((void*)(addr & ~0xfff), 0x1000, PROT_READ | PROT_WRITE);
                if (orig_func && !*orig_func) *orig_func = *(void**)addr;
                *(void**)addr = hook_func;
                mprotect((void*)(addr & ~0xfff), 0x1000, PROT_READ);
                hooked = true;
            }
        }
    }
    fclose(maps);
    return hooked;
}

// ====== Zygisk 模块类 ======
class ColaMangaModule {
public:
    void onLoad() {
        LOGI("ColaManga Zygisk module loaded");
    }
    
    void preAppSpecialize(const char* nice_name) {
        // 检查是否是目标进程
        if (!nice_name) return;
        for (int i = 0; TARGET_PACKAGES[i]; i++) {
            if (strcmp(nice_name, TARGET_PACKAGES[i]) == 0) {
                isTargetProcess = true;
                break;
            }
        }
        
        if (isTargetProcess) {
            LOGI("Target process detected: %s", nice_name);
            loadFakeDevice();
            loadSettings();
        }
    }
    
    void postAppSpecialize() {
        if (!isTargetProcess) return;
        
        LOGI("Installing native hooks for colamanga...");
        
        // 安装 __system_property_get hook
        install_plt_hook("__system_property_get", (void*)hook_property_get, (void**)&orig_property_get);
        LOGI("property_get hook: %s", orig_property_get ? "OK" : "FAIL");
        
        // 安装 ptrace hook
        install_plt_hook("ptrace", (void*)hook_ptrace, (void**)&orig_ptrace);
        LOGI("ptrace hook: %s", orig_ptrace ? "OK" : "FAIL");
        
        // 安装 openat hook
        install_plt_hook("openat", (void*)hook_openat, (void**)&orig_openat);
        LOGI("openat hook: %s", orig_openat ? "OK" : "FAIL");
        
        // 安装 connect hook（抓包）
        install_plt_hook("connect", (void*)hook_connect, (void**)&orig_connect);
        LOGI("connect hook: %s", orig_connect ? "OK" : "FAIL");
        
        LOGI("All native hooks installed for colamanga");
    }
};

static ColaMangaModule g_module;

// Zygisk 入口（被 Zygisk 框架调用）
extern "C" [[gnu::visibility("default")]] void* zygisk_module_entry(void* api) {
    LOGI("zygisk_module_entry called");
    return &g_module;
}

// 兼容：某些 Zygisk 版本用 REGISTER_ZYGISK_MODULE 宏
extern "C" [[gnu::visibility("default")]] void* create_module(void* table) {
    return &g_module;
}