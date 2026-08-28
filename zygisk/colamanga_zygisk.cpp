// colamanga_zygisk.cpp - 纯 Zygisk 模块 v2（修复 trampoline bug + 补全 so 层 hook）
// 不依赖 LSPosed，native 层 hook libc + JNI 方法
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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <android/log.h>
#include <errno.h>

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
    LOGI("[cfg] %s %s serial=%s imei=%s widevine=%s", s_brand, s_model, s_serialno, s_imei, s_widevine);
}

// ====== inline hook（多 hook，每个独立 trampoline，修复 trampoline 覆盖 bug）======
#define MAX_HOOKS 16
struct HookEntry { void* target; void* tramp; unsigned char orig[16]; };
static HookEntry g_hooks[MAX_HOOKS];
static int g_hook_count = 0;

static void* inline_hook(void* target, void* hook_fn) {
    if (!target || !hook_fn || g_hook_count >= MAX_HOOKS) return nullptr;
    HookEntry& e = g_hooks[g_hook_count];
    e.target = target;
    memcpy(e.orig, target, 16);
    e.tramp = mmap(nullptr, 4096, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (e.tramp == MAP_FAILED) return nullptr;
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

// ====== ptrace（反调试）======
static void* tramp_ptrace = nullptr;
typedef long (*ptrace_t)(int, pid_t, void*, void*);
static long hook_ptrace(int request, pid_t pid, void* addr, void* data) {
    if (request == PTRACE_TRACEME) return 0;
    if (request == PTRACE_ATTACH) { errno = 0; return -1; }
    return ((ptrace_t)tramp_ptrace)(request, pid, addr, data);
}

// ====== access（隐藏 frida/root 文件）======
static void* tramp_access = nullptr;
typedef int (*access_t)(const char*, int);
static int hook_access(const char* path, int mode) {
    if (path) {
        const char* kws[] = {"frida", "gum-js-loop", "magisk", "/su", "supersu", "kernelsu", "xposed", "lsposed", "riru", "zygisk", "gadget", nullptr};
        for (int i = 0; kws[i]; i++) if (strstr(path, kws[i])) { errno = ENOENT; return -1; }
    }
    return ((access_t)tramp_access)(path, mode);
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

// ====== JNI hook：返回假字符串 ======
static jstring jstr(JNIEnv* env, const char* s) { return env->NewStringUTF(s); }

// 返回假 byte[]（MAC/Widevine 用）
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
    // MAC "A8:63:EA:C6:D2:3E" -> 6 bytes
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

        // 1. inline hook libc（每个独立 trampoline）
        void* fn = dlsym(RTLD_DEFAULT, "__system_property_get");
        tramp_property = inline_hook(fn, (void*)hook_property_get);
        fn = dlsym(RTLD_DEFAULT, "ptrace");
        tramp_ptrace = inline_hook(fn, (void*)hook_ptrace);
        fn = dlsym(RTLD_DEFAULT, "access");
        tramp_access = inline_hook(fn, (void*)hook_access);
        fn = dlsym(RTLD_DEFAULT, "connect");
        tramp_connect = inline_hook(fn, (void*)hook_connect);
        fn = dlsym(RTLD_DEFAULT, "getaddrinfo");
        tramp_getaddrinfo = inline_hook(fn, (void*)hook_getaddrinfo);
        LOGI("[hook] libc: property=%p ptrace=%p access=%p connect=%p dns=%p",
             tramp_property, tramp_ptrace, tramp_access, tramp_connect, tramp_getaddrinfo);

        // 2. hook JNI native 方法（设备标识）
        JNINativeMethod build_methods[] = {
            {"getSerial", "()Ljava/lang/String;", (void*)hook_Build_getSerial},
            {"getRadioVersion", "()Ljava/lang/String;", (void*)hook_Build_getRadioVersion},
        };
        api->hookJniNativeMethods(env, "android/os/Build", build_methods, 2);

        JNINativeMethod tel_methods[] = {
            {"getImei", "()Ljava/lang/String;", (void*)hook_Tel_getImei},
            {"getDeviceId", "()Ljava/lang/String;", (void*)hook_Tel_getDeviceId},
            {"getLine1Number", "()Ljava/lang/String;", (void*)hook_Tel_getLine1Number},
            {"getSubscriberId", "()Ljava/lang/String;", (void*)hook_Tel_getSubscriberId},
            {"getMeid", "()Ljava/lang/String;", (void*)hook_Tel_getMeid},
        };
        api->hookJniNativeMethods(env, "android/telephony/TelephonyManager", tel_methods, 5);

        JNINativeMethod wifi_methods[] = {
            {"getMacAddress", "()Ljava/lang/String;", (void*)hook_Wifi_getMac},
        };
        api->hookJniNativeMethods(env, "android/net/wifi/WifiInfo", wifi_methods, 1);

        JNINativeMethod netif_methods[] = {
            {"getHardwareAddress", "()[B", (void*)hook_Netif_getHardwareAddr},
        };
        api->hookJniNativeMethods(env, "java/net/NetworkInterface", netif_methods, 1);

        JNINativeMethod drm_methods[] = {
            {"getPropertyByteArray", "(Ljava/lang/String;)[B", (void*)hook_MediaDrm_getProperty},
        };
        api->hookJniNativeMethods(env, "android/media/MediaDrm", drm_methods, 1);

        LOGI("[hook] JNI: Build(2)+Telephony(5)+Wifi(1)+Netif(1)+MediaDrm(1) 已替换");
        LOGI("[hook] ColaManga 纯 Zygisk 模块 hook 完成");
    }

    void preServerSpecialize(ServerSpecializeArgs*) override {}
    void postServerSpecialize(const ServerSpecializeArgs*) override {}
};

REGISTER_ZYGISK_MODULE(ColaMangaModule)