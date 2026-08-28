// colamanga_zygisk.cpp - 纯 Zygisk 模块（系统原生级，不依赖 LSPosed）
// 通过 Zygisk 在 zygote 注入，native 层 hook libc + JNI 方法，无 xposed 特征
// hook: __system_property_get(假属性) + ptrace(反调试) + access(隐藏frida/root) + JNI(设备标识)
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

// ===== 假属性（从 device_id.json 读取，WebUI 实时改）=====
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
    free(json);
    LOGI("[cfg] %s %s serial=%s imei=%s", s_brand, s_model, s_serialno, s_imei);
}

// ====== inline hook（手写，最可控）======
static unsigned char g_orig[16];
static void* g_tramp = nullptr;

static void* inline_hook(void* target, void* hook_fn) {
    if (!target || !hook_fn) return nullptr;
    memcpy(g_orig, target, 16);
    g_tramp = mmap(nullptr, 4096, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (g_tramp == MAP_FAILED) return nullptr;
    unsigned char* t = (unsigned char*)g_tramp;
    memcpy(t, g_orig, 16);
    *(uint32_t*)(t+16) = 0x58000050;
    *(uint32_t*)(t+20) = 0xD61FE020;
    *(void**)(t+24) = (void*)((uintptr_t)target + 16);
    __builtin___clear_cache((char*)g_tramp, (char*)g_tramp + 32);
    uintptr_t page = (uintptr_t)target & ~0xFFFULL;
    mprotect((void*)page, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC);
    *(uint32_t*)((unsigned char*)target+0) = 0x58000050;
    *(uint32_t*)((unsigned char*)target+4) = 0xD61FE020;
    *(void**)((unsigned char*)target+8) = hook_fn;
    mprotect((void*)page, 0x1000, PROT_READ|PROT_EXEC);
    __builtin___clear_cache((char*)target, (char*)target + 16);
    return g_tramp;
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

// ====== JNI 方法 hook（设备标识 native 方法）======
static jstring fakeJString(JNIEnv* env, const char* s) { return env->NewStringUTF(s); }

static jstring hook_Build_getSerial(JNIEnv* env, jclass) { return fakeJString(env, s_serialno); }
static jstring hook_Telephony_getImei(JNIEnv* env, jobject) { return fakeJString(env, s_imei); }
static jstring hook_Telephony_getDeviceId(JNIEnv* env, jobject) { return fakeJString(env, s_imei); }
static jstring hook_Telephony_getLine1Number(JNIEnv* env, jobject) { return fakeJString(env, s_line1); }
static jstring hook_Telephony_getSubscriberId(JNIEnv* env, jobject) { return fakeJString(env, s_imei); }
static jstring hook_Telephony_getMeid(JNIEnv* env, jobject) { return fakeJString(env, s_meid); }

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
        LOGI("[post] 目标进程已沙箱化，开始 hook");
        load_config();

        // 1. inline hook libc 函数
        void* fn = dlsym(RTLD_DEFAULT, "__system_property_get");
        tramp_property = inline_hook(fn, (void*)hook_property_get);
        fn = dlsym(RTLD_DEFAULT, "ptrace");
        tramp_ptrace = inline_hook(fn, (void*)hook_ptrace);
        fn = dlsym(RTLD_DEFAULT, "access");
        tramp_access = inline_hook(fn, (void*)hook_access);
        LOGI("[hook] libc: property=%p ptrace=%p access=%p", tramp_property, tramp_ptrace, tramp_access);

        // 2. hook JNI native 方法（设备标识）
        const char* build_serial[] = {"getSerial"};
        JNINativeMethod build_methods[] = {
            {"getSerial", "()Ljava/lang/String;", (void*)hook_Build_getSerial},
        };
        api->hookJniNativeMethods(env, "android/os/Build", build_methods, 1);

        JNINativeMethod telephony_methods[] = {
            {"getImei", "()Ljava/lang/String;", (void*)hook_Telephony_getImei},
            {"getDeviceId", "()Ljava/lang/String;", (void*)hook_Telephony_getDeviceId},
            {"getLine1Number", "()Ljava/lang/String;", (void*)hook_Telephony_getLine1Number},
            {"getSubscriberId", "()Ljava/lang/String;", (void*)hook_Telephony_getSubscriberId},
            {"getMeid", "()Ljava/lang/String;", (void*)hook_Telephony_getMeid},
        };
        api->hookJniNativeMethods(env, "android/telephony/TelephonyManager", telephony_methods, 5);

        LOGI("[hook] JNI 方法已替换 (Build getSerial + Telephony getImei等)");
        LOGI("[hook] ColaManga Zygisk 模块 hook 完成");
    }

    void preServerSpecialize(ServerSpecializeArgs*) override {}
    void postServerSpecialize(const ServerSpecializeArgs*) override {}
};

REGISTER_ZYGISK_MODULE(ColaMangaModule)