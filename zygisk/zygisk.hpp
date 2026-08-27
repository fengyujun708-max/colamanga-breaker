/* Zygisk API - 精简版 (基于 Magisk 官方 Zygisk 接口规范) */
/* 放在 zygisk/ 目录下，编译时 -I. 包含 */
#pragma once
#include <jni.h>

#define ZYGISK_API_VERSION 4

namespace zygisk {

struct AppSpecializeArgs {
    jint &uid;
    jstring &nice_name;
    jstring &app_data_dir;
    jintArray &gid;
    jstringArray &fd_list;
    jstringArray &deny_list_fds;
    jstringArray &env_list;
    jstringArray &fd_paths;
    jboolean &is_top_app;
    jstringArray &fd_paths_whitelist;
    jboolean &hook_min_compat;
    void *server_fd_ptr;
    AppSpecializeArgs() = delete;
};

struct ServerSpecializeArgs {
    jstringArray &fd_list;
    jstringArray &fd_paths;
    jstringArray &env_list;
    jboolean &is_top_app;
    void *server_fd_ptr;
    ServerSpecializeArgs() = delete;
};

struct Module {
    virtual void onLoad() {}
    virtual void preAppSpecialize(AppSpecializeArgs *) {}
    virtual void postAppSpecialize(const AppSpecializeArgs *) {}
    virtual void preServerSpecialize(ServerSpecializeArgs *) {}
    virtual void postServerSpecialize(const ServerSpecializeArgs *) {}
};

} // namespace zygisk