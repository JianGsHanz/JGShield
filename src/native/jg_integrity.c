/*
 * jg_integrity.c - JGShield 环境检测 + 运行时自校验（root/模拟器/自 hook 篡改）
 * --------------------------------------------------------------------------
 * 与 jg_guard.c（活跃篡改检测：frida/maps/TracerPid/端口）互补，本模块聚焦：
 *   1) envCheck：root（su 二进制）、test-keys 构建、模拟器指纹、qemu 设备节点。
 *   2) integrityScan：可疑线程名（frida/gum/...）、libjgguard.so 自身被改为可写、
 *      自身关键函数被 inline hook（首指令跳转到 .so 之外）。
 * 全部 fail-safe：任何解析失败都视为「未命中」，绝不抛异常 / 退出，不影响 App 启动。
 * 默认响应为「仅记录日志」（不主动退出），避免误杀正常设备；如需强硬可在 Java 侧
 * 读取返回值后决定。RWX 区域计数仅作信息性日志（JIT 也会产生 RWX，不计入 issue）。
 */
#include <jni.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/system_properties.h>
#include <android/log.h>

#define TAG "JG-Integrity"

/* 防御读文件：返回字节数，失败 -1，末尾补 \0 */
static int read_file(const char *path, char *buf, size_t buflen) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    size_t n = fread(buf, 1, buflen - 1, f);
    if (ferror(f)) { fclose(f); return -1; }
    buf[n] = '\0';
    fclose(f);
    return (int)n;
}

/* 小写化（原地） */
static void lower(char *s) { for (; *s; s++) if (*s >= 'A' && *s <= 'Z') *s += 32; }

/* ---------- root 检测 ---------- */
static int check_root(void) {
    static const char *su[] = {
        "/system/bin/su", "/system/xbin/su", "/sbin/su",
        "/su/bin/su", "/magisk/.core", "/data/local/bin/su", NULL
    };
    for (int i = 0; su[i]; i++) {
        if (access(su[i], F_OK) == 0) {
            __android_log_print(ANDROID_LOG_WARN, TAG, "root: %s exists", su[i]);
            return 1;
        }
    }
    return 0;
}

/* ---------- 模拟器检测 ---------- */
static int check_emulator(void) {
    char buf[PROP_VALUE_MAX];
    int hit = 0;
    if (__system_property_get("ro.build.tags", buf) > 0) {
        lower(buf);
        if (strstr(buf, "test-keys")) {
            __android_log_print(ANDROID_LOG_WARN, TAG, "emu: ro.build.tags=test-keys");
            hit = 1;
        }
    }
    if (__system_property_get("ro.product.model", buf) > 0) {
        lower(buf);
        if (strstr(buf, "sdk") || strstr(buf, "emulator") || strstr(buf, "google_sdk")
            || strstr(buf, "goldfish") || strstr(buf, "ranchu")) {
            __android_log_print(ANDROID_LOG_WARN, TAG, "emu: model='%s'", buf);
            hit = 1;
        }
    }
    if (__system_property_get("ro.hardware", buf) > 0) {
        lower(buf);
        if (strstr(buf, "goldfish") || strstr(buf, "ranchu")) {
            __android_log_print(ANDROID_LOG_WARN, TAG, "emu: hardware='%s'", buf);
            hit = 1;
        }
    }
    if (__system_property_get("ro.kernel.qemu", buf) > 0) {
        if (buf[0] == '1') {
            __android_log_print(ANDROID_LOG_WARN, TAG, "emu: kernel.qemu=1");
            hit = 1;
        }
    }
    if (access("/dev/socket/qemud", F_OK) == 0 || access("/dev/qemu_pipe", F_OK) == 0) {
        __android_log_print(ANDROID_LOG_WARN, TAG, "emu: qemu device node");
        hit = 1;
    }
    return hit;
}

/* ---------- 可疑线程名扫描 ---------- */
static int scan_threads(void) {
    static const char *bad[] = { "frida", "gum", "gmain", "magisk", "sandhook", "substrate", "xposed", NULL };
    DIR *d = opendir("/proc/self/task");
    if (!d) return 0;
    int hits = 0;
    struct dirent *e;
    char path[80], name[32];
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        snprintf(path, sizeof(path), "/proc/self/task/%s/comm", e->d_name);
        FILE *f = fopen(path, "rb");
        if (!f) continue;
        size_t n = fread(name, 1, sizeof(name) - 1, f);
        fclose(f);
        if (n == 0) continue;
        while (n > 0 && (name[n-1] == '\n' || name[n-1] == '\0')) name[--n] = '\0';
        name[sizeof(name)-1] = '\0';
        lower(name);
        for (int k = 0; bad[k]; k++) {
            if (strstr(name, bad[k])) {
                __android_log_print(ANDROID_LOG_WARN, TAG, "thread '%s' matches '%s'", name, bad[k]);
                hits++; break;
            }
        }
    }
    closedir(d);
    return hits;
}

/* ---------- libjgguard.so 自身被改为可写（自保护 / 自篡改） ---------- */
static int check_self_writable(void) {
    char buf[16384];
    if (read_file("/proc/self/maps", buf, sizeof(buf)) < 0) return 0;
    char *p = buf;
    int hit = 0;
    while (*p) {
        char *nl = strchr(p, '\n');
        if (nl) *nl = '\0';
        char *q = p;
        while (*q && *q != ' ') q++;       /* 跳过地址列 */
        while (*q == ' ') q++;              /* q 指向权限位 */
        if (q[0] == 'r' && q[1] == 'w' && strstr(p, "libjgguard.so")) {
            __android_log_print(ANDROID_LOG_WARN, TAG, "self .so is writable: %s", p);
            hit = 1;
        }
        if (!nl) break;
        *nl = '\n';
        p = nl + 1;
    }
    return hit;
}

/* ---------- 自身关键函数首指令是否跳转到 .so 之外（inline hook 痕迹） ---------- */
static int check_self_hook(void) {
    void *fn = dlsym(RTLD_DEFAULT, "jg_restore_methods");
    if (!fn) return 0;
    uintptr_t faddr = (uintptr_t)fn;
    char buf[16384];
    if (read_file("/proc/self/maps", buf, sizeof(buf)) < 0) return 0;
    uintptr_t so_min = 0, so_max = 0;
    char *p = buf;
    while (*p) {
        char *nl = strchr(p, '\n');
        if (nl) *nl = '\0';
        if (strstr(p, "libjgguard.so")) {
            uintptr_t a, b;
            if (sscanf(p, "%lx-%lx", &a, &b) == 2) {
                if (so_min == 0 || a < so_min) so_min = a;
                if (b > so_max) so_max = b;
            }
        }
        if (!nl) break;
        *nl = '\n';
        p = nl + 1;
    }
    if (so_min == 0 || so_max == 0) return 0;
    uint32_t insn = *(volatile uint32_t *)faddr;
    /* arm64 B(0x14000000) / BL(0x94000000)，opcode 位 [31:26]=000101 / 100101 */
    uint32_t op = insn & 0xFC000000u;
    if (op == 0x14000000u || op == 0x94000000u) {
        int32_t imm = (int32_t)(insn & 0x03FFFFFFu);
        if (imm & 0x02000000u) imm |= 0xFC000000u;       /* 符号扩展 */
        int64_t target = (int64_t)faddr + (int64_t)imm * 4;
        if ((uintptr_t)target < so_min || (uintptr_t)target > so_max) {
            __android_log_print(ANDROID_LOG_WARN, TAG,
                "self function hooked? branch to %p outside .so", (void *)(intptr_t)target);
            return 1;
        }
    }
    return 0;
}

/* ---------- 全进程 RWX 区域计数（信息性，不计入 issue） ---------- */
static int count_rwx(void) {
    char buf[16384];
    if (read_file("/proc/self/maps", buf, sizeof(buf)) < 0) return 0;
    int n = 0;
    char *p = buf;
    while (*p) {
        char *nl = strchr(p, '\n');
        if (nl) *nl = '\0';
        char *q = p;
        while (*q && *q != ' ') q++;
        while (*q == ' ') q++;
        if (q[0] == 'r' && q[1] == 'w' && q[2] == 'x') n++;
        if (!nl) break;
        *nl = '\n';
        p = nl + 1;
    }
    return n;
}

JNIEXPORT jint JNICALL
Java_com_gx_runtime_GxGuard_nativeEnvCheck(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    int mask = 0;
    if (check_root()) mask |= 1;
    if (check_emulator()) mask |= 2;
    if (mask) __android_log_print(ANDROID_LOG_WARN, TAG, "envCheck mask=0x%x", mask);
    else __android_log_print(ANDROID_LOG_INFO, TAG, "envCheck: clean");
    return mask;
}

JNIEXPORT jint JNICALL
Java_com_gx_runtime_GxGuard_nativeIntegrityScan(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    int t = scan_threads();
    int selfW = check_self_writable();
    int selfH = check_self_hook();
    int rwx = count_rwx();
    int issues = t + (selfW ? 1 : 0) + (selfH ? 1 : 0);
    __android_log_print(ANDROID_LOG_INFO, TAG,
        "integrityScan: thread_hits=%d selfWritable=%d selfHooked=%d rwxRegions=%d (rwx informational)",
        t, selfW, selfH, rwx);
    if (issues) __android_log_print(ANDROID_LOG_WARN, TAG, "integrity issues=%d", issues);
    else __android_log_print(ANDROID_LOG_INFO, TAG, "integrity: clean");
    return issues;
}
