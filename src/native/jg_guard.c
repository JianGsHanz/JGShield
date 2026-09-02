/*
 * JGShield native 反篡改 / 反调试守护层 (jg_guard.c)
 * --------------------------------------------------------------------------
 * 设计原则（与 Java 反篡改一致，且更难点 hook）：
 *   1. fail-safe：任何异常（文件读不到、socket 失败、线程创建失败）都「视为未篡改」，
 *      绝不因自身错误导致 App 崩溃或退出。
 *   2. 与加载器物理隔离：仅做后台周期检测 + 命中即静默 exit，不碰解密/加载逻辑。
 *   3. 纯 C + JNI + liblog，无 C++/STL 依赖，ABI 稳定、体积小。
 *   4. 不引入自 ptrace(PTRACE_TRACEME)：避免影响开发者正常调试自己的 App，
 *      调试器检测仍由 TracerPid 扫描覆盖。
 *
 * 检测项（与 Java AntiTamper 对齐，但运行在 native，hook 难度更高）：
 *   - /proc/self/maps 关键字（frida/gadget/substrate/xposed/magisk/...）
 *   - /proc/self/status 与 /proc/self/task 下各线程 status 的 TracerPid != 0
 *   - frida-server 默认端口 27042/27043 是否监听
 *   - /data/local/tmp/re.frida.server 文件是否存在
 * 命中 -> 静默 exit(1)（与 Java 端默认行为一致，干净设备永远走不到这里）。
 */
#include <jni.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <android/log.h>
#include "jg_crypto.h"
#ifdef WB_KDF
/* P0-B 真白盒：仅 -DWB_KDF 时引入白盒 KDF（WB_STATE 已烘焙进该头）。 */
#include "whitebox_kdf.h"
#endif

#define TAG "JG-Native"

/* 扩展特征库：覆盖改名后的 frida-gadget / magisk / 各类 hook 框架 */
static const char *MAP_KEYWORDS[] = {
    "frida", "gadget", "libfrida", "frida-agent", "substrate",
    "xposed", "libsandhook", "libmsaoaidsec", "libnativehook",
    "cydia", "magisk", "re.frida", "frida-server", NULL
};

static const int FRIDA_PORTS[] = {27042, 27043};
static const int POLL_MS = 2000;          /* 周期轮询间隔 */
static volatile int g_stop = 0;
static int g_response_exit = 0;   /* 0 = log-only(fail-safe 默认); 1 = exit */

/* 防御式读文件：成功返回读取字节数(>=0)，失败返回 -1；buf 末尾补 \0 */
static int read_file(const char *path, char *buf, size_t buflen) {
    if (!path || !buf || buflen == 0) return -1;
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    size_t n = fread(buf, 1, buflen - 1, f);
    if (ferror(f)) { fclose(f); return -1; }
    buf[n] = '\0';
    fclose(f);
    return (int)n;
}

/* 逐行扫描 maps，命中任一关键字即视为篡改 */
static int scan_maps(void) {
    char buf[16384];
    if (read_file("/proc/self/maps", buf, sizeof(buf)) < 0) return 0;
    char *p = buf;
    while (*p) {
        for (int k = 0; MAP_KEYWORDS[k]; k++) {
            if (strstr(p, MAP_KEYWORDS[k])) {
                __android_log_print(ANDROID_LOG_WARN, TAG, "maps hit: %s", MAP_KEYWORDS[k]);
                return 1;
            }
        }
        char *nl = strchr(p, '\n');
        if (!nl) break;
        p = nl + 1;
    }
    return 0;
}

/* 检查单个 status 文件中的 TracerPid 字段 */
static int check_status_tracerpid(const char *path) {
    char buf[4096];
    if (read_file(path, buf, sizeof(buf)) < 0) return 0;
    char *p = buf;
    while (*p) {
        if (strncmp(p, "TracerPid:", 11) == 0) {
            char *v = p + 11;
            while (*v == ' ' || *v == '\t') v++;
            int pid = atoi(v);
            if (pid != 0) {
                __android_log_print(ANDROID_LOG_WARN, TAG, "TracerPid=%d @ %s", pid, path);
                return 1;
            }
            return 0;   /* TracerPid 字段读到且为 0，无需继续 */
        }
        char *nl = strchr(p, '\n');
        if (!nl) break;
        p = nl + 1;
    }
    return 0;
}

/* 检查自身进程与所有线程的 TracerPid */
static int check_tracerpid(void) {
    if (check_status_tracerpid("/proc/self/status")) return 1;
    /* 遍历 /proc/self/task/<tid>/status，任一线程被 trace 即视为篡改 */
    DIR *d = opendir("/proc/self/task");
    if (!d) return 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        char path[64];
        snprintf(path, sizeof(path), "/proc/self/task/%s/status", e->d_name);
        if (check_status_tracerpid(path)) {
            closedir(d);
            return 1;
        }
    }
    closedir(d);
    return 0;
}

/* 探测本地端口是否监听（阻塞 connect + 短超时），命中视为 frida 在跑 */
static int probe_port(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 0;
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 200000;   /* 200ms */
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    sa.sin_addr.s_addr = inet_addr("127.0.0.1");
    int r = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
    close(fd);
    if (r == 0) {
        __android_log_print(ANDROID_LOG_WARN, TAG, "frida port %d open", port);
        return 1;
    }
    return 0;
}

static int check_frida_server_file(void) {
    struct stat st;
    if (stat("/data/local/tmp/re.frida.server", &st) == 0) {
        __android_log_print(ANDROID_LOG_WARN, TAG, "frida server file exists");
        return 1;
    }
    return 0;
}

/* 综合检测：任一命中即视为被篡改。各子检测独立，互不影响。 */
static int detect(void) {
    return scan_maps()
        || check_tracerpid()
        || check_frida_server_file()
        || probe_port(FRIDA_PORTS[0])
        || probe_port(FRIDA_PORTS[1]);
}

static void respond(void) {
    /* 统一收口到 Java 侧 STRENGTHEN_RESPONSE：默认 log=仅记录、不阻断；
       exit=静默退出进程（与 AntiDebug / AntiTamper 行为一致）。 */
    if (!g_response_exit) {
        __android_log_print(ANDROID_LOG_WARN, TAG,
            "tamper detected but response=log (STRENGTHEN_RESPONSE) -> continue");
        return;
    }
    __android_log_print(ANDROID_LOG_WARN, TAG, "tamper confirmed -> exit");
    exit(1);
}

static void *guard_thread(void *arg) {
    (void)arg;
    /* 启动即查一次；之后周期轮询 */
    if (detect()) respond();
    while (!g_stop) {
        usleep((useconds_t)POLL_MS * 1000);
        if (detect()) respond();
    }
    return NULL;
}

/* JNI 入口：由 Java 侧 JgGuard.nativeStart() 调用，启动守护线程 */
JNIEXPORT void JNICALL
Java_com_gx_runtime_GxGuard_nativeStart(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    pthread_t tid;
    if (pthread_create(&tid, NULL, guard_thread, NULL) != 0) {
        /* 线程创建失败：优雅降级，不抛异常、不影响 App */
        return;
    }
    pthread_detach(tid);
}

JNIEXPORT void JNICALL
Java_com_gx_runtime_GxGuard_nativeSetResponse(JNIEnv *env, jclass clazz, jstring mode) {
    (void)clazz;
    g_response_exit = 0;
    if (mode) {
        const char *s = (*env)->GetStringUTFChars(env, mode, NULL);
        if (s) {
            if (strcmp(s, "exit") == 0) g_response_exit = 1;
            (*env)->ReleaseStringUTFChars(env, mode, s);
        }
    }
    __android_log_print(ANDROID_LOG_INFO, TAG, "response mode=%s",
                        g_response_exit ? "exit" : "log");
}

/* ===== 密钥派生下沉（GxKeys）===== */
/* seed = HMAC(key=salt, msg=SHA256(certDer))；与 Java 原 seed() 语义一致。 */
JNIEXPORT jbyteArray JNICALL
Java_com_gx_runtime_GxKeys_nativeDeriveSeed(JNIEnv *env, jclass clazz,
        jbyteArray certDer, jbyteArray salt) {
    (void)clazz;
    jbyte *cert = (*env)->GetByteArrayElements(env, certDer, NULL);
    jsize clen = (*env)->GetArrayLength(env, certDer);
    jbyte *slt = (*env)->GetByteArrayElements(env, salt, NULL);
    jsize slen = (*env)->GetArrayLength(env, salt);
    uint8_t certHash[32];
    jg_sha256_ctx sc; jg_sha256_init(&sc);
    jg_sha256_update(&sc, (const uint8_t*)cert, (size_t)clen);
    jg_sha256_final(certHash, &sc);
    uint8_t seed[32];
    jg_hmac_sha256((const uint8_t*)slt, (size_t)slen, certHash, 32, seed);
    (*env)->ReleaseByteArrayElements(env, certDer, cert, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, salt, slt, JNI_ABORT);
    jbyteArray out = (*env)->NewByteArray(env, 32);
    (*env)->SetByteArrayRegion(env, out, 0, 32, (jbyte*)seed);
    return out;
}

/* key = HMAC(key=seed, msg="JG|"+info)；与 Java 原 keyFor() 语义一致。 */
JNIEXPORT jbyteArray JNICALL
Java_com_gx_runtime_GxKeys_nativeKeyFor(JNIEnv *env, jclass clazz,
        jbyteArray seedArr, jbyteArray info) {
    (void)clazz;
    jbyte *sd = (*env)->GetByteArrayElements(env, seedArr, NULL);
    jsize sdlen = (*env)->GetArrayLength(env, seedArr);
    jbyte *inf = (*env)->GetByteArrayElements(env, info, NULL);
    jsize inflen = (*env)->GetArrayLength(env, info);
    uint8_t out[32];
#ifdef WB_KDF
    /* P0-B 真白盒：final = SHA256_cont(WB_STATE, HMAC(seed, info))；
     * WB_STATE 由 build_stub 烘焙进 whitebox_kdf.h（与 Python 写端逐字节一致）。 */
    wb_key_for((const uint8_t*)sd, (const uint8_t*)inf, (size_t)inflen, out);
#else
    jg_hmac_sha256((const uint8_t*)sd, (size_t)sdlen, (const uint8_t*)inf, (size_t)inflen, out);
#endif
    (*env)->ReleaseByteArrayElements(env, seedArr, sd, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, info, inf, JNI_ABORT);
    jbyteArray res = (*env)->NewByteArray(env, 32);
    (*env)->SetByteArrayRegion(env, res, 0, 32, (jbyte*)out);
    return res;
}

/* ===== P0-A：壳 DEX 密钥派生下沉（GxBootstrap）=====
 * 与 Java_com_gx_runtime_GxBootstrap.nativeDeriveShellKey / harden.py shell_salt
 * + encrypt_shell_dex 逐字节一致。salt 不再直接取 payload 末 32B 明文，改为
 * HMAC(key=payload[plen-32:], msg=payload[0:32]) 融合，避免明文 salt 暴露。
 * 本函数随壳 .so 经 OLLVM 混淆（-fla/-bcf/-sub/-sobf），静态读壳成本显著上升。
 * 派生链：certHash = SHA256(certDer)
 *         salt     = HMAC(trailer, head)
 *         seed     = HMAC(salt, certHash)
 *         key      = HMAC(seed, "JG|shell0")   // KEY_PREFIX + "shell" + idx */
JNIEXPORT jbyteArray JNICALL
Java_com_gx_runtime_GxBootstrap_nativeDeriveShellKey(JNIEnv *env, jclass clazz,
        jbyteArray certDer, jbyteArray payload) {
    (void)clazz;
    jbyte *cert = (*env)->GetByteArrayElements(env, certDer, NULL);
    jsize clen = (*env)->GetArrayLength(env, certDer);
    jbyte *pay = (*env)->GetByteArrayElements(env, payload, NULL);
    jsize plen = (*env)->GetArrayLength(env, payload);

    uint8_t certHash[32];
    jg_sha256_ctx sc; jg_sha256_init(&sc);
    jg_sha256_update(&sc, (const uint8_t*)cert, (size_t)clen);
    jg_sha256_final(certHash, &sc);

    /* shell_salt = HMAC(key=payload[plen-32:], msg=payload[0:32]) */
    uint8_t salt[32];
    const uint8_t *trailer = (plen >= 32) ? (const uint8_t*)pay + (plen - 32) : (const uint8_t*)pay;
    size_t tlen = (plen >= 32) ? 32 : (size_t)plen;
    const uint8_t *head = (const uint8_t*)pay;
    size_t hlen = (plen >= 32) ? 32 : (size_t)plen;
    jg_hmac_sha256(trailer, tlen, head, hlen, salt);

    uint8_t seed[32];
    jg_hmac_sha256(salt, 32, certHash, 32, seed);

    /* info = KEY_PREFIX + "shell" + idx；前缀随 stamp 随机化（见 build_stub._sed_native）。
     * 必须用字符串字面量 "JG|shell0" 以便 _sed_native 替换为随机前缀，禁止手写字节，
     * 否则写端(随机前缀)与读端(死 JG|)密钥不等 → GCM BAD_DECRYPT（P0-A 引入的回归）。
     * 严禁在此函数写任何循环：壳 .so 经远端 OLLVM -fla/-bcf 混淆，-fla 对用户循环拍平
     * 会生成非终止代码 → 启动期无限循环 → 主线程 ANR（P0-A 修复引入的二次回归）。
     * 故用 strlen+memcpy 取字节（库函数，不受 -fla 用户循环拍平影响），函数体保持直线。 */
    const char *info_str = "JG|shell0";
    uint8_t info[16];
    int il = (int)strlen(info_str);
    memcpy(info, info_str, (size_t)il);
    uint8_t key[32];
    jg_hmac_sha256(seed, 32, info, (size_t)il, key);

    (*env)->ReleaseByteArrayElements(env, certDer, cert, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, payload, pay, JNI_ABORT);
    jbyteArray out = (*env)->NewByteArray(env, 32);
    (*env)->SetByteArrayRegion(env, out, 0, 32, (jbyte*)key);
    return out;
}

JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm; (void)reserved;
    return JNI_VERSION_1_6;
}
