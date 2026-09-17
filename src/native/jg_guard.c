/*
 * JGShield native 反篡改 / 反调试守护层 (jg_guard.c)
 * --------------------------------------------------------------------------
 * 设计原则（与 Java 反篡改一致，且更难点 hook）：
 *   1. fail-safe：任何异常（文件读不到、socket 失败、线程创建失败）都「视为未篡改」，
 *      绝不因自身错误导致 App 崩溃或退出。
 *   2. 与加载器物理隔离：仅做后台周期检测 + 命中即静默 exit，不碰解密/加载逻辑。
 *   3. 纯 C + JNI + liblog，无 C++/STL 依赖，ABI 稳定、体积小。
 *   4. 自 ptrace：2026-09-04 起由 jg_ptrace_guard.c 的【持久 ptrace 守护】承担
 *      （fork 子进程 trace 全线程，堵 root /proc/pid/mem 直读）；本文件只做
 *      检测，TracerPid 类检测放行自己的守护子进程（jg_guard_tracer_is_child）。
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
#include <signal.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <android/log.h>
#include "jg_crypto.h"
#include "jg_rawsys.h"   /* P0-A：检测 IO 裸 syscall 化（frida hook libc 读不到真数据） */
#include "jg_strcrypt.h"  /* P4: 明文锚点 XOR(0x37) 编码，运行时解码 */
#ifdef WB_KDF
/* P0-B 真白盒：仅 -DWB_KDF 时引入白盒 KDF（WB_STATE 已烘焙进该头）。 */
#include "whitebox_kdf.h"
#endif

#define TAG "JG-Native"

/* 扩展特征库：覆盖改名后的 frida-gadget / magisk / 各类 hook 框架。
 * 注意：不放 "libmsaoaidsec"——那是 MSA(移动安全联盟) OAID SDK 的合法库，
 * 集成 OAID 的包自己 maps 里必有，出现≠被攻击（0904 报告①误杀分析：留着只会在
 * exit 模式下 100% 误杀集成 OAID 的全部真实用户，永远不会抓到攻击者）。
 * P4: 检测关键字表改为运行时解码（jg_strcrypt.h 的 JGX_MAP_KEYWORDS），
 * 见 scan_maps()，逐条 jgx_tbl 解码后 strstr 比对，原语义不变。 */

static const int FRIDA_PORTS[] = {27042, 27043};
static const int POLL_MS = 2000;          /* 周期轮询间隔 */

/* 来自 jg_anti_frida.c（同 .so）：B 跳板检测 / C 全端口握手 */
extern int jg_af_hook_patched(void);
extern int jg_af_frida_port_any(void);
/* 来自 jg_preload.c（同 .so）：P0-B OpenCommon 入口预载校验。
 * 返回 1=入口被下跳板（硬信号） 0=干净 -1=不确定（fail-safe 跳过）。 */
extern int jg_preload_check(void);
void jg_hard_exit(void);   /* 定义见本文件下方，裸 syscall 自毁 */
static volatile int g_stop = 0;
static int g_response_exit = 0;   /* 0 = log-only(fail-safe 默认); 1 = exit */

/* 防御式读文件（裸 syscall，P0-A）：成功返回读取字节数(>=0)，失败返回 -1；buf 末尾补 \0 */
static int read_file(const char *path, char *buf, size_t buflen) {
    if (!path || !buf || buflen < 2) return -1;
    return jg_read_file_raw(path, buf, (int)buflen);
}

/* 逐行扫描 maps，命中任一关键字即视为篡改（P4：路径与关键字均运行时解码） */
static int scan_maps(void) {
    char path[64];
    jgx_dec(JGX_MAPS, path, sizeof(path));
    char buf[16384];
    if (read_file(path, buf, sizeof(buf)) < 0) return 0;
    char *p = buf;
    char kw[32];
    while (*p) {
        for (int k = 0; k < (int)JGX_MAP_KEYWORDS_N; k++) {
            jgx_tbl(JGX_MAP_KEYWORDS, k, kw, sizeof(kw));
            if (strstr(p, kw)) {
                __android_log_print(ANDROID_LOG_WARN, TAG, "maps hit: %s", kw);
                return 1;
            }
        }
        char *nl = strchr(p, '\n');
        if (!nl) break;
        p = nl + 1;
    }
    return 0;
}

/* 检查单个 status 文件中的 TracerPid 字段。
 * 例外（2026-09-04 P0 补强）：持久 self-ptrace 守护激活后 TracerPid 恒为
 * 本进程 fork 出的守护子进程（PPid==self），必须放行，否则每 2s 误报一次。 */
extern int jg_guard_tracer_is_child(int tpid);

static int check_status_tracerpid(const char *path) {
    char buf[4096];
    if (read_file(path, buf, sizeof(buf)) < 0) return 0;
    char *p = buf;
    while (*p) {
        if (strncmp(p, "TracerPid:", 11) == 0) {
            char *v = p + 11;
            while (*v == ' ' || *v == '\t') v++;
            int pid = atoi(v);
            if (pid != 0 && !jg_guard_tracer_is_child(pid)) {
                __android_log_print(ANDROID_LOG_WARN, TAG, "TracerPid=%d @ %s", pid, path);
                return 1;
            }
            return 0;   /* TracerPid 为 0 或是自己的守护子进程 */
        }
        char *nl = strchr(p, '\n');
        if (!nl) break;
        p = nl + 1;
    }
    return 0;
}

/* 检查自身进程与所有线程的 TracerPid（裸 syscall 遍历 /proc/self/task） */
static int _status_tracer_cb(const char *name, void *ud) {
    int *hit = (int *)ud;
    char fmt[96], path[128];
    jgx_dec(JGX_TASK_STATUS, fmt, sizeof(fmt));
    snprintf(path, sizeof(path), fmt, name);
    if (check_status_tracerpid(path)) { *hit = 1; return 1; }
    return 0;
}

static int check_tracerpid(void) {
    char self_status[64];
    jgx_dec(JGX_STATUS, self_status, sizeof(self_status));
    if (check_status_tracerpid(self_status)) return 1;
    /* 遍历 /proc/self/task/<tid>/status，任一线程被 trace 即视为篡改 */
    char task[64];
    jgx_dec(JGX_TASK, task, sizeof(task));
    int hit = 0;
    jg_for_each_dir(task, _status_tracer_cb, &hit);
    return hit;
}

/* 探测本地端口是否监听（裸 syscall connect + 短超时），命中视为 frida 在跑 */
static int probe_port(int port) {
    long fd = jg_socket_tcp();
    if (fd < 0) return 0;
    jg_sock_timeo((int)fd, 200000, 0);
    int r = (jg_connect_local((int)fd, (unsigned short)port) == 0) ? 1 : 0;
    jg_close((int)fd);
    if (r == 1) {
        char s[96];
        jgx_dec(JGX_LOG_PORT_OPEN, s, sizeof(s));
        __android_log_print(ANDROID_LOG_WARN, TAG, s, port);
        return 1;
    }
    return 0;
}

static int check_frida_server_file(void) {
    /* 裸 syscall openat 探测存在性（替代 libc stat，防 PLT hook） */
    char srv[64];
    jgx_dec(JGX_FRIDA_SRV, srv, sizeof(srv));
    long fd = jg_open_ro(srv);
    if (fd >= 0) {
        jg_close((int)fd);
        char s[96];
        jgx_dec(JGX_LOG_SRV, s, sizeof(s));
        __android_log_print(ANDROID_LOG_WARN, TAG, s);
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
       exit=裸 syscall 自毁进程（exit(1) 走 libc 会被 frida hook 拦掉，必须用裸 syscall）。 */
    if (!g_response_exit) {
        __android_log_print(ANDROID_LOG_WARN, TAG,
            "tamper detected but response=log (STRENGTHEN_RESPONSE) -> continue");
        return;
    }
    __android_log_print(ANDROID_LOG_WARN, TAG, "tamper confirmed -> raw exit");
    jg_hard_exit();
}

/* 分级响应（0904 三次报告①：检测到却等于没检测，frida spawn 存活 40s+）：
 * 硬信号 = 外部 TracerPid 非 0——正常用户设备恒为 0（自家 ptrace 守护已按
 *   PPid==self 放行，跨 uid 无其他合法 ptrace 来源），误杀率≈0
 *   → 无条件 exit(1)，不受 STRENGTHEN_RESPONSE 门控，frida spawn 秒杀。
 * 模糊信号 = maps 关键词 / 端口 / 特征文件——有误报面（改名 so、root 机跑
 *   别家 frida 等）→ 走 respond()，仍由 STRENGTHEN_RESPONSE 统一收口。 */
static void hard_exit_on_tracer(void) {
    if (!check_tracerpid()) return;
    __android_log_print(ANDROID_LOG_WARN, TAG,
        "external tracer detected (hard signal) -> raw exit");
    jg_hard_exit();
}

/* F2: frida 线程名扫描（/proc/self/task/<tid>/comm，裸 syscall 读）。
 * frida17 spawn 注入完即 detach、agent 走 memfd（maps 无路径），
 * gum-js-loop / pool-frida-* 线程名是唯一稳定残留。
 * 自有线程统一 gx- 前缀，不会自咬。 */
struct jg_gum_ctx { int hit; };

static int _gum_comm_cb(const char *name, void *ud) {
    struct jg_gum_ctx *ctx = (struct jg_gum_ctx *)ud;
    char fmt[96], path[128];
    jgx_dec(JGX_TASK_COMM, fmt, sizeof(fmt));
    snprintf(path, sizeof(path), fmt, name);
    char comm[64];
    if (jg_read_file_raw(path, comm, (int)sizeof(comm)) < 0) return 0;
    size_t n = strlen(comm);
    while (n > 0 && (comm[n-1] == '\n' || comm[n-1] == '\r')) comm[--n] = 0;
    char g[32], p[32], f[32];
    jgx_dec(JGX_GUM, g, sizeof(g));
    jgx_dec(JGX_POOL, p, sizeof(p));
    jgx_dec(JGX_FRIDA, f, sizeof(f));
    if (strncmp(comm, g, 12) == 0 ||
        strncmp(comm, p, 11) == 0 ||
        strncmp(comm, f, 6) == 0) {
        ctx->hit = 1;
        return 1;
    }
    return 0;
}

static int check_gum_thread(void) {
    struct jg_gum_ctx ctx = {0};
    char task[64];
    jgx_dec(JGX_TASK, task, sizeof(task));
    jg_for_each_dir(task, _gum_comm_cb, &ctx);
    return ctx.hit;
}

/* F2 硬信号：frida 默认端口 27042/27043 被监听（connect 探测），或本进程存在 frida
 * 工作线程。端口误杀面 = root 机为其他 App 跑 frida-server 的用户（0904 拍板接受，
 * ylyk 用户群非 root）；线程名误杀面 ≈ 0。 */
static void hard_exit_on_frida_port(void) {
    int hit = probe_port(FRIDA_PORTS[0]) || probe_port(FRIDA_PORTS[1]) || check_gum_thread();
    if (!hit) return;
    char s[96];
    jgx_dec(JGX_LOG_HARD_PT, s, sizeof(s));
    __android_log_print(ANDROID_LOG_WARN, TAG, s);
    jg_hard_exit();
}

/* C 硬信号（2026-09-07）：frida-server 改名 + -l 0.0.0.0:<任意端口> 时，硬编码 27042/27043
 * 探测失效。这里直接复用 jg_anti_frida.c 的全端口枚举 + D-Bus 握手，命中即裸 syscall 自毁。
 * 独立于 Java 路径，即使 Java 侧被 hook 失效，native 守护线程仍能在下一轮轮询（2s）内击杀。 */
static void hard_exit_on_frida_port_any(void) {
    if (!jg_af_frida_port_any()) return;
    char s[96];
    jgx_dec(JGX_LOG_HARD_PA, s, sizeof(s));
    __android_log_print(ANDROID_LOG_WARN, TAG, s);
    jg_hard_exit();
}

/* B（2026-09-07）：libc/libart 入口被下跳板 = 疑似 inline hook（frida Interceptor）。
 * 不管攻击者怎么改端口、改线程名、拦自毁，他只要 hook 就必在函数入口留跳板。
 * 注意：本信号【仅诊断、不击杀】——MIUI/部分 OEM ROM 个别 libc 函数入口会被误判为跳板
 * （h_v6 实测 MIX2 干净机误杀），误杀率不可接受；降级为日志，待跳板指纹收紧后再升硬信号。 */
/* 限流：该信号在 MIX2/MIUI/Magisk 上恒为误报(见上方注释)，仅诊断不杀；若无关联信号则 10 分钟内至多记一次，
 * 杜绝周期扫描导致的循环刷屏。 */
static long s_last_hook_diag_ms = 0;
static void log_hook_patched(void) {
    if (!jg_af_hook_patched()) return;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    long now = (long)tv.tv_sec * 1000 + tv.tv_usec / 1000;
    if (now - s_last_hook_diag_ms < 10L * 60 * 1000) return;
    s_last_hook_diag_ms = now;
    __android_log_print(ANDROID_LOG_WARN, TAG,
        "function entry patched (inline hook suspected) -> diagnostic only (no exit, rate-limited)");
}

/* P0-B 周期兜底：OpenCommon 入口复查（预载检查在解密前已做过一次；这里抓
 * attach 后/预载后新装的 hook）。命中即裸 syscall 自毁。 */
static void hard_exit_on_opencommon_patched(void) {
    int r = jg_preload_check();
    if (r != 1) return;
    __android_log_print(ANDROID_LOG_WARN, TAG,
        "OpenCommon entry patched (periodic recheck) -> raw exit");
    jg_hard_exit();
}

/* 0907 A10 修复配套：self-ptrace 守护死亡探测（EXITKILL 已移除，守护死亡不再
 * 连坐 App——那正是 A10 静默闪退根因；此处感知防护丢失并按响应策略上报） */
extern int jg_guard_tracer_pid(void);
static void check_guard_alive(void) {
    static int s_reported = 0;
    int pid = jg_guard_tracer_pid();
    if (pid <= 0 || s_reported) return;
    if (kill((pid_t)pid, 0) != 0 && errno == ESRCH) {
        s_reported = 1;
        __android_log_print(ANDROID_LOG_WARN, TAG,
            "self-ptrace guard died -> ptrace protection lost (report mode applies)");
    }
}

static void *guard_thread(void *arg) {
    (void)arg;
    /* 启动即查一次；之后周期轮询。硬信号独立先查（优先级高于模糊信号）。
     * 硬信号组（外部 tracer / frida 端口+线程名 / 改名端口握手 / OpenCommon 入口跳板）
     * 全部裸 syscall 自毁，绕过 frida 对 libc kill/exit/raise/abort 的 hook。 */
    hard_exit_on_tracer();
    hard_exit_on_frida_port();
    hard_exit_on_frida_port_any();
    hard_exit_on_opencommon_patched();
    log_hook_patched();
    check_guard_alive();
    if (detect()) respond();
    while (!g_stop) {
        usleep((useconds_t)POLL_MS * 1000);
        hard_exit_on_tracer();
        hard_exit_on_frida_port();
        hard_exit_on_frida_port_any();
        hard_exit_on_opencommon_patched();
        log_hook_patched();
        check_guard_alive();
        if (detect()) respond();
    }
    return NULL;
}

/* =========================================================================
 * A（2026-09-07 四道验证反打穿）：裸 syscall 自毁
 * 攻击手法：frida 在 resume() 前注入并 hook libc 的 kill/tgkill/abort/_exit/raise，
 *          把致命信号置 0 → 我们所有「Java System.exit / libc exit / abort」全被吞掉，
 *          「检测到却杀不掉」。
 * 对策：完全绕开 libc，用内联汇编直接发 exit_group 系统调用。libc 层 hook 无论怎么
 *      拦都拦不到 svc 指令本身（除非 hook 到内核或改我们的代码页）。
 * 进程级自毁：exit_group 终止所有线程，不给攻击者留下可用的运行态进程。
 * ========================================================================= */
void jg_hard_exit(void) {
    __android_log_print(ANDROID_LOG_WARN, TAG, "hard exit via raw syscall");
#if defined(__aarch64__)
    __asm__ __volatile__(
        "mov x0, #1\n\t"        /* status = 1 */
        "mov x8, #94\n\t"       /* __NR_exit_group (aarch64) */
        "svc #0\n\t"
        :
        :
        : "x0", "x8"
    );
#elif defined(__arm__)
    __asm__ __volatile__(
        "mov r0, #1\n\t"
        "mov r7, #248\n\t"      /* __NR_exit_group (EABI) */
        "swi #0\n\t"
        :
        :
        : "r0", "r7"
    );
#elif defined(__x86_64__)
    __asm__ __volatile__(
        "mov $231, %%rax\n\t"   /* __NR_exit_group */
        "mov $1, %%rdi\n\t"
        "syscall\n\t"
        :
        :
        : "rax", "rdi"
    );
#elif defined(__i386__)
    __asm__ __volatile__(
        "mov $252, %%eax\n\t"   /* __NR_exit_group */
        "mov $1, %%ebx\n\t"
        "int $0x80\n\t"
        :
        :
        : "eax", "ebx"
    );
#else
    _exit(1);
#endif
    /* 兜底：syscall 未生效则强制踩空指针崩溃，绝不返回 */
    __asm__ __volatile__("" ::: "memory");
    for (;;) { volatile int *p = (volatile int *)0; *p = 0; }
}

/* Java 侧硬信号统一改走裸 syscall 自毁（System.exit 会经 libc 被拦截） */
JNIEXPORT void JNICALL
Java_com_gx_runtime_GxGuard_nativeHardExit(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    jg_hard_exit();
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
