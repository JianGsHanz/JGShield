/*
 * JGShield 强反 Frida 检测层（jg_anti_frida.c）
 * 定位：在不依赖服务端的前提下，尽量抬高 AI 辅助动态逆向（Frida / Xposed / LSPosed
 *       类注入框架）的门槛。属于「被动检测」——能给出运行期信号，但无法「杜绝」：
 *       攻击者仍可 patch 掉响应函数、或自定义 dump，故本层只发信号、断不断由
 *       STRENGTHEN_RESPONSE（加固期经 meta gx.antifrida 开启 + manifest gx.strengthen 决定）统一收口。
 *
 * 铁律：
 *   1. 只读检测，异常全吞，绝不外抛、绝不影响 App 启动。
 *   2. 本文件不碰任何密钥派生 / 写读对称逻辑（与 harden.py 加密端解耦，零对称风险）。
 *   3. 默认关闭：Java 侧 GxAntiFrida.ANTI_FRIDA_ENABLED 为 false 时根本不调用本 native。
 *   4. 误报红线：仅匹配明确签名串，宁可漏检不可误伤正常设备。
 *
 * 抗 AI / 抗熟悉开源方案逆向者的补强（A1-A3）：
 *   A1. frida / xposed 签名串在 .so 中以 XOR(0x37) 存储，运行时解码后匹配；
 *       .so 二进制里搜不到明文 "frida"/"XposedBridge"，阻断 strings+grep+patch 最便宜的攻击路。
 *   A2. fork 子进程对父进程做 PTRACE_SEIZE（非 PTRACE_ATTACH）：成功=父此前未被 trace，
 *       失败(EPERM)=父已被 frida/gdb trace（一个进程只能有一个 tracer）。关键修正
 *       (2026-09-03)：原实现用 PTRACE_ATTACH 会 group-stop 目标全部线程，多线程 App 在 MIUI
 *       上每 2s 被反复打断，实测与启动期 binder 握手卡死、ANR dumpJavaBacktrace 超时有关；
 *       PTRACE_SEIZE 仅声明 tracer 关系、不停止目标线程，检测能力不变且不再冻结全进程。
 *       EINVAL(极旧内核<3.4 不支持 SEIZE)保守判未命中。
 *   A3. maps 扫描 Xposed / LSPosed / riru / lspd / lspose 签名，覆盖 AI 常用 LSPosed hook。
 *
 * 返回位掩码：
 *   bit0 (1)  = maps 路径命中 frida 签名
 *   bit1 (2)  = TracerPid != 0
 *   bit2 (4)  = frida 默认端口开放(27042/27043)
 *   bit3 (8)  = 主动 ptrace 自检：本进程已被 trace（frida/gdb），PTRACE_SEIZE 实现
 *   bit4 (16) = maps 路径命中 Xposed/LSPosed 签名
 *   bit5 (32) = 线程名命中 gum-js-loop / pool-frida / frida*（frida17 spawn 唯一稳定残留）
 *   bit6 (64) = libc/libart 关键函数入口被改写为跳板（frida Interceptor 必留痕迹）
 *   bit7 (128)= 全端口扫描 + frida WebSocket(/ws 升级) 握手命中（堵 -l 0.0.0.0:<任意端口>）
 */
#include <jni.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <dirent.h>
#include <dlfcn.h>
#include "jg_rawsys.h"

/* =========================================================================
 * P0-A（2026-09-07 四步打穿复盘）：检测 IO 全面裸 syscall 化
 * 此前本文件所有探测（fopen /proc/self/maps、opendir task、socket/connect）
 * 都走 libc PLT——frida hook libc open/read/connect 后：
 *   - 伪造 read 内容 → maps/comm/tcp 扫描全部失明；
 *   - 拦截 connect → 改名端口（bit7）永不命中。
 * 对策：本文件检测路径一律走 jg_rawsys.h 的 svc 直调封装，libc hook 全部失效。
 * 例外：bit6（log-only 诊断）仍用 dlsym——不参与击杀决策，被欺骗只是少一条日志。
 * ========================================================================= */

/* 内存内大小写不敏感子串匹配 */
static int _mem_casestr(const char* hay, int haylen, const char* needle) {
    int nl = (int)strlen(needle);
    if (nl == 0 || haylen < nl) return 0;
    for (int i = 0; i + nl <= haylen; i++) {
        int j = 0;
        for (; j < nl; j++) {
            char a = hay[i + j], b = needle[j];
            if (a >= 'A' && a <= 'Z') a = (char)(a + 32);
            if (b >= 'A' && b <= 'Z') b = (char)(b + 32);
            if (a != b) break;
        }
        if (j == nl) return 1;
    }
    return 0;
}

/* 前置声明：定义在下方签名表之后 */
static void _decode_sig(const unsigned char* enc, char* out, int outsz);

/* 分块读 /proc/self/maps 并扫描签名表（XOR 表逐条解码后匹配）。
 * 分块带 64B 尾部衔接，防签名恰好跨块。 */
#define _MAPS_CHUNK (16 * 1024)
static int _raw_scan_maps_sigs(const unsigned char* table, int rows, int rowlen) {
    long fd = jg_open_ro("/proc/self/maps");
    if (fd < 0) return 0;
    char chunk[_MAPS_CHUNK];
    char scan[_MAPS_CHUNK + 64];
    char carry[64];
    int carry_n = 0;
    char dec[64];
    int hit = 0;
    for (;;) {
        long n = jg_read((int)fd, chunk, sizeof(chunk));
        if (n <= 0) break;
        int len = (int)n;
        memcpy(scan, carry, (size_t)carry_n);
        memcpy(scan + carry_n, chunk, (size_t)len);
        len += carry_n;
        carry_n = (len > 64) ? 64 : len;
        memcpy(carry, scan + len - carry_n, (size_t)carry_n);
        for (int i = 0; i < rows && !hit; i++) {
            _decode_sig(table + (size_t)i * (size_t)rowlen, dec, (int)sizeof(dec));
            if (_mem_casestr(scan, len, dec)) hit = 1;
        }
        if (hit) break;
    }
    jg_close((int)fd);
    return hit;
}

/* ---- A1: XOR 混淆签名表（.so 内无明文） ---- */
#define SIG_XOR_KEY 0x37

/* frida 明确签名子串（XOR 0x37 存储，0x00 结尾哨兵）。运行时解码后大小写不敏感匹配。 */
static const unsigned char FRIDA_SIGS[][24] = {
    {0x51,0x45,0x5e,0x53,0x56,0x00},                                            /* frida */
    {0x51,0x45,0x5e,0x53,0x56,0x1a,0x56,0x50,0x52,0x59,0x43,0x00},              /* frida-agent */
    {0x51,0x45,0x5e,0x53,0x56,0x1a,0x50,0x56,0x53,0x50,0x52,0x43,0x00},        /* frida-gadget */
    {0x5b,0x5e,0x55,0x51,0x45,0x5e,0x53,0x56,0x00},                            /* libfrida */
    {0x50,0x42,0x5a,0x1a,0x5d,0x44,0x1a,0x5b,0x58,0x58,0x47,0x00},             /* gum-js-loop */
    {0x5b,0x5e,0x59,0x5d,0x52,0x54,0x43,0x58,0x45,0x00},                       /* linjector */
    {0x45,0x52,0x19,0x51,0x45,0x5e,0x53,0x56,0x19,0x44,0x52,0x45,0x41,0x52,0x45,0x00}, /* re.frida.server */
};
#define N_FRIDA (sizeof(FRIDA_SIGS) / sizeof(FRIDA_SIGS[0]))

/* A3: Xposed / LSPosed 签名（XOR 0x37 存储）。 */
static const unsigned char XPOSED_SIGS[][32] = {
    {0x53,0x52,0x19,0x45,0x58,0x55,0x41,0x19,0x56,0x59,0x53,0x45,0x58,0x5e,0x53,0x19,0x4f,0x47,0x58,0x44,0x52,0x53,0x00}, /* de.robv.android.xposed */
    {0x6f,0x47,0x58,0x44,0x52,0x53,0x75,0x45,0x5e,0x53,0x50,0x52,0x00},        /* XposedBridge */
    {0x45,0x5e,0x45,0x42,0x00},                                                /* riru */
    {0x5b,0x44,0x47,0x53,0x00},                                                /* lspd */
    {0x5b,0x44,0x47,0x58,0x44,0x52,0x00},                                      /* lspose */
    {0x4f,0x47,0x58,0x44,0x52,0x53,0x00},                                      /* xposed (覆盖 libxposed_art/libxposed/xposedbridge) */
};
#define N_XPOSED (sizeof(XPOSED_SIGS) / sizeof(XPOSED_SIGS[0]))

/* 解码第 i 条签名到 out（NUL 结尾）。 */
static void _decode_sig(const unsigned char* enc, char* out, int outsz) {
    int i = 0;
    while (enc[i] != 0x00 && i < outsz - 1) {
        out[i] = (char)(enc[i] ^ SIG_XOR_KEY);
        i++;
    }
    out[i] = '\0';
}

/* 大小写不敏感子串匹配（bionic 无 strcasestr，自实现）。 */
static int _strcasestr(const char* hay, const char* needle) {
    if (!hay || !needle) return 0;
    size_t nl = strlen(needle);
    if (nl == 0) return 0;
    size_t hl = strlen(hay);
    for (size_t i = 0; i + nl <= hl; i++) {
        size_t j = 0;
        for (; j < nl; j++) {
            char a = hay[i + j];
            char b = needle[j];
            if (a >= 'A' && a <= 'Z') a = (char)(a + 32);
            if (b >= 'A' && b <= 'Z') b = (char)(b + 32);
            if (a != b) break;
        }
        if (j == nl) return 1;
    }
    return 0;
}

/* 扫 /proc/self/maps（裸 syscall 读）：匹配 frida 签名表。
 * frida-agent 注入后会在 maps 留下 libfrida-agent.so / re.frida.server / [anon:...frida...] 等命名区。 */
static int _scan_maps_frida(void) {
    return _raw_scan_maps_sigs(&FRIDA_SIGS[0][0], (int)N_FRIDA,
                               (int)sizeof(FRIDA_SIGS[0]));
}

static int _scan_maps_xposed(void) {
    return _raw_scan_maps_sigs(&XPOSED_SIGS[0][0], (int)N_XPOSED,
                               (int)sizeof(XPOSED_SIGS[0]));
}

/* 持久 self-ptrace 守护（jg_ptrace_guard.c，2026-09-04 P0 补强）：
 * 守护子进程持续 trace 本进程全部线程，堵死 root /proc/pid/mem 直读。
 * 本文件的所有 TracerPid 类检测必须放行「自己的守护子进程」，否则永远误报。 */
extern int jg_guard_tracer_pid(void);
extern int jg_guard_tracer_is_child(int tpid);
extern long jg_guard_fork_ms(void);
extern int jg_guard_active_pid(void);

#include <time.h>
#include <android/log.h>
static long _af_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

/* /proc/self/status 的 TracerPid 非 0 == 正被 ptrace（调试器 / frida 注入的典型特征）。
 * 例外：TracerPid 是本进程 fork 出的 ptrace 守护子进程（PPid==self）→ 放行。 */
static int _read_tracer_pid(void) {
    char buf[4096];
    if (jg_read_file_raw("/proc/self/status", buf, (int)sizeof(buf)) < 0) return 0;
    const char* p = strstr(buf, "TracerPid:");
    if (!p) return 0;
    return atoi(p + 10);
}

static int _scan_tracer_pid(void) {
    int pid = _read_tracer_pid();
    if (pid != 0 && !jg_guard_tracer_is_child(pid)) return 1;
    return 0;
}

/* frida-server / gadget 默认监听本地 TCP 27042 / 27043。探测开放即命中。
 * 裸 syscall connect + 200ms 发送超时，防长阻塞。 */
static int _scan_port(int port) {
    long fd = jg_socket_tcp();
    if (fd < 0) return 0;
    jg_sock_timeo((int)fd, 200000, 0);
    int r = (jg_connect_local((int)fd, (unsigned short)port) == 0) ? 1 : 0;
    jg_close((int)fd);
    return r;
}

/* A2: 主动 ptrace 自检（不 group-stop）。
 * 思路：fork 子进程对父进程做 PTRACE_SEIZE。
 *   - 成功 → 父进程此前未被 trace（detach 还原），子进程 _exit(0)；
 *   - EPERM → 父进程已被 frida/gdb trace（一个进程只能有一个 tracer），子进程 _exit(2) 命中；
 *   - EINVAL → 内核不支持 SEIZE（Android < 3.4），子进程 _exit(1) 保守未命中。
 * PTRACE_SEIZE 仅声明 tracer 关系、不向目标线程发 SIGSTOP，故不会 group-stop 父进程全部线程，
 * 区别于原 PTRACE_ATTACH 实现（已实测在 MIUI 多线程 App 上引发启动期 binder 卡死）。 */
static int _scan_ptrace_self(void) {
    /* 0907 A10 竞态修复（三层）：
     * 1) 自家守护在位（握手成功且存活）＝防护已生效，守护必然 trace 着主线程，
     *    SEIZE 探针/TracerPid 全部失真 → 直接放行，防护由守护本体提供；
     * 2) 守护 fork 后 10s 窗口（握手未完成的瞬间）→ 放行；
     * 3) 窗口外且无守护：TracerPid 判定 + SEIZE 探针照常。
     * 实测根因：守护在位时探针 SEIZE 主线程必 EPERM → 误判外部 tracer → 硬自毁。 */
    if (jg_guard_active_pid() > 0) return 0;
    long fms = jg_guard_fork_ms();
    if (fms != 0 && _af_now_ms() - fms < 10000) return 0;
    /* 持久 self-ptrace 守护激活时：TracerPid 恒为守护子进程 pid → SEIZE 必 EPERM，
     * 探针失去意义。先读 TracerPid 判定：是自己的守护 → 直接放行（未命中）；
     * 是【外部】tracer（frida/gdb，非本进程子进程）→ 直接命中，无需再 fork 探测。
     * 全程裸 syscall（status 读 / clone / ptrace / wait4 / exit_group）——libc 层
     * hook ptrace/fork/waitpid 伪造结果对本探针无效。 */
    int tpid = _read_tracer_pid();
    if (tpid != 0) {
        int ic = jg_guard_tracer_is_child(tpid);
        __android_log_print(ANDROID_LOG_WARN, "JG-Diag",
            "ptrace-self: TracerPid=%d is_child=%d active_pid=%d fork_ms_ago=%ld",
            tpid, ic, jg_guard_active_pid(),
            fms ? _af_now_ms() - fms : -1);
        if (ic) return 0;                                /* 自己的守护（含无法判定） */
        return 1;                                        /* 确定外部 tracer */
    }
    pid_t child = (pid_t)jg_fork();
    if (child < 0) return 0;          /* fork 失败 → 保守判未命中 */
    if (child == 0) {
        /* 子进程：全程裸 syscall。SEIZE 父进程：
         *   成功 → 父未被 trace → DETACH 还原 → exit 0；
         *   -EINVAL → 内核不支持 SEIZE → exit 1（保守未命中）；
         *   其他（EPERM 等）→ 父已被 trace → exit 2（命中）。 */
        long ppid = jg_getppid();
        long r = jg_raw_ptrace((long)PTRACE_SEIZE, (int)ppid, 0, 0);
        if (r == 0) {
            jg_raw_ptrace((long)PTRACE_DETACH, (int)ppid, 0, 0);
            jg_raw_exit(0);
        }
        if (r == -EINVAL) jg_raw_exit(1);
        jg_raw_exit(2);
    }
    int status = 0;
    if (jg_wait4((int)child, &status) < 0) return 0;
    if (WIFEXITED(status) && WEXITSTATUS(status) == 2) {
        /* EPERM 有两种来源：①已被外部 tracer 占用（TracerPid≠0）→ 攻击信号；
         * ②内核/SELinux 直接拒绝 ptrace 系统调用（TracerPid=0）——荣耀/华为
         * HarmonyOS 内核全禁 untrusted_app 的 ptrace，实测复现（0907 JG-Diag：
         * SEIZE EPERM 但 TracerPid=0）。②不是攻击，必须放行。 */
        int tp = _read_tracer_pid();
        __android_log_print(ANDROID_LOG_WARN, "JG-Diag",
            "ptrace-self: SEIZE EPERM TracerPid=%d active_pid=%d -> %s",
            tp, jg_guard_active_pid(),
            (tp != 0 && !jg_guard_tracer_is_child(tp)) ? "external-tracer" : "kernel-deny-or-own, pass");
        if (tp == 0) return 0;
        if (jg_guard_tracer_is_child(tp)) return 0;
        return 1;
    }
    return 0;
}

/* F2（2026-09-04 frida17 spawn 实测）：frida 17 spawn 注入完即 detach（TracerPid 归零）、
 * agent 走 memfd 匿名映射（maps 无路径）→ bit0/bit1/bit3 全空。唯一稳定残留特征是
 * frida 的 glib 工作线程名：/proc/self/task/<tid>/comm 里的 "gum-js-loop" /
 * "pool-frida-*"（comm 截断 15 字符）。这些线程名由 frida 核心写死，正常运行 App 不会
 * 有（自有线程统一 gx- 前缀），误杀面 ≈ 0 → 归入硬信号 bit5。 */
static int _comm_cb(const char* name, void* ud) {
    (void)ud;
    char path[96];
    snprintf(path, sizeof(path), "/proc/self/task/%s/comm", name);
    char comm[64];
    if (jg_read_file_raw(path, comm, (int)sizeof(comm)) < 0) return 0;
    size_t n = strlen(comm);
    while (n > 0 && (comm[n-1] == '\n' || comm[n-1] == '\r')) comm[--n] = 0;
    if (strncmp(comm, "gum-js-loop", 12) == 0 ||
        strncmp(comm, "pool-frida", 11) == 0 ||
        strncmp(comm, "frida", 6) == 0) {
        return 1;   /* 命中，终止遍历 */
    }
    return 0;
}

/* F2（2026-09-04 frida17 spawn 实测）：frida 17 spawn 注入完即 detach（TracerPid 归零）、
 * agent 走 memfd 匿名映射（maps 无路径）→ bit0/bit1/bit3 全空。唯一稳定残留特征是
 * frida 的 glib 工作线程名。读取全程裸 syscall（getdents64 + openat/read），
 * frida hook libc prctl 改写线程名不影响我们直读内核视角的真实 comm。 */
static int _scan_thread_names(void) {
    return jg_for_each_dir("/proc/self/task", _comm_cb, NULL) == 1 ? 1 : 0;
}

/* =========================================================================
 * C（2026-09-07 四道验证反打穿）：全端口扫描 + frida WebSocket 握手探测
 * 攻击手法：frida-server -l 0.0.0.0:<任意端口> 即可让原「硬编码 27042/27043」失效。
 * 对策：枚举 /proc/net/tcp{,6} 的 LISTEN(0A) 端口，逐个 connect 后发 WebSocket(/ws)
 *       升级握手，响应含 "101"+"websocket" 即判 frida（适配 frida 17，改名/任意端口通用）。
 * 上限 MAX_PROBE 个端口、每个 150ms connect + 250ms 读，避免拖慢启动/轮询。
 * ========================================================================= */
#define MAX_PROBE 24

static int _port_seen[MAX_PROBE];
static int _port_seen_n = 0;

static void _add_port(int p) {
    if (p < 1024 || p > 65535) return;
    if (_port_seen_n >= MAX_PROBE) return;
    for (int i = 0; i < _port_seen_n; i++) if (_port_seen[i] == p) return;
    _port_seen[_port_seen_n++] = p;
}

/* 解析 /proc/net/tcp 与 tcp6（裸 syscall 读），收集 LISTEN 状态的本地监听端口 */
static void _collect_listen_ports(void) {
    static const char* files[] = {"/proc/net/tcp", "/proc/net/tcp6"};
    char buf[16384];
    for (int f = 0; f < 2; f++) {
        if (jg_read_file_raw(files[f], buf, (int)sizeof(buf)) < 0) continue;
        char* save = NULL;
        char* line = strtok_r(buf, "\n", &save);
        while (line != NULL) {
            /* 格式: "  sl local_address rem_address st ..." */
            const char* p = strchr(line, ':');
            if (p) {
                p++;                                  /* skip 'sl:' */
                const char* colon = strchr(p, ':');
                if (colon) {
                    const char* sp = strchr(colon, ' ');
                    if (sp) {
                        const char* st = sp + 1;
                        while (*st == ' ') st++;
                        const char* sp2 = strchr(st, ' ');
                        if (sp2) {
                            st = sp2 + 1;
                            while (*st == ' ') st++;
                            if (strncmp(st, "0A", 2) == 0)   /* 0A = TCP_LISTEN */
                                _add_port((int)strtol(colon + 1, NULL, 16));
                        }
                    }
                }
            }
            line = strtok_r(NULL, "\n", &save);
        }
    }
}

/* 对单个端口做 WebSocket 升级探测（适配 frida 17 的真实握手协议）。
 * frida 17 的 frida-server 不再走裸 D-Bus AUTH，而是 HTTP/1.1 WebSocket 升级：
 *   客户端发 "GET /ws HTTP/1.1\r\nUpgrade: websocket\r\n..."，
 *   server 回 "HTTP/1.1 101 Switching Protocols ... Upgrade: websocket"。
 * 改写前（裸 D-Bus AUTH 探测）在 frida 17 上恒超时、永不命中——这是 v7 之前 C 失效的根因。
 * 改为 WS 升级探测后，改名端口（-l 0.0.0.0:41529）也能被握手特征精确识别。 */
static int _probe_frida_handshake(int port) {
    long fd = jg_socket_tcp();
    if (fd < 0) return 0;
    jg_sock_timeo((int)fd, 150000, 150000);   /* 150ms 发送 / 250ms 内足够读响应头 */
    int hit = 0;
    if (jg_connect_local((int)fd, (unsigned short)port) == 0) {
        static const char req[] =
            "GET /ws HTTP/1.1\r\n"
            "Host: 127.0.0.1\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAA==\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n";
        if (jg_send_n((int)fd, req, strlen(req)) > 0) {
            char buf[256];
            long n = jg_recv_n((int)fd, buf, sizeof(buf) - 1);
            if (n > 0) {
                buf[n] = 0;
                /* 101 + websocket 升级 = frida WS 握手特征（改名/任意端口通用） */
                if (strstr(buf, "101") != NULL &&
                    (strstr(buf, "websocket") != NULL || strstr(buf, "WebSocket") != NULL)) {
                    hit = 1;
                }
            }
        }
    }
    jg_close((int)fd);
    return hit;
}

static int _scan_frida_port_any(void) {
    _port_seen_n = 0;
    memset(_port_seen, 0, sizeof(_port_seen));
    _collect_listen_ports();
    for (int i = 0; i < _port_seen_n; i++) {
        if (_probe_frida_handshake(_port_seen[i])) return 1;
    }
    return 0;
}

/* =========================================================================
 * B（2026-09-07）：libc / libart 关键函数入口跳板检测
 * frida Interceptor（及其绕过线程名检测所必需的 prctl hook、拦截自毁所必需的
 * kill/tgkill/abort/_exit/raise hook）必然改写目标函数入口为「跳板」。
 * 对策：dlsym 取真实符号地址，检查入口前几条指令是否为 br/blr xN（aarch64）等
 *       跳板编码。这比查线程名/端口更本质——不管 frida 怎么改名，它要 hook 就得
 *       改函数入口。
 * 误报面：正常函数入口不会在头 4 条指令里出现 br xN（除真实 thunk，libc 中罕见）。
 * ========================================================================= */
static int _is_trampoline(const void* fn) {
    if (!fn) return 0;
    const unsigned char* p = (const unsigned char*)fn;
#if defined(__aarch64__)
    for (int i = 0; i < 4; i++) {
        unsigned int ins = 0;
        memcpy(&ins, p + (i * 4), 4);
        if ((ins & 0xFFFFFC1Fu) == 0xD61F0000u) return 1;  /* br  xN */
        if ((ins & 0xFFFFFC1Fu) == 0xD63F0000u) return 1;  /* blr xN */
    }
#elif defined(__arm__)
    unsigned int w = 0;
    memcpy(&w, p, 4);
    if (w == 0xE51FF004u) return 1;                 /* ldr pc,[pc,#-4] */
    if ((w & 0x0000FFFFu) == 0x0000F8DFu) return 1; /* thumb ldr pc,[pc,#..] */
    if ((w & 0x0000FFFFu) == 0x00004778u) return 1; /* thumb bx pc */
#elif defined(__i386__) || defined(__x86_64__)
    if (p[0] == 0xFF && p[1] == 0x25) return 1;     /* jmp [rip+disp32] */
    if (p[0] == 0xE9) return 1;                     /* jmp rel32 at entry */
    if (p[0] == 0x48 && p[1] == 0xB8) {             /* movabs rax,addr; jmp rax */
        for (int i = 2; i < 10; i++) if (p[i] == 0xFF && p[i+1] == 0xE0) return 1;
    }
#endif
    return 0;
}

/* 检查一组符号里任一被下跳板即命中。返回命中符号名（static buf）或 NULL。 */
static int _syms_patched(void* h, const char* names[], int n) {
    for (int i = 0; i < n; i++) {
        void* fn = dlsym(h, names[i]);
        if (fn != NULL && _is_trampoline(fn)) return 1;
    }
    return 0;
}

static int _scan_hook_patched(void) {
    static const char* libc_syms[] = {
        "prctl", "kill", "tgkill", "abort", "raise", "_exit", "exit",
        "pthread_create", "mmap", "mprotect", "socket", "connect"
    };
    /* 注意：用 dlopen 自身句柄取 libc（RTLD_NOLOAD 不可靠，直接 dlopen 引用计数即可） */
    void* libc = dlopen("libc.so", RTLD_NOW);
    int hit = 0;
    if (libc != NULL) {
        hit = _syms_patched(libc, libc_syms,
                            (int)(sizeof(libc_syms) / sizeof(libc_syms[0])));
    }
    if (!hit) {
        /* libart 的 dex 加载入口（落盘必经），不同 Android 版本符号不同，逐个尝试 */
        static const char* art_syms[] = {
            "_ZN3art13ArtDexFileLoader10OpenCommonEPKhmS2_mRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileEbbPS9_PNS0_12VerifyResultE",
            "_ZN3art7DexFile10OpenCommonEPKhmRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_7OatFileEbbPSA_PNS0_12VerifyResultE"
        };
        void* art = dlopen("libart.so", RTLD_NOW);
        if (art != NULL) hit = _syms_patched(art, art_syms, 2);
    }
    return hit;
}

/* 供 jg_guard.c 复用（同 .so，extern 声明即可） */
int jg_af_hook_patched(void)   { return _scan_hook_patched(); }
int jg_af_frida_port_any(void) { return _scan_frida_port_any(); }
/* 供 jg_preload.c 预载路径复用：agent 线程残留（raw syscall 版） */
int jg_af_thread_names(void)   { return _scan_thread_names(); }

/* 裸 syscall 自毁（实现在 jg_guard.c，绕过 libc hook 无法拦截） */
extern void jg_hard_exit(void);

JNIEXPORT jint JNICALL
Java_com_gx_runtime_GxAntiFrida_scanJNI(JNIEnv* env, jclass clazz) {
    (void)env; (void)clazz;
    int mask = 0;
    if (_scan_maps_frida())                       mask |= 1;   /* bit0 frida maps */
    if (_scan_tracer_pid())                       mask |= 2;   /* bit1 TracerPid */
    if (_scan_port(27042) || _scan_port(27043))   mask |= 4;   /* bit2 frida port */
    if (_scan_ptrace_self())                      mask |= 8;   /* bit3 ptrace self (SEIZE) */
    if (_scan_maps_xposed())                      mask |= 16;  /* bit4 Xposed/LSPosed */
    if (_scan_thread_names())                     mask |= 32;  /* bit5 gum-js-loop 等线程名 */
    if (_scan_hook_patched())                     mask |= 64;  /* bit6 libc/libart 入口被下跳板 */
    /* bit7 全端口握手探测较重（最多 24 端口 × 150ms），每 4 次轮询做一次（≈8s）；
     * 一旦命中即 sticky 保持，避免漏掉间歇监听。 */
    {
        static int call_n = 0;
        static int port_hit = 0;
        if (port_hit || (call_n++ % 4) == 0) {
            if (_scan_frida_port_any()) port_hit = 1;
        }
        if (port_hit) mask |= 128;
    }
    return (jint)mask;
}
