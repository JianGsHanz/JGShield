/*
 * JGShield 持久 self-ptrace 防护层（jg_ptrace_guard.c）
 * --------------------------------------------------------------------------
 * 目标（2026-09-04 对比报告 P0）：堵死「root 直读 /proc/<pid>/mem 拿明文 dex」通道。
 * 实测 5.9.5 被 root 直读取走全部 4 个业务 dex（~31.8MB / 51k 方法 / 30.5k 类）。
 *
 * 原理（对齐梆梆/360 的有效成分）：
 *   fork 一个守护子进程，对本进程【全部线程】做 PTRACE_ATTACH 并【持续持有】：
 *   - 每个线程同时只能有一个 tracer。外部进程（root 的 dd 直读 /proc/<pid>/mem、
 *     process_vm_readv、frida-server 注入、gdb attach）在 ptrace_may_access 处
 *     一律 EPERM/EBUSY —— 本进程内存对外不可读；
 *   - PTRACE_O_TRACECLONE：已 trace 的线程 clone 出的新线程自动继承 trace 关系；
 *   - PTRACE_O_EXITKILL：守护子进程死亡 → 本进程被内核 SIGKILL —— 「先杀守护
 *     再 dump」直接作废（dump 不出一个已死进程）；
 *   - 每 ~5s 重扫 /proc/<pid>/task，补 attach 初始扫描窗口期克隆出的漏网线程。
 *
 * 铁律（2026-09-03 P0-D 卡死事故教训，绝不重蹈）：
 *   1. 一次性 attach（每线程停顿微秒级、attach 即 CONT），之后仅被动
 *      waitpid+WNOHANG+CONT；绝不周期性反复 group-stop 全进程（当年 2s 轮询
 *      PTRACE_ATTACH group-stop 全线程 → MIUI binder 握手卡死 ANR）。
 *   2. 守护子进程内绝不碰 ART / 堆 / stdio / 日志：fork 时其他线程可能正持
 *      malloc 锁，子进程调 malloc 类函数会死锁 —— 列线程用裸 getdents64，
 *      数字转字符串手写，管道通知用 write。
 *   3. 启动握手 pipe + poll(3s)：守护子进程任何异常，父进程最多等 3s 即返回，
 *      绝不 hang 启动；超时不杀守护（若它已 attach，杀掉会触发 EXITKILL）。
 *   4. 全链路 fail-safe：fork/attach 失败一律降级（返回失败码），App 照常启动。
 *
 * 诚实边界（与梆梆/360 同天花板）：
 *   - 挡得住：root dd /proc/pid/mem、process_vm_readv、frida-server 注入、gdb。
 *   - 挡不住：内核模块级攻击者（内核态 access_process_vm 绕过 ptrace 检查）；
 *     已在进程内运行的代码（frida-gadget 走 APK 重打包注入，不经 ptrace）。
 */
#include <jni.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <time.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#ifndef __WALL
#define __WALL 0x40000000
#endif
#ifndef PTRACE_O_TRACECLONE
#define PTRACE_O_TRACECLONE 0x00000008
#endif
#ifndef PTRACE_O_EXITKILL
#define PTRACE_O_EXITKILL 0x00000010
#endif
#ifndef PTRACE_EVENT_CLONE
#define PTRACE_EVENT_CLONE 3
#endif

#define GX_TASK_MAX 512

/* 本进程当前的自持守护（tracer 子进程）pid；0 = 未启用。父进程侧写入。 */
static volatile int g_guard_pid = 0;

/* 0907 A10：fork 时刻（CLOCK_MONOTONIC ms）。守护启动后有一段逐线程 ATTACH 窗口，
 * 窗口内 TracerPid/SEIZE 探针都会被自家守护污染，检测层须放行。 */
static volatile long g_guard_fork_ms = 0;
long jg_guard_fork_ms(void) { return g_guard_fork_ms; }

/* 0907 A10：守护在位判定——握手成功写入的 g_guard_pid 且 kill(pid,0) 确认存活。
 * 在位时自家守护必然 trace 着主线程，检测层的 TracerPid/SEIZE 探针全部失真，
 * 调用方必须直接放行（防护由守护本体提供，无需探针）。 */
int jg_guard_active_pid(void) {
    int pid = g_guard_pid;
    if (pid <= 0) return 0;
    if (kill((pid_t)pid, 0) != 0) return 0;
    return pid;
}

/* 供 jg_anti_frida.c / jg_guard.c 过滤自身守护的误报 */
int jg_guard_tracer_pid(void) { return g_guard_pid; }

/* ---- 小工具：无 malloc / 无 stdio（守护子进程内安全） ---- */
static int _utoa_pos(char *dst, int v) {
    char tmp[12];
    int n = 0;
    if (v <= 0) { dst[0] = '0'; return 1; }
    while (v > 0) { tmp[n++] = (char)('0' + (v % 10)); v /= 10; }
    for (int i = 0; i < n; i++) dst[i] = tmp[n - 1 - i];
    return n;
}

/* 裸 getdents64 列出 /proc/<proc>/task 下的 tid（零堆分配）。返回条数，-1=失败 */
struct gx_dirent64 {
    unsigned long long d_ino;
    long long d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[1];
};

static int _list_tids(pid_t proc, pid_t *out, int maxn) {
    char path[48], buf[4096];
    int len = 0;
    memcpy(path, "/proc/", 6); len = 6;
    len += _utoa_pos(path + len, (int)proc);
    memcpy(path + len, "/task", 6); len += 5;
    path[len] = '\0';
    int fd = open(path, O_RDONLY | O_DIRECTORY);
    if (fd < 0) return -1;
    int n = 0;
    for (;;) {
        long r = syscall(SYS_getdents64, fd, buf, sizeof(buf));
        if (r <= 0) break;
        long off = 0;
        while (off < r) {
            struct gx_dirent64 *d = (struct gx_dirent64 *)(buf + off);
            if (d->d_reclen == 0) break;   /* 防御：异常条目，避免死循环 */
            int v = 0;
            const char *s = d->d_name;
            while (*s >= '0' && *s <= '9') { v = v * 10 + (*s - '0'); s++; }
            if (v > 0 && n < maxn) out[n++] = (pid_t)v;
            off += d->d_reclen;
        }
    }
    close(fd);
    return n;
}

/* ---- 判定 tpid 是否本进程 fork 出的守护子进程（读 /proc/<tpid>/status 的 PPid）。
 * 供父进程侧各检测层过滤自身守护误报；比记全局 pid 更稳（握手超时等场景也对）。
 * 在父进程（App 进程）内执行，可用 stdlib。
 * 返回：1 = 自己的守护【或 tpid 进程已消失无法判定】；0 = 确定是外部 tracer。
 * 0907 A10 实测：守护 ATTACH 期间检测线程读到 TracerPid=守护 pid，若守护恰已
 * 退出（EPERM 自杀）则 /proc/<tpid> 读不到——旧版返回 0 会把自家守护误判为
 * 外部 tracer → 硬自毁。读不到一律按「无威胁」放行。 ---- */
int jg_guard_tracer_is_child(int tpid) {
    if (tpid <= 0) return 1;
    char path[48], buf[512];
    int len = 0;
    memcpy(path, "/proc/", 6); len = 6;
    len += _utoa_pos(path + len, tpid);
    memcpy(path + len, "/status", 8); len += 7;
    path[len] = '\0';
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 1;               /* 进程已消失 → 无威胁，放行 */
    int n = (int)read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return 1;               /* 同上 */
    buf[n] = '\0';
    char *p = buf;
    while (*p) {
        if (strncmp(p, "PPid:", 5) == 0) {
            int ppid = atoi(p + 5);
            return ppid == (int)getpid();
        }
        char *nl = strchr(p, '\n');
        if (!nl) break;
        p = nl + 1;
    }
    return 1;                           /* status 无 PPid 字段：保守放行 */
}

/* ---- 守护子进程主体（此后代码只在 fork 出的子进程里跑，零堆分配） ---- */

/* attach 单线程：ATTACH -> 等停 -> SETOPTIONS -> 立即 CONT（单线程停顿微秒级）。
 * 返回 0=成功；-1=ATTACH 失败（errno==EPERM 表示已被外部 tracer 持有）；
 * -2/-3=等停/SETOPTIONS 失败（内部已 DETACH 还原）。 */
static int _attach_one(pid_t tid) {
    if (ptrace(PTRACE_ATTACH, tid, 0, 0) != 0) return -1;
    int st;
    pid_t r;
    do { r = waitpid(tid, &st, __WALL); } while (r < 0 && errno == EINTR);
    if (r != tid || !WIFSTOPPED(st)) return -2;
    /* 0907 A10 实测修复：去掉 PTRACE_O_EXITKILL。EXITKILL 绑定在 tracee 上——
     * 守护（tracer）【任何形式】的死亡（包括 waitpid 异常 _exit、握手超时后残留的
     * 守护出错退场）都会让内核 SIGKILL 全部被 trace 的 App 线程 = 静默闪退（荣耀
     * A10/HarmonyOS 实测 has died: fore TOP 零日志）。改为无 EXITKILL + 守护异常
     * 先 DETACH 全线程再退场；守护死亡由 Java 层 kill(pid,0) 探测响应，不再连坐。 */
    long opts = PTRACE_O_TRACECLONE;
    if (ptrace(PTRACE_SETOPTIONS, tid, 0, (void *)opts) != 0) {
        ptrace(PTRACE_DETACH, tid, 0, 0);
        return -3;
    }
    ptrace(PTRACE_CONT, tid, 0, 0);
    return 0;
}

static void _guard_main(pid_t parent, int wfd) {
    pid_t tids[GX_TASK_MAX];
    int attached[GX_TASK_MAX];
    int na = 0;

    /* 1) 初始扫描：attach 当前全部线程 */
    int n = _list_tids(parent, tids, GX_TASK_MAX);
    if (n <= 0) _exit(7);
    for (int i = 0; i < n; i++) {
        int rc = _attach_one(tids[i]);
        if (rc == -1) {
            if (errno == EPERM) _exit(3);   /* 已被外部 tracer（frida/gdb）持有 */
            continue;                        /* 线程恰好退出等，跳过 */
        }
        if (rc == 0 && na < GX_TASK_MAX) attached[na++] = tids[i];
    }
    if (na == 0) _exit(8);

    /* 2) 握手：通知父进程守护已就绪（1 字节，管道缓冲足够，write 不阻塞） */
    char ok = 'G';
    ssize_t wr = write(wfd, &ok, 1);
    (void)wr;

    /* 3) 监控主循环：被动 waitpid + CONT，绝不 group-stop 周期轮询 */
    int idle_ticks = 0;
    for (;;) {
        int st;
        pid_t t = waitpid(-1, &st, __WALL | WNOHANG);
        if (t == 0) {
            struct timespec ts;
            ts.tv_sec = 0;
            ts.tv_nsec = 200 * 1000 * 1000;   /* 200ms */
            nanosleep(&ts, 0);
            if (++idle_ticks >= 25) {          /* ~5s：补 attach 漏网线程 */
                idle_ticks = 0;
                int m = _list_tids(parent, tids, GX_TASK_MAX);
                for (int i = 0; i < m; i++) {
                    int known = 0;
                    for (int j = 0; j < na; j++) {
                        if (attached[j] == tids[i]) { known = 1; break; }
                    }
                    if (known) continue;
                    if (_attach_one(tids[i]) == 0) {
                        if (na < GX_TASK_MAX) attached[na++] = tids[i];
                    }
                    /* EPERM（漏网线程已被 frida 占）：不误杀不退出，下轮再试 */
                }
            }
            continue;
        }
        if (t < 0) {
            if (errno == EINTR) continue;
            _exit(6);   /* waitpid 不可恢复失败：无 EXITKILL，内核自动 DETACH，App 不受牵连 */
        }
        if (WIFEXITED(st) || WIFSIGNALED(st)) {
            if (t == parent) _exit(0);   /* App 正常退出，守护随之退 */
            continue;                     /* 某线程正常死亡 */
        }
        if (WIFSTOPPED(st)) {
            unsigned ev = (unsigned)st >> 16;   /* PTRACE_EVENT_* 停在高位 */
            int sig = WSTOPSIG(st);
            if (ev == PTRACE_EVENT_CLONE || sig == SIGTRAP || sig == SIGSTOP) {
                ptrace(PTRACE_CONT, t, 0, 0);            /* 内部停走：吞掉并恢复 */
            } else {
                ptrace(PTRACE_CONT, t, 0, (void *)(long)sig);  /* 真实信号：原样透传 */
            }
        }
    }
}

/* JNI 入口：Java 侧 GxGuard.nativePtraceGuardStart()。
 * 返回 >0 = 守护子进程 pid（防护已生效）；0 = 启动失败（降级，App 照常跑）；
 * -1 = 启动时即检测到外部 tracer 已持本进程（攻击信号，由 Java 决定响应）。
 * 幂等：重复调用返回已有守护 pid。 */
JNIEXPORT jint JNICALL
Java_com_gx_runtime_GxGuard_nativePtraceGuardStart(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    if (g_guard_pid != 0) return g_guard_pid;

    int fds[2];
    if (pipe(fds) != 0) return 0;
    pid_t pid = fork();
    if (pid < 0) { close(fds[0]); close(fds[1]); return 0; }
    if (pid == 0) {
        close(fds[0]);
        _guard_main(getppid(), fds[1]);
        _exit(9);   /* unreachable */
    }
    {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        g_guard_fork_ms = (long)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
    }

    /* 父进程侧：握手最多等 3s，绝不 hang 启动 */
    close(fds[1]);
    struct pollfd p;
    p.fd = fds[0];
    p.events = POLLIN;
    p.revents = 0;
    int pr = poll(&p, 1, 3000);
    int ok = 0;
    if (pr == 1 && (p.revents & POLLIN)) {
        char c = 0;
        if (read(fds[0], &c, 1) == 1 && c == 'G') ok = 1;
    }
    close(fds[0]);
    if (ok) {
        g_guard_pid = pid;
        return pid;
    }
    /* 0907 A10 修复：握手失败（超时/EOF）→ SIGKILL 守护并回收。
     * 旧版「超时=放着不管」留下一边 trace 主线程、一边游离于管控外的守护——检测层
     * 的 SEIZE 探针随后必 EPERM，把自家守护误判为外部 tracer → 硬自毁（实测 10.2s
     * 稳定复现）。EXITKILL 已移除，杀守护只会令内核自动 DETACH 全部线程，安全。 */
    kill(pid, SIGKILL);
    {
        int st;
        pid_t r;
        do { r = waitpid(pid, &st, 0); } while (r < 0 && errno == EINTR);
        if (r == pid && WIFEXITED(st) && WEXITSTATUS(st) == 3) return -1;
    }
    return 0;
}
