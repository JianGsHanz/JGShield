/*
 * JGShield 裸 syscall 层 (jg_rawsys.h)
 * --------------------------------------------------------------------------
 * P0-A（2026-09-07 四步打穿复盘）：壳的检测 IO（open/read/opendir/connect）此前
 * 全部走 libc PLT——frida Interceptor hook libc 的 open/read/ connect/prctl 后：
 *   - 可拦截我们的探测 connect（改名端口永不命中）；
 *   - 可伪造 read 结果（maps/comm/tcp 扫描读到的是攻击者过滤后的内容）；
 *   - 可改写线程名（bit5 失效）。
 * 对策：全部检测 IO 改为内联汇编 svc/syscall/int80 直调内核，不经任何 libc 符号。
 * libc 层 hook（无论 hook 多少个函数）都拦不到 svc 指令本身。
 *
 * 覆盖 ABI：arm64-v8a / armeabi-v7a(EABI) / x86_64 / x86(int80 + socketcall)。
 * 注意：x86(i386) 的 socket 系列 6 参直调 syscall 需要栈传参，改走 socketcall(102)
 *       多路复用（2 参寄存器即可）；其余 ABI 全部用各自 socket 直调号。
 * 所有封装都是 static inline（各 TU 独立副本），不引入新编译单元。
 */
#ifndef JG_RAWSYS_H
#define JG_RAWSYS_H

#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ptrace.h>

#ifndef AT_FDCWD
#define AT_FDCWD (-100)
#endif

/* ---------------- 各 ABI 系统调用号 ---------------- */
#if defined(__aarch64__)
#define JG_NR_read        63
#define JG_NR_close       57
#define JG_NR_lseek       62
#define JG_NR_getdents64  61
#define JG_NR_openat      56
#define JG_NR_socket     198
#define JG_NR_connect    203
#define JG_NR_sendto     206
#define JG_NR_recvfrom   207
#define JG_NR_setsockopt 208
#define JG_NR_exit_group  94
#define JG_NR_clone      220
#define JG_NR_wait4      260
#define JG_NR_ptrace     117
#define JG_NR_getppid    172

static __inline__ long jg_sc(long n, long a0, long a1, long a2,
                             long a3, long a4, long a5) {
    register long __n __asm__("x8") = n;
    register long __x0 __asm__("x0") = a0;
    register long __x1 __asm__("x1") = a1;
    register long __x2 __asm__("x2") = a2;
    register long __x3 __asm__("x3") = a3;
    register long __x4 __asm__("x4") = a4;
    register long __x5 __asm__("x5") = a5;
    __asm__ __volatile__("svc #0"
        : "+r"(__x0)
        : "r"(__n), "r"(__x1), "r"(__x2), "r"(__x3), "r"(__x4), "r"(__x5)
        : "memory", "cc");
    return __x0;
}

#elif defined(__arm__)
#define JG_NR_read         3
#define JG_NR_close        6
#define JG_NR_lseek       19
#define JG_NR_getdents64 217
#define JG_NR_openat     322
#define JG_NR_socket     281
#define JG_NR_connect    283
#define JG_NR_sendto     290
#define JG_NR_recvfrom   292
#define JG_NR_setsockopt 294
#define JG_NR_exit_group 248
#define JG_NR_clone      120
#define JG_NR_wait4      114
#define JG_NR_ptrace      26
#define JG_NR_getppid     64

static __inline__ long jg_sc(long n, long a0, long a1, long a2,
                             long a3, long a4, long a5) {
    register long __r7 __asm__("r7") = n;
    register long __r0 __asm__("r0") = a0;
    register long __r1 __asm__("r1") = a1;
    register long __r2 __asm__("r2") = a2;
    register long __r3 __asm__("r3") = a3;
    register long __r4 __asm__("r4") = a4;
    register long __r5 __asm__("r5") = a5;
    __asm__ __volatile__("swi #0"
        : "+r"(__r0)
        : "r"(__r7), "r"(__r1), "r"(__r2), "r"(__r3), "r"(__r4), "r"(__r5)
        : "memory", "cc");
    return __r0;
}

#elif defined(__x86_64__)
#define JG_NR_read         0
#define JG_NR_close        3
#define JG_NR_lseek        8
#define JG_NR_getdents64 217
#define JG_NR_openat      257
#define JG_NR_socket      41
#define JG_NR_connect     42
#define JG_NR_sendto      44
#define JG_NR_recvfrom    45
#define JG_NR_setsockopt  54
#define JG_NR_exit_group 231
#define JG_NR_clone       56
#define JG_NR_wait4       61
#define JG_NR_ptrace     101
#define JG_NR_getppid    110

static __inline__ long jg_sc(long n, long a0, long a1, long a2,
                             long a3, long a4, long a5) {
    register long __rax __asm__("rax") = n;
    register long __rdi __asm__("rdi") = a0;
    register long __rsi __asm__("rsi") = a1;
    register long __rdx __asm__("rdx") = a2;
    register long __r10 __asm__("r10") = a3;
    register long __r8  __asm__("r8")  = a4;
    register long __r9  __asm__("r9")  = a5;
    __asm__ __volatile__("syscall"
        : "+r"(__rax)
        : "r"(__rdi), "r"(__rsi), "r"(__rdx), "r"(__r10), "r"(__r8), "r"(__r9)
        : "memory", "cc", "rcx", "r11");
    return __rax;
}

#elif defined(__i386__)
#define JG_NR_read         3
#define JG_NR_close        6
#define JG_NR_lseek       19
#define JG_NR_getdents64 220
#define JG_NR_openat      295
#define JG_NR_socketcall 102
#define JG_NR_exit_group 252
#define JG_NR_clone      120
#define JG_NR_wait4      114
#define JG_NR_ptrace      26
#define JG_NR_getppid     64

/* i386 只有 5 个寄存器传参（ebx,ecx,edx,esi,edi），仅提供 <=5 参封装；
 * socket 系列走 socketcall 多路复用。 */
static __inline__ long jg_sc5(long n, long a0, long a1, long a2,
                              long a3, long a4) {
    long __ret;
    __asm__ __volatile__("int $0x80"
        : "=a"(__ret)
        : "a"(n), "b"(a0), "c"(a1), "d"(a2), "S"(a3), "D"(a4)
        : "memory");
    return __ret;
}
static __inline__ long jg_sc3(long n, long a0, long a1, long a2) {
    long __ret;
    __asm__ __volatile__("int $0x80"
        : "=a"(__ret)
        : "a"(n), "b"(a0), "c"(a1), "d"(a2)
        : "memory");
    return __ret;
}
/* 统一入口：i386 只支持到 5 参，第 6 参必须为 0（本层所有 6 参场景走 socketcall） */
static __inline__ long jg_sc(long n, long a0, long a1, long a2,
                             long a3, long a4, long a5) {
    (void)a5;
    return jg_sc5(n, a0, a1, a2, a3, a4);
}
/* socketcall 子调用号（asm-i386/socketcall.h） */
#define JG_SC_SOCKET      1
#define JG_SC_CONNECT     3
#define JG_SC_SEND        9
#define JG_SC_RECV       10
#define JG_SC_SETSOCKOPT 14

#else
#error "jg_rawsys.h: unsupported ABI"
#endif

/* ---------------- 文件 IO ---------------- */

static __inline__ long jg_open_ro(const char *path) {
#if defined(__arm__) || defined(__aarch64__) || defined(__x86_64__) || defined(__i386__)
    return jg_sc(JG_NR_openat, (long)AT_FDCWD, (long)path, O_RDONLY, 0, 0, 0);
#endif
}

static __inline__ long jg_read(int fd, void *buf, unsigned long n) {
    return jg_sc(JG_NR_read, fd, (long)buf, n, 0, 0, 0);
}

static __inline__ long jg_close(int fd) {
    return jg_sc(JG_NR_close, fd, 0, 0, 0, 0, 0);
}

static __inline__ long jg_lseek(int fd, long off, int whence) {
    return jg_sc(JG_NR_lseek, fd, off, whence, 0, 0, 0);
}

/* linux_dirent64（内核私有结构，libc 不暴露） */
struct jg_dirent64 {
    unsigned long long d_ino;
    long long          d_off;
    unsigned short     d_reclen;
    unsigned char      d_type;
    char               d_name[];
};

static __inline__ long jg_getdents64(int fd, void *buf, unsigned long n) {
    return jg_sc(JG_NR_getdents64, fd, (long)buf, n, 0, 0, 0);
}

/* 整文件读入（<= cap-1 字节），NUL 结尾。失败返回 -1，成功返回字节数。 */
static __inline__ int jg_read_file_raw(const char *path, char *buf, int cap) {
    long fd = jg_open_ro(path);
    if (fd < 0) return -1;
    int total = 0;
    while (total < cap - 1) {
        long n = jg_read((int)fd, buf + total, (unsigned long)(cap - 1 - total));
        if (n <= 0) break;
        total += (int)n;
    }
    jg_close((int)fd);
    buf[total] = '\0';
    return total;
}

/* 目录遍历：对 /proc/self/task 等目录的每个非 "." 项调 cb(name, ud)。
 * cb 返回非 0 = 提前终止（返回 1）；读完返回 0。出错返回 -1。 */
typedef int (*jg_dir_fn)(const char *name, void *ud);

static __inline__ int jg_for_each_dir(const char *path, jg_dir_fn cb, void *ud) {
    long fd = jg_open_ro(path);
    if (fd < 0) return -1;
    char buf[2048];
    int stopped = 0;
    for (;;) {
        long n = jg_getdents64((int)fd, buf, sizeof(buf));
        if (n <= 0) break;
        int off = 0;
        while (off < (int)n) {
            struct jg_dirent64 *de = (struct jg_dirent64 *)(buf + off);
            if (de->d_reclen == 0) break;   /* 防御：畸形记录防死循环 */
            const char *nm = de->d_name;
            if (nm[0] != '.') {
                if (cb(nm, ud)) { stopped = 1; break; }
            }
            off += (int)de->d_reclen;
        }
        if (stopped) break;
    }
    jg_close((int)fd);
    return stopped;
}

/* ---------------- 网络 IO ---------------- */

static __inline__ long jg_socket_tcp(void) {
#if defined(__i386__)
    long args[3] = {AF_INET, SOCK_STREAM, 0};
    return jg_sc(JG_NR_socketcall, JG_SC_SOCKET, (long)args, 0, 0, 0, 0);
#else
    return jg_sc(JG_NR_socket, AF_INET, SOCK_STREAM, 0, 0, 0, 0);
#endif
}

static __inline__ long jg_connect_local(int fd, unsigned short port) {
    struct sockaddr_in sa;
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
#if defined(__i386__)
    long args[3] = {fd, (long)&sa, (long)sizeof(sa)};
    return jg_sc(JG_NR_socketcall, JG_SC_CONNECT, (long)args, 0, 0, 0, 0);
#else
    return jg_sc(JG_NR_connect, fd, (long)&sa, (long)sizeof(sa), 0, 0, 0);
#endif
}

static __inline__ long jg_sock_timeo(int fd, long usec_snd, long usec_rcv) {
    struct timeval tv;
    long r = 0;
    if (usec_snd > 0) {
        tv.tv_sec = usec_snd / 1000000L; tv.tv_usec = usec_snd % 1000000L;
#if defined(__i386__)
        long args[5] = {fd, SOL_SOCKET, SO_SNDTIMEO, (long)&tv, (long)sizeof(tv)};
        r = jg_sc(JG_NR_socketcall, JG_SC_SETSOCKOPT, (long)args, 0, 0, 0, 0);
#else
        r = jg_sc(JG_NR_setsockopt, fd, SOL_SOCKET, SO_SNDTIMEO, (long)&tv, (long)sizeof(tv), 0);
#endif
        if (r < 0) return r;
    }
    if (usec_rcv > 0) {
        tv.tv_sec = usec_rcv / 1000000L; tv.tv_usec = usec_rcv % 1000000L;
#if defined(__i386__)
        long args[5] = {fd, SOL_SOCKET, SO_RCVTIMEO, (long)&tv, (long)sizeof(tv)};
        return jg_sc(JG_NR_socketcall, JG_SC_SETSOCKOPT, (long)args, 0, 0, 0, 0);
#else
        return jg_sc(JG_NR_setsockopt, fd, SOL_SOCKET, SO_RCVTIMEO, (long)&tv, (long)sizeof(tv), 0);
#endif
    }
    return r;
}

static __inline__ long jg_send_n(int fd, const void *buf, unsigned long n) {
#if defined(__i386__)
    long args[4] = {fd, (long)buf, (long)n, 0};
    return jg_sc(JG_NR_socketcall, JG_SC_SEND, (long)args, 0, 0, 0, 0);
#else
    return jg_sc(JG_NR_sendto, fd, (long)buf, n, 0, 0, 0);
#endif
}

static __inline__ long jg_recv_n(int fd, void *buf, unsigned long n) {
#if defined(__i386__)
    long args[4] = {fd, (long)buf, (long)n, 0};
    return jg_sc(JG_NR_socketcall, JG_SC_RECV, (long)args, 0, 0, 0, 0);
#else
    return jg_sc(JG_NR_recvfrom, fd, (long)buf, n, 0, 0, 0);
#endif
}

/* ---------------- 进程控制 ---------------- */

static __inline__ long jg_getppid(void) {
    return jg_sc(JG_NR_getppid, 0, 0, 0, 0, 0, 0);
}

/* fork 语义的 clone：SIGCHLD + 栈/TLS/_tid 全零（aarch64 与其他 ABI 的参数顺序
 * 不同，但全零场景下顺序无关，语义一致）。 */
static __inline__ long jg_fork(void) {
    return jg_sc(JG_NR_clone, (long)SIGCHLD, 0, 0, 0, 0, 0);
}

static __inline__ long jg_wait4(int pid, int *status) {
    return jg_sc(JG_NR_wait4, pid, (long)status, 0, 0, 0, 0);
}

static __inline__ long jg_raw_ptrace(long req, int pid, long addr, long data) {
    return jg_sc(JG_NR_ptrace, req, pid, addr, data, 0, 0);
}

/* 裸 exit_group：子进程探针 / 自毁共用的最底层退出，libc hook 拦不到 */
static __inline__ void jg_raw_exit(int code) __attribute__((noreturn));
static __inline__ void jg_raw_exit(int code) {
#if defined(__aarch64__)
    (void)jg_sc(JG_NR_exit_group, code, 0, 0, 0, 0, 0);
#elif defined(__arm__)
    (void)jg_sc(JG_NR_exit_group, code, 0, 0, 0, 0, 0);
#elif defined(__x86_64__)
    (void)jg_sc(JG_NR_exit_group, code, 0, 0, 0, 0, 0);
#elif defined(__i386__)
    (void)jg_sc3(JG_NR_exit_group, code, 0, 0);
#endif
    for (;;) { volatile int *p = (volatile int *)0; *p = 0; }
}

#endif /* JG_RAWSYS_H */
