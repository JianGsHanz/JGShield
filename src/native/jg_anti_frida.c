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
 *   A2. fork 子进程对父进程做 PTRACE_ATTACH：成功=未被 trace，失败=已被 frida/gdb trace
 *       （detach 还原，对本进程零副作用）。抓 frida-gum / gdb 早于 maps 留名。
 *   A3. maps 扫描 Xposed / LSPosed / riru / lspd / lspose 签名，覆盖 AI 常用 LSPosed hook。
 *
 * 返回位掩码：
 *   bit0 (1)  = maps 路径命中 frida 签名
 *   bit1 (2)  = TracerPid != 0
 *   bit2 (4)  = frida 默认端口开放(27042/27043)
 *   bit3 (8)  = 主动 ptrace 自检：本进程已被 trace（frida/gdb）
 *   bit4 (16) = maps 路径命中 Xposed/LSPosed 签名
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

/* 扫 /proc/self/maps：提取每个映射的路径列（最后一个空格之后），匹配 frida 签名表。
 * frida-agent 注入后会在 maps 留下 libfrida-agent.so / re.frida.server / [anon:...frida...] 等命名区。 */
static int _scan_maps_frida(void) {
    int hit = 0;
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    char line[1024];
    char dec[64];
    while (fgets(line, sizeof(line), f)) {
        char* p = line;
        char* last = NULL;
        while (*p) { if (*p == ' ') last = p + 1; p++; }
        if (!last) continue;
        for (int i = 0; i < (int)N_FRIDA; i++) {
            _decode_sig(FRIDA_SIGS[i], dec, sizeof(dec));
            if (_strcasestr(last, dec)) { hit = 1; break; }
        }
        if (hit) break;
    }
    fclose(f);
    return hit;
}

static int _scan_maps_xposed(void) {
    int hit = 0;
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    char line[1024];
    char dec[64];
    while (fgets(line, sizeof(line), f)) {
        char* p = line;
        char* last = NULL;
        while (*p) { if (*p == ' ') last = p + 1; p++; }
        if (!last) continue;
        for (int i = 0; i < (int)N_XPOSED; i++) {
            _decode_sig(XPOSED_SIGS[i], dec, sizeof(dec));
            if (_strcasestr(last, dec)) { hit = 1; break; }
        }
        if (hit) break;
    }
    fclose(f);
    return hit;
}

/* /proc/self/status 的 TracerPid 非 0 == 正被 ptrace（调试器 / frida 注入的典型特征）。 */
static int _scan_tracer_pid(void) {
    FILE* f = fopen("/proc/self/status", "r");
    if (!f) return 0;
    char line[256];
    int hit = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            int pid = atoi(line + 10);
            if (pid != 0) hit = 1;
            break;
        }
    }
    fclose(f);
    return hit;
}

/* A2: 主动 ptrace 自检（无副作用）。
 * 思路：fork 子进程对父进程做 PTRACE_ATTACH。
 *   - 成功 → 父进程此前未被 trace（detach 还原），返回 0；
 *   - 失败(EBUSY/EPERM) → 父进程已被 frida/gdb trace（一个进程只能有一个 tracer），返回 1。
 * 子进程立即 detach 并退出，对父进程 trace 状态零影响。 */
static int _scan_ptrace_self(void) {
    pid_t child = fork();
    if (child < 0) return 0;          /* fork 失败 → 保守判未命中 */
    if (child == 0) {
        /* 子进程：尝试 attach 父进程 */
        pid_t parent = getppid();
        if (ptrace(PTRACE_ATTACH, parent, 0, 0) == 0) {
            ptrace(PTRACE_DETACH, parent, 0, 0);
            _exit(0);                  /* 父未被 trace */
        }
        _exit(1);                      /* attach 失败 → 父已被 trace */
    }
    int status = 0;
    if (waitpid(child, &status, 0) < 0) return 0;
    if (WIFEXITED(status) && WEXITSTATUS(status) == 1) return 1;
    return 0;
}

/* frida-server / gadget 默认监听本地 TCP 27042 / 27043。探测开放即命中。
 * 带 200ms 超时，避免对未开放端口长阻塞。 */
static int _scan_port(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 0;
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 200000; /* 200ms */
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)port);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    int r = connect(fd, (struct sockaddr*)&addr, sizeof(addr));
    close(fd);
    return (r == 0) ? 1 : 0;
}

JNIEXPORT jint JNICALL
Java_com_gx_runtime_GxAntiFrida_scanJNI(JNIEnv* env, jclass clazz) {
    (void)env; (void)clazz;
    int mask = 0;
    if (_scan_maps_frida())                       mask |= 1;   /* bit0 frida maps */
    if (_scan_tracer_pid())                       mask |= 2;   /* bit1 TracerPid */
    if (_scan_port(27042) || _scan_port(27043))   mask |= 4;   /* bit2 frida port */
    if (_scan_ptrace_self())                      mask |= 8;   /* bit3 ptrace self */
    if (_scan_maps_xposed())                      mask |= 16;  /* bit4 Xposed/LSPosed */
    return (jint)mask;
}
