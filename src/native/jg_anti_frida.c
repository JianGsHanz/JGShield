/*
 * JGShield 强反 Frida 检测层（jg_anti_frida.c）
 * 定位：在不依赖服务端的前提下，尽量抬高 AI 辅助动态逆向（Frida/xposed 类注入框架）
 *       的门槛。属于「被动检测」——能给出运行期信号，但无法「杜绝」：
 *       攻击者仍可 patch 掉响应函数、或自定义 dump，故本层只发信号、断不断由
 *       STRENGTHEN_RESPONSE（加固期经 meta gx.antifrida 开启 + manifest gx.strengthen 决定）统一收口。
 *
 * 铁律：
 *   1. 只读检测，异常全吞，绝不外抛、绝不影响 App 启动。
 *   2. 本文件不碰任何密钥派生 / 写读对称逻辑（与 harden.py 加密端解耦，零对称风险）。
 *   3. 默认关闭：Java 侧 GxAntiFrida.ANTI_FRIDA_ENABLED 为 false 时根本不调用本 native。
 *   4. 误报红线：仅匹配 frida 明确签名串，宁可漏检不可误伤正常用户。
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

/* frida 明确签名子串（小写），命中 /proc/self/maps 路径即判为 frida 痕迹。
 * 刻意排除 "gmain"/"gadget" 等泛化串，避免误伤正常设备。 */
static const char* FRIDA_SIGS[] = {
    "frida", "frida-agent", "frida-gadget", "libfrida",
    "gum-js-loop", "linjector", "re.frida.server",
};
#define N_SIGS (sizeof(FRIDA_SIGS) / sizeof(FRIDA_SIGS[0]))

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

/* 扫 /proc/self/maps：提取每个映射的路径列（最后一个空格之后），匹配 frida 签名。
 * frida-agent 注入后会在 maps 留下 libfrida-agent.so / re.frida.server / [anon:...frida...] 等命名区。 */
static int _scan_maps_frida(void) {
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    char line[1024];
    int hit = 0;
    while (fgets(line, sizeof(line), f)) {
        /* 找最后一个空格，之后即路径列 */
        char* p = line;
        char* last = NULL;
        while (*p) {
            if (*p == ' ') last = p + 1;
            p++;
        }
        if (!last) continue;
        for (size_t i = 0; i < N_SIGS; i++) {
            if (_strcasestr(last, FRIDA_SIGS[i])) { hit = 1; break; }
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

/*
 * 返回位掩码：
 *   bit0 (1) = maps 路径命中 frida 签名
 *   bit1 (2) = TracerPid != 0
 *   bit2 (4) = frida 默认端口开放
 */
JNIEXPORT jint JNICALL
Java_com_gx_runtime_GxAntiFrida_scanJNI(JNIEnv* env, jclass clazz) {
    (void)env; (void)clazz;
    int mask = 0;
    if (_scan_maps_frida())  mask |= 1;
    if (_scan_tracer_pid())  mask |= 2;
    if (_scan_port(27042) || _scan_port(27043)) mask |= 4;
    return (jint)mask;
}
