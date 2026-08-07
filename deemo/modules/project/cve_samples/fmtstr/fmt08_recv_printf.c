// fmt08_recv_printf: recv接收数据直接作为printf格式参数
// 模式: read/recv → printf(buffer) — 网络输入可控格式字符串
// 预期检测: DIRECT_USER_FMT — CRITICAL
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <winsock2.h>
#else
#include <unistd.h>
#endif

int main(int argc, char **argv) {
    char buf[256];
    // 模拟从网络接收数据
#ifdef _WIN32
    // Windows: 用fgets模拟
    if (!fgets(buf, sizeof(buf), stdin)) return 1;
#else
    ssize_t n = read(0, buf, sizeof(buf) - 1);
    if (n <= 0) return 1;
    buf[n] = '\0';
#endif
    // 漏洞: 从输入读取的数据直接作为格式字符串
    printf(buf);
    return 0;
}
