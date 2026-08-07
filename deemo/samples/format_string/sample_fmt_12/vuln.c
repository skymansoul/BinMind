/*
 * sample_fmt_12 — recv→printf (网络输入)
 * 模式: recv(sock, buf) → printf(buf)
 * 期望: CONFIRMED (网络输入完全可控)
 */
#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#endif

int main(void) {
    char buf[256];
    /* 模拟: recv(sock, buf, sizeof(buf), 0) */
    fgets(buf, sizeof(buf), stdin);  /* 简化: 用fgets模拟网络输入 */
    printf(buf);  /* [VULN] 网络输入作为格式字符串 */
    return 0;
}
