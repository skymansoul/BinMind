/**
 * CVE-2023-0461 — Linux io_uring IORING_OP_ACCEPT UAF via socket lifecycle
 * UAF模式: lifecycle_race_uaf
 *
 * 样本设计:
 *   精简化复现该CVE的核心UAF机制.
 *   保留原始漏洞的数据流结构: malloc→free→use.
 *   去除平台特定代码, 仅保留可静态分析的user-space等价逻辑.
 *
 * 对静态分析具有挑战性的原因:
 *   1. free和use可能在不同的执行路径上 (路径敏感)
 *   2. 指针可能通过全局变量/栈/寄存器间接到use (别名分析)
 *   3. free后可能有NULL赋值但走不到use (条件分析)
 *   4. 跨函数free→use传播 (过程间分析)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { int fd; char *rx_buf; int state; } Conn_v_2023_0461_iouring;
static Conn_v_2023_0461_iouring *g_conn_v_2023_0461_iouring;

void v_2023_0461_iouring_open(void) {
    g_conn_v_2023_0461_iouring = (Conn_v_2023_0461_iouring *)malloc(sizeof(Conn_v_2023_0461_iouring));
    if (g_conn_v_2023_0461_iouring) {
        g_conn_v_2023_0461_iouring->fd = 42;
        g_conn_v_2023_0461_iouring->rx_buf = (char *)malloc(1024);
        g_conn_v_2023_0461_iouring->state = 1;
    }
}

void v_2023_0461_iouring_close(void) {
    if (g_conn_v_2023_0461_iouring) {
        free(g_conn_v_2023_0461_iouring->rx_buf); free(g_conn_v_2023_0461_iouring);
    }
}

void v_2023_0461_iouring_read(void) {
    if (g_conn_v_2023_0461_iouring && g_conn_v_2023_0461_iouring->state == 1)
        printf("%c", g_conn_v_2023_0461_iouring->rx_buf[0]);  /* UAF */
}

int main(void) {
    printf("=== v_2023_0461_iouring lifecycle race UAF ===\n");
    v_2023_0461_iouring_open(); v_2023_0461_iouring_close(); v_2023_0461_iouring_read();
    return 0;
}

