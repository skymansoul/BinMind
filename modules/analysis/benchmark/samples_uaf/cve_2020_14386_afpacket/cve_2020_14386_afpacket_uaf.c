/**
 * CVE-2020-14386 — Linux AF_PACKET ring buffer UAF via setsockopt overflow
 * UAF模式: loop_iteration_uaf
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

static char *g_items_v_2020_14386_afpacket[4];

void v_2020_14386_afpacket_loop_free(void) {
    for (int i = 0; i < 4; i++) {
        g_items_v_2020_14386_afpacket[i] = (char *)malloc(64);
        if (g_items_v_2020_14386_afpacket[i]) memset(g_items_v_2020_14386_afpacket[i], i, 64);
    }
    for (int i = 0; i < 4; i++)
        free(g_items_v_2020_14386_afpacket[i]);  /* 缺少 g_items[i]=NULL */
    printf("%d", g_items_v_2020_14386_afpacket[2][0]);  /* UAF */
}

int main(void) {
    printf("=== v_2020_14386_afpacket loop iteration UAF ===\n");
    v_2020_14386_afpacket_loop_free();
    return 0;
}

