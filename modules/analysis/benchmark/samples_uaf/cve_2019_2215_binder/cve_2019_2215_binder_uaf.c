/**
 * CVE-2019-2215 — Android Binder driver epoll UAF via ioctl
 * UAF模式: double_free_uaf
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

void v_2019_2215_binder_run(void) {
    char *p = (char *)malloc(64);
    if (!p) return;
    memset(p, 'A', 64);
    free(p);
    free(p);  /* double free */
    printf("double-free done\n");
}

int main(void) {
    printf("=== v_2019_2215_binder double free test ===\n");
    v_2019_2215_binder_run();
    return 0;
}

