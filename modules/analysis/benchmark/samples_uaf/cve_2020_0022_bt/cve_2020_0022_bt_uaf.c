/**
 * CVE-2020-0022 — Android Bluetooth L2CAP packet fragment reassembly UAF
 * UAF模式: realloc_uaf
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

void v_2020_0022_bt_bug(void) {
    char *p = (char *)malloc(64);
    char *old = p;
    if (!p) return;
    memset(p, 'B', 64);
    p = (char *)realloc(p, 128);
    if (p) { printf("realloc OK\n"); free(p); }
    printf("%c", old[0]);  /* UAF: old可能已失效 */
}

int main(void) {
    printf("=== v_2020_0022_bt realloc UAF ===\n");
    v_2020_0022_bt_bug();
    return 0;
}

